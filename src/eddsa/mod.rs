// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! EdDSA cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc8032

use crate::pem;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::asn1::OctetStringRef;
use der::{Decode, Encode};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signer, Verifier};
use pkcs8::PrivateKeyInfoRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Digest;
use spki::der::AnyRef;
use spki::der::asn1::BitStringRef;
use spki::{ObjectIdentifier, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

/// OID is the ASN.1 object identifier for Ed25519.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Size of the secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Size of a fingerprint in bytes.
pub const FINGERPRINT_SIZE: usize = 32;

/// Error is the failures that can occur during EdDSA operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("pem: {0}")]
    Pem(#[from] pem::Error),
    #[error("invalid PEM tag {0}")]
    UnexpectedPemTag(String),
    #[error("not an Ed25519 key")]
    UnexpectedAlgorithm,
    #[error("malformed key: {0}")]
    MalformedKey(String),
    #[error("trailing data in key encoding")]
    TrailingData,
    #[error("signature verification failed")]
    InvalidSignature,
}

/// SecretKey contains an Ed25519 private key usable for signing.
#[derive(Clone)]
pub struct SecretKey {
    inner: ed25519_dalek::SigningKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        getrandom::fill(seed.as_mut()).unwrap();

        Self::from_bytes(&seed)
    }

    /// from_bytes converts a 32-byte array into a private key.
    pub fn from_bytes(bin: &[u8; SECRET_KEY_SIZE]) -> Self {
        let key = Zeroizing::new(ed25519_dalek::SecretKey::from(*bin));
        let sig = ed25519_dalek::SigningKey::from(&*key);
        Self { inner: sig }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let info =
            PrivateKeyInfoRef::try_from(der).map_err(|err| Error::MalformedKey(err.to_string()))?;

        // Reject trailing data by verifying re-encoded length matches input
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Ensure the algorithm OID matches Ed25519
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        // Reject v2 keys. The decoder only ever yields v1 keys without or v2
        // keys with an embedded public key, all other combinations fail to
        // parse, so public key presence is an exact v2 marker.
        if info.public_key.is_some() {
            return Err(Error::MalformedKey("unsupported PKCS#8 version".into()));
        }
        // Ensure no algorithm parameters are present, none are allowed
        if info.algorithm.parameters.is_some() {
            return Err(Error::MalformedKey(
                "unexpected algorithm parameters".into(),
            ));
        }
        // The private key field contains an OCTET STRING wrapping the seed
        let seed = <&OctetStringRef>::from_der(info.private_key.as_bytes())
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        let seed: Zeroizing<[u8; SECRET_KEY_SIZE]> = Zeroizing::new(
            seed.as_bytes()
                .try_into()
                .map_err(|_| Error::MalformedKey("seed not 32 bytes".into()))?,
        );
        Ok(Self::from_bytes(&seed))
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        Self::from_der(&data)
    }

    /// to_bytes converts a private key into a 32-byte array.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        // The private key field contains an OCTET STRING wrapping the seed
        let seed = self.to_bytes();
        let inner = Zeroizing::new(
            OctetStringRef::new(seed.as_slice())
                .unwrap()
                .to_der()
                .unwrap(),
        );

        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        let info = PrivateKeyInfoRef {
            algorithm: alg,
            private_key: OctetStringRef::new(&inner).unwrap(),
            public_key: None,
        };
        Zeroizing::new(info.to_der().unwrap())
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem::encode("PRIVATE KEY", &self.to_der()))
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// fingerprint returns a 256bit unique identified for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// sign creates a digital signature of the message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.inner.sign(message).to_bytes())
    }
}

/// PublicKey contains an Ed25519 public key usable for verification.
#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// from_bytes converts a 32-byte array into a public key.
    pub fn from_bytes(bin: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        let inner = ed25519_dalek::VerifyingKey::from_bytes(bin)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        Ok(Self { inner })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Parse with SPKI to check for trailing data
        let info: SubjectPublicKeyInfo<AnyRef, BitStringRef> = SubjectPublicKeyInfo::from_der(der)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Ensure the algorithm OID matches Ed25519
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        // Ensure no algorithm parameters are present, none are allowed
        if info.algorithm.parameters.is_some() {
            return Err(Error::MalformedKey(
                "unexpected algorithm parameters".into(),
            ));
        }
        let inner = ed25519_dalek::VerifyingKey::from_public_key_der(der)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        Self::from_der(&data)
    }

    /// to_bytes converts a public key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_public_key_der().unwrap().as_bytes().to_vec()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identified for this key. For Ed25519,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.to_bytes());
        Fingerprint(hasher.finalize().into())
    }

    /// verify verifies a digital signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.to_bytes());
        self.inner
            .verify(message, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid public key length"))?;
        PublicKey::from_bytes(&arr).map_err(de::Error::custom)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for PublicKey {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for PublicKey {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; PUBLIC_KEY_SIZE]>::decode_cbor(data)?;
        Self::from_bytes(&bytes).map_err(|e| crate::cbor::Error::DecodeFailed(e.to_string()))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<PUBLIC_KEY_SIZE>()?;
        Self::from_bytes(&bytes).map_err(|e| crate::cbor::Error::DecodeFailed(e.to_string()))
    }
}

/// Signature contains an Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// from_bytes converts a 64-byte array into a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// to_bytes converts a signature into a 64-byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid signature length"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for Signature {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for Signature {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; SIGNATURE_SIZE]>::decode_cbor(data)?;
        Ok(Self::from_bytes(&bytes))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<SIGNATURE_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// Fingerprint contains an Ed25519 key fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl Fingerprint {
    /// from_bytes converts a 32-byte array into a fingerprint.
    pub fn from_bytes(bytes: &[u8; FINGERPRINT_SIZE]) -> Self {
        Self(*bytes)
    }

    /// to_bytes converts a fingerprint into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; FINGERPRINT_SIZE] {
        self.0
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; FINGERPRINT_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid fingerprint length"))?;
        Ok(Fingerprint::from_bytes(&arr))
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for Fingerprint {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for Fingerprint {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; FINGERPRINT_SIZE]>::decode_cbor(data)?;
        Ok(Self::from_bytes(&bytes))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<FINGERPRINT_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 8410 Sections 10.1 and 10.3
    // https://datatracker.ietf.org/doc/html/rfc8410
    mod ietf_vectors {
        pub const SECKEY_SEED: &str =
            "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";

        pub const SECKEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

        pub const SECKEY_V2_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----";

        pub const PUBKEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----";
    }

    // Tests operations with IETF test vectors: the private key must parse into
    // the published raw seed, re-encode into the published PEM and DER, and
    // derive the RFC's matching public key.
    #[test]
    fn test_ietf_vectors() {
        // Round trip the secret key pem and verify the expected seed
        let key = SecretKey::from_pem(ietf_vectors::SECKEY_PEM).unwrap();
        assert_eq!(hex::encode(*key.to_bytes()), ietf_vectors::SECKEY_SEED);
        assert_eq!(key.to_pem().trim(), ietf_vectors::SECKEY_PEM.trim());

        // Round trip the secret key der
        let (_, der) = pem::decode(ietf_vectors::SECKEY_PEM.as_bytes()).unwrap();
        assert_eq!(*key.to_der(), *der);

        // Verify the expected public key
        assert_eq!(
            key.public_key().to_pem().trim(),
            ietf_vectors::PUBKEY_PEM.trim()
        );

        // Round trip the public key pem
        let key = PublicKey::from_pem(ietf_vectors::PUBKEY_PEM).unwrap();
        assert_eq!(key.to_pem().trim(), ietf_vectors::PUBKEY_PEM.trim());

        // Round trip the public key der
        let (_, der) = pem::decode(ietf_vectors::PUBKEY_PEM.as_bytes()).unwrap();
        assert_eq!(key.to_der(), *der);
    }

    // Tests that the RFC 8410 v2 private key vector carrying an attribute and
    // an embedded public key is rejected: only v1 keys without embedded public
    // data are supported.
    #[test]
    fn test_ietf_v2_rejected() {
        assert!(SecretKey::from_pem(ietf_vectors::SECKEY_V2_PEM).is_err());
    }

    // Tests signing and verifying messages. Note, this test is not meant to test
    // cryptography, it is mostly an API sanity check to verify that everything
    // seems to work.
    #[test]
    fn test_sign_verify() {
        // Create the keys for Alice
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Run a bunch of different authentication/encryption combinations
        struct TestCase<'a> {
            message: &'a [u8],
        }
        let tests = [TestCase {
            message: b"message to authenticate",
        }];

        for tt in &tests {
            // Sign the message using the test case data
            let signature = secret.sign(tt.message);

            // Verify the signature message
            public
                .verify(tt.message, &signature)
                .unwrap_or_else(|e| panic!("failed to verify message: {}", e));
        }
    }

    // Tests that a public key whose algorithm identifier carries parameters is
    // rejected.
    #[test]
    fn test_publickey_der_rejects_params() {
        // Rebuild a valid public key with injected NULL algorithm parameters
        let key = SecretKey::from_bytes(&[7; 32]).public_key();
        let der = key.to_der();

        let mut info: SubjectPublicKeyInfo<AnyRef, BitStringRef> =
            SubjectPublicKeyInfo::from_der(&der).unwrap();
        info.algorithm.parameters = Some(AnyRef::NULL);
        let der_bad = info.to_der().unwrap();

        let err = PublicKey::from_der(&der_bad);
        assert!(matches!(err, Err(Error::MalformedKey(_))));
    }

    // Tests that a private key whose algorithm identifier carries parameters is
    // rejected.
    #[test]
    fn test_secretkey_der_rejects_params() {
        // Rebuild a valid private key with NULL algorithm parameters spliced in
        let der = SecretKey::from_bytes(&[7; 32]).to_der().to_vec();
        let long = der[1] == 0x82;
        let algid_pos = if long { 7 } else { 5 };
        let algid_len = der[algid_pos + 1] as usize;
        let oid_pos = algid_pos + 2;
        let oid_len = 2 + der[oid_pos + 1] as usize;
        let after_oid = oid_pos + oid_len;

        let mut bad = der.clone();
        bad.splice(after_oid..after_oid, [0x05, 0x00]);
        bad[algid_pos + 1] = (algid_len + 2) as u8;
        if long {
            let grown = (((der[2] as usize) << 8) | der[3] as usize) + 2;
            bad[2] = (grown >> 8) as u8;
            bad[3] = (grown & 0xff) as u8;
        } else {
            bad[1] = (der[1] as usize + 2) as u8;
        }

        let err = SecretKey::from_der(&bad);
        assert!(matches!(err, Err(Error::MalformedKey(_))));
    }
}
