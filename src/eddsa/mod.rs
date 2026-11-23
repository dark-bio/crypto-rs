// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Ed25519 digital signatures.
//!
//! <https://datatracker.ietf.org/doc/html/rfc8032>
//!
//! Standalone Ed25519 signatures, forming the classical half of the composite
//! scheme in the `xdsa` module. Prefer `xdsa` unless a protocol requires plain
//! Ed25519.
//!
//! ```
//! use darkbio_crypto::eddsa;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let secret = eddsa::SecretKey::generate();
//! let signature = secret.sign(b"hello");
//! secret.public_key().verify(b"hello", &signature)?;
//! # Ok(())
//! # }
//! ```

use crate::pem;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::asn1::OctetStringRef;
use der::{Decode, Encode};
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, Verifier};
use pkcs8::PrivateKeyInfoRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Digest;
use spki::der::AnyRef;
use spki::der::asn1::BitStringRef;
use spki::{ObjectIdentifier, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

/// ASN.1 object identifier for Ed25519.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Size of the secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Size of a fingerprint in bytes.
pub const FINGERPRINT_SIZE: usize = 32;

/// Failures returned by Ed25519 operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// PEM wrapper is malformed; the inner error identifies the broken rule.
    /// Returned by [`SecretKey::from_pem`] and [`PublicKey::from_pem`].
    #[error("pem: {0}")]
    Pem(#[from] pem::Error),
    /// PEM block label does not match the expected one (`PRIVATE KEY` for
    /// [`SecretKey::from_pem`] or `PUBLIC KEY` for [`PublicKey::from_pem`]).
    /// Carries the label found.
    #[error("invalid PEM tag {0}")]
    UnexpectedPemTag(String),
    /// DER key identifies an algorithm other than Ed25519 (see [`OID`]).
    /// Returned by [`SecretKey::from_der`] and [`PublicKey::from_der`], and
    /// through them by the PEM parsers.
    #[error("not an Ed25519 key")]
    UnexpectedAlgorithm,
    /// Key encoding cannot be parsed or its contents are unusable, such as a
    /// wrong size, unexpected algorithm parameters, trailing DER bytes, or an
    /// unsupported PKCS#8 version. Returned by the fallible key constructors.
    #[error("malformed key: {0}")]
    MalformedKey(String),
    /// Parsed DER key re-encodes to a different length than the input. This is
    /// a fallback consistency check in the DER constructors; the DER parser
    /// rejects appended bytes first with [`Error::MalformedKey`].
    #[error("trailing data in key encoding")]
    TrailingData,
    /// Signature does not verify for this key and message. Returned by
    /// [`PublicKey::verify`].
    #[error("signature verification failed")]
    InvalidSignature,
}

/// Ed25519 private key for signing.
#[derive(Clone)]
pub struct SecretKey {
    inner: ed25519_dalek::SigningKey,
}

impl SecretKey {
    /// Generates a random private key.
    pub fn generate() -> SecretKey {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        getrandom::fill(seed.as_mut()).unwrap();

        Self::from_bytes(&seed)
    }

    /// Creates a private key from a 32-byte seed.
    pub fn from_bytes(bin: &[u8; SECRET_KEY_SIZE]) -> Self {
        let key = Zeroizing::new(ed25519_dalek::SecretKey::from(*bin));
        let sig = ed25519_dalek::SigningKey::from(&*key);
        Self { inner: sig }
    }

    /// Parses a PKCS#8 DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let info =
            PrivateKeyInfoRef::try_from(der).map_err(|err| Error::MalformedKey(err.to_string()))?;

        // Verify the re-encoded length matches the input to reject trailing data
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Check that the algorithm OID matches Ed25519
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        // Reject v2 keys. The decoder yields v1 keys without an embedded public
        // key and v2 keys with one, so a present public key identifies v2.
        if info.public_key.is_some() {
            return Err(Error::MalformedKey("unsupported PKCS#8 version".into()));
        }
        // Reject algorithm parameters since Ed25519 permits none
        if info.algorithm.parameters.is_some() {
            return Err(Error::MalformedKey(
                "unexpected algorithm parameters".into(),
            ));
        }
        // Unwrap the OCTET STRING carrying the 32-byte seed
        let seed = <&OctetStringRef>::from_der(info.private_key.as_bytes())
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        let seed: Zeroizing<[u8; SECRET_KEY_SIZE]> = Zeroizing::new(
            seed.as_bytes()
                .try_into()
                .map_err(|_| Error::MalformedKey("seed not 32 bytes".into()))?,
        );
        Ok(Self::from_bytes(&seed))
    }

    /// Parses a PKCS#8 PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        Self::from_der(&data)
    }

    /// Returns the 32-byte private key seed.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    /// Serializes the private key into PKCS#8 DER.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        // Wrap the 32-byte seed in an OCTET STRING for the PKCS#8 privateKey field
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

    /// Serializes the private key into PKCS#8 PEM.
    pub fn to_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem::encode("PRIVATE KEY", &self.to_der()))
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Returns the 256-bit key fingerprint, computed as the SHA-256 hash of
    /// the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// Signs `message` with Ed25519.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.inner.sign(message).to_bytes())
    }
}

/// Ed25519 public key for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// Creates a public key from a 32-byte encoding.
    pub fn from_bytes(bin: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        let inner = ed25519_dalek::VerifyingKey::from_bytes(bin)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        Ok(Self { inner })
    }

    /// Parses an SPKI DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Parse SPKI and verify the re-encoded length matches the input
        let info: SubjectPublicKeyInfo<AnyRef, BitStringRef> = SubjectPublicKeyInfo::from_der(der)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Check that the algorithm OID matches Ed25519
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        // Reject algorithm parameters since Ed25519 permits none
        if info.algorithm.parameters.is_some() {
            return Err(Error::MalformedKey(
                "unexpected algorithm parameters".into(),
            ));
        }
        let bytes: &[u8; PUBLIC_KEY_SIZE] = info
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::MalformedKey("invalid public key bit string".into()))?;
        Self::from_bytes(bytes)
    }

    /// Parses an SPKI PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        Self::from_der(&data)
    }

    /// Returns the 32-byte public key encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Serializes the public key into SPKI DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_public_key_der().unwrap().as_bytes().to_vec()
    }

    /// Serializes the public key into SPKI PEM.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// Returns the 256-bit key fingerprint, computed as the SHA-256 hash of
    /// the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.to_bytes());
        Fingerprint(hasher.finalize().into())
    }

    /// Verifies `signature` over `message`.
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
    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<PUBLIC_KEY_SIZE>()?;
        Self::from_bytes(&bytes).map_err(|e| crate::cbor::Error::DecodeFailed(e.to_string()))
    }
}

/// An Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Converts a 64-byte array into a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Converts a signature into a 64-byte array.
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
    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<SIGNATURE_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// An Ed25519 key fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl Fingerprint {
    /// Converts a 32-byte array into a fingerprint.
    pub fn from_bytes(bytes: &[u8; FINGERPRINT_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Converts a fingerprint into a 32-byte array.
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

    /// Test vectors from RFC 8410 Sections 10.1 and 10.3.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8410>
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

    /// Tests that the RFC 8410 key vectors parse to the published seed,
    /// re-encode identically to PEM and DER, and derive the matching public key.
    #[test]
    fn test_ietf_vectors() {
        // Round-trip the secret key PEM and verify the expected seed
        let key = SecretKey::from_pem(ietf_vectors::SECKEY_PEM).unwrap();
        assert_eq!(hex::encode(*key.to_bytes()), ietf_vectors::SECKEY_SEED);
        assert_eq!(key.to_pem().trim(), ietf_vectors::SECKEY_PEM.trim());

        // Round-trip the secret key DER
        let (_, der) = pem::decode(ietf_vectors::SECKEY_PEM.as_bytes()).unwrap();
        assert_eq!(*key.to_der(), *der);

        // Verify the derived public key matches the published PEM
        assert_eq!(
            key.public_key().to_pem().trim(),
            ietf_vectors::PUBKEY_PEM.trim()
        );

        // Round-trip the public key PEM and DER
        let key = PublicKey::from_pem(ietf_vectors::PUBKEY_PEM).unwrap();
        assert_eq!(key.to_pem().trim(), ietf_vectors::PUBKEY_PEM.trim());

        let (_, der) = pem::decode(ietf_vectors::PUBKEY_PEM.as_bytes()).unwrap();
        assert_eq!(key.to_der(), *der);
    }

    /// Tests that the RFC 8410 v2 private key carrying an attribute and
    /// embedded public key is rejected, since only v1 keys are supported.
    #[test]
    fn test_ietf_v2_rejected() {
        assert!(SecretKey::from_pem(ietf_vectors::SECKEY_V2_PEM).is_err());
    }

    /// Tests verification with the original and altered messages, signatures, and keys.
    #[test]
    fn test_sign_verify() {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        let other = SecretKey::from_bytes(&[7; SECRET_KEY_SIZE]).public_key();
        let message = b"message to authenticate".as_slice();
        let signature = secret.sign(message);
        let mut tampered = signature;
        tampered.0[0] ^= 1;

        public.verify(message, &signature).unwrap();
        for (key, message, sig) in [
            (&public, b"changed".as_slice(), &signature),
            (&public, message, &tampered),
            (&other, message, &signature),
        ] {
            assert_eq!(key.verify(message, sig), Err(Error::InvalidSignature));
        }
    }

    /// Tests round-tripping a public key through JSON and CBOR.
    #[test]
    fn test_publickey_serde_roundtrip() {
        let key = SecretKey::from_bytes(&[7; SECRET_KEY_SIZE]).public_key();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), key);

        #[cfg(feature = "cbor")]
        {
            let bytes = crate::cbor::encode(&key).unwrap();
            assert_eq!(crate::cbor::decode::<PublicKey>(&bytes).unwrap(), key);
        }
    }

    /// Tests that Ed25519 SPKI keys must contain exactly 32 byte-aligned bytes.
    #[test]
    fn test_publickey_der_rejects_invalid_bit_strings() {
        let bytes = [0; PUBLIC_KEY_SIZE + 1];
        for (unused, len) in [
            (1, PUBLIC_KEY_SIZE),
            (0, PUBLIC_KEY_SIZE - 1),
            (0, PUBLIC_KEY_SIZE + 1),
        ] {
            let info = SubjectPublicKeyInfo {
                algorithm: spki::AlgorithmIdentifierRef {
                    oid: OID,
                    parameters: None,
                },
                subject_public_key: BitStringRef::new(unused, &bytes[..len]).unwrap(),
            };
            assert_eq!(
                PublicKey::from_der(&info.to_der().unwrap()),
                Err(Error::MalformedKey("invalid public key bit string".into()))
            );
        }
    }

    /// Tests that a public key whose algorithm identifier carries parameters is
    /// rejected.
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

    /// Tests that a private key whose algorithm identifier carries parameters is
    /// rejected.
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
