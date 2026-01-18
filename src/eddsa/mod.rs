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
use der::Encode;
use der::asn1::OctetString;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{SignatureError, Signer, Verifier};
use pkcs8::PrivateKeyInfo;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Digest;
use spki::ObjectIdentifier;
use spki::der::AnyRef;
use std::error::Error;

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

/// SecretKey contains an Ed25519 private key usable for signing.
#[derive(Clone)]
pub struct SecretKey {
    inner: ed25519_dalek::SigningKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut rng = OsRng;

        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        Self { inner: key }
    }

    /// from_bytes converts a 32-byte array into a private key.
    pub fn from_bytes(bin: &[u8; SECRET_KEY_SIZE]) -> Self {
        let key = ed25519_dalek::SecretKey::from(*bin);
        let sig = ed25519_dalek::SigningKey::from(&key);
        Self { inner: sig }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let info = PrivateKeyInfo::try_from(der)?;
        if info.public_key.is_some() {
            return Err("embedded public key not supported".into());
        }
        let inner = ed25519_dalek::SigningKey::from_pkcs8_der(der)?;
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        Self::from_der(&data)
    }

    /// to_bytes converts a private key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        // The private key field contains an OCTET STRING wrapping the seed
        let seed = OctetString::new(self.inner.to_bytes()).unwrap();
        let inner = seed.to_der().unwrap();

        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        let info = PrivateKeyInfo {
            algorithm: alg,
            private_key: &inner,
            public_key: None,
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PRIVATE KEY", &self.to_der())
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
    pub fn from_bytes(bin: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Box<dyn Error>> {
        let inner = ed25519_dalek::VerifyingKey::from_bytes(bin)?;
        Ok(Self { inner })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let inner = ed25519_dalek::VerifyingKey::from_public_key_der(der)?;
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
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
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.to_bytes());
        self.inner.verify(message, &sig)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Tests signing and verifying messages. Note, this test is not meant to test
    // cryptography, it is mostly an API sanity check to verify that everything
    // seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
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
}
