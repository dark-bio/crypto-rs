// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! EdDSA cryptography wrappers and parametrization.

use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, Error,
};
use ed25519_dalek::{Signature, SignatureError, Signer, Verifier};

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
    pub fn from_bytes(bin: &[u8; 32]) -> Self {
        let key = ed25519_dalek::SecretKey::from(*bin);
        let sig = ed25519_dalek::SigningKey::from(&key);
        Self { inner: sig }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let inner = ed25519_dalek::SigningKey::from_pkcs8_der(der)?;
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let inner = ed25519_dalek::SigningKey::from_pkcs8_pem(pem)?;
        Ok(Self { inner })
    }

    /// to_bytes converts a private key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> String {
        self.inner.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// sign creates a digital signature of the message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).to_vec()
    }
}

/// PublicKey contains an Ed25519 public key usable for verification.
#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// from_bytes converts a 32-byte array into a public key.
    pub fn from_bytes(bin: &[u8; 32]) -> Self {
        let inner = ed25519_dalek::VerifyingKey::from_bytes(bin).unwrap();
        Self { inner }
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let inner = ed25519_dalek::VerifyingKey::from_public_key_der(der)?;
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let inner = ed25519_dalek::VerifyingKey::from_public_key_pem(pem)?;
        Ok(Self { inner })
    }

    /// to_bytes converts a public key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_public_key_der().unwrap().as_bytes().to_vec()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        self.inner
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    /// fingerprint returns a 256bit unique identified for this key. For Ed25519,
    /// that is the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.to_bytes()
    }

    /// verify verifies a digital signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let sig = Signature::try_from(signature)?;
        self.inner.verify(message, &sig)
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
                .verify(tt.message, signature.as_slice())
                .unwrap_or_else(|e| panic!("failed to verify message: {}", e));
        }
    }
}
