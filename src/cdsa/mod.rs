// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composite ML-DSA cryptography wrappers and parametrization.

use crate::{eddsa, mldsa};
use der::asn1::BitStringRef;
use der::{AnyRef, Decode, Encode};
use sha2::Digest;
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use std::error::Error;

/// Prefix is the byte encoding of "CompositeAlgorithmSignatures2025" per the
/// IETF composite signature spec.
const SIGNATURE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Label is the signature label for ML-DSA-65-Ed25519-SHA512.
const SIGNATURE_DOMAIN: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// SecretKey is an ML-DSA-65 private key paired with an Ed25519 private key for
/// creating and verifying quantum resistant digital signatures.    
#[derive(Clone)]
pub struct SecretKey {
    ml_key: mldsa::SecretKey,
    ed_key: eddsa::SecretKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        SecretKey {
            ml_key: mldsa::SecretKey::generate(),
            ed_key: eddsa::SecretKey::generate(),
        }
    }

    /// from_seed creates a private key from a 64-byte seed.
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let ml_seed: [u8; 32] = seed[..32].try_into().unwrap();
        let ed_seed: [u8; 32] = seed[32..].try_into().unwrap();

        Self {
            ml_key: mldsa::SecretKey::from_seed(&ml_seed),
            ed_key: eddsa::SecretKey::from_bytes(&ed_seed),
        }
    }

    /// from_bytes creates a private key from a 4064-byte expanded key.
    pub fn from_bytes(bytes: &[u8; 4064]) -> Self {
        let ml_bytes: [u8; 4032] = bytes[..4032].try_into().unwrap();
        let ed_seed: [u8; 32] = bytes[4032..].try_into().unwrap();

        Self {
            ml_key: mldsa::SecretKey::from_bytes(&ml_bytes),
            ed_key: eddsa::SecretKey::from_bytes(&ed_seed),
        }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info = pkcs8::PrivateKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48)
        if info.algorithm.oid.to_string() != "1.3.6.1.5.5.7.6.48" {
            return Err("not a composite ML-DSA-65-Ed25519-SHA512 private key".into());
        }
        // Private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
        let key_bytes = info.private_key;
        if key_bytes.len() != 64 {
            return Err("composite private key must be 64 bytes".into());
        }
        let ml_seed: [u8; 32] = key_bytes[..32].try_into()?;
        let ed_seed: [u8; 32] = key_bytes[32..64].try_into()?;

        let ml_key = mldsa::SecretKey::from_seed(&ml_seed);
        let ed_key = eddsa::SecretKey::from_bytes(&ed_seed);

        Ok(Self { ml_key, ed_key })
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the private key info
        let res = pem::parse(pem.as_bytes())?;
        if res.tag() != "PRIVATE KEY" {
            return Err(format!("invalid PEM tag {}", res.tag()).into());
        }
        // Parse the DER content
        Self::from_der(res.contents())
    }

    /// to_seed converts a secret key into a 64-byte seed.
    pub fn to_seed(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ml_key.to_seed());
        out[32..].copy_from_slice(&self.ed_key.to_bytes());
        out
    }

    /// to_bytes converts a secret key into a 4064-byte array.
    pub fn to_bytes(&self) -> [u8; 4064] {
        let mut out = [0u8; 4064];
        out[..4032].copy_from_slice(&self.ml_key.to_bytes());
        out[4032..].copy_from_slice(&self.ed_key.to_bytes());
        out
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        // Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
        // MUST be absent
        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48"),
            parameters: None,
        };
        // The private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
        let mut key_bytes = Vec::with_capacity(64);
        key_bytes.extend_from_slice(&self.ml_key.to_seed());
        key_bytes.extend_from_slice(&self.ed_key.to_bytes());

        let info = pkcs8::PrivateKeyInfo {
            algorithm: alg,
            private_key: &key_bytes,
            public_key: None,
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        pem::encode_config(
            &pem::Pem::new("PRIVATE KEY", der),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            ml_key: self.ml_key.public_key(),
            ed_key: self.ed_key.public_key(),
        }
    }

    /// fingerprint returns a 256bit unique identifier for this key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_key().fingerprint()
    }

    /// sign creates a digital signature of the message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        // Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
        // where ctx is empty and PH is SHA512
        let mut hasher = sha2::Sha512::new();
        hasher.update(message);
        let prehash: [u8; 64] = hasher.finalize().into();

        let mut m_prime =
            Vec::with_capacity(SIGNATURE_PREFIX.len() + SIGNATURE_DOMAIN.len() + 1 + 64);
        m_prime.extend_from_slice(SIGNATURE_PREFIX);
        m_prime.extend_from_slice(SIGNATURE_DOMAIN);
        m_prime.push(0); // len(ctx) = 0, no ctx bytes follow
        m_prime.extend_from_slice(&prehash);

        // Sign M' with both algorithms
        let ml_sig = self.ml_key.sign(&m_prime, SIGNATURE_DOMAIN);
        let ed_sig = self.ed_key.sign(&m_prime);

        // Concatenate: ML-DSA-65 (3309 bytes) || Ed25519 (64 bytes)
        let mut sig = Vec::with_capacity(3309 + 64);
        sig.extend_from_slice(&ml_sig);
        sig.extend_from_slice(&ed_sig);
        sig
    }
}

/// PublicKey is an ML-DSA-65 public key paired with an Ed25519 public key for
/// verifying quantum resistant digital signatures.
#[derive(Debug, Clone)]
pub struct PublicKey {
    ml_key: mldsa::PublicKey,
    ed_key: eddsa::PublicKey,
}

impl PublicKey {
    /// from_bytes converts a 1984-byte array into a public key.
    pub fn from_bytes(bytes: &[u8; 1984]) -> Self {
        let ml_bytes: [u8; 1952] = bytes[..1952].try_into().unwrap();
        let ed_bytes: [u8; 32] = bytes[1952..].try_into().unwrap();

        Self {
            ml_key: mldsa::PublicKey::from_bytes(&ml_bytes),
            ed_key: eddsa::PublicKey::from_bytes(&ed_bytes),
        }
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48)
        if info.algorithm.oid.to_string() != "1.3.6.1.5.5.7.6.48" {
            return Err("not a composite ML-DSA-65-Ed25519-SHA512 public key".into());
        }
        // Public key is ML-DSA-65 (1952 bytes) || Ed25519 (32 bytes) = 1984 bytes
        let key_bytes = info.subject_public_key.as_bytes().unwrap();
        if key_bytes.len() != 1984 {
            return Err("composite public key must be 1984 bytes".into());
        }
        let ml_bytes: [u8; 1952] = key_bytes[..1952].try_into()?;
        let ed_bytes: [u8; 32] = key_bytes[1952..].try_into()?;

        let ml_key = mldsa::PublicKey::from_bytes(&ml_bytes);
        let ed_key = eddsa::PublicKey::from_bytes(&ed_bytes);

        Ok(Self { ml_key, ed_key })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the public key info
        let res = pem::parse(pem.as_bytes())?;
        if res.tag() != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", res.tag()).into());
        }
        // Parse the DER content
        Self::from_der(res.contents())
    }

    /// to_bytes converts a public key into a 1984-byte array.
    pub fn to_bytes(&self) -> [u8; 1984] {
        let mut out = [0u8; 1984];
        out[..1952].copy_from_slice(&self.ml_key.to_bytes());
        out[1952..].copy_from_slice(&self.ed_key.to_bytes());
        out
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        // Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
        // MUST be absent
        let alg = spki::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48"),
            parameters: None,
        };
        // The public key info is the BITSTRING of the two keys concatenated
        let mut key_bytes = Vec::with_capacity(1984);
        key_bytes.extend_from_slice(&self.ml_key.to_bytes());
        key_bytes.extend_from_slice(&self.ed_key.to_bytes());

        let info = SubjectPublicKeyInfo::<AnyRef, BitStringRef> {
            algorithm: alg,
            subject_public_key: BitStringRef::from_bytes(&key_bytes).unwrap(),
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        pem::encode_config(
            &pem::Pem::new("PUBLIC KEY", der),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }

    /// fingerprint returns a 256bit unique identifier for this key.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.ml_key.to_bytes());
        hasher.update(self.ed_key.to_bytes());
        hasher.finalize().into()
    }

    /// verify verifies a digital signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; 3373]) -> Result<(), Box<dyn Error>> {
        // Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
        // where ctx is empty and PH is SHA512
        let mut hasher = sha2::Sha512::new();
        hasher.update(message);
        let prehash: [u8; 64] = hasher.finalize().into();

        let mut m_prime =
            Vec::with_capacity(SIGNATURE_PREFIX.len() + SIGNATURE_DOMAIN.len() + 1 + 64);
        m_prime.extend_from_slice(SIGNATURE_PREFIX);
        m_prime.extend_from_slice(SIGNATURE_DOMAIN);
        m_prime.push(0); // len(ctx) = 0, no ctx bytes follow
        m_prime.extend_from_slice(&prehash);

        // Split and verify both signatures
        let ml_sig = &signature[..3309];
        let ed_sig = &signature[3309..];

        self.ml_key.verify(&m_prime, SIGNATURE_DOMAIN, ml_sig)?;
        self.ed_key.verify(&m_prime, ed_sig)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from draft-ietf-lamps-pq-composite-sigs-latest Appendix E
    // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
    pub const TEST_SECKEY: &str =
        "15uFQa8YW3u2HqmcMC3xHSt2DLiqHQYovoiCqC2HWJyEIQy28ZxuuzKZK1lEDrf01cddUOvhwY9V7RboVl41KQ==";
    pub const TEST_SECKEY_PKCS8: &str = "MFECAQAwCgYIKwYBBQUHBjAEQNebhUGvGFt7th6pnDAt8R0rdgy4qh0GKL6Igqgth1ichCEMtvGcbrsymStZRA639NXHXVDr4cGPVe0W6FZeNSk=";
    pub const TEST_PUBKEY: &str = "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";
    pub const TEST_MSG: &str = "The quick brown fox jumps over the lazy dog.";
    pub const TEST_SIG: &str = "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";

    use base64::prelude::*;

    // Tests operations with IETF test vectors.
    #[test]
    fn test_ietf_vectors() {
        // Parse the secret key seed (ML-DSA seed || Ed25519 seed)
        let seed_bytes = BASE64_STANDARD.decode(TEST_SECKEY).unwrap();
        let seed: [u8; 64] = seed_bytes.try_into().unwrap();
        let seckey = SecretKey::from_seed(&seed);

        // Verify the public key matches (ML-DSA || Ed25519)
        let expected_pubkey = BASE64_STANDARD.decode(TEST_PUBKEY).unwrap();
        let pubkey = seckey.public_key();
        assert_eq!(pubkey.to_bytes().to_vec(), expected_pubkey);

        // Sign and verify (ML-DSA uses randomized signing, so we can't compare bytes)
        let signature = seckey.sign(TEST_MSG.as_bytes());
        let sig_array: [u8; 3373] = signature.try_into().unwrap();
        pubkey.verify(TEST_MSG.as_bytes(), &sig_array).unwrap();

        // Verify the IETF test signature can be verified
        let expected_sig = BASE64_STANDARD.decode(TEST_SIG).unwrap();
        let expected_sig_array: [u8; 3373] = expected_sig.try_into().unwrap();
        pubkey
            .verify(TEST_MSG.as_bytes(), &expected_sig_array)
            .unwrap();
    }

    #[test]
    fn test_pkcs8_encoding() {
        // Parse the secret key from seed and from PKCS8
        let seed_bytes = BASE64_STANDARD.decode(TEST_SECKEY).unwrap();
        let seed: [u8; 64] = seed_bytes.try_into().unwrap();
        let seckey_from_seed = SecretKey::from_seed(&seed);

        let pkcs8_bytes = BASE64_STANDARD.decode(TEST_SECKEY_PKCS8).unwrap();
        let seckey_from_pkcs8 = SecretKey::from_der(&pkcs8_bytes).unwrap();

        // Both should produce the same public key
        assert_eq!(
            seckey_from_seed.public_key().to_bytes(),
            seckey_from_pkcs8.public_key().to_bytes()
        );

        // Re-encoding to DER should match the test vector
        let encoded_der = seckey_from_seed.to_der();
        assert_eq!(encoded_der, pkcs8_bytes);

        // Round-trip: decode and re-encode
        let roundtrip = SecretKey::from_der(&encoded_der).unwrap();
        assert_eq!(roundtrip.to_der(), encoded_der);
    }
}
