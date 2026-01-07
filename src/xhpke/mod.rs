// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9180

// We can't use Kem for our own type, it clashes with the hpke lib stuff. Let us
// keep our all-caps abbreviations.
#![allow(clippy::upper_case_acronyms)]

pub mod cert;
pub mod xwing;

use crate::pem;
use hpke::rand_core::SeedableRng;
use hpke::{Deserializable, HpkeError, Kem, Serializable};
use pkcs8::PrivateKeyInfo;
use sha2::Digest;
use spki::der::asn1::BitStringRef;
use spki::der::{AnyRef, Decode, Encode};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use std::error::Error;

// KEM, AEAD and KDF are the HPKE crypto suite parameters. They are all 256 bit
// variants, which should be enough for current purposes. Some details:
//
// - For the key exchange, X-Wing was chosen as a hybrid post-quantum KEM that
//   combines X25519 with ML-KEM-768 for quantum resistance.
// - For symmetric encryption, ChaCha20 was chosen, authenticated with Poly1305,
//   which should be more portable to systems without AES hardware acceleration.
// - For key derivation, HKDF was chosen (pretty much the only contender).
type KEM = xwing::Kem;
type AEAD = hpke::aead::ChaCha20Poly1305;
type KDF = hpke::kdf::HkdfSha256;

// INFO_PREFIX is the prefix of a public string known to both parties during any
// cryptographic operation, with the purpose of binding the keys used to some
// application context.
//
// The final info will be this prefix concatenated with another contextual info
// from an app layer action.
const INFO_PREFIX: &[u8] = b"dark-bio-v1:";

/// Size of the secret key seed in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1216;

/// Size of the encapsulated key in bytes.
pub const ENCAP_KEY_SIZE: usize = 1120;

/// SecretKey contains a private key of the type bound to the configured crypto.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    inner: <KEM as Kem>::PrivateKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut rng = rand::rng();

        let (key, _) = KEM::gen_keypair(&mut rng);
        Self { inner: key }
    }

    /// from_bytes converts a 32-byte seed into a private key.
    pub fn from_bytes(bin: &[u8; SECRET_KEY_SIZE]) -> Self {
        let inner = <KEM as Kem>::PrivateKey::from_bytes(bin).unwrap();
        Self { inner }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info = PrivateKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches X-Wing and extract the actual private key
        if info.algorithm.oid.to_string() != "1.3.6.1.4.1.62253.25722" {
            return Err("not an X-Wing private key".into());
        }
        let bytes: [u8; 32] = info.private_key.try_into()?;
        Ok(SecretKey::from_bytes(&bytes))
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the private key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes converts a private key into a 32-byte seed.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.inner.to_bytes().into()
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let bytes = self.inner.to_bytes();

        // Create the X-Wing algorithm identifier; parameters MUST be absent
        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62253.25722"),
            parameters: None::<AnyRef>,
        };
        // Per RFC, privateKey contains the raw 32-byte seed directly
        let info = PrivateKeyInfo {
            algorithm: alg,
            private_key: &bytes,
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
            inner: KEM::sk_to_pk(&self.inner),
        }
    }

    /// fingerprint returns a 256bit unique identifier for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_key().fingerprint()
    }

    /// open consumes a standalone cryptographic construct encrypted to this secret
    /// key. The method will deconstruct the given encapsulated key and ciphertext
    /// and will also verify the authenticity of the (unencrypted) message-to-auth
    /// (not included in the ciphertext).
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The sender's identity
    /// cannot be verified from the ciphertext alone.
    pub fn open(
        &self,
        session_key: &[u8; ENCAP_KEY_SIZE],
        msg_to_open: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let info = [INFO_PREFIX, domain].concat();

        // Parse the encapsulated session key
        let session = <KEM as Kem>::EncappedKey::from_bytes(session_key)?;

        // Create a receiver session using Base mode (X-Wing doesn't support Auth mode)
        let mut ctx = hpke::setup_receiver::<AEAD, KDF, KEM>(
            &hpke::OpModeR::Base,
            &self.inner,
            &session,
            &info,
        )?;
        // Verify the construct and decrypt the message if everything checks out
        ctx.open(msg_to_open, msg_to_auth)
    }
}

/// PublicKey contains a public key of the type bound to the configured crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: <KEM as Kem>::PublicKey,
}

impl PublicKey {
    /// from_bytes converts a 1216-byte array into a public key.
    ///
    /// This validates the ML-KEM-768 component by checking that all polynomial
    /// coefficients are in the valid range [0, 3329). This matches Go's validation.
    pub fn from_bytes(bin: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Box<dyn Error>> {
        // Validate ML-KEM-768 encapsulation key (first 1184 bytes).
        // The key contains 3 polynomials of 256 coefficients each, encoded as 12-bit values.
        // Each coefficient must be < 3329 (the modulus q).
        validate_mlkem768_encapsulation_key(&bin[..1184])?;

        let inner = <KEM as Kem>::PublicKey::from_bytes(bin)?;
        Ok(Self { inner })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches X-Wing and extract the actual public key
        if info.algorithm.oid.to_string() != "1.3.6.1.4.1.62253.25722" {
            return Err("not an X-Wing public key".into());
        }
        let key = info.subject_public_key.as_bytes().unwrap();

        // Public key extracted, return the wrapper
        let bytes: [u8; 1216] = key.try_into()?;
        PublicKey::from_bytes(&bytes)
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the public key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes converts a public key into a 1216-byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut result = [0u8; 1216];
        result.copy_from_slice(&self.inner.to_bytes());
        result
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let bytes = self.inner.to_bytes();

        // Create the X-Wing algorithm identifier; parameters MUST be absent
        let alg = AlgorithmIdentifier::<AnyRef> {
            oid: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62253.25722"),
            parameters: None::<AnyRef>,
        };
        // The subject public key is simply the BITSTRING of the pubkey
        let info = SubjectPublicKeyInfo::<AnyRef, BitStringRef> {
            algorithm: alg,
            subject_public_key: BitStringRef::from_bytes(&bytes).unwrap(),
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identifier for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }

    /// seal creates a standalone cryptographic construct encrypted to this public
    /// key. The construct will contain the given message-to-seal (encrypted) and
    /// also an authenticity proof for the (unencrypted) message-to-auth (message
    /// not included).
    ///
    /// The method returns the encapsulated session key and the ciphertext separately.
    /// To open it on the other side needs transmitting both components along with
    /// `msg_to_auth`.
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The recipient cannot
    /// verify the sender's identity from the ciphertext alone.
    pub fn seal(
        &self,
        msg_to_seal: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<([u8; ENCAP_KEY_SIZE], Vec<u8>), HpkeError> {
        let info = [INFO_PREFIX, domain].concat();

        // Create a random number stream that works in WASM
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("Failed to get random seed");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        // Create a sender session using Base mode (X-Wing doesn't support Auth mode)
        let (key, mut ctx) = hpke::setup_sender::<AEAD, KDF, KEM, _>(
            &hpke::OpModeS::Base,
            &self.inner,
            &info,
            &mut rng,
        )?;

        // Encrypt the messages and seal all the crypto details into a nice box
        let enc = ctx.seal(msg_to_seal, msg_to_auth)?;

        let mut encap_key = [0u8; 1120];
        encap_key.copy_from_slice(&key.to_bytes());
        Ok((encap_key, enc))
    }
}

/// Validates an ML-KEM-768 encapsulation key by checking that all polynomial
/// coefficients are in the valid range [0, 3329).
///
/// The encapsulation key is 1184 bytes: 3 polynomials × 256 coefficients × 12 bits
/// = 1152 bytes for the coefficient vectors, plus 32 bytes for the seed ρ.
fn validate_mlkem768_encapsulation_key(key: &[u8]) -> Result<(), Box<dyn Error>> {
    const Q: u16 = 3329;

    // Process 3 bytes at a time (24 bits = 2 coefficients of 12 bits each)
    // Only validate the first 1152 bytes (the polynomial coefficients)
    let coeff_bytes = &key[..1152];
    for chunk in coeff_bytes.chunks(3) {
        // Decode two 12-bit coefficients from 3 bytes (little-endian)
        let coeff1 = u16::from(chunk[0]) | ((u16::from(chunk[1]) & 0x0F) << 8);
        let coeff2 = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);

        if coeff1 >= Q {
            return Err(format!("invalid ML-KEM coefficient: {} >= {}", coeff1, Q).into());
        }
        if coeff2 >= Q {
            return Err(format!("invalid ML-KEM coefficient: {} >= {}", coeff2, Q).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that a private key can be serialized to bytes and parsed back.
    #[test]
    fn test_secretkey_bytes_roundtrip() {
        let key = SecretKey::generate();
        let bytes = key.to_bytes();
        let parsed = SecretKey::from_bytes(&bytes);
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to bytes and parsed back.
    #[test]
    fn test_publickey_bytes_roundtrip() {
        let key = SecretKey::generate().public_key();
        let bytes = key.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a private key can be serialized to DER and parsed back.
    #[test]
    fn test_secretkey_der_roundtrip() {
        let key = SecretKey::generate();
        let der = key.to_der();
        let parsed = SecretKey::from_der(&der).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a private key can be serialized to PEM and parsed back.
    #[test]
    fn test_secretkey_pem_roundtrip() {
        let key = SecretKey::generate();
        let pem = key.to_pem();
        let parsed = SecretKey::from_pem(&pem).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to DER and parsed back.
    #[test]
    fn test_publickey_der_roundtrip() {
        let key = SecretKey::generate().public_key();
        let der = key.to_der();
        let parsed = PublicKey::from_der(&der).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to PEM and parsed back.
    #[test]
    fn test_publickey_pem_roundtrip() {
        let key = SecretKey::generate().public_key();
        let pem = key.to_pem();
        let parsed = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests sealing and opening various combinations of messages (authenticate,
    // encrypt, both). Note, this test is not meant to test cryptography, it is
    // mostly an API sanity check to verify that everything seems to work.
    #[test]
    fn test_seal_open() {
        // Create the keys
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Run a bunch of different authentication/encryption combinations
        struct TestCase<'a> {
            seal_msg: &'a [u8],
            auth_msg: &'a [u8],
        }
        let tests = [
            // Only message to authenticate
            TestCase {
                seal_msg: &[],
                auth_msg: b"message to authenticate",
            },
            // Only message to encrypt
            TestCase {
                seal_msg: b"message to encrypt",
                auth_msg: &[],
            },
            // Both message to authenticate and to encrypt
            TestCase {
                seal_msg: b"message to encrypt",
                auth_msg: b"message to authenticate",
            },
        ];

        for tt in &tests {
            // Seal the message to the public key
            let (sess_key, seal_msg) = public
                .seal(tt.seal_msg, tt.auth_msg, b"test")
                .unwrap_or_else(|e| panic!("failed to seal message: {}", e));

            // Open the sealed message with the secret key
            let cleartext = secret
                .open(&sess_key, &seal_msg, tt.auth_msg, b"test")
                .unwrap_or_else(|e| panic!("failed to open message: {}", e));

            // Validate that the cleartext matches our expected encrypted payload
            assert_eq!(cleartext, tt.seal_msg, "unexpected cleartext");
        }
    }
}
