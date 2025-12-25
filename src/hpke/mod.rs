// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.

// We can't use Kem for our own type, it clashes with the hpke lib stuff. Let us
// keep our all-caps abbreviations.
#![allow(clippy::upper_case_acronyms)]

pub mod xwing;

#[cfg(feature = "cert")]
pub mod cert;

use hpke::rand_core::SeedableRng;
use hpke::{Deserializable, HpkeError, Kem, Serializable};
use pkcs8::PrivateKeyInfo;
use sha2::Digest;
use spki::der::asn1::{BitStringRef, OctetStringRef};
use spki::der::{AnyRef, Decode, Encode};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use std::error::Error;

// KEM, AEAD and KDF are the HPKE crypto suite parameters. They are all 256 bit
// variants, which should be enough for current purposes. Some details:
//
// - For the key exchange, X25519 was chosen vs. P256 due to uncertainty around
//   the curve parameters in P256 (i.e. unknown government influence).
// - For symmetric encryption, ChaCha20 was chosen, authenticated with Poly1305,
//   which should be more portable to systems without AES hardware acceleration.
// - For key derivation, HKDF was chosen (pretty much the only contender).
type KEM = hpke::kem::X25519HkdfSha256;
type AEAD = hpke::aead::ChaCha20Poly1305;
type KDF = hpke::kdf::HkdfSha256;

// INFO_PREFIX is the prefix of a public string known to both parties during any
// cryptographic operation, with the purpose of binding the keys used to some
// application context.
//
// The final info will be this prefix concatenated with another contextual info
// from an app layer action.
const INFO_PREFIX: &str = "dark-bio-v1:";

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

    /// from_bytes converts a 32-byte array into a private key.
    pub fn from_bytes(bin: &[u8; 32]) -> Self {
        let inner = <KEM as Kem>::PrivateKey::from_bytes(bin).unwrap();
        Self { inner }
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info = PrivateKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches X25519 (OID: 1.3.101.110) and extract
        // the actual private key
        if info.algorithm.oid.to_string() != "1.3.101.110" {
            panic!("not an X25519 private key");
        }
        if info.private_key[0] != 0x04 {
            panic!("private key not an octet string");
        }
        if info.private_key[1] != 0x20 {
            panic!("private key not a 32 byte octet string");
        }
        // Private key extracted, return the HKDF wrapper
        let bytes: [u8; 32] = info.private_key[2..].try_into()?;
        Ok(SecretKey::from_bytes(&bytes))
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

    /// to_bytes converts a private key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let bytes = self.inner.to_bytes();
        let encoded = OctetStringRef::new(&bytes).unwrap();

        // Create the X25519 algorithm identifier (OID 1.3.101.110); parameters
        // MUST be absent
        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.101.110"),
            parameters: None::<AnyRef>,
        };
        // The private key info is simply the BITSTRING of the key
        let info = PrivateKeyInfo {
            algorithm: alg,
            private_key: &encoded.to_der().unwrap(),
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
            inner: KEM::sk_to_pk(&self.inner),
        }
    }

    /// fingerprint returns a 256bit unique identified for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_key().fingerprint()
    }
}

/// PublicKey contains a public key of the type bound to the configured crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: <KEM as Kem>::PublicKey,
}

impl PublicKey {
    /// from_bytes converts a 32-byte array into a public key.
    pub fn from_bytes(bin: &[u8; 32]) -> Self {
        let inner = <KEM as Kem>::PublicKey::from_bytes(bin).unwrap();
        Self { inner }
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches X25519 (OID: 1.3.101.110) and extract
        // the actual public key
        if info.algorithm.oid.to_string() != "1.3.101.110" {
            panic!("not an X25519 public key");
        }
        let key = info.subject_public_key.as_bytes().unwrap();

        // Public key extracted, return the HKDF wrapper
        let bytes: [u8; 32] = key.try_into()?;
        Ok(PublicKey::from_bytes(&bytes))
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

    /// to_bytes converts a public key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let bytes = self.inner.to_bytes();

        // Create the X25519 algorithm identifier (OID 1.3.101.110); parameters
        // MUST be absent
        let alg = AlgorithmIdentifier::<AnyRef> {
            oid: ObjectIdentifier::new_unwrap("1.3.101.110"),
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
        let der = self.to_der();
        pem::encode_config(
            &pem::Pem::new("PUBLIC KEY", der),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }

    /// fingerprint returns a 256bit unique identified for this key. For HPKE,
    /// that is the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }
}

/// Context represents all contextual information for two parties to securely send
/// authenticated and encrypted messages to one another within a specific usage
/// domain.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    pub(crate) local: SecretKey,  // Secret key of the local entity
    pub(crate) remote: PublicKey, // Public key of the remote entity
    pub(crate) domain: String,    // Shared (sub-)domain for the HPKE info
}

impl Context {
    /// new constructs a new crypto context between a designated local and remote
    /// entity, also tied to a specific application domain.
    pub fn new(local: SecretKey, remote: PublicKey, domain: &str) -> Self {
        Self {
            local,
            remote,
            domain: INFO_PREFIX.to_string() + domain,
        }
    }

    /// seal creates a standalone cryptographic construct encrypted to the embedded
    /// remote identity and authenticated with the embedded local one. The construct
    /// will contain the given message-to-seal (encrypted) and also an authenticity
    /// proof for the (unencrypted) message-to-auth (message not included).
    ///
    /// The method returns an encapsulated session key (which may be used for stream
    /// communication but this method does not need it) concatenated with the cipher-
    /// text with the encrypted data and authenticity proofs. To open it on the other
    /// side needs transmitting the `concat-session-key-ciphertext` and `msg_to_auth`.
    ///
    /// This method (and open) requires the public keys of both parties to be pre-
    /// shared. It is not suitable for a key exchange protocol!
    pub fn seal(&self, msg_to_seal: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, HpkeError> {
        // Derive the public key for the sender. We could pass this along, but ugh,
        // such an ugly API honestly. Might as well recompute and yolo.
        let pubkey = KEM::sk_to_pk(&self.local.inner);

        // Create a random number stream that works in WASM
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("Failed to get random seed");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        // Create a sender session. We won't use it long term, just for a one-shot
        // message sealing.
        let (key, mut ctx) = hpke::setup_sender::<AEAD, KDF, KEM, _>(
            &hpke::OpModeS::Auth((self.local.inner.clone(), pubkey)),
            &self.remote.inner,
            self.domain.as_bytes(),
            &mut rng,
        )?;

        // Encrypt the messages and seal all the crypto details into a nice box
        let mut enc = ctx.seal(msg_to_seal, msg_to_auth)?;

        let mut res = key.to_bytes().to_vec();
        res.append(&mut enc);
        Ok(res)
    }

    /// open consumes a standalone cryptographic construct encrypted to the embedded
    /// local identity and authenticated with the embedded remote one. The method
    /// will deconstruct the give message-to-open (encrypted) and will also verify
    /// the authenticity of the (unencrypted) message-to-auth (not included in the
    /// ciphertext).
    ///
    /// This method (and seal) requires the public keys of both parties to be pre-
    /// shared. It is not suitable for a key exchange protocol!
    pub fn open(&self, msg_to_open: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, HpkeError> {
        // Split out the session key from the ciphertext
        let encapsize = <KEM as Kem>::PublicKey::size();
        if msg_to_open.len() < encapsize {
            return Err(HpkeError::OpenError);
        }
        let session = <KEM as Kem>::EncappedKey::from_bytes(&msg_to_open[0..encapsize])?;

        // Create a receiver session. We won't use it long term, just for a one-shot
        // message sealing.
        let mut ctx = hpke::setup_receiver::<AEAD, KDF, KEM>(
            &hpke::OpModeR::Auth(self.remote.inner.clone()),
            &self.local.inner,
            &session,
            self.domain.as_bytes(),
        )?;
        // Verify the construct and decrypt the message if everything checks out
        ctx.open(&msg_to_open[encapsize..], msg_to_auth)
    }

    /// sign is similar to creating a digital signature, but based on HPKE protocol.
    /// The resulting "signature" is not publicly verifiable, only by the intended
    /// recipient.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.seal(&[], message)
    }

    /// verify is similar to verifying a digital signature, but based on the HPKE
    /// protocol. The "signature" is not publicly verifiable, only by the intended
    /// recipient.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), HpkeError> {
        let body = self.open(signature, message)?;
        if !body.is_empty() {
            return Err(HpkeError::ValidationError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that a PEM encoded X25519 private key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_secretkey_pem_codec() {
        // Generated with:
        //   openssl genpkey -algorithm X25519 -out test.key
        let input = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIFAOSxZzmCL3ZE3NFjeYeZQbgxIk0xDwYGXy+7Qhv/Bi
-----END PRIVATE KEY-----";

        let key = SecretKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a PEM encoded X25519 public key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_publickey_pem_codec() {
        // Generated with:
        //   openssl pkey -in test.key -pubout -out test.pub
        let input = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEALSnOr8HqfB9flSD3+jad72mIarW0sMConGAvJ1wHMh0=
-----END PUBLIC KEY-----";

        let key = PublicKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a DER encoded X25519 private key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_secretkey_der_codec() {
        // Generated with:
        //   openssl pkey -in test.key -outform DER -out test.der
        //   cat test.der | xxd -p
        let input = "\
302e020100300506032b656e04220420500e4b16739822f7644dcd163798
79941b831224d310f06065f2fbb421bff062"
            .trim()
            .replace("\n", "");

        let der = hex::decode(&input).unwrap();
        let key = SecretKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
    }
    // Tests that a DER encoded X25519 public key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_publickey_der_codec() {
        // Generated with:
        //   openssl pkey -in test.key -pubout -out test.pub
        //   cat test.pub | xxd -p
        let input = "\
302a300506032b656e0321002d29ceafc1ea7c1f5f9520f7fa369def6988
6ab5b4b0c0a89c602f275c07321d"
            .trim()
            .replace("\n", "");

        let der = hex::decode(&input).unwrap();
        let key = PublicKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
    }

    // Tests sealing and opening various combinations of messages (authenticate,
    // encrypt, both). Note, this test is not meant to test cryptography, it is
    // mostly an API sanity check to verify that everything seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
    #[test]
    fn test_seal_open() {
        // Create the keys for Alice and Bobby
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        let alice_context = Context::new(alice_secret, bobby_public, "test");
        let bobby_context = Context::new(bobby_secret, alice_public, "test");

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
            // Seal the message using the test case data.
            let cipher = alice_context
                .seal(tt.seal_msg, tt.auth_msg)
                .unwrap_or_else(|e| panic!("failed to seal message: {}", e));

            // Open the sealed message.
            let cleartext = bobby_context
                .open(cipher.as_slice(), tt.auth_msg)
                .unwrap_or_else(|e| panic!("failed to open message: {}", e));

            // Validate that the cleartext matches our expected encrypted payload.
            assert_eq!(cleartext, tt.seal_msg, "unexpected cleartext");
        }
    }

    // Tests authenticating and verifying messages. Note, this test is not meant to
    // test cryptography, it is mostly an API sanity check to verify that everything
    // seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
    #[test]
    fn test_sign_verify() {
        // Create the keys for Alice and Bobby
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        let alice_context = Context::new(alice_secret, bobby_public, "test");
        let bobby_context = Context::new(bobby_secret, alice_public, "test");

        // Run a bunch of different authentication/encryption combinations
        struct TestCase<'a> {
            message: &'a [u8],
        }
        let tests = [TestCase {
            message: b"message to authenticate",
        }];

        for tt in &tests {
            // Sign the message using the test case data
            let signature = alice_context
                .sign(tt.message)
                .unwrap_or_else(|e| panic!("failed to auth message: {}", e));

            // Verify the signature message
            bobby_context
                .verify(tt.message, signature.as_slice())
                .unwrap_or_else(|e| panic!("failed to verify message: {}", e));
        }
    }
}
