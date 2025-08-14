// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.

use hpke::rand_core::SeedableRng;
use hpke::{Deserializable, HpkeError, Kem, Serializable};

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

    /// to_bytes converts a private key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: KEM::sk_to_pk(&self.inner),
        }
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

    /// to_bytes converts a public key into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// fingerprint returns a 256bit unique identified for this key. For HPKE,
    /// that is the raw public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.to_bytes()
    }
}

/// Context represents all contextual information for two parties to securely send
/// authenticated and encrypted messages to one another within a specific usage
/// domain.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    local: SecretKey,  // Secret key of the local entity
    remote: PublicKey, // Public key of the remote entity
    domain: String,    // Shared (sub-)domain for the HPKE info
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
    /// side needs transmitting the <concat-session-key-ciphertext> and <msg_to_auth>.
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
        if body.len() != 0 {
            return Err(HpkeError::ValidationError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // Tests signing and verifying messages. Note, this test is not meant to test
    // cryptography, it is mostly an API sanity check to verify that everything
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
                .unwrap_or_else(|e| panic!("failed to sign message: {}", e));

            // Verify the signature message
            bobby_context
                .verify(tt.message, signature.as_slice())
                .unwrap_or_else(|e| panic!("failed to verify message: {}", e));
        }
    }
}
