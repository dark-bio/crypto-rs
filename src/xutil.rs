// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! High-level cryptographic utils combining xDSA signing and xHPKE encryption.

use crate::{cbor, xdsa, xhpke};
use std::error::Error;

/// sign_and_encrypt signs a message with the sender's xDSA key, then encrypts
/// the message and signature together to the recipient's xHPKE key.
///
/// - `msg_to_seal`: The message to sign and encrypt (included in ciphertext)
/// - `msg_to_auth`: Additional data to authenticate but not encrypt (not embedded)
///
/// The cleartext is encoded as CBOR(msg_to_seal, signature) before encryption.
pub fn sign_and_encrypt(
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    sender: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signature = sender.sign(msg_to_seal);
    let cleartext = cbor::encode(&(msg_to_seal, &signature));

    recipient
        .seal(&cleartext, msg_to_auth, domain)
        .map_err(|e| e.into())
}

/// decrypt_and_verify decrypts a ciphertext with the recipient's xHPKE key, then
/// verifies the embedded signature against the sender's xDSA key.
///
/// - `msg_to_open`: The ciphertext to decrypt
/// - `msg_to_auth`: The same additional authenticated data used during encryption
///
/// Returns the original message if decryption and verification succeed.
pub fn decrypt_and_verify(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cleartext = recipient.open(msg_to_open, msg_to_auth, domain)?;
    let (message, signature): (Vec<u8>, [u8; 3373]) = cbor::decode(&cleartext)?;

    sender.verify(&message, &signature)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that the happy path encryption/decryption works.
    #[test]
    fn test_sign_encrypt_decrypt_verify() {
        let alice_xdsa = xdsa::SecretKey::generate();
        let bob_xhpke = xhpke::SecretKey::generate();

        let ciphertext = sign_and_encrypt(
            b"Hello Bob!",
            b"some auth data",
            &alice_xdsa,
            &bob_xhpke.public_key(),
            "test-crypto-domain",
        )
        .unwrap();

        let res = decrypt_and_verify(
            &ciphertext,
            b"some auth data",
            &bob_xhpke,
            &alice_xdsa.public_key(),
            "test-crypto-domain",
        )
        .unwrap();

        assert_eq!(res, b"Hello Bob!");
    }

    // Tests that decryption fails with the wrong crypto domain.
    #[test]
    fn test_wrong_domain() {
        let alice_xdsa = xdsa::SecretKey::generate();
        let bob_xhpke = xhpke::SecretKey::generate();

        let ciphertext = sign_and_encrypt(
            b"Hello Bob!",
            &[],
            &alice_xdsa,
            &bob_xhpke.public_key(),
            "test-crypto-domain",
        )
        .unwrap();

        let result = decrypt_and_verify(
            &ciphertext,
            &[],
            &bob_xhpke,
            &alice_xdsa.public_key(),
            "wrong-crypto-domain",
        );
        assert!(result.is_err());
    }

    // Tests that decryption fails with the wrong authentication data.

    #[test]
    fn test_wrong_auth() {
        let alice_xdsa = xdsa::SecretKey::generate();
        let bob_xhpke = xhpke::SecretKey::generate();

        let ciphertext = sign_and_encrypt(
            b"Hello Bob!",
            b"some auth data",
            &alice_xdsa,
            &bob_xhpke.public_key(),
            "test-crypto-domain",
        )
        .unwrap();

        let result = decrypt_and_verify(
            &ciphertext,
            b"wrong auth data",
            &bob_xhpke,
            &alice_xdsa.public_key(),
            "test-crypto-domain",
        );
        assert!(result.is_err());
    }

    // Tests that verification fails with a bad signer.
    #[test]
    fn test_wrong_signature() {
        let alice_xdsa = xdsa::SecretKey::generate();
        let bob_xhpke = xhpke::SecretKey::generate();
        let eve_xdsa = xdsa::SecretKey::generate();

        let ciphertext = sign_and_encrypt(
            b"Hello Bob!",
            &[],
            &alice_xdsa,
            &bob_xhpke.public_key(),
            "test-crypto-domain",
        )
        .unwrap();

        let result = decrypt_and_verify(
            &ciphertext,
            &[],
            &bob_xhpke,
            &eve_xdsa.public_key(),
            "test-crypto-domain",
        );
        assert!(result.is_err());
    }
}
