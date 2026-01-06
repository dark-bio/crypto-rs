// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wrappers for xDSA and xHPKE.
//!
//! https://datatracker.ietf.org/doc/html/rfc8152
//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke

mod types;

pub use types::{
    CoseEncrypt0, CoseSign1, ENCAP_KEY_SIZE, EmptyHeader, EncStructure, EncapKeyHeader,
    ProtectedHeader, SIGNATURE_SIZE, SigStructure,
};

use crate::cbor::{self, Encode};
use crate::{xdsa, xhpke};

/// Error is the failures that can occur during COSE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("cbor: {0}")]
    Cbor(#[from] cbor::Error),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("unexpected algorithm: have {0}, want {1}")]
    UnexpectedProtectedHeaderAlgorithm(i64, i64),
    #[error("invalid encapsulated key size: {0}, expected {1}")]
    InvalidEncapKeySize(usize, usize),
}

/// Private COSE algorithm identifier for composite ML-DSA-65 + Ed25519 signatures.
pub const ALGORITHM_ID_XDSA: i64 = -70000;

/// Private COSE algorithm identifier for X-Wing (ML-KEM-768 + X25519).
pub const ALGORITHM_ID_XHPKE: i64 = -70001;

/// sign creates a COSE_Sign1 digital signature of the msg_to_embed.
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign(msg_to_embed: &[u8], msg_to_auth: &[u8], signer: &xdsa::SecretKey) -> Vec<u8> {
    // Build protected header
    let protected = cbor::encode(&ProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
    });

    // Build and sign Sig_structure
    let signature = signer.sign(
        &SigStructure {
            context: "Signature1".to_string(),
            protected: protected.clone(),
            external_aad: msg_to_auth.to_vec(),
            payload: msg_to_embed.to_vec(),
        }
        .encode_cbor(),
    );
    // Build and encode COSE_Sign1
    cbor::encode(&CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: msg_to_embed.to_vec(),
        signature,
    })
}

/// verify validates a COSE_Sign1 digital signature and returns the payload.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
///
/// Returns the embedded payload if verification succeeds.
pub fn verify(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &xdsa::PublicKey,
) -> Result<Vec<u8>, Error> {
    // Parse COSE_Sign1
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;

    // Verify the protected header
    verify_protected_header(&sign1.protected, ALGORITHM_ID_XDSA)?;

    // Reconstruct Sig_structure to verify
    let blob = SigStructure {
        context: "Signature1".to_string(),
        protected: sign1.protected.clone(),
        external_aad: msg_to_auth.to_vec(),
        payload: sign1.payload.clone(),
    }
    .encode_cbor();

    // Verify signature
    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::Signature(e.to_string()))?;

    Ok(sign1.payload)
}

/// seal signs a message then encrypts it to a recipient.
///
/// - `msg_to_seal`: The message to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
pub fn seal(
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    // Create a COSE_Sign1 with the payload, binding the AAD
    let signed = sign(msg_to_seal, msg_to_auth, signer);

    // Build protected header
    let protected = cbor::encode(&ProtectedHeader {
        algorithm: ALGORITHM_ID_XHPKE,
    });

    // Build and seal Enc_structure
    let (encap_key, ciphertext) = recipient
        .seal(
            &signed,
            &EncStructure {
                context: "Encrypt0".to_string(),
                protected: protected.clone(),
                external_aad: msg_to_auth.to_vec(),
            }
            .encode_cbor(),
            domain,
        )
        .map_err(|e| Error::Decryption(e.to_string()))?;

    // Build and encode COSE_Encrypt0
    Ok(cbor::encode(&CoseEncrypt0 {
        protected,
        unprotected: EncapKeyHeader {
            encap_key: encap_key.to_vec(),
        },
        ciphertext,
    }))
}

/// open decrypts and verifies a sealed message.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the original payload if decryption and verification succeed.
pub fn open(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    // Parse COSE_Encrypt0
    let encrypt0: CoseEncrypt0 = cbor::decode(msg_to_open)?;

    // Verify protected header
    verify_protected_header(&encrypt0.protected, ALGORITHM_ID_XHPKE)?;

    // Extract encapsulated key from the unprotected headers
    let encap_key: &[u8; ENCAP_KEY_SIZE] = encrypt0
        .unprotected
        .encap_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::InvalidEncapKeySize(encrypt0.unprotected.encap_key.len(), ENCAP_KEY_SIZE)
        })?;

    // Rebuild and open Enc_structure
    let msg_to_check = recipient
        .open(
            encap_key,
            &encrypt0.ciphertext,
            &EncStructure {
                context: "Encrypt0".to_string(),
                protected: encrypt0.protected.clone(),
                external_aad: msg_to_auth.to_vec(),
            }
            .encode_cbor(),
            domain,
        )
        .map_err(|e| Error::Decryption(e.to_string()))?;

    // Verify the signature and extract the payload
    verify(&msg_to_check, msg_to_auth, sender)
}

/// Verifies the protected header contains exactly the expected algorithm.
fn verify_protected_header(bytes: &[u8], exp_algo: i64) -> Result<(), Error> {
    let header: ProtectedHeader = cbor::decode(bytes)?;
    if header.algorithm != exp_algo {
        return Err(Error::UnexpectedProtectedHeaderAlgorithm(
            header.algorithm,
            exp_algo,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests various combinations of signing and verifying ops.
    #[test]
    fn test_sign_verify() {
        struct TestCase {
            msg_to_sign: &'static [u8],
            msg_to_auth: &'static [u8],
            verifier_msg_to_auth: &'static [u8],
            wrong_key: bool,
            want_ok: bool,
        }
        let tests = [
            // Valid signature with aad
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                wrong_key: false,
                want_ok: true,
            },
            // Valid signature, empty aad
            TestCase {
                msg_to_sign: b"foobar",
                msg_to_auth: b"",
                verifier_msg_to_auth: b"",
                wrong_key: false,
                want_ok: true,
            },
            // Wrong aad
            TestCase {
                msg_to_sign: b"foo!",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"baz",
                wrong_key: false,
                want_ok: false,
            },
            // Wrong key
            TestCase {
                msg_to_sign: b"foo!",
                msg_to_auth: b"",
                verifier_msg_to_auth: b"",
                wrong_key: true,
                want_ok: false,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let alice = xdsa::SecretKey::generate();
            let bobby = xdsa::SecretKey::generate();

            let signed = sign(test.msg_to_sign, test.msg_to_auth, &alice);
            let verifier = if test.wrong_key {
                bobby.public_key()
            } else {
                alice.public_key()
            };
            let result = verify(&signed, test.verifier_msg_to_auth, &verifier);

            if test.want_ok {
                let recovered = result.expect(&format!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_sign, "test {}: payload mismatch", i);
            } else {
                assert!(result.is_err(), "test {}: expected error", i);
            }
        }
    }

    // Tests various combinations of sealing and opening ops.
    #[test]
    fn test_seal_open() {
        struct TestCase {
            msg_to_seal: &'static [u8],
            msg_to_auth: &'static [u8],
            opener_msg_to_auth: &'static [u8],
            domain: &'static [u8],
            opener_domain: &'static [u8],
            wrong_signer: bool,
            want_ok: bool,
        }
        let tests = [
            // Valid seal/open with aad
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                wrong_signer: false,
                want_ok: true,
            },
            // Valid seal/open, empty aad
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"",
                opener_msg_to_auth: b"",
                domain: b"baz",
                opener_domain: b"baz",
                wrong_signer: false,
                want_ok: true,
            },
            // Wrong domain
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"",
                opener_msg_to_auth: b"",
                domain: b"baz",
                opener_domain: b"baz2",
                wrong_signer: false,
                want_ok: false,
            },
            // Wrong aad
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar2",
                domain: b"baz",
                opener_domain: b"baz",
                wrong_signer: false,
                want_ok: false,
            },
            // Wrong signer
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"",
                opener_msg_to_auth: b"",
                domain: b"baz",
                opener_domain: b"baz",
                wrong_signer: true,
                want_ok: false,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let alice = xdsa::SecretKey::generate();
            let bobby = xdsa::SecretKey::generate();
            let carol = xhpke::SecretKey::generate();

            let sealed = seal(
                test.msg_to_seal,
                test.msg_to_auth,
                &alice,
                &carol.public_key(),
                test.domain,
            )
            .unwrap();

            let verifier = if test.wrong_signer {
                bobby.public_key()
            } else {
                alice.public_key()
            };
            let result = open(
                &sealed,
                test.opener_msg_to_auth,
                &carol,
                &verifier,
                test.opener_domain,
            );

            if test.want_ok {
                let recovered = result.expect(&format!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_seal, "test {}: payload mismatch", i);
            } else {
                assert!(result.is_err(), "test {}: expected error", i);
            }
        }
    }
}
