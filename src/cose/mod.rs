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
    CoseEncrypt0, CoseSign1, ENCAP_KEY_SIZE, EmptyHeader, EncProtectedHeader, EncStructure,
    EncapKeyHeader, HEADER_TIMESTAMP, SIGNATURE_SIZE, SigProtectedHeader, SigStructure,
};

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::{self, Decode, Encode};
use crate::{xdsa, xhpke};

/// Error is the failures that can occur during COSE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("cbor: {0}")]
    CborError(#[from] cbor::Error),
    #[error("unexpected algorithm: have {0}, want {1}")]
    UnexpectedAlgorithm(i64, i64),
    #[error("unexpected key: have {0:x?}, want {1:x?}")]
    UnexpectedKey([u8; 32], [u8; 32]),
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("signature stale: time drift {0}s exceeds max {1}s")]
    StaleSignature(u64, u64),
    #[error("invalid encapsulated key size: {0}, expected {1}")]
    InvalidEncapKeySize(usize, usize),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Private COSE algorithm identifier for composite ML-DSA-65 + Ed25519 signatures.
pub const ALGORITHM_ID_XDSA: i64 = -70000;

/// Private COSE algorithm identifier for X-Wing (ML-KEM-768 + X25519).
pub const ALGORITHM_ID_XHPKE: i64 = -70001;

/// sign_cbor creates a COSE_Sign1 digital signature of the msg_to_embed.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_cbor_at`].
///
/// - `msg_to_embed`: The message to sign (CBOR-encoded, embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (CBOR-encoded, not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_cbor<E: Encode, A: Encode>(
    msg_to_embed: &E,
    msg_to_auth: &A,
    signer: &xdsa::SecretKey,
) -> Vec<u8> {
    sign(
        &cbor::encode(msg_to_embed),
        &cbor::encode(msg_to_auth),
        signer,
    )
}

/// sign creates a COSE_Sign1 digital signature of the msg_to_embed.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_at`].
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign(msg_to_embed: &[u8], msg_to_auth: &[u8], signer: &xdsa::SecretKey) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    sign_at(msg_to_embed, msg_to_auth, signer, timestamp)
}

/// sign_cbor_at creates a COSE_Sign1 digital signature of the msg_to_embed with
/// an explicit timestamp.
///
/// - `msg_to_embed`: The message to sign (CBOR-encoded, embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (CBOR-encoded, not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_cbor_at<E: Encode, A: Encode>(
    msg_to_embed: &E,
    msg_to_auth: &A,
    signer: &xdsa::SecretKey,
    timestamp: i64,
) -> Vec<u8> {
    sign_at(
        &cbor::encode(msg_to_embed),
        &cbor::encode(msg_to_auth),
        signer,
        timestamp,
    )
}

/// sign_at creates a COSE_Sign1 digital signature with an explicit timestamp.
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_at(
    msg_to_embed: &[u8],
    msg_to_auth: &[u8],
    signer: &xdsa::SecretKey,
    timestamp: i64,
) -> Vec<u8> {
    let protected = cbor::encode(&SigProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
        kid: signer.fingerprint(),
        timestamp,
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
        signature: signature.to_bytes(),
    })
}

/// verify_cbor validates a COSE_Sign1 digital signature and returns payload.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing (CBOR-encoded)
/// - `verifier`: The xDSA public key to verify against
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded payload if verification succeeds.
pub fn verify_cbor<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: &A,
    verifier: &xdsa::PublicKey,
    max_drift: Option<u64>,
) -> Result<E, Error> {
    let payload = verify(
        msg_to_check,
        &cbor::encode(msg_to_auth),
        verifier,
        max_drift,
    )?;
    Ok(cbor::decode(&payload)?)
}

/// verify validates a COSE_Sign1 digital signature and returns the payload.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the embedded payload if verification succeeds.
pub fn verify(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &xdsa::PublicKey,
    max_drift: Option<u64>,
) -> Result<Vec<u8>, Error> {
    // Parse COSE_Sign1
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;

    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check signature timestamp drift if max_drift is specified
    if let Some(max) = max_drift {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64;
        let drift = (now - header.timestamp).unsigned_abs();
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }

    // Reconstruct Sig_structure to verify
    let blob = SigStructure {
        context: "Signature1".to_string(),
        protected: sign1.protected.clone(),
        external_aad: msg_to_auth.to_vec(),
        payload: sign1.payload.clone(),
    }
    .encode_cbor();

    // Verify signature
    let signature = xdsa::Signature::from_bytes(&sign1.signature);
    verifier
        .verify(&blob, &signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(sign1.payload)
}

/// seal_cbor signs a message then encrypts it to a recipient.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`seal_cbor_at`].
///
/// - `msg_to_seal`: The message to sign and encrypt (CBOR-encoded)
/// - `msg_to_auth`: Additional authenticated data (CBOR-encoded, signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
pub fn seal_cbor<E: Encode, A: Encode>(
    msg_to_seal: &E,
    msg_to_auth: &A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    seal(
        &cbor::encode(msg_to_seal),
        &cbor::encode(msg_to_auth),
        signer,
        recipient,
        domain,
    )
}

/// seal signs a message then encrypts it to a recipient.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`seal_at`].
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
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    seal_at(
        msg_to_seal,
        msg_to_auth,
        signer,
        recipient,
        domain,
        timestamp,
    )
}

/// seal_cbor_at signs a message then encrypts it to a recipient with an explicit
/// timestamp.
///
/// - `msg_to_seal`: The message to sign and encrypt (CBOR-encoded)
/// - `msg_to_auth`: Additional authenticated data (CBOR-encoded, signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `timestamp`: Unix timestamp in seconds to embed in the signature's protected header
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
pub fn seal_cbor_at<E: Encode, A: Encode>(
    msg_to_seal: &E,
    msg_to_auth: &A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    seal_at(
        &cbor::encode(msg_to_seal),
        &cbor::encode(msg_to_auth),
        signer,
        recipient,
        domain,
        timestamp,
    )
}

/// seal_at signs a message then encrypts it to a recipient with an explicit timestamp.
///
/// - `msg_to_seal`: The message to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `timestamp`: Unix timestamp in seconds to embed in the signature's protected header
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
pub fn seal_at(
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Create a COSE_Sign1 with the payload, binding the AAD
    let signed = sign_at(msg_to_seal, msg_to_auth, signer, timestamp);

    // Build protected header with recipient's fingerprint
    let protected = cbor::encode(&EncProtectedHeader {
        algorithm: ALGORITHM_ID_XHPKE,
        kid: recipient.fingerprint(),
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
        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

    // Build and encode COSE_Encrypt0
    Ok(cbor::encode(&CoseEncrypt0 {
        protected,
        unprotected: EncapKeyHeader {
            encap_key: encap_key.to_vec(),
        },
        ciphertext,
    }))
}

/// open_cbor decrypts and verifies a sealed message.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing (will be CBOR-encoded)
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded payload if decryption and verification succeed.
pub fn open_cbor<E: Decode, A: Encode>(
    msg_to_open: &[u8],
    msg_to_auth: &A,
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    let payload = open(
        msg_to_open,
        &cbor::encode(msg_to_auth),
        recipient,
        sender,
        domain,
        max_drift,
    )?;
    Ok(cbor::decode(&payload)?)
}

/// open decrypts and verifies a sealed message.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the original payload if decryption and verification succeed.
pub fn open(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<Vec<u8>, Error> {
    // Parse COSE_Encrypt0
    let encrypt0: CoseEncrypt0 = cbor::decode(msg_to_open)?;

    // Verify protected header
    verify_enc_protected_header(&encrypt0.protected, ALGORITHM_ID_XHPKE, recipient)?;

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
        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

    // Verify the signature and extract the payload
    verify(&msg_to_check, msg_to_auth, sender, max_drift)
}

/// Verifies the signature protected header contains exactly the expected algorithm
/// and that the key identifier matches the provided verifier.
fn verify_sig_protected_header(
    bytes: &[u8],
    exp_algo: i64,
    verifier: &xdsa::PublicKey,
) -> Result<SigProtectedHeader, Error> {
    let header: SigProtectedHeader = cbor::decode(bytes)?;
    if header.algorithm != exp_algo {
        return Err(Error::UnexpectedAlgorithm(header.algorithm, exp_algo));
    }
    if header.kid != verifier.fingerprint() {
        return Err(Error::UnexpectedKey(header.kid, verifier.fingerprint()));
    }
    Ok(header)
}

/// Verifies the encryption protected header contains exactly the expected algorithm
/// and that the key identifier matches the provided recipient.
fn verify_enc_protected_header(
    bytes: &[u8],
    exp_algo: i64,
    recipient: &xhpke::SecretKey,
) -> Result<EncProtectedHeader, Error> {
    let header: EncProtectedHeader = cbor::decode(bytes)?;
    if header.algorithm != exp_algo {
        return Err(Error::UnexpectedAlgorithm(header.algorithm, exp_algo));
    }
    if header.kid != recipient.fingerprint() {
        return Err(Error::UnexpectedKey(header.kid, recipient.fingerprint()));
    }
    Ok(header)
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
            timestamp: Option<i64>,
            max_drift: Option<u64>,
            wrong_key: bool,
            want_ok: bool,
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let tests = [
            // Valid signature with aad
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                timestamp: None,
                max_drift: None,
                wrong_key: false,
                want_ok: true,
            },
            // Valid signature, empty aad
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"",
                verifier_msg_to_auth: b"",
                timestamp: None,
                max_drift: None,
                wrong_key: false,
                want_ok: true,
            },
            // Valid signature with explicit timestamp, no drift check
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                timestamp: Some(now),
                max_drift: None,
                wrong_key: false,
                want_ok: true,
            },
            // Valid signature within drift tolerance
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                timestamp: Some(now - 30),
                max_drift: Some(60),
                wrong_key: false,
                want_ok: true,
            },
            // Signature too old (exceeds max_drift)
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                timestamp: Some(now - 120),
                max_drift: Some(60),
                wrong_key: false,
                want_ok: false,
            },
            // Signature too far in the future (exceeds max_drift)
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                timestamp: Some(now + 120),
                max_drift: Some(60),
                wrong_key: false,
                want_ok: false,
            },
            // Wrong aad
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar2",
                timestamp: None,
                max_drift: None,
                wrong_key: false,
                want_ok: false,
            },
            // Wrong key
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"",
                verifier_msg_to_auth: b"",
                timestamp: None,
                max_drift: None,
                wrong_key: true,
                want_ok: false,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let alice = xdsa::SecretKey::generate();
            let bobby = xdsa::SecretKey::generate();

            let signed = match test.timestamp {
                Some(ts) => sign_at(test.msg_to_sign, test.msg_to_auth, &alice, ts),
                None => sign(test.msg_to_sign, test.msg_to_auth, &alice),
            };
            let verifier = if test.wrong_key {
                bobby.public_key()
            } else {
                alice.public_key()
            };
            let result = verify(
                &signed,
                test.verifier_msg_to_auth,
                &verifier,
                test.max_drift,
            );

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
            timestamp: Option<i64>,
            max_drift: Option<u64>,
            wrong_signer: bool,
            want_ok: bool,
        }
        // Fetch the current time for drift tests
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let tests = [
            // Valid seal/open with aad
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                timestamp: None,
                max_drift: None,
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
                timestamp: None,
                max_drift: None,
                wrong_signer: false,
                want_ok: true,
            },
            // Valid seal/open, no drift check
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                timestamp: Some(now),
                max_drift: None,
                wrong_signer: false,
                want_ok: true,
            },
            // Valid seal/open, valid drift
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                timestamp: Some(now - 30),
                max_drift: Some(60),
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
                timestamp: None,
                max_drift: None,
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
                timestamp: None,
                max_drift: None,
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
                timestamp: None,
                max_drift: None,
                wrong_signer: true,
                want_ok: false,
            },
            // Timestamp too far in the past
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                timestamp: Some(now - 120),
                max_drift: Some(60),
                wrong_signer: false,
                want_ok: false,
            },
            // Timestamp too far in the future
            TestCase {
                msg_to_seal: b"foo",
                msg_to_auth: b"bar",
                opener_msg_to_auth: b"bar",
                domain: b"baz",
                opener_domain: b"baz",
                timestamp: Some(now + 120),
                max_drift: Some(60),
                wrong_signer: false,
                want_ok: false,
            },
        ];

        for (i, test) in tests.iter().enumerate() {
            let alice = xdsa::SecretKey::generate();
            let bobby = xdsa::SecretKey::generate();
            let carol = xhpke::SecretKey::generate();

            let sealed = match test.timestamp {
                Some(ts) => seal_at(
                    test.msg_to_seal,
                    test.msg_to_auth,
                    &alice,
                    &carol.public_key(),
                    test.domain,
                    ts,
                )
                .unwrap(),
                None => seal(
                    test.msg_to_seal,
                    test.msg_to_auth,
                    &alice,
                    &carol.public_key(),
                    test.domain,
                )
                .unwrap(),
            };

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
                test.max_drift,
            );

            if test.want_ok {
                let recovered = result.expect(&format!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_seal, "test {}: payload mismatch", i);
            } else {
                assert!(result.is_err(), "test {}: expected error", i);
            }
        }
    }

    // Tests CBOR encoding/decoding for sign/verify.
    #[test]
    fn test_sign_verify_cbor() {
        let alice = xdsa::SecretKey::generate();

        let payload = (42u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let signed = sign_cbor(&payload, &aad, &alice);
        let recovered: (u64, String) =
            verify_cbor(&signed, &aad, &alice.public_key(), None).unwrap();

        assert_eq!(recovered, payload);
    }

    // Tests CBOR encoding/decoding for seal/open.
    #[test]
    fn test_seal_open_cbor() {
        let alice = xdsa::SecretKey::generate();
        let carol = xhpke::SecretKey::generate();

        let payload = (123u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let sealed = seal_cbor(&payload, &aad, &alice, &carol.public_key(), b"baz").unwrap();
        let recovered: (u64, String) =
            open_cbor(&sealed, &aad, &carol, &alice.public_key(), b"baz", None).unwrap();

        assert_eq!(recovered, payload);
    }
}
