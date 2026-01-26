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
    CoseEncrypt0, CoseSign1, CritHeader, EmptyHeader, EncProtectedHeader, EncStructure,
    EncapKeyHeader, HEADER_TIMESTAMP, SigProtectedHeader, SigStructure,
};

// Use an indirect time package that mostly defers to sts::time on most platforms,
// except on wasm, where it uses the JS engine's time subsystem.
use web_time::{SystemTime, UNIX_EPOCH};

use crate::cbor::{self, Decode, Encode, Raw};
use crate::{xdsa, xhpke};

// DOMAIN_PREFIX is the prefix of a public string known to both parties during
// cryptographic operation, with the purpose of binding the keys used to some
// application context.
//
// The final domain will be this prefix concatenated with another contextual one
// from an app layer action.
pub const DOMAIN_PREFIX: &[u8] = b"dark-bio-v1:";

/// Error is the failures that can occur during COSE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("cbor: {0}")]
    CborError(#[from] cbor::Error),
    #[error("unexpected algorithm: have {0}, want {1}")]
    UnexpectedAlgorithm(i64, i64),
    #[error("unexpected signing key: have {0:x?}, want {1:x?}")]
    UnexpectedSigningKey(xdsa::Fingerprint, xdsa::Fingerprint),
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("signature stale: time drift {0}s exceeds max {1}s")]
    StaleSignature(u64, u64),
    #[error("unexpected payload in detached signature")]
    UnexpectedPayload,
    #[error("missing payload in embedded signature")]
    MissingPayload,
    #[error("unexpected encryption key: have {0:x?}, want {1:x?}")]
    UnexpectedEncryptionKey(xhpke::Fingerprint, xhpke::Fingerprint),
    #[error("invalid encapsulated key size: {0}, expected {1}")]
    InvalidEncapKeySize(usize, usize),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Private COSE algorithm identifier for composite ML-DSA-65 + Ed25519 signatures.
pub const ALGORITHM_ID_XDSA: i64 = -70000;

/// Private COSE algorithm identifier for X-Wing (ML-KEM-768 + X25519).
pub const ALGORITHM_ID_XHPKE: i64 = -70001;

/// sign_detached creates a COSE_Sign1 digital signature without an embedded
/// payload (i.e. payload is empty).
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_detached_at`].
///
/// - `msg_to_auth`: The message to sign (not embedded in COSE_Sign1)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for replay protection
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_detached<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    sign_detached_at(msg_to_auth, signer, domain, timestamp)
}

/// sign creates a COSE_Sign1 digital signature with an embedded payload.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_at`].
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for replay protection
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    sign_at(msg_to_embed, msg_to_auth, signer, domain, timestamp)
}

/// sign_detached_at creates a COSE_Sign1 digital signature without an embedded
/// payload and with an explicit timestamp.
///
/// - `msg_to_auth`: The message to sign (not embedded in COSE_Sign1)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for replay protection
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_detached_at<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth));

    let protected = cbor::encode(&SigProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
        crit: CritHeader {
            timestamp: HEADER_TIMESTAMP,
        },
        kid: signer.fingerprint(),
        timestamp,
    });
    // Build and sign Sig_structure with empty payload for detached mode
    let signature = signer.sign(
        &SigStructure {
            context: "Signature1",
            protected: &protected,
            external_aad: &aad,
            payload: &[],
        }
        .encode_cbor(),
    );
    // Build and encode COSE_Sign1 with null payload
    cbor::encode(&CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: None,
        signature,
    })
}

/// sign_at creates a COSE_Sign1 digital signature with an embedded payload
/// and an explicit timestamp.
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for replay protection
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_at<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Vec<u8> {
    let msg_to_embed = cbor::encode(msg_to_embed);

    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth));

    let protected = cbor::encode(&SigProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
        crit: CritHeader {
            timestamp: HEADER_TIMESTAMP,
        },
        kid: signer.fingerprint(),
        timestamp,
    });
    // Build and sign Sig_structure
    let signature = signer.sign(
        &SigStructure {
            context: "Signature1",
            protected: &protected,
            external_aad: &aad,
            payload: &msg_to_embed,
        }
        .encode_cbor(),
    );
    // Build and encode COSE_Sign1
    cbor::encode(&CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: Some(msg_to_embed),
        signature,
    })
}

/// verify_detached validates a COSE_Sign1 digital signature with a detached payload.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`verify_detached_at`].
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure (with null payload)
/// - `msg_to_auth`: The same message used during signing (verified but not embedded)
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for replay protection
/// - `max_drift`: Signatures more in the past or future are rejected
pub fn verify_detached<A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<(), Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    verify_detached_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// verify_detached_at validates a COSE_Sign1 digital signature with a detached payload
/// and an explicit current time for drift checking.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure (with null payload)
/// - `msg_to_auth`: The same message used during signing (verified but not embedded)
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for replay protection
/// - `max_drift`: Signatures more in the past or future are rejected
/// - `now`: Unix timestamp in seconds to use for drift checking
pub fn verify_detached_at<A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<(), Error> {
    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth));

    // Parse COSE_Sign1
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;

    // Verify payload is null (detached)
    if sign1.payload.is_some() {
        return Err(Error::UnexpectedPayload);
    }
    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check signature timestamp drift if max_drift is specified
    if let Some(max) = max_drift {
        let drift = (now - header.timestamp).unsigned_abs();
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure to verify (empty payload for detached mode)
    let blob = SigStructure {
        context: "Signature1",
        protected: &sign1.protected,
        external_aad: &aad,
        payload: &[],
    }
    .encode_cbor();

    // Verify signature
    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(())
}

/// verify validates a COSE_Sign1 digital signature and returns the embedded payload.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`verify_at`].
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for replay protection
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded embedded payload if verification succeeds.
pub fn verify<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    verify_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// verify_at validates a COSE_Sign1 digital signature and returns the embedded payload,
/// using an explicit current time for drift checking.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for replay protection
/// - `max_drift`: Signatures more in the past or future are rejected
/// - `now`: Unix timestamp in seconds to use for drift checking
///
/// Returns the CBOR-decoded embedded payload if verification succeeds.
pub fn verify_at<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<E, Error> {
    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth));

    // Parse COSE_Sign1
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;

    // Verify payload is present (embedded)
    let payload = sign1.payload.ok_or(Error::MissingPayload)?;

    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check signature timestamp drift if max_drift is specified
    if let Some(max) = max_drift {
        let drift = (now - header.timestamp).unsigned_abs();
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure to verify
    let blob = SigStructure {
        context: "Signature1",
        protected: &sign1.protected,
        external_aad: &aad,
        payload: &payload,
    }
    .encode_cbor();

    // Verify signature
    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(cbor::decode(&payload)?)
}

/// signer extracts the signer's fingerprint from a COSE_Sign1 signature without
/// verifying it.
///
/// This allows looking up the appropriate verification key before attempting
/// full signature verification.
///
/// - `signature`: The serialized COSE_Sign1 structure
///
/// Returns the signer's fingerprint from the protected header's `kid` field.
pub fn signer(signature: &[u8]) -> Result<xdsa::Fingerprint, Error> {
    let sign1: CoseSign1 = cbor::decode(signature)?;
    let header: SigProtectedHeader = cbor::decode(&sign1.protected)?;
    Ok(header.kid)
}

/// peek extracts the embedded payload from a COSE_Sign1 signature without
/// verifying it.
///
/// **Warning**: This function does NOT verify the signature. The returned payload
/// is unauthenticated and should not be trusted until verified with [`verify`].
/// Use [`signer`] to extract the signer's fingerprint for key lookup.
///
/// - `signature`: The serialized COSE_Sign1 structure
///
/// Returns the CBOR-decoded payload.
pub fn peek<E: Decode>(signature: &[u8]) -> Result<E, Error> {
    let sign1: CoseSign1 = cbor::decode(signature)?;
    let payload = sign1.payload.ok_or(Error::MissingPayload)?;
    Ok(cbor::decode(&payload)?)
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
pub fn seal<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
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

/// seal_at signs a message then encrypts it to a recipient with an explicit
/// timestamp.
///
/// - `msg_to_seal`: The message to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `timestamp`: Unix timestamp in seconds to embed in the signature's protected header
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
pub fn seal_at<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Pre-encode for EncStructure (which needs raw bytes for external_aad)
    let msg_to_seal = cbor::encode(msg_to_seal);
    let msg_to_auth = cbor::encode(msg_to_auth);

    // Create a COSE_Sign1 with the payload, binding the AAD (use Raw to avoid re-encoding)
    let signed = sign_at(
        Raw(msg_to_seal),
        Raw(msg_to_auth.clone()),
        signer,
        domain,
        timestamp,
    );
    // Encrypt the signed message to the recipient
    encrypt(&signed, Raw(msg_to_auth), recipient, domain)
}

/// encrypt encrypts an already-signed COSE_Sign1 to a recipient.
///
/// For most use cases, prefer [`seal`] which signs and encrypts in one step.
/// Use this only when re-encrypting a message (from [`decrypt`]) to a different
/// recipient without access to the original signer's key.
///
/// - `sign1`: The COSE_Sign1 structure (e.g., from [`decrypt`])
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the serialized COSE_Encrypt0 structure.
pub fn encrypt<A: Encode>(
    sign1: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    // Pre-encode for EncStructure (which needs raw bytes for external_aad)
    let msg_to_auth = cbor::encode(msg_to_auth);

    // Build protected header with recipient's fingerprint
    let protected = cbor::encode(&EncProtectedHeader {
        algorithm: ALGORITHM_ID_XHPKE,
        kid: recipient.fingerprint(),
    });
    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();

    // Build and seal Enc_structure
    let (encap_key, ciphertext) = recipient
        .seal(
            sign1,
            &EncStructure {
                context: "Encrypt0",
                protected: &protected,
                external_aad: &msg_to_auth,
            }
            .encode_cbor(),
            &info,
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

/// open decrypts and verifies a sealed message.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`open_at`].
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded payload if decryption and verification succeed.
pub fn open<E: Decode, A: Encode + Clone>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    open_at(
        msg_to_open,
        msg_to_auth,
        recipient,
        sender,
        domain,
        max_drift,
        now,
    )
}

/// open_at decrypts and verifies a sealed message with an explicit current time
/// for drift checking.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Signatures more in the past or future are rejected
/// - `now`: Unix timestamp in seconds to use for drift checking
///
/// Returns the CBOR-decoded payload if decryption and verification succeed.
pub fn open_at<E: Decode, A: Encode + Clone>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<E, Error> {
    // Decrypt the COSE_Encrypt0 to get the COSE_Sign1
    let sign1 = decrypt(msg_to_open, msg_to_auth.clone(), recipient, domain)?;

    // Verify the signature and extract the payload
    let raw: Raw = verify_at::<Raw, _>(&sign1, &msg_to_auth, sender, domain, max_drift, now)?;
    Ok(cbor::decode(&raw.0)?)
}

/// decrypt decrypts a sealed message without verifying the signature.
///
/// This allows inspecting the signer before verification. Use [`signer`] to
/// extract the signer's fingerprint, then [`verify`] or [`verify_at`] to verify.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the decrypted COSE_Sign1 structure (not yet verified).
pub fn decrypt<A: Encode>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    // Pre-encode for EncStructure (which needs raw bytes for external_aad)
    let msg_to_auth = cbor::encode(msg_to_auth);

    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();

    // Parse COSE_Encrypt0
    let encrypt0: CoseEncrypt0 = cbor::decode(msg_to_open)?;

    // Verify protected header
    verify_enc_protected_header(&encrypt0.protected, ALGORITHM_ID_XHPKE, recipient)?;

    // Extract encapsulated key from the unprotected headers
    let encap_key: &[u8; xhpke::ENCAP_KEY_SIZE] = encrypt0
        .unprotected
        .encap_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::InvalidEncapKeySize(encrypt0.unprotected.encap_key.len(), xhpke::ENCAP_KEY_SIZE)
        })?;

    // Rebuild and open Enc_structure
    let decrypted = recipient
        .open(
            encap_key,
            &encrypt0.ciphertext,
            &EncStructure {
                context: "Encrypt0",
                protected: &encrypt0.protected,
                external_aad: &msg_to_auth,
            }
            .encode_cbor(),
            &info,
        )
        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

    Ok(decrypted)
}

/// recipient extracts the recipient's fingerprint from a COSE_Encrypt0 message
/// without decrypting it.
///
/// This allows looking up the appropriate decryption key before attempting
/// full decryption.
///
/// - `ciphertext`: The serialized COSE_Encrypt0 structure
///
/// Returns the recipient's fingerprint from the protected header's `kid` field.
pub fn recipient(ciphertext: &[u8]) -> Result<xhpke::Fingerprint, Error> {
    let encrypt0: CoseEncrypt0 = cbor::decode(ciphertext)?;
    let header: EncProtectedHeader = cbor::decode(&encrypt0.protected)?;
    Ok(header.kid)
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
    if header.crit.timestamp != HEADER_TIMESTAMP {
        return Err(Error::UnexpectedAlgorithm(
            header.crit.timestamp,
            HEADER_TIMESTAMP,
        ));
    }
    if header.kid != verifier.fingerprint() {
        return Err(Error::UnexpectedSigningKey(
            header.kid,
            verifier.fingerprint(),
        ));
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
        return Err(Error::UnexpectedEncryptionKey(
            header.kid,
            recipient.fingerprint(),
        ));
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
            domain: &'static [u8],
            verifier_domain: &'static [u8],
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
                timestamp: Some(now + 120),
                max_drift: Some(60),
                wrong_key: false,
                want_ok: false,
            },
            // Wrong domain
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                domain: b"baz",
                verifier_domain: b"baz2",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                domain: b"baz",
                verifier_domain: b"baz",
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
                Some(ts) => sign_at(
                    &test.msg_to_sign.to_vec(),
                    &test.msg_to_auth.to_vec(),
                    &alice,
                    test.domain,
                    ts,
                ),
                None => sign(
                    &test.msg_to_sign.to_vec(),
                    &test.msg_to_auth.to_vec(),
                    &alice,
                    test.domain,
                ),
            };
            let verifier = if test.wrong_key {
                bobby.public_key()
            } else {
                alice.public_key()
            };
            let result: Result<Vec<u8>, _> = verify(
                &signed,
                &test.verifier_msg_to_auth.to_vec(),
                &verifier,
                test.verifier_domain,
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
                    &test.msg_to_seal.to_vec(),
                    &test.msg_to_auth.to_vec(),
                    &alice,
                    &carol.public_key(),
                    test.domain,
                    ts,
                )
                .unwrap(),
                None => seal(
                    &test.msg_to_seal.to_vec(),
                    &test.msg_to_auth.to_vec(),
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
            let result: Result<Vec<u8>, _> = open(
                &sealed,
                &test.opener_msg_to_auth.to_vec(),
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
    fn test_sign_verify_typed() {
        let alice = xdsa::SecretKey::generate();

        let payload = (42u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let signed = sign(&payload, &aad, &alice, b"baz");
        let recovered: (u64, String) =
            verify(&signed, &aad, &alice.public_key(), b"baz", None).unwrap();

        assert_eq!(recovered, payload);
    }

    // Tests CBOR encoding/decoding for seal/open.
    #[test]
    fn test_seal_open_typed() {
        let alice = xdsa::SecretKey::generate();
        let carol = xhpke::SecretKey::generate();

        let payload = (123u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let sealed = seal(&payload, &aad, &alice, &carol.public_key(), b"baz").unwrap();
        let recovered: (u64, String) =
            open(&sealed, &aad, &carol, &alice.public_key(), b"baz", None).unwrap();

        assert_eq!(recovered, payload);
    }
}
