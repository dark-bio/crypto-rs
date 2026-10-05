// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wrappers for xDSA and xHPKE.
//!
//! <https://datatracker.ietf.org/doc/html/rfc9052>
//! <https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke>
//!
//! Signatures are [`CoseSign1`] envelopes carrying the signer's fingerprint and
//! a timestamp in the protected header. Encryption is [`CoseEncrypt0`] around a
//! signed envelope, so every message created by [`seal`] is also signed.
//! Payloads and authenticated messages can be any types implementing the crate's
//! CBOR traits. Signing, verification, encryption, and decryption use an
//! application domain, prefixed with [`DOMAIN_PREFIX`], which both sides must
//! agree on.
//!
//! ```
//! use darkbio_crypto::{cose, xdsa, xhpke};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = xdsa::SecretKey::generate();
//!
//! // Sign a payload, binding a second message supplied separately
//! let envelope = cose::sign("hello".to_string(), "context", &signer, b"example")?;
//! let payload: String =
//!     cose::verify(&envelope, "context", &signer.public_key(), b"example", Some(60))?;
//! assert_eq!(payload, "hello");
//!
//! // Sign and encrypt to a recipient in one step, then open and verify it back
//! let recipient = xhpke::SecretKey::generate();
//! let sealed = cose::seal(
//!     "secret".to_string(),
//!     "context",
//!     &signer,
//!     &recipient.public_key(),
//!     b"example",
//!     &cose::Padding::Buckets { floor: 8192, step: 20 },
//! )?;
//! let opened: String = cose::open(
//!     &sealed,
//!     "context",
//!     &recipient,
//!     &signer.public_key(),
//!     b"example",
//!     Some(60),
//! )?;
//! assert_eq!(opened, "secret");
//! # Ok(())
//! # }
//! ```
//!
//! # Domain separation and freshness
//!
//! Choose distinct domains for distinct application operations. Domains prevent
//! a message for one purpose from being accepted for another; they do not stop
//! repeated use within the same domain. Verification accepts a signature whose
//! timestamp is at most `max_drift` seconds in the past or future. `None` skips
//! this timestamp check. Applications that require one-time acceptance must
//! also track a message identifier, nonce, or challenge to reject replays.
//!
//! # Wire profile
//!
//! Interoperating implementations must match these Dark Bio conventions:
//!
//! - Envelopes are untagged [`CoseSign1`] and [`CoseEncrypt0`] arrays. CBOR tags
//!   are not accepted. Headers use this crate's deterministic integer-key maps.
//! - The private algorithm IDs are [`ALGORITHM_ID_XDSA`] (`-70000`) and
//!   [`ALGORITHM_ID_XHPKE`] (`-70001`). The protected `kid` is the appropriate
//!   public key's fingerprint. Signatures require the private timestamp header
//!   [`HEADER_TIMESTAMP`] (`-70002`) and name it in `crit`.
//! - For signatures, [`SigStructure::external_aad`] is the CBOR encoding of
//!   `[bstr(DOMAIN_PREFIX || domain), msg_to_auth]`. An embedded payload is the
//!   CBOR encoding of the caller's value.
//! - For [`sign_detached`], the caller's message is authenticated in that
//!   `external_aad`, while [`SigStructure::payload`] is an empty byte string
//!   and the envelope payload is null. A generic COSE detached-payload API that
//!   puts the caller's message in `Sig_structure.payload` must be adapted to
//!   this convention.
//! - For encryption, [`EncStructure::external_aad`] is the CBOR encoding of
//!   `msg_to_auth`; the complete encoded `EncStructure` is passed as HPKE AAD.
//!   HPKE key derivation uses `DOMAIN_PREFIX || domain` as its info. The X-Wing
//!   encapsulated key is carried in unprotected header `-4`.
//! - The encryption plaintext is the encoded [`CoseSign1`] followed by zero
//!   bytes, as many as the sender's [`Padding`] policy picks. The signature does
//!   not cover them, while the encryption authenticates them. A receiver finds
//!   the end of the [`CoseSign1`] by decoding it and refuses a nonzero byte after
//!   it. It accepts any number of zeros, none included, so a sender can change
//!   its policy without its receivers.
//!
//! Here `bstr` denotes a CBOR byte string and `||` denotes byte concatenation.
//! The domain and `msg_to_auth` are not included in the returned envelope;
//! both parties must know them or transmit them separately.

mod types;

pub use types::{
    CoseEncrypt0, CoseSign1, CritHeader, EmptyHeader, EncProtectedHeader, EncStructure,
    EncapKeyHeader, HEADER_TIMESTAMP, SigProtectedHeader, SigStructure,
};

// Use an indirect time package that mostly defers to sts::time on most platforms,
// except on wasm, where it uses the JS engine's time subsystem.
use web_time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Decode, Encode, Raw};
use crate::{xdsa, xhpke};

/// Prefix prepended to the caller's application domain for signature
/// authentication and HPKE key derivation. Both parties must use the same bytes.
/// Distinct domains separate application purposes; replay detection within a
/// domain is the application's responsibility.
pub const DOMAIN_PREFIX: &[u8] = crate::xhpke::DOMAIN_PREFIX;

/// How many zero bytes a sender appends to the signed envelope inside the
/// encryption, so the ciphertext's length shows little about the message.
///
/// Receivers strip any number of zeros, so the policy is the sender's alone and
/// can change without them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Padding {
    /// No padding: the plaintext is the signed envelope alone.
    None,
    /// Zeros after the signed envelope, up to the smallest size that fits.
    /// Sizes start at `floor`, and each next one is the previous one plus
    /// `1/step` of it, rounded up.
    Buckets {
        /// Smallest padded size in bytes, which must be nonzero.
        floor: usize,
        /// Each size grows by itself divided by `step`, rounded up, and `step`
        /// must be nonzero.
        step: usize,
    },
}

impl Padding {
    /// Returns the plaintext size after padding an envelope of `len` bytes.
    ///
    /// # Panics
    ///
    /// Panics if a bucket's `floor` or `step` is zero, or the required bucket
    /// size exceeds [`usize::MAX`].
    fn padded_len(&self, len: usize) -> usize {
        let Self::Buckets { floor, step } = *self else {
            return len;
        };
        assert!(floor > 0, "padding floor must be nonzero");
        assert!(step > 0, "padding step must be nonzero");

        // Grow by the rounded-up fraction until the envelope fits
        let mut size = floor;
        while size < len {
            size = size
                .checked_add(size.div_ceil(step))
                .expect("padding bucket size overflow");
        }
        size
    }
}

/// Failures of the COSE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The envelope, a header or a payload is not valid CBOR under this
    /// crate's rules.
    #[error("cbor: {0}")]
    CborError(#[from] cbor::Error),
    /// The protected header names the first algorithm where the second was
    /// required. Also raised when the [`CritHeader`] list is not the expected
    /// one.
    #[error("unexpected algorithm: have {0}, want {1}")]
    UnexpectedAlgorithm(i64, i64),
    /// The envelope was signed by the first fingerprint, the verifier's key
    /// has the second. [`signer`] looks the right key up without verifying.
    #[error("unexpected signing key: have {0:x?}, want {1:x?}")]
    UnexpectedSigningKey(xdsa::Fingerprint, xdsa::Fingerprint),
    /// The xDSA signature does not verify. Carries the underlying error text.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    /// The signature timestamp is the first number of seconds away from now,
    /// more than the second, which is the allowed drift.
    #[error("signature stale: time drift {0}s exceeds max {1}s")]
    StaleSignature(u64, u64),
    /// [`verify_detached`] found an embedded payload.
    #[error("unexpected payload in detached signature")]
    UnexpectedPayload,
    /// [`verify`] or [`peek`] found no payload.
    #[error("missing payload in embedded signature")]
    MissingPayload,
    /// The envelope was encrypted to the first fingerprint, the recipient's
    /// key has the second. [`recipient`] looks the right key up without
    /// decrypting.
    #[error("unexpected encryption key: have {0:x?}, want {1:x?}")]
    UnexpectedEncryptionKey(xhpke::Fingerprint, xhpke::Fingerprint),
    /// The [`EncapKeyHeader`] carries an encapsulated key of the first size
    /// where the second, [`xhpke::ENCAP_KEY_SIZE`], is required.
    #[error("invalid encapsulated key size: {0}, expected {1}")]
    InvalidEncapKeySize(usize, usize),
    /// Opening the ciphertext failed, the wrong key, tampered data or a
    /// mismatched authenticated message. Also raised when [`seal`] or [`encrypt`]
    /// fails.
    /// Carries the xHPKE error text.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    /// The decrypted plaintext holds a nonzero byte after its COSE_Sign1.
    #[error("invalid padding")]
    InvalidPadding,
}

/// Private COSE algorithm identifier for composite ML-DSA-65 + Ed25519 signatures.
pub const ALGORITHM_ID_XDSA: i64 = -70000;

/// Private COSE algorithm identifier for X-Wing (ML-KEM-768 + X25519).
pub const ALGORITHM_ID_XHPKE: i64 = -70001;

/// Creates a COSE_Sign1 digital signature without an embedded payload, whose
/// envelope payload is null.
///
/// The caller's message is included in `external_aad`, and the payload in the
/// signature input is empty. See the module's wire profile for interoperability.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_detached_at`].
///
/// - `msg_to_auth`: The message to sign (not embedded in COSE_Sign1)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for separating protocol purposes
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_detached<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    sign_detached_at(msg_to_auth, signer, domain, timestamp)
}

/// Creates a COSE_Sign1 digital signature with an embedded payload.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`sign_at`].
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for separating protocol purposes
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64;
    sign_at(msg_to_embed, msg_to_auth, signer, domain, timestamp)
}

/// Creates a COSE_Sign1 digital signature without an embedded payload, with an
/// explicit timestamp.
///
/// Uses the same external-AAD convention as [`sign_detached`].
///
/// - `msg_to_auth`: The message to sign (not embedded in COSE_Sign1)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for separating protocol purposes
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_detached_at<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth))?;

    let protected = cbor::encode(&SigProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
        crit: CritHeader {
            timestamp: HEADER_TIMESTAMP,
        },
        kid: signer.fingerprint(),
        timestamp,
    })?;
    // Build and sign Sig_structure with empty payload for detached mode
    let signature = signer.sign(&cbor::encode(SigStructure {
        context: "Signature1",
        protected: &protected,
        external_aad: &aad,
        payload: &[],
    })?);
    // Build and encode COSE_Sign1 with null payload
    Ok(cbor::encode(&CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: None,
        signature,
    })?)
}

/// Creates a COSE_Sign1 digital signature with an embedded payload and an
/// explicit timestamp.
///
/// - `msg_to_embed`: The message to sign (embedded in COSE_Sign1)
/// - `msg_to_auth`: Additional authenticated data (not embedded, but signed)
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application domain for separating protocol purposes
/// - `timestamp`: Unix timestamp in seconds to embed in the protected header
///
/// Returns the serialized COSE_Sign1 structure.
pub fn sign_at<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // The payload can hold secrets, so every buffer holding it is wiped on drop
    let mut msg_to_embed = Zeroizing::new(cbor::encode(msg_to_embed)?);

    // Restrict the user's domain to the context of this library
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth))?;

    let protected = cbor::encode(&SigProtectedHeader {
        algorithm: ALGORITHM_ID_XDSA,
        crit: CritHeader {
            timestamp: HEADER_TIMESTAMP,
        },
        kid: signer.fingerprint(),
        timestamp,
    })?;
    // Build and sign Sig_structure
    let blob = encode_wiped(
        SigStructure {
            context: "Signature1",
            protected: &protected,
            external_aad: &aad,
            payload: &msg_to_embed,
        },
        protected.len() + aad.len() + msg_to_embed.len(),
    )?;
    let signature = signer.sign(&blob);

    // Build and encode COSE_Sign1, wiping the payload it holds once encoded
    let len = protected.len() + msg_to_embed.len() + xdsa::SIGNATURE_SIZE;
    let mut sign1 = CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: Some(std::mem::take(&mut *msg_to_embed)),
        signature,
    };
    let encoded = encode_wiped(&sign1, len);
    sign1.payload.zeroize();

    // Hand the encoded COSE_Sign1 over to the caller
    Ok(std::mem::take(&mut *encoded?))
}

/// Validates a COSE_Sign1 digital signature with a detached payload.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`verify_detached_at`].
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure (with null payload)
/// - `msg_to_auth`: The same message used during signing (verified but not embedded)
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for separating protocol purposes
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
pub fn verify_detached<A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<(), Error> {
    // Read the clock only if max_drift is specified
    let now = match max_drift {
        Some(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64,
        None => 0,
    };
    verify_detached_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// Validates a COSE_Sign1 digital signature with a detached payload, checking
/// drift against an explicit current time.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure (with null payload)
/// - `msg_to_auth`: The same message used during signing (verified but not embedded)
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for separating protocol purposes
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
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
    let aad = cbor::encode(&(&info, msg_to_auth))?;

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
        let drift = now.abs_diff(header.timestamp);
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure to verify (empty payload for detached mode)
    let blob = cbor::encode(SigStructure {
        context: "Signature1",
        protected: &sign1.protected,
        external_aad: &aad,
        payload: &[],
    })?;

    // Verify signature
    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(())
}

/// Validates a COSE_Sign1 digital signature and returns the embedded payload.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`verify_at`].
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for separating protocol purposes
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
///
/// Returns the CBOR-decoded embedded payload if verification succeeds.
pub fn verify<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    // Read the clock only if max_drift is specified
    let now = match max_drift {
        Some(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64,
        None => 0,
    };
    verify_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// Validates a COSE_Sign1 digital signature and returns the embedded payload,
/// checking drift against an explicit current time.
///
/// - `msg_to_check`: The serialized COSE_Sign1 structure
/// - `msg_to_auth`: The same additional authenticated data used during signing
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application domain for separating protocol purposes
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
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
    let aad = cbor::encode(&(&info, msg_to_auth))?;

    // Parse COSE_Sign1
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;

    // Verify payload is present (embedded). It can hold secrets, so every
    // buffer holding it is wiped on drop.
    let payload = Zeroizing::new(sign1.payload.ok_or(Error::MissingPayload)?);

    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check signature timestamp drift if max_drift is specified
    if let Some(max) = max_drift {
        let drift = now.abs_diff(header.timestamp);
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure to verify
    let blob = encode_wiped(
        SigStructure {
            context: "Signature1",
            protected: &sign1.protected,
            external_aad: &aad,
            payload: &payload,
        },
        sign1.protected.len() + aad.len() + payload.len(),
    )?;

    // Verify signature
    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(cbor::decode(&payload)?)
}

/// Extracts the signer's fingerprint from a COSE_Sign1 signature without
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

    // The payload can hold secrets and is never read, so it is wiped right away
    drop(Zeroizing::new(sign1.payload));

    let header: SigProtectedHeader = cbor::decode(&sign1.protected)?;
    Ok(header.kid)
}

/// Extracts the embedded payload from a COSE_Sign1 signature without
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

    // The payload can hold secrets, so it is wiped on drop
    let payload = Zeroizing::new(sign1.payload.ok_or(Error::MissingPayload)?);
    Ok(cbor::decode(&payload)?)
}

/// Signs a message, then encrypts it to a recipient.
///
/// Uses the current system time as the signature timestamp. For testing or custom
/// timestamps, use [`seal_at`].
///
/// - `msg_to_seal`: The message to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `padding`: Sender's policy for zeros after the signed envelope
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, or the required
/// bucket size exceeds [`usize::MAX`]. Also panics if the system time precedes
/// the Unix epoch.
pub fn seal<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
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
        padding,
        timestamp,
    )
}

/// Signs a message with an explicit timestamp, then encrypts it to a
/// recipient.
///
/// - `msg_to_seal`: The message to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (signed and bound to encryption, but not embedded)
/// - `signer`: The xDSA secret key to sign with
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `padding`: Sender's policy for zeros after the signed envelope
/// - `timestamp`: Unix timestamp in seconds to embed in the signature's protected header
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, or the required
/// bucket size exceeds [`usize::MAX`].
pub fn seal_at<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Pre-encode for EncStructure (which needs raw bytes for external_aad)
    let msg_to_auth = cbor::encode(msg_to_auth)?;

    // Create a COSE_Sign1 with the payload, binding the AAD (use Raw to avoid
    // re-encoding). It holds the plaintext, so it is wiped once encrypted.
    let signed = Zeroizing::new(sign_at(
        msg_to_seal,
        Raw(msg_to_auth.clone()),
        signer,
        domain,
        timestamp,
    )?);
    // Encrypt the signed message to the recipient
    encrypt(&signed, Raw(msg_to_auth), recipient, domain, padding)
}

/// Encrypts an already signed COSE_Sign1 to a recipient.
///
/// For most use cases, prefer [`seal`] which signs and encrypts in one step.
/// Use this only when re-encrypting a message (from [`decrypt`]) to a different
/// recipient without access to the original signer's key.
///
/// - `sign1`: The COSE_Sign1 structure (e.g., from [`decrypt`])
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `padding`: Sender's policy for zeros after the signed envelope
///
/// Returns the serialized COSE_Encrypt0 structure.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, or the required
/// bucket size exceeds [`usize::MAX`].
pub fn encrypt<A: Encode>(
    sign1: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
) -> Result<Vec<u8>, Error> {
    // Allocate the final size before copying plaintext, so it never reallocates
    let len = padding.padded_len(sign1.len());
    let mut plaintext = Zeroizing::new(Vec::with_capacity(len));
    plaintext.extend_from_slice(sign1);
    plaintext.resize(len, 0);

    // Pre-encode for EncStructure (which needs raw bytes for external_aad)
    let msg_to_auth = cbor::encode(msg_to_auth)?;

    // Build protected header with recipient's fingerprint
    let protected = cbor::encode(&EncProtectedHeader {
        algorithm: ALGORITHM_ID_XHPKE,
        kid: recipient.fingerprint(),
    })?;
    // Build and seal Enc_structure (domain prefixing is handled by xHPKE)
    let (encap_key, ciphertext) = recipient
        .seal(
            &plaintext,
            &cbor::encode(EncStructure {
                context: "Encrypt0",
                protected: &protected,
                external_aad: &msg_to_auth,
            })?,
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
    })?)
}

/// Decrypts and verifies a sealed message.
///
/// Uses the current system time for drift checking. For testing or custom
/// timestamps, use [`open_at`].
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
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
    // Read the clock only if max_drift is specified
    let now = match max_drift {
        Some(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64,
        None => 0,
    };
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

/// Decrypts and verifies a sealed message, checking drift against an explicit
/// current time.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `sender`: The xDSA public key to verify the signature against
/// - `domain`: Application domain for HPKE key derivation
/// - `max_drift`: Maximum allowed timestamp difference in seconds, past or future.
///   `Some(n)` accepts differences up to and including `n`; `None` skips the check.
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
    // Decrypt the COSE_Encrypt0 to get the COSE_Sign1. It holds the plaintext,
    // so it is wiped on drop, as is the payload extracted from it.
    let sign1 = Zeroizing::new(decrypt(
        msg_to_open,
        msg_to_auth.clone(),
        recipient,
        domain,
    )?);

    // Verify the signature and extract the payload
    let raw: Raw = verify_at::<Raw, _>(&sign1, &msg_to_auth, sender, domain, max_drift, now)?;
    let payload = Zeroizing::new(raw.0);
    Ok(cbor::decode(&payload)?)
}

/// Decrypts a sealed message without verifying its signature.
///
/// This allows inspecting the signer before verification. Use [`signer`] to
/// extract the signer's fingerprint, then [`verify`] or [`verify_at`] to verify.
///
/// It strips the zero bytes after the COSE_Sign1, accepting any number of them,
/// and returns the COSE_Sign1 as encoded. A plaintext that does not start with
/// one CBOR item fails with [`Error::CborError`], and a nonzero byte after it
/// with [`Error::InvalidPadding`].
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
    let msg_to_auth = cbor::encode(msg_to_auth)?;

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

    // Rebuild and open Enc_structure (domain prefixing is handled by xHPKE)
    let decrypted = Zeroizing::new(
        recipient
            .open(
                encap_key,
                &encrypt0.ciphertext,
                &cbor::encode(EncStructure {
                    context: "Encrypt0",
                    protected: &encrypt0.protected,
                    external_aad: &msg_to_auth,
                })?,
                domain,
            )
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?,
    );

    // Traverse one item without re-encoding, keeping both plaintext buffers wiped
    let mut decoder = cbor::Decoder::new(&decrypted);
    let mut sign1 = Zeroizing::new(Raw::decode_cbor_notrail(&mut decoder)?.0);
    if decrypted[sign1.len()..].iter().any(|&byte| byte != 0) {
        return Err(Error::InvalidPadding);
    }
    Ok(std::mem::take(&mut *sign1))
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 message without
/// decrypting it.
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

/// Upper bound in bytes on the CBOR framing around the variable length fields
/// of a COSE structure, covering the array and byte string headers, the context
/// string and the empty header map.
const FRAMING_OVERHEAD: usize = 64;

/// Encodes a structure holding a payload into a buffer wiped on drop. The
/// buffer is sized up front for `len` bytes of fields plus their framing, so it
/// never reallocates and leaves no partial copy of the payload behind.
fn encode_wiped<T: Encode>(value: T, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new(Vec::with_capacity(len + FRAMING_OVERHEAD));
    value.encode_cbor_to(&mut buf)?;
    debug_assert!(buf.len() <= len + FRAMING_OVERHEAD);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the bucket sequences and their boundary targets.
    #[test]
    fn test_padding_buckets() {
        // Pin each rounded-up step independently of the bucket calculation
        for (floor, step, sizes) in [
            (
                8192,
                20,
                [
                    8192, 8602, 9033, 9485, 9960, 10458, 10981, 11531, 12108, 12714,
                ]
                .as_slice(),
            ),
            (100, 3, [100, 134, 179, 239, 319, 426].as_slice()),
        ] {
            let padding = Padding::Buckets { floor, step };
            for pair in sizes.windows(2) {
                assert_eq!(padding.padded_len(pair[0]), pair[0], "{floor}/{step}");
                assert_eq!(padding.padded_len(pair[0] + 1), pair[1], "{floor}/{step}");
            }
        }

        // Check the floor, exact fits, transitions, and a larger envelope
        let padding = Padding::Buckets {
            floor: 8192,
            step: 20,
        };
        for (len, expected) in [
            (0, 8192),
            (1, 8192),
            (8192, 8192),
            (8193, 8602),
            (8602, 8602),
            (8603, 9033),
            (300000, 303278),
        ] {
            assert_eq!(padding.padded_len(len), expected, "{len}");
        }

        // No-padding preserves all lengths, and ceiling division cannot overflow
        for len in [0, 1, 8192, 8193, 300000, usize::MAX] {
            assert_eq!(Padding::None.padded_len(len), len, "{len}");
        }
        assert_eq!(
            Padding::Buckets {
                floor: usize::MAX - 1,
                step: usize::MAX,
            }
            .padded_len(usize::MAX),
            usize::MAX,
        );
    }

    /// Tests that a zero floor panics when sealing.
    #[test]
    #[should_panic(expected = "padding floor must be nonzero")]
    fn test_padding_zero_floor() {
        let recipient = xhpke::SecretKey::from_bytes(&[7; 32]);
        let _ = encrypt(
            &[0],
            (),
            &recipient.public_key(),
            b"padding",
            &Padding::Buckets { floor: 0, step: 20 },
        );
    }

    /// Tests that a zero step panics, even when the envelope fits the floor.
    #[test]
    #[should_panic(expected = "padding step must be nonzero")]
    fn test_padding_zero_step() {
        let recipient = xhpke::SecretKey::from_bytes(&[7; 32]);
        let _ = encrypt(
            &[0],
            (),
            &recipient.public_key(),
            b"padding",
            &Padding::Buckets {
                floor: 8192,
                step: 0,
            },
        );
    }

    /// Tests that a bucket size past usize::MAX panics instead of wrapping.
    #[test]
    #[should_panic(expected = "padding bucket size overflow")]
    fn test_padding_bucket_overflow() {
        Padding::Buckets {
            floor: usize::MAX - 1,
            step: 1,
        }
        .padded_len(usize::MAX);
    }

    /// Opens the raw AEAD plaintext through xHPKE, keeping the padding.
    fn open_plaintext<A: Encode>(
        envelope: &[u8],
        aad: A,
        recipient: &xhpke::SecretKey,
        domain: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        let envelope: CoseEncrypt0 = cbor::decode(envelope).unwrap();
        let aad = cbor::encode(EncStructure {
            context: "Encrypt0",
            protected: &envelope.protected,
            external_aad: &cbor::encode(aad).unwrap(),
        })
        .unwrap();
        Zeroizing::new(
            recipient
                .open(
                    envelope
                        .unprotected
                        .encap_key
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    &envelope.ciphertext,
                    &aad,
                    domain,
                )
                .unwrap(),
        )
    }

    /// Encrypts any plaintext through xHPKE, to test the COSE reader.
    fn seal_plaintext<A: Encode>(
        plaintext: &[u8],
        aad: A,
        recipient: &xhpke::PublicKey,
        domain: &[u8],
    ) -> Vec<u8> {
        // Bind the same headers and external AAD as the wire profile
        let protected = cbor::encode(EncProtectedHeader {
            algorithm: ALGORITHM_ID_XHPKE,
            kid: recipient.fingerprint(),
        })
        .unwrap();
        let aad = cbor::encode(EncStructure {
            context: "Encrypt0",
            protected: &protected,
            external_aad: &cbor::encode(aad).unwrap(),
        })
        .unwrap();

        // Bypass the COSE sender's padding policy
        let (encap_key, ciphertext) = recipient.seal(plaintext, &aad, domain).unwrap();
        cbor::encode(CoseEncrypt0 {
            protected,
            unprotected: EncapKeyHeader {
                encap_key: encap_key.to_vec(),
            },
            ciphertext,
        })
        .unwrap()
    }

    /// Tests both policies against a fixed COSE_Sign1 and its exact padded plaintext.
    #[test]
    fn test_sealed_plaintext_padding() {
        // Reuse the fixed v0.16 signature as the expected plaintext prefix
        let corpus: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
        let signer =
            xdsa::SecretKey::from_bytes(&fixture(&corpus, "xdsa_seed").try_into().unwrap());
        let recipient =
            xhpke::SecretKey::from_bytes(&fixture(&corpus, "xhpke_seed").try_into().unwrap());
        let sign1 = Zeroizing::new(fixture(&corpus, "sign1"));

        // Seal a payload and re-encrypt an existing signature under each policy
        for (padding, expected_len, expected_zeros) in [
            (Padding::None, 3461, 0),
            (
                Padding::Buckets {
                    floor: 8192,
                    step: 20,
                },
                8192,
                4731,
            ),
        ] {
            let sealed = seal_at(
                b"cose fixture payload".as_slice(),
                b"cose fixture aad".as_slice(),
                &signer,
                &recipient.public_key(),
                b"v016-fixtures",
                &padding,
                1700000000,
            )
            .unwrap();
            let encrypted = encrypt(
                &sign1,
                b"cose fixture aad".as_slice(),
                &recipient.public_key(),
                b"v016-fixtures",
                &padding,
            )
            .unwrap();

            // Inspect through xHPKE, then check stripping and signature verification
            for envelope in [sealed, encrypted] {
                let plaintext = open_plaintext(
                    &envelope,
                    b"cose fixture aad".as_slice(),
                    &recipient,
                    b"v016-fixtures",
                );
                assert_eq!(plaintext.len(), expected_len, "{padding:?}");
                assert_eq!(&plaintext[..3461], sign1.as_slice(), "{padding:?}");
                assert_eq!(&plaintext[3461..], vec![0; expected_zeros], "{padding:?}");
                let decrypted = Zeroizing::new(
                    decrypt(
                        &envelope,
                        b"cose fixture aad".as_slice(),
                        &recipient,
                        b"v016-fixtures",
                    )
                    .unwrap(),
                );
                assert_eq!(decrypted, sign1, "{padding:?}");
                let payload: Vec<u8> = open(
                    &envelope,
                    b"cose fixture aad".as_slice(),
                    &recipient,
                    &signer.public_key(),
                    b"v016-fixtures",
                    None,
                )
                .unwrap();
                assert_eq!(payload, b"cose fixture payload", "{padding:?}");
            }
        }
    }

    /// Tests that padding outside the sender's sizes opens, while a nonzero byte fails.
    #[test]
    fn test_decrypt_padding_validation() {
        // Append 37 zeros to a fixed Sign1, independently of the sender's policy
        let corpus: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
        let signer =
            xdsa::SecretKey::from_bytes(&fixture(&corpus, "xdsa_seed").try_into().unwrap());
        let recipient = xhpke::SecretKey::from_bytes(&[7; 32]);
        let sign1 = Zeroizing::new(fixture(&corpus, "sign1"));
        let mut plaintext = Zeroizing::new(vec![0; 3498]);
        plaintext[..3461].copy_from_slice(&sign1);
        let envelope = seal_plaintext(
            &plaintext,
            b"cose fixture aad".as_slice(),
            &recipient.public_key(),
            b"v016-fixtures",
        );

        // The reader accepts any zero padding length and returns the bare Sign1
        let decrypted = Zeroizing::new(
            decrypt(
                &envelope,
                b"cose fixture aad".as_slice(),
                &recipient,
                b"v016-fixtures",
            )
            .unwrap(),
        );
        assert_eq!(decrypted, sign1);
        let payload: Vec<u8> = open_at(
            &envelope,
            b"cose fixture aad".as_slice(),
            &recipient,
            &signer.public_key(),
            b"v016-fixtures",
            Some(0),
            1700000000,
        )
        .unwrap();
        assert_eq!(payload, b"cose fixture payload");

        // Refuse a nonzero at the start, middle, or end of authenticated padding
        for position in [3461, 3479, 3497] {
            for byte in [1, 255] {
                plaintext[position] = byte;
                let envelope = seal_plaintext(
                    &plaintext,
                    b"cose fixture aad".as_slice(),
                    &recipient.public_key(),
                    b"v016-fixtures",
                );
                assert_eq!(
                    decrypt(
                        &envelope,
                        b"cose fixture aad".as_slice(),
                        &recipient,
                        b"v016-fixtures",
                    ),
                    Err(Error::InvalidPadding),
                    "{position}/{byte}",
                );
                assert_eq!(
                    open::<Vec<u8>, _>(
                        &envelope,
                        b"cose fixture aad".as_slice(),
                        &recipient,
                        &signer.public_key(),
                        b"v016-fixtures",
                        None,
                    ),
                    Err(Error::InvalidPadding),
                    "{position}/{byte}",
                );
                plaintext[position] = 0;
            }
        }
    }

    /// Tests that a malformed plaintext fails in decrypt itself.
    #[test]
    fn test_decrypt_malformed_cbor() {
        let recipient = xhpke::SecretKey::from_bytes(&[7; 32]);
        for (plaintext, expected) in [
            (vec![], cbor::Error::UnexpectedEof),
            (vec![0x82, 0], cbor::Error::UnexpectedEof),
            (vec![0x81, 0x42, 0], cbor::Error::UnexpectedEof),
            (vec![0x18, 0], cbor::Error::NonCanonical),
            (vec![0xc0, 0], cbor::Error::UnsupportedType(6)),
            (vec![0x9f, 0xff], cbor::Error::InvalidAdditionalInfo(31)),
            (
                vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                cbor::Error::UnexpectedEof,
            ),
            (
                [vec![0x81; 32], vec![0]].concat(),
                cbor::Error::MaxDepthExceeded(32),
            ),
        ] {
            let envelope = seal_plaintext(&plaintext, (), &recipient.public_key(), b"padding");
            assert_eq!(
                decrypt(&envelope, (), &recipient, b"padding"),
                Err(Error::CborError(expected)),
                "{plaintext:x?}",
            );
        }
    }

    /// Tests that decrypt keeps the COSE_Sign1's encoding, zeros inside it included.
    #[test]
    fn test_decrypt_preserves_cbor_item() {
        // The item contains out-of-order map keys and a byte string ending in zero
        let recipient = xhpke::SecretKey::from_bytes(&[7; 32]);
        let plaintext = [0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0, 0, 0, 0];
        let envelope = seal_plaintext(&plaintext, (), &recipient.public_key(), b"padding");

        // Schema validation belongs to verification, and padding starts after the item
        let decrypted = Zeroizing::new(decrypt(&envelope, (), &recipient, b"padding").unwrap());
        assert_eq!(
            decrypted.as_slice(),
            [0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0]
        );
    }

    /// Tests various combinations of signing and verifying ops.
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
                    test.msg_to_sign.to_vec(),
                    test.msg_to_auth.to_vec(),
                    &alice,
                    test.domain,
                    ts,
                ),
                None => sign(
                    test.msg_to_sign.to_vec(),
                    test.msg_to_auth.to_vec(),
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
                &signed.unwrap(),
                test.verifier_msg_to_auth.to_vec(),
                &verifier,
                test.verifier_domain,
                test.max_drift,
            );

            if test.want_ok {
                let recovered = result.unwrap_or_else(|_| panic!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_sign, "test {}: payload mismatch", i);
            } else {
                assert!(result.is_err(), "test {}: expected error", i);
            }
        }
    }

    /// Tests that the drift check measures the true distance between timestamps
    /// at opposite ends of the i64 range, for embedded and detached signatures.
    #[test]
    fn test_drift_range() {
        let signer = xdsa::SecretKey::generate();
        let tests: [(&str, i64, i64, u64, bool); 5] = [
            (
                "wrapping distance",
                -9223372036854775740,
                9223372036854775683,
                209,
                false,
            ),
            ("full range within max", i64::MIN, i64::MAX, u64::MAX, true),
            (
                "full range over max",
                i64::MIN,
                i64::MAX,
                u64::MAX - 1,
                false,
            ),
            ("near the maximum", i64::MAX - 5, i64::MAX, 5, true),
            ("near the minimum", i64::MIN + 5, i64::MIN, 5, true),
        ];
        for (name, timestamp, now, max_drift, want_ok) in tests {
            let signed = sign_at(
                b"payload".as_slice(),
                b"".as_slice(),
                &signer,
                b"",
                timestamp,
            )
            .unwrap();
            let result = verify_at::<Vec<u8>, _>(
                &signed,
                b"".as_slice(),
                &signer.public_key(),
                b"",
                Some(max_drift),
                now,
            );
            assert_eq!(result.is_ok(), want_ok, "{name}");
            assert!(
                want_ok || matches!(result, Err(Error::StaleSignature(..))),
                "{name}"
            );

            let signed = sign_detached_at(b"".as_slice(), &signer, b"", timestamp).unwrap();
            let result = verify_detached_at(
                &signed,
                b"".as_slice(),
                &signer.public_key(),
                b"",
                Some(max_drift),
                now,
            );
            assert_eq!(result.is_ok(), want_ok, "{name}");
            assert!(
                want_ok || matches!(result, Err(Error::StaleSignature(..))),
                "{name}"
            );
        }
    }

    /// Tests various combinations of sealing and opening ops.
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
                    test.msg_to_seal.to_vec(),
                    test.msg_to_auth.to_vec(),
                    &alice,
                    &carol.public_key(),
                    test.domain,
                    &Padding::None,
                    ts,
                )
                .unwrap(),
                None => seal(
                    test.msg_to_seal.to_vec(),
                    test.msg_to_auth.to_vec(),
                    &alice,
                    &carol.public_key(),
                    test.domain,
                    &Padding::None,
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
                let recovered = result.unwrap_or_else(|_| panic!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_seal, "test {}: payload mismatch", i);
            } else {
                assert!(result.is_err(), "test {}: expected error", i);
            }
        }
    }

    /// Tests CBOR encoding/decoding for sign/verify.
    #[test]
    fn test_sign_verify_typed() {
        let alice = xdsa::SecretKey::generate();

        let payload = (42u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let signed = sign(&payload, &aad, &alice, b"baz").unwrap();
        let recovered: (u64, String) =
            verify(&signed, &aad, &alice.public_key(), b"baz", None).unwrap();

        assert_eq!(recovered, payload);
    }

    /// Tests CBOR encoding/decoding for seal/open.
    #[test]
    fn test_seal_open_typed() {
        let alice = xdsa::SecretKey::generate();
        let carol = xhpke::SecretKey::generate();

        let payload = (123u64, "foo".to_string());
        let aad = ("bar".to_string(),);

        let sealed = seal(
            &payload,
            &aad,
            &alice,
            &carol.public_key(),
            b"baz",
            &Padding::Buckets {
                floor: 8192,
                step: 20,
            },
        )
        .unwrap();
        assert_eq!(open_plaintext(&sealed, &aad, &carol, b"baz").len(), 8192);
        let recovered: (u64, String) =
            open(&sealed, &aad, &carol, &alice.public_key(), b"baz", None).unwrap();

        assert_eq!(recovered, payload);
    }

    /// Tests that signer and peek read an envelope without verifying it, and
    /// refuse one that is truncated or followed by trailing bytes.
    #[test]
    fn test_signer_peek() {
        let alice = xdsa::SecretKey::generate();

        // Read the signer and the payload of an embedded signature
        let signed = sign_at(b"foo".as_slice(), b"bar".as_slice(), &alice, b"baz", 0).unwrap();
        assert_eq!(signer(&signed).unwrap(), alice.fingerprint());
        assert_eq!(peek::<Vec<u8>>(&signed).unwrap(), b"foo");

        // Refuse the same envelope truncated or with a trailing byte
        let truncated = &signed[..signed.len() - 1];
        let trailing = [signed.as_slice(), &[0]].concat();
        for input in [truncated, &trailing] {
            assert!(signer(input).is_err());
            assert!(peek::<Vec<u8>>(input).is_err());
        }
        // A detached signature has a signer but no payload to peek at
        let signed = sign_detached_at(b"bar".as_slice(), &alice, b"baz", 0).unwrap();
        assert_eq!(signer(&signed).unwrap(), alice.fingerprint());
        assert!(matches!(
            peek::<Vec<u8>>(&signed),
            Err(Error::MissingPayload)
        ));
    }

    /// Fixture corpus generated with v0.16.0 to pin the COSE wire format.
    const FIXTURES: &str = include_str!("testdata/v0.16.json");

    /// Retrieves a hex encoded field from a fixture corpus.
    fn fixture(corpus: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(corpus[key].as_str().unwrap()).unwrap()
    }

    /// Tests that the padded fixture opens to its payload, pinning the padded format.
    #[test]
    fn test_padded_fixture() {
        // This envelope was sealed once by crypto-rs with invented fixture data
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("testdata/padded.json")).unwrap();
        let signer =
            xdsa::SecretKey::from_bytes(&fixture(&corpus, "xdsa_seed").try_into().unwrap());
        let recipient =
            xhpke::SecretKey::from_bytes(&fixture(&corpus, "xhpke_seed").try_into().unwrap());
        let domain = fixture(&corpus, "domain");
        let aad = fixture(&corpus, "aad");
        let sign1 = Zeroizing::new(fixture(&corpus, "sign1"));
        let envelope = fixture(&corpus, "encrypt0");

        // Pin the exact plaintext layout independently of the padding implementation
        assert_eq!(
            corpus["padding"],
            serde_json::json!({ "type": "buckets", "floor": 8192, "step": 20 }),
        );
        assert_eq!(corpus["plaintext_length"], 8192);
        let plaintext = open_plaintext(&envelope, aad.as_slice(), &recipient, &domain);
        assert_eq!(plaintext.len(), 8192);
        assert_eq!(&plaintext[..3470], sign1.as_slice());
        assert_eq!(&plaintext[3470..], [0; 4722]);
        let decrypted =
            Zeroizing::new(decrypt(&envelope, aad.as_slice(), &recipient, &domain).unwrap());
        assert_eq!(decrypted, sign1);

        // Verify the signature and its fixed timestamp, then read the payload
        assert_eq!(corpus["timestamp"], 1700000000);
        let payload: Vec<u8> = open_at(
            &envelope,
            aad.as_slice(),
            &recipient,
            &signer.public_key(),
            &domain,
            Some(0),
            1700000000,
        )
        .unwrap();
        assert_eq!(payload, b"padded cose fixture payload");
        assert_eq!(payload, fixture(&corpus, "payload"));
    }

    /// Tests that the v0.16 fixture corpus still validates, since that was in the
    /// first public release of the Ark, so we can't change the format anymore.
    #[test]
    fn test_v0_16_fixtures() {
        let corpus: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();

        let xdsa_seed: [u8; 64] = fixture(&corpus, "xdsa_seed").try_into().unwrap();
        let xhpke_seed: [u8; 32] = fixture(&corpus, "xhpke_seed").try_into().unwrap();
        let signer = xdsa::SecretKey::from_bytes(&xdsa_seed);
        let recipient = xhpke::SecretKey::from_bytes(&xhpke_seed);

        let domain = fixture(&corpus, "domain");
        let payload = fixture(&corpus, "payload");
        let aad = fixture(&corpus, "aad");
        let sign1 = fixture(&corpus, "sign1");
        let encrypt0 = fixture(&corpus, "encrypt0");

        // Verify the committed signature and check the embedded payload
        let got: Vec<u8> = verify_at(
            &sign1,
            aad.as_slice(),
            &signer.public_key(),
            &domain,
            None,
            0,
        )
        .unwrap();
        assert_eq!(got, payload);

        // Read the committed signature's signer and payload without verifying
        assert_eq!(super::signer(&sign1).unwrap(), signer.fingerprint());
        assert_eq!(peek::<Vec<u8>>(&sign1).unwrap(), payload);

        // Wrong domains and tampered structures must fail
        let bad = verify_at::<Vec<u8>, _>(
            &sign1,
            aad.as_slice(),
            &signer.public_key(),
            b"wrong",
            None,
            0,
        );
        assert!(bad.is_err());

        let mut tampered = sign1.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let bad = verify_at::<Vec<u8>, _>(
            &tampered,
            aad.as_slice(),
            &signer.public_key(),
            &domain,
            None,
            0,
        );
        assert!(bad.is_err());

        // Open the committed encrypted message and check the payload
        let got: Vec<u8> = open_at(
            &encrypt0,
            aad.as_slice(),
            &recipient,
            &signer.public_key(),
            &domain,
            None,
            0,
        )
        .unwrap();
        assert_eq!(got, payload);

        let mut tampered = encrypt0.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let bad = open_at::<Vec<u8>, _>(
            &tampered,
            aad.as_slice(),
            &recipient,
            &signer.public_key(),
            &domain,
            None,
            0,
        );
        assert!(bad.is_err());
    }
}
