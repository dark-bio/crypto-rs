// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE signed and encrypted envelopes over xDSA and xHPKE.
//!
//! <https://datatracker.ietf.org/doc/html/rfc9052>
//! <https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke>
//!
//! Signatures use [`CoseSign1`] envelopes carrying the signer's fingerprint and
//! a timestamp in the protected header. Encryption wraps a signed envelope in
//! [`CoseEncrypt0`], so every message created by [`seal`] is also signed.
//! Payloads and authenticated messages can be any type implementing this
//! crate's CBOR traits. Every operation binds an application domain prefixed
//! with [`DOMAIN_PREFIX`] that both sides must supply.
//!
//! ```
//! use darkbio_crypto::{cose, xdsa, xhpke};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = xdsa::SecretKey::generate();
//! let recipient = xhpke::SecretKey::generate();
//!
//! // Sign and verify a payload with separately supplied authenticated context
//! let envelope = cose::sign("hello".to_string(), "ctx", &signer, b"example")?;
//! let payload: String = cose::verify(&envelope, "ctx", &signer.public_key(), b"example", Some(60))?;
//! assert_eq!(payload, "hello");
//!
//! // Sign and encrypt to a recipient, then open and verify
//! let padding = cose::Padding::Buckets { floor: 8192, step: 20 };
//! let sealed = cose::seal("secret".to_string(), "ctx", &signer, &recipient.public_key(), b"example", &padding)?;
//! let opened: String = cose::open(&sealed, "ctx", &recipient, &signer.public_key(), b"example", Some(60))?;
//! assert_eq!(opened, "secret");
//! # Ok(())
//! # }
//! ```
//!
//! # Domain separation and freshness
//!
//! Choose distinct domains for distinct application operations. Domains prevent
//! a message for one purpose from verifying under another, but do not prevent
//! replays within the same domain. Verification accepts timestamps within
//! `max_drift` seconds of now (past or future); `None` skips the timestamp
//! check. Applications requiring one-time acceptance must track a message
//! identifier, nonce, or challenge to reject replays.
//!
//! # Wire profile
//!
//! Interoperating implementations must match these Dark Bio conventions:
//!
//! - Envelopes are untagged [`CoseSign1`] and [`CoseEncrypt0`] arrays; CBOR
//!   tags are rejected. Headers use this crate's deterministic integer-key
//!   maps.
//! - Private algorithm IDs are [`ALGORITHM_ID_XDSA`] (`-70000`) and
//!   [`ALGORITHM_ID_XHPKE`] (`-70001`). The protected `kid` holds the key
//!   fingerprint. Signatures require [`HEADER_TIMESTAMP`] (`-70002`) and list
//!   it in `crit`.
//! - For signatures, [`SigStructure::external_aad`] is the CBOR encoding of
//!   `[bstr(DOMAIN_PREFIX || domain), msg_to_auth]`. An embedded payload is the
//!   CBOR encoding of the caller's value.
//! - For [`sign_detached`], the caller's message travels in `external_aad`,
//!   [`SigStructure::payload`] is an empty byte string, and the envelope
//!   payload is null. Generic COSE detached-payload APIs that place the message
//!   in `Sig_structure.payload` must adapt to this convention.
//! - For encryption, [`EncStructure::external_aad`] is the CBOR encoding of
//!   `msg_to_auth`, and the encoded `EncStructure` is passed as HPKE AAD. HPKE
//!   key derivation uses `DOMAIN_PREFIX || domain` as `info`, and the X-Wing
//!   encapsulated key sits in unprotected header `-4`.
//! - The encryption plaintext is the encoded [`CoseSign1`] followed by zero
//!   bytes chosen by the sender's [`Padding`] policy. The signature does not
//!   cover the padding, while the encryption authenticates it. Receivers locate
//!   the end of [`CoseSign1`] by decoding one CBOR item and reject any nonzero
//!   trailing byte, accepting any count of trailing zeros (including zero) so
//!   senders can change padding policies independently.
//!
//! Here `bstr` denotes a CBOR byte string and `||` denotes byte concatenation.
//! Neither `domain` nor `msg_to_auth` appears in the returned envelope; both
//! sides must know or transmit them separately.

mod types;

pub use types::{
    CoseEncrypt0, CoseSign1, CritHeader, EmptyHeader, EncProtectedHeader, EncStructure,
    EncapKeyHeader, HEADER_TIMESTAMP, SigProtectedHeader, SigStructure,
};

// Use web-time so SystemTime works on both native targets and WebAssembly
use web_time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::cbor::{self, Decode, Encode, Raw};
use crate::{xdsa, xhpke};

/// Prefix prepended to the caller's application domain for signature
/// authentication and HPKE key derivation.
///
/// Both parties must use the same domain. Distinct domains separate application
/// purposes; replay protection within a domain is the application's
/// responsibility.
pub const DOMAIN_PREFIX: &[u8] = crate::xhpke::DOMAIN_PREFIX;

/// Policy controlling how many zero bytes a sender appends to a signed envelope
/// inside encryption to obscure message length.
///
/// Receivers strip any number of trailing zero bytes, so senders can change
/// their policy independently.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Padding {
    /// No padding; the plaintext is only the signed envelope.
    None,
    /// Trailing zeros up to the smallest bucket that fits the signed envelope.
    /// Buckets start at `floor` and grow by `ceil(size / step)` at each step.
    Buckets {
        /// Smallest padded size in bytes (must be nonzero).
        floor: usize,
        /// Growth denominator; each bucket adds `ceil(size / step)` (must be
        /// nonzero).
        step: usize,
    },
}

impl Padding {
    /// Returns the plaintext size after padding an envelope of `len` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `floor` or `step` is zero, or if the required bucket size
    /// exceeds [`usize::MAX`].
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

/// Failures returned by COSE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Envelope, header, or payload is not valid CBOR under this crate's rules.
    #[error("cbor: {0}")]
    CborError(#[from] cbor::Error),
    /// Protected header specifies the first algorithm (or `crit` label) where
    /// the second is required.
    #[error("unexpected algorithm: have {0}, want {1}")]
    UnexpectedAlgorithm(i64, i64),
    /// Envelope was signed by the first fingerprint, while the verifier key has
    /// the second. Use [`signer`] to look up the right key before verifying.
    #[error("unexpected signing key: have {0:x?}, want {1:x?}")]
    UnexpectedSigningKey(xdsa::Fingerprint, xdsa::Fingerprint),
    /// xDSA signature failed verification. Carries the underlying error text.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    /// Signature timestamp differs from now by the first count of seconds,
    /// exceeding the allowed drift in the second.
    #[error("signature stale: time drift {0}s exceeds max {1}s")]
    StaleSignature(u64, u64),
    /// [`verify_detached`] or [`verify_detached_at`] encountered an embedded
    /// payload.
    #[error("unexpected payload in detached signature")]
    UnexpectedPayload,
    /// [`verify`], [`verify_at`], or [`peek`] encountered a detached envelope
    /// with no payload.
    #[error("missing payload in embedded signature")]
    MissingPayload,
    /// Envelope was encrypted to the first fingerprint, while the recipient key
    /// has the second. Use [`recipient`] to look up the right key before
    /// decrypting.
    #[error("unexpected encryption key: have {0:x?}, want {1:x?}")]
    UnexpectedEncryptionKey(xhpke::Fingerprint, xhpke::Fingerprint),
    /// [`EncapKeyHeader`] carries an encapsulated key of the first size instead
    /// of [`xhpke::ENCAP_KEY_SIZE`].
    #[error("invalid encapsulated key size: {0}, expected {1}")]
    InvalidEncapKeySize(usize, usize),
    /// xHPKE encryption or decryption failed, such as from a wrong key,
    /// tampered ciphertext, or mismatched authenticated data.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    /// Decrypted plaintext contains a nonzero byte after its `COSE_Sign1`.
    #[error("invalid padding")]
    InvalidPadding,
}

/// Private COSE algorithm identifier for composite ML-DSA-65 + Ed25519
/// signatures.
pub const ALGORITHM_ID_XDSA: i64 = -70000;

/// Private COSE algorithm identifier for X-Wing (ML-KEM-768 + X25519).
pub const ALGORITHM_ID_XHPKE: i64 = -70001;

/// Returns the current Unix timestamp in seconds.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}

/// Creates a detached `COSE_Sign1` signature whose envelope payload is null.
///
/// `msg_to_auth` is authenticated through `external_aad` while the signature's
/// payload input is empty; see the module wire profile. Uses the current system
/// time as the signature timestamp; use [`sign_detached_at`] for an explicit
/// timestamp.
pub fn sign_detached<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_detached_at(msg_to_auth, signer, domain, now_unix())
}

/// Creates a `COSE_Sign1` signature embedding `msg_to_embed` and authenticating
/// `msg_to_auth` externally.
///
/// Uses the current system time as the signature timestamp; use [`sign_at`] for
/// an explicit timestamp.
pub fn sign<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_at(msg_to_embed, msg_to_auth, signer, domain, now_unix())
}

/// Creates a detached `COSE_Sign1` signature with an explicit Unix `timestamp`
/// in seconds.
///
/// Uses the same `external_aad` convention as [`sign_detached`].
pub fn sign_detached_at<A: Encode>(
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Scope the caller's domain under this crate's prefix
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
    // Build and sign Sig_structure with an empty payload for detached mode
    let signature = signer.sign(&cbor::encode(SigStructure {
        context: "Signature1",
        protected: &protected,
        external_aad: &aad,
        payload: &[],
    })?);
    // Encode COSE_Sign1 with a null payload
    Ok(cbor::encode(&CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: None,
        signature,
    })?)
}

/// Creates a `COSE_Sign1` signature embedding `msg_to_embed`, authenticating
/// `msg_to_auth` externally, and recording an explicit Unix `timestamp` in
/// seconds.
pub fn sign_at<E: Encode, A: Encode>(
    msg_to_embed: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // The payload can hold secrets, so every buffer holding it is wiped on drop
    let mut msg_to_embed = Zeroizing::new(cbor::encode(msg_to_embed)?);

    // Scope the caller's domain under this crate's prefix
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

    // Build and encode COSE_Sign1; its Drop impl wipes the payload on return
    let len = protected.len() + msg_to_embed.len() + xdsa::SIGNATURE_SIZE;
    let sign1 = CoseSign1 {
        protected,
        unprotected: EmptyHeader {},
        payload: Some(std::mem::take(&mut *msg_to_embed)),
        signature,
    };
    let mut encoded = encode_wiped(&sign1, len)?;

    // Hand the encoded COSE_Sign1 over to the caller
    Ok(std::mem::take(&mut *encoded))
}

/// Verifies a detached `COSE_Sign1` signature against `msg_to_auth`, `verifier`,
/// and `domain`.
///
/// `max_drift` bounds the allowed timestamp difference in seconds (past or
/// future) against the current system time; `None` skips the timestamp check.
/// Use [`verify_detached_at`] for an explicit reference time.
pub fn verify_detached<A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<(), Error> {
    // Read the clock only when drift checking is requested
    let now = match max_drift {
        Some(_) => now_unix(),
        None => 0,
    };
    verify_detached_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// Verifies a detached `COSE_Sign1` signature, checking timestamp drift
/// against the explicit Unix time `now` in seconds.
pub fn verify_detached_at<A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<(), Error> {
    // Scope the caller's domain under this crate's prefix
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth))?;

    // Decode COSE_Sign1 and require a null payload
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;
    if sign1.payload.is_some() {
        return Err(Error::UnexpectedPayload);
    }
    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check timestamp drift when max_drift is set
    if let Some(max) = max_drift {
        let drift = now.abs_diff(header.timestamp);
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure with an empty payload and verify the signature
    let blob = cbor::encode(SigStructure {
        context: "Signature1",
        protected: &sign1.protected,
        external_aad: &aad,
        payload: &[],
    })?;

    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(())
}

/// Verifies a `COSE_Sign1` signature and returns its decoded embedded payload.
///
/// `max_drift` bounds the allowed timestamp difference in seconds (past or
/// future) against the current system time; `None` skips the timestamp check.
/// Use [`verify_at`] for an explicit reference time.
pub fn verify<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    // Read the clock only when drift checking is requested
    let now = match max_drift {
        Some(_) => now_unix(),
        None => 0,
    };
    verify_at(msg_to_check, msg_to_auth, verifier, domain, max_drift, now)
}

/// Verifies a `COSE_Sign1` signature and returns its decoded embedded payload,
/// checking timestamp drift against the explicit Unix time `now` in seconds.
pub fn verify_at<E: Decode, A: Encode>(
    msg_to_check: &[u8],
    msg_to_auth: A,
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<E, Error> {
    // Scope the caller's domain under this crate's prefix
    let info = [DOMAIN_PREFIX, domain].concat();
    let aad = cbor::encode(&(&info, msg_to_auth))?;

    // Decode COSE_Sign1 and require an embedded payload; Drop wipes it on return
    let sign1: CoseSign1 = cbor::decode(msg_to_check)?;
    let payload = sign1.payload.as_deref().ok_or(Error::MissingPayload)?;

    // Verify the protected header
    let header = verify_sig_protected_header(&sign1.protected, ALGORITHM_ID_XDSA, verifier)?;

    // Check timestamp drift when max_drift is set
    if let Some(max) = max_drift {
        let drift = now.abs_diff(header.timestamp);
        if drift > max {
            return Err(Error::StaleSignature(drift, max));
        }
    }
    // Reconstruct Sig_structure and verify the signature
    let blob = encode_wiped(
        SigStructure {
            context: "Signature1",
            protected: &sign1.protected,
            external_aad: &aad,
            payload,
        },
        sign1.protected.len() + aad.len() + payload.len(),
    )?;

    verifier
        .verify(&blob, &sign1.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(cbor::decode(payload)?)
}

/// Extracts the signer's fingerprint from a `COSE_Sign1` envelope without
/// verifying the signature.
///
/// Use this to look up the expected verification key before calling [`verify`]
/// or [`verify_detached`].
pub fn signer(signature: &[u8]) -> Result<xdsa::Fingerprint, Error> {
    let sign1: CoseSign1 = cbor::decode(signature)?;
    let header: SigProtectedHeader = cbor::decode(&sign1.protected)?;
    Ok(header.kid)
}

/// Extracts and decodes the embedded payload from a `COSE_Sign1` envelope
/// without verifying the signature.
///
/// Do not trust the returned payload until the envelope has been verified with
/// [`verify`]. Use [`signer`] to look up the verification key by fingerprint.
pub fn peek<E: Decode>(signature: &[u8]) -> Result<E, Error> {
    let sign1: CoseSign1 = cbor::decode(signature)?;
    let payload = sign1.payload.as_deref().ok_or(Error::MissingPayload)?;
    Ok(cbor::decode(payload)?)
}

/// Signs `msg_to_seal` with `signer`, pads it according to `padding`, and
/// encrypts the resulting `COSE_Sign1` to `recipient` in a `COSE_Encrypt0`
/// envelope.
///
/// `msg_to_auth` is authenticated by both the signature and the encryption, and
/// must be supplied separately when opening. Uses the current system time as
/// the signature timestamp; use [`seal_at`] for an explicit timestamp.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, if the required
/// bucket size exceeds [`usize::MAX`], or if the system time precedes the Unix
/// epoch.
pub fn seal<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
) -> Result<Vec<u8>, Error> {
    seal_at(
        msg_to_seal,
        msg_to_auth,
        signer,
        recipient,
        domain,
        padding,
        now_unix(),
    )
}

/// Signs `msg_to_seal` with an explicit Unix `timestamp` in seconds, pads it
/// according to `padding`, and encrypts the resulting `COSE_Sign1` to
/// `recipient` in a `COSE_Encrypt0` envelope.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, or if the
/// required bucket size exceeds [`usize::MAX`].
pub fn seal_at<E: Encode, A: Encode>(
    msg_to_seal: E,
    msg_to_auth: A,
    signer: &xdsa::SecretKey,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    // Pre-encode msg_to_auth once so both signing and encryption share the bytes
    let aad = Raw(cbor::encode(msg_to_auth)?);

    // Sign the payload, keeping the encoded Sign1 wiped once encrypted
    let signed = Zeroizing::new(sign_at(msg_to_seal, &aad, signer, domain, timestamp)?);
    encrypt(&signed, &aad, recipient, domain, padding)
}

/// Pads and encrypts an already signed `COSE_Sign1` envelope to `recipient` in
/// a `COSE_Encrypt0` envelope.
///
/// Prefer [`seal`] for normal use. Use this only when re-encrypting a signed
/// envelope (for example from [`decrypt`]) to another recipient without access
/// to the original signer's key.
///
/// # Panics
///
/// Panics if [`Padding::Buckets`] has a zero `floor` or `step`, or if the
/// required bucket size exceeds [`usize::MAX`].
pub fn encrypt<A: Encode>(
    sign1: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::PublicKey,
    domain: &[u8],
    padding: &Padding,
) -> Result<Vec<u8>, Error> {
    // Allocate the final size before copying plaintext so it never reallocates
    let len = padding.padded_len(sign1.len());
    let mut plaintext = Zeroizing::new(Vec::with_capacity(len));
    plaintext.extend_from_slice(sign1);
    plaintext.resize(len, 0);

    // Pre-encode msg_to_auth for EncStructure::external_aad
    let msg_to_auth = cbor::encode(msg_to_auth)?;

    // Build protected header with recipient's fingerprint
    let protected = cbor::encode(&EncProtectedHeader {
        algorithm: ALGORITHM_ID_XHPKE,
        kid: recipient.fingerprint(),
    })?;
    // Seal Enc_structure with xHPKE (which prefixes the domain)
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

    // Encode COSE_Encrypt0
    Ok(cbor::encode(&CoseEncrypt0 {
        protected,
        unprotected: EncapKeyHeader {
            encap_key: encap_key.to_vec(),
        },
        ciphertext,
    })?)
}

/// Decrypts a `COSE_Encrypt0` envelope, verifies its inner `COSE_Sign1`
/// signature, and returns the decoded payload.
///
/// `max_drift` bounds the allowed timestamp difference in seconds (past or
/// future) against the current system time; `None` skips the timestamp check.
/// Use [`open_at`] for an explicit reference time.
pub fn open<E: Decode, A: Encode>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
) -> Result<E, Error> {
    // Read the clock only when drift checking is requested
    let now = match max_drift {
        Some(_) => now_unix(),
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

/// Decrypts a `COSE_Encrypt0` envelope, verifies its inner `COSE_Sign1`
/// signature against the explicit Unix time `now` in seconds, and returns the
/// decoded payload.
pub fn open_at<E: Decode, A: Encode>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    sender: &xdsa::PublicKey,
    domain: &[u8],
    max_drift: Option<u64>,
    now: i64,
) -> Result<E, Error> {
    let aad = Raw(cbor::encode(msg_to_auth)?);

    // Wipe the decrypted Sign1 buffer after verification completes
    let sign1 = Zeroizing::new(decrypt(msg_to_open, &aad, recipient, domain)?);
    verify_at::<E, _>(&sign1, &aad, sender, domain, max_drift, now)
}

/// Decrypts a `COSE_Encrypt0` envelope and strips trailing zero padding,
/// returning the unverified inner `COSE_Sign1` bytes.
///
/// Use [`signer`] to inspect the sender's fingerprint before verifying with
/// [`verify`] or [`verify_at`]. A plaintext that does not start with one valid
/// CBOR item fails with [`Error::CborError`], and any nonzero trailing byte
/// fails with [`Error::InvalidPadding`].
pub fn decrypt<A: Encode>(
    msg_to_open: &[u8],
    msg_to_auth: A,
    recipient: &xhpke::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    // Pre-encode msg_to_auth for EncStructure::external_aad
    let msg_to_auth = cbor::encode(msg_to_auth)?;

    // Decode COSE_Encrypt0 and verify its protected header
    let encrypt0: CoseEncrypt0 = cbor::decode(msg_to_open)?;
    verify_enc_protected_header(&encrypt0.protected, ALGORITHM_ID_XHPKE, recipient)?;

    // Extract the fixed-size encapsulated key from the unprotected header
    let encap_key: &[u8; xhpke::ENCAP_KEY_SIZE] = encrypt0
        .unprotected
        .encap_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::InvalidEncapKeySize(encrypt0.unprotected.encap_key.len(), xhpke::ENCAP_KEY_SIZE)
        })?;

    // Open Enc_structure with xHPKE (which prefixes the domain)
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

/// Extracts the recipient's fingerprint from a `COSE_Encrypt0` envelope without
/// decrypting it.
///
/// Use this to look up the expected decryption key before calling [`open`] or
/// [`decrypt`].
pub fn recipient(ciphertext: &[u8]) -> Result<xhpke::Fingerprint, Error> {
    let encrypt0: CoseEncrypt0 = cbor::decode(ciphertext)?;
    let header: EncProtectedHeader = cbor::decode(&encrypt0.protected)?;
    Ok(header.kid)
}

/// Verifies that the signature protected header matches `exp_algo`, lists
/// [`HEADER_TIMESTAMP`] in `crit`, and matches `verifier`'s fingerprint.
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

/// Verifies that the encryption protected header matches `exp_algo` and
/// `recipient`'s fingerprint.
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

/// Upper bound in bytes on the CBOR framing around the variable-length fields
/// of a COSE structure, covering the array and byte string headers, the context
/// string, and the empty header map.
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
            for (envelope, fixed_sign1) in [(sealed, false), (encrypted, true)] {
                let plaintext = open_plaintext(
                    &envelope,
                    b"cose fixture aad".as_slice(),
                    &recipient,
                    b"v016-fixtures",
                );
                assert_eq!(plaintext.len(), expected_len, "{padding:?}");
                if fixed_sign1 {
                    assert_eq!(&plaintext[..3461], sign1.as_slice(), "{padding:?}");
                }
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
                assert_eq!(decrypted.as_slice(), &plaintext[..3461], "{padding:?}");
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

    /// Tests signing and verification across valid, drifted, wrong-domain,
    /// wrong-AAD, and wrong-key cases.
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
            want_err: Option<fn(&Error) -> bool>,
        }
        let now = now_unix();

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
                want_err: None,
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
                want_err: None,
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
                want_err: None,
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
                want_err: None,
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
                want_err: Some(|err| matches!(err, Error::StaleSignature(..))),
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
                want_err: Some(|err| matches!(err, Error::StaleSignature(..))),
            },
            // Wrong domain
            TestCase {
                msg_to_sign: b"foo",
                msg_to_auth: b"bar",
                verifier_msg_to_auth: b"bar",
                domain: b"baz",
                verifier_domain: b"baz2",
                timestamp: None,
                max_drift: None,
                wrong_key: false,
                want_err: Some(|err| matches!(err, Error::InvalidSignature(_))),
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
                want_err: Some(|err| matches!(err, Error::InvalidSignature(_))),
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
                want_err: Some(|err| matches!(err, Error::UnexpectedSigningKey(..))),
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

            if let Some(check) = test.want_err {
                let err = result.unwrap_err();
                assert!(check(&err), "test {i}: unexpected error {err:?}");
            } else {
                let recovered = result.unwrap_or_else(|_| panic!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_sign, "test {}: payload mismatch", i);
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

    /// Tests sealing and opening across valid, drifted, wrong-domain,
    /// wrong-AAD, and wrong-signer cases.
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
            want_err: Option<fn(&Error) -> bool>,
        }
        // Fetch the current time for drift tests
        let now = now_unix();

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
                want_err: None,
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
                want_err: None,
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
                want_err: None,
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
                want_err: None,
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
                want_err: Some(|err| matches!(err, Error::DecryptionFailed(_))),
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
                want_err: Some(|err| matches!(err, Error::DecryptionFailed(_))),
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
                want_err: Some(|err| matches!(err, Error::UnexpectedSigningKey(..))),
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
                want_err: Some(|err| matches!(err, Error::StaleSignature(..))),
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
                want_err: Some(|err| matches!(err, Error::StaleSignature(..))),
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
                test.opener_msg_to_auth,
                &carol,
                &verifier,
                test.opener_domain,
                test.max_drift,
            );

            if let Some(check) = test.want_err {
                let err = result.unwrap_err();
                assert!(check(&err), "test {i}: unexpected error {err:?}");
            } else {
                let recovered = result.unwrap_or_else(|_| panic!("test {}: expected success", i));
                assert_eq!(recovered, test.msg_to_seal, "test {}: payload mismatch", i);
            }
        }
    }

    /// Tests rejection of incorrect COSE headers, payload modes, and encapsulated key sizes.
    #[test]
    fn test_header_and_envelope_errors() {
        let signer = xdsa::SecretKey::generate();
        let verifier = signer.public_key();
        let kid = verifier.fingerprint();
        let other = xdsa::Fingerprint::from_bytes(&[0; xdsa::FINGERPRINT_SIZE]);
        let signed = sign_at((), (), &signer, b"", 0).unwrap();
        let mut sign1: CoseSign1 = cbor::decode(&signed).unwrap();

        // Check Sign1 payload-mode and protected-header mismatches
        assert_eq!(
            verify_detached_at(&signed, (), &verifier, b"", None, 0),
            Err(Error::UnexpectedPayload)
        );
        let alg = ALGORITHM_ID_XDSA;
        let crit = HEADER_TIMESTAMP;
        for (algorithm, crit, kid, expected) in [
            (0, crit, kid, Error::UnexpectedAlgorithm(0, alg)),
            (alg, 0, kid, Error::UnexpectedAlgorithm(0, crit)),
            (alg, crit, other, Error::UnexpectedSigningKey(other, kid)),
        ] {
            sign1.protected = cbor::encode(SigProtectedHeader {
                algorithm,
                crit: CritHeader { timestamp: crit },
                kid,
                timestamp: 0,
            })
            .unwrap();
            let envelope = cbor::encode(&sign1).unwrap();
            assert_eq!(
                verify_at::<(), _>(&envelope, (), &verifier, b"", None, 0),
                Err(expected)
            );
        }
        let detached = sign_detached_at((), &signer, b"", 0).unwrap();
        assert_eq!(
            verify_at::<(), _>(&detached, (), &verifier, b"", None, 0),
            Err(Error::MissingPayload)
        );

        // Check Encrypt0 protected-header and encapsulated-key-length errors
        let recipient = xhpke::SecretKey::generate();
        let kid = recipient.fingerprint();
        let other = xhpke::Fingerprint::from_bytes(&[0; xhpke::FINGERPRINT_SIZE]);
        let size = xhpke::ENCAP_KEY_SIZE;
        let sealed = encrypt(&signed, (), &recipient.public_key(), b"", &Padding::None).unwrap();
        let alg = ALGORITHM_ID_XHPKE;
        for (algorithm, kid, len, expected) in [
            (0, kid, size, Error::UnexpectedAlgorithm(0, alg)),
            (alg, other, size, Error::UnexpectedEncryptionKey(other, kid)),
            (alg, kid, 0, Error::InvalidEncapKeySize(0, size)),
        ] {
            let mut encrypt0: CoseEncrypt0 = cbor::decode(&sealed).unwrap();
            encrypt0.protected = cbor::encode(EncProtectedHeader { algorithm, kid }).unwrap();
            encrypt0.unprotected.encap_key.truncate(len);
            let envelope = cbor::encode(&encrypt0).unwrap();
            assert_eq!(decrypt(&envelope, (), &recipient, b""), Err(expected));
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

    /// Retrieves a hex-encoded field from a fixture corpus.
    fn fixture(corpus: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(corpus[key].as_str().unwrap()).unwrap()
    }

    /// Tests that the padded fixture opens to its payload, pinning the padded format.
    #[test]
    fn test_padded_fixture() {
        // Envelope sealed once with invented fixture data
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

    /// Tests that the committed v0.16 COSE fixtures still verify and open.
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
