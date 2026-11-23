// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wire structures with CBOR serialization.

use zeroize::Zeroize;

use crate::cbor::Cbor;
use crate::{xdsa, xhpke};

/// Private COSE header label for the Unix timestamp.
pub const HEADER_TIMESTAMP: i64 = -70002;

/// Protected header for [`CoseSign1`].
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct SigProtectedHeader {
    /// Algorithm identifier (COSE header label 1).
    #[cbor(key = 1)]
    pub algorithm: i64,
    /// Critical header labels that every verifier must understand (COSE header
    /// label 2).
    #[cbor(key = 2)]
    pub crit: CritHeader,
    /// Signer's key fingerprint (COSE header label 4).
    #[cbor(key = 4)]
    pub kid: xdsa::Fingerprint,
    /// Signing time in seconds since the Unix epoch ([`HEADER_TIMESTAMP`]).
    #[cbor(key = -70002)]
    pub timestamp: i64,
}

/// Critical header labels list per RFC 9052.
///
/// Verifiers reject messages carrying unknown `crit` labels.
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct CritHeader {
    /// Timestamp header label ([`HEADER_TIMESTAMP`]).
    pub timestamp: i64,
}

/// Protected header for [`CoseEncrypt0`].
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EncProtectedHeader {
    /// Algorithm identifier (COSE header label 1).
    #[cbor(key = 1)]
    pub algorithm: i64,
    /// Recipient's key fingerprint (COSE header label 4).
    #[cbor(key = 4)]
    pub kid: xhpke::Fingerprint,
}

/// Empty unprotected header map for [`CoseSign1`].
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EmptyHeader {}

/// Unprotected header carrying the encapsulated key for [`CoseEncrypt0`].
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EncapKeyHeader {
    /// X-Wing encapsulated key (COSE header label -4).
    #[cbor(key = -4)]
    pub encap_key: Vec<u8>,
}

/// `COSE_Sign1` structure per RFC 9052 Section 4.2.
///
/// The payload is wiped on drop because signed envelopes can carry plaintext
/// secrets.
///
/// ```text
/// COSE_Sign1 = [
///     protected:   bstr,
///     unprotected: header_map,
///     payload:     bstr / null,
///     signature:   bstr
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct CoseSign1 {
    /// CBOR-encoded protected header map wrapped as a byte string.
    pub protected: Vec<u8>,
    /// Unprotected header map, always empty for signatures.
    pub unprotected: EmptyHeader,
    /// Embedded payload bytes, or `None` for detached signatures.
    pub payload: Option<Vec<u8>>,
    /// Composite xDSA signature.
    pub signature: xdsa::Signature,
}

impl Drop for CoseSign1 {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// `COSE_Encrypt0` structure per RFC 9052 Section 5.2.
///
/// ```text
/// COSE_Encrypt0 = [
///     protected:   bstr,
///     unprotected: header_map,
///     ciphertext:  bstr
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct CoseEncrypt0 {
    /// CBOR-encoded protected header map wrapped as a byte string.
    pub protected: Vec<u8>,
    /// Unprotected header map carrying the encapsulated key.
    pub unprotected: EncapKeyHeader,
    /// Encrypted payload bytes.
    pub ciphertext: Vec<u8>,
}

/// `Sig_structure` input for signing per RFC 9052 Section 4.4.
///
/// ```text
/// Sig_structure = [
///     context:        "Signature1",
///     body_protected: bstr,
///     external_aad:   bstr,
///     payload:        bstr
/// ]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigStructure<'a> {
    /// Fixed context string, `"Signature1"` for [`CoseSign1`].
    pub context: &'static str,
    /// CBOR-encoded protected header bytes.
    pub protected: &'a [u8],
    /// Authenticated external data carrying the prefixed domain and caller AAD.
    pub external_aad: &'a [u8],
    /// Signed payload bytes, or empty for detached signatures where the message
    /// travels in `external_aad`.
    pub payload: &'a [u8],
}

impl crate::cbor::Encode for SigStructure<'_> {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        crate::cbor::encode_array_header_to(buf, 4);
        self.context.encode_cbor_to(buf)?;
        self.protected.encode_cbor_to(buf)?;
        self.external_aad.encode_cbor_to(buf)?;
        self.payload.encode_cbor_to(buf)?;
        Ok(())
    }
}

/// `Enc_structure` input for AEAD authentication per RFC 9052 Section 5.3.
///
/// ```text
/// Enc_structure = [
///     context:      "Encrypt0",
///     protected:    bstr,
///     external_aad: bstr
/// ]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncStructure<'a> {
    /// Fixed context string, `"Encrypt0"` for [`CoseEncrypt0`].
    pub context: &'static str,
    /// CBOR-encoded protected header bytes.
    pub protected: &'a [u8],
    /// Authenticated external data carrying the CBOR-encoded caller AAD.
    pub external_aad: &'a [u8],
}

impl crate::cbor::Encode for EncStructure<'_> {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        crate::cbor::encode_array_header_to(buf, 3);
        self.context.encode_cbor_to(buf)?;
        self.protected.encode_cbor_to(buf)?;
        self.external_aad.encode_cbor_to(buf)?;
        Ok(())
    }
}
