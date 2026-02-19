// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE structure types with CBOR serialization.

use crate::cbor::Cbor;
use crate::{xdsa, xhpke};

/// Private COSE header label for Unix timestamp.
pub const HEADER_TIMESTAMP: i64 = -70002;

/// Protected header for COSE_Sign1.
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct SigProtectedHeader {
    /// Algorithm identifier (COSE header label 1)
    #[cbor(key = 1)]
    pub algorithm: i64,
    /// Critical headers that must be understood (COSE header label 2)
    #[cbor(key = 2)]
    pub crit: CritHeader,
    /// Key identifier - signer's fingerprint (COSE header label 4)
    #[cbor(key = 4)]
    pub kid: xdsa::Fingerprint,
    /// Unix timestamp in seconds (private header label)
    #[cbor(key = -70002)]
    pub timestamp: i64,
}

/// Critical headers list per RFC 9052.
/// Implementations must reject messages with unknown crit labels.
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct CritHeader {
    /// HeaderTimestamp label - must be understood
    pub timestamp: i64,
}

/// Protected header for COSE_Encrypt0.
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EncProtectedHeader {
    /// Algorithm identifier (COSE header label 1)
    #[cbor(key = 1)]
    pub algorithm: i64,
    /// Key identifier - recipient's fingerprint (COSE header label 4)
    #[cbor(key = 4)]
    pub kid: xhpke::Fingerprint,
}

/// Empty unprotected header map (for COSE_Sign1).
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EmptyHeader {}

/// Unprotected header containing the encapsulated key (for COSE_Encrypt0).
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct EncapKeyHeader {
    /// Encapsulated key (COSE header label -4)
    #[cbor(key = -4)]
    pub encap_key: Vec<u8>,
}

/// COSE_Sign1 structure per RFC 9052 Section 4.2.
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
    /// Protected header (CBOR-encoded map, wrapped as bstr)
    pub protected: Vec<u8>,
    /// Unprotected header map (empty for signatures)
    pub unprotected: EmptyHeader,
    /// Payload bytes (null for detached payload)
    pub payload: Option<Vec<u8>>,
    /// Signature (fixed size for xDSA)
    pub signature: xdsa::Signature,
}

/// COSE_Encrypt0 structure per RFC 9052 Section 5.2.
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
    /// Protected header (CBOR-encoded map, wrapped as bstr)
    pub protected: Vec<u8>,
    /// Unprotected header map (contains encapsulated key)
    pub unprotected: EncapKeyHeader,
    /// Ciphertext bytes
    pub ciphertext: Vec<u8>,
}

/// Sig_structure for computing signatures per RFC 9052 Section 4.4.
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
    pub context: &'static str,
    pub protected: &'a [u8],
    pub external_aad: &'a [u8],
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

/// Enc_structure for computing AAD per RFC 9052 Section 5.3.
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
    pub context: &'static str,
    pub protected: &'a [u8],
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
