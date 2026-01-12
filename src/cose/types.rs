// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE structure types with CBOR serialization.

use crate::cbor::Cbor;

/// xDSA signature size: 3309 (ML-DSA-65) + 64 (Ed25519) = 3373 bytes.
pub const SIGNATURE_SIZE: usize = 3373;

/// X-Wing encapsulated key size: 1088 (ML-KEM-768) + 32 (X25519) = 1120 bytes.
pub const ENCAP_KEY_SIZE: usize = 1120;

/// Private COSE header label for Unix timestamp.
pub const HEADER_TIMESTAMP: i64 = -70002;

/// Protected header for COSE_Sign1.
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
pub struct SigProtectedHeader {
    /// Algorithm identifier (COSE header label 1)
    #[cbor(key = 1)]
    pub algorithm: i64,
    /// Key identifier - signer's fingerprint (COSE header label 4)
    #[cbor(key = 4)]
    pub kid: [u8; 32],
    /// Unix timestamp in seconds (private header label)
    #[cbor(key = -70002)]
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
    pub kid: [u8; 32],
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
///     payload:     bstr,
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
    /// Payload bytes
    pub payload: Vec<u8>,
    /// Signature (fixed size for xDSA)
    pub signature: [u8; SIGNATURE_SIZE],
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
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct SigStructure {
    pub context: String,
    pub protected: Vec<u8>,
    pub external_aad: Vec<u8>,
    pub payload: Vec<u8>,
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
#[derive(Debug, Clone, PartialEq, Eq, Cbor)]
#[cbor(array)]
pub struct EncStructure {
    pub context: String,
    pub protected: Vec<u8>,
    pub external_aad: Vec<u8>,
}
