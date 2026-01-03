// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE structure types with CBOR serialization.

use crate::cbor::{Decode, Decoder, Encode, Encoder, Error};
use std::collections::HashMap;

/// xDSA signature size: 3309 (ML-DSA-65) + 64 (Ed25519) = 3373 bytes.
pub const SIGNATURE_SIZE: usize = 3373;

/// X-Wing encapsulated key size: 1088 (ML-KEM-768) + 32 (X25519) = 1120 bytes.
pub const ENCAP_KEY_SIZE: usize = 1120;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1 {
    /// Protected header (CBOR-encoded map, wrapped as bstr)
    pub protected: Vec<u8>,
    /// Unprotected header map
    pub unprotected: HashMap<i64, Vec<u8>>,
    /// Payload bytes
    pub payload: Vec<u8>,
    /// Signature (fixed size for xDSA)
    pub signature: [u8; SIGNATURE_SIZE],
}

/// Internal tuple type for CoseSign1 serialization.
type CoseSign1Tuple = (
    Vec<u8>,
    HashMap<i64, Vec<u8>>,
    Vec<u8>,
    [u8; SIGNATURE_SIZE],
);

impl Encode for CoseSign1 {
    fn encode_cbor(&self) -> Vec<u8> {
        let tuple: CoseSign1Tuple = (
            self.protected.clone(),
            self.unprotected.clone(),
            self.payload.clone(),
            self.signature,
        );
        tuple.encode_cbor()
    }
}

impl Decode for CoseSign1 {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut decoder)?;
        decoder.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let (protected, unprotected, payload, signature) =
            CoseSign1Tuple::decode_cbor_notrail(decoder)?;

        Ok(Self {
            protected,
            unprotected,
            payload,
            signature,
        })
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseEncrypt0 {
    /// Protected header (CBOR-encoded map, wrapped as bstr)
    pub protected: Vec<u8>,
    /// Unprotected header map (contains encapsulated key)
    pub unprotected: HashMap<i64, Vec<u8>>,
    /// Ciphertext bytes
    pub ciphertext: Vec<u8>,
}

/// Internal tuple type for CoseEncrypt0 serialization.
type CoseEncrypt0Tuple = (Vec<u8>, HashMap<i64, Vec<u8>>, Vec<u8>);

impl Encode for CoseEncrypt0 {
    fn encode_cbor(&self) -> Vec<u8> {
        let tuple: CoseEncrypt0Tuple = (
            self.protected.clone(),
            self.unprotected.clone(),
            self.ciphertext.clone(),
        );
        tuple.encode_cbor()
    }
}

impl Decode for CoseEncrypt0 {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut decoder)?;
        decoder.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let (protected, unprotected, ciphertext) = CoseEncrypt0Tuple::decode_cbor_notrail(decoder)?;

        Ok(Self {
            protected,
            unprotected,
            ciphertext,
        })
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigStructure<'a> {
    pub protected: &'a [u8],
    pub external_aad: &'a [u8],
    pub payload: &'a [u8],
}

impl Encode for SigStructure<'_> {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_array_header(4);
        encoder.encode_text("Signature1");
        encoder.encode_bytes(self.protected);
        encoder.encode_bytes(self.external_aad);
        encoder.encode_bytes(self.payload);
        encoder.finish()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncStructure<'a> {
    pub protected: &'a [u8],
    pub external_aad: &'a [u8],
}

impl Encode for EncStructure<'_> {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_array_header(3);
        encoder.encode_text("Encrypt0");
        encoder.encode_bytes(self.protected);
        encoder.encode_bytes(self.external_aad);
        encoder.finish()
    }
}
