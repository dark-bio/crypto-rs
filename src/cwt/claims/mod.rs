// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Standard CWT claim types.
//!
//! <https://datatracker.ietf.org/doc/html/rfc8392>

pub mod eat;

use crate::cbor::{
    self, Cbor, Decode, Encode, MapDecode, MapEncode, MapEncodeBuffer, MapEntryAccess,
};
use crate::cose;
use crate::xdsa;
use crate::xhpke;

/// Principal that issued the token (key 1).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Issuer {
    /// Issuer identity, such as a URI or agreed-upon identifier.
    #[cbor(key = 1)]
    pub iss: String,
}

/// Principal that is the subject of the token (key 2).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Subject {
    /// Subject identity, such as a device serial or attestation subject.
    #[cbor(key = 2)]
    pub sub: String,
}

/// Intended recipients of the token (key 3).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Audience {
    /// Intended audience, such as a URI or agreed-upon identifier.
    #[cbor(key = 3)]
    pub aud: String,
}

/// Time on or after which the token must not be accepted (key 4).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Expiration {
    /// Expiration time in seconds since the Unix epoch; rejected at or after.
    #[cbor(key = 4)]
    pub exp: u64,
}

/// Time before which the token must not be accepted (key 5).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct NotBefore {
    /// Not-before time in seconds since the Unix epoch; rejected before.
    #[cbor(key = 5)]
    pub nbf: u64,
}

/// Time at which the token was issued (key 6).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct IssuedAt {
    /// Issue time in seconds since the Unix epoch.
    #[cbor(key = 6)]
    pub iat: u64,
}

/// Unique identifier for the token (key 7).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct TokenId {
    /// Opaque bytes uniquely identifying this token.
    #[cbor(key = 7)]
    pub cti: Vec<u8>,
}

/// Private module sealing [`ConfirmKey`] so external crates cannot implement it.
mod sealed {
    use crate::cbor;

    /// Internal codec contract for public keys embedded in a `cnf` claim.
    pub trait ConfirmKeySealed {
        /// COSE algorithm identifier stored in `COSE_Key`'s `kty` field.
        const ALGORITHM: i64;
        /// Serializes the key into raw bytes for `COSE_Key` parameter `-2`.
        fn to_confirm_bytes(&self) -> Vec<u8>;
        /// Parses raw bytes from `COSE_Key` parameter `-2` into the key.
        fn from_confirm_bytes(bytes: &[u8]) -> Result<Self, cbor::Error>
        where
            Self: Sized;
    }
}

/// Marker trait for key types usable with [`Confirm`].
///
/// Implemented for [`xdsa::PublicKey`] and [`xhpke::PublicKey`].
pub trait ConfirmKey: sealed::ConfirmKeySealed + Clone + std::fmt::Debug {}

impl sealed::ConfirmKeySealed for xdsa::PublicKey {
    const ALGORITHM: i64 = cose::ALGORITHM_ID_XDSA;

    fn to_confirm_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_confirm_bytes(bytes: &[u8]) -> Result<Self, cbor::Error> {
        let arr: [u8; xdsa::PUBLIC_KEY_SIZE] = bytes.try_into().map_err(|_| {
            cbor::Error::DecodeFailed(format!(
                "cnf: unexpected key size {}, want {}",
                bytes.len(),
                xdsa::PUBLIC_KEY_SIZE,
            ))
        })?;
        xdsa::PublicKey::from_bytes(&arr).map_err(|e| cbor::Error::DecodeFailed(e.to_string()))
    }
}

impl ConfirmKey for xdsa::PublicKey {}

impl sealed::ConfirmKeySealed for xhpke::PublicKey {
    const ALGORITHM: i64 = cose::ALGORITHM_ID_XHPKE;

    fn to_confirm_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_confirm_bytes(bytes: &[u8]) -> Result<Self, cbor::Error> {
        let arr: [u8; xhpke::PUBLIC_KEY_SIZE] = bytes.try_into().map_err(|_| {
            cbor::Error::DecodeFailed(format!(
                "cnf: unexpected key size {}, want {}",
                bytes.len(),
                xhpke::PUBLIC_KEY_SIZE,
            ))
        })?;
        xhpke::PublicKey::from_bytes(&arr).map_err(|e| cbor::Error::DecodeFailed(e.to_string()))
    }
}

impl ConfirmKey for xhpke::PublicKey {}

/// Public key bound to the token through the `cnf` claim (key 8, RFC 8747).
///
/// `COSE_Key` wrapping is handled internally. A verified token authenticates
/// this key binding, but does not prove that the presenter possesses the
/// corresponding private key; applications must check proof of possession
/// separately.
#[derive(Clone, Debug)]
pub struct Confirm<T: ConfirmKey> {
    key: T,
}

impl<T: ConfirmKey> Confirm<T> {
    /// Creates a [`Confirm`] claim binding `key`.
    pub fn new(key: T) -> Self {
        Self { key }
    }

    /// Returns a reference to the bound public key.
    pub fn key(&self) -> &T {
        &self.key
    }
}

/// Wire envelope `{ 1: COSE_Key }` for the `cnf` claim value.
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
struct CnfMap {
    #[cbor(key = 1)]
    cose_key: CoseKey,
}

/// Minimal `COSE_Key` `{ 1: kty, -2: x }` carrying raw public key bytes in
/// parameter `-2` per the OKP convention (RFC 9053 Section 7.2).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
struct CoseKey {
    #[cbor(key = 1)]
    kty: i64,
    #[cbor(key = -2)]
    x: Vec<u8>,
}

impl<T: ConfirmKey> Encode for Confirm<T> {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        let mut enc = MapEncodeBuffer::new(1);
        <Self as MapEncode>::encode_map(self, &mut enc)?;
        enc.finish_to(buf)
    }
}

impl<T: ConfirmKey> Decode for Confirm<T> {
    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let entries = cbor::decode_map_entries_slices_notrail(dec)?;
        let mut remaining = cbor::MapEntries::new(entries);
        let value = <Self as MapDecode>::decode_map(&mut remaining)?;
        if !remaining.is_empty() {
            let unknown: Vec<i64> = remaining.remaining_keys();
            return Err(cbor::Error::DecodeFailed(format!(
                "unknown CBOR map keys: {unknown:?}"
            )));
        }
        Ok(value)
    }
}

impl<T: ConfirmKey> MapEncode for Confirm<T> {
    fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), cbor::Error> {
        let cnf = CnfMap {
            cose_key: CoseKey {
                kty: T::ALGORITHM,
                x: self.key.to_confirm_bytes(),
            },
        };
        enc.push(8, &cnf)
    }
}

impl<T: ConfirmKey> MapDecode for Confirm<T> {
    fn cbor_map_keys() -> &'static [i64] {
        &[8]
    }

    fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, cbor::Error> {
        let raw = entries.take(8).ok_or(cbor::Error::DecodeFailed(
            "missing required key 8 (cnf)".into(),
        ))?;
        let cnf = CnfMap::decode_cbor(raw)?;

        // Verify the algorithm matches the expected key type
        if cnf.cose_key.kty != T::ALGORITHM {
            return Err(cbor::Error::DecodeFailed(format!(
                "cnf: unexpected key type {}, want {}",
                cnf.cose_key.kty,
                T::ALGORITHM,
            )));
        }
        let key = T::from_confirm_bytes(&cnf.cose_key.x)?;
        Ok(Self { key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests round-trip encoding of `Confirm<xdsa::PublicKey>`.
    #[test]
    fn test_confirm_xdsa() {
        let key = xdsa::SecretKey::generate().public_key();

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            cnf: Confirm<xdsa::PublicKey>,
        }
        let orig = Token {
            cnf: Confirm::new(key.clone()),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.cnf.key().to_bytes(), key.to_bytes());
    }

    /// Tests round-trip encoding of `Confirm<xhpke::PublicKey>`.
    #[test]
    fn test_confirm_xhpke() {
        let key = xhpke::SecretKey::generate().public_key();

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            cnf: Confirm<xhpke::PublicKey>,
        }
        let orig = Token {
            cnf: Confirm::new(key.clone()),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.cnf.key().to_bytes(), key.to_bytes());
    }

    /// Tests round-trip encoding of a struct embedding multiple claim types.
    #[test]
    fn test_composite_claims() {
        let key = xdsa::SecretKey::generate().public_key();

        #[derive(Debug, Cbor)]
        struct DeviceCert {
            #[cbor(embed)]
            sub: Subject,
            #[cbor(embed)]
            exp: Expiration,
            #[cbor(embed)]
            nbf: NotBefore,
            #[cbor(embed)]
            cnf: Confirm<xdsa::PublicKey>,
            #[cbor(key = 256)]
            ueid: Vec<u8>,
        }
        let orig = DeviceCert {
            sub: Subject {
                sub: "device-abc-123".into(),
            },
            exp: Expiration { exp: 1000000 },
            nbf: NotBefore { nbf: 100 },
            cnf: Confirm::new(key.clone()),
            ueid: b"SN-12345".to_vec(),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = DeviceCert::decode_cbor(&data).expect("decode");

        assert_eq!(got.sub.sub, "device-abc-123");
        assert_eq!(got.exp.exp, 1000000);
        assert_eq!(got.nbf.nbf, 100);
        assert_eq!(got.cnf.key().to_bytes(), key.to_bytes());
        assert_eq!(got.ueid, b"SN-12345");
    }

    /// Tests that decoding a `cnf` claim with a mismatched `kty` fails.
    #[test]
    fn test_confirm_wrong_key_type() {
        let key = xdsa::SecretKey::generate().public_key();

        #[derive(Debug, Cbor)]
        struct XdsaToken {
            #[cbor(embed)]
            cnf: Confirm<xdsa::PublicKey>,
        }
        #[derive(Debug, Cbor)]
        struct XhpkeToken {
            #[cbor(embed)]
            cnf: Confirm<xhpke::PublicKey>,
        }
        let orig = XdsaToken {
            cnf: Confirm::new(key),
        };
        let data = cbor::encode(&orig).expect("encode");

        // Decoding as xhpke should fail due to key type mismatch
        let err = XhpkeToken::decode_cbor(&data).expect_err("should fail with wrong key type");
        let msg = err.to_string();
        assert!(
            msg.contains("unexpected key type"),
            "expected key type error, got: {msg}"
        );
    }
}
