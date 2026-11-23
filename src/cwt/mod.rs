// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CBOR Web Tokens over `COSE_Sign1`.
//!
//! <https://datatracker.ietf.org/doc/html/rfc8392>
//!
//! Tokens carry a claims set encoded as a deterministic CBOR map. Standard
//! claims live in [`claims`] as embeddable single-field structs (such as
//! [`claims::Issuer`] and [`claims::Subject`]) that compose into
//! application-specific token types.
//!
//! [`verify`] checks the signature against the supplied key and, when a
//! reference time is given, the `nbf` and `exp` bounds. Applications must
//! establish trust in the signing key, check issuer and audience claims, and
//! enforce their own attestation policy. EAT claim relationships and proof of
//! possession of a `cnf` key are not checked automatically.
//!
//! ```
//! use darkbio_crypto::cbor::Cbor;
//! use darkbio_crypto::cwt::{self, claims};
//! use darkbio_crypto::xdsa;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #[derive(Cbor)]
//! struct DeviceCert {
//!     #[cbor(embed)] sub: claims::Subject,
//!     #[cbor(embed)] exp: claims::Expiration,
//!     #[cbor(embed)] nbf: claims::NotBefore,
//!     #[cbor(embed)] cnf: claims::Confirm<xdsa::PublicKey>,
//! }
//!
//! let issuer = xdsa::SecretKey::generate();
//! let device = xdsa::SecretKey::generate();
//! let now = 1_700_000_000;
//!
//! let cert = DeviceCert {
//!     sub: claims::Subject { sub: "ark-0001".into() },
//!     exp: claims::Expiration { exp: now + 3600 },
//!     nbf: claims::NotBefore { nbf: now },
//!     cnf: claims::Confirm::new(device.public_key()),
//! };
//! let token = cwt::issue(&cert, &issuer, b"device-cert")?;
//!
//! let verified: DeviceCert =
//!     cwt::verify(&token, &issuer.public_key(), b"device-cert", Some(now + 60))?;
//! assert_eq!(verified.sub.sub, "ark-0001");
//! assert_eq!(verified.cnf.key().fingerprint(), device.fingerprint());
//!
//! // Outside the validity window the token is rejected
//! assert!(cwt::verify::<DeviceCert>(&token, &issuer.public_key(), b"device-cert", Some(now + 7200)).is_err());
//! # Ok(())
//! # }
//! ```

pub mod claims;

use crate::cbor::{self, Decode, Encode, Raw};
use crate::{cose, xdsa};

/// Failures returned by CWT operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Token or its claims are not valid CBOR under this crate's rules.
    #[error("cbor: {0}")]
    Cbor(#[from] cbor::Error),
    /// Underlying [`cose::CoseSign1`] envelope failed decoding or verification.
    #[error("cose: {0}")]
    Cose(#[from] cose::Error),
    /// [`verify`] requested time validation, but the claims omit `nbf` (key 5).
    #[error("missing nbf claim")]
    MissingNbf,
    /// Claims map repeats a temporal claim key (`exp` or `nbf`).
    #[error("duplicate claim key {0}")]
    DuplicateKey(i64),
    /// Token's `nbf` ([`claims::NotBefore`]) lies after the check time.
    #[error("token not yet valid: nbf {nbf} > now {now}")]
    NotYetValid {
        /// Not-before claim in seconds since the Unix epoch.
        nbf: u64,
        /// Check time in seconds since the Unix epoch.
        now: u64,
    },
    /// Token's `exp` ([`claims::Expiration`]) is at or before the check time.
    #[error("token already expired: exp {exp} <= now {now}")]
    AlreadyExpired {
        /// Expiration claim in seconds since the Unix epoch.
        exp: u64,
        /// Check time in seconds since the Unix epoch.
        now: u64,
    },
}

/// Signs a claims map as a CWT using [`cose::sign`] and the current system
/// time as the COSE timestamp.
///
/// `claims` must encode as a deterministic CBOR map (using `#[cbor(key = N)]`
/// fields and embedded claim types).
pub fn issue(
    claims: &impl Encode,
    signer: &xdsa::SecretKey,
    domain: &[u8],
) -> Result<Vec<u8>, Error> {
    Ok(cose::sign(
        encode_claims(claims)?,
        cbor::NULL,
        signer,
        domain,
    )?)
}

/// Signs a claims map as a CWT using [`cose::sign_at`] with an explicit Unix
/// COSE timestamp in seconds.
pub fn issue_at(
    claims: &impl Encode,
    signer: &xdsa::SecretKey,
    domain: &[u8],
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    Ok(cose::sign_at(
        encode_claims(claims)?,
        cbor::NULL,
        signer,
        domain,
        timestamp,
    )?)
}

/// Encodes `claims` to CBOR and verifies that the payload is a canonical CBOR
/// map.
fn encode_claims(claims: &impl Encode) -> Result<Raw, cbor::Error> {
    let bytes = cbor::encode(claims)?;
    cbor::Decoder::new(&bytes).decode_map_header()?;
    cbor::verify(&bytes)?;
    Ok(Raw(bytes))
}

/// Verifies a CWT's COSE signature and temporal validity, then decodes the
/// claims into `T`.
///
/// When `now` is `Some`, `nbf` (key 5, [`claims::NotBefore`]) must be present
/// with `nbf <= now`, and if `exp` (key 4, [`claims::Expiration`]) is present
/// then `now < exp`. When `now` is `None`, temporal checks are skipped.
///
/// The COSE signature timestamp is ignored because temporal validity comes
/// from the CWT claims. `T` defines the accepted claim schema. Verification
/// does not establish issuer trust, enforce an audience, evaluate attestation
/// policy or EAT claim relationships, or prove possession of a
/// [`claims::Confirm`] key.
pub fn verify<T: Decode>(
    data: &[u8],
    verifier: &xdsa::PublicKey,
    domain: &[u8],
    now: Option<u64>,
) -> Result<T, Error> {
    // Verify the COSE signature without COSE drift checks; CWT owns temporal checks
    let raw: Raw = cose::verify(data, cbor::NULL, verifier, domain, None)?;

    validate_claims(&raw, now)?;
    Ok(cbor::decode(&raw.0)?)
}

/// Extracts the signer's fingerprint from a CWT without verifying its
/// signature.
pub fn signer(data: &[u8]) -> Result<xdsa::Fingerprint, Error> {
    Ok(cose::signer(data)?)
}

/// Extracts and decodes claims from a CWT without verifying its signature.
///
/// Do not trust the returned claims until the token has been verified with
/// [`verify`]. Use [`signer`] to look up keys by fingerprint; this function is
/// intended for self-signed key discovery.
pub fn peek<T: Decode>(data: &[u8]) -> Result<T, Error> {
    let raw: Raw = cose::peek(data)?;
    Ok(cbor::decode(&raw.0)?)
}

/// Validates that the claims payload is a canonical CBOR map and, when `now`
/// is `Some`, enforces the `nbf` (key 5) and optional `exp` (key 4) bounds.
fn validate_claims(raw: &[u8], now: Option<u64>) -> Result<(), Error> {
    // Parse the top-level map first so duplicate temporal claim keys surface
    // as Error::DuplicateKey rather than a generic CBOR map error
    let mut dec = cbor::Decoder::new(raw);
    let entries = cbor::decode_map_entries_slices_notrail(&mut dec).map_err(|err| match err {
        cbor::Error::DuplicateMapKey(key @ (4 | 5)) => Error::DuplicateKey(key),
        _ => Error::Cbor(err),
    })?;
    dec.finish()?;

    // Verify full canonical CBOR rules across nested values and total depth
    cbor::verify(raw)?;

    // Enforce temporal bounds when a reference time is supplied
    if let Some(now) = now {
        let mut nbf = None;
        let mut exp = None;
        for (key, value) in entries {
            match key {
                4 => exp = Some(cbor::decode::<u64>(value)?),
                5 => nbf = Some(cbor::decode::<u64>(value)?),
                _ => {}
            }
        }
        let nbf = nbf.ok_or(Error::MissingNbf)?;
        if now < nbf {
            return Err(Error::NotYetValid { nbf, now });
        }
        if let Some(exp) = exp
            && now >= exp
        {
            return Err(Error::AlreadyExpired { exp, now });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Cbor;
    use crate::cwt::claims;
    use crate::cwt::claims::eat;

    /// The minimal token type used by most tests.
    #[derive(Debug, Cbor)]
    struct SimpleCert {
        #[cbor(embed)]
        sub: claims::Subject,
        #[cbor(embed)]
        exp: Option<claims::Expiration>,
        #[cbor(embed)]
        nbf: claims::NotBefore,
        #[cbor(embed)]
        cnf: claims::Confirm<xdsa::PublicKey>,
    }

    /// A composite token type with EAT claims.
    #[derive(Debug, Cbor)]
    struct DeviceCert {
        #[cbor(embed)]
        sub: claims::Subject,
        #[cbor(embed)]
        exp: Option<claims::Expiration>,
        #[cbor(embed)]
        nbf: claims::NotBefore,
        #[cbor(embed)]
        cnf: claims::Confirm<xdsa::PublicKey>,
        #[cbor(embed)]
        ueid: eat::Ueid,
    }

    /// Token type without NotBefore, used for missing-nbf test.
    #[derive(Debug, Cbor)]
    struct NoNbfCert {
        #[cbor(embed)]
        sub: claims::Subject,
        #[cbor(embed)]
        cnf: claims::Confirm<xdsa::PublicKey>,
    }

    /// Token type without Expiration, used for no-expiration test.
    #[derive(Debug, Cbor)]
    struct NoExpCert {
        #[cbor(embed)]
        sub: claims::Subject,
        #[cbor(embed)]
        nbf: claims::NotBefore,
        #[cbor(embed)]
        cnf: claims::Confirm<xdsa::PublicKey>,
    }

    /// Tests issuing and verifying a token with EAT claims.
    #[test]
    fn test_issue_verify() {
        let issuer = xdsa::SecretKey::generate();
        let device = xdsa::SecretKey::generate();

        let cert = DeviceCert {
            sub: claims::Subject {
                sub: "device-abc".into(),
            },
            exp: Some(claims::Expiration { exp: 2000000 }),
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(device.public_key()),
            ueid: eat::Ueid {
                ueid: b"SN-999".to_vec(),
            },
        };
        let token = issue(&cert, &issuer, b"test-domain").expect("issue");
        let got: DeviceCert =
            verify(&token, &issuer.public_key(), b"test-domain", Some(1500000)).expect("verify");

        assert_eq!(got.sub.sub, "device-abc");
        assert_eq!(got.exp.unwrap().exp, 2000000);
        assert_eq!(got.cnf.key().to_bytes(), device.public_key().to_bytes(),);
        assert_eq!(got.ueid.ueid, b"SN-999");
    }

    /// Tests that `issue` and `issue_at` reject non-map and non-canonical raw claims.
    #[test]
    fn test_issue_requires_map() {
        let issuer = xdsa::SecretKey::generate();
        let err = Error::Cbor(cbor::Error::InvalidMajorType(4, 5));
        let array = Raw(vec![0x80]);
        assert_eq!(issue(&array, &issuer, b"test"), Err(err.clone()));
        assert_eq!(issue_at(&array, &issuer, b"test", 1), Err(err));

        let unsorted = Raw(vec![0xa2, 5, 0, 1, 0]);
        let order_err = Error::Cbor(cbor::Error::InvalidMapKeyOrder(1, 5));
        assert_eq!(issue(&unsorted, &issuer, b"test"), Err(order_err.clone()));
        assert_eq!(issue_at(&unsorted, &issuer, b"test", 1), Err(order_err));
    }

    /// Tests that `verify::<Raw>` enforces map structure, canonical key order,
    /// duplicate detection, UTF-8 validity, and total nesting depth.
    #[test]
    fn test_verify_raw_claims_wire_format() {
        let issuer = xdsa::SecretKey::generate();
        let verifier = issuer.public_key();

        // Build a claims map whose value nests 31 arrays deep (total depth 32)
        let mut over_depth = vec![0xa2, 1];
        over_depth.extend(std::iter::repeat_n(0x81u8, 31));
        over_depth.extend_from_slice(&[0x00, 5, 0]);

        let cases: &[(&[u8], Error)] = &[
            (&[0x80], Error::Cbor(cbor::Error::InvalidMajorType(4, 5))),
            (
                &[0xa2, 5, 0, 1, 0],
                Error::Cbor(cbor::Error::InvalidMapKeyOrder(1, 5)),
            ),
            (
                &[0xa3, 1, 0, 1, 0, 5, 0],
                Error::Cbor(cbor::Error::DuplicateMapKey(1)),
            ),
            (&[0xa2, 4, 1, 4, 1], Error::DuplicateKey(4)),
            (&[0xa2, 5, 0, 5, 0], Error::DuplicateKey(5)),
            (
                &[0xa2, 1, 0x81, 0x61, 0xff, 5, 0],
                Error::Cbor(cbor::Error::InvalidUtf8),
            ),
            (
                &[0xa2, 1, 0xa2, 4, 0, 4, 0, 5, 0],
                Error::Cbor(cbor::Error::DuplicateMapKey(4)),
            ),
            (
                &over_depth,
                Error::Cose(cose::Error::CborError(cbor::Error::MaxDepthExceeded(32))),
            ),
        ];
        for (bytes, err) in cases {
            let token = cose::sign(Raw(bytes.to_vec()), cbor::NULL, &issuer, b"test").unwrap();
            for now in [None, Some(0)] {
                assert_eq!(
                    verify::<Raw>(&token, &verifier, b"test", now),
                    Err(err.clone())
                );
            }
        }
    }

    /// Tests that `now == None` skips temporal validation.
    #[test]
    fn test_verify_skip_time() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let got: SimpleCert =
            verify(&token, &issuer.public_key(), b"test", None).expect("verify with None time");

        assert_eq!(got.sub.sub, "test");
    }

    /// Tests rejection when `now < nbf`.
    #[test]
    fn test_verify_not_yet_valid() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), b"test", Some(500000))
            .expect_err("should fail");

        assert!(matches!(err, Error::NotYetValid { .. }));
    }

    /// Tests rejection when `now > exp`.
    #[test]
    fn test_verify_expired() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: Some(claims::Expiration { exp: 2000000 }),
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), b"test", Some(3000000))
            .expect_err("should fail");

        assert!(matches!(err, Error::AlreadyExpired { .. }));
    }

    /// Tests rejection when `nbf` is absent and time validation is enabled.
    #[test]
    fn test_verify_missing_nbf() {
        let issuer = xdsa::SecretKey::generate();

        let cert = NoNbfCert {
            sub: claims::Subject { sub: "test".into() },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let err = verify::<NoNbfCert>(&token, &issuer.public_key(), b"test", Some(1000000))
            .expect_err("should fail");

        assert!(matches!(err, Error::MissingNbf));
    }

    /// Tests rejection with wrong verifier key.
    #[test]
    fn test_verify_wrong_key() {
        let issuer = xdsa::SecretKey::generate();
        let wrong = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");

        assert!(verify::<SimpleCert>(&token, &wrong.public_key(), b"test", Some(1500000)).is_err());
    }

    /// Tests fingerprint extraction from a token.
    #[test]
    fn test_signer() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let fp = signer(&token).expect("signer");

        assert_eq!(fp, issuer.public_key().fingerprint());
    }

    /// Tests unauthenticated claims extraction.
    #[test]
    fn test_peek() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject {
                sub: "peek-test".into(),
            },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");
        let got: SimpleCert = peek(&token).expect("peek");

        assert_eq!(got.sub.sub, "peek-test");
    }

    /// Tests rejection when the verification domain differs.
    #[test]
    fn test_verify_wrong_domain() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"domain-a").expect("issue");

        assert!(
            verify::<SimpleCert>(&token, &issuer.public_key(), b"domain-b", Some(1500000)).is_err()
        );
    }

    /// Tests that `now == nbf` passes and `now == exp` fails per RFC 8392.
    #[test]
    fn test_verify_boundary_exact() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: Some(claims::Expiration { exp: 2000000 }),
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");

        // now == nbf should pass
        verify::<SimpleCert>(&token, &issuer.public_key(), b"test", Some(1000000))
            .expect("now == nbf should pass");

        // now == exp should fail
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), b"test", Some(2000000))
            .expect_err("now == exp should fail");
        assert!(matches!(err, Error::AlreadyExpired { .. }));
    }

    /// Tests that a token without `exp` passes time validation.
    #[test]
    fn test_verify_no_expiration() {
        let issuer = xdsa::SecretKey::generate();

        let cert = NoExpCert {
            sub: claims::Subject { sub: "test".into() },
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, b"test").expect("issue");

        // Should pass even far in the future since there's no exp
        verify::<NoExpCert>(&token, &issuer.public_key(), b"test", Some(99999999))
            .expect("no exp should pass");
    }

    /// Tests that duplicate temporal claim keys are rejected.
    #[test]
    fn test_verify_duplicate_nbf() {
        let issuer = xdsa::SecretKey::generate();

        // Manually construct a CBOR map with duplicate nbf (key 5)
        let mut enc = cbor::Encoder::new();
        enc.encode_map_header(3);
        enc.encode_int(2);
        enc.encode_text("test");
        enc.encode_int(5);
        enc.encode_uint(1000000);
        enc.encode_int(5); // duplicate nbf
        enc.encode_uint(2000000);

        // Sign the raw payload via COSE (bypassing CWT's encoder)
        let token = cose::sign(Raw(enc.finish()), cbor::NULL, &issuer, b"test").expect("sign");

        // Verify should fail with DuplicateKey before claims decoding
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), b"test", Some(1500000))
            .expect_err("should reject duplicate nbf");
        assert!(matches!(err, Error::DuplicateKey(5)));
    }

    /// Fixture corpus generated with v0.16.0 to pin the CWT wire format.
    const FIXTURES: &str = include_str!("testdata/v0.16.json");

    /// Retrieves a hex-encoded field from the v0.16 fixture corpus.
    fn fixture(corpus: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(corpus[key].as_str().unwrap()).unwrap()
    }

    /// Tests that the committed v0.16 CWT fixtures keep their expected validity.
    #[test]
    fn test_v0_16_fixtures() {
        let corpus: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();

        let xdsa_seed: [u8; 64] = fixture(&corpus, "xdsa_seed").try_into().unwrap();
        let signer = xdsa::SecretKey::from_bytes(&xdsa_seed);

        let domain = fixture(&corpus, "domain");
        let now = corpus["now"].as_u64().unwrap();

        // Verify the committed valid token and check the decoded claims
        let valid = fixture(&corpus, "valid");
        let got: SimpleCert = verify(&valid, &signer.public_key(), &domain, Some(now)).unwrap();
        assert_eq!(got.sub.sub, "fixture");
        assert_eq!(got.exp.unwrap().exp, 4102444800);
        assert_eq!(got.nbf.nbf, 1500000000);
        assert_eq!(got.cnf.key().to_bytes(), signer.public_key().to_bytes());

        // The expired and premature tokens must keep failing temporally
        let expired = fixture(&corpus, "expired");
        let err = verify::<SimpleCert>(&expired, &signer.public_key(), &domain, Some(now));
        assert!(matches!(err, Err(Error::AlreadyExpired { .. })));

        let premature = fixture(&corpus, "premature");
        let err = verify::<NoExpCert>(&premature, &signer.public_key(), &domain, Some(now));
        assert!(matches!(err, Err(Error::NotYetValid { .. })));

        // A tampered token must fail the signature check
        let mut tampered = valid.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let err = verify::<SimpleCert>(&tampered, &signer.public_key(), &domain, Some(now));
        assert!(err.is_err());
    }
}
