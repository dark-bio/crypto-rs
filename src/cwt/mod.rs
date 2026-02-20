// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CBOR Web Tokens on top of COSE Sign1.
//!
//! <https://datatracker.ietf.org/doc/html/rfc8392>
//!
//! Tokens carry a set of claims encoded as a CBOR map. Standard claims are
//! provided as embeddable single-field structs ([`claims::Issuer`],
//! [`claims::Subject`], etc.) that can be composed into application-specific
//! token types.
//!
//! # Example
//!
//! ```ignore
//! use darkbio_crypto::cbor::Cbor;
//! use darkbio_crypto::cwt::{self, claims};
//! use darkbio_crypto::xdsa;
//!
//! #[derive(Cbor)]
//! struct DeviceCert {
//!     #[cbor(embed)]
//!     sub: claims::Subject,
//!     #[cbor(embed)]
//!     exp: claims::Expiration,
//!     #[cbor(embed)]
//!     nbf: claims::NotBefore,
//!     #[cbor(embed)]
//!     cnf: claims::Confirm<xdsa::PublicKey>,
//!     #[cbor(key = 256)]
//!     ueid: Vec<u8>,
//! }
//!
//! let token = cwt::issue(&cert, &signer_key, "device-cert").unwrap();
//! let verified: DeviceCert = cwt::verify(&token, &issuer_pub, "device-cert", Some(now)).unwrap();
//! ```

pub mod claims;

use crate::cbor::{self, Decode, Encode, Raw};
use crate::{cose, xdsa};

/// Error is the failures that can occur during CWT operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("cbor: {0}")]
    Cbor(#[from] cbor::Error),
    #[error("cose: {0}")]
    Cose(#[from] cose::Error),
    #[error("missing nbf claim")]
    MissingNbf,
    #[error("token not yet valid: nbf {nbf} > now {now}")]
    NotYetValid { nbf: u64, now: u64 },
    #[error("token already expired: exp {exp} <= now {now}")]
    AlreadyExpired { exp: u64, now: u64 },
}

/// issue signs a set of claims as a CWT using COSE Sign1.
///
/// The claims value must be a struct whose fields encode as a CBOR map
/// (using `#[cbor(key = N)]` tags and/or embedded claim types).
///
/// Uses the current system time as the COSE signature timestamp.
pub fn issue(
    claims: &impl Encode,
    signer: &xdsa::SecretKey,
    domain: &str,
) -> Result<Vec<u8>, Error> {
    let claims_bytes = cbor::encode(claims)?;
    Ok(cose::sign(
        Raw(claims_bytes),
        cbor::NULL,
        signer,
        domain.as_bytes(),
    )?)
}

/// issue_at signs a set of claims as a CWT with an explicit COSE timestamp.
///
/// This is primarily useful for testing with deterministic timestamps.
pub fn issue_at(
    claims: &impl Encode,
    signer: &xdsa::SecretKey,
    domain: &str,
    timestamp: i64,
) -> Result<Vec<u8>, Error> {
    let claims_bytes = cbor::encode(claims)?;
    Ok(cose::sign_at(
        Raw(claims_bytes),
        cbor::NULL,
        signer,
        domain.as_bytes(),
        timestamp,
    )?)
}

/// verify verifies a CWT's COSE signature and temporal validity, then decodes
/// the claims into T.
///
/// When `now` is `Some`, temporal claims are validated: nbf (key 5) must be
/// present and `nbf <= now`, and if exp (key 4) is present then `now < exp`.
/// When `now` is `None`, temporal validation is skipped entirely.
pub fn verify<T: Decode>(
    data: &[u8],
    verifier: &xdsa::PublicKey,
    domain: &str,
    now: Option<u64>,
) -> Result<T, Error> {
    // Verify COSE signature (skip COSE drift check — CWT handles temporal validation)
    let raw: Raw = cose::verify(data, &cbor::NULL, verifier, domain.as_bytes(), None)?;

    // Extract and validate temporal claims if requested
    if let Some(now) = now {
        let (nbf, exp) = read_temporal_claims(&raw)?;
        if now < nbf {
            return Err(Error::NotYetValid { nbf, now });
        }
        if let Some(exp) = exp {
            if now >= exp {
                return Err(Error::AlreadyExpired { exp, now });
            }
        }
    }
    // Decode claims into T
    Ok(cbor::decode(&raw.0)?)
}

/// signer extracts the signer's fingerprint from a CWT without verifying
/// the signature. The returned data is unauthenticated.
pub fn signer(data: &[u8]) -> Result<xdsa::Fingerprint, Error> {
    Ok(cose::signer(data)?)
}

/// peek extracts and decodes claims from a CWT without verifying the signature.
///
/// **Warning**: This function does NOT verify the signature. The returned payload
/// is unauthenticated and should not be trusted until verified with [`verify`].
/// Use [`signer`] to extract the signer's fingerprint for key lookup. The single
/// case for this method is self-signed key discovery.
pub fn peek<T: Decode>(data: &[u8]) -> Result<T, Error> {
    let raw: Raw = cose::peek(data)?;
    Ok(cbor::decode(&raw.0)?)
}

/// Reads temporal claims (exp key 4, nbf key 5) from raw CBOR map bytes.
/// Returns nbf (required) and exp (optional, None if absent).
fn read_temporal_claims(raw: &[u8]) -> Result<(u64, Option<u64>), Error> {
    let mut dec = cbor::Decoder::new(raw);
    let n = dec.decode_map_header().map_err(cbor::Error::from)?;

    let mut nbf: Option<u64> = None;
    let mut exp: Option<u64> = None;

    for _ in 0..n {
        let key = dec.decode_int().map_err(cbor::Error::from)?;
        match key {
            4 => {
                // exp
                exp = Some(dec.decode_uint().map_err(cbor::Error::from)?);
            }
            5 => {
                // nbf
                nbf = Some(dec.decode_uint().map_err(cbor::Error::from)?);
            }
            _ => {
                // Skip unknown claim value
                Raw::decode_cbor_notrail(&mut dec).map_err(cbor::Error::from)?;
            }
        }
    }
    let nbf = nbf.ok_or(Error::MissingNbf)?;
    Ok((nbf, exp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Cbor;
    use crate::cwt::claims;
    use crate::cwt::claims::eat;

    /// simpleCert is the minimal token type used by most tests.
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

    /// deviceCert is a composite token type with EAT claims.
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

    /// Tests the happy path: issue a token and verify it.
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
        let token = issue(&cert, &issuer, "test-domain").expect("issue");
        let got: DeviceCert =
            verify(&token, &issuer.public_key(), "test-domain", Some(1500000)).expect("verify");

        assert_eq!(got.sub.sub, "device-abc");
        assert_eq!(got.exp.unwrap().exp, 2000000);
        assert_eq!(got.cnf.key().to_bytes(), device.public_key().to_bytes(),);
        assert_eq!(got.ueid.ueid, b"SN-999");
    }

    /// Tests that now=None skips temporal validation.
    #[test]
    fn test_verify_skip_time() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");
        let got: SimpleCert =
            verify(&token, &issuer.public_key(), "test", None).expect("verify with None time");

        assert_eq!(got.sub.sub, "test");
    }

    /// Tests rejection when now < nbf.
    #[test]
    fn test_verify_not_yet_valid() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: None,
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), "test", Some(500000))
            .expect_err("should fail");

        assert!(matches!(err, Error::NotYetValid { .. }));
    }

    /// Tests rejection when now > exp.
    #[test]
    fn test_verify_expired() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: Some(claims::Expiration { exp: 2000000 }),
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), "test", Some(3000000))
            .expect_err("should fail");

        assert!(matches!(err, Error::AlreadyExpired { .. }));
    }

    /// Tests rejection when nbf is absent and time check is on.
    #[test]
    fn test_verify_missing_nbf() {
        let issuer = xdsa::SecretKey::generate();

        let cert = NoNbfCert {
            sub: claims::Subject { sub: "test".into() },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");
        let err = verify::<NoNbfCert>(&token, &issuer.public_key(), "test", Some(1000000))
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
        let token = issue(&cert, &issuer, "test").expect("issue");

        assert!(verify::<SimpleCert>(&token, &wrong.public_key(), "test", Some(1500000)).is_err());
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
        let token = issue(&cert, &issuer, "test").expect("issue");
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
        let token = issue(&cert, &issuer, "test").expect("issue");
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
        let token = issue(&cert, &issuer, "domain-a").expect("issue");

        assert!(
            verify::<SimpleCert>(&token, &issuer.public_key(), "domain-b", Some(1500000)).is_err()
        );
    }

    /// Tests that now == nbf passes and now == exp fails per RFC 8392.
    #[test]
    fn test_verify_boundary_exact() {
        let issuer = xdsa::SecretKey::generate();

        let cert = SimpleCert {
            sub: claims::Subject { sub: "test".into() },
            exp: Some(claims::Expiration { exp: 2000000 }),
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");

        // now == nbf should pass
        verify::<SimpleCert>(&token, &issuer.public_key(), "test", Some(1000000))
            .expect("now == nbf should pass");

        // now == exp should fail
        let err = verify::<SimpleCert>(&token, &issuer.public_key(), "test", Some(2000000))
            .expect_err("now == exp should fail");
        assert!(matches!(err, Error::AlreadyExpired { .. }));
    }

    /// Tests that a token without exp passes time validation.
    #[test]
    fn test_verify_no_expiration() {
        let issuer = xdsa::SecretKey::generate();

        let cert = NoExpCert {
            sub: claims::Subject { sub: "test".into() },
            nbf: claims::NotBefore { nbf: 1000000 },
            cnf: claims::Confirm::new(xdsa::SecretKey::generate().public_key()),
        };
        let token = issue(&cert, &issuer, "test").expect("issue");

        // Should pass even far in the future since there's no exp
        verify::<NoExpCert>(&token, &issuer.public_key(), "test", Some(99999999))
            .expect("no exp should pass");
    }
}
