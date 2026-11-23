// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HKDF-SHA256 key derivation.
//!
//! <https://datatracker.ietf.org/doc/html/rfc5869>
//!
//! Derives one or more keys bound to a context string from a high-entropy
//! secret, such as a shared secret or file key. For passwords, use the
//! `argon2` module instead.
//!
//! ```
//! use darkbio_crypto::hkdf;
//!
//! let secret = [42u8; 32];
//! let encryption = hkdf::key::<32>(&secret, b"", b"example encryption key");
//! let authentication = hkdf::key::<32>(&secret, b"", b"example authentication key");
//! assert_ne!(*encryption, *authentication);
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Derives a fixed-size key from `secret`, `salt`, and `info` using
/// HKDF-SHA256.
///
/// # Panics
///
/// Panics if `N` exceeds the 8160-byte (`255 * 32`) HKDF-SHA256 limit.
pub fn key<const N: usize>(secret: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(salt, secret);
    prk.as_mut_slice().zeroize();

    let mut output = Zeroizing::new([0u8; N]);
    hkdf.expand(info, output.as_mut()).unwrap();
    output
}

/// Derives a variable-length key from `secret`, `salt`, and `info` using
/// HKDF-SHA256.
///
/// Analogous to [`key`], taking the output length at runtime and returning a
/// `Vec<u8>`. Intended for FFI bindings where const generics do not compose;
/// prefer [`key`] in Rust.
///
/// # Panics
///
/// Panics if `out` exceeds the 8160-byte (`255 * 32`) HKDF-SHA256 limit.
pub fn key_with_len(secret: &[u8], salt: &[u8], info: &[u8], out: usize) -> Zeroizing<Vec<u8>> {
    assert!(out <= 255 * 32, "HKDF output exceeds 8160 bytes");
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(salt, secret);
    prk.as_mut_slice().zeroize();

    let mut output = Zeroizing::new(vec![0u8; out]);
    hkdf.expand(info, &mut output).unwrap();
    output
}

/// Extracts a 32-byte pseudorandom key for [`expand`] from `secret` and an
/// optional `salt`.
///
/// Use this only when reusing one extracted key across multiple [`expand`]
/// calls with different context values. Most callers should use [`key`].
pub fn extract(secret: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (mut prk, _hkdf) = Hkdf::<Sha256>::extract(salt, secret);

    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(prk.as_slice());
    prk.as_mut_slice().zeroize();
    output
}

/// Expands a 32-byte pseudorandom key and optional `info` into a fixed-size
/// key, skipping extraction.
///
/// Pass a key produced by [`extract`] or another uniformly random secret per
/// RFC 5869 Section 3.3. Most callers should use [`key`] instead.
///
/// # Panics
///
/// Panics if `N` exceeds the 8160-byte (`255 * 32`) HKDF-SHA256 limit.
pub fn expand<const N: usize>(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; N]> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).unwrap();

    let mut output = Zeroizing::new([0u8; N]);
    hkdf.expand(info, output.as_mut()).unwrap();
    output
}

/// Expands a 32-byte pseudorandom key and optional `info` into a
/// variable-length key, skipping extraction.
///
/// Pass a key produced by [`extract`] or another uniformly random secret per
/// RFC 5869 Section 3.3. Analogous to [`expand`], taking the output length at
/// runtime and returning a `Vec<u8>`. Intended for FFI bindings where const
/// generics do not compose; prefer [`expand`] or [`key`] in Rust.
///
/// # Panics
///
/// Panics if `out` exceeds the 8160-byte (`255 * 32`) HKDF-SHA256 limit.
pub fn expand_with_len(prk: &[u8; 32], info: &[u8], out: usize) -> Zeroizing<Vec<u8>> {
    assert!(out <= 255 * 32, "HKDF output exceeds 8160 bytes");
    let hkdf = Hkdf::<Sha256>::from_prk(prk).unwrap();

    let mut output = Zeroizing::new(vec![0u8; out]);
    hkdf.expand(info, &mut output).unwrap();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that the 8160-byte SHA-256 HKDF limit succeeds at the boundary and
    /// panics before allocation when exceeded.
    #[test]
    fn test_output_length_limit() {
        assert_eq!(key_with_len(b"secret", b"", b"", 255 * 32).len(), 255 * 32);
        assert_eq!(expand_with_len(&[0; 32], b"", 255 * 32).len(), 255 * 32);

        #[cfg(not(target_arch = "wasm32"))]
        {
            let cases: [(&str, fn()); 2] = [
                ("key_with_len", || {
                    key_with_len(b"secret", b"", b"", usize::MAX);
                }),
                ("expand_with_len", || {
                    expand_with_len(&[0; 32], b"", usize::MAX);
                }),
            ];
            for (name, run) in cases {
                let err = std::panic::catch_unwind(run).expect_err(name);
                let msg = err
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| err.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("");
                assert!(
                    msg.contains("HKDF output exceeds 8160 bytes"),
                    "{name}: {msg}"
                );
            }
        }
    }

    /// Tests key derivation against the RFC 5869 Appendix A (SHA-256) vectors.
    #[test]
    fn test_hkdf() {
        struct TestCase {
            secret: &'static str,
            salt: &'static str,
            info: &'static str,
            out: &'static str,
        }
        let tests = [
            // RFC 5869 A.1, basic SHA-256 vector
            TestCase {
                secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                info: "f0f1f2f3f4f5f6f7f8f9",
                out: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                      34007208d5b887185865",
            },
            // RFC 5869 A.2, longer SHA-256 inputs and outputs
            TestCase {
                secret: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                         404142434445464748494a4b4c4d4e4f",
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                       808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                       a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                       d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                       f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                out: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                      59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                      cc30c58179ec3e87c14c01d5c1f3434f1d87",
            },
            // RFC 5869 A.3, zero-length salt and info
            TestCase {
                secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "",
                info: "",
                out: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                      9d201395faa4b61a96c8",
            },
        ];
        fn run<const N: usize>(secret: &str, salt: &str, info: &str, out: &str) {
            let secret = hex::decode(secret).unwrap();
            let salt = hex::decode(salt).unwrap();
            let info = hex::decode(info).unwrap();
            let expected = hex::decode(out).unwrap();

            let got = key::<N>(&secret, &salt, &info);
            assert_eq!(got.as_slice(), expected.as_slice());

            let got = key_with_len(&secret, &salt, &info, N);
            assert_eq!(got.as_slice(), expected.as_slice());
        }
        for tc in tests {
            match hex::decode(tc.out).unwrap().len() {
                42 => run::<42>(tc.secret, tc.salt, tc.info, tc.out),
                82 => run::<82>(tc.secret, tc.salt, tc.info, tc.out),
                n => panic!("unsupported output length: {}", n),
            }
        }
    }

    /// Tests extraction against the RFC 5869 Appendix A (SHA-256) vectors.
    #[test]
    fn test_hkdf_extract() {
        struct TestCase {
            secret: &'static str,
            salt: &'static str,
            prk: &'static str,
        }
        let tests = [
            // RFC 5869 A.1, basic SHA-256 vector
            TestCase {
                secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            },
            // RFC 5869 A.2, longer SHA-256 inputs and outputs
            TestCase {
                secret: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                         404142434445464748494a4b4c4d4e4f",
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                       808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                       a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            },
            // RFC 5869 A.3, zero-length salt and info
            TestCase {
                secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "",
                prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            },
        ];
        for tc in tests {
            let secret = hex::decode(tc.secret).unwrap();
            let salt = hex::decode(tc.salt).unwrap();
            let expected = hex::decode(tc.prk).unwrap();

            let got = extract(&secret, &salt);
            assert_eq!(got.as_slice(), expected.as_slice());
        }
    }

    /// Tests expansion against the RFC 5869 Appendix A (SHA-256) vectors.
    #[test]
    fn test_hkdf_expand() {
        struct TestCase {
            prk: &'static str,
            info: &'static str,
            out: &'static str,
        }
        let tests = [
            // RFC 5869 A.1, basic SHA-256 vector
            TestCase {
                prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                info: "f0f1f2f3f4f5f6f7f8f9",
                out: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                      34007208d5b887185865",
            },
            // RFC 5869 A.2, longer SHA-256 inputs and outputs
            TestCase {
                prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                       d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                       f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                out: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                      59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                      cc30c58179ec3e87c14c01d5c1f3434f1d87",
            },
            // RFC 5869 A.3, zero-length salt and info
            TestCase {
                prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                info: "",
                out: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                      9d201395faa4b61a96c8",
            },
        ];
        fn run<const N: usize>(prk: &str, info: &str, out: &str) {
            let prk: [u8; 32] = hex::decode(prk).unwrap().try_into().unwrap();
            let info = hex::decode(info).unwrap();
            let expected = hex::decode(out).unwrap();

            let got = expand::<N>(&prk, &info);
            assert_eq!(got.as_slice(), expected.as_slice());

            let got = expand_with_len(&prk, &info, N);
            assert_eq!(got.as_slice(), expected.as_slice());
        }
        for tc in tests {
            match hex::decode(tc.out).unwrap().len() {
                42 => run::<42>(tc.prk, tc.info, tc.out),
                82 => run::<82>(tc.prk, tc.info, tc.out),
                n => panic!("unsupported output length: {}", n),
            }
        }
    }
}
