// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HKDF cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc5869

use hkdf::Hkdf;
use sha2::Sha256;

/// Key derives a key from the secret, salt, and info using HKDF-SHA256,
/// returning a fixed byte array that can be used as a cryptographic key.
///
/// # Panics
///
/// Panics if N exceeds the maximum output length for SHA-256 HKDF, which is
/// 255 * 32 = 8160 bytes.
pub fn key<const N: usize>(secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; N] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt, secret);

    let mut output = [0u8; N];
    hkdf.expand(info, &mut output).unwrap();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 5869 Appendix A (SHA-256).
    #[test]
    fn test_hkdf() {
        struct TestCase {
            secret: &'static str,
            salt: &'static str,
            info: &'static str,
            out: &'static str,
        }
        let tests = [
            // RFC 5869 A.1: Basic test case with SHA-256
            TestCase {
                secret: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                info: "f0f1f2f3f4f5f6f7f8f9",
                out: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                      34007208d5b887185865",
            },
            // RFC 5869 A.2: Test with SHA-256 and longer inputs/outputs
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
            // RFC 5869 A.3: Test with SHA-256 and zero-length salt/info
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

            let got: [u8; N] = key(&secret, &salt, &info);
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
}
