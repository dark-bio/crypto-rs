// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! PBKDF2 cryptography wrappers and parametrization.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// key derives a key from the password, salt and iteration count, returning a
/// vector of length keylen that can be used as cryptographic key. The key is
/// derived based on the method described as PBKDF2 with HMAC using SHA256.
pub fn key(secret: &[u8], salt: &[u8], iterations: u32, keylen: usize) -> Vec<u8> {
    let mut seed = vec![0u8; keylen];
    pbkdf2_hmac::<Sha256>(secret, salt, iterations, &mut seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2() {
        // Test vectors from:
        //   http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

        let result = key(b"password", b"salt", 1, 20);
        let expected = vec![
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9,
        ];
        assert_eq!(result, expected);

        let result = key(b"password", b"salt", 2, 20);
        let expected = vec![
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0,
            0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e,
        ];
        assert_eq!(result, expected);

        let result = key(b"password", b"salt", 4096, 20);
        let expected = vec![
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
            0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0,
        ];
        assert_eq!(result, expected);

        let result = key(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
        );
        let expected = vec![
            0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e,
            0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c,
        ];
        assert_eq!(result, expected);

        let result = key(b"pass\0word", b"sa\0lt", 4096, 16);
        let expected = vec![
            0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89, 0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a,
            0x86, 0x87,
        ];
        assert_eq!(result, expected);
    }
}
