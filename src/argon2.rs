// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Argon2id cryptography wrappers and parametrization.

use argon2::{Algorithm, Argon2, Params, Version};

/// Key derives a key from the password, salt, and cost parameters using
/// Argon2id returning a byte slice of length keyLen that can be used as
/// cryptographic key. The CPU cost and parallelism degree must be greater
/// than zero.
///
/// For example, you can get a derived key for e.g. AES-256 (which needs a
/// 32-byte key) by doing:
///
///      key := argon2::Key(b"some password", salt, 1, 64*1024, 4, 32)
///
/// [RFC 9106 Section 7.4] recommends time=1, and memory=2048*1024 as a sensible
/// number. If using that amount of memory (2GB) is not possible in some contexts
/// then the time parameter can be increased to compensate.
///
/// The time parameter specifies the number of passes over the memory and the
/// memory parameter specifies the size of the memory in KiB. The number of threads
/// can be adjusted to the numbers of available CPUs. The cost parameters should be
/// increased as memory latency and CPU parallelism increases. Remember to get a
/// good random salt.
///
/// [RFC 9106 Section 7.4]: https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4
pub fn key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    keylen: usize,
) -> Vec<u8> {
    let params = Params::new(memory, time, threads, Some(keylen)).expect("invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; keylen];
    argon2
        .hash_password_into(password, salt, &mut output)
        .expect("Argon2 hashing failed");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_vectors() {
        // Test vectors from Go's x/crypto/argon2 package.
        // Copyright 2017 The Go Authors. All rights reserved.
        // https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.39.0:argon2/argon2_test.go
        struct TestCase {
            time: u32,
            memory: u32,
            threads: u32,
            hash: &'static str,
        }
        let tests = [
            TestCase {
                time: 1,
                memory: 64,
                threads: 1,
                hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb",
            },
            TestCase {
                time: 2,
                memory: 64,
                threads: 1,
                hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7",
            },
            TestCase {
                time: 2,
                memory: 64,
                threads: 2,
                hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362",
            },
            TestCase {
                time: 3,
                memory: 256,
                threads: 2,
                hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b",
            },
            TestCase {
                time: 4,
                memory: 4096,
                threads: 4,
                hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a",
            },
            TestCase {
                time: 4,
                memory: 1024,
                threads: 8,
                hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f",
            },
            TestCase {
                time: 2,
                memory: 64,
                threads: 3,
                hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079",
            },
            TestCase {
                time: 3,
                memory: 1024,
                threads: 6,
                hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016",
            },
        ];
        let password = b"password";
        let salt = b"somesalt";

        for (_, v) in tests.iter().enumerate() {
            let want = hex::decode(v.hash).unwrap();
            let have = key(password, salt, v.time, v.memory, v.threads, want.len());
            assert_eq!(have, want);
        }
    }
}
