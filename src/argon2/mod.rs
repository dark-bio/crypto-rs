// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Argon2id password-based key derivation.
//!
//! <https://datatracker.ietf.org/doc/html/rfc9106>
//!
//! Derives key material from a password and salt with configurable time and
//! memory cost to slow down offline guessing. Both the derived key and working
//! memory are wiped when dropped. For high-entropy secrets, use the `hkdf`
//! module instead.
//!
//! ```
//! use darkbio_crypto::argon2;
//!
//! // Example salt only; generate and store a fresh random 16-byte salt in real code
//! let salt = b"example salt1234";
//! let key = argon2::key::<32>(b"password", salt, 3, 64 * 1024, 4);
//! assert_eq!(key.len(), 32);
//! ```

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::{Zeroize, Zeroizing};

/// Derives a fixed-size key from `password`, `salt`, and cost parameters using
/// Argon2id.
///
/// [RFC 9106 Section 4] recommends `time = 1`, `memory = 2 * 1024 * 1024`
/// (2 GiB), and `threads = 4`, or `time = 3`, `memory = 64 * 1024` (64 MiB),
/// and `threads = 4` for memory-constrained environments. Both profiles use a
/// random 16-byte salt and a 32-byte output.
///
/// `time` is the number of passes and `memory` is the total working memory in
/// KiB. `threads` is Argon2's lane count, which changes the derived key even
/// though this crate runs Argon2 serially rather than spawning OS threads.
/// Store the salt and all cost parameters so other devices can reproduce the
/// same key.
///
/// # Panics
///
/// Panics if any input violates RFC 9106 bounds or working-memory allocation
/// fails:
///
/// - `time` must be at least 1.
/// - `threads` must be in `1..=0x00ff_ffff`.
/// - `memory` must be at least `8 * threads` KiB.
/// - `salt` must contain 8 to `u32::MAX` bytes.
/// - `password` must contain at most `u32::MAX` bytes.
/// - `N` must be in `4..=u32::MAX`.
///
/// [RFC 9106 Section 4]: https://www.rfc-editor.org/rfc/rfc9106.html#section-4
pub fn key<const N: usize>(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
) -> Zeroizing<[u8; N]> {
    validate_input_lengths(password.len(), salt.len());
    let params = Params::new(memory, time, threads, Some(N)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; N]);
    hash(&argon2, password, salt, output.as_mut());
    output
}

/// Derives a variable-length key from `password`, `salt`, and cost parameters
/// using Argon2id.
///
/// See [`key`] for parameter meanings and recommended profiles. Analogous to
/// [`key`], taking the output length at runtime and returning a `Vec<u8>`.
/// Intended for FFI bindings where const generics do not compose; prefer
/// [`key`] in Rust.
///
/// # Panics
///
/// Panics for the same invalid inputs as [`key`], with `out` in place of `N`,
/// or if allocating the output or working memory fails.
pub fn key_with_len(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    out: usize,
) -> Zeroizing<Vec<u8>> {
    validate_input_lengths(password.len(), salt.len());
    let params = Params::new(memory, time, threads, Some(out)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new(Vec::new());
    output.try_reserve_exact(out).unwrap();
    output.resize(out, 0);
    hash(&argon2, password, salt, &mut output);
    output
}

/// Validates password and salt lengths against RFC 9106 bounds before
/// allocating output or working memory.
fn validate_input_lengths(password_len: usize, salt_len: usize) {
    assert!(password_len <= argon2::MAX_PWD_LEN, "password too long");
    assert!(
        (argon2::MIN_SALT_LEN..=argon2::MAX_SALT_LEN).contains(&salt_len),
        "invalid salt length"
    );
}

/// Runs Argon2id into `output` using working memory owned by this crate and
/// wiped before returning.
fn hash(argon2: &Argon2, password: &[u8], salt: &[u8], output: &mut [u8]) {
    // The allocating Argon2 API never wipes its working memory, so own it here.
    // Reserving first turns an allocation failure into a panic rather than an abort.
    let count = argon2.params().block_count();
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(count).unwrap();
    blocks.resize(count, Block::new());

    let result =
        argon2.hash_password_into_with_memory(password, salt, output, blocks.as_mut_slice());

    // Wipe each block's backing words before releasing working memory
    for block in blocks.iter_mut() {
        block.as_mut().zeroize();
    }
    result.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests RFC 9106 input and output length boundaries, ensuring invalid
    /// parameters panic before allocating output or working memory.
    #[test]
    fn test_argon2id_limits() {
        // Minimum valid output length succeeds
        assert_eq!(key_with_len(b"", b"12345678", 1, 8, 1, 4).len(), 4);

        #[cfg(target_pointer_width = "64")]
        validate_input_lengths(u32::MAX as usize, u32::MAX as usize);

        // Verify each out-of-range input triggers its validation panic on native targets
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut cases: Vec<(&str, &str, fn())> = vec![
                ("short output", "OutputTooShort", || {
                    key_with_len(b"", b"12345678", 1, 8, 1, 3);
                }),
                ("zero time", "TimeTooSmall", || {
                    key_with_len(b"", b"12345678", 0, 8, 1, 4);
                }),
                ("short salt in key", "invalid salt length", || {
                    key::<4>(b"", b"1234567", 1, 8, 1);
                }),
                ("short salt in key_with_len", "invalid salt length", || {
                    key_with_len(b"", b"1234567", 1, 8, 1, 4);
                }),
            ];
            #[cfg(target_pointer_width = "64")]
            cases.extend([
                (
                    "oversized password",
                    "password too long",
                    (|| validate_input_lengths(u32::MAX as usize + 1, 8)) as fn(),
                ),
                ("oversized salt", "invalid salt length", || {
                    validate_input_lengths(0, u32::MAX as usize + 1);
                }),
                ("oversized output", "OutputTooLong", || {
                    key_with_len(b"", b"12345678", 1, 8, 1, usize::MAX);
                }),
            ]);
            for (name, want, run) in cases {
                let err = std::panic::catch_unwind(run).expect_err(name);
                let msg = err
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| err.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("");
                assert!(msg.contains(want), "{name}: got panic `{msg}`");
            }
        }
    }

    /// Tests Argon2id key derivation against the Go `x/crypto/argon2` vectors.
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

        for v in tests {
            let want = hex::decode(v.hash).unwrap();
            let have = key::<24>(password, salt, v.time, v.memory, v.threads);
            assert_eq!(have.as_slice(), want.as_slice());

            let have = key_with_len(password, salt, v.time, v.memory, v.threads, 24);
            assert_eq!(have.as_slice(), want.as_slice());
        }
    }
}
