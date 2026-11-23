// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Random bytes from the operating system's secure source.
//!
//! ```
//! let nonce = darkbio_crypto::rand::generate(32);
//! assert_eq!(nonce.len(), 32);
//! ```

/// Generates a buffer of `bytes` random bytes from the operating system.
///
/// # Panics
///
/// Panics if the operating system's random source fails.
pub fn generate(bytes: usize) -> Vec<u8> {
    // Fill a buffer from the WASM-compatible OS entropy source
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf[..]).expect("Failed to get random bytes");
    buf
}

#[cfg(test)]
mod tests {
    use crate::rand::generate;

    /// Tests that random buffers of various sizes are generated with the
    /// requested length and distinct outputs.
    #[test]
    fn test_generate() {
        for len in [0, 1, 32, 33, 1024 * 1024] {
            assert_eq!(generate(len).len(), len);
        }
        assert_ne!(generate(32), generate(32));
    }
}
