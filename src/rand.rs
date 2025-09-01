// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;

/// generate creates an arbitrarily large buffer filled with randomness. Under
/// the hood it retrieves a 32-byte random seed from the OS and expands it via
/// ChaCha20.
pub fn generate(bytes: usize) -> Vec<u8> {
    // Create a random number stream that works in WASM
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("Failed to get random seed");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

    // Generate a random buffer filled with safe random numbers
    let mut buf = vec![0u8; bytes];
    rng.fill_bytes(&mut buf[..]);
    buf
}

#[cfg(test)]
mod tests {
    use crate::rand::generate;

    // Tests that generating different sized random buffers work. This test is
    // more of a smoke-test that the API works; it does not actually test the
    // quality of the generated random numbers.
    #[test]
    fn test_generate() {
        generate(0);
        generate(1);
        generate(32);
        generate(33);
        generate(1024 * 1024);
    }
}
