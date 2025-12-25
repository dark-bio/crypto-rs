// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// generate creates an arbitrarily large buffer filled with randomness.
pub fn generate(bytes: usize) -> Vec<u8> {
    // Create a random buffer with a WASM friendly source
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf[..]).expect("Failed to get random bytes");
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
