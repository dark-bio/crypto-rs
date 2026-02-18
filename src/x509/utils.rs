// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use sha1::{Digest, Sha1};

/// Computes the SHA1 hash of a public key.
pub(super) fn key_identifier(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}
