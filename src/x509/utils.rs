// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use const_oid::ObjectIdentifier;
use sha1::{Digest, Sha1};

/// Returns a PEN-scoped OID (`1.3.6.1.4.1.<pen>.<suffix...>`).
pub fn private_enterprise_oid(pen: u32, suffix: &[u32]) -> crate::x509::Result<ObjectIdentifier> {
    let mut oid = format!("1.3.6.1.4.1.{}", pen);
    for arc in suffix {
        oid.push('.');
        oid.push_str(arc.to_string().as_str());
    }
    Ok(ObjectIdentifier::new(oid.as_str())?)
}

/// Computes the SHA1 hash of a public key.
pub(super) fn key_identifier(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}
