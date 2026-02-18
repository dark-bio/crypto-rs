// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::Name;
use const_oid::ObjectIdentifier;

/// X.509 certificate parameters used for both issuance and verification.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// Subject distinguished name.
    pub subject: Name,
    /// Issuer distinguished name.
    pub issuer: Name,
    /// NotBefore UNIX timestamp (seconds).
    pub not_before: u64,
    /// NotAfter UNIX timestamp (seconds).
    pub not_after: u64,
    /// End-entity or CA role.
    pub role: Role,
    /// Non-standard extensions.
    pub extensions: Vec<Extension>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            subject: Name::default(),
            issuer: Name::default(),
            not_before: 0,
            not_after: 0,
            role: Role::Leaf,
            extensions: Vec::new(),
        }
    }
}

/// Verified public key with the extracted certificate parameters.
#[derive(Clone, Debug)]
pub struct Verified<K> {
    /// Subject public key extracted from certificate SPKI.
    pub public_key: K,
    /// Parsed certificate parameters.
    pub cert: Certificate,
}

/// Role an issued certificate may fulfil.
#[derive(Clone, Debug)]
pub enum Role {
    /// End-entity (leaf) certificate.
    Leaf,
    /// Certificate authority, with optional path length constraint.
    Authority { path_len: Option<u8> },
}

/// Private extension to include / check in a certificate.
#[derive(Clone, Debug)]
pub struct Extension {
    /// Extension OID.
    pub oid: ObjectIdentifier,
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// DER-encoded extension payload (inside OCTET STRING).
    pub value: Vec<u8>,
}

/// Certificate validity check mode.
#[derive(Clone, Copy, Debug)]
pub enum ValidityCheck {
    /// Validate against current wall-clock time.
    Now,
    /// Validate against a specific unix timestamp.
    At(u64),
    /// Skip validity-time checks.
    Disabled,
}
