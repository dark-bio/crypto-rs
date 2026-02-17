// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::DistinguishedName;
use const_oid::ObjectIdentifier;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::ext::pkix::KeyUsage;

/// Validity window.
#[derive(Clone, Debug)]
pub struct ValidityWindow {
    /// NotBefore UNIX timestamp (seconds).
    pub not_before: u64,
    /// NotAfter UNIX timestamp (seconds).
    pub not_after: u64,
}

/// Role that an issued certificate may fulfil.
#[derive(Clone, Debug)]
pub enum CertificateRole {
    /// End-entity (leaf) certificate.
    Leaf,
    /// Certificate authority, with optional path length constraint.
    Authority { path_len: Option<u8> },
}

/// Private extension data.
#[derive(Clone, Debug)]
pub struct CustomExtension {
    /// Extension OID.
    pub oid: ObjectIdentifier,
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// DER-encoded extension payload (inside OCTET STRING).
    pub value: Vec<u8>,
}

/// Certificate issuance template.
#[derive(Clone, Debug)]
pub struct CertificateTemplate {
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Certificate validity window.
    pub validity: ValidityWindow,
    /// End-entity or CA role.
    pub role: CertificateRole,
    /// Optional serial, ff omitted, a random one is generated.
    pub serial: Option<Vec<u8>>,
    /// Non-standard extensions to append.
    pub extensions: Vec<CustomExtension>,
}

impl Default for CertificateTemplate {
    fn default() -> Self {
        Self {
            subject: DistinguishedName::default(),
            issuer: DistinguishedName::default(),
            validity: ValidityWindow {
                not_before: 0,
                not_after: 0,
            },
            role: CertificateRole::Leaf,
            serial: None,
            extensions: Vec::new(),
        }
    }
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

impl ValidityCheck {
    pub(super) fn timestamp(&self) -> Option<u64> {
        match self {
            ValidityCheck::Now => Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            ),
            ValidityCheck::At(ts) => Some(*ts),
            ValidityCheck::Disabled => None,
        }
    }
}

/// Parsed certificate metadata.
#[derive(Clone, Debug)]
pub struct CertificateMetadata {
    /// Parsed serial bytes.
    pub serial: Vec<u8>,
    /// Parsed subject DN.
    pub subject: DistinguishedName,
    /// Parsed issuer DN.
    pub issuer: DistinguishedName,
    /// Parsed validity window.
    pub validity: ValidityWindow,
    /// Certificate role (leaf or authority).
    pub role: CertificateRole,
    /// Parsed keyUsage extension.
    pub key_usage: KeyUsage,
    /// Parsed SKI bytes.
    pub subject_key_id: Vec<u8>,
    /// Parsed AKI bytes.
    pub authority_key_id: Vec<u8>,
    /// Parsed non-standard extensions.
    pub extensions: Vec<CustomExtension>,
}

/// A verified certificate with extracted public key and metadata.
#[derive(Clone, Debug)]
pub struct VerifiedCertificate<K> {
    /// Subject public key extracted from certificate SPKI.
    pub public_key: K,
    /// Parsed certificate metadata.
    pub meta: CertificateMetadata,
}
