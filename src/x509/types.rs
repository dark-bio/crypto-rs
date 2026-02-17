// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::DistinguishedName;
use crate::xdsa;
#[cfg(feature = "xhpke")]
use crate::xhpke;
use const_oid::ObjectIdentifier;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

/// Validity window.
#[derive(Clone, Debug)]
pub struct ValidityWindow {
    /// NotBefore UNIX timestamp (seconds).
    pub not_before: u64,
    /// NotAfter UNIX timestamp (seconds).
    pub not_after: u64,
}

impl ValidityWindow {
    /// Creates a validity window from unix timestamps.
    pub fn from_unix(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

/// CA profile for certificate issuance.
#[derive(Clone, Debug)]
pub enum CertificateProfile {
    /// End-entity certificate profile.
    EndEntity,
    /// CA certificate profile, with optional path length constraint.
    CertificateAuthority { path_len: Option<u8> },
}

/// Private extension data.
#[derive(Clone, Debug)]
pub struct CustomExtension {
    /// Extension OID.
    pub oid: ObjectIdentifier,
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// DER-encoded extension payload (inside OCTET STRING).
    pub value_der: Vec<u8>,
}

/// Certificate issuance template.
#[derive(Clone, Debug)]
pub struct CertificateTemplate {
    /// Subject distinguished name.
    pub subject: super::DistinguishedName,
    /// Issuer distinguished name.
    pub issuer: super::DistinguishedName,
    /// Certificate validity window.
    pub validity: ValidityWindow,
    /// End-entity or CA profile.
    pub profile: CertificateProfile,
    /// Optional explicit serial bytes. If omitted, a random serial is generated.
    pub serial: Option<Vec<u8>>,
    /// Optional explicit keyUsage extension. If omitted, defaults depend on key/profile.
    pub key_usage: Option<KeyUsage>,
    /// Extended key usage OIDs.
    pub ext_key_usage: Vec<ObjectIdentifier>,
    /// Non-standard extensions to append.
    pub custom_extensions: Vec<CustomExtension>,
}

impl Default for CertificateTemplate {
    fn default() -> Self {
        Self {
            subject: super::DistinguishedName::default(),
            issuer: super::DistinguishedName::default(),
            validity: ValidityWindow::from_unix(0, 0),
            profile: CertificateProfile::EndEntity,
            serial: None,
            key_usage: None,
            ext_key_usage: Vec::new(),
            custom_extensions: Vec::new(),
        }
    }
}

/// Verification policy.
#[derive(Clone, Debug)]
pub struct VerifyPolicy {
    /// Controls how certificate validity (`not_before`/`not_after`) is checked.
    pub validity_check: ValidityCheck,
    /// Maximum accepted certificate DER size in bytes.
    pub max_certificate_size: usize,
    /// Maximum accepted serial number length in bytes.
    pub max_serial_length: usize,
    /// Maximum accepted DN attribute count for subject and issuer names.
    pub max_dn_attributes: usize,
    /// Maximum accepted DN attribute value length in bytes.
    pub max_dn_attr_value_size: usize,
    /// Maximum accepted extension value size in bytes.
    pub max_extension_value_size: usize,
    /// Maximum accepted number of non-standard custom extensions.
    pub max_custom_extensions: usize,
    /// Require SubjectKeyIdentifier extension to be present.
    pub require_subject_key_id: bool,
    /// Require AuthorityKeyIdentifier extension to be present.
    pub require_authority_key_id: bool,
    /// Require child issuer DN to match issuer certificate subject DN
    /// when using *_with_issuer_cert verification APIs.
    pub require_name_chaining: bool,
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

impl Default for VerifyPolicy {
    /// Defaults to validating against current wall-clock time.
    ///
    /// For deterministic tests, set an explicit timestamp.
    fn default() -> Self {
        Self {
            validity_check: ValidityCheck::Now,
            max_certificate_size: 64 * 1024,
            max_serial_length: 20,
            max_dn_attributes: 32,
            max_dn_attr_value_size: 1024,
            max_extension_value_size: 16 * 1024,
            max_custom_extensions: 64,
            require_subject_key_id: true,
            require_authority_key_id: true,
            require_name_chaining: true,
        }
    }
}

impl VerifyPolicy {
    pub(super) fn validity_timestamp(&self) -> Option<u64> {
        match self.validity_check {
            ValidityCheck::Now => Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            ),
            ValidityCheck::At(ts) => Some(ts),
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
    /// Whether `basicConstraints.ca` is true.
    pub is_ca: bool,
    /// Parsed `pathLenConstraint` when present.
    pub path_len: Option<u8>,
    /// Parsed keyUsage extension.
    pub key_usage: Option<KeyUsage>,
    /// Parsed EKU OID list.
    pub ext_key_usage: Vec<ObjectIdentifier>,
    /// Parsed SKI bytes.
    pub subject_key_id: Option<Vec<u8>>,
    /// Parsed AKI bytes.
    pub authority_key_id: Option<Vec<u8>>,
    /// Parsed non-standard extensions.
    pub custom_extensions: Vec<CustomExtension>,
}

/// A verified certificate with extracted public key and metadata.
#[derive(Clone, Debug)]
pub struct VerifiedCertificate<K> {
    /// Subject public key extracted from certificate SPKI.
    pub public_key: K,
    /// Parsed certificate metadata.
    pub meta: CertificateMetadata,
}

pub(super) trait Subject {
    type Bytes: AsRef<[u8]>;

    fn to_bytes(&self) -> Self::Bytes;
    fn algorithm_oid(&self) -> ObjectIdentifier;
    fn default_key_usage(profile: &CertificateProfile) -> KeyUsage;
}

impl Subject for xdsa::PublicKey {
    type Bytes = [u8; xdsa::PUBLIC_KEY_SIZE];

    fn to_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn algorithm_oid(&self) -> ObjectIdentifier {
        xdsa::OID
    }

    fn default_key_usage(profile: &CertificateProfile) -> KeyUsage {
        match profile {
            CertificateProfile::CertificateAuthority { .. } => {
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            }
            CertificateProfile::EndEntity => KeyUsage(KeyUsages::DigitalSignature.into()),
        }
    }
}

#[cfg(feature = "xhpke")]
impl Subject for xhpke::PublicKey {
    type Bytes = [u8; xhpke::PUBLIC_KEY_SIZE];

    fn to_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn algorithm_oid(&self) -> ObjectIdentifier {
        xhpke::OID
    }

    fn default_key_usage(_profile: &CertificateProfile) -> KeyUsage {
        KeyUsage(KeyUsages::KeyAgreement.into())
    }
}
