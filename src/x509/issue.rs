// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::utils::key_identifier;
use super::{Certificate, Error, Result, Role};
use crate::xdsa;
use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{BitString, OctetString, UtcTime};
use std::collections::HashSet;
use std::time::Duration;
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// Internal certificate builder shared by all public issue APIs.
///
/// The function validates template invariants, builds RFC 5280 extensions,
/// signs the `TBSCertificate`, and returns the in-memory certificate object.
pub(crate) fn issue_cert(
    subject_key: &[u8],
    subject_algorithm: ObjectIdentifier,
    default_key_usage: KeyUsage,
    issuer: &xdsa::SecretKey,
    template: &Certificate,
) -> Result<CertificateInner> {
    // Sanity check some mandatory fields
    if template.subject.attrs.is_empty() {
        return Err(Error::EmptyDistinguishedName { field: "subject" });
    }
    if template.issuer.attrs.is_empty() {
        return Err(Error::EmptyDistinguishedName { field: "issuer" });
    }
    if template.not_before >= template.not_after {
        return Err(Error::InvalidValidity);
    }
    // Generate a random serial number
    let mut serial_bytes = [0u8; 16];
    getrandom::fill(&mut serial_bytes).unwrap();

    serial_bytes[0] &= 0x7F; // Ensure positive (MSB = 0)
    let serial_number = SerialNumber::new(&serial_bytes).unwrap();

    // Create the signature algorithm identifier (always xDSA)
    let signature_alg = AlgorithmIdentifierOwned {
        oid: xdsa::OID,
        parameters: None,
    };

    let subject_name = template.subject.to_x509_name()?;
    let issuer_name = template.issuer.to_x509_name()?;

    // Tracking extensions to ensure custom OIDs don't collide with mandatory
    // or previously inserted extension IDs
    let mut extensions = Vec::<Extension>::new();
    let mut extension_oids = HashSet::new();

    // Inject the base components
    let (is_ca, path_len) = match &template.role {
        Role::Leaf => (false, None),
        Role::Authority { path_len } => (true, *path_len),
    };

    let bc = BasicConstraints {
        ca: is_ca,
        path_len_constraint: path_len,
    };
    let bc_ext = bc.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(bc_ext.extn_id.to_string());
    extensions.push(bc_ext);

    let key_usage = default_key_usage;
    let ku_ext = key_usage.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(ku_ext.extn_id.to_string());
    extensions.push(ku_ext);

    // Inject the subject and authority key identifiers
    let ski = make_ski(subject_key);
    let aki = make_aki(&issuer.public_key().to_bytes());
    let ski_ext = ski.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(ski_ext.extn_id.to_string());
    extensions.push(ski_ext);

    let aki_ext = aki.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(aki_ext.extn_id.to_string());
    extensions.push(aki_ext);

    // Inject custom extensions
    for custom in &template.extensions {
        let oid = custom.oid.to_string();
        if oid.starts_with("2.5.29.") {
            return Err(Error::ReservedExtensionOid);
        }
        if !extension_oids.insert(oid.clone()) {
            return Err(Error::DuplicateExtensionOid { oid });
        }
        extensions.push(Extension {
            extn_id: custom.oid,
            critical: custom.critical,
            extn_value: OctetString::new(custom.value.clone())?,
        });
    }

    // Assemble the certificate content
    let tbs_certificate = TbsCertificateInner {
        version: Version::V3,
        serial_number,
        signature: signature_alg.clone(),
        issuer: issuer_name,
        validity: Validity {
            not_before: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(
                template.not_before,
            ))?),
            not_after: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(
                template.not_after,
            ))?),
        },
        subject: subject_name,
        subject_public_key_info: SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: subject_algorithm,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(subject_key)?,
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    // Sign the canonical DER encoding of TBSCertificate.
    let tbs_der = tbs_certificate.to_der()?;
    let signature = issuer.sign(&tbs_der);

    Ok(CertificateInner {
        tbs_certificate,
        signature_algorithm: signature_alg,
        signature: BitString::from_bytes(&signature.to_bytes())?,
    })
}

/// Builds SubjectKeyIdentifier as SHA-1(subjectPublicKey bytes).
fn make_ski(public_key: &[u8]) -> SubjectKeyIdentifier {
    let hash = key_identifier(public_key);
    SubjectKeyIdentifier(OctetString::new(hash).unwrap())
}

/// Builds AuthorityKeyIdentifier as SHA-1(issuer subjectPublicKey bytes).
fn make_aki(public_key: &[u8]) -> AuthorityKeyIdentifier {
    let hash = key_identifier(public_key);
    AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(hash).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    }
}

#[cfg(test)]
mod test {
    use super::super::*;
    use crate::xdsa;
    #[cfg(feature = "xhpke")]
    use crate::xhpke;
    use const_oid::ObjectIdentifier;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Verifies that an xDSA certificate round-trips through issue and verify in both PEM and DER.
    #[test]
    fn test_issue_and_verify_xdsa() {
        let alice = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            extensions: vec![Extension {
                oid: ObjectIdentifier::new("1.3.6.1.4.1.62253.1.1").unwrap(),
                critical: false,
                value: vec![0x0c, 0x04, b't', b'e', b's', b't'],
            }],
        };

        let pem = xdsa::issue_cert_pem(&alice.public_key(), &issuer, &template).unwrap();
        let cert = xdsa::verify_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(
            cert.cert.role,
            Role::Authority { path_len: Some(0) }
        ));
        assert_eq!(cert.cert.extensions.len(), 1);

        let der = xdsa::issue_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(
            cert.cert.role,
            Role::Authority { path_len: Some(0) }
        ));
        assert_eq!(cert.cert.extensions.len(), 1);
    }

    /// Verifies that an xHPKE certificate round-trips through issue and verify in DER.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_issue_and_verify_xhpke() {
        let alice = xhpke::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            extensions: Vec::new(),
        };

        let pem = xhpke::issue_cert_pem(&alice.public_key(), &issuer, &template).unwrap();
        let cert = xhpke::verify_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(cert.cert.role, Role::Leaf));

        let der = xhpke::issue_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert = xhpke::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(cert.cert.role, Role::Leaf));
    }

    /// Verifies that issuing an xHPKE certificate with a CA role is rejected.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_issue_xhpke_rejects_ca_profile() {
        let subject = xhpke::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };

        let result = xhpke::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a template with not_before > not_after is rejected.
    #[test]
    fn test_issue_rejects_inverted_validity_window() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now + 3600,
            not_after: now,
            role: Role::Leaf,
            ..Default::default()
        };

        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a custom extension using a reserved standard OID (2.5.29.*) is rejected.
    #[test]
    fn test_issue_rejects_custom_standard_extension_oid() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            extensions: vec![Extension {
                oid: ObjectIdentifier::new_unwrap("2.5.29.19"),
                critical: false,
                value: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that DN attributes with custom private-enterprise OIDs are accepted.
    #[test]
    fn test_issue_accepts_custom_oid_names() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let subject_dn = Name::new().cn("Alice-1").push(
            ObjectIdentifier::new("1.3.6.1.4.1.62253.42").unwrap(),
            "alice@example.com",
        );

        let template = Certificate {
            subject: subject_dn,
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };

        let der = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.public_key.to_bytes(), subject.public_key().to_bytes());
    }

    /// Verifies that a template with an empty subject DN is rejected.
    #[test]
    fn test_issue_rejects_empty_subject_dn() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new(),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a template with an empty issuer DN is rejected.
    #[test]
    fn test_issue_rejects_empty_issuer_dn() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Subject"),
            issuer: Name::new(),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that duplicate custom extension OIDs in a template are rejected.
    #[test]
    fn test_issue_rejects_duplicate_custom_extension_oid() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let oid = ObjectIdentifier::new("1.3.6.1.4.1.62253.8.8").unwrap();

        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            extensions: vec![
                Extension {
                    oid,
                    critical: false,
                    value: vec![0x05, 0x00],
                },
                Extension {
                    oid,
                    critical: false,
                    value: vec![0x05, 0x00],
                },
            ],
            ..Default::default()
        };

        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a validity window with equal not_before and not_after is rejected.
    #[test]
    fn test_issue_rejects_equal_validity_window() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now,
            role: Role::Leaf,
            ..Default::default()
        };

        let result = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }
}
