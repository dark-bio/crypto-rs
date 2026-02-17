// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::utils::key_identifier;
use super::{CertificateRole, CertificateTemplate, Error, Result};
use crate::xdsa;
#[cfg(feature = "xhpke")]
use crate::xhpke;
use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{BitString, OctetString, UtcTime};
use std::collections::HashSet;
use std::time::Duration;
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// Issues an xDSA certificate and returns it DER encoded.
pub fn issue_xdsa_cert_der(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>> {
    let default_key_usage = match template.role {
        CertificateRole::Authority { .. } => KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        CertificateRole::Leaf => KeyUsage(KeyUsages::DigitalSignature.into()),
    };
    Ok(issue_cert(
        &subject.to_bytes(),
        xdsa::OID,
        default_key_usage,
        issuer,
        template,
    )?
    .to_der()?)
}

/// Issues an xDSA certificate and returns it PEM encoded.
pub fn issue_xdsa_cert_pem(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String> {
    let der = issue_xdsa_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

/// Issues an xHPKE certificate and returns it DER encoded.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_der(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>> {
    if !matches!(template.role, CertificateRole::Leaf) {
        return Err(Error::XhpkeMustBeEndEntity);
    }
    let default_key_usage = KeyUsage(KeyUsages::KeyAgreement.into());
    Ok(issue_cert(
        &subject.to_bytes(),
        xhpke::OID,
        default_key_usage,
        issuer,
        template,
    )?
    .to_der()?)
}

/// Issues an xHPKE certificate and returns it PEM encoded.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_pem(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String> {
    let der = issue_xhpke_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

/// Helper to encode a supposedly DER blob into a PEM certificate container.
fn encode_certificate_pem(der: &[u8]) -> Result<String> {
    let pem =
        der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, der).map_err(|e| {
            Error::PemEncode {
                details: format!("{e:?}"),
            }
        })?;
    Ok(pem)
}

/// Internal certificate builder shared by all public issue APIs.
///
/// The function validates template invariants, builds RFC 5280 extensions,
/// signs the `TBSCertificate`, and returns the in-memory certificate object.
pub(super) fn issue_cert(
    subject_key: &[u8],
    subject_algorithm: ObjectIdentifier,
    default_key_usage: KeyUsage,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<CertificateInner> {
    // Sanity check some mandatory fields
    if template.subject.attrs.is_empty() {
        return Err(Error::EmptyDistinguishedName { field: "subject" });
    }
    if template.issuer.attrs.is_empty() {
        return Err(Error::EmptyDistinguishedName { field: "issuer" });
    }
    if template.validity.not_before >= template.validity.not_after {
        return Err(Error::InvalidValidityWindow);
    }
    // Hard code xDSA as the signature algorithm
    let signature_alg = AlgorithmIdentifierOwned {
        oid: xdsa::OID,
        parameters: None,
    };

    let serial_number = make_serial(template.serial.as_deref())?;
    let subject_name = template.subject.to_x509_name()?;
    let issuer_name = template.issuer.to_x509_name()?;

    // Tracking extensions to ensure custom OIDs don't collide with mandatory
    // or previously inserted extension IDs
    let mut extensions = Vec::<Extension>::new();
    let mut extension_oids = HashSet::new();

    // Inject the base components
    let (is_ca, path_len) = match &template.role {
        CertificateRole::Leaf => (false, None),
        CertificateRole::Authority { path_len } => (true, *path_len),
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
        if !extension_oids.insert(oid) {
            return Err(Error::DuplicateTemplateExtensionOid);
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
                template.validity.not_before,
            ))?),
            not_after: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(
                template.validity.not_after,
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

/// Builds the serial number either from input or random.
fn make_serial(serial: Option<&[u8]>) -> Result<SerialNumber> {
    if let Some(serial) = serial {
        if serial.is_empty() || serial.iter().all(|b| *b == 0) {
            return Err(Error::InvalidSerial {
                details: "serial number must be non-zero",
            });
        }
        if serial.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::InvalidSerial {
                details: "serial number must be positive (MSB must be clear)",
            });
        }
        return Ok(SerialNumber::new(serial)?);
    }
    let mut serial_bytes = [0u8; 16];
    getrandom::fill(&mut serial_bytes).map_err(|e| Error::SerialGenerationFailed {
        details: e.to_string(),
    })?;
    // Force positive INTEGER encoding (MSB clear) and ensure non-zero.
    serial_bytes[0] &= 0x7F;
    serial_bytes[0] |= 0x01;
    Ok(SerialNumber::new(&serial_bytes)?)
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
    use super::*;
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            serial: None,
            extensions: vec![CustomExtension {
                oid: private_enterprise_oid(62253, &[1, 1]).unwrap(),
                critical: false,
                value: vec![0x0c, 0x04, b't', b'e', b's', b't'],
            }],
        };

        let pem = issue_xdsa_cert_pem(&alice.public_key(), &issuer, &template).unwrap();
        let cert = verify_xdsa_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(
            cert.meta.role,
            CertificateRole::Authority { path_len: Some(0) }
        ));
        assert_eq!(cert.meta.extensions.len(), 1);

        let der = issue_xdsa_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(
            cert.meta.role,
            CertificateRole::Authority { path_len: Some(0) }
        ));
        assert_eq!(cert.meta.extensions.len(), 1);
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Encryption"),
            issuer: DistinguishedName::new().cn("Alice Identity"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            serial: None,
            extensions: Vec::new(),
        };

        let pem = issue_xhpke_cert_pem(&alice.public_key(), &issuer, &template).unwrap();
        let cert = verify_xhpke_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(cert.meta.role, CertificateRole::Leaf));

        let der = issue_xhpke_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert = verify_xhpke_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(matches!(cert.meta.role, CertificateRole::Leaf));
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Encryption"),
            issuer: DistinguishedName::new().cn("Alice Identity"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };

        let result = issue_xhpke_cert_der(&subject.public_key(), &issuer, &template);
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now + 3600,
                not_after: now,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            extensions: vec![CustomExtension {
                oid: ObjectIdentifier::new_unwrap("2.5.29.19"),
                critical: false,
                value: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
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

        let subject_dn = DistinguishedName::new().cn("Alice-1").push(
            private_enterprise_oid(62253, &[42]).unwrap(),
            "alice@example.com",
        );

        let template = CertificateTemplate {
            subject: subject_dn,
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new(),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Subject"),
            issuer: DistinguishedName::new(),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a user-supplied serial number is used verbatim in the issued certificate.
    #[test]
    fn test_issue_uses_explicit_serial() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let serial = vec![0x01, 0x23, 0x45, 0x67];

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            serial: Some(serial.clone()),
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert_eq!(cert.meta.serial, serial);
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
        let oid = private_enterprise_oid(62253, &[8, 8]).unwrap();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            extensions: vec![
                CustomExtension {
                    oid,
                    critical: false,
                    value: vec![0x05, 0x00],
                },
                CustomExtension {
                    oid,
                    critical: false,
                    value: vec![0x05, 0x00],
                },
            ],
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a user-supplied serial number with MSB set is rejected as negative.
    #[test]
    fn test_issue_rejects_negative_serial() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            serial: Some(vec![0x80, 0x01]),
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
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

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that a zero serial number is rejected.
    #[test]
    fn test_issue_rejects_zero_serial() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            serial: Some(vec![0x00]),
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    /// Verifies that an empty serial number is rejected.
    #[test]
    fn test_issue_rejects_empty_serial() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            serial: Some(vec![]),
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }
}
