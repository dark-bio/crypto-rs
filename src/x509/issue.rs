// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::{CertificateProfile, CertificateTemplate, Error, Result, Subject, key_identifier};
use crate::xdsa;
#[cfg(feature = "xhpke")]
use crate::xhpke;
use der::Encode;
use der::asn1::{BitString, OctetString, UtcTime};
use std::collections::HashSet;
use std::time::Duration;
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// Issues an xDSA subject certificate and returns DER.
///
/// The certificate is signed by `issuer` and populated from `template`.
pub fn issue_xdsa_cert_der(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>> {
    Ok(issue_cert(subject, issuer, template)?.to_der()?)
}

/// Issues an xDSA subject certificate and returns PEM.
///
/// This is a thin wrapper over [`issue_xdsa_cert_der`] with `CERTIFICATE` PEM encoding.
pub fn issue_xdsa_cert_pem(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String> {
    let der = issue_xdsa_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

/// Issues an xHPKE subject certificate and returns DER.
///
/// xHPKE certificates are restricted to end-entity profile.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_der(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>> {
    if !matches!(template.profile, CertificateProfile::EndEntity) {
        return Err(Error::XhpkeMustBeEndEntity);
    }
    Ok(issue_cert(subject, issuer, template)?.to_der()?)
}

/// Issues an xHPKE subject certificate and returns PEM.
///
/// This is a thin wrapper over [`issue_xhpke_cert_der`] with `CERTIFICATE` PEM encoding.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_pem(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String> {
    let der = issue_xhpke_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

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
pub(super) fn issue_cert<S: Subject>(
    subject: &S,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<CertificateInner> {
    if template.subject.attrs.is_empty() {
        return Err(Error::EmptySubjectDn);
    }
    if template.issuer.attrs.is_empty() {
        return Err(Error::EmptyIssuerDn);
    }
    if template.validity.not_before >= template.validity.not_after {
        return Err(Error::InvalidValidityWindow);
    }

    let signature_alg = AlgorithmIdentifierOwned {
        oid: xdsa::OID,
        parameters: None,
    };

    let serial_number = make_serial(template.serial.as_deref())?;
    let subject_name = template.subject.to_x509_name()?;
    let issuer_name = template.issuer.to_x509_name()?;

    // Keep extension tracking to ensure custom OIDs cannot collide with
    // mandatory or previously inserted extension IDs.
    let mut extensions = Vec::<Extension>::new();
    let mut extension_oids = HashSet::new();

    let (is_ca, path_len) = match &template.profile {
        CertificateProfile::EndEntity => (false, None),
        CertificateProfile::CertificateAuthority { path_len } => (true, *path_len),
    };

    let bc = BasicConstraints {
        ca: is_ca,
        path_len_constraint: path_len,
    };
    let bc_ext = bc.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(bc_ext.extn_id.to_string());
    extensions.push(bc_ext);

    let key_usage = template
        .key_usage
        .unwrap_or_else(|| S::default_key_usage(&template.profile));
    let ku_ext = key_usage.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(ku_ext.extn_id.to_string());
    extensions.push(ku_ext);

    let ski = make_ski(subject.to_bytes().as_ref());
    let aki = make_aki(&issuer.public_key().to_bytes());
    let ski_ext = ski.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(ski_ext.extn_id.to_string());
    extensions.push(ski_ext);
    let aki_ext = aki.to_extension(&subject_name, extensions.as_slice())?;
    extension_oids.insert(aki_ext.extn_id.to_string());
    extensions.push(aki_ext);

    if !template.ext_key_usage.is_empty() {
        let eku = ExtendedKeyUsage(template.ext_key_usage.clone());
        let eku_ext = eku.to_extension(&subject_name, extensions.as_slice())?;
        extension_oids.insert(eku_ext.extn_id.to_string());
        extensions.push(eku_ext);
    }

    for custom in &template.custom_extensions {
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
            extn_value: OctetString::new(custom.value_der.clone())?,
        });
    }

    let not_before =
        UtcTime::from_unix_duration(Duration::from_secs(template.validity.not_before))?;
    let not_after = UtcTime::from_unix_duration(Duration::from_secs(template.validity.not_after))?;

    let tbs_certificate = TbsCertificateInner {
        version: Version::V3,
        serial_number,
        signature: signature_alg.clone(),
        issuer: issuer_name,
        validity: Validity {
            not_before: Time::UtcTime(not_before),
            not_after: Time::UtcTime(not_after),
        },
        subject: subject_name,
        subject_public_key_info: SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: subject.algorithm_oid(),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(subject.to_bytes().as_ref())?,
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    // Signature always covers the canonical DER encoding of TBSCertificate.
    let tbs_der = tbs_certificate.to_der()?;
    let signature = issuer.sign(&tbs_der);

    Ok(CertificateInner {
        tbs_certificate,
        signature_algorithm: signature_alg,
        signature: BitString::from_bytes(&signature.to_bytes())?,
    })
}

fn make_serial(serial: Option<&[u8]>) -> Result<SerialNumber> {
    if let Some(serial) = serial {
        return Ok(SerialNumber::new(serial)?);
    }
    let mut serial_bytes = [0u8; 16];
    getrandom::fill(&mut serial_bytes).map_err(|e| Error::SerialGenerationFailed {
        details: e.to_string(),
    })?;
    // Force positive INTEGER encoding (MSB clear).
    serial_bytes[0] &= 0x7F;
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
    use super::super::name::OID_CN;
    use super::super::*;
    use super::*;
    use crate::xdsa;
    #[cfg(feature = "xhpke")]
    use crate::xhpke;
    use const_oid::ObjectIdentifier;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            serial: None,
            key_usage: None,
            ext_key_usage: Vec::new(),
            custom_extensions: vec![CustomExtension {
                oid: private_enterprise_oid(62253, &[1, 1]).unwrap(),
                critical: false,
                value_der: vec![0x0c, 0x04, b't', b'e', b's', b't'],
            }],
        };

        let pem = issue_xdsa_cert_pem(&alice.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default()).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(cert.meta.is_ca);
        assert_eq!(cert.meta.path_len, Some(0));
        assert_eq!(cert.meta.custom_extensions.len(), 1);

        let der = issue_xdsa_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(cert.meta.is_ca);
        assert_eq!(cert.meta.path_len, Some(0));
        assert_eq!(cert.meta.custom_extensions.len(), 1);
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            serial: None,
            key_usage: None,
            ext_key_usage: Vec::new(),
            custom_extensions: Vec::new(),
        };

        let der = issue_xhpke_cert_der(&alice.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xhpke_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();

        assert_eq!(cert.public_key.to_bytes(), alice.public_key().to_bytes());
        assert!(!cert.meta.is_ca);
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };

        let result = issue_xhpke_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_rejects_invalid_printable_name() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().push(OID_CN, NameValue::Printable("bad*name".into())),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_rejects_invalid_ia5_name() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().push(OID_CN, NameValue::Ia5("na\u{80}me".into())),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

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
            validity: ValidityWindow::from_unix(now + 3600, now),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            custom_extensions: vec![CustomExtension {
                oid: ObjectIdentifier::new_unwrap("2.5.29.19"),
                critical: false,
                value_der: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_accepts_valid_printable_and_ia5_names() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let subject_dn = DistinguishedName::new()
            .push(OID_CN, NameValue::Printable("Alice-1".into()))
            .push(
                private_enterprise_oid(62253, &[42]).unwrap(),
                NameValue::Ia5("alice@example.com".into()),
            );

        let template = CertificateTemplate {
            subject: subject_dn,
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert_eq!(cert.public_key.to_bytes(), subject.public_key().to_bytes());
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            serial: Some(serial.clone()),
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert_eq!(cert.meta.serial, serial);
    }

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
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            custom_extensions: vec![
                CustomExtension {
                    oid,
                    critical: false,
                    value_der: vec![0x05, 0x00],
                },
                CustomExtension {
                    oid,
                    critical: false,
                    value_der: vec![0x05, 0x00],
                },
            ],
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
        assert!(result.is_err());
    }
}
