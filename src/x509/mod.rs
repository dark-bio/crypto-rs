// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

use const_oid::ObjectIdentifier;
use sha1::{Digest, Sha1};

mod error;
mod issue;
mod name;
mod types;
mod verify;

pub use error::{Error, Result};
pub use name::{DistinguishedName, NameAttribute, NameValue};
pub use types::{
    CertificateMetadata, CertificateProfile, CertificateTemplate, CustomExtension, ValidityCheck,
    ValidityWindow, VerifiedCertificate, VerifyPolicy,
};

/// Returns a PEN-scoped OID (`1.3.6.1.4.1.<pen>.<suffix...>`).
pub fn private_enterprise_oid(pen: u32, suffix: &[u32]) -> Result<ObjectIdentifier> {
    let mut oid = format!("1.3.6.1.4.1.{}", pen);
    for arc in suffix {
        oid.push('.');
        oid.push_str(arc.to_string().as_str());
    }
    Ok(ObjectIdentifier::new(oid.as_str())?)
}

pub use issue::{issue_xdsa_cert_der, issue_xdsa_cert_pem};
#[cfg(feature = "xhpke")]
pub use issue::{issue_xhpke_cert_der, issue_xhpke_cert_pem};

pub use verify::{
    verify_xdsa_cert_der, verify_xdsa_cert_der_with_issuer_cert, verify_xdsa_cert_pem,
    verify_xdsa_cert_pem_with_issuer_cert,
};
#[cfg(feature = "xhpke")]
pub use verify::{
    verify_xhpke_cert_der, verify_xhpke_cert_der_with_issuer_cert, verify_xhpke_cert_pem,
    verify_xhpke_cert_pem_with_issuer_cert,
};

#[cfg(test)]
use issue::issue_cert;
#[cfg(test)]
use verify::{convert_path_len, unix_ts_to_u64, validate_serial_encoding};

fn key_identifier(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

use types::Subject;

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::xdsa;
    #[cfg(feature = "xhpke")]
    use crate::xhpke;
    use const_oid::db::rfc5280::{
        ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION, ID_KP_OCSP_SIGNING,
        ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING,
    };
    use der::asn1::{Any, BitString, OctetString, SetOfVec};
    use der::{Encode, Tag};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::certificate::Version;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

    #[test]
    fn test_verify_xdsa_rejects_wrong_signer() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let wrong = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &wrong.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_xdsa_rejects_key_agreement_usage() {
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
            key_usage: Some(KeyUsage(KeyUsages::KeyAgreement.into())),
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_wrong_signer() {
        let subject = xhpke::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let wrong = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Encryption"),
            issuer: DistinguishedName::new().cn("Alice Identity"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let pem = issue_xhpke_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xhpke_cert_pem(&pem, &wrong.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_signing_key_usage() {
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
            profile: CertificateProfile::EndEntity,
            key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
            ..Default::default()
        };

        let pem = issue_xhpke_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xhpke_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_ca_certificate() {
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

        // Build a malformed xHPKE CA certificate via internal helper to ensure
        // verification enforces the end-entity invariant.
        let der = issue_cert(&subject.public_key(), &issuer, &template)
            .unwrap()
            .to_der()
            .unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_unrecognized_critical_extension() {
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
                oid: private_enterprise_oid(62253, &[9, 9]).unwrap(),
                critical: true,
                value_der: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_non_v3_certificate() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.version = Version::V1;
        cert.tbs_certificate.extensions = None;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_non_certificate_pem_label() {
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
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let pem = pem.replace("CERTIFICATE", "PRIVATE KEY");

        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_trailing_der_data() {
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
            ..Default::default()
        };

        let mut der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        der.extend_from_slice(&[0xde, 0xad]);
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_trailing_pem_data() {
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
            ..Default::default()
        };

        let mut pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        pem.push_str("TRAILING");
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_signature_algorithm_parameters() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.signature.parameters =
            Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());
        cert.signature_algorithm.parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_xdsa_ee_rejects_ca_key_usage_flags() {
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
            key_usage: Some(KeyUsage(
                KeyUsages::DigitalSignature | KeyUsages::KeyCertSign,
            )),
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_malformed_validity_without_time_policy() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.validity.not_after = cert.tbs_certificate.validity.not_before;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let policy = VerifyPolicy {
            validity_check: ValidityCheck::Disabled,
            ..Default::default()
        };
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_ski_mismatch() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        let mut patched = false;
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.14") {
                ext.extn_value = OctetString::new(vec![0x04, 0x01, 0x00]).unwrap();
                patched = true;
                break;
            }
        }
        assert!(patched);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_non_certificate_pem_label() {
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
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let pem = issue_xhpke_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let pem = pem.replace("CERTIFICATE", "PRIVATE KEY");

        let result = verify_xhpke_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_path_len_rejects_large_values() {
        assert!(convert_path_len(Some(256)).is_err());
        assert_eq!(convert_path_len(Some(255)).unwrap(), Some(255));
        assert_eq!(convert_path_len(None).unwrap(), None);
    }

    #[test]
    fn test_unix_ts_to_u64_rejects_negative_values() {
        assert!(unix_ts_to_u64(-1).is_err());
        assert_eq!(unix_ts_to_u64(0).unwrap(), 0);
    }

    #[test]
    fn test_validate_serial_encoding_rejects_noncanonical_values() {
        assert!(validate_serial_encoding(&[]).is_err());
        assert!(validate_serial_encoding(&[0x80]).is_err());
        assert!(validate_serial_encoding(&[0x00, 0x01]).is_err());
        assert!(validate_serial_encoding(&[0x00]).is_err());
        assert!(validate_serial_encoding(&[0x01]).is_ok());
        assert!(validate_serial_encoding(&[0x7f]).is_ok());
    }

    #[test]
    fn test_verify_rejects_xdsa_subject_algorithm_mismatch() {
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
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid =
            ObjectIdentifier::new_unwrap("1.2.3.4");

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_xdsa_spki_parameters() {
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
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_signature_algorithm_oid_mismatch() {
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
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong = ObjectIdentifier::new_unwrap("1.2.3.4");
        cert.tbs_certificate.signature.oid = wrong;
        cert.signature_algorithm.oid = wrong;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_future_cert_by_time_policy() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now + 3600, now + 7200),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            validity_check: ValidityCheck::At(now),
            ..Default::default()
        };
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_allows_valid_cert_without_time_policy() {
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
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            validity_check: ValidityCheck::Disabled,
            ..Default::default()
        };
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_extracts_all_eku_flags() {
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
            ext_key_usage: vec![
                ObjectIdentifier::new_unwrap("2.5.29.37.0"),
                ID_KP_SERVER_AUTH,
                ID_KP_CLIENT_AUTH,
                ID_KP_CODE_SIGNING,
                ID_KP_EMAIL_PROTECTION,
                ID_KP_TIME_STAMPING,
                ID_KP_OCSP_SIGNING,
                private_enterprise_oid(62253, &[9, 1]).unwrap(),
            ],
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("2.5.29.37.0"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9"))
        );
        assert!(
            cert.meta
                .ext_key_usage
                .contains(&private_enterprise_oid(62253, &[9, 1]).unwrap())
        );
    }

    #[test]
    fn test_verify_parses_missing_basic_constraints_as_end_entity() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|ext| ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.19"));

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let parsed =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert!(!parsed.meta.is_ca);
        assert_eq!(parsed.meta.path_len, None);
    }

    #[test]
    fn test_verify_rejects_aki_mismatch() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        let mut patched = false;
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.35") {
                ext.extn_value = OctetString::new(vec![0x30, 0x03, 0x80, 0x01, 0x00]).unwrap();
                patched = true;
                break;
            }
        }
        assert!(patched);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_missing_ski_and_aki_by_default() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|ext| {
                ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.14")
                    && ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.35")
            });

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());

        let policy = VerifyPolicy {
            require_subject_key_id: false,
            require_authority_key_id: false,
            ..Default::default()
        };
        let parsed = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy).unwrap();
        assert!(parsed.meta.subject_key_id.is_none());
        assert!(parsed.meta.authority_key_id.is_none());
    }

    #[test]
    fn test_verify_rejects_certificate_over_size_limit() {
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
            ..Default::default()
        };
        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            max_certificate_size: der.len() - 1,
            ..Default::default()
        };
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_extension_value_over_limit() {
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
                oid: private_enterprise_oid(62253, &[99]).unwrap(),
                critical: false,
                value_der: vec![0x04, 0x03, 1, 2, 3],
            }],
            ..Default::default()
        };
        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            max_extension_value_size: 2,
            ..Default::default()
        };
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_xdsa_ca_wrong_key_usage() {
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
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_handles_binary_subject_attribute_values() {
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
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();

        let mut set = SetOfVec::new();
        set.insert(AttributeTypeAndValue {
            oid: name::OID_CN,
            value: Any::new(Tag::OctetString, vec![1, 2, 3]).unwrap(),
        })
        .unwrap();
        cert.tbs_certificate.subject = RdnSequence(vec![RelativeDistinguishedName::from(set)]);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let parsed =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert_eq!(parsed.meta.subject.attrs.len(), 1);
        assert!(matches!(
            parsed.meta.subject.attrs[0].value,
            NameValue::Bytes(_)
        ));
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_rejects_xhpke_subject_algorithm_mismatch() {
        let subject = xhpke::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Encryption"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid =
            ObjectIdentifier::new_unwrap("1.2.3.4");

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_rejects_xhpke_spki_parameters() {
        let subject = xhpke::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Encryption"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_with_issuer_cert_rejects_non_ca_issuer() {
        let issuer_ee = xdsa::SecretKey::generate();
        let subject_ee = xhpke::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Issuer EE"),
            issuer: DistinguishedName::new().cn("Issuer EE"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let issuer_cert_pem =
            issue_xdsa_cert_pem(&issuer_ee.public_key(), &issuer_ee, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_cert_pem,
            &issuer_ee.public_key(),
            &VerifyPolicy::default(),
        )
        .unwrap();

        let leaf_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Leaf HPKE"),
            issuer: DistinguishedName::new().cn("Issuer EE"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let leaf_pem =
            issue_xhpke_cert_pem(&subject_ee.public_key(), &issuer_ee, &leaf_template).unwrap();

        let result = verify_xhpke_cert_pem_with_issuer_cert(
            &leaf_pem,
            &issuer_cert,
            &VerifyPolicy::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_basic_constraints_pathlen_without_ca() {
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
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19") {
                let bc = BasicConstraints {
                    ca: false,
                    path_len_constraint: Some(0),
                };
                ext.extn_value = OctetString::new(bc.to_der().unwrap()).unwrap();
                break;
            }
        }

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_issuer_cert_enforces_path_len_for_ca_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Issuer"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_pem,
            &issuer_sk.public_key(),
            &VerifyPolicy::default(),
        )
        .unwrap();

        let child_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Child CA"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result = verify_xdsa_cert_pem_with_issuer_cert(
            &child_pem,
            &issuer_cert,
            &VerifyPolicy::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_issuer_cert_allows_path_len_zero_for_ee_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Issuer"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_pem,
            &issuer_sk.public_key(),
            &VerifyPolicy::default(),
        )
        .unwrap();

        let child_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Child EE"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result = verify_xdsa_cert_pem_with_issuer_cert(
            &child_pem,
            &issuer_cert,
            &VerifyPolicy::default(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_with_issuer_cert_rejects_dn_name_mismatch() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Issuer Subject"),
            issuer: DistinguishedName::new().cn("Issuer Subject"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_pem,
            &issuer_sk.public_key(),
            &VerifyPolicy::default(),
        )
        .unwrap();

        let child_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Child EE"),
            issuer: DistinguishedName::new().cn("Fake Issuer Name"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result = verify_xdsa_cert_pem_with_issuer_cert(
            &child_pem,
            &issuer_cert,
            &VerifyPolicy::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_issuer_cert_can_disable_dn_name_chaining() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Issuer Subject"),
            issuer: DistinguishedName::new().cn("Issuer Subject"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_pem,
            &issuer_sk.public_key(),
            &VerifyPolicy::default(),
        )
        .unwrap();

        let child_template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Child EE"),
            issuer: DistinguishedName::new().cn("Fake Issuer Name"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let policy = VerifyPolicy {
            require_name_chaining: false,
            ..Default::default()
        };
        let result = verify_xdsa_cert_pem_with_issuer_cert(&child_pem, &issuer_cert, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_rejects_ca_with_noncritical_basic_constraints() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("CA Subject"),
            issuer: DistinguishedName::new().cn("CA Subject"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19") {
                ext.critical = false;
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_noncritical_key_usage() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("EE Subject"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.critical = false;
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_subject_unique_id() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("EE Subject"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_unique_id = Some(BitString::from_bytes(&[0x01]).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_issuer_unique_id() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("EE Subject"),
            issuer: DistinguishedName::new().cn("Issuer"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertificateProfile::EndEntity,
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.issuer_unique_id = Some(BitString::from_bytes(&[0x01]).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
    }
}
