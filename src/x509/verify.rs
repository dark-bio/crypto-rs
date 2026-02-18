// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::{Certificate, Error, Extension, Name, NameAttribute, Result, Role, ValidityCheck};
use crate::xdsa;
use const_oid::ObjectIdentifier;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::extensions::ParsedExtension;

/// Verifies an xDSA-signed certificate from DER, validates the subject SPKI
/// against `expected_oid`, and returns the raw subject public key bytes along
/// with parsed certificate metadata.
pub(crate) fn verify_cert<const N: usize>(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<([u8; N], Certificate, u16)> {
    // Parse the certificate
    let (rem, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| Error::X509Parse {
        details: e.to_string(),
    })?;
    if !rem.is_empty() {
        return Err(Error::X509Parse {
            details: "trailing data after DER certificate".into(),
        });
    }
    // Validate the content against the provided signer
    let tbs = cert.tbs_certificate.as_ref();
    let sig_bytes: [u8; xdsa::SIGNATURE_SIZE] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::X509Parse {
            details: "invalid signature length".into(),
        })?;
    let sig = xdsa::Signature::from_bytes(&sig_bytes);
    issuer.verify(tbs, &sig)?;

    // Reject pre-Unix timestamps
    let not_before = cert.tbs_certificate.validity.not_before.timestamp();
    let not_after = cert.tbs_certificate.validity.not_after.timestamp();

    if not_before < 0 || not_after < 0 {
        return Err(Error::X509Parse {
            details: "invalid timestamp".into(),
        });
    }
    let not_before = not_before as u64;
    let not_after = not_after as u64;

    // Check time validity if requested
    let check_time = match validity {
        ValidityCheck::Now => Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        ),
        ValidityCheck::At(ts) => Some(ts),
        ValidityCheck::Disabled => None,
    };
    if let Some(now) = check_time
        && (now < not_before || now > not_after)
    {
        return Err(Error::ExpiredCertificate);
    }
    // Extract the embedded public key and certificate parameters
    let key_bytes = subject_public_key_bytes::<N>(&cert)?;
    let (parsed, key_usage) = extract_cert(&cert)?;

    Ok((key_bytes, parsed, key_usage))
}

/// Extracts and length-checks SPKI subjectPublicKey bytes.
fn subject_public_key_bytes<const N: usize>(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<[u8; N]> {
    if cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .unused_bits
        != 0
    {
        return Err(Error::X509Parse {
            details: "non-canonical BIT STRING: subjectPublicKey must have zero unused bits".into(),
        });
    }
    cert.tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::X509Parse {
            details: "invalid subject public key length".into(),
        })
}

/// Extracts parsed certificate parameters while enforcing constraints.
fn extract_cert(cert: &x509_parser::certificate::X509Certificate) -> Result<(Certificate, u16)> {
    let basic_constraints =
        cert.tbs_certificate
            .basic_constraints()
            .map_err(|e| Error::X509Parse {
                details: format!("basicConstraints: {e}"),
            })?;
    let role = match basic_constraints {
        Some(ext) if ext.value.ca => {
            let path_len = convert_path_len(ext.value.path_len_constraint)?;
            Role::Authority { path_len }
        }
        Some(ext) if ext.value.path_len_constraint.is_some() => {
            return Err(Error::InvalidPathLen {
                details: "requires ca=true",
            });
        }
        _ => Role::Leaf,
    };

    let key_usage = cert
        .tbs_certificate
        .key_usage()
        .map_err(|e| Error::X509Parse {
            details: format!("keyUsage: {e}"),
        })?
        .map(|ku| parse_key_usage_flags(ku.value.flags))
        .transpose()?;

    let mut extensions = Vec::new();
    let mut extension_oids = HashSet::new();
    for ext in cert.tbs_certificate.extensions() {
        let oid = ext.oid.to_id_string();
        if !extension_oids.insert(oid.clone()) {
            return Err(Error::DuplicateExtensionOid { oid });
        }

        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(_)
            | ParsedExtension::AuthorityKeyIdentifier(_)
            | ParsedExtension::BasicConstraints(_)
            | ParsedExtension::KeyUsage(_) => {}
            _ => {
                extensions.push(Extension {
                    oid: ObjectIdentifier::new(ext.oid.to_id_string().as_str())?,
                    critical: ext.critical,
                    value: ext.value.to_vec(),
                });
            }
        }
    }

    let key_usage = key_usage.ok_or(Error::X509Parse {
        details: "keyUsage extension is required".into(),
    })?;
    let parsed = Certificate {
        subject: parse_name(&cert.tbs_certificate.subject)?,
        issuer: parse_name(&cert.tbs_certificate.issuer)?,
        not_before: cert.tbs_certificate.validity.not_before.timestamp() as u64, // validated non-negative in verify_cert
        not_after: cert.tbs_certificate.validity.not_after.timestamp() as u64, // validated non-negative in verify_cert
        role,
        extensions,
    };
    Ok((parsed, key_usage))
}

/// Converts parsed pathLenConstraint into storage type used by this module.
pub(super) fn convert_path_len(path_len: Option<u32>) -> Result<Option<u8>> {
    match path_len {
        Some(v) if v > u8::MAX as u32 => Err(Error::InvalidPathLen {
            details: "exceeds u8::MAX",
        }),
        Some(v) => Ok(Some(v as u8)),
        None => Ok(None),
    }
}

fn parse_key_usage_flags(flags: u16) -> Result<u16> {
    const ALL_KNOWN: u16 = (1 << 9) - 1;
    if flags & !ALL_KNOWN != 0 {
        return Err(Error::X509Parse {
            details: "keyUsage: unknown bits set".into(),
        });
    }
    Ok(flags)
}

/// Parses an X.509 name into public metadata format.
fn parse_name(name: &x509_parser::x509::X509Name<'_>) -> Result<Name> {
    let mut attrs = Vec::new();
    for attr in name.iter_attributes() {
        let value = attr
            .as_str()
            .map_err(|_| Error::X509Parse {
                details: "DN attribute value is not valid UTF-8".into(),
            })?
            .to_string();
        attrs.push(NameAttribute {
            oid: ObjectIdentifier::new(attr.attr_type().to_id_string().as_str())?,
            value,
        });
    }
    Ok(Name { attrs })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::x509::issue_cert;
    use crate::x509::name;
    use crate::xdsa;
    #[cfg(feature = "xhpke")]
    use crate::xhpke;
    use const_oid::ObjectIdentifier;
    use der::asn1::{Any, BitString, OctetString, SetOfVec};
    use der::{Encode, Tag};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::certificate::CertificateInner;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

    fn build_xdsa_cert(
        subject: &xdsa::PublicKey,
        issuer: &xdsa::SecretKey,
        template: &Certificate,
    ) -> Result<CertificateInner> {
        let default_ku = match template.role {
            Role::Authority { .. } => KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            Role::Leaf => KeyUsage(KeyUsages::DigitalSignature.into()),
        };
        issue_cert(&subject.to_bytes(), xdsa::OID, default_ku, issuer, template)
    }

    #[cfg(feature = "xhpke")]
    fn build_xhpke_cert(
        subject: &xhpke::PublicKey,
        issuer: &xdsa::SecretKey,
        template: &Certificate,
    ) -> Result<CertificateInner> {
        issue_cert(
            &subject.to_bytes(),
            xhpke::OID,
            KeyUsage(KeyUsages::KeyAgreement.into()),
            issuer,
            template,
        )
    }

    /// Verifies that an xDSA certificate is rejected when verified against the wrong issuer key.
    #[test]
    fn test_verify_xdsa_rejects_wrong_signer() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let wrong = xdsa::SecretKey::generate();

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
            ..Default::default()
        };

        let pem = xdsa::issue_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = xdsa::verify_cert_pem(&pem, &wrong.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xHPKE certificate is rejected when verified against the wrong issuer key.
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

        let template = Certificate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };

        let pem = xhpke::issue_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = xhpke::verify_cert_pem(&pem, &wrong.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xHPKE certificate with CA role is rejected (xHPKE must be end-entity).
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_ca_certificate() {
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

        // Build a malformed xHPKE CA certificate via internal helper to ensure
        // verification enforces the end-entity invariant.
        let der = build_xhpke_cert(&subject.public_key(), &issuer, &template)
            .unwrap()
            .to_der()
            .unwrap();
        let result = xhpke::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a PEM block with a non-CERTIFICATE label is rejected.
    #[test]
    fn test_verify_rejects_non_certificate_pem_label() {
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
            ..Default::default()
        };

        let pem = xdsa::issue_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let pem = pem.replace("CERTIFICATE", "PRIVATE KEY");

        let result = xdsa::verify_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that trailing bytes after DER-encoded certificate data are rejected.
    #[test]
    fn test_verify_rejects_trailing_der_data() {
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
            ..Default::default()
        };

        let mut der = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        der.extend_from_slice(&[0xde, 0xad]);
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that trailing data after a PEM certificate block is rejected.
    #[test]
    fn test_verify_rejects_trailing_pem_data() {
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
            ..Default::default()
        };

        let mut pem = xdsa::issue_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        pem.push_str("TRAILING");
        let result = xdsa::verify_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that pathLenConstraint values exceeding u8::MAX are rejected.
    #[test]
    fn test_convert_path_len_rejects_large_values() {
        assert!(convert_path_len(Some(256)).is_err());
        assert_eq!(convert_path_len(Some(255)).unwrap(), Some(255));
        assert_eq!(convert_path_len(None).unwrap(), None);
    }

    /// Verifies that a not-yet-valid certificate is rejected by time policy.
    #[test]
    fn test_verify_rejects_future_cert_by_time_policy() {
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
            not_after: now + 7200,
            role: Role::Leaf,
            ..Default::default()
        };

        let der = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::At(now));
        assert!(result.is_err());
    }

    /// Verifies that a valid certificate passes with time validation disabled.
    #[test]
    fn test_verify_allows_valid_cert_without_time_policy() {
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
            ..Default::default()
        };

        let der = xdsa::issue_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Disabled);
        assert!(result.is_ok());
    }

    /// Verifies that an xDSA end-entity certificate with keyAgreement usage is rejected.
    #[test]
    fn test_verify_xdsa_ee_rejects_key_agreement_usage() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong_ku = KeyUsage(KeyUsages::KeyAgreement.into());
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(wrong_ku.to_der().unwrap()).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xHPKE certificate with digitalSignature usage is rejected.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_rejects_digital_signature_usage() {
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
            role: Role::Leaf,
            ..Default::default()
        };

        let mut cert = build_xhpke_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong_ku = KeyUsage(KeyUsages::DigitalSignature.into());
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(wrong_ku.to_der().unwrap()).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xhpke::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xDSA end-entity certificate with extra key usage flags is accepted
    /// as long as the required bits are set.
    #[test]
    fn test_verify_xdsa_ee_accepts_extra_key_usage_flags() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let mixed_ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign);
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(mixed_ku.to_der().unwrap()).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that a certificate without basicConstraints is parsed as end-entity.
    #[test]
    fn test_verify_parses_missing_basic_constraints_as_end_entity() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|ext| ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.19"));

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let parsed = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert!(matches!(parsed.cert.role, Role::Leaf));
    }

    /// Verifies that an xDSA CA certificate with wrong key usage is rejected.
    #[test]
    fn test_verify_rejects_xdsa_ca_wrong_key_usage() {
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
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong_ku = KeyUsage(KeyUsages::DigitalSignature.into());
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(wrong_ku.to_der().unwrap()).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with non-UTF-8 subject attribute values is rejected.
    #[test]
    fn test_verify_rejects_binary_subject_attribute_values() {
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
            ..Default::default()
        };
        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();

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
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining rejects a non-CA issuer certificate.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_with_issuer_rejects_non_ca_issuer() {
        let issuer_ee = xdsa::SecretKey::generate();
        let subject_ee = xhpke::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer EE"),
            issuer: Name::new().cn("Issuer EE"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let issuer_cert_pem =
            xdsa::issue_cert_pem(&issuer_ee.public_key(), &issuer_ee, &issuer_template).unwrap();
        let issuer_cert = xdsa::verify_cert_pem(
            &issuer_cert_pem,
            &issuer_ee.public_key(),
            ValidityCheck::Now,
        )
        .unwrap();

        let leaf_template = Certificate {
            subject: Name::new().cn("Leaf HPKE"),
            issuer: Name::new().cn("Issuer EE"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let leaf_pem =
            xhpke::issue_cert_pem(&subject_ee.public_key(), &issuer_ee, &leaf_template).unwrap();

        let result =
            xhpke::verify_cert_pem_with_issuer(&leaf_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that pathLenConstraint without ca=true is rejected.
    #[test]
    fn test_verify_rejects_basic_constraints_pathlen_without_ca() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
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
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining rejects a CA child when pathLenConstraint is 0.
    #[test]
    fn test_verify_with_issuer_enforces_path_len_for_ca_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            xdsa::issue_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            xdsa::verify_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now)
                .unwrap();

        let child_template = Certificate {
            subject: Name::new().cn("Child CA"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let child_pem =
            xdsa::issue_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            xdsa::verify_cert_pem_with_issuer(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining allows an end-entity child when pathLenConstraint is 0.
    #[test]
    fn test_verify_with_issuer_allows_path_len_zero_for_ee_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            xdsa::issue_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            xdsa::verify_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now)
                .unwrap();

        let child_template = Certificate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let child_pem =
            xdsa::issue_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            xdsa::verify_cert_pem_with_issuer(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that issuer-cert chaining rejects a DN name mismatch.
    #[test]
    fn test_verify_with_issuer_rejects_dn_name_mismatch() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer Subject"),
            issuer: Name::new().cn("Issuer Subject"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            xdsa::issue_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            xdsa::verify_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now)
                .unwrap();

        let child_template = Certificate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Fake Issuer Name"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let child_pem =
            xdsa::issue_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            xdsa::verify_cert_pem_with_issuer(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that xdsa::verify_cert_der_with_issuer works for the DER path.
    #[test]
    fn test_verify_xdsa_der_with_issuer() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: None },
            ..Default::default()
        };
        let issuer_der =
            xdsa::issue_cert_der(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            xdsa::verify_cert_der(&issuer_der, &issuer_sk.public_key(), ValidityCheck::Now)
                .unwrap();

        let child_template = Certificate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let child_der =
            xdsa::issue_cert_der(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            xdsa::verify_cert_der_with_issuer(&child_der, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that xhpke::verify_cert_der_with_issuer works for the DER path.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_der_with_issuer() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xhpke::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = Certificate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Authority { path_len: None },
            ..Default::default()
        };
        let issuer_der =
            xdsa::issue_cert_der(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            xdsa::verify_cert_der(&issuer_der, &issuer_sk.public_key(), ValidityCheck::Now)
                .unwrap();

        let child_template = Certificate {
            subject: Name::new().cn("Child HPKE"),
            issuer: Name::new().cn("Issuer"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            ..Default::default()
        };
        let child_der =
            xhpke::issue_cert_der(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            xhpke::verify_cert_der_with_issuer(&child_der, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that a certificate with unknown key usage bits set is rejected.
    #[test]
    fn test_verify_rejects_unknown_key_usage_bits() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        // Set bit 9 (outside the 9 known KeyUsage bits 0..8).
        // DER BIT STRING: 03 04 06 00 02 00 (4 content bytes, 6 unused bits, bit 9 set).
        let raw_ku = vec![0x03, 0x04, 0x06, 0x00, 0x02, 0x00];
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(raw_ku).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with a duplicated standard extension OID is rejected.
    #[test]
    fn test_verify_rejects_duplicate_standard_extension_oid() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let duplicate = cert.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(duplicate);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with duplicated custom (non-critical, unknown)
    /// extension OIDs is rejected by our own check, not by x509-parser.
    #[test]
    fn test_verify_rejects_duplicate_custom_extension_oid() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let custom_oid = ObjectIdentifier::new("1.3.6.1.4.1.62253.7.7").unwrap();
        let template = Certificate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            not_before: now,
            not_after: now + 3600,
            role: Role::Leaf,
            extensions: vec![Extension {
                oid: custom_oid,
                critical: false,
                value: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        // Append a second extension with the same custom OID.
        let duplicate = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(duplicate);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a subjectPublicKey BIT STRING with non-zero unused bits is rejected.
    #[test]
    fn test_verify_rejects_spki_nonzero_unused_bits() {
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
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        // Rebuild with a non-zero unused-bits byte in the SPKI public key BIT STRING.
        let pk_bytes = subject.public_key().to_bytes();
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(1, &pk_bytes).unwrap();

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = xdsa::verify_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }
}
