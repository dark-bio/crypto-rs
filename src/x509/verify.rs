// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::utils::key_identifier;
use super::{
    CertificateMetadata, CertificateRole, CustomExtension, Error, Name, NameAttribute, Result,
    ValidityCheck, ValidityWindow, VerifiedCertificate,
};
#[cfg(feature = "xhpke")]
use crate::xhpke;
use crate::{pem, xdsa};
use const_oid::ObjectIdentifier;
use std::collections::HashSet;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
use x509_parser::extensions::ParsedExtension;

/// Verifies an xDSA cert from DER and returns key + metadata.
///
/// Enforces signature validity, SKI/AKI bindings, and xDSA
/// key usage/role constraints.
pub fn verify_xdsa_cert_der(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xdsa::PublicKey>> {
    let cert = parse_and_verify_cert(der, issuer, validity)?;
    validate_subject_public_key_algorithm(&cert, xdsa::OID, "xDSA")?;
    let key_bytes = subject_public_key_bytes::<{ xdsa::PUBLIC_KEY_SIZE }>(&cert)?;

    let meta = extract_meta(&cert)?;
    validate_key_identifier_bindings(&meta, &key_bytes, &issuer.to_bytes())?;
    validate_key_usage_for_xdsa(&meta)?;

    Ok(VerifiedCertificate {
        public_key: xdsa::PublicKey::from_bytes(&key_bytes)?,
        meta,
    })
}

/// Verifies an xDSA cert from PEM and returns key + metadata.
///
/// Requires a single `CERTIFICATE` PEM block with no trailing data.
pub fn verify_xdsa_cert_pem(
    pem_data: &str,
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xdsa::PublicKey>> {
    let der = decode_certificate_pem(pem_data)?;
    verify_xdsa_cert_der(&der, issuer, validity)
}

/// Verifies an xDSA cert from DER using an issuer certificate and enforces
/// issuer authorization for chaining (CA role + CA key usage).
pub fn verify_xdsa_cert_der_with_issuer_cert(
    der: &[u8],
    issuer_cert: &VerifiedCertificate<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xdsa::PublicKey>> {
    let cert = verify_xdsa_cert_der(der, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(cert, issuer_cert)
}

/// Verifies an xDSA cert from PEM using an issuer certificate and enforces
/// issuer authorization for chaining (CA role + CA key usage).
pub fn verify_xdsa_cert_pem_with_issuer_cert(
    pem_data: &str,
    issuer_cert: &VerifiedCertificate<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xdsa::PublicKey>> {
    let cert = verify_xdsa_cert_pem(pem_data, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(cert, issuer_cert)
}

/// Verifies an xHPKE cert from DER and returns key + metadata.
///
/// Enforces signature validity, SKI/AKI bindings, and xHPKE
/// end-entity key usage/role constraints.
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_der(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xhpke::PublicKey>> {
    let cert = parse_and_verify_cert(der, issuer, validity)?;
    validate_subject_public_key_algorithm(&cert, xhpke::OID, "xHPKE (X-Wing)")?;
    let key_bytes = subject_public_key_bytes::<{ xhpke::PUBLIC_KEY_SIZE }>(&cert)?;

    let meta = extract_meta(&cert)?;
    if matches!(meta.role, CertificateRole::Authority { .. }) {
        return Err(Error::XhpkeMustBeEndEntity);
    }
    validate_key_identifier_bindings(&meta, &key_bytes, &issuer.to_bytes())?;
    validate_key_usage_for_xhpke(&meta)?;

    Ok(VerifiedCertificate {
        public_key: xhpke::PublicKey::from_bytes(&key_bytes)?,
        meta,
    })
}

/// Verifies an xHPKE cert from PEM and returns key + metadata.
///
/// Requires a single `CERTIFICATE` PEM block with no trailing data.
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_pem(
    pem_data: &str,
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xhpke::PublicKey>> {
    let der = decode_certificate_pem(pem_data)?;
    verify_xhpke_cert_der(&der, issuer, validity)
}

/// Verifies an xHPKE cert from DER using an issuer certificate and enforces
/// issuer authorization for chaining (CA role + CA key usage).
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_der_with_issuer_cert(
    der: &[u8],
    issuer_cert: &VerifiedCertificate<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xhpke::PublicKey>> {
    let cert = verify_xhpke_cert_der(der, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(cert, issuer_cert)
}

/// Verifies an xHPKE cert from PEM using an issuer certificate and enforces
/// issuer authorization for chaining (CA role + CA key usage).
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_pem_with_issuer_cert(
    pem_data: &str,
    issuer_cert: &VerifiedCertificate<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> Result<VerifiedCertificate<xhpke::PublicKey>> {
    let cert = verify_xhpke_cert_pem(pem_data, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(cert, issuer_cert)
}

fn decode_certificate_pem(pem_data: &str) -> Result<Vec<u8>> {
    let (label, der) = pem::decode(pem_data.as_bytes())?;
    if label != "CERTIFICATE" {
        return Err(Error::InvalidPemLabel);
    }
    Ok(der)
}

/// Shared parsing/validation prelude for DER verification paths.
fn parse_and_verify_cert<'a>(
    der: &'a [u8],
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<x509_parser::certificate::X509Certificate<'a>> {
    let (rem, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| Error::X509Parse {
        details: e.to_string(),
    })?;
    ensure_no_trailing_der(rem)?;
    verify_signature_and_validity(&cert, issuer, validity)?;
    Ok(cert)
}

/// Enforces expected SPKI algorithm OID and parameter absence.
fn validate_subject_public_key_algorithm(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    expected_oid: ObjectIdentifier,
    algorithm_name: &'static str,
) -> Result<()> {
    if cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string()
        != expected_oid.to_string()
    {
        return Err(Error::InvalidSubjectAlgorithm {
            details: format!("expected {algorithm_name}"),
        });
    }
    if cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .parameters
        .is_some()
    {
        return Err(Error::InvalidSubjectAlgorithm {
            details: format!("{algorithm_name} parameters must be absent"),
        });
    }
    Ok(())
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
        return Err(Error::NonCanonicalBitString {
            details: "subjectPublicKey must have zero unused bits",
        });
    }
    cert.tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidSubjectPublicKeyLength)
}

/// Applies issuer-certificate chaining checks after leaf verification.
fn enforce_issuer_chaining<K>(
    cert: VerifiedCertificate<K>,
    issuer_cert: &VerifiedCertificate<xdsa::PublicKey>,
) -> Result<VerifiedCertificate<K>> {
    validate_issuer_authority(&issuer_cert.meta, &cert.meta.role)?;
    validate_name_chaining(&cert.meta, &issuer_cert.meta)?;
    Ok(cert)
}

/// Performs signature-level and validity-window checks.
fn verify_signature_and_validity(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> Result<()> {
    if cert.tbs_certificate.version != x509_parser::x509::X509Version::V3 {
        return Err(Error::UnsupportedCertificateVersion);
    }

    let not_before = unix_ts_to_u64(cert.tbs_certificate.validity.not_before.timestamp())?;
    let not_after = unix_ts_to_u64(cert.tbs_certificate.validity.not_after.timestamp())?;
    if not_before >= not_after {
        return Err(Error::InvalidValidityWindow);
    }

    // Signature algorithm must match both at certificate and TBSCertificate level.
    let outer_sig_alg = cert.signature_algorithm.algorithm.to_id_string();
    let tbs_sig_alg = cert.tbs_certificate.signature.algorithm.to_id_string();
    let expected_sig_alg = xdsa::OID.to_string();
    if outer_sig_alg != expected_sig_alg || tbs_sig_alg != expected_sig_alg {
        return Err(Error::InvalidSignatureAlgorithm {
            details: "expected xDSA",
        });
    }
    if cert.signature_algorithm.parameters.is_some()
        || cert.tbs_certificate.signature.parameters.is_some()
    {
        return Err(Error::InvalidSignatureAlgorithm {
            details: "parameters must be absent",
        });
    }
    if cert.tbs_certificate.issuer_uid.is_some() || cert.tbs_certificate.subject_uid.is_some() {
        return Err(Error::UniqueIdsNotAllowed);
    }

    // x509-parser exposes a borrowed TBSCertificate byte view suitable for verify().
    let tbs = cert.tbs_certificate.as_ref();
    if cert.signature_value.unused_bits != 0 {
        return Err(Error::NonCanonicalBitString {
            details: "signatureValue must have zero unused bits",
        });
    }
    let sig_bytes: [u8; xdsa::SIGNATURE_SIZE] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidSignatureLength)?;
    let sig = xdsa::Signature::from_bytes(&sig_bytes);
    issuer.verify(tbs, &sig)?;

    if let Some(now) = validity.timestamp()
        && (now < not_before || now > not_after)
    {
        return Err(Error::InvalidAtRequestedTime);
    }
    Ok(())
}

/// Extracts parsed metadata while enforcing criticality constraints.
fn extract_meta(cert: &x509_parser::certificate::X509Certificate) -> Result<CertificateMetadata> {
    let serial = cert.tbs_certificate.raw_serial();
    validate_serial_encoding(serial)?;

    let basic_constraints =
        cert.tbs_certificate
            .basic_constraints()
            .map_err(|e| Error::ExtensionParseFailed {
                details: format!("basicConstraints: {e}"),
            })?;
    let role = match basic_constraints {
        Some(ext) if ext.value.ca => {
            let path_len = convert_path_len(ext.value.path_len_constraint)?;
            CertificateRole::Authority { path_len }
        }
        Some(ext) if ext.value.path_len_constraint.is_some() => {
            return Err(Error::InvalidPathLen {
                details: "requires ca=true",
            });
        }
        _ => CertificateRole::Leaf,
    };

    let key_usage = cert
        .tbs_certificate
        .key_usage()
        .map_err(|e| Error::ExtensionParseFailed {
            details: format!("keyUsage: {e}"),
        })?
        .map(|ku| parse_key_usage_flags(ku.value.flags))
        .transpose()?;

    let mut subject_key_id = None;
    let mut authority_key_id = None;
    let mut extensions = Vec::new();
    let mut extension_oids = HashSet::new();
    let mut basic_constraints_critical = None;
    let mut key_usage_critical = None;
    for ext in cert.tbs_certificate.extensions() {
        let oid = ext.oid.to_id_string();
        if !extension_oids.insert(oid.clone()) {
            return Err(Error::DuplicateCertificateExtension { oid });
        }

        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(keyid) => {
                subject_key_id = Some(keyid.0.to_vec());
            }
            ParsedExtension::AuthorityKeyIdentifier(akid) => {
                authority_key_id = akid.key_identifier.as_ref().map(|kid| kid.0.to_vec());
            }
            ParsedExtension::BasicConstraints(_) => {
                basic_constraints_critical = Some(ext.critical);
            }
            ParsedExtension::KeyUsage(_) => {
                key_usage_critical = Some(ext.critical);
            }
            ParsedExtension::ExtendedKeyUsage(_) => {
                return Err(Error::ExtendedKeyUsageNotAllowed);
            }
            _ => {
                // Unknown critical extensions must hard-fail per RFC 5280.
                if ext.critical {
                    return Err(Error::UnknownCriticalExtension {
                        oid: ext.oid.to_id_string(),
                    });
                }
                extensions.push(CustomExtension {
                    oid: ObjectIdentifier::new(ext.oid.to_id_string().as_str())?,
                    critical: ext.critical,
                    value: ext.value.to_vec(),
                });
            }
        }
    }

    if matches!(role, CertificateRole::Authority { .. }) && basic_constraints_critical != Some(true)
    {
        return Err(Error::ExtensionMustBeCritical {
            extension: "basicConstraints",
        });
    }
    if key_usage_critical != Some(true) {
        return Err(Error::ExtensionMustBeCritical {
            extension: "keyUsage",
        });
    }

    Ok(CertificateMetadata {
        serial: serial.to_vec(),
        subject: parse_name(&cert.tbs_certificate.subject)?,
        issuer: parse_name(&cert.tbs_certificate.issuer)?,
        validity: ValidityWindow {
            not_before: unix_ts_to_u64(cert.tbs_certificate.validity.not_before.timestamp())?,
            not_after: unix_ts_to_u64(cert.tbs_certificate.validity.not_after.timestamp())?,
        },
        role,
        key_usage: key_usage.ok_or(Error::ExtensionParseFailed {
            details: "keyUsage extension is required".to_string(),
        })?,
        subject_key_id: subject_key_id.ok_or(Error::InvalidKeyIdentifier {
            details: "missing subjectKeyIdentifier",
        })?,
        authority_key_id: authority_key_id.ok_or(Error::InvalidKeyIdentifier {
            details: "missing authorityKeyIdentifier",
        })?,
        extensions,
    })
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

/// Converts parsed timestamp to `u64`, rejecting pre-UNIX values.
pub(super) fn unix_ts_to_u64(ts: i64) -> Result<u64> {
    u64::try_from(ts).map_err(|_| Error::PreUnixTimestamp)
}

/// Validates DER INTEGER canonicality constraints for serial numbers.
pub(super) fn validate_serial_encoding(serial: &[u8]) -> Result<()> {
    if serial.is_empty() {
        return Err(Error::InvalidSerial {
            details: "must not be empty",
        });
    }
    if serial[0] & 0x80 != 0 {
        return Err(Error::InvalidSerial {
            details: "must be positive",
        });
    }
    if serial.len() > 1 && serial[0] == 0x00 && serial[1] & 0x80 == 0 {
        return Err(Error::InvalidSerial {
            details: "non-canonical DER INTEGER encoding",
        });
    }
    if serial.iter().all(|b| *b == 0) {
        return Err(Error::InvalidSerial {
            details: "must be non-zero",
        });
    }
    Ok(())
}

fn ensure_no_trailing_der(rem: &[u8]) -> Result<()> {
    if !rem.is_empty() {
        return Err(Error::TrailingDerData);
    }
    Ok(())
}

fn parse_key_usage_flags(flags: u16) -> Result<KeyUsage> {
    const ALL_KNOWN_BITS: u16 = (1 << 9) - 1;
    if flags & !ALL_KNOWN_BITS != 0 {
        return Err(Error::ExtensionParseFailed {
            details: "keyUsage: unknown bits set".to_string(),
        });
    }
    let mut parsed = der::flagset::FlagSet::<KeyUsages>::default();
    if flags & (1 << 0) != 0 {
        parsed |= KeyUsages::DigitalSignature;
    }
    if flags & (1 << 1) != 0 {
        parsed |= KeyUsages::NonRepudiation;
    }
    if flags & (1 << 2) != 0 {
        parsed |= KeyUsages::KeyEncipherment;
    }
    if flags & (1 << 3) != 0 {
        parsed |= KeyUsages::DataEncipherment;
    }
    if flags & (1 << 4) != 0 {
        parsed |= KeyUsages::KeyAgreement;
    }
    if flags & (1 << 5) != 0 {
        parsed |= KeyUsages::KeyCertSign;
    }
    if flags & (1 << 6) != 0 {
        parsed |= KeyUsages::CRLSign;
    }
    if flags & (1 << 7) != 0 {
        parsed |= KeyUsages::EncipherOnly;
    }
    if flags & (1 << 8) != 0 {
        parsed |= KeyUsages::DecipherOnly;
    }
    Ok(KeyUsage(parsed))
}

/// Verifies SKI/AKI presence and key-binding matches.
fn validate_key_identifier_bindings(
    meta: &CertificateMetadata,
    subject_public_key: &[u8],
    issuer_public_key: &[u8],
) -> Result<()> {
    let expected_ski = key_identifier(subject_public_key);
    if meta.subject_key_id != expected_ski {
        return Err(Error::InvalidKeyIdentifier {
            details: "SKI does not match subject public key",
        });
    }
    let expected_aki = key_identifier(issuer_public_key);
    if meta.authority_key_id != expected_aki {
        return Err(Error::InvalidKeyIdentifier {
            details: "AKI does not match issuer public key",
        });
    }
    Ok(())
}

/// Enforces strict keyUsage profile for xDSA certificates.
fn validate_key_usage_for_xdsa(meta: &CertificateMetadata) -> Result<()> {
    let ca_usage = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
    let ee_usage: der::flagset::FlagSet<KeyUsages> = KeyUsages::DigitalSignature.into();
    match meta.role {
        CertificateRole::Authority { .. } => {
            if meta.key_usage.0 != ca_usage {
                return Err(Error::InvalidKeyUsage {
                    details: "xDSA CA requires keyCertSign|cRLSign",
                });
            }
        }
        CertificateRole::Leaf => {
            if meta.key_usage.0 != ee_usage {
                return Err(Error::InvalidKeyUsage {
                    details: "xDSA end-entity requires digitalSignature",
                });
            }
        }
    }
    Ok(())
}

/// Ensures an issuer cert is allowed to issue the target child role.
fn validate_issuer_authority(
    meta: &CertificateMetadata,
    child_role: &CertificateRole,
) -> Result<()> {
    let path_len = match &meta.role {
        CertificateRole::Authority { path_len } => path_len,
        CertificateRole::Leaf => {
            return Err(Error::InvalidIssuer {
                details: "not a CA",
            });
        }
    };
    if meta.key_usage.0 != (KeyUsages::KeyCertSign | KeyUsages::CRLSign) {
        return Err(Error::InvalidKeyUsage {
            details: "issuer requires keyCertSign|cRLSign",
        });
    }
    if matches!(child_role, CertificateRole::Authority { .. }) && *path_len == Some(0) {
        return Err(Error::InvalidIssuer {
            details: "pathLenConstraint forbids CA certificates",
        });
    }
    Ok(())
}

/// Enforces issuer/subject DN chaining.
fn validate_name_chaining(child: &CertificateMetadata, issuer: &CertificateMetadata) -> Result<()> {
    if child.issuer != issuer.subject {
        return Err(Error::InvalidIssuer {
            details: "issuer DN does not match",
        });
    }
    Ok(())
}

#[cfg(feature = "xhpke")]
/// Enforces strict keyUsage profile for xHPKE certificates.
fn validate_key_usage_for_xhpke(meta: &CertificateMetadata) -> Result<()> {
    let ee_usage: der::flagset::FlagSet<KeyUsages> = KeyUsages::KeyAgreement.into();
    if meta.key_usage.0 != ee_usage {
        return Err(Error::InvalidKeyUsage {
            details: "xHPKE requires keyAgreement",
        });
    }
    Ok(())
}

/// Parses an X.509 name into public metadata format.
fn parse_name(name: &x509_parser::x509::X509Name<'_>) -> Result<Name> {
    let mut attrs = Vec::new();
    for attr in name.iter_attributes() {
        let value = attr
            .as_str()
            .map_err(|_| Error::NonUtf8DnAttribute)?
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
    use crate::x509::issue::{issue_cert, issue_xdsa_cert_der, issue_xdsa_cert_pem};
    #[cfg(feature = "xhpke")]
    use crate::x509::issue::{issue_xhpke_cert_der, issue_xhpke_cert_pem};
    use crate::x509::{CertificateTemplate, name, private_enterprise_oid};
    use crate::xdsa;
    #[cfg(feature = "xhpke")]
    use crate::xhpke;
    use der::asn1::{Any, BitString, OctetString, SetOfVec};
    use der::{Encode, Tag};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::certificate::{CertificateInner, Version};
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

    fn build_xdsa_cert(
        subject: &xdsa::PublicKey,
        issuer: &xdsa::SecretKey,
        template: &CertificateTemplate,
    ) -> Result<CertificateInner> {
        let default_ku = match template.role {
            CertificateRole::Authority { .. } => {
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            }
            CertificateRole::Leaf => KeyUsage(KeyUsages::DigitalSignature.into()),
        };
        issue_cert(&subject.to_bytes(), xdsa::OID, default_ku, issuer, template)
    }

    #[cfg(feature = "xhpke")]
    fn build_xhpke_cert(
        subject: &xhpke::PublicKey,
        issuer: &xdsa::SecretKey,
        template: &CertificateTemplate,
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &wrong.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let pem = issue_xhpke_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xhpke_cert_pem(&pem, &wrong.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };

        // Build a malformed xHPKE CA certificate via internal helper to ensure
        // verification enforces the end-entity invariant.
        let der = build_xhpke_cert(&subject.public_key(), &issuer, &template)
            .unwrap()
            .to_der()
            .unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with an unrecognized critical extension is rejected.
    #[test]
    fn test_verify_rejects_unrecognized_critical_extension() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            extensions: vec![CustomExtension {
                oid: private_enterprise_oid(62253, &[9, 9]).unwrap(),
                critical: true,
                value: vec![0x05, 0x00],
            }],
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a non-v3 certificate is rejected.
    #[test]
    fn test_verify_rejects_non_v3_certificate() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.version = Version::V1;
        cert.tbs_certificate.extensions = None;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let pem = pem.replace("CERTIFICATE", "PRIVATE KEY");

        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        der.extend_from_slice(&[0xde, 0xad]);
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        pem.push_str("TRAILING");
        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with signature algorithm parameters is rejected.
    #[test]
    fn test_verify_rejects_signature_algorithm_parameters() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.signature.parameters =
            Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());
        cert.signature_algorithm.parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with equal not_before and not_after is rejected even with time validation disabled.
    #[test]
    fn test_verify_rejects_malformed_validity_without_time_policy() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.validity.not_after = cert.tbs_certificate.validity.not_before;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Disabled);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with a tampered SubjectKeyIdentifier is rejected.
    #[test]
    fn test_verify_rejects_ski_mismatch() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that pathLenConstraint values exceeding u8::MAX are rejected.
    #[test]
    fn test_convert_path_len_rejects_large_values() {
        assert!(convert_path_len(Some(256)).is_err());
        assert_eq!(convert_path_len(Some(255)).unwrap(), Some(255));
        assert_eq!(convert_path_len(None).unwrap(), None);
    }

    /// Verifies that negative timestamps are rejected.
    #[test]
    fn test_unix_ts_to_u64_rejects_negative_values() {
        assert!(unix_ts_to_u64(-1).is_err());
        assert_eq!(unix_ts_to_u64(0).unwrap(), 0);
    }

    /// Verifies that non-canonical DER INTEGER serial encodings are rejected.
    #[test]
    fn test_validate_serial_encoding_rejects_noncanonical_values() {
        assert!(validate_serial_encoding(&[]).is_err());
        assert!(validate_serial_encoding(&[0x80]).is_err());
        assert!(validate_serial_encoding(&[0x00, 0x01]).is_err());
        assert!(validate_serial_encoding(&[0x00]).is_err());
        assert!(validate_serial_encoding(&[0x01]).is_ok());
        assert!(validate_serial_encoding(&[0x7f]).is_ok());
    }

    /// Verifies that an xDSA certificate with a wrong SPKI algorithm OID is rejected.
    #[test]
    fn test_verify_rejects_xdsa_subject_algorithm_mismatch() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid =
            ObjectIdentifier::new_unwrap("1.2.3.4");

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xDSA certificate with SPKI algorithm parameters is rejected.
    #[test]
    fn test_verify_rejects_xdsa_spki_parameters() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with a non-xDSA signature algorithm OID is rejected.
    #[test]
    fn test_verify_rejects_signature_algorithm_oid_mismatch() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong = ObjectIdentifier::new_unwrap("1.2.3.4");
        cert.tbs_certificate.signature.oid = wrong;
        cert.signature_algorithm.oid = wrong;

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now + 3600,
                not_after: now + 7200,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::At(now));
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Disabled);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Alice Identity"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xDSA end-entity certificate with mixed key usage flags is rejected.
    #[test]
    fn test_verify_xdsa_ee_rejects_mixed_key_usage_flags() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        let wrong_ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign);
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.extn_value = OctetString::new(wrong_ku.to_der().unwrap()).unwrap();
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let parsed = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now).unwrap();
        assert!(matches!(parsed.meta.role, CertificateRole::Leaf));
    }

    /// Verifies that a certificate with a tampered AuthorityKeyIdentifier is rejected.
    #[test]
    fn test_verify_rejects_aki_mismatch() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xHPKE certificate with a wrong SPKI algorithm OID is rejected.
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
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let mut cert = build_xhpke_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_public_key_info.algorithm.oid =
            ObjectIdentifier::new_unwrap("1.2.3.4");

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that an xHPKE certificate with SPKI algorithm parameters is rejected.
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
            subject: Name::new().cn("Alice Encryption"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let mut cert = build_xhpke_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xhpke_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining rejects a non-CA issuer certificate.
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
            subject: Name::new().cn("Issuer EE"),
            issuer: Name::new().cn("Issuer EE"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let issuer_cert_pem =
            issue_xdsa_cert_pem(&issuer_ee.public_key(), &issuer_ee, &issuer_template).unwrap();
        let issuer_cert = verify_xdsa_cert_pem(
            &issuer_cert_pem,
            &issuer_ee.public_key(),
            ValidityCheck::Now,
        )
        .unwrap();

        let leaf_template = CertificateTemplate {
            subject: Name::new().cn("Leaf HPKE"),
            issuer: Name::new().cn("Issuer EE"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let leaf_pem =
            issue_xhpke_cert_pem(&subject_ee.public_key(), &issuer_ee, &leaf_template).unwrap();

        let result =
            verify_xhpke_cert_pem_with_issuer_cert(&leaf_pem, &issuer_cert, ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining rejects a CA child when pathLenConstraint is 0.
    #[test]
    fn test_verify_with_issuer_cert_enforces_path_len_for_ca_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            verify_xdsa_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child CA"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xdsa_cert_pem_with_issuer_cert(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that issuer-cert chaining allows an end-entity child when pathLenConstraint is 0.
    #[test]
    fn test_verify_with_issuer_cert_allows_path_len_zero_for_ee_child() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            verify_xdsa_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xdsa_cert_pem_with_issuer_cert(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that issuer-cert chaining rejects a DN name mismatch.
    #[test]
    fn test_verify_with_issuer_cert_rejects_dn_name_mismatch() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer Subject"),
            issuer: Name::new().cn("Issuer Subject"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };
        let issuer_pem =
            issue_xdsa_cert_pem(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            verify_xdsa_cert_pem(&issuer_pem, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Fake Issuer Name"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xdsa_cert_pem_with_issuer_cert(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a CA certificate with non-critical basicConstraints is rejected.
    #[test]
    fn test_verify_rejects_ca_with_noncritical_basic_constraints() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("CA Subject"),
            issuer: Name::new().cn("CA Subject"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: Some(0) },
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19") {
                ext.critical = false;
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with non-critical keyUsage is rejected.
    #[test]
    fn test_verify_rejects_noncritical_key_usage() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("EE Subject"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
            if ext.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15") {
                ext.critical = false;
                break;
            }
        }
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with subjectUniqueID is rejected.
    #[test]
    fn test_verify_rejects_subject_unique_id() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("EE Subject"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.subject_unique_id = Some(BitString::from_bytes(&[0x01]).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate with issuerUniqueID is rejected.
    #[test]
    fn test_verify_rejects_issuer_unique_id() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("EE Subject"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.issuer_unique_id = Some(BitString::from_bytes(&[0x01]).unwrap());

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that verify_xdsa_cert_der_with_issuer_cert works for the DER path.
    #[test]
    fn test_verify_xdsa_der_with_issuer_cert() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: None },
            ..Default::default()
        };
        let issuer_der =
            issue_xdsa_cert_der(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            verify_xdsa_cert_der(&issuer_der, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let child_der =
            issue_xdsa_cert_der(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xdsa_cert_der_with_issuer_cert(&child_der, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that verify_xhpke_cert_der_with_issuer_cert works for the DER path.
    #[test]
    #[cfg(feature = "xhpke")]
    fn test_verify_xhpke_der_with_issuer_cert() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xhpke::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: None },
            ..Default::default()
        };
        let issuer_der =
            issue_xdsa_cert_der(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let issuer_cert =
            verify_xdsa_cert_der(&issuer_der, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child HPKE"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let child_der =
            issue_xhpke_cert_der(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xhpke_cert_der_with_issuer_cert(&child_der, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_ok());
    }

    /// Verifies that issuer-cert chaining rejects an issuer with wrong key usage.
    #[test]
    fn test_verify_with_issuer_cert_rejects_issuer_wrong_key_usage() {
        let issuer_sk = xdsa::SecretKey::generate();
        let child_sk = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let issuer_template = CertificateTemplate {
            subject: Name::new().cn("Issuer"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Authority { path_len: None },
            ..Default::default()
        };
        let issuer_der =
            issue_xdsa_cert_der(&issuer_sk.public_key(), &issuer_sk, &issuer_template).unwrap();
        let mut issuer_cert =
            verify_xdsa_cert_der(&issuer_der, &issuer_sk.public_key(), ValidityCheck::Now).unwrap();

        // Tamper: swap the issuer's key usage to digitalSignature only.
        issuer_cert.meta.key_usage = KeyUsage(KeyUsages::DigitalSignature.into());

        let child_template = CertificateTemplate {
            subject: Name::new().cn("Child EE"),
            issuer: Name::new().cn("Issuer"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };
        let child_pem =
            issue_xdsa_cert_pem(&child_sk.public_key(), &issuer_sk, &child_template).unwrap();

        let result =
            verify_xdsa_cert_pem_with_issuer_cert(&child_pem, &issuer_cert, ValidityCheck::Now);
        assert!(result.is_err());
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a certificate containing an extendedKeyUsage extension is rejected.
    #[test]
    fn test_verify_rejects_extended_key_usage() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut cert = build_xdsa_cert(&subject.public_key(), &issuer, &template).unwrap();
        // EKU OID 2.5.29.37 with serverAuth (1.3.6.1.5.5.7.3.1).
        let eku_ext = x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.37"),
            critical: false,
            extn_value: OctetString::new(vec![
                0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
            ])
            .unwrap(),
        };
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(eku_ext);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        cert.signature = BitString::from_bytes(&issuer.sign(&tbs_der).to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let custom_oid = private_enterprise_oid(62253, &[7, 7]).unwrap();
        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            extensions: vec![CustomExtension {
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }

    /// Verifies that a signature BIT STRING with non-zero unused bits is rejected.
    #[test]
    fn test_verify_rejects_signature_nonzero_unused_bits() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
            ..Default::default()
        };

        let mut der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        // The signature BIT STRING is the last TLV in the certificate.
        // Its content starts with the unused-bits byte (0x00). Patch it to 0x01.
        // Walk backwards: the signature is SIGNATURE_SIZE bytes of data preceded
        // by 0x00 (unused bits), preceded by the BIT STRING length/tag.
        let sig_unused_bits_pos = der.len() - xdsa::SIGNATURE_SIZE - 1;
        assert_eq!(der[sig_unused_bits_pos], 0x00);
        der[sig_unused_bits_pos] = 0x01;

        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
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

        let template = CertificateTemplate {
            subject: Name::new().cn("Alice Identity"),
            issuer: Name::new().cn("Root"),
            validity: ValidityWindow {
                not_before: now,
                not_after: now + 3600,
            },
            role: CertificateRole::Leaf,
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
        let result = verify_xdsa_cert_der(&der, &issuer.public_key(), ValidityCheck::Now);
        assert!(result.is_err());
    }
}
