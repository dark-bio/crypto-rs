// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::{
    CertificateMetadata, CertificateRole, CustomExtension, DistinguishedName, Error, NameAttribute,
    Result, ValidityCheck, ValidityWindow, VerifiedCertificate, key_identifier,
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

    let mut ext_key_usage = Vec::new();
    if let Some(eku) =
        cert.tbs_certificate
            .extended_key_usage()
            .map_err(|e| Error::ExtensionParseFailed {
                details: format!("extendedKeyUsage: {e}"),
            })?
    {
        if eku.value.any {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("2.5.29.37.0"));
        }
        if eku.value.server_auth {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"));
        }
        if eku.value.client_auth {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"));
        }
        if eku.value.code_signing {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"));
        }
        if eku.value.email_protection {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4"));
        }
        if eku.value.time_stamping {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8"));
        }
        if eku.value.ocsp_signing {
            ext_key_usage.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9"));
        }
        for oid in &eku.value.other {
            ext_key_usage.push(ObjectIdentifier::new(oid.to_id_string().as_str())?);
        }
    }

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
            ParsedExtension::ExtendedKeyUsage(_) => {}
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
        ext_key_usage,
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
fn parse_name(name: &x509_parser::x509::X509Name<'_>) -> Result<DistinguishedName> {
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
    Ok(DistinguishedName { attrs })
}
