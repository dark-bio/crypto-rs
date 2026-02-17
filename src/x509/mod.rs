// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

#[cfg(feature = "xhpke")]
use crate::xhpke;
use crate::{pem, xdsa};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString, OctetString, SetOfVec, UtcTime};
use der::{Encode, Tag};
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_parser::extensions::ParsedExtension;

const CERTIFICATE_PEM_LABEL: &str = "CERTIFICATE";

/// OID for CommonName (2.5.4.3).
pub const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// OID prefix for Private Enterprise Number tree (1.3.6.1.4.1).
pub const OID_PRIVATE_ENTERPRISE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1");

/// A DN attribute value encoding.
#[derive(Clone, Debug)]
pub enum NameValue {
    Utf8(String),
    Printable(String),
    Ia5(String),
}

impl NameValue {
    fn as_any(&self) -> Result<Any, Box<dyn Error>> {
        match self {
            NameValue::Utf8(value) => Ok(Any::new(Tag::Utf8String, value.as_bytes())?),
            NameValue::Printable(value) => {
                if !is_printable_string(value) {
                    return Err("invalid PrintableString characters".into());
                }
                Ok(Any::new(Tag::PrintableString, value.as_bytes())?)
            }
            NameValue::Ia5(value) => {
                if !is_ia5_string(value) {
                    return Err("invalid IA5String characters".into());
                }
                Ok(Any::new(Tag::Ia5String, value.as_bytes())?)
            }
        }
    }
}

fn is_ia5_string(value: &str) -> bool {
    value.as_bytes().iter().all(|b| *b <= 0x7f)
}

fn is_printable_string(value: &str) -> bool {
    value.as_bytes().iter().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                *b,
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            )
    })
}

/// A single DN attribute.
#[derive(Clone, Debug)]
pub struct NameAttribute {
    pub oid: ObjectIdentifier,
    pub value: NameValue,
}

/// Distinguished Name represented as ordered attributes.
#[derive(Clone, Debug, Default)]
pub struct DistinguishedName {
    pub attrs: Vec<NameAttribute>,
}

impl DistinguishedName {
    /// Creates an empty DN.
    pub fn new() -> Self {
        Self { attrs: Vec::new() }
    }

    /// Adds a UTF8String CN attribute.
    pub fn cn(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_CN,
            value: NameValue::Utf8(value.into()),
        });
        self
    }

    /// Adds an arbitrary attribute.
    pub fn push(mut self, oid: ObjectIdentifier, value: NameValue) -> Self {
        self.attrs.push(NameAttribute { oid, value });
        self
    }

    fn to_x509_name(&self) -> Result<Name, Box<dyn Error>> {
        let mut rdns = Vec::with_capacity(self.attrs.len());
        for attr in &self.attrs {
            let mut set = SetOfVec::new();
            set.insert(AttributeTypeAndValue {
                oid: attr.oid,
                value: attr.value.as_any()?,
            })
            .expect("single ATAV per RDN must be unique");
            rdns.push(RelativeDistinguishedName::from(set));
        }
        Ok(RdnSequence(rdns))
    }
}

/// Parsed DN attribute value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedNameValue {
    Text(String),
    Bytes(Vec<u8>),
}

/// Parsed DN attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedNameAttribute {
    pub oid: String,
    pub value: ParsedNameValue,
}

/// Parsed distinguished name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedDistinguishedName {
    pub attrs: Vec<ParsedNameAttribute>,
}

/// Validity window.
#[derive(Clone, Debug)]
pub struct ValidityWindow {
    pub not_before: u64,
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
pub enum CertProfile {
    EndEntity,
    CertificateAuthority { path_len: Option<u8> },
}

/// Private extension data.
#[derive(Clone, Debug)]
pub struct CustomExtension {
    pub oid: ObjectIdentifier,
    pub critical: bool,
    pub value_der: Vec<u8>,
}

/// Certificate issuance template.
#[derive(Clone, Debug)]
pub struct CertificateTemplate {
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub validity: ValidityWindow,
    pub profile: CertProfile,
    pub serial: Option<Vec<u8>>,
    pub key_usage: Option<KeyUsage>,
    pub ext_key_usage: Vec<ObjectIdentifier>,
    pub custom_extensions: Vec<CustomExtension>,
}

impl Default for CertificateTemplate {
    fn default() -> Self {
        Self {
            subject: DistinguishedName::default(),
            issuer: DistinguishedName::default(),
            validity: ValidityWindow::from_unix(0, 0),
            profile: CertProfile::EndEntity,
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
    /// If set, certificate validity (`not_before`/`not_after`) is checked
    /// against this unix timestamp. If `None`, validity-time checks are skipped.
    pub verify_validity_at: Option<u64>,
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

impl Default for VerifyPolicy {
    /// Defaults to validating against current wall-clock time.
    ///
    /// For deterministic tests, set an explicit timestamp.
    fn default() -> Self {
        Self {
            verify_validity_at: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs(),
            ),
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

/// Parsed certificate metadata.
#[derive(Clone, Debug)]
pub struct CertMeta {
    pub serial: Vec<u8>,
    pub subject: ParsedDistinguishedName,
    pub issuer: ParsedDistinguishedName,
    pub validity: ValidityWindow,
    pub is_ca: bool,
    pub path_len: Option<u8>,
    pub key_usage: Option<u16>,
    pub ext_key_usage: Vec<String>,
    pub subject_key_id: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
    pub custom_extensions: Vec<ParsedCustomExtension>,
}

/// Parsed custom extension value.
#[derive(Clone, Debug)]
pub struct ParsedCustomExtension {
    pub oid: String,
    pub critical: bool,
    pub value_der: Vec<u8>,
}

/// A verified certificate with extracted public key and metadata.
#[derive(Clone, Debug)]
pub struct VerifiedCert<K> {
    pub public_key: K,
    pub meta: CertMeta,
}

trait Subject {
    type Bytes: AsRef<[u8]>;

    fn to_bytes(&self) -> Self::Bytes;
    fn algorithm_oid(&self) -> ObjectIdentifier;
    fn default_key_usage(profile: &CertProfile) -> KeyUsage;
}

impl Subject for xdsa::PublicKey {
    type Bytes = [u8; xdsa::PUBLIC_KEY_SIZE];

    fn to_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn algorithm_oid(&self) -> ObjectIdentifier {
        xdsa::OID
    }

    fn default_key_usage(profile: &CertProfile) -> KeyUsage {
        match profile {
            CertProfile::CertificateAuthority { .. } => {
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            }
            CertProfile::EndEntity => KeyUsage(KeyUsages::DigitalSignature.into()),
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

    fn default_key_usage(_profile: &CertProfile) -> KeyUsage {
        KeyUsage(KeyUsages::KeyAgreement.into())
    }
}

/// Returns a PEN-scoped OID (`1.3.6.1.4.1.<pen>.<suffix...>`).
pub fn enterprise_oid(pen: u32, suffix: &[u32]) -> Result<ObjectIdentifier, Box<dyn Error>> {
    let mut oid = format!("1.3.6.1.4.1.{}", pen);
    for arc in suffix {
        oid.push('.');
        oid.push_str(arc.to_string().as_str());
    }
    Ok(ObjectIdentifier::new(oid.as_str())?)
}

/// Issues an xDSA subject certificate and returns DER.
pub fn issue_xdsa_cert_der(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>, Box<dyn Error>> {
    issue_cert(subject, issuer, template)?
        .to_der()
        .map_err(Into::into)
}

/// Issues an xDSA subject certificate and returns PEM.
pub fn issue_xdsa_cert_pem(
    subject: &xdsa::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String, Box<dyn Error>> {
    let der = issue_xdsa_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

/// Issues an xHPKE subject certificate and returns DER.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_der(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !matches!(template.profile, CertProfile::EndEntity) {
        return Err("xHPKE certificates must be end-entity certificates".into());
    }
    issue_cert(subject, issuer, template)?
        .to_der()
        .map_err(Into::into)
}

/// Issues an xHPKE subject certificate and returns PEM.
#[cfg(feature = "xhpke")]
pub fn issue_xhpke_cert_pem(
    subject: &xhpke::PublicKey,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<String, Box<dyn Error>> {
    let der = issue_xhpke_cert_der(subject, issuer, template)?;
    encode_certificate_pem(&der)
}

/// Verifies an xDSA cert from DER and returns key + metadata.
pub fn verify_xdsa_cert_der(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xdsa::PublicKey>, Box<dyn Error>> {
    let cert = parse_and_verify_cert(der, issuer, policy)?;
    validate_subject_public_key_algorithm(&cert, xdsa::OID, "xDSA")?;
    let key_bytes = subject_public_key_bytes::<{ xdsa::PUBLIC_KEY_SIZE }>(&cert)?;

    let meta = extract_meta(&cert, policy)?;
    validate_key_identifier_bindings(&meta, &key_bytes, &issuer.to_bytes(), policy)?;
    validate_key_usage_for_xdsa(&meta)?;

    Ok(VerifiedCert {
        public_key: xdsa::PublicKey::from_bytes(&key_bytes)?,
        meta,
    })
}

/// Verifies an xDSA cert from PEM and returns key + metadata.
pub fn verify_xdsa_cert_pem(
    pem_data: &str,
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xdsa::PublicKey>, Box<dyn Error>> {
    let der = decode_certificate_pem(pem_data)?;
    verify_xdsa_cert_der(&der, issuer, policy)
}

/// Verifies an xDSA cert from DER using an issuer certificate and enforces
/// issuer authorization for chaining (CA profile + CA key usage).
pub fn verify_xdsa_cert_der_with_issuer_cert(
    der: &[u8],
    issuer_cert: &VerifiedCert<xdsa::PublicKey>,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xdsa::PublicKey>, Box<dyn Error>> {
    let cert = verify_xdsa_cert_der(der, &issuer_cert.public_key, policy)?;
    enforce_issuer_chaining(cert, issuer_cert, policy)
}

/// Verifies an xDSA cert from PEM using an issuer certificate and enforces
/// issuer authorization for chaining (CA profile + CA key usage).
pub fn verify_xdsa_cert_pem_with_issuer_cert(
    pem_data: &str,
    issuer_cert: &VerifiedCert<xdsa::PublicKey>,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xdsa::PublicKey>, Box<dyn Error>> {
    let cert = verify_xdsa_cert_pem(pem_data, &issuer_cert.public_key, policy)?;
    enforce_issuer_chaining(cert, issuer_cert, policy)
}

/// Verifies an xHPKE cert from DER and returns key + metadata.
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_der(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xhpke::PublicKey>, Box<dyn Error>> {
    let cert = parse_and_verify_cert(der, issuer, policy)?;
    validate_subject_public_key_algorithm(&cert, xhpke::OID, "xHPKE (X-Wing)")?;
    let key_bytes = subject_public_key_bytes::<{ xhpke::PUBLIC_KEY_SIZE }>(&cert)?;

    let meta = extract_meta(&cert, policy)?;
    if meta.is_ca {
        return Err("xHPKE certificate must be end-entity (ca=false)".into());
    }
    validate_key_identifier_bindings(&meta, &key_bytes, &issuer.to_bytes(), policy)?;
    validate_key_usage_for_xhpke(&meta)?;

    Ok(VerifiedCert {
        public_key: xhpke::PublicKey::from_bytes(&key_bytes)?,
        meta,
    })
}

/// Verifies an xHPKE cert from PEM and returns key + metadata.
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_pem(
    pem_data: &str,
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xhpke::PublicKey>, Box<dyn Error>> {
    let der = decode_certificate_pem(pem_data)?;
    verify_xhpke_cert_der(&der, issuer, policy)
}

/// Verifies an xHPKE cert from DER using an issuer certificate and enforces
/// issuer authorization for chaining (CA profile + CA key usage).
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_der_with_issuer_cert(
    der: &[u8],
    issuer_cert: &VerifiedCert<xdsa::PublicKey>,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xhpke::PublicKey>, Box<dyn Error>> {
    let cert = verify_xhpke_cert_der(der, &issuer_cert.public_key, policy)?;
    enforce_issuer_chaining(cert, issuer_cert, policy)
}

/// Verifies an xHPKE cert from PEM using an issuer certificate and enforces
/// issuer authorization for chaining (CA profile + CA key usage).
#[cfg(feature = "xhpke")]
pub fn verify_xhpke_cert_pem_with_issuer_cert(
    pem_data: &str,
    issuer_cert: &VerifiedCert<xdsa::PublicKey>,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<xhpke::PublicKey>, Box<dyn Error>> {
    let cert = verify_xhpke_cert_pem(pem_data, &issuer_cert.public_key, policy)?;
    enforce_issuer_chaining(cert, issuer_cert, policy)
}

fn encode_certificate_pem(der: &[u8]) -> Result<String, Box<dyn Error>> {
    let pem = der::pem::encode_string(CERTIFICATE_PEM_LABEL, der::pem::LineEnding::LF, der)
        .map_err(|e| format!("PEM encoding error: {:?}", e))?;
    Ok(pem)
}

fn decode_certificate_pem(pem_data: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let (label, der) = pem::decode(pem_data.as_bytes())?;
    if label != CERTIFICATE_PEM_LABEL {
        return Err("PEM block is not a CERTIFICATE".into());
    }
    Ok(der)
}

fn parse_and_verify_cert<'a>(
    der: &'a [u8],
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<x509_parser::certificate::X509Certificate<'a>, Box<dyn Error>> {
    validate_der_size(der, policy)?;
    let (rem, cert) = x509_parser::parse_x509_certificate(der)?;
    ensure_no_trailing_der(rem)?;
    verify_signature_and_policy(&cert, issuer, policy)?;
    Ok(cert)
}

fn validate_subject_public_key_algorithm(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    expected_oid: ObjectIdentifier,
    algorithm_name: &str,
) -> Result<(), Box<dyn Error>> {
    if cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string()
        != expected_oid.to_string()
    {
        return Err(format!(
            "certificate subject key algorithm is not {}",
            algorithm_name
        )
        .into());
    }
    if cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .parameters
        .is_some()
    {
        return Err(format!(
            "{} subjectPublicKeyInfo algorithm parameters must be absent",
            algorithm_name
        )
        .into());
    }
    Ok(())
}

fn subject_public_key_bytes<const N: usize>(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<[u8; N], Box<dyn Error>> {
    cert.tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| "invalid subject public key length".into())
}

fn enforce_issuer_chaining<K>(
    cert: VerifiedCert<K>,
    issuer_cert: &VerifiedCert<xdsa::PublicKey>,
    policy: &VerifyPolicy,
) -> Result<VerifiedCert<K>, Box<dyn Error>> {
    validate_issuer_authority(&issuer_cert.meta, cert.meta.is_ca)?;
    validate_name_chaining(&cert.meta, &issuer_cert.meta, policy)?;
    Ok(cert)
}

fn issue_cert<S: Subject>(
    subject: &S,
    issuer: &xdsa::SecretKey,
    template: &CertificateTemplate,
) -> Result<CertificateInner, Box<dyn Error>> {
    if template.subject.attrs.is_empty() {
        return Err("certificate subject DN must not be empty".into());
    }
    if template.issuer.attrs.is_empty() {
        return Err("certificate issuer DN must not be empty".into());
    }
    if template.validity.not_before >= template.validity.not_after {
        return Err("invalid certificate validity window: not_before must be < not_after".into());
    }

    let signature_alg = AlgorithmIdentifierOwned {
        oid: xdsa::OID,
        parameters: None,
    };

    let serial_number = make_serial(template.serial.as_deref())?;
    let subject_name = template.subject.to_x509_name()?;
    let issuer_name = template.issuer.to_x509_name()?;

    let mut extensions = Vec::<Extension>::new();
    let mut extension_oids = HashSet::new();

    let (is_ca, path_len) = match &template.profile {
        CertProfile::EndEntity => (false, None),
        CertProfile::CertificateAuthority { path_len } => (true, *path_len),
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
            return Err("custom extension OID under 2.5.29 is reserved".into());
        }
        if !extension_oids.insert(oid) {
            return Err("duplicate extension OID in certificate template".into());
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

    let tbs_der = tbs_certificate.to_der()?;
    let signature = issuer.sign(&tbs_der);

    Ok(CertificateInner {
        tbs_certificate,
        signature_algorithm: signature_alg,
        signature: BitString::from_bytes(&signature.to_bytes())?,
    })
}

fn verify_signature_and_policy(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &xdsa::PublicKey,
    policy: &VerifyPolicy,
) -> Result<(), Box<dyn Error>> {
    if cert.tbs_certificate.version != x509_parser::x509::X509Version::V3 {
        return Err("certificate version must be X.509 v3".into());
    }

    let not_before = unix_ts_to_u64(cert.tbs_certificate.validity.not_before.timestamp())?;
    let not_after = unix_ts_to_u64(cert.tbs_certificate.validity.not_after.timestamp())?;
    if not_before >= not_after {
        return Err("invalid certificate validity window: not_before must be < not_after".into());
    }

    let outer_sig_alg = cert.signature_algorithm.algorithm.to_id_string();
    let tbs_sig_alg = cert.tbs_certificate.signature.algorithm.to_id_string();
    let expected_sig_alg = xdsa::OID.to_string();
    if outer_sig_alg != expected_sig_alg || tbs_sig_alg != expected_sig_alg {
        return Err("certificate signature algorithm is not xDSA".into());
    }
    if cert.signature_algorithm.parameters.is_some()
        || cert.tbs_certificate.signature.parameters.is_some()
    {
        return Err("certificate signature algorithm parameters must be absent".into());
    }
    if cert.tbs_certificate.issuer_uid.is_some() || cert.tbs_certificate.subject_uid.is_some() {
        return Err("issuerUniqueID and subjectUniqueID are not allowed".into());
    }

    let tbs = cert.tbs_certificate.as_ref();
    let sig_bytes: [u8; xdsa::SIGNATURE_SIZE] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| "invalid signature length")?;
    let sig = xdsa::Signature::from_bytes(&sig_bytes);
    issuer.verify(tbs, &sig)?;

    if let Some(now) = policy.verify_validity_at {
        if now < not_before || now > not_after {
            return Err("certificate is not valid at the requested time".into());
        }
    }
    Ok(())
}

fn extract_meta(
    cert: &x509_parser::certificate::X509Certificate,
    policy: &VerifyPolicy,
) -> Result<CertMeta, Box<dyn Error>> {
    let serial = cert.tbs_certificate.raw_serial();
    if serial.len() > policy.max_serial_length {
        return Err("certificate serial exceeds policy maximum".into());
    }
    validate_serial_encoding(serial)?;

    let basic_constraints = cert.tbs_certificate.basic_constraints()?;
    let (is_ca, path_len) = match basic_constraints {
        Some(ext) => (
            ext.value.ca,
            convert_path_len(ext.value.path_len_constraint)?,
        ),
        None => (false, None),
    };
    if !is_ca && path_len.is_some() {
        return Err(
            "certificate basicConstraints invalid: pathLenConstraint requires ca=true".into(),
        );
    }

    let key_usage = cert.tbs_certificate.key_usage()?.map(|ku| ku.value.flags);

    let mut ext_key_usage = Vec::new();
    if let Some(eku) = cert.tbs_certificate.extended_key_usage()? {
        if eku.value.any {
            ext_key_usage.push("2.5.29.37.0".to_string());
        }
        if eku.value.server_auth {
            ext_key_usage.push("1.3.6.1.5.5.7.3.1".to_string());
        }
        if eku.value.client_auth {
            ext_key_usage.push("1.3.6.1.5.5.7.3.2".to_string());
        }
        if eku.value.code_signing {
            ext_key_usage.push("1.3.6.1.5.5.7.3.3".to_string());
        }
        if eku.value.email_protection {
            ext_key_usage.push("1.3.6.1.5.5.7.3.4".to_string());
        }
        if eku.value.time_stamping {
            ext_key_usage.push("1.3.6.1.5.5.7.3.8".to_string());
        }
        if eku.value.ocsp_signing {
            ext_key_usage.push("1.3.6.1.5.5.7.3.9".to_string());
        }
        for oid in &eku.value.other {
            ext_key_usage.push(oid.to_id_string());
        }
    }

    let mut subject_key_id = None;
    let mut authority_key_id = None;
    let mut custom_extensions = Vec::new();
    let mut extension_oids = HashSet::new();
    let mut basic_constraints_critical = None;
    let mut key_usage_critical = None;
    for ext in cert.tbs_certificate.extensions() {
        if ext.value.len() > policy.max_extension_value_size {
            return Err("certificate extension value exceeds policy maximum".into());
        }
        let oid = ext.oid.to_id_string();
        if !extension_oids.insert(oid.clone()) {
            return Err(format!("certificate contains duplicate extension: {}", oid).into());
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
                if ext.critical {
                    return Err(format!(
                        "certificate contains unrecognized critical extension: {}",
                        ext.oid.to_id_string()
                    )
                    .into());
                }
                custom_extensions.push(ParsedCustomExtension {
                    oid: ext.oid.to_id_string(),
                    critical: ext.critical,
                    value_der: ext.value.to_vec(),
                });
                if custom_extensions.len() > policy.max_custom_extensions {
                    return Err("certificate custom extension count exceeds policy maximum".into());
                }
            }
        }
    }

    if is_ca && basic_constraints_critical != Some(true) {
        return Err("CA certificate basicConstraints must be marked critical".into());
    }
    if key_usage_critical != Some(true) {
        return Err("certificate keyUsage extension must be marked critical".into());
    }

    Ok(CertMeta {
        serial: serial.to_vec(),
        subject: parse_name(&cert.tbs_certificate.subject, policy)?,
        issuer: parse_name(&cert.tbs_certificate.issuer, policy)?,
        validity: ValidityWindow {
            not_before: unix_ts_to_u64(cert.tbs_certificate.validity.not_before.timestamp())?,
            not_after: unix_ts_to_u64(cert.tbs_certificate.validity.not_after.timestamp())?,
        },
        is_ca,
        path_len,
        key_usage,
        ext_key_usage,
        subject_key_id,
        authority_key_id,
        custom_extensions,
    })
}

fn convert_path_len(path_len: Option<u32>) -> Result<Option<u8>, Box<dyn Error>> {
    match path_len {
        Some(v) if v > u8::MAX as u32 => {
            Err("certificate path_len_constraint exceeds u8::MAX".into())
        }
        Some(v) => Ok(Some(v as u8)),
        None => Ok(None),
    }
}

fn unix_ts_to_u64(ts: i64) -> Result<u64, Box<dyn Error>> {
    u64::try_from(ts).map_err(|_| "certificate validity contains pre-UNIX timestamp".into())
}

fn validate_serial_encoding(serial: &[u8]) -> Result<(), Box<dyn Error>> {
    if serial.is_empty() {
        return Err("certificate serial must not be empty".into());
    }
    if serial[0] & 0x80 != 0 {
        return Err("certificate serial must be positive".into());
    }
    if serial.len() > 1 && serial[0] == 0x00 && serial[1] & 0x80 == 0 {
        return Err("certificate serial must use canonical DER INTEGER encoding".into());
    }
    if serial.iter().all(|b| *b == 0) {
        return Err("certificate serial must be non-zero".into());
    }
    Ok(())
}

fn ensure_no_trailing_der(rem: &[u8]) -> Result<(), Box<dyn Error>> {
    if !rem.is_empty() {
        return Err("trailing data after DER certificate".into());
    }
    Ok(())
}

fn validate_der_size(der: &[u8], policy: &VerifyPolicy) -> Result<(), Box<dyn Error>> {
    if der.len() > policy.max_certificate_size {
        return Err("certificate DER exceeds policy maximum size".into());
    }
    Ok(())
}

fn key_identifier(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

fn validate_key_identifier_bindings(
    meta: &CertMeta,
    subject_public_key: &[u8],
    issuer_public_key: &[u8],
    policy: &VerifyPolicy,
) -> Result<(), Box<dyn Error>> {
    if policy.require_subject_key_id && meta.subject_key_id.is_none() {
        return Err("certificate is missing subjectKeyIdentifier".into());
    }
    if policy.require_authority_key_id && meta.authority_key_id.is_none() {
        return Err("certificate is missing authorityKeyIdentifier".into());
    }
    if let Some(ski) = &meta.subject_key_id {
        let expected = key_identifier(subject_public_key);
        if *ski != expected {
            return Err("subjectKeyIdentifier does not match subject public key".into());
        }
    }
    if let Some(aki) = &meta.authority_key_id {
        let expected = key_identifier(issuer_public_key);
        if *aki != expected {
            return Err("authorityKeyIdentifier does not match issuer public key".into());
        }
    }
    Ok(())
}

const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
#[cfg(feature = "xhpke")]
const KU_KEY_AGREEMENT: u16 = 1 << 4;
const KU_KEY_CERT_SIGN: u16 = 1 << 5;
const KU_CRL_SIGN: u16 = 1 << 6;

const XDSA_EE_KEY_USAGE: u16 = KU_DIGITAL_SIGNATURE;
const XDSA_CA_KEY_USAGE: u16 = KU_KEY_CERT_SIGN | KU_CRL_SIGN;
#[cfg(feature = "xhpke")]
const XHPKE_EE_KEY_USAGE: u16 = KU_KEY_AGREEMENT;

fn validate_key_usage_for_xdsa(meta: &CertMeta) -> Result<(), Box<dyn Error>> {
    let usage = meta
        .key_usage
        .ok_or("xDSA certificate is missing keyUsage extension")?;
    if meta.is_ca {
        if usage != XDSA_CA_KEY_USAGE {
            return Err("xDSA CA certificate keyUsage must be exactly keyCertSign|cRLSign".into());
        }
    } else if usage != XDSA_EE_KEY_USAGE {
        return Err("xDSA end-entity certificate keyUsage must be exactly digitalSignature".into());
    }
    Ok(())
}

fn validate_issuer_authority(meta: &CertMeta, child_is_ca: bool) -> Result<(), Box<dyn Error>> {
    if !meta.is_ca {
        return Err("issuer certificate is not a CA".into());
    }
    let usage = meta
        .key_usage
        .ok_or("issuer certificate is missing keyUsage extension")?;
    if usage != XDSA_CA_KEY_USAGE {
        return Err("issuer certificate keyUsage must be exactly keyCertSign|cRLSign".into());
    }
    if child_is_ca && meta.path_len == Some(0) {
        return Err("issuer certificate pathLenConstraint forbids issuing CA certificates".into());
    }
    Ok(())
}

fn validate_name_chaining(
    child: &CertMeta,
    issuer: &CertMeta,
    policy: &VerifyPolicy,
) -> Result<(), Box<dyn Error>> {
    if policy.require_name_chaining && child.issuer != issuer.subject {
        return Err("certificate issuer DN does not match issuer certificate subject DN".into());
    }
    Ok(())
}

#[cfg(feature = "xhpke")]
fn validate_key_usage_for_xhpke(meta: &CertMeta) -> Result<(), Box<dyn Error>> {
    let usage = meta
        .key_usage
        .ok_or("xHPKE certificate is missing keyUsage extension")?;
    if usage != XHPKE_EE_KEY_USAGE {
        return Err("xHPKE certificate keyUsage must be exactly keyAgreement".into());
    }
    Ok(())
}

fn parse_name(
    name: &x509_parser::x509::X509Name<'_>,
    policy: &VerifyPolicy,
) -> Result<ParsedDistinguishedName, Box<dyn Error>> {
    let mut attrs = Vec::new();
    for attr in name.iter_attributes() {
        if attrs.len() >= policy.max_dn_attributes {
            return Err("certificate DN attribute count exceeds policy maximum".into());
        }
        if attr.as_slice().len() > policy.max_dn_attr_value_size {
            return Err("certificate DN attribute value exceeds policy maximum".into());
        }
        let value = match attr.as_str() {
            Ok(text) => ParsedNameValue::Text(text.to_string()),
            Err(_) => ParsedNameValue::Bytes(attr.as_slice().to_vec()),
        };
        attrs.push(ParsedNameAttribute {
            oid: attr.attr_type().to_id_string(),
            value,
        });
    }
    Ok(ParsedDistinguishedName { attrs })
}

fn make_serial(serial: Option<&[u8]>) -> Result<SerialNumber, Box<dyn Error>> {
    if let Some(serial) = serial {
        return Ok(SerialNumber::new(serial)?);
    }
    let mut serial_bytes = [0u8; 16];
    getrandom::fill(&mut serial_bytes)
        .map_err(|e| format!("failed to generate certificate serial: {}", e))?;
    serial_bytes[0] &= 0x7F;
    Ok(SerialNumber::new(&serial_bytes)?)
}

fn make_ski(public_key: &[u8]) -> SubjectKeyIdentifier {
    let hash = key_identifier(public_key);
    SubjectKeyIdentifier(OctetString::new(hash).unwrap())
}

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
    use super::*;
    use const_oid::db::rfc5280::{
        ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION, ID_KP_OCSP_SIGNING,
        ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING,
    };

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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
            serial: None,
            key_usage: None,
            ext_key_usage: Vec::new(),
            custom_extensions: vec![CustomExtension {
                oid: enterprise_oid(62253, &[1, 1]).unwrap(),
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
            ..Default::default()
        };

        let pem = issue_xhpke_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let result = verify_xhpke_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
        assert!(result.is_err());
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
            ..Default::default()
        };

        let result = issue_xhpke_cert_der(&subject.public_key(), &issuer, &template);
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
            custom_extensions: vec![CustomExtension {
                oid: enterprise_oid(62253, &[9, 9]).unwrap(),
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };

        let result = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template);
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };

        let pem = issue_xdsa_cert_pem(&subject.public_key(), &issuer, &template).unwrap();
        let pem = pem.replace("CERTIFICATE", "PRIVATE KEY");

        let result = verify_xdsa_cert_pem(&pem, &issuer.public_key(), &VerifyPolicy::default());
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            key_usage: Some(KeyUsage(
                (KeyUsages::DigitalSignature | KeyUsages::KeyCertSign).into(),
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };

        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();
        cert.tbs_certificate.validity.not_after = cert.tbs_certificate.validity.not_before.clone();

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let signature = issuer.sign(&tbs_der);
        cert.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();

        let der = cert.to_der().unwrap();
        let policy = VerifyPolicy {
            verify_validity_at: None,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
                enterprise_oid(62253, &[42]).unwrap(),
                NameValue::Ia5("alice@example.com".into()),
            );

        let template = CertificateTemplate {
            subject: subject_dn,
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            serial: Some(serial.clone()),
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert_eq!(cert.meta.serial, serial);
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            verify_validity_at: Some(now),
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let policy = VerifyPolicy {
            verify_validity_at: None,
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
            profile: CertProfile::EndEntity,
            ext_key_usage: vec![
                ObjectIdentifier::new_unwrap("2.5.29.37.0"),
                ID_KP_SERVER_AUTH,
                ID_KP_CLIENT_AUTH,
                ID_KP_CODE_SIGNING,
                ID_KP_EMAIL_PROTECTION,
                ID_KP_TIME_STAMPING,
                ID_KP_OCSP_SIGNING,
                enterprise_oid(62253, &[9, 1]).unwrap(),
            ],
            ..Default::default()
        };

        let der = issue_xdsa_cert_der(&subject.public_key(), &issuer, &template).unwrap();
        let cert =
            verify_xdsa_cert_der(&der, &issuer.public_key(), &VerifyPolicy::default()).unwrap();
        assert!(cert.meta.ext_key_usage.contains(&"2.5.29.37.0".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.1".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.2".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.3".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.4".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.8".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .contains(&"1.3.6.1.5.5.7.3.9".to_string()));
        assert!(cert
            .meta
            .ext_key_usage
            .iter()
            .any(|oid| oid.ends_with("62253.9.1")));
    }

    #[test]
    fn test_issue_rejects_duplicate_custom_extension_oid() {
        let subject = xdsa::SecretKey::generate();
        let issuer = xdsa::SecretKey::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let oid = enterprise_oid(62253, &[8, 8]).unwrap();

        let template = CertificateTemplate {
            subject: DistinguishedName::new().cn("Alice Identity"),
            issuer: DistinguishedName::new().cn("Root"),
            validity: ValidityWindow::from_unix(now, now + 3600),
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
            custom_extensions: vec![CustomExtension {
                oid: enterprise_oid(62253, &[99]).unwrap(),
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
            ..Default::default()
        };
        let mut cert = issue_cert(&subject.public_key(), &issuer, &template).unwrap();

        let mut set = SetOfVec::new();
        set.insert(AttributeTypeAndValue {
            oid: OID_CN,
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
            ParsedNameValue::Bytes(_)
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::CertificateAuthority { path_len: Some(0) },
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
            profile: CertProfile::EndEntity,
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
