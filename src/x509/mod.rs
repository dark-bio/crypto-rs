// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

use crate::xdsa;
use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{BitString, OctetString, SetOfVec, UtcTime};
use sha1::{Digest, Sha1};
use std::error::Error;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::AsExtension;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// OID for CommonName (2.5.4.3)
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Subject is a trait for types that can be embedded into X.509 certificates
/// as the subject's public key.
pub trait Subject {
    /// The byte array type returned by `to_bytes()`.
    type Bytes: AsRef<[u8]>;

    /// Returns the raw public key bytes to embed in the certificate.
    fn to_bytes(&self) -> Self::Bytes;

    /// Returns the OID for the subject's algorithm.
    fn algorithm_oid(&self) -> ObjectIdentifier;
}

/// Parameters for creating an X.509 certificate.
pub struct Params<'a> {
    /// The subject's common name (CN) in the certificate.
    pub subject_name: &'a str,
    /// The issuer's common name (CN) in the certificate.
    pub issuer_name: &'a str,
    /// The certificate validity start time (Unix timestamp).
    pub not_before: u64,
    /// The certificate validity end time (Unix timestamp).
    pub not_after: u64,
    /// Whether this certificate is a CA certificate.
    pub is_ca: bool,
    /// Maximum number of intermediate CAs allowed below this one.
    /// Only relevant if `is_ca` is true.
    pub path_len: Option<u8>,
}

/// Creates a common name field.
fn make_cn_name(cn: &str) -> Result<Name, Box<dyn Error>> {
    let cn_value = der::asn1::Any::new(der::Tag::Utf8String, cn.as_bytes())?;
    let attr = AttributeTypeAndValue {
        oid: OID_CN,
        value: cn_value,
    };
    let mut rdn_set = SetOfVec::new();
    rdn_set.insert(attr)?;
    let rdn = RelativeDistinguishedName::from(rdn_set);
    Ok(RdnSequence(vec![rdn]))
}

/// Creates a SubjectKeyIdentifier from public key bytes.
fn make_ski(public_key: &[u8]) -> SubjectKeyIdentifier {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    SubjectKeyIdentifier(OctetString::new(&hash[..]).unwrap())
}

/// Creates an AuthorityKeyIdentifier from issuer public key bytes.
fn make_aki(public_key: &[u8]) -> AuthorityKeyIdentifier {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(&hash[..]).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    }
}

/// Creates KeyUsage for CA or end-entity certificates.
fn make_key_usage(is_ca: bool) -> KeyUsage {
    if is_ca {
        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
    } else {
        KeyUsage(KeyUsages::DigitalSignature.into())
    }
}

/// Creates an X.509 certificate for a subject, signed by an issuer.
pub fn new<S: Subject>(
    subject: &S,
    issuer: &xdsa::SecretKey,
    params: &Params,
) -> Result<CertificateInner, Box<dyn Error>> {
    // Create the composite algorithm identifier for signing (C-MLDSA)
    let composite_alg = AlgorithmIdentifierOwned {
        oid: xdsa::OID,
        parameters: None,
    };

    // Generate a random serial number
    let mut serial_bytes = [0u8; 16];
    getrandom::fill(&mut serial_bytes).unwrap();
    serial_bytes[0] &= 0x7F; // Ensure positive (MSB = 0)
    let serial_number = SerialNumber::new(&serial_bytes)?;

    // Build extensions
    let subject_name = make_cn_name(params.subject_name)?;
    let ski = make_ski(subject.to_bytes().as_ref());
    let aki = make_aki(&issuer.public_key().to_bytes());
    let bc = BasicConstraints {
        ca: params.is_ca,
        path_len_constraint: params.path_len,
    };
    let ku = make_key_usage(params.is_ca);

    let extensions = vec![
        bc.to_extension(&subject_name, &[])?,
        ku.to_extension(&subject_name, &[])?,
        ski.to_extension(&subject_name, &[])?,
        aki.to_extension(&subject_name, &[])?,
    ];

    // Convert timestamps to UtcTime
    let not_before =
        UtcTime::from_unix_duration(std::time::Duration::from_secs(params.not_before))?;
    let not_after = UtcTime::from_unix_duration(std::time::Duration::from_secs(params.not_after))?;

    // Create the TBS certificate
    let tbs_certificate = TbsCertificateInner {
        version: Version::V3,
        serial_number,
        signature: composite_alg.clone(),
        issuer: make_cn_name(params.issuer_name)?,
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

    // Encode and sign the TBS certificate
    let tbs_der = tbs_certificate.to_der()?;
    let signature = issuer.sign(&tbs_der);

    // Create the final certificate
    Ok(CertificateInner {
        tbs_certificate,
        signature_algorithm: composite_alg,
        signature: BitString::from_bytes(&signature.to_bytes())?,
    })
}
