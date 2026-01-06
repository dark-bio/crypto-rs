// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

use crate::xdsa;
use bcder::Mode;
use bcder::Oid;
use bcder::encode::Values;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use std::error::Error;
use x509_certificate::asn1time::Time;
use x509_certificate::rfc3280::{
    AttributeTypeAndValue, AttributeValue, Name, RdnSequence, RelativeDistinguishedName,
};
use x509_certificate::rfc5280::{AlgorithmIdentifier, AlgorithmParameter, Extension, Extensions};
use x509_certificate::{X509Certificate, rfc5280};

/// OID for id-MLDSA65-Ed25519-SHA512: 1.3.6.1.5.5.7.6.48
const CMLDSA_OID: &[u8] = &[43, 6, 1, 5, 5, 7, 6, 48];

/// Subject is a trait for types that can be embedded into X.509 certificates
/// as the subject's public key.
pub trait Subject {
    /// The byte array type returned by `to_bytes()`.
    type Bytes: AsRef<[u8]>;

    /// Returns the raw public key bytes to embed in the certificate.
    fn to_bytes(&self) -> Self::Bytes;

    /// Returns the OID bytes for the subject's algorithm.
    fn algorithm_oid(&self) -> &'static [u8];
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
fn make_cn_name(cn: &str) -> Name {
    let cn_oid = Oid(Bytes::from_static(&[85, 4, 3])); // OID 2.5.4.3 (CommonName)
    let cn_value = AttributeValue::new_utf8_string(cn).unwrap();
    let attr = AttributeTypeAndValue {
        typ: cn_oid,
        value: cn_value,
    };
    let mut rdn = RelativeDistinguishedName::default();
    rdn.push(attr);
    let mut seq = RdnSequence::default();
    seq.push(rdn);
    Name::RdnSequence(seq)
}

/// Creates a SubjectKeyIdentifier extension.
fn make_ski_ext(public_key: &[u8]) -> Extension {
    // Create the SHA1 hash of the subject public key
    let id = {
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(public_key);
        ctx.finish()
    };
    // Encode the subject extension value
    let mut buf = Vec::new();
    buf.push(0x04); // OCTET STRING tag
    buf.push(20); // length (SHA-1 = 20 bytes)
    buf.extend_from_slice(id.as_ref());

    Extension {
        id: Oid(Bytes::from_static(&[85, 29, 14])), // OID 2.5.29.14
        critical: Some(false),
        value: bcder::OctetString::new(Bytes::copy_from_slice(&buf)),
    }
}

/// Creates an AuthorityKeyIdentifier extension.
fn make_aki_ext(public_key: &[u8]) -> Extension {
    // Create the SHA1 hash of the issuer public key
    let id = {
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(public_key);
        ctx.finish()
    };
    // Encode the issuer extension value
    let mut buf = vec![
        0x30, // SEQUENCE tag
        22,   // length (context tag + length + 20 bytes)
        0x80, // context tag [0] implicit
        20,   // length
    ];
    buf.extend_from_slice(id.as_ref());

    Extension {
        id: Oid(Bytes::from_static(&[85, 29, 35])), // OID 2.5.29.35
        critical: Some(false),
        value: bcder::OctetString::new(Bytes::copy_from_slice(&buf)),
    }
}

/// Creates a BasicConstraints extension.
///
/// For CA certificates, set `is_ca=true`. The `path_len` constrains how many
/// intermediate CAs can follow (e.g., 0 means can only sign end-entity certs).
fn make_basic_constraints_ext(is_ca: bool, path_len: Option<u8>) -> Extension {
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    let inner = if is_ca {
        let mut inner = vec![0x01, 0x01, 0xFF]; // BOOLEAN TRUE
        if let Some(len) = path_len {
            inner.extend_from_slice(&[0x02, 0x01, len]); // INTEGER
        }
        inner
    } else {
        vec![] // Empty sequence = cA defaults to FALSE
    };

    let mut buf = Vec::new();
    buf.push(0x30); // SEQUENCE tag
    buf.push(inner.len() as u8);
    buf.extend(inner);

    Extension {
        id: Oid(Bytes::from_static(&[85, 29, 19])), // OID 2.5.29.19
        critical: Some(true),                       // MUST be critical per RFC 5280
        value: bcder::OctetString::new(Bytes::copy_from_slice(&buf)),
    }
}

/// Creates a KeyUsage extension.
///
/// For CA certificates, sets keyCertSign (bit 5) and cRLSign (bit 6).
/// For end-entity certificates, sets digitalSignature (bit 0).
fn make_key_usage_ext(is_ca: bool) -> Extension {
    // KeyUsage ::= BIT STRING
    // Bit 0: digitalSignature, Bit 5: keyCertSign, Bit 6: cRLSign
    let (usage_byte, unused_bits) = if is_ca {
        (0b0000_0110, 1u8) // keyCertSign (bit 5) + cRLSign (bit 6), 1 unused bit
    } else {
        (0b1000_0000, 7u8) // digitalSignature (bit 0), 7 unused bits
    };

    // BIT STRING: tag 0x03, length, unused bits count, data
    let buf = vec![0x03, 0x02, unused_bits, usage_byte];

    Extension {
        id: Oid(Bytes::from_static(&[85, 29, 15])), // OID 2.5.29.15
        critical: Some(true),                       // SHOULD be critical per RFC 5280
        value: bcder::OctetString::new(Bytes::copy_from_slice(&buf)),
    }
}

/// Creates an X.509 certificate for a subject, signed by an issuer.
pub fn new<S: Subject>(
    subject: &S,
    issuer: &xdsa::SecretKey,
    params: &Params,
) -> Result<X509Certificate, Box<dyn Error>> {
    // Validate and convert timestamps
    let not_before = Utc
        .timestamp_opt(params.not_before as i64, 0)
        .single()
        .ok_or_else(|| format!("invalid not_before timestamp: {}", params.not_before))?;
    let not_after = Utc
        .timestamp_opt(params.not_after as i64, 0)
        .single()
        .ok_or_else(|| format!("invalid not_after timestamp: {}", params.not_after))?;

    // Create a dummy parameter that doesn't encode to NULL
    // https://github.com/indygreg/cryptography-rs/issues/26
    let no_params = AlgorithmParameter::from_captured(bcder::Captured::empty(Mode::Der));

    // Create the composite algorithm identifier for signing (C-MLDSA)
    let composite_oid = Oid(Bytes::from_static(CMLDSA_OID));
    let composite_alg = AlgorithmIdentifier {
        algorithm: composite_oid,
        parameters: Some(no_params.clone()),
    };
    // Generate a random serial number
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).unwrap();
    serial[0] &= 0x7F; // Ensure positive (MSB = 0)

    // Build extensions for the key identities and constraints
    let ski_ext = make_ski_ext(subject.to_bytes().as_ref());
    let aki_ext = make_aki_ext(&issuer.public_key().to_bytes());
    let bc_ext = make_basic_constraints_ext(params.is_ca, params.path_len);
    let ku_ext = make_key_usage_ext(params.is_ca);

    let mut extensions = Extensions::default();
    extensions.push(bc_ext);
    extensions.push(ku_ext);
    extensions.push(ski_ext);
    extensions.push(aki_ext);

    // Create the TBS certificate
    let tbs_certificate = rfc5280::TbsCertificate {
        version: Some(rfc5280::Version::V3),
        serial_number: bcder::Integer::from(u128::from_be_bytes(serial)),
        signature: composite_alg.clone(),
        issuer: make_cn_name(params.issuer_name),
        validity: rfc5280::Validity {
            not_before: Time::from(not_before),
            not_after: Time::from(not_after),
        },
        subject: make_cn_name(params.subject_name),
        subject_public_key_info: rfc5280::SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: Oid(Bytes::from_static(subject.algorithm_oid())),
                parameters: Some(no_params),
            },
            subject_public_key: bcder::BitString::new(
                0,
                Bytes::copy_from_slice(subject.to_bytes().as_ref()),
            ),
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
        raw_data: None,
    };
    // Encode and sign the TBS certificate
    let mut tbs_der = Vec::<u8>::new();
    tbs_certificate
        .encode_ref()
        .write_encoded(Mode::Der, &mut tbs_der)
        .unwrap();

    let signature = issuer.sign(&tbs_der);

    // Create the final certificate
    Ok(X509Certificate::from(rfc5280::Certificate {
        tbs_certificate,
        signature_algorithm: composite_alg,
        signature: bcder::BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
    }))
}
