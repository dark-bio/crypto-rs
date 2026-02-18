// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification for xDSA keys.

use super::{OID, PUBLIC_KEY_SIZE, PublicKey, SecretKey};
use crate::pem;
use crate::x509::{self, ValidityCheck};
use der::Encode;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

/// Generates a DER-encoded X.509 certificate for the subject public key,
/// signed by the issuer.
pub fn issue_cert_der(
    subject: &PublicKey,
    issuer: &SecretKey,
    template: &x509::Certificate,
) -> x509::Result<Vec<u8>> {
    let default_key_usage = match template.role {
        x509::Role::Authority { .. } => KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        x509::Role::Leaf => KeyUsage(KeyUsages::DigitalSignature.into()),
    };
    Ok(x509::issue_cert(
        &subject.to_bytes(),
        OID,
        default_key_usage,
        issuer,
        template,
    )?
    .to_der()?)
}

/// Generates a PEM-encoded X.509 certificate for the subject public key,
/// signed by the issuer.
pub fn issue_cert_pem(
    subject: &PublicKey,
    issuer: &SecretKey,
    template: &x509::Certificate,
) -> x509::Result<String> {
    let der = issue_cert_der(subject, issuer, template)?;
    Ok(pem::encode("CERTIFICATE", &der))
}

/// Parses and verifies a DER-encoded X.509 certificate against the issuer's
/// public key, checking signature validity and optionally time validity.
pub fn verify_cert_der(
    der: &[u8],
    issuer: &PublicKey,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let (key_bytes, cert, key_usage) = x509::verify_cert::<PUBLIC_KEY_SIZE>(der, issuer, validity)?;

    // Enforce strict key usage profile based on certificate role
    let expected: u16 = match cert.role {
        x509::Role::Authority { .. } => (1 << 5) | (1 << 6), // keyCertSign | cRLSign
        x509::Role::Leaf => 1 << 0,                          // digitalSignature
    };
    if key_usage != expected {
        return Err(x509::Error::InvalidKeyUsage {
            details: "xDSA key usage does not match certificate role",
        });
    }
    Ok(x509::Verified {
        public_key: PublicKey::from_bytes(&key_bytes)?,
        cert,
    })
}

/// Parses and verifies a PEM-encoded X.509 certificate against the issuer's
/// public key.
pub fn verify_cert_pem(
    pem_data: &str,
    issuer: &PublicKey,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let (tag, der) = pem::decode(pem_data.as_bytes())?;
    if tag != "CERTIFICATE" {
        return Err(x509::Error::External(
            format!("invalid PEM tag {}", tag).into(),
        ));
    }
    verify_cert_der(&der, issuer, validity)
}

/// Parses and verifies a DER-encoded X.509 certificate using a previously
/// verified issuer certificate. In addition to signature and time checks, it
/// enforces CA role, key usage, path length, and DN chaining constraints on
/// the issuer.
pub fn verify_cert_der_with_issuer(
    der: &[u8],
    issuer_cert: &x509::Verified<PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let cert = verify_cert_der(der, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(&cert, issuer_cert)?;
    Ok(cert)
}

/// Parses and verifies a PEM-encoded X.509 certificate using a previously
/// verified issuer certificate. In addition to signature and time checks, it
/// enforces CA role, key usage, path length, and DN chaining constraints on
/// the issuer.
pub fn verify_cert_pem_with_issuer(
    pem_data: &str,
    issuer_cert: &x509::Verified<PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let cert = verify_cert_pem(pem_data, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(&cert, issuer_cert)?;
    Ok(cert)
}

/// Validates that the issuer certificate is authorized to sign the child
/// certificate (CA role, key usage, path length, DN chaining).
fn enforce_issuer_chaining(
    cert: &x509::Verified<PublicKey>,
    issuer_cert: &x509::Verified<PublicKey>,
) -> x509::Result<()> {
    // Issuer must be a CA
    let path_len = match &issuer_cert.cert.role {
        x509::Role::Authority { path_len } => path_len,
        x509::Role::Leaf => {
            return Err(x509::Error::InvalidIssuer {
                details: "not a CA",
            });
        }
    };
    // If issuer has pathLen constraint and child is also a CA, check depth
    if matches!(cert.cert.role, x509::Role::Authority { .. }) && *path_len == Some(0) {
        return Err(x509::Error::InvalidIssuer {
            details: "pathLenConstraint forbids CA certificates",
        });
    }
    // Child's issuer DN must match issuer's subject DN
    if cert.cert.issuer != issuer_cert.cert.subject {
        return Err(x509::Error::InvalidIssuer {
            details: "issuer DN does not match",
        });
    }
    Ok(())
}
