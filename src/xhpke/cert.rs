// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification for xHPKE keys.

use super::{OID, PUBLIC_KEY_SIZE, PublicKey};
use crate::pem;
use crate::x509::{self, ValidityCheck};
use crate::xdsa;
use der::Encode;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

/// Generates a DER-encoded X.509 certificate for the subject public key,
/// signed by an xDSA issuer.
///
/// xHPKE certificates are always end-entity certificates. If the template
/// asks for a CA role, an error is returned.
pub fn issue_cert_der(
    subject: &PublicKey,
    issuer: &xdsa::SecretKey,
    template: &x509::Certificate,
) -> x509::Result<Vec<u8>> {
    if !matches!(template.role, x509::Role::Leaf) {
        return Err(x509::Error::MustBeLeaf);
    }
    let default_key_usage = KeyUsage(KeyUsages::KeyAgreement.into());
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
/// signed by an xDSA issuer.
///
/// xHPKE certificates are always end-entity certificates. If the template
/// asks for a CA role, an error is returned.
pub fn issue_cert_pem(
    subject: &PublicKey,
    issuer: &xdsa::SecretKey,
    template: &x509::Certificate,
) -> x509::Result<String> {
    let der = issue_cert_der(subject, issuer, template)?;
    Ok(pem::encode("CERTIFICATE", &der))
}

/// Parses and verifies a DER-encoded X.509 certificate against the xDSA
/// issuer's public key, checking signature validity and optionally time
/// validity.
pub fn verify_cert_der(
    der: &[u8],
    issuer: &xdsa::PublicKey,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let (key_bytes, cert, key_usage) = x509::verify_cert::<PUBLIC_KEY_SIZE>(der, issuer, validity)?;

    // Enforce strict key usage profile based on certificate role
    if matches!(cert.role, x509::Role::Authority { .. }) {
        return Err(x509::Error::MustBeLeaf);
    }
    if key_usage != 1 << 4 {
        // keyAgreement
        return Err(x509::Error::InvalidKeyUsage {
            details: "xHPKE requires keyAgreement",
        });
    }
    Ok(x509::Verified {
        public_key: PublicKey::from_bytes(&key_bytes)?,
        cert,
    })
}

/// Parses and verifies a PEM-encoded X.509 certificate against the xDSA
/// issuer's public key.
pub fn verify_cert_pem(
    pem_data: &str,
    issuer: &xdsa::PublicKey,
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
/// verified xDSA issuer certificate. In addition to signature and time checks,
/// it enforces CA role, key usage, and DN chaining constraints on the issuer.
pub fn verify_cert_der_with_issuer(
    der: &[u8],
    issuer_cert: &x509::Verified<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let cert = verify_cert_der(der, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(&cert, issuer_cert)?;
    Ok(cert)
}

/// Parses and verifies a PEM-encoded X.509 certificate using a previously
/// verified xDSA issuer certificate. In addition to signature and time checks,
/// it enforces CA role, key usage, and DN chaining constraints on the issuer.
pub fn verify_cert_pem_with_issuer(
    pem_data: &str,
    issuer_cert: &x509::Verified<xdsa::PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<x509::Verified<PublicKey>> {
    let cert = verify_cert_pem(pem_data, &issuer_cert.public_key, validity)?;
    enforce_issuer_chaining(&cert, issuer_cert)?;
    Ok(cert)
}

/// Validates that the issuer certificate is authorized to sign the child
/// certificate (CA role, key usage, DN chaining).
fn enforce_issuer_chaining(
    cert: &x509::Verified<PublicKey>,
    issuer_cert: &x509::Verified<xdsa::PublicKey>,
) -> x509::Result<()> {
    // Issuer must be a CA
    if !matches!(issuer_cert.cert.role, x509::Role::Authority { .. }) {
        return Err(x509::Error::InvalidIssuer {
            details: "not a CA",
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
