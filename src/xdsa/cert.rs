// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification for xDSA keys.

use super::{PublicKey, SecretKey};
use crate::x509::{self, CertificateTemplate, ValidityCheck, VerifiedCertificate};

/// Issues an xDSA certificate and returns it DER encoded.
pub fn issue_cert_der(
    subject: &PublicKey,
    issuer: &SecretKey,
    template: &CertificateTemplate,
) -> x509::Result<Vec<u8>> {
    x509::issue::issue_xdsa_cert_der(subject, issuer, template)
}

/// Issues an xDSA certificate and returns it PEM encoded.
pub fn issue_cert_pem(
    subject: &PublicKey,
    issuer: &SecretKey,
    template: &CertificateTemplate,
) -> x509::Result<String> {
    x509::issue::issue_xdsa_cert_pem(subject, issuer, template)
}

/// Verifies an xDSA cert from DER and returns key + metadata.
pub fn verify_cert_der(
    der: &[u8],
    issuer: &PublicKey,
    validity: ValidityCheck,
) -> x509::Result<VerifiedCertificate<PublicKey>> {
    x509::verify::verify_xdsa_cert_der(der, issuer, validity)
}

/// Verifies an xDSA cert from PEM and returns key + metadata.
pub fn verify_cert_pem(
    pem_data: &str,
    issuer: &PublicKey,
    validity: ValidityCheck,
) -> x509::Result<VerifiedCertificate<PublicKey>> {
    x509::verify::verify_xdsa_cert_pem(pem_data, issuer, validity)
}

/// Verifies an xDSA cert from DER using an issuer certificate.
pub fn verify_cert_der_with_issuer_cert(
    der: &[u8],
    issuer_cert: &VerifiedCertificate<PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<VerifiedCertificate<PublicKey>> {
    x509::verify::verify_xdsa_cert_der_with_issuer_cert(der, issuer_cert, validity)
}

/// Verifies an xDSA cert from PEM using an issuer certificate.
pub fn verify_cert_pem_with_issuer_cert(
    pem_data: &str,
    issuer_cert: &VerifiedCertificate<PublicKey>,
    validity: ValidityCheck,
) -> x509::Result<VerifiedCertificate<PublicKey>> {
    x509::verify::verify_xdsa_cert_pem_with_issuer_cert(pem_data, issuer_cert, validity)
}
