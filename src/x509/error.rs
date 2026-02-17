// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::error::Error as StdError;
use thiserror::Error;

/// Result type used by x509 APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type used by x509 APIs.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid PrintableString characters")]
    InvalidPrintableString,
    #[error("invalid IA5String characters")]
    InvalidIa5String,
    #[error("raw DN attribute bytes are not allowed for certificate issuance")]
    RawNameValueNotAllowedForIssuance,
    #[error("xHPKE certificates must be end-entity certificates")]
    XhpkeMustBeEndEntity,
    #[error("PEM block is not a CERTIFICATE")]
    InvalidPemLabel,
    #[error("PEM encoding error: {details}")]
    PemEncode { details: String },
    #[error("certificate subject DN must not be empty")]
    EmptySubjectDn,
    #[error("certificate issuer DN must not be empty")]
    EmptyIssuerDn,
    #[error("invalid certificate validity window: not_before must be < not_after")]
    InvalidValidityWindow,
    #[error("custom extension OID under 2.5.29 is reserved")]
    ReservedExtensionOid,
    #[error("duplicate extension OID in certificate template")]
    DuplicateTemplateExtensionOid,
    #[error("failed to generate certificate serial: {details}")]
    SerialGenerationFailed { details: String },
    #[error("X.509 parse error: {details}")]
    X509Parse { details: String },
    #[error("certificate subject key algorithm is not {algorithm}")]
    SubjectAlgorithmMismatch { algorithm: &'static str },
    #[error("{algorithm} subjectPublicKeyInfo algorithm parameters must be absent")]
    SubjectAlgorithmParametersPresent { algorithm: &'static str },
    #[error("invalid subject public key length")]
    InvalidSubjectPublicKeyLength,
    #[error("certificate version must be X.509 v3")]
    UnsupportedCertificateVersion,
    #[error("certificate signature algorithm is not xDSA")]
    SignatureAlgorithmMismatch,
    #[error("certificate signature algorithm parameters must be absent")]
    SignatureAlgorithmParametersPresent,
    #[error("issuerUniqueID and subjectUniqueID are not allowed")]
    UniqueIdsNotAllowed,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("certificate is not valid at the requested time")]
    InvalidAtRequestedTime,
    #[error("certificate serial exceeds policy maximum")]
    SerialTooLong,
    #[error("failed to parse basicConstraints extension: {details}")]
    BasicConstraintsParse { details: String },
    #[error("certificate basicConstraints invalid: pathLenConstraint requires ca=true")]
    PathLenRequiresCa,
    #[error("failed to parse keyUsage extension: {details}")]
    KeyUsageParse { details: String },
    #[error("failed to parse extendedKeyUsage extension: {details}")]
    ExtendedKeyUsageParse { details: String },
    #[error("certificate extension value exceeds policy maximum")]
    ExtensionValueTooLarge,
    #[error("certificate contains duplicate extension: {oid}")]
    DuplicateCertificateExtension { oid: String },
    #[error("certificate contains unrecognized critical extension: {oid}")]
    UnknownCriticalExtension { oid: String },
    #[error("certificate custom extension count exceeds policy maximum")]
    TooManyCustomExtensions,
    #[error("CA certificate basicConstraints must be marked critical")]
    BasicConstraintsMustBeCritical,
    #[error("certificate keyUsage extension must be marked critical")]
    KeyUsageMustBeCritical,
    #[error("certificate path_len_constraint exceeds u8::MAX")]
    PathLenTooLarge,
    #[error("certificate validity contains pre-UNIX timestamp")]
    PreUnixTimestamp,
    #[error("certificate serial must not be empty")]
    EmptySerial,
    #[error("certificate serial must be positive")]
    NegativeSerial,
    #[error("certificate serial must use canonical DER INTEGER encoding")]
    NonCanonicalSerial,
    #[error("certificate serial must be non-zero")]
    ZeroSerial,
    #[error("trailing data after DER certificate")]
    TrailingDerData,
    #[error("certificate DER exceeds policy maximum size")]
    CertificateTooLarge,
    #[error("certificate is missing subjectKeyIdentifier")]
    MissingSubjectKeyId,
    #[error("certificate is missing authorityKeyIdentifier")]
    MissingAuthorityKeyId,
    #[error("subjectKeyIdentifier does not match subject public key")]
    SubjectKeyIdMismatch,
    #[error("authorityKeyIdentifier does not match issuer public key")]
    AuthorityKeyIdMismatch,
    #[error("xDSA certificate is missing keyUsage extension")]
    MissingXdsaKeyUsage,
    #[error("xDSA CA certificate keyUsage must be exactly keyCertSign|cRLSign")]
    InvalidXdsaCaKeyUsage,
    #[error("xDSA end-entity certificate keyUsage must be exactly digitalSignature")]
    InvalidXdsaEeKeyUsage,
    #[error("issuer certificate is not a CA")]
    IssuerNotCa,
    #[error("issuer certificate is missing keyUsage extension")]
    MissingIssuerKeyUsage,
    #[error("issuer certificate keyUsage must be exactly keyCertSign|cRLSign")]
    InvalidIssuerKeyUsage,
    #[error("issuer certificate pathLenConstraint forbids issuing CA certificates")]
    IssuerPathLenForbidsCa,
    #[error("certificate issuer DN does not match issuer certificate subject DN")]
    IssuerNameMismatch,
    #[error("xHPKE certificate is missing keyUsage extension")]
    MissingXhpkeKeyUsage,
    #[error("xHPKE certificate keyUsage must be exactly keyAgreement")]
    InvalidXhpkeKeyUsage,
    #[error("xHPKE certificate must be end-entity (ca=false)")]
    XhpkeCertificateCannotBeCa,
    #[error("certificate DN attribute count exceeds policy maximum")]
    TooManyDnAttributes,
    #[error("certificate DN attribute value exceeds policy maximum")]
    DnAttributeValueTooLarge,
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error(transparent)]
    Oid(#[from] const_oid::Error),
    #[error(transparent)]
    External(#[from] Box<dyn StdError>),
}
