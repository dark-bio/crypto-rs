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
    #[error("DN attribute value is not valid UTF-8")]
    NonUtf8DnAttribute,
    #[error("xHPKE certificates must be end-entity certificates")]
    XhpkeMustBeEndEntity,
    #[error("PEM block is not a CERTIFICATE")]
    InvalidPemLabel,
    #[error("PEM encoding error: {details}")]
    PemEncode { details: String },
    #[error("certificate {field} DN must not be empty")]
    EmptyDistinguishedName { field: &'static str },
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
    #[error("invalid subject algorithm: {details}")]
    InvalidSubjectAlgorithm { details: String },
    #[error("invalid subject public key length")]
    InvalidSubjectPublicKeyLength,
    #[error("certificate version must be X.509 v3")]
    UnsupportedCertificateVersion,
    #[error("invalid signature algorithm: {details}")]
    InvalidSignatureAlgorithm { details: &'static str },
    #[error("issuerUniqueID and subjectUniqueID are not allowed")]
    UniqueIdsNotAllowed,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("certificate is not valid at the requested time")]
    InvalidAtRequestedTime,
    #[error("failed to parse extension: {details}")]
    ExtensionParseFailed { details: String },
    #[error("invalid path length constraint: {details}")]
    InvalidPathLen { details: &'static str },
    #[error("certificate contains duplicate extension: {oid}")]
    DuplicateCertificateExtension { oid: String },
    #[error("certificate contains unrecognized critical extension: {oid}")]
    UnknownCriticalExtension { oid: String },
    #[error("{extension} extension must be marked critical")]
    ExtensionMustBeCritical { extension: &'static str },
    #[error("extendedKeyUsage extension is not allowed")]
    ExtendedKeyUsageNotAllowed,
    #[error("certificate validity contains pre-UNIX timestamp")]
    PreUnixTimestamp,
    #[error("invalid certificate serial: {details}")]
    InvalidSerial { details: &'static str },
    #[error("trailing data after DER certificate")]
    TrailingDerData,
    #[error("invalid key identifier: {details}")]
    InvalidKeyIdentifier { details: &'static str },
    #[error("invalid key usage: {details}")]
    InvalidKeyUsage { details: &'static str },
    #[error("invalid issuer: {details}")]
    InvalidIssuer { details: &'static str },
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error(transparent)]
    Oid(#[from] const_oid::Error),
    #[error(transparent)]
    External(#[from] Box<dyn StdError>),
}
