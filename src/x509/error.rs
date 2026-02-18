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
    #[error("certificate {field} DN must not be empty")]
    EmptyDistinguishedName { field: &'static str },
    #[error("not_before must be before not_after")]
    InvalidValidity,
    #[error("custom extension OID under 2.5.29 is reserved")]
    ReservedExtensionOid,
    #[error("duplicate extension OID in certificate: {oid}")]
    DuplicateExtensionOid { oid: String },
    #[error("key type can only be end-entity certificate")]
    MustBeLeaf,
    #[error("invalid key usage: {details}")]
    InvalidKeyUsage { details: &'static str },
    #[error("certificate is not valid at requested time")]
    ExpiredCertificate,
    #[error("X.509 parse error: {details}")]
    X509Parse { details: String },
    #[error("invalid path length constraint: {details}")]
    InvalidPathLen { details: &'static str },
    #[error("invalid issuer: {details}")]
    InvalidIssuer { details: &'static str },
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error(transparent)]
    Oid(#[from] const_oid::Error),
    #[error(transparent)]
    External(#[from] Box<dyn StdError>),
}
