// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

mod error;
mod issue;
mod name;
mod types;
mod utils;
mod verify;

pub use error::{Error, Result};
pub use name::{Name, NameAttribute};
pub use types::{
    CertificateMetadata, CertificateRole, CertificateTemplate, CustomExtension, ValidityCheck,
    ValidityWindow, VerifiedCertificate,
};
pub use utils::private_enterprise_oid;

pub use issue::{issue_xdsa_cert_der, issue_xdsa_cert_pem};
#[cfg(feature = "xhpke")]
pub use issue::{issue_xhpke_cert_der, issue_xhpke_cert_pem};

pub use verify::{
    verify_xdsa_cert_der, verify_xdsa_cert_der_with_issuer_cert, verify_xdsa_cert_pem,
    verify_xdsa_cert_pem_with_issuer_cert,
};
#[cfg(feature = "xhpke")]
pub use verify::{
    verify_xhpke_cert_der, verify_xhpke_cert_der_with_issuer_cert, verify_xhpke_cert_pem,
    verify_xhpke_cert_pem_with_issuer_cert,
};
