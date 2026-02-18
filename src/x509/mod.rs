// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! X.509 certificate issuance and verification.
//!
//! https://datatracker.ietf.org/doc/html/rfc5280

mod error;
pub(crate) mod issue;
mod name;
mod types;
mod utils;
pub(crate) mod verify;

pub use error::{Error, Result};
pub use name::{Name, NameAttribute};
pub use types::{
    CertificateMetadata, CertificateRole, CertificateTemplate, CustomExtension, ValidityCheck,
    ValidityWindow, VerifiedCertificate,
};
pub use utils::private_enterprise_oid;
