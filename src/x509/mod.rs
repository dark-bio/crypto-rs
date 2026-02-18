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

pub(crate) use issue::issue_cert;
pub(crate) use verify::verify_cert;

pub use error::{Error, Result};
pub use name::{Name, NameAttribute};
pub use types::{Certificate, Extension, Role, ValidityCheck, Verified};
