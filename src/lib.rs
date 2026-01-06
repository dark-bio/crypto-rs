// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Pull in the README as the package doc
#![doc = include_str!("../README.md")]
// Enable the experimental doc_cfg feature
#![cfg_attr(docsrs, feature(doc_cfg))]

// Allow derive macros to reference this crate as `darkbio_crypto` even when
// used internally (proc macros can't distinguish internal vs external use).
extern crate self as darkbio_crypto;

#[cfg(feature = "argon2")]
pub mod argon2;

#[cfg(feature = "hkdf")]
pub mod hkdf;

#[cfg(feature = "cbor")]
pub mod cbor;

#[cfg(feature = "cose")]
pub mod cose;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "mldsa")]
pub mod mldsa;

#[cfg(feature = "pem")]
pub mod pem;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "rand")]
pub mod rand;

#[cfg(feature = "stream")]
pub mod stream;

#[cfg(feature = "x509")]
pub mod x509;

#[cfg(feature = "xdsa")]
pub mod xdsa;

#[cfg(feature = "xhpke")]
pub mod xhpke;
