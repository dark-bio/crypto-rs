// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Pull in the README as the package doc
#![doc = include_str!("../README.md")]
// Enable the experimental doc_cfg feature
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "argon2")]
pub mod argon2;

#[cfg(feature = "cbor")]
pub mod cbor;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "hpke")]
pub mod hpke;

#[cfg(all(feature = "hpke", feature = "cert"))]
pub mod hpke_cert;

#[cfg(feature = "mldsa")]
pub mod mldsa;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "rand")]
pub mod rand;

#[cfg(feature = "stream")]
pub mod stream;
