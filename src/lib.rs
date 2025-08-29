// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#![doc = include_str!("../README.md")]

#[cfg(feature = "cbor")]
pub mod cbor;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "hpke")]
pub mod hpke;

#[cfg(all(feature = "hpke", feature = "cert"))]
pub mod hpke_cert;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "stream")]
pub mod stream;
