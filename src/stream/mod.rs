// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Streaming authenticated encryption based on age's STREAM construction.
//!
//! The implementation lives in the `inner` module, which is a maintained
//! verbatim fork of age's stream primitive. This module wraps it with the
//! crate's own public API surface.
//!
//! Plaintext is split into 64 KiB chunks, each sealed with ChaCha20-Poly1305
//! under a nonce that counts up and marks the final chunk, so truncation and
//! reordering are detected. [`StreamWriter::finish`] must be called for the
//! last chunk to be written out.
//!
//! ```
//! use darkbio_crypto::stream::{PayloadKey, Stream};
//! use std::io::{Read, Write};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Derive a fresh key per stream in real code, never reuse one
//! let key = [7u8; 32];
//!
//! let mut writer = Stream::encrypt(PayloadKey::from_bytes(&key), Vec::new());
//! writer.write_all(b"hello stream")?;
//! let ciphertext = writer.finish()?;
//!
//! let mut reader = Stream::decrypt(PayloadKey::from_bytes(&key), ciphertext.as_slice());
//! let mut plaintext = Vec::new();
//! reader.read_to_end(&mut plaintext)?;
//! assert_eq!(plaintext, b"hello stream");
//! # Ok(())
//! # }
//! ```

mod inner;

#[cfg(all(test, feature = "hkdf"))]
mod cctv;

pub use inner::{StreamReader, StreamWriter};

use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// Size of the payload key in bytes.
pub const PAYLOAD_KEY_SIZE: usize = 32;

/// PayloadKey is the symmetric key encrypting or decrypting a stream.
///
/// The key must **never** be repeated across multiple streams. Derive it with
/// HKDF from both a random file key and a random nonce.
pub struct PayloadKey([u8; PAYLOAD_KEY_SIZE]);

impl PayloadKey {
    /// from_bytes converts a 32-byte array into a payload key.
    pub fn from_bytes(bin: &[u8; PAYLOAD_KEY_SIZE]) -> Self {
        Self(*bin)
    }

    /// to_bytes converts a payload key into a 32-byte array.
    pub fn to_bytes(&self) -> Zeroizing<[u8; PAYLOAD_KEY_SIZE]> {
        Zeroizing::new(self.0)
    }
}

impl From<[u8; PAYLOAD_KEY_SIZE]> for PayloadKey {
    fn from(bin: [u8; PAYLOAD_KEY_SIZE]) -> Self {
        Self(bin)
    }
}

impl Drop for PayloadKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Stream is the STREAM construction for online authenticated encryption,
/// instantiated with ChaCha20-Poly1305 in 64KiB chunks.
pub struct Stream;

impl Stream {
    /// encrypt wraps STREAM encryption under the given key around a writer.
    pub fn encrypt<W: Write>(key: PayloadKey, writer: W) -> StreamWriter<W> {
        inner::Stream::encrypt(inner::PayloadKey(key.0.into()), writer)
    }

    /// decrypt wraps STREAM decryption under the given key around a reader.
    pub fn decrypt<R: Read>(key: PayloadKey, reader: R) -> StreamReader<R> {
        inner::Stream::decrypt(inner::PayloadKey(key.0.into()), reader)
    }
}
