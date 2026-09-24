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

pub use inner::StreamWriter;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex, MutexGuard};
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

/// Source is the caller's ciphertext reader, with the bookkeeping needed to
/// find where the ciphertext starts in it.
struct Source<R> {
    /// The caller's reader, positioned at the first ciphertext byte when the
    /// stream reader was created.
    reader: R,
    /// Bytes read so far, counted until `start` is known.
    consumed: u64,
    /// Position of the first ciphertext byte in `reader`, pinned by the first seek.
    start: Option<u64>,
}

impl<R: Seek> Source<R> {
    /// Returns the position of the first ciphertext byte in the reader. The
    /// reader can only report its position once seeking is available, so the
    /// bytes read before that are subtracted from it.
    fn start(&mut self) -> io::Result<u64> {
        if let Some(start) = self.start {
            return Ok(start);
        }
        let position = self.reader.stream_position()?;
        let start = position.checked_sub(self.consumed).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "STREAM source position is behind the bytes read from it",
            )
        })?;
        self.start = Some(start);
        Ok(start)
    }
}

/// SharedSource hands one [`Source`] to both the stream reader and its
/// decoder, so a replacement decoder can reuse it.
struct SharedSource<R>(Arc<Mutex<Source<R>>>);

impl<R> SharedSource<R> {
    /// Locks the source, reporting a poisoned lock as an I/O error.
    fn lock(&self) -> io::Result<MutexGuard<'_, Source<R>>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("STREAM source lock poisoned"))
    }
}

impl<R> Clone for SharedSource<R> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<R: Read> Read for SharedSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut source = self.lock()?;
        let n = source.reader.read(buf)?;
        if source.start.is_none() {
            source.consumed += n as u64;
        }
        Ok(n)
    }
}

impl<R: Seek> Seek for SharedSource<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.lock()?.reader.seek(pos)
    }
}

/// StreamReader decrypts a STREAM ciphertext from an underlying reader,
/// authenticating each chunk before returning any of its plaintext.
///
/// With a seekable reader it also supports random access. A failed read can be
/// retried, or followed by a seek elsewhere. A damaged chunk keeps failing
/// wherever it is read, while intact chunks stay readable. After a failed seek,
/// reads fail until a later seek succeeds.
pub struct StreamReader<R> {
    /// Decoder over the shared source, replaced after a failure.
    decoder: inner::StreamReader<SharedSource<R>>,
    /// Handle to the source, kept to build a replacement decoder.
    source: SharedSource<R>,
    /// Key kept to build a replacement decoder, wiped on drop.
    key: PayloadKey,
    /// Plaintext position after the last successful read or seek.
    position: u64,
    /// Whether a failure may have left stale state in the decoder, so the next
    /// seek must replace it first.
    stale: bool,
    /// Whether the last seek failed, leaving no position to read from.
    seek_failed: bool,
}

impl<R: Read> StreamReader<R> {
    /// Creates a stream reader decrypting the ciphertext in `reader` under `key`.
    fn new(key: PayloadKey, reader: R) -> Self {
        let source = SharedSource(Arc::new(Mutex::new(Source {
            reader,
            consumed: 0,
            start: None,
        })));
        Self {
            decoder: Self::decoder(&key, &source),
            source,
            key,
            position: 0,
            stale: false,
            seek_failed: false,
        }
    }

    /// Builds a decoder reading the shared source from its current position.
    fn decoder(key: &PayloadKey, source: &SharedSource<R>) -> inner::StreamReader<SharedSource<R>> {
        inner::Stream::decrypt(inner::PayloadKey(key.0.into()), source.clone())
    }
}

impl<R: Read + Seek> StreamReader<R> {
    /// Replaces the decoder with a fresh one reading from the ciphertext start.
    fn reset(&mut self) -> io::Result<()> {
        {
            let mut source = self.source.lock()?;
            let start = source.start()?;
            source.reader.seek(SeekFrom::Start(start))?;
        }
        self.decoder = Self::decoder(&self.key, &self.source);
        self.stale = false;
        Ok(())
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.seek_failed {
            return Err(io::Error::other("STREAM read after a failed seek"));
        }
        match self.decoder.read(buf) {
            Ok(n) => {
                self.position += n as u64;
                self.stale = false;
                Ok(n)
            }
            Err(err) => {
                // A retry can resume the read, but seeking away needs a fresh decoder
                self.stale = true;
                Err(err)
            }
        }
    }
}

impl<R: Read + Seek> Seek for StreamReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // A fresh decoder starts at zero, so a relative seek is resolved against
        // the last good position instead of the decoder's own
        let pos = match pos {
            SeekFrom::Current(offset) => {
                let target = self.position.checked_add_signed(offset).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid seek to a negative or overflowing position",
                    )
                })?;
                SeekFrom::Start(target)
            }
            pos => pos,
        };
        // Pin the ciphertext start before the source moves, so a reset can find it
        self.source.lock()?.start()?;

        let result = if self.stale {
            self.reset().and_then(|()| self.decoder.seek(pos))
        } else {
            self.decoder.seek(pos)
        };
        match result {
            Ok(position) => {
                self.position = position;
                self.seek_failed = false;
                Ok(position)
            }
            Err(err) => {
                self.stale = true;
                self.seek_failed = true;
                Err(err)
            }
        }
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
        StreamReader::new(key, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Plaintext size, one full chunk followed by a one-byte last chunk.
    const PLAINTEXT_SIZE: u64 = 64 * 1024 + 1;

    /// Unrelated bytes before the ciphertext, so it does not start at offset zero.
    const PREFIX_SIZE: u64 = 23;

    /// Ciphertext offset inside the first chunk where the flaky source fails once.
    const FLAKE_OFFSET: u64 = 100;

    /// Returns the plaintext byte at a position, so reads can check where they landed.
    fn byte_at(position: u64) -> u8 {
        (position % 251) as u8
    }

    /// Encrypts the test plaintext after an unrelated prefix.
    fn ciphertext() -> Vec<u8> {
        let plaintext: Vec<u8> = (0..PLAINTEXT_SIZE).map(byte_at).collect();
        let mut writer = Stream::encrypt(PayloadKey::from([7; 32]), vec![0; PREFIX_SIZE as usize]);
        writer.write_all(&plaintext).unwrap();
        writer.finish().unwrap()
    }

    /// Opens a stream reader past the prefix, as a caller that parsed a header would.
    fn open<R: Read + Seek>(mut source: R) -> StreamReader<R> {
        source.seek(SeekFrom::Start(PREFIX_SIZE)).unwrap();
        Stream::decrypt(PayloadKey::from([7; 32]), source)
    }

    /// Opens a stream reader over a source that fails once inside the first chunk.
    fn open_flaky() -> StreamReader<FlakySource> {
        open(FlakySource {
            inner: Cursor::new(ciphertext()),
            flaked: false,
        })
    }

    /// Reads one byte, returning it or the read error.
    fn read_byte<R: Read>(reader: &mut R) -> io::Result<u8> {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    /// Ciphertext source failing once at FLAKE_OFFSET, after serving the bytes before it.
    struct FlakySource {
        inner: Cursor<Vec<u8>>,
        flaked: bool,
    }

    impl Read for FlakySource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let flake = PREFIX_SIZE + FLAKE_OFFSET;
            let position = self.inner.position();
            if position == flake && !self.flaked {
                self.flaked = true;
                return Err(io::Error::other("transient failure"));
            }
            // Stop at the failure point, so the next read hits it exactly
            let len = if position < flake {
                buf.len().min((flake - position) as usize)
            } else {
                buf.len()
            };
            self.inner.read(&mut buf[..len])
        }
    }

    impl Seek for FlakySource {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    // Tests that a chunk failing authentication keeps failing, while seeking
    // away still reaches intact chunks, with or without the length cached.
    #[test]
    fn test_seek_after_authentication_failure() {
        let mut damaged = ciphertext();
        damaged[PREFIX_SIZE as usize] ^= 1;

        let last = PLAINTEXT_SIZE - 1;
        for cached in [false, true] {
            for failures in [1, 2] {
                let case = format!("cached={cached} failures={failures}");
                let mut reader = open(Cursor::new(damaged.clone()));
                if cached {
                    assert_eq!(
                        reader.seek(SeekFrom::End(0)).unwrap(),
                        PLAINTEXT_SIZE,
                        "{case}"
                    );
                    reader.rewind().unwrap();
                }
                for _ in 0..failures {
                    assert!(read_byte(&mut reader).is_err(), "{case}");
                }
                assert_eq!(reader.seek(SeekFrom::Start(last)).unwrap(), last, "{case}");
                assert_eq!(read_byte(&mut reader).unwrap(), byte_at(last), "{case}");
                assert_eq!(reader.read(&mut [0]).unwrap(), 0, "{case}");

                reader.rewind().unwrap();
                assert!(read_byte(&mut reader).is_err(), "{case}");
            }
        }
    }

    // Tests that after a transient source failure, a seek from any origin
    // resumes reading at the right place, with or without the length cached.
    #[test]
    fn test_seek_after_io_failure() {
        let last = PLAINTEXT_SIZE - 1;
        let targets = [
            (SeekFrom::Start(17), 17),
            (SeekFrom::Start(last), last),
            (SeekFrom::Current(17), 17),
            (SeekFrom::End(-1), last),
        ];
        for cached in [false, true] {
            for (seek, position) in targets {
                let case = format!("cached={cached} seek={seek:?}");
                let mut reader = open_flaky();
                if cached {
                    assert_eq!(
                        reader.seek(SeekFrom::End(0)).unwrap(),
                        PLAINTEXT_SIZE,
                        "{case}"
                    );
                    reader.rewind().unwrap();
                }
                assert!(read_byte(&mut reader).is_err(), "{case}");
                assert_eq!(reader.seek(seek).unwrap(), position, "{case}");
                assert_eq!(read_byte(&mut reader).unwrap(), byte_at(position), "{case}");
            }
        }
    }

    // Tests that a read failing on the source can be retried directly, and
    // that seeking still works afterwards.
    #[test]
    fn test_retry_after_io_failure() {
        let mut reader = open_flaky();
        assert!(read_byte(&mut reader).is_err());
        assert_eq!(read_byte(&mut reader).unwrap(), byte_at(0));
        assert_eq!(read_byte(&mut reader).unwrap(), byte_at(1));

        let last = PLAINTEXT_SIZE - 1;
        assert_eq!(reader.seek(SeekFrom::Start(last)).unwrap(), last);
        assert_eq!(read_byte(&mut reader).unwrap(), byte_at(last));
    }

    // Tests that reads fail after a failed seek until a later seek succeeds,
    // instead of continuing wherever the failed seek left the source.
    #[test]
    fn test_read_after_failed_seek() {
        // Drop the one-byte last chunk and its 16-byte tag, truncating the stream
        let mut truncated = ciphertext();
        truncated.truncate(truncated.len() - (1 + 16));

        let mut reader = open(Cursor::new(truncated));
        assert!(reader.seek(SeekFrom::End(0)).is_err());
        assert!(reader.read(&mut [0]).is_err());

        reader.rewind().unwrap();
        let mut plaintext = Vec::new();
        assert!(reader.read_to_end(&mut plaintext).is_err());
    }

    // Tests that a relative seek out of range fails without moving the reader.
    #[test]
    fn test_invalid_relative_seek() {
        let mut reader = open(Cursor::new(ciphertext()));
        assert_eq!(read_byte(&mut reader).unwrap(), byte_at(0));

        let err = reader.seek(SeekFrom::Current(-2)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(read_byte(&mut reader).unwrap(), byte_at(1));
    }
}
