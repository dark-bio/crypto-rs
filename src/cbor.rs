// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Tiny CBOR encoder and decoder.
//!
//! This is an implementation of the CBOR spec with an extremely reduced type
//! system, focusing on security rather than flexibility or completeness. The
//! following types are supported:
//! - 64bit positive integers: u64
//! - UTF-8 text strings:      String, &str
//! - Byte strings:            Vec<u8>, &[u8], [u8; N]
//! - Arrays:                  (), (X,), (X,Y), ... tuples

// Supported CBOR major types
const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;

// Additional info values
const INFO_UINT8: u8 = 24;
const INFO_UINT16: u8 = 25;
const INFO_UINT32: u8 = 26;
const INFO_UINT64: u8 = 27;

/// Error is the failures that can occur while encoding or decoding CBOR data.
#[derive(Debug)]
pub enum Error {
    InvalidMajorType(u8, u8),
    InvalidAdditionalInfo(u8),
    UnexpectedEof,
    NonCanonical,
    InvalidUtf8,
    TrailingBytes,
    UnexpectedItemCount(usize, usize),
    UnsupportedType(u8),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidMajorType(h, w) => {
                write!(f, "invalid major type: {}, want {}", h, w)
            }
            Error::InvalidAdditionalInfo(i) => {
                write!(f, "invalid additional info: {}", i)
            }
            Error::UnexpectedEof => {
                write!(f, "unexpected end of data")
            }
            Error::NonCanonical => {
                write!(f, "non-canonical encoding")
            }
            Error::InvalidUtf8 => {
                write!(f, "invalid UTF-8 in text string")
            }
            Error::TrailingBytes => {
                write!(f, "unexpected trailing bytes")
            }
            Error::UnexpectedItemCount(h, w) => {
                write!(f, "unexpected item count: {}, want {}", h, w)
            }
            Error::UnsupportedType(t) => {
                write!(f, "unsupported type: {}", t)
            }
        }
    }
}

impl std::error::Error for Error {}

/// encode attempts to encode a generic Rust value to CBOR using the tiny, strict
/// subset of types permitted by this package.
pub fn encode<T: Encode>(value: &T) -> Vec<u8> {
    value.encode_cbor()
}

/// decode attempts to decode a CBOR blob into a generic Rust type using the tiny,
/// strict subset of types permitted by this package.
pub fn decode<T: Decode>(data: &[u8]) -> Result<T, Error> {
    T::decode_cbor(data)
}

/// verify does a dry-run decoding to verify that only the tiny, strict subset of
/// types permitted by this package were used.
pub fn verify(data: &[u8]) -> Result<(), Error> {
    let mut decoder = Decoder::new(data);
    verify_object(&mut decoder)?;
    decoder.finish()
}

// Encoder is the low level implementation of the CBOR encoder with only the
// handful of desired types supported.
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    // new creates a CBOR encoder with an underlying buffer, pre-allocated to
    // 1KB (small enough not to be relevant, large enough to avoid tiny appends).
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024),
        }
    }

    // finish terminates encoding and retrieves the accumulated CBOR data.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    // encode_uint encodes a positive integer into its canonical shortest-form.
    pub fn encode_uint(&mut self, value: u64) {
        // Piggyback on the length encoder to avoid duplicating code
        self.encode_length(MAJOR_UINT, value);
    }

    // encode_bytes encodes an opaque byte string.
    pub fn encode_bytes(&mut self, value: &[u8]) {
        self.encode_length(MAJOR_BYTES, value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    // encode_text encodes a UTF-8 text string.
    pub fn encode_text(&mut self, value: &str) {
        self.encode_length(MAJOR_TEXT, value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    // encode_array_header encodes an array size.
    pub fn encode_array_header(&mut self, len: usize) {
        self.encode_length(MAJOR_ARRAY, len as u64);
    }

    // encode_empty_tuple special cases the empty tuple to encode as [].
    pub fn encode_empty_tuple(&mut self) {
        self.encode_array_header(0);
    }

    // encode_length encodes a major type, injecting an unsigned integer after,
    // which will for most types define the length. For integers, it will simply
    // be the value itself.
    fn encode_length(&mut self, major_type: u8, len: u64) {
        if len < 24 {
            self.buf.push(major_type << 5 | len as u8);
        } else if len <= u8::MAX as u64 {
            self.buf.push(major_type << 5 | INFO_UINT8);
            self.buf.push(len as u8);
        } else if len <= u16::MAX as u64 {
            self.buf.push(major_type << 5 | INFO_UINT16);
            self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else if len <= u32::MAX as u64 {
            self.buf.push(major_type << 5 | INFO_UINT32);
            self.buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            self.buf.push(major_type << 5 | INFO_UINT64);
            self.buf.extend_from_slice(&len.to_be_bytes());
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

// Decoder is the low level implementation of the CBOR decoder with only the
// handful of desired types supported.
#[derive(Clone)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    // new creates a decoder around a data blob.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    // finish terminates decoding and returns whether trailing bytes linger.
    pub fn finish(self) -> Result<(), Error> {
        if self.pos != self.data.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(())
    }

    // decode_uint decodes a positive integer, enforcing minimal canonicalness.
    pub fn decode_uint(&mut self) -> Result<u64, Error> {
        // Extract the field type and attached value
        let (major, value) = self.decode_header()?;
        if major != MAJOR_UINT {
            return Err(Error::InvalidMajorType(major, MAJOR_UINT));
        }
        Ok(value)
    }

    // decode_bytes decodes a byte string.
    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_BYTES {
            return Err(Error::InvalidMajorType(major, MAJOR_BYTES));
        }
        // Retrieve the blob and return as is
        let bytes = self.read_bytes(len as usize)?;
        Ok(bytes.to_vec())
    }

    // decode_bytes_fixed decodes a byte string into a fixed-size array.
    pub fn decode_bytes_fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_BYTES {
            return Err(Error::InvalidMajorType(major, MAJOR_BYTES));
        }
        // Check that the length matches the expected array size
        if len as usize != N {
            return Err(Error::UnexpectedItemCount(len as usize, N));
        }
        // Retrieve the bytes and copy into the fixed-size array
        let bytes = self.read_bytes(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    // decode_text decodes a UTF-8 text string.
    pub fn decode_text(&mut self) -> Result<String, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_TEXT {
            return Err(Error::InvalidMajorType(major, MAJOR_TEXT));
        }
        // Retrieve the blob and reinterpret as UTF-8
        let bytes = self.read_bytes(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
    }

    // decode_array_header decodes an array header, returning its length.
    pub fn decode_array_header(&mut self) -> Result<usize, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_ARRAY {
            return Err(Error::InvalidMajorType(major, MAJOR_ARRAY));
        }
        Ok(len as usize)
    }

    // decode_header extracts the major type for the next field and the integer
    // value embedded as the additional info.
    fn decode_header(&mut self) -> Result<(u8, u64), Error> {
        // Ensure there's still data left in the buffer
        if self.pos >= self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        // Extract the type byte and split it apart
        let byte = self.data[self.pos];
        self.pos += 1;

        let major = byte >> 5;
        let info = byte & 0x1f;

        // Extract the integer embedded in the info
        let value = match info {
            0..=23 => Ok(info as u64),
            INFO_UINT8 => {
                let bytes = self.read_bytes(1)?;
                Ok(bytes[0] as u64)
            }
            INFO_UINT16 => {
                let bytes = self.read_bytes(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            INFO_UINT32 => {
                let bytes = self.read_bytes(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            INFO_UINT64 => {
                let bytes = self.read_bytes(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => Err(Error::InvalidAdditionalInfo(info)),
        }?;

        // Ensure it was canonical in the first place
        if !match info {
            0..=23 => value < 24,
            INFO_UINT8 => value >= 24 && value <= u8::MAX as u64,
            INFO_UINT16 => value > u8::MAX as u64 && value <= u16::MAX as u64,
            INFO_UINT32 => value > u16::MAX as u64 && value <= u32::MAX as u64,
            INFO_UINT64 => value > u32::MAX as u64,
            _ => false,
        } {
            return Err(Error::NonCanonical);
        }
        Ok((major, value))
    }

    // read_bytes retrieves the next handful of bytes from the buffer.
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        // Ensure there's still enough data left in the buffer
        if self.pos + len > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        // Retrieve the byte and move the cursor forward
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;

        Ok(bytes)
    }

    // skip_bytes advances the position without retrieving the data.
    fn skip_bytes(&mut self, len: usize) -> Result<(), Error> {
        // Ensure there's still enough data left in the buffer
        if self.pos + len > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        // Ignore the data, just move the cursor forward
        self.pos += len;
        Ok(())
    }
}

/// Encode is the interface needed to encode a type to CBOR.
pub trait Encode {
    // encode_cbor converts the type to CBOR.
    fn encode_cbor(&self) -> Vec<u8>;
}

/// Decode is the interface needed to decode a type from CBOR.
pub trait Decode: Sized {
    // decode_cbor converts CBOR to the type.
    fn decode_cbor(data: &[u8]) -> Result<Self, Error>;

    // decode_cbor_notrail converts CBOR to the type, ignoring any trailing data.
    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error>;
}

// Encoder and decoder implementation for positive integers.
impl Encode for u64 {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_uint(*self);
        encoder.finish()
    }
}

impl Decode for u64 {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_uint()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_uint()
    }
}

// Encoder and decoder implementation for dynamic byte blobs.
impl Encode for Vec<u8> {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_bytes(self);
        encoder.finish()
    }
}

impl Encode for &Vec<u8> {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_bytes(self);
        encoder.finish()
    }
}

impl Encode for &[u8] {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_bytes(self);
        encoder.finish()
    }
}

impl Decode for Vec<u8> {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_bytes()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_bytes()
    }
}

// Encoder and decoder implementation for fixed byte blobs.
impl<const N: usize> Encode for [u8; N] {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_bytes(self);
        encoder.finish()
    }
}

impl<const N: usize> Encode for &[u8; N] {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_bytes(*self);
        encoder.finish()
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_bytes_fixed::<N>()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_bytes_fixed::<N>()
    }
}

// Encoder and decoder implementation for UTF-8 strings.
impl Encode for String {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_text(self);
        encoder.finish()
    }
}

impl Encode for &String {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_text(self);
        encoder.finish()
    }
}

impl Encode for &str {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_text(self);
        encoder.finish()
    }
}

impl Decode for String {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_text()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_text()
    }
}

// Encoder and decoder implementation for the empty tuple.
impl Encode for () {
    fn encode_cbor(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.encode_empty_tuple();
        encoder.finish()
    }
}

impl Decode for () {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let len = decoder.decode_array_header()?;
        if len != 0 {
            return Err(Error::UnexpectedItemCount(len, 0));
        }
        decoder.finish()?;
        Ok(())
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let len = decoder.decode_array_header()?;
        if len != 0 {
            return Err(Error::UnexpectedItemCount(len, 0));
        }
        Ok(())
    }
}

// Encoder and decoder implementation for real tuples.
macro_rules! impl_tuple {
    ($($t:ident),+) => {
        impl<$($t: Encode),+> Encode for ($($t,)+) {
            fn encode_cbor(&self) -> Vec<u8> {
                let mut encoder = Encoder::new();

                // Encode the length of the tuple
                let len = args!($($t),+);
                encoder.encode_array_header(len);

                // Encode all the tuple elements individually
                let ($($t,)+) = self;
                $(encoder.buf.extend_from_slice(&$t.encode_cbor());)+
                encoder.finish()
            }
        }

        impl<$($t: Decode),+> Decode for ($($t,)+) {
            fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
                let mut decoder = Decoder::new(data);

                // Decode the length of the tuple
                let len = decoder.decode_array_header()?;
                let exp = args!($($t),+);
                if len != exp {
                    return Err(Error::UnexpectedItemCount(len, exp));
                }
                // Decode all the tuple elements individually
                $(
                    let $t = $t::decode_cbor_notrail(&mut decoder)?;
                )+
                decoder.finish()?;
                Ok(($($t,)+))
            }

            fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
                // Decode the length of the tuple
                let len = decoder.decode_array_header()?;
                let exp = args!($($t),+);
                if len != exp {
                    return Err(Error::UnexpectedItemCount(len, exp));
                }
                // Decode all the tuple elements individually
                $(
                    let $t = $t::decode_cbor_notrail(decoder)?;
                )+
                Ok(($($t,)+))
            }
        }
    };
}

macro_rules! args {
    ($($t:ident),+) => { args!(@count $($t),+) };
    (@count $t1:ident) => { 1 };
    (@count $t1:ident, $($t:ident),+) => { 1 + args!(@count $($t),+) };
}

#[allow(non_snake_case)]
mod tuple_impls {
    use super::*;

    impl_tuple!(T1);
    impl_tuple!(T1, T2);
    impl_tuple!(T1, T2, T3);
    impl_tuple!(T1, T2, T3, T4);
    impl_tuple!(T1, T2, T3, T4, T5);
    impl_tuple!(T1, T2, T3, T4, T5, T6);
    impl_tuple!(T1, T2, T3, T4, T5, T6, T7);
    impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8);
}

// verify_object is an internal function to verify a single CBOR item without
// full deserialization.
fn verify_object(decoder: &mut Decoder) -> Result<(), Error> {
    let (major, value) = decoder.decode_header()?;

    match major {
        MAJOR_UINT => {
            // Positive integers are always valid (canonicalness was already
            // verified in the header decoding)
            Ok(())
        }
        MAJOR_BYTES => {
            // Opaque bytes are always valid, skip over
            decoder.skip_bytes(value as usize)
        }
        MAJOR_TEXT => {
            // Verify that the text is indeed UTF-8
            let bytes = decoder.read_bytes(value as usize)?;
            std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
            Ok(())
        }
        MAJOR_ARRAY => {
            // Recursively verify each array element
            let len = value as usize;
            for _ in 0..len {
                verify_object(decoder)?;
            }
            Ok(())
        }
        _ => {
            // Any other major type is disallowed
            Err(Error::UnsupportedType(major))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that positive integers encode correctly across the various ranges
    // that CBOR special cases.
    #[test]
    fn test_uint_encoding() {
        let cases = [
            (0u64, vec![0x00]),
            (23u64, vec![0x17]),
            (24u64, vec![0x18, 0x18]),
            (u8::MAX as u64, vec![0x18, 0xff]),
            (u8::MAX as u64 + 1, vec![0x19, 0x01, 0x00]),
            (u16::MAX as u64, vec![0x19, 0xff, 0xff]),
            (u16::MAX as u64 + 1, vec![0x1a, 0x00, 0x01, 0x00, 0x00]),
            (u32::MAX as u64, vec![0x1a, 0xff, 0xff, 0xff, 0xff]),
            (
                u32::MAX as u64 + 1,
                vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                u64::MAX,
                vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(
                encode(&value),
                expected,
                "encoding failed for value {}",
                value
            );
        }
    }

    // Tests that positive integers decode correctly across the various ranges
    // that CBOR special cases.
    #[test]
    fn test_uint_decoding() {
        let cases = [
            (vec![0x00], 0u64),
            (vec![0x17], 23u64),
            (vec![0x18, 0x18], 24u64),
            (vec![0x18, 0xff], u8::MAX as u64),
            (vec![0x19, 0x01, 0x00], u8::MAX as u64 + 1),
            (vec![0x19, 0xff, 0xff], u16::MAX as u64),
            (vec![0x1a, 0x00, 0x01, 0x00, 0x00], u16::MAX as u64 + 1),
            (vec![0x1a, 0xff, 0xff, 0xff, 0xff], u32::MAX as u64),
            (
                vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
                u32::MAX as u64 + 1,
            ),
            (
                vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                u64::MAX,
            ),
        ];

        for (data, expected) in cases {
            assert_eq!(
                decode::<u64>(&data).unwrap(),
                expected,
                "decoding failed for data {:?}",
                data
            );
        }
    }

    // Tests that positive integers are rejected for invalid size / encoding
    // combinations.
    #[test]
    fn test_uint_rejection() {
        // Values 0-23 must use direct embedding
        for value in 0..24u64 {
            // Should fail with INFO_UINT8
            let mut data = vec![MAJOR_UINT << 5 | INFO_UINT8, value as u8];
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT16
            data = vec![MAJOR_UINT << 5 | INFO_UINT16];
            data.extend_from_slice(&(value as u16).to_be_bytes());
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT32
            data = vec![MAJOR_UINT << 5 | INFO_UINT32];
            data.extend_from_slice(&(value as u32).to_be_bytes());
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT64
            data = vec![MAJOR_UINT << 5 | INFO_UINT64];
            data.extend_from_slice(&value.to_be_bytes());
            assert!(decode::<u64>(&data).is_err());
        }

        // Values 24-255 must use INFO_UINT8
        for value in 24..=u8::MAX as u64 {
            // Should fail with INFO_UINT16
            let mut data = vec![MAJOR_UINT << 5 | INFO_UINT16];
            data.extend_from_slice(&(value as u16).to_be_bytes());
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT32
            data = vec![MAJOR_UINT << 5 | INFO_UINT32];
            data.extend_from_slice(&(value as u32).to_be_bytes());
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT64
            data = vec![MAJOR_UINT << 5 | INFO_UINT64];
            data.extend_from_slice(&value.to_be_bytes());
            assert!(decode::<u64>(&data).is_err());
        }

        // Values 256-65535 must use INFO_UINT16
        for value in [(u8::MAX as u64 + 1), u16::MAX as u64] {
            // Should fail with INFO_UINT32
            let mut data = vec![MAJOR_UINT << 5 | INFO_UINT32];
            data.extend_from_slice(&(value as u32).to_be_bytes());
            assert!(decode::<u64>(&data).is_err());

            // Should fail with INFO_UINT64
            data = vec![MAJOR_UINT << 5 | INFO_UINT64];
            data.extend_from_slice(&value.to_be_bytes());
            assert!(decode::<u64>(&data).is_err());
        }

        // Values 65536-4294967295 must use INFO_UINT32
        for value in [(u16::MAX as u64 + 1), u32::MAX as u64] {
            // Should fail with INFO_UINT64
            let mut data = vec![MAJOR_UINT << 5 | INFO_UINT64];
            data.extend_from_slice(&value.to_be_bytes());
            assert!(decode::<u64>(&data).is_err());
        }
    }

    // Tests that byte strings encode correctly on a bunch of samples.
    #[test]
    fn test_bytes_encoding() {
        // Empty bytes
        let empty: Vec<u8> = vec![];
        let encoded = encode(&empty);
        assert_eq!(encoded, vec![0x40]); // major 2, length 0

        // 1 byte
        let one_byte = vec![0xaa];
        let encoded = encode(&one_byte);
        assert_eq!(encoded, vec![0x41, 0xaa]); // major 2, length 1, data

        // Longer bytes
        let long_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = encode(&long_bytes);
        assert_eq!(encoded, vec![0x44, 0xde, 0xad, 0xbe, 0xef]); // major 2, length 4, data

        // Test &Vec<u8> reference
        let bytes_vec = vec![1, 2, 3];
        let bytes_vec_ref = &bytes_vec;
        let encoded = encode(&bytes_vec_ref);
        assert_eq!(encoded, vec![0x43, 1, 2, 3]);

        // Test &[u8] slice reference
        let bytes_slice: &[u8] = &[4, 5, 6];
        let encoded = encode(&bytes_slice);
        assert_eq!(encoded, vec![0x43, 4, 5, 6]);

        // Test [u8; N] fixed-size array
        let bytes_array: [u8; 3] = [7, 8, 9];
        let encoded = encode(&bytes_array);
        assert_eq!(encoded, vec![0x43, 7, 8, 9]);

        // Test &[u8; N] fixed-size array reference
        let bytes_array_ref = &[10u8, 11, 12];
        let encoded = encode(&bytes_array_ref);
        assert_eq!(encoded, vec![0x43, 10, 11, 12]);
    }

    // Tests that byte strings decode correctly on a bunch of samples.
    #[test]
    fn test_bytes_decoding() {
        // Empty bytes
        let encoded = vec![0x40];
        let decoded = decode::<Vec<u8>>(&encoded).unwrap();
        assert_eq!(decoded, Vec::<u8>::new());

        // 1 byte
        let encoded = vec![0x41, 0xaa];
        let decoded = decode::<Vec<u8>>(&encoded).unwrap();
        assert_eq!(decoded, vec![0xaa]);

        // Longer bytes
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let mut encoded = vec![0x44]; // major 2, length 4
        encoded.extend_from_slice(&data);
        let decoded = decode::<Vec<u8>>(&encoded).unwrap();
        assert_eq!(decoded, data);

        // Test fixed-size array decoding
        let encoded = vec![0x43, 1, 2, 3]; // major 2, length 3, data [1,2,3]
        let decoded = decode::<[u8; 3]>(&encoded).unwrap();
        assert_eq!(decoded, [1, 2, 3]);

        // Test empty fixed-size array
        let encoded = vec![0x40]; // major 2, length 0
        let decoded = decode::<[u8; 0]>(&encoded).unwrap();
        assert_eq!(decoded, []);
    }

    // Tests that bytes decoding fails when fixed size lengths don't match.
    #[test]
    fn test_bytes_rejection() {
        // Try to decode 3 bytes into a 4-byte array
        let encoded = vec![0x43, 1, 2, 3]; // major 2, length 3
        let result = decode::<[u8; 4]>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(3, 4) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(3, 4) error, got {:?}", other),
        }

        // Try to decode 4 bytes into a 2-byte array
        let encoded = vec![0x44, 1, 2, 3, 4]; // major 2, length 4
        let result = decode::<[u8; 2]>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(4, 2) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(4, 2) error, got {:?}", other),
        }
    }

    // Tests that UTF-8 strings encode correctly on a bunch of samples.
    #[test]
    fn test_string_encoding() {
        // Empty string
        let empty = "";
        let encoded = encode(&empty);
        assert_eq!(encoded, vec![0x60]); // major 3, length 0

        // 1 character
        let one_char = "a";
        let encoded = encode(&one_char);
        assert_eq!(encoded, vec![0x61, 0x61]); // major 3, length 1, 'a'

        // Longer string
        let long_string = "Peter says hi!";
        let encoded = encode(&long_string);
        assert_eq!(encoded[0], 0x60 | long_string.len() as u8); // major 3, length embedded
        assert_eq!(&encoded[1..], long_string.as_bytes());

        // Test String type
        let string_type = "Peter says hi!".to_string();
        let encoded = encode(&string_type);
        assert_eq!(encoded[0], 0x60 | string_type.len() as u8); // major 3, length embedded
        assert_eq!(&encoded[1..], string_type.as_bytes());

        // Test &String type
        let string_ref = &"Peter says hi!".to_string();
        let encoded = encode(&string_ref);
        assert_eq!(encoded[0], 0x60 | string_ref.len() as u8); // major 3, length embedded
        assert_eq!(&encoded[1..], string_ref.as_bytes());
    }

    // Tests that UTF-8 strings decode correctly on a bunch of samples.
    #[test]
    fn test_string_decoding() {
        // Empty string
        let encoded = vec![0x60];
        let decoded = decode::<String>(&encoded).unwrap();
        assert_eq!(decoded, "");

        // 1 character
        let encoded = vec![0x61, 0x61];
        let decoded = decode::<String>(&encoded).unwrap();
        assert_eq!(decoded, "a");

        // Longer string
        let test_str = "Peter says hi!";
        let mut encoded = vec![0x60 | test_str.len() as u8];
        encoded.extend_from_slice(test_str.as_bytes());
        let decoded = decode::<String>(&encoded).unwrap();
        assert_eq!(decoded, test_str);
    }

    // Tests that UTF-8 strings are rejected if containing invalid data.
    #[test]
    fn test_string_rejection() {
        // 0xff is not valid UTF-8
        let encoded = vec![0x61, 0xff]; // major 3, length 1, invalid byte
        let result = decode::<String>(&encoded);
        assert!(result.is_err());

        match result.unwrap_err() {
            Error::InvalidUtf8 => {} // Expected error
            other => panic!("Expected InvalidUtf8 error, got {:?}", other),
        }

        // Incomplete multi-byte sequence
        let encoded = vec![0x62, 0xc2, 0x00]; // major 3, length 2, incomplete UTF-8
        let result = decode::<String>(&encoded);
        assert!(result.is_err());

        match result.unwrap_err() {
            Error::InvalidUtf8 => {} // Expected error
            other => panic!("Expected InvalidUtf8 error, got {:?}", other),
        }

        // Length overflows
        let encoded = vec![123, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];
        let result = decode::<String>(&encoded);
        assert!(result.is_err());
    }

    // Tests that tuples encode correctly on a bunch of samples.
    #[test]
    fn test_tuple_encoding() {
        // 0-tuple
        let empty = ();
        let encoded = encode(&empty);
        assert_eq!(encoded, vec![0x80]); // major 4, length 0 (empty array)

        // 1-tuple (wonky Rust syntax)
        let one_tuple = (42u64,);
        let encoded = encode(&one_tuple);
        assert_eq!(encoded[0], 0x81); // major 4, length 1 (array with 1 element)
        assert_eq!(encoded[1], 0x18); // major 0, INFO_UINT8
        assert_eq!(encoded[2], 42);

        // 2-tuple
        let t = ("hello".to_string(), 42u64);
        let encoded = encode(&t);
        assert_eq!(encoded[0], 0x82); // major 4, length 2 (array with 2 elements)
        // First element: "hello" -> 0x65 + "hello" bytes
        assert_eq!(encoded[1], 0x65); // major 3, length 5
        assert_eq!(&encoded[2..7], b"hello");
        // Second element: 42 -> 0x182a
        assert_eq!(encoded[7], 0x18); // major 0, INFO_UINT8
        assert_eq!(encoded[8], 42);
    }

    // Tests that tuples decode correctly on a bunch of samples.
    #[test]
    fn test_tuple_decoding() {
        // 0-tuple
        let encoded = vec![0x80]; // empty array
        let decoded = decode::<()>(&encoded).unwrap();
        assert_eq!(decoded, ());

        // 1-tuple (wonky Rust syntax)
        let mut encoded = vec![0x81]; // array length 1
        encoded.extend_from_slice(&encode(&42u64)); // single element
        let decoded = decode::<(u64,)>(&encoded).unwrap();
        assert_eq!(decoded, (42u64,));

        // 2-tuple
        let mut encoded = vec![0x82]; // array length 2
        encoded.extend_from_slice(&encode(&"hello".to_string())); // first element
        encoded.extend_from_slice(&encode(&42u64)); // second element
        let decoded = decode::<(String, u64)>(&encoded).unwrap();
        assert_eq!(decoded, ("hello".to_string(), 42u64));
    }

    // Tests that tuples are rejected if the size of the array does not match the
    // expected size.
    #[test]
    fn test_tuple_rejection() {
        // Try to decode array with 1 element as 2-tuple
        let mut encoded = vec![0x81]; // array length 1
        encoded.extend_from_slice(&encode(&42u64)); // single element
        let result = decode::<(u64, u64)>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(1, 2) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(1, 2) error, got {:?}", other),
        }

        // Try to decode array with 3 elements as 2-tuple
        let mut encoded = vec![0x83]; // array length 3
        encoded.extend_from_slice(&encode(&42u64));
        encoded.extend_from_slice(&encode(&"test".to_string()));
        encoded.extend_from_slice(&encode(&vec![1u8, 2]));
        let result = decode::<(u64, String)>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(3, 2) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(3, 2) error, got {:?}", other),
        }

        // Try to decode array with 1 element as empty tuple
        let mut encoded = vec![0x81]; // array length 1
        encoded.extend_from_slice(&encode(&42u64));
        let result = decode::<()>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(1, 0) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(1, 0) error, got {:?}", other),
        }
    }

    // Tests that the dry-decoding verifier properly restricts the allowed types.
    #[test]
    fn test_verify() {
        // Valid types should pass
        assert!(verify(&encode(&42u64)).is_ok());
        assert!(verify(&encode(&"hello")).is_ok());
        assert!(verify(&encode(&vec![1u8, 2, 3])).is_ok());
        assert!(verify(&encode(&())).is_ok());
        assert!(verify(&encode(&(42u64, "test"))).is_ok());

        // Trailing bytes
        let mut bad_data = encode(&42u64);
        bad_data.push(0x00);
        assert!(verify(&bad_data).is_err());
        match verify(&bad_data).unwrap_err() {
            Error::TrailingBytes => {}
            other => panic!("Expected TrailingBytes error, got {:?}", other),
        }

        // Major type 1 (negative integers) - unsupported
        let negative_int = vec![0x20]; // -1 in CBOR
        assert!(verify(&negative_int).is_err());
        match verify(&negative_int).unwrap_err() {
            Error::UnsupportedType(1) => {}
            other => panic!("Expected UnsupportedType(1) error, got {:?}", other),
        }

        // Major type 5 (maps) - unsupported
        let map_data = vec![0xa1, 0x61, 0x61, 0x61, 0x62]; // {"a": "b"}
        assert!(verify(&map_data).is_err());
        match verify(&map_data).unwrap_err() {
            Error::UnsupportedType(5) => {}
            other => panic!("Expected UnsupportedType(5) error, got {:?}", other),
        }

        // Major type 6 (tags) - unsupported
        let tagged_data = vec![
            0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32,
            0x30, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a,
        ]; // tag 0 datetime
        assert!(verify(&tagged_data).is_err());
        match verify(&tagged_data).unwrap_err() {
            Error::UnsupportedType(6) => {}
            other => panic!("Expected UnsupportedType(6) error, got {:?}", other),
        }

        // Major type 7 (floats/booleans/null/undefined) - unsupported
        // Boolean false
        let bool_false = vec![0xf4];
        assert!(verify(&bool_false).is_err());
        match verify(&bool_false).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Boolean true
        let bool_true = vec![0xf5];
        assert!(verify(&bool_true).is_err());
        match verify(&bool_true).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // null
        let null_val = vec![0xf6];
        assert!(verify(&null_val).is_err());
        match verify(&null_val).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // undefined
        let undefined_val = vec![0xf7];
        assert!(verify(&undefined_val).is_err());
        match verify(&undefined_val).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Float16
        let float16 = vec![0xf9, 0x3c, 0x00]; // 1.0 as float16
        assert!(verify(&float16).is_err());
        match verify(&float16).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Float32
        let float32 = vec![0xfa, 0x3f, 0x80, 0x00, 0x00]; // 1.0 as float32
        assert!(verify(&float32).is_err());
        match verify(&float32).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Float64
        let float64 = vec![0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 1.0 as float64
        assert!(verify(&float64).is_err());
        match verify(&float64).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Invalid UTF-8 in text string
        let invalid_text = vec![0x61, 0xff]; // text string with invalid UTF-8
        assert!(verify(&invalid_text).is_err());
        match verify(&invalid_text).unwrap_err() {
            Error::InvalidUtf8 => {}
            other => panic!("Expected InvalidUtf8 error, got {:?}", other),
        }

        // Non-canonical encodings
        let non_canonical = vec![0x18, 0x10]; // 16 encoded as INFO_UINT8 instead of direct
        assert!(verify(&non_canonical).is_err());
        match verify(&non_canonical).unwrap_err() {
            Error::NonCanonical => {}
            other => panic!("Expected NonCanonical error, got {:?}", other),
        }

        // Nested arrays with invalid content
        let nested_invalid = vec![0x81, 0xf4]; // [false]
        assert!(verify(&nested_invalid).is_err());
        match verify(&nested_invalid).unwrap_err() {
            Error::UnsupportedType(7) => {}
            other => panic!("Expected UnsupportedType(7) error, got {:?}", other),
        }

        // Incomplete data
        let incomplete = vec![0x61]; // text string header without data
        assert!(verify(&incomplete).is_err());
        match verify(&incomplete).unwrap_err() {
            Error::UnexpectedEof => {}
            other => panic!("Expected UnexpectedEof error, got {:?}", other),
        }

        // Invalid additional info
        let invalid_info = vec![0x1c]; // UINT with additional info 28 (reserved)
        assert!(verify(&invalid_info).is_err());
        match verify(&invalid_info).unwrap_err() {
            Error::InvalidAdditionalInfo(28) => {}
            other => panic!("Expected InvalidAdditionalInfo(28) error, got {:?}", other),
        }
    }
}
