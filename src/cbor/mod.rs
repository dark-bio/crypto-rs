// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Tiny CBOR encoder and decoder.
//!
//! https://datatracker.ietf.org/doc/html/rfc8949
//!
//! This is an implementation of the CBOR spec with an extremely reduced type
//! system, focusing on security rather than flexibility or completeness. The
//! following types are supported:
//! - Booleans:                bool
//! - Null:                    Option<T>::None, cbor::Null
//! - 64bit positive integers: u64
//! - 64bit signed integers:   i64
//! - UTF-8 text strings:      String, &str
//! - Byte strings:            Vec<u8>, &[u8], [u8; N]
//! - Arrays:                  (), (X,), (X,Y), ... tuples, or structs with #[cbor(array)]
//! - Maps:                    structs with #[cbor(key = N)] fields, Option<T>::None omitted

pub use darkbio_crypto_cbor_derive::Cbor;

use std::cmp::Ordering;

// Supported CBOR major types
const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

// Additional info values
const INFO_UINT8: u8 = 24;
const INFO_UINT16: u8 = 25;
const INFO_UINT32: u8 = 26;
const INFO_UINT64: u8 = 27;

// Simple values (major type 7)
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// Maximum nesting depth for CBOR arrays and maps. Inputs nested deeper than
/// this are rejected to prevent stack overflow from recursive parsing.
const MAX_DEPTH: usize = 32;

/// Error is the failures that can occur while encoding or decoding CBOR data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid major type: {0}, want {1}")]
    InvalidMajorType(u8, u8),
    #[error("invalid additional info: {0}")]
    InvalidAdditionalInfo(u8),
    #[error("unexpected end of data")]
    UnexpectedEof,
    #[error("non-canonical encoding")]
    NonCanonical,
    #[error("invalid UTF-8 in text string")]
    InvalidUtf8,
    #[error("unexpected trailing bytes")]
    TrailingBytes,
    #[error("unexpected item count: {0}, want {1}")]
    UnexpectedItemCount(u64, usize),
    #[error("unsupported type: {0}")]
    UnsupportedType(u8),
    #[error("{sign} integer overflow: {value} exceeds max {max}", sign = if *.0 { "negative" } else { "positive" }, value = .1, max = .2)]
    IntegerOverflow(bool, u64, u64),
    #[error("duplicate map key: {0}")]
    DuplicateMapKey(i64),
    #[error("invalid map key order: {0} must come before {1}")]
    InvalidMapKeyOrder(i64, i64),
    #[error("nesting depth exceeds maximum of {0}")]
    MaxDepthExceeded(usize),
    #[error("decode failed: {0}")]
    DecodeFailed(String),
}

/// encode attempts to encode a generic Rust value to CBOR using the tiny, strict
/// subset of types permitted by this package.
pub fn encode<T: Encode>(value: T) -> Result<Vec<u8>, Error> {
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
    verify_object(&mut decoder, MAX_DEPTH)?;
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

    // extend appends raw bytes to the encoder buffer (for derive macros).
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    // encode_uint encodes a positive integer into its canonical shortest-form.
    pub fn encode_uint(&mut self, value: u64) {
        self.encode_length(MAJOR_UINT, value);
    }

    // encode_int encodes a signed integer into its canonical shortest-form.
    pub fn encode_int(&mut self, value: i64) {
        if value >= 0 {
            self.encode_length(MAJOR_UINT, value as u64);
        } else {
            self.encode_length(MAJOR_NINT, (-1 - value) as u64);
        }
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

    // encode_map_header encodes a map size.
    pub fn encode_map_header(&mut self, len: usize) {
        self.encode_length(MAJOR_MAP, len as u64);
    }

    // encode_bool encodes a CBOR boolean value.
    pub fn encode_bool(&mut self, value: bool) {
        self.buf
            .push(MAJOR_SIMPLE << 5 | if value { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }

    // encode_null encodes a CBOR null value.
    pub fn encode_null(&mut self) {
        self.buf.push(MAJOR_SIMPLE << 5 | SIMPLE_NULL);
    }

    /// encode_field encodes a value directly into this encoder's buffer,
    /// bypassing the per-field allocation of `encode_cbor()`.
    pub fn encode_field<T: Encode + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        value.encode_cbor_to(&mut self.buf)
    }

    // encodeLength encodes a major type with an unsigned integer, which defines
    // the length for most types, or the value itself for integers.
    fn encode_length(&mut self, major_type: u8, len: u64) {
        encode_length_to(&mut self.buf, major_type, len);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

// encode_length_to writes a CBOR major-type + length header directly into a
// buffer, matching the canonical shortest-form encoding.
fn encode_length_to(buf: &mut Vec<u8>, major_type: u8, len: u64) {
    if len < 24 {
        buf.push(major_type << 5 | len as u8);
    } else if len <= u8::MAX as u64 {
        buf.push(major_type << 5 | INFO_UINT8);
        buf.push(len as u8);
    } else if len <= u16::MAX as u64 {
        buf.push(major_type << 5 | INFO_UINT16);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= u32::MAX as u64 {
        buf.push(major_type << 5 | INFO_UINT32);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        buf.push(major_type << 5 | INFO_UINT64);
        buf.extend_from_slice(&len.to_be_bytes());
    }
}

// encode_int_to encodes a signed integer directly into a buffer.
pub fn encode_int_to(buf: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        encode_length_to(buf, MAJOR_UINT, value as u64);
    } else {
        encode_length_to(buf, MAJOR_NINT, (-1 - value) as u64);
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

    // finish terminates decoding and returns an error if trailing bytes remain.
    pub fn finish(self) -> Result<(), Error> {
        if self.pos != self.data.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(())
    }

    // decode_uint decodes a positive integer, enforcing minimal canonicalness.
    pub fn decode_uint(&mut self) -> Result<u64, Error> {
        let (major, value) = self.decode_header()?;
        if major != MAJOR_UINT {
            return Err(Error::InvalidMajorType(major, MAJOR_UINT));
        }
        Ok(value)
    }

    // decode_int decodes a signed integer (major type 0 or 1).
    pub fn decode_int(&mut self) -> Result<i64, Error> {
        let (major, value) = self.decode_header()?;
        match major {
            MAJOR_UINT => {
                if value > i64::MAX as u64 {
                    return Err(Error::IntegerOverflow(false, value, i64::MAX as u64));
                }
                Ok(value as i64)
            }
            MAJOR_NINT => {
                if value > i64::MAX as u64 {
                    return Err(Error::IntegerOverflow(true, value, i64::MAX as u64));
                }
                Ok(-1 - value as i64)
            }
            _ => Err(Error::InvalidMajorType(major, MAJOR_UINT)),
        }
    }

    // decode_bytes decodes a byte string.
    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_BYTES {
            return Err(Error::InvalidMajorType(major, MAJOR_BYTES));
        }
        // Retrieve the blob and return as is
        let bytes = self.read_bytes(len)?;
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
            return Err(Error::UnexpectedItemCount(len, N));
        }
        // Retrieve the bytes and copy into the fixed-size array
        let bytes = self.read_bytes(N as u64)?;
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
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
    }

    // decode_array_header decodes an array header, returning its length.
    pub fn decode_array_header(&mut self) -> Result<u64, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_ARRAY {
            return Err(Error::InvalidMajorType(major, MAJOR_ARRAY));
        }
        // Sanity check: each element needs at least 1 byte
        let remaining = (self.data.len() - self.pos) as u64;
        if len > remaining {
            return Err(Error::UnexpectedEof);
        }
        Ok(len)
    }

    // decode_map_header decodes a map header, returning the number of key-value pairs.
    pub fn decode_map_header(&mut self) -> Result<u64, Error> {
        // Extract the field type and attached length
        let (major, len) = self.decode_header()?;
        if major != MAJOR_MAP {
            return Err(Error::InvalidMajorType(major, MAJOR_MAP));
        }
        // Sanity check: each key-value pair needs at least 2 bytes
        let remaining = (self.data.len() - self.pos) as u64;
        if len > remaining / 2 {
            return Err(Error::UnexpectedEof);
        }
        Ok(len)
    }

    // decode_bool decodes a CBOR boolean value.
    pub fn decode_bool(&mut self) -> Result<bool, Error> {
        if self.pos >= self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let byte = self.data[self.pos];
        match byte {
            b if b == (MAJOR_SIMPLE << 5 | SIMPLE_FALSE) => {
                self.pos += 1;
                Ok(false)
            }
            b if b == (MAJOR_SIMPLE << 5 | SIMPLE_TRUE) => {
                self.pos += 1;
                Ok(true)
            }
            _ => Err(Error::InvalidMajorType(byte >> 5, MAJOR_SIMPLE)),
        }
    }

    // decode_null decodes a CBOR null value.
    pub fn decode_null(&mut self) -> Result<(), Error> {
        if self.pos >= self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let byte = self.data[self.pos];
        if byte != (MAJOR_SIMPLE << 5 | SIMPLE_NULL) {
            return Err(Error::InvalidMajorType(byte >> 5, MAJOR_SIMPLE));
        }
        self.pos += 1;
        Ok(())
    }

    // peek_null checks if the next value is null without consuming it.
    pub fn peek_null(&self) -> bool {
        self.pos < self.data.len() && self.data[self.pos] == (MAJOR_SIMPLE << 5 | SIMPLE_NULL)
    }

    // peek_int returns the next signed integer value without consuming it.
    pub fn peek_int(&self) -> Result<i64, Error> {
        self.clone().decode_int()
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
    fn read_bytes(&mut self, len: u64) -> Result<&'a [u8], Error> {
        // Ensure there's still enough data left in the buffer
        if len > usize::MAX as u64 {
            return Err(Error::UnexpectedEof);
        }
        let len = len as usize;

        match self.pos.checked_add(len) {
            None => return Err(Error::UnexpectedEof),
            Some(end) => {
                if end > self.data.len() {
                    return Err(Error::UnexpectedEof);
                }
            }
        }
        // Retrieve the byte and move the cursor forward
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;

        Ok(bytes)
    }
}

/// Encode is the interface needed to encode a type to CBOR.
pub trait Encode {
    // encode_cbor converts the type to CBOR.
    fn encode_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.encode_cbor_to(&mut buf)?;
        Ok(buf)
    }

    // encode_cbor_to writes the CBOR encoding directly into an existing buffer,
    // avoiding the allocation overhead of encode_cbor(). Primitive types override
    // this for zero-allocation encoding; the default falls back to encode_cbor().
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.extend_from_slice(&self.encode_cbor()?);
        Ok(())
    }
}

/// Decode is the interface needed to decode a type from CBOR.
pub trait Decode: Sized {
    // decode_cbor converts CBOR to the type.
    fn decode_cbor(data: &[u8]) -> Result<Self, Error>;

    // decode_cbor_notrail converts CBOR to the type, ignoring any trailing data.
    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error>;
}

// Encoder and decoder implementation for booleans.
impl Encode for bool {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.push(MAJOR_SIMPLE << 5 | if *self { SIMPLE_TRUE } else { SIMPLE_FALSE });
        Ok(())
    }
}

impl Decode for bool {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_bool()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_bool()
    }
}

// Encoder and decoder implementation for positive integers.
impl Encode for u64 {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_UINT, *self);
        Ok(())
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

// Encoder and decoder implementation for signed integers.
impl Encode for i64 {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_int_to(buf, *self);
        Ok(())
    }
}

impl Decode for i64 {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let value = decoder.decode_int()?;
        decoder.finish()?;
        Ok(value)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_int()
    }
}

// Encoder and decoder implementation for dynamic byte blobs.
impl Encode for Vec<u8> {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_BYTES, self.len() as u64);
        buf.extend_from_slice(self);
        Ok(())
    }
}

impl Encode for &[u8] {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_BYTES, self.len() as u64);
        buf.extend_from_slice(self);
        Ok(())
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
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_BYTES, N as u64);
        buf.extend_from_slice(self);
        Ok(())
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
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_TEXT, self.len() as u64);
        buf.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

impl Encode for &str {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_TEXT, self.len() as u64);
        buf.extend_from_slice(self.as_bytes());
        Ok(())
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
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        encode_length_to(buf, MAJOR_ARRAY, 0);
        Ok(())
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
            fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
                // Encode the length of the tuple
                let len = args!($($t),+);
                encode_length_to(buf, MAJOR_ARRAY, len as u64);

                // Encode all the tuple elements individually
                let ($($t,)+) = self;
                $($t.encode_cbor_to(buf)?;)+
                Ok(())
            }
        }

        impl<$($t: Decode),+> Decode for ($($t,)+) {
            fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
                let mut decoder = Decoder::new(data);

                // Decode the length of the tuple
                let len = decoder.decode_array_header()?;
                let exp = args!($($t),+);
                if len != exp as u64 {
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
                if len != exp as u64 {
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

// Blanket encoder for references.
impl<T: Encode> Encode for &T {
    fn encode_cbor(&self) -> Result<Vec<u8>, Error> {
        (*self).encode_cbor()
    }

    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        (*self).encode_cbor_to(buf)
    }
}

/// Constant for convenient CBOR null encoding (use `cbor::NULL`).
pub const NULL: Null = Null;

/// Null is a unit type that encodes/decodes as CBOR null (0xf6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Null;

impl Encode for Null {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.push(MAJOR_SIMPLE << 5 | SIMPLE_NULL);
        Ok(())
    }
}

impl Decode for Null {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut decoder)?;
        decoder.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        decoder.decode_null()?;
        Ok(Null)
    }
}

// Encoder and decoder implementation for Option<T> (None encodes as null).
impl<T: Encode> Encode for Option<T> {
    fn encode_cbor(&self) -> Result<Vec<u8>, Error> {
        match self {
            Some(value) => value.encode_cbor(),
            None => {
                let mut buf = Vec::new();
                buf.push(MAJOR_SIMPLE << 5 | SIMPLE_NULL);
                Ok(buf)
            }
        }
    }

    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Some(value) => value.encode_cbor_to(buf),
            None => {
                buf.push(MAJOR_SIMPLE << 5 | SIMPLE_NULL);
                Ok(())
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut decoder)?;
        decoder.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        if decoder.peek_null() {
            decoder.decode_null()?;
            Ok(None)
        } else {
            Ok(Some(T::decode_cbor_notrail(decoder)?))
        }
    }
}

/// MapEncode exposes direct map-entry encoding for derive-generated map-mode
/// structs. This avoids map encode/decode roundtrips when flattening embeds.
pub trait MapEncode {
    fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), Error>;
}

/// MapEncodeBuffer collects CBOR map entries into a single shared buffer,
/// recording (key, start, end) offsets. This avoids per-field allocation:
/// all encoded values are written contiguously into `data`.
pub struct MapEncodeBuffer {
    pub data: Vec<u8>,
    pub entries: Vec<(i64, u32, u32)>,
}

impl MapEncodeBuffer {
    /// Creates a new buffer pre-sized for the expected number of entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity * 9), // ~9 bytes per field
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Encodes a required field directly into the shared buffer.
    pub fn push<T: Encode>(&mut self, key: i64, value: &T) -> Result<(), Error> {
        let start = self.data.len() as u32;
        value.encode_cbor_to(&mut self.data)?;
        let end = self.data.len() as u32;
        self.entries.push((key, start, end));
        Ok(())
    }

    /// Encodes an optional field; omits the entry entirely when None.
    pub fn push_optional<T: Encode>(&mut self, key: i64, value: &Option<T>) -> Result<(), Error> {
        if let Some(v) = value {
            self.push(key, v)?;
        }
        Ok(())
    }

    /// Assembles the final CBOR map bytes. Sorts entries by CBOR key order
    /// if not already sorted, then verifies no duplicate keys.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        // Check if already in order (common case: keys from embeds interleave nicely)
        let ordered = self
            .entries
            .windows(2)
            .all(|w| cbor_key_cmp(w[0].0, w[1].0) == Ordering::Less);

        if !ordered {
            self.entries
                .sort_unstable_by(|a, b| cbor_key_cmp(a.0, b.0));
        }
        // Verify no duplicates after sorting
        for w in self.entries.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(Error::DuplicateMapKey(w[0].0));
            }
        }
        // Assemble output: map header + sorted key-value pairs
        let mut out = Vec::with_capacity(self.data.len() + self.entries.len() * 10 + 5);
        encode_length_to(&mut out, MAJOR_MAP, self.entries.len() as u64);
        for &(key, start, end) in &self.entries {
            encode_int_to(&mut out, key);
            out.extend_from_slice(&self.data[start as usize..end as usize]);
        }
        Ok(out)
    }
}

/// MapDecode exposes direct map-entry decoding for derive-generated map-mode
/// structs. Implementations consume claimed keys from `entries`.
pub trait MapDecode: Sized {
    fn cbor_map_keys() -> &'static [i64];
    fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, Error>;
}

/// MapEntryAccess provides key-based access to encoded CBOR map values.
pub trait MapEntryAccess<'a> {
    fn take(&mut self, key: i64) -> Option<&'a [u8]>;
    fn contains(&self, key: i64) -> bool;
    fn is_empty(&self) -> bool;
    fn remaining_keys(&self) -> Vec<i64>;
}

/// MapEntries stores a deterministic CBOR map as key/value slots and supports
/// efficient key-based extraction without rebuilding tree maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapEntries<'a> {
    entries: Vec<(i64, Option<&'a [u8]>)>,
    remaining: usize,
}

impl<'a> MapEntries<'a> {
    /// Creates from entries that are already in CBOR deterministic key order
    /// (as validated by `decode_map_entries_slices_notrail`). Skips re-sorting.
    pub fn new(entries: Vec<(i64, &'a [u8])>) -> Self {
        let len = entries.len();
        let entries: Vec<(i64, Option<&'a [u8]>)> =
            entries.into_iter().map(|(k, v)| (k, Some(v))).collect();
        Self {
            remaining: len,
            entries,
        }
    }

    pub fn take(&mut self, key: i64) -> Option<&'a [u8]> {
        let index = self
            .entries
            .binary_search_by(|(k, _)| cbor_key_cmp(*k, key))
            .ok()?;
        let value = self.entries[index].1.take();
        if value.is_some() {
            self.remaining -= 1;
        }
        value
    }

    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    pub fn contains(&self, key: i64) -> bool {
        self.entries
            .binary_search_by(|(k, _)| cbor_key_cmp(*k, key))
            .ok()
            .and_then(|index| self.entries[index].1.as_ref())
            .is_some()
    }

    pub fn remaining_keys(&self) -> Vec<i64> {
        self.entries
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|_| *k))
            .collect()
    }
}

impl<'a> MapEntryAccess<'a> for MapEntries<'a> {
    fn take(&mut self, key: i64) -> Option<&'a [u8]> {
        MapEntries::take(self, key)
    }

    fn contains(&self, key: i64) -> bool {
        MapEntries::contains(self, key)
    }

    fn is_empty(&self) -> bool {
        MapEntries::is_empty(self)
    }

    fn remaining_keys(&self) -> Vec<i64> {
        MapEntries::remaining_keys(self)
    }
}

/// MapEntriesScoped is a view into `MapEntries` restricted to a fixed key set.
pub struct MapEntriesScoped<'a, 'b, E: MapEntryAccess<'a>> {
    entries: &'b mut E,
    keys: &'b [i64],
    marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, 'b, E: MapEntryAccess<'a>> MapEntriesScoped<'a, 'b, E> {
    pub fn new(entries: &'b mut E, keys: &'b [i64]) -> Self {
        Self {
            entries,
            keys,
            marker: std::marker::PhantomData,
        }
    }

    fn key_allowed(&self, key: i64) -> bool {
        if self.keys.len() <= 8 {
            self.keys.contains(&key)
        } else {
            self.keys
                .binary_search_by(|k| cbor_key_cmp(*k, key))
                .is_ok()
        }
    }
}

impl<'a, 'b, E: MapEntryAccess<'a>> MapEntryAccess<'a> for MapEntriesScoped<'a, 'b, E> {
    fn take(&mut self, key: i64) -> Option<&'a [u8]> {
        if self.key_allowed(key) {
            self.entries.take(key)
        } else {
            None
        }
    }

    fn contains(&self, key: i64) -> bool {
        self.key_allowed(key) && self.entries.contains(key)
    }

    fn is_empty(&self) -> bool {
        self.keys.iter().all(|k| !self.contains(*k))
    }

    fn remaining_keys(&self) -> Vec<i64> {
        self.keys
            .iter()
            .copied()
            .filter(|k| self.entries.contains(*k))
            .collect()
    }
}

/// Raw is a placeholder type to allow only partially parsing CBOR objects when
/// some part might depend on another (e.g. version tag, method in an RPC, etc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raw(pub Vec<u8>);

impl std::ops::Deref for Raw {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Raw {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for Raw {
    fn encode_cbor(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }

    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.extend_from_slice(&self.0);
        Ok(())
    }
}

impl Decode for Raw {
    fn decode_cbor(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut decoder)?;
        decoder.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let start = decoder.pos;
        skip_object(decoder, MAX_DEPTH)?;
        let end = decoder.pos;
        Ok(Raw(decoder.data[start..end].to_vec()))
    }
}

// skip_object advances the decoder past one CBOR item without validation. It
// does do some minimal type checks as walking the CBOR does require walking
// all the inner fields too. The depth parameter limits nesting to prevent
// stack overflow from malicious inputs.
fn skip_object(decoder: &mut Decoder<'_>, depth: usize) -> Result<(), Error> {
    if depth == 0 {
        return Err(Error::MaxDepthExceeded(MAX_DEPTH));
    }
    let (major, value) = decoder.decode_header()?;
    match major {
        MAJOR_UINT | MAJOR_NINT => Ok(()),
        MAJOR_BYTES | MAJOR_TEXT => {
            decoder.read_bytes(value)?;
            Ok(())
        }
        MAJOR_ARRAY => {
            for _ in 0..value {
                skip_object(decoder, depth - 1)?;
            }
            Ok(())
        }
        MAJOR_MAP => {
            for _ in 0..value {
                skip_object(decoder, depth - 1)?;
                skip_object(decoder, depth - 1)?;
            }
            Ok(())
        }
        MAJOR_SIMPLE
            if value == SIMPLE_FALSE as u64
                || value == SIMPLE_TRUE as u64
                || value == SIMPLE_NULL as u64 =>
        {
            Ok(())
        }
        _ => Err(Error::UnsupportedType(major)),
    }
}

/// cbor_key_cmp compares two i64 keys according to CBOR deterministic encoding
/// order (RFC 8949 Section 4.2.1): bytewise lexicographic order of encoded keys.
///
/// For integers this means: positive integers (0, 1, 2, ...) come before negative
/// integers (-1, -2, -3, ...), and within each category they're ordered by their
/// encoded length first, then by value.
pub fn cbor_key_cmp(a: i64, b: i64) -> Ordering {
    // CBOR deterministic encoding of integer keys:
    //   - Major type 0 (non-negative) encodes as 0x00..0x1b; shorter forms sort first.
    //   - Major type 1 (negative)     encodes as 0x20..0x3b; shorter forms sort first.
    //   - Major 0 bytes always < Major 1 bytes, so all non-negatives sort before negatives.
    //
    // Within each sign category, CBOR uses canonical shortest-form encoding,
    // so smaller absolute values get shorter encodings which sort first; equal
    // lengths are ordered by value. This matches plain unsigned comparison of
    // the wire value (the value itself for non-negative, (-1 - n) for negative n).
    match (a >= 0, b >= 0) {
        (true, true) => (a as u64).cmp(&(b as u64)),
        (false, false) => {
            // Wire value for negative n is (-1 - n) as u64.
            // -1 → wire 0, -2 → wire 1, … so smaller absolute value sorts first.
            ((-1 - a) as u64).cmp(&((-1 - b) as u64))
        }
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
    }
}

/// decode_map_entries_notrail reads a CBOR map from the decoder and returns its
/// entries as (key, raw_value) pairs.
pub fn decode_map_entries_notrail(dec: &mut Decoder<'_>) -> Result<Vec<(i64, Raw)>, Error> {
    let entries = decode_map_entries_slices_notrail(dec)?;
    Ok(entries
        .into_iter()
        .map(|(k, v)| (k, Raw(v.to_vec())))
        .collect())
}

/// decode_map_entries_slices_notrail reads a CBOR map from the decoder and
/// returns borrowed slices for each value.
pub fn decode_map_entries_slices_notrail<'a>(
    dec: &mut Decoder<'a>,
) -> Result<Vec<(i64, &'a [u8])>, Error> {
    let len = dec.decode_map_header()?;
    let mut entries = Vec::with_capacity(len as usize);
    let mut prev_key: Option<i64> = None;
    for _ in 0..len {
        let key = dec.decode_int()?;
        if let Some(prev) = prev_key
            && cbor_key_cmp(prev, key) != Ordering::Less
        {
            return Err(if prev == key {
                Error::DuplicateMapKey(key)
            } else {
                Error::InvalidMapKeyOrder(key, prev)
            });
        }
        prev_key = Some(key);
        let start = dec.pos;
        skip_object(dec, MAX_DEPTH)?;
        let end = dec.pos;
        entries.push((key, &dec.data[start..end]));
    }
    Ok(entries)
}

/// decode_map_entries reads a CBOR map from raw bytes and returns its entries
/// as (key, raw_value) pairs.
pub fn decode_map_entries(data: &[u8]) -> Result<Vec<(i64, Raw)>, Error> {
    let mut dec = Decoder::new(data);
    let entries = decode_map_entries_notrail(&mut dec)?;
    dec.finish()?;
    Ok(entries)
}

/// encode_map_entries encodes a list of (key, raw_value) pairs as a CBOR map.
/// The entries must already be sorted by CBOR key order.
pub fn encode_map_entries(entries: &[(i64, Raw)]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.encode_map_header(entries.len());
    for (key, value) in entries {
        enc.encode_int(*key);
        enc.extend(&value.0);
    }
    enc.finish()
}

// verify_object is an internal function to verify a single CBOR item without
// full deserialization. The depth parameter limits nesting to prevent stack
// overflow from malicious inputs.
fn verify_object(decoder: &mut Decoder, depth: usize) -> Result<(), Error> {
    if depth == 0 {
        return Err(Error::MaxDepthExceeded(MAX_DEPTH));
    }
    let (major, value) = decoder.decode_header()?;

    match major {
        MAJOR_UINT | MAJOR_NINT => {
            // Integers are valid (canonicalness was already verified in the
            // header decoding). Overflow checking is done at decode time based
            // on the target type (u64 vs i64).
            Ok(())
        }
        MAJOR_BYTES => {
            // Opaque bytes are always valid, skip over
            _ = decoder.read_bytes(value)?;
            Ok(())
        }
        MAJOR_TEXT => {
            // Verify that the text is indeed UTF-8
            let bytes = decoder.read_bytes(value)?;
            std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
            Ok(())
        }
        MAJOR_ARRAY => {
            // Recursively verify each array element
            let len = value as usize;
            for _ in 0..len {
                verify_object(decoder, depth - 1)?;
            }
            Ok(())
        }
        MAJOR_MAP => {
            // Verify map has integer keys in deterministic order
            let len = value as usize;
            let mut prev_key: Option<i64> = None;

            for _ in 0..len {
                // Decode and verify the key is an integer
                let key = decoder.decode_int()?;

                // Verify deterministic ordering
                if let Some(prev) = prev_key
                    && cbor_key_cmp(prev, key) != Ordering::Less
                {
                    return Err(Error::InvalidMapKeyOrder(key, prev));
                }
                prev_key = Some(key);

                // Recursively verify the value
                verify_object(decoder, depth - 1)?;
            }
            Ok(())
        }
        MAJOR_SIMPLE
            if value == SIMPLE_FALSE as u64
                || value == SIMPLE_TRUE as u64
                || value == SIMPLE_NULL as u64 =>
        {
            // Booleans and null are valid simple values
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

    // Tests that booleans encode correctly.
    #[test]
    fn test_bool_encoding() {
        assert_eq!(encode(&false).unwrap(), vec![0xf4]);
        assert_eq!(encode(&true).unwrap(), vec![0xf5]);
    }

    // Tests that booleans decode correctly.
    #[test]
    fn test_bool_decoding() {
        assert_eq!(decode::<bool>(&[0xf4]).unwrap(), false);
        assert_eq!(decode::<bool>(&[0xf5]).unwrap(), true);

        // Invalid values should fail
        assert!(decode::<bool>(&[0xf6]).is_err()); // null
        assert!(decode::<bool>(&[0x00]).is_err()); // integer
    }

    // Tests that null encodes correctly.
    #[test]
    fn test_null_encoding() {
        assert_eq!(encode(&None::<u64>).unwrap(), vec![0xf6]);
        assert_eq!(encode(&Some(42u64)).unwrap(), encode(&42u64).unwrap());
    }

    // Tests that null decodes correctly.
    #[test]
    fn test_null_decoding() {
        assert_eq!(decode::<Option<u64>>(&[0xf6]).unwrap(), None);
        assert_eq!(
            decode::<Option<u64>>(&encode(&42u64).unwrap()).unwrap(),
            Some(42)
        );

        // Nested options
        assert_eq!(decode::<Option<bool>>(&[0xf4]).unwrap(), Some(false));
        assert_eq!(decode::<Option<bool>>(&[0xf5]).unwrap(), Some(true));
        assert_eq!(decode::<Option<bool>>(&[0xf6]).unwrap(), None);

        // Null type
        assert_eq!(decode::<Null>(&[0xf6]).unwrap(), Null);
        assert!(decode::<Null>(&[0xf4]).is_err()); // false is not null
        assert!(decode::<Null>(&[0x00]).is_err()); // integer is not null
    }

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
                encode(&value).unwrap(),
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

    // Tests that signed integers encode correctly across the various ranges.
    #[test]
    fn test_int_encoding() {
        let cases = [
            // Positive values use major type 0
            (0i64, vec![0x00]),
            (23i64, vec![0x17]),
            (24i64, vec![0x18, 0x18]),
            (
                i64::MAX,
                vec![0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
            // Negative values use major type 1 with (-1 - n) encoding
            (-1i64, vec![0x20]),               // -1 -> wire value 0
            (-24i64, vec![0x37]),              // -24 -> wire value 23
            (-25i64, vec![0x38, 0x18]),        // -25 -> wire value 24
            (-256i64, vec![0x38, 0xff]),       // -256 -> wire value 255
            (-257i64, vec![0x39, 0x01, 0x00]), // -257 -> wire value 256
            (
                i64::MIN,
                vec![0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(
                encode(&value).unwrap(),
                expected,
                "encoding failed for value {}",
                value
            );
        }
    }

    // Tests that signed integers decode correctly across the various ranges.
    #[test]
    fn test_int_decoding() {
        let cases = [
            // Positive values (major type 0)
            (vec![0x00], 0i64),
            (vec![0x17], 23i64),
            (vec![0x18, 0x18], 24i64),
            (
                vec![0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                i64::MAX,
            ),
            // Negative values (major type 1)
            (vec![0x20], -1i64),
            (vec![0x37], -24i64),
            (vec![0x38, 0x18], -25i64),
            (vec![0x38, 0xff], -256i64),
            (vec![0x39, 0x01, 0x00], -257i64),
            (
                vec![0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                i64::MIN,
            ),
        ];

        for (data, expected) in cases {
            assert_eq!(
                decode::<i64>(&data).unwrap(),
                expected,
                "decoding failed for data {:?}",
                data
            );
        }
    }

    // Tests that signed integers are rejected for overflow conditions.
    #[test]
    fn test_int_rejection() {
        // Positive value > i64::MAX (major type 0 with value i64::MAX + 1)
        let mut data = vec![MAJOR_UINT << 5 | INFO_UINT64];
        data.extend_from_slice(&((i64::MAX as u64) + 1).to_be_bytes());
        let result = decode::<i64>(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::IntegerOverflow(negative, v, max) => {
                assert!(!negative);
                assert_eq!(v, 9223372036854775808);
                assert_eq!(max, 9223372036854775807);
            }
            other => panic!("Expected IntegerOverflow error, got {:?}", other),
        }

        // Negative value < i64::MIN (major type 1 with wire value > i64::MAX)
        let mut data = vec![MAJOR_NINT << 5 | INFO_UINT64];
        data.extend_from_slice(&((i64::MAX as u64) + 1).to_be_bytes());
        let result = decode::<i64>(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::IntegerOverflow(negative, v, max) => {
                assert!(negative);
                assert_eq!(v, 9223372036854775808);
                assert_eq!(max, 9223372036854775807);
            }
            other => panic!("Expected IntegerOverflow error, got {:?}", other),
        }

        // Non-canonical negative integer encoding
        let data = vec![MAJOR_NINT << 5 | INFO_UINT8, 0x10]; // -17 with INFO_UINT8
        let result = decode::<i64>(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::NonCanonical => {}
            other => panic!("Expected NonCanonical error, got {:?}", other),
        }
    }

    // Tests that byte strings encode correctly on a bunch of samples.
    #[test]
    fn test_bytes_encoding() {
        // Empty bytes
        let empty: Vec<u8> = vec![];
        let encoded = encode(&empty).unwrap();
        assert_eq!(encoded, vec![0x40]); // major 2, length 0

        // 1 byte
        let one_byte = vec![0xaa];
        let encoded = encode(&one_byte).unwrap();
        assert_eq!(encoded, vec![0x41, 0xaa]); // major 2, length 1, data

        // Longer bytes
        let long_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = encode(&long_bytes).unwrap();
        assert_eq!(encoded, vec![0x44, 0xde, 0xad, 0xbe, 0xef]); // major 2, length 4, data

        // Test &Vec<u8> reference
        let bytes_vec = vec![1, 2, 3];
        let bytes_vec_ref = &bytes_vec;
        let encoded = encode(&bytes_vec_ref).unwrap();
        assert_eq!(encoded, vec![0x43, 1, 2, 3]);

        // Test &[u8] slice reference
        let bytes_slice: &[u8] = &[4, 5, 6];
        let encoded = encode(&bytes_slice).unwrap();
        assert_eq!(encoded, vec![0x43, 4, 5, 6]);

        // Test [u8; N] fixed-size array
        let bytes_array: [u8; 3] = [7, 8, 9];
        let encoded = encode(&bytes_array).unwrap();
        assert_eq!(encoded, vec![0x43, 7, 8, 9]);

        // Test &[u8; N] fixed-size array reference
        let bytes_array_ref = &[10u8, 11, 12];
        let encoded = encode(&bytes_array_ref).unwrap();
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
        let encoded = encode(&empty).unwrap();
        assert_eq!(encoded, vec![0x60]); // major 3, length 0

        // 1 character
        let one_char = "a";
        let encoded = encode(&one_char).unwrap();
        assert_eq!(encoded, vec![0x61, 0x61]); // major 3, length 1, 'a'

        // Longer string
        let long_string = "Peter says hi!";
        let encoded = encode(&long_string).unwrap();
        assert_eq!(encoded[0], 0x60 | long_string.len() as u8); // major 3, length embedded
        assert_eq!(&encoded[1..], long_string.as_bytes());

        // Test String type
        let string_type = "Peter says hi!".to_string();
        let encoded = encode(&string_type).unwrap();
        assert_eq!(encoded[0], 0x60 | string_type.len() as u8); // major 3, length embedded
        assert_eq!(&encoded[1..], string_type.as_bytes());

        // Test &String type
        let string_ref = &"Peter says hi!".to_string();
        let encoded = encode(&string_ref).unwrap();
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
    }

    // Tests that tuples encode correctly on a bunch of samples.
    #[test]
    fn test_tuple_encoding() {
        // 0-tuple
        let empty = ();
        let encoded = encode(&empty).unwrap();
        assert_eq!(encoded, vec![0x80]); // major 4, length 0 (empty array)

        // 1-tuple (wonky Rust syntax)
        let one_tuple = (42u64,);
        let encoded = encode(&one_tuple).unwrap();
        assert_eq!(encoded[0], 0x81); // major 4, length 1 (array with 1 element)
        assert_eq!(encoded[1], 0x18); // major 0, INFO_UINT8
        assert_eq!(encoded[2], 42);

        // 2-tuple
        let t = ("hello".to_string(), 42u64);
        let encoded = encode(&t).unwrap();
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
        encoded.extend_from_slice(&encode(&42u64).unwrap()); // single element
        let decoded = decode::<(u64,)>(&encoded).unwrap();
        assert_eq!(decoded, (42u64,));

        // 2-tuple
        let mut encoded = vec![0x82]; // array length 2
        encoded.extend_from_slice(&encode(&"hello".to_string()).unwrap()); // first element
        encoded.extend_from_slice(&encode(&42u64).unwrap()); // second element
        let decoded = decode::<(String, u64)>(&encoded).unwrap();
        assert_eq!(decoded, ("hello".to_string(), 42u64));
    }

    // Tests that tuples are rejected if the size of the array does not match the
    // expected size.
    #[test]
    fn test_tuple_rejection() {
        // Try to decode array with 1 element as 2-tuple
        let mut encoded = vec![0x81]; // array length 1
        encoded.extend_from_slice(&encode(&42u64).unwrap()); // single element
        let result = decode::<(u64, u64)>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(1, 2) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(1, 2) error, got {:?}", other),
        }

        // Try to decode array with 3 elements as 2-tuple
        let mut encoded = vec![0x83]; // array length 3
        encoded.extend_from_slice(&encode(&42u64).unwrap());
        encoded.extend_from_slice(&encode(&"test".to_string()).unwrap());
        encoded.extend_from_slice(&encode(&vec![1u8, 2]).unwrap());
        let result = decode::<(u64, String)>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(3, 2) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(3, 2) error, got {:?}", other),
        }

        // Try to decode array with 1 element as empty tuple
        let mut encoded = vec![0x81]; // array length 1
        encoded.extend_from_slice(&encode(&42u64).unwrap());
        let result = decode::<()>(&encoded);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(1, 0) => {} // Expected error
            other => panic!("Expected UnexpectedItemCount(1, 0) error, got {:?}", other),
        }
    }

    // Test struct for array encoding/decoding with derive macros.
    #[derive(Debug, PartialEq, Cbor)]
    #[cbor(array)]
    struct TestArray {
        first: u64,
        second: String,
        third: Vec<u8>,
    }

    // Tests that array structs encode correctly in field declaration order.
    #[test]
    fn test_array_encoding() {
        let arr = TestArray {
            first: 42,
            second: "hello".to_string(),
            third: vec![1, 2, 3],
        };
        let encoded = encode(&arr).unwrap();

        // Should be: [42, "hello", h'010203']
        let mut expected = vec![0x83]; // array with 3 elements
        expected.extend_from_slice(&encode(&42u64).unwrap());
        expected.extend_from_slice(&encode(&"hello".to_string()).unwrap());
        expected.extend_from_slice(&encode(&vec![1u8, 2, 3]).unwrap());

        assert_eq!(encoded, expected);
    }

    // Tests that array structs decode correctly.
    #[test]
    fn test_array_decoding() {
        let mut data = vec![0x83]; // array with 3 elements
        data.extend_from_slice(&encode(&100u64).unwrap());
        data.extend_from_slice(&encode(&"world".to_string()).unwrap());
        data.extend_from_slice(&encode(&vec![4u8, 5, 6]).unwrap());

        let decoded = decode::<TestArray>(&data).unwrap();
        assert_eq!(decoded.first, 100);
        assert_eq!(decoded.second, "world");
        assert_eq!(decoded.third, vec![4, 5, 6]);
    }

    // Tests that array structs are rejected if the size does not match.
    #[test]
    fn test_array_rejection() {
        // Too few elements (2 instead of 3)
        let mut data = vec![0x82]; // array with 2 elements
        data.extend_from_slice(&encode(&42u64).unwrap());
        data.extend_from_slice(&encode(&"test".to_string()).unwrap());
        let result = decode::<TestArray>(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(2, 3) => {}
            other => panic!("Expected UnexpectedItemCount(2, 3) error, got {:?}", other),
        }
        // Too many elements (4 instead of 3)
        let mut data = vec![0x84]; // array with 4 elements
        data.extend_from_slice(&encode(&42u64).unwrap());
        data.extend_from_slice(&encode(&"test".to_string()).unwrap());
        data.extend_from_slice(&encode(&vec![1u8]).unwrap());
        data.extend_from_slice(&encode(&42u64).unwrap());
        let result = decode::<TestArray>(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::UnexpectedItemCount(4, 3) => {}
            other => panic!("Expected UnexpectedItemCount(4, 3) error, got {:?}", other),
        }
    }

    // Test struct for map encoding/decoding with derive macros.
    #[derive(Debug, PartialEq, Cbor)]
    struct TestMap {
        #[cbor(key = 1)]
        key1: u64,
        #[cbor(key = 2)]
        key2: u64,
        #[cbor(key = -1)]
        key_neg1: u64,
    }

    // Tests that maps encode correctly with deterministic key ordering.
    #[test]
    fn test_map_encoding() {
        // Map with positive and negative keys (should be sorted by bytewise order)
        let map = TestMap {
            key1: 42,
            key2: 67,
            key_neg1: 100,
        };
        let encoded = encode(&map).unwrap();

        // Keys in bytewise order: 0x01, 0x02, 0x20 (1, 2, -1)
        assert_eq!(encoded[0], 0xa3); // map with 3 entries
        assert_eq!(encoded[1], 0x01); // key 1
        assert_eq!(encoded[2], 0x18);
        assert_eq!(encoded[3], 42);
        assert_eq!(encoded[4], 0x02); // key 2
        assert_eq!(encoded[5], 0x18);
        assert_eq!(encoded[6], 67);
        assert_eq!(encoded[7], 0x20); // key -1
        assert_eq!(encoded[8], 0x18);
        assert_eq!(encoded[9], 100);
    }

    // Tests that maps decode correctly.
    #[test]
    fn test_map_decoding() {
        // Multiple entries (in correct deterministic order)
        let decoded = decode::<TestMap>(&vec![
            0xa3, // map with 3 entries
            0x01, 0x18, 0x2a, // 1: 42
            0x02, 0x18, 0x43, // 2: 67
            0x20, 0x18, 0x64, // -1: 100
        ])
        .unwrap();
        assert_eq!(decoded.key1, 42);
        assert_eq!(decoded.key2, 67);
        assert_eq!(decoded.key_neg1, 100);
    }

    // Tests that maps with invalid key ordering are rejected.
    #[test]
    fn test_map_rejection() {
        // Keys out of order: 2 before 1
        let result = decode::<TestMap>(&vec![
            0xa3, // map with 3 entries
            0x02, 0x18, 0x43, // 2: 67 (should come after 1)
            0x01, 0x18, 0x2a, // 1: 42
            0x20, 0x18, 0x64, // -1: 100
        ]);
        assert!(result.is_err());

        // Wrong key value
        let result = decode::<TestMap>(&vec![
            0xa3, // map with 3 entries
            0x05, 0x18, 0x2a, // 5: 42 (should be 1)
            0x02, 0x18, 0x43, // 2: 67
            0x20, 0x18, 0x64, // -1: 100
        ]);
        assert!(result.is_err());
    }

    // Test struct for map encoding/decoding with optional fields.
    #[derive(Debug, PartialEq, Cbor)]
    struct TestMapOptional {
        #[cbor(key = 1)]
        required: u64,
        #[cbor(key = 2)]
        optional1: Option<String>,
        #[cbor(key = 3)]
        nullable: Option<Option<u64>>,
        #[cbor(key = -1)]
        optional2: Option<Vec<u8>>,
    }

    // Tests that optional map fields are omitted when None during encoding,
    // and that Option<Option<T>> (nullable) fields are always present.
    #[test]
    fn test_map_optional_encoding() {
        // All fields present (nullable with value)
        let map = TestMapOptional {
            required: 42,
            optional1: Some("hello".to_string()),
            nullable: Some(Some(1)),
            optional2: Some(vec![1, 2, 3]),
        };
        let encoded = encode(&map).unwrap();
        // Keys in bytewise order: 0x01, 0x02, 0x03, 0x20 (1, 2, 3, -1)
        assert_eq!(encoded[0], 0xa4); // map with 4 entries
        let decoded = decode::<TestMapOptional>(&encoded).unwrap();
        assert_eq!(decoded, map);

        // Only required + nullable (optionals None, nullable with null value)
        let map = TestMapOptional {
            required: 42,
            optional1: None,
            nullable: Some(None),
            optional2: None,
        };
        let encoded = encode(&map).unwrap();
        assert_eq!(encoded[0], 0xa2); // map with 2 entries (required + nullable)
        assert_eq!(encoded, vec![0xa2, 0x01, 0x18, 42, 0x03, 0xf6]);
        let decoded = decode::<TestMapOptional>(&encoded).unwrap();
        assert_eq!(decoded, map);

        // None and Some(None) both encode identically as null (2-state collapse)
        let map_none = TestMapOptional {
            required: 42,
            optional1: None,
            nullable: None,
            optional2: None,
        };
        let map_some_none = TestMapOptional {
            required: 42,
            optional1: None,
            nullable: Some(None),
            optional2: None,
        };
        assert_eq!(encode(&map_none).unwrap(), encode(&map_some_none).unwrap());
        // Both decode back as Some(None) since the key is always present
        let decoded = decode::<TestMapOptional>(&encode(&map_none).unwrap()).unwrap();
        assert_eq!(decoded.nullable, Some(None));

        // One optional present, one absent (nullable always present as null)
        let map = TestMapOptional {
            required: 42,
            optional1: Some("hi".to_string()),
            nullable: Some(None),
            optional2: None,
        };
        let encoded = encode(&map).unwrap();
        assert_eq!(encoded[0], 0xa3); // map with 3 entries
        let decoded = decode::<TestMapOptional>(&encoded).unwrap();
        assert_eq!(decoded, map);

        // Other optional present (nullable always present as null)
        let map = TestMapOptional {
            required: 42,
            optional1: None,
            nullable: Some(None),
            optional2: Some(vec![0xff]),
        };
        let encoded = encode(&map).unwrap();
        assert_eq!(encoded[0], 0xa3); // map with 3 entries
        let decoded = decode::<TestMapOptional>(&encoded).unwrap();
        assert_eq!(decoded, map);
    }

    // Tests that optional map fields decode as None when keys are missing,
    // and that nullable (Option<Option<T>>) fields must always be present.
    #[test]
    fn test_map_optional_decoding() {
        // Decode a map with required + nullable (null value), optionals absent
        let decoded = decode::<TestMapOptional>(&vec![
            0xa2, // map with 2 entries
            0x01, 0x18, 0x2a, // 1: 42
            0x03, 0xf6, // 3: null
        ])
        .unwrap();
        assert_eq!(decoded.required, 42);
        assert_eq!(decoded.optional1, None);
        assert_eq!(decoded.nullable, Some(None));
        assert_eq!(decoded.optional2, None);

        // Decode a map with required + nullable + first optional
        let decoded = decode::<TestMapOptional>(&vec![
            0xa3, // map with 3 entries
            0x01, 0x00, // 1: 0
            0x02, 0x62, 0x68, 0x69, // 2: "hi"
            0x03, 0xf6, // 3: null
        ])
        .unwrap();
        assert_eq!(decoded.required, 0);
        assert_eq!(decoded.optional1, Some("hi".to_string()));
        assert_eq!(decoded.nullable, Some(None));
        assert_eq!(decoded.optional2, None);

        // Decode a map with required + nullable + second optional (key -1)
        let decoded = decode::<TestMapOptional>(&vec![
            0xa3, // map with 3 entries
            0x01, 0x05, // 1: 5
            0x03, 0xf6, // 3: null
            0x20, 0x41, 0xab, // -1: h'ab'
        ])
        .unwrap();
        assert_eq!(decoded.required, 5);
        assert_eq!(decoded.optional1, None);
        assert_eq!(decoded.nullable, Some(None));
        assert_eq!(decoded.optional2, Some(vec![0xab]));

        // Decode with nullable absent must fail (it's required)
        let result = decode::<TestMapOptional>(&vec![
            0xa1, // map with 1 entry
            0x01, 0x18, 0x2a, // 1: 42 (key 3 missing)
        ]);
        assert!(result.is_err());
    }

    // Tests that maps with optional fields still reject invalid data.
    #[test]
    fn test_map_optional_rejection() {
        // Too many entries
        let result = decode::<TestMapOptional>(&vec![
            0xa5, // map with 5 entries (max is 4)
            0x01, 0x00, // 1: 0
            0x02, 0x60, // 2: ""
            0x03, 0xf6, // 3: null
            0x04, 0x00, // 4: 0 (unknown key)
            0x20, 0x40, // -1: h''
        ]);
        assert!(result.is_err());

        // Required field missing (map has optional keys but not the required one)
        let result = decode::<TestMapOptional>(&vec![
            0xa1, // map with 1 entry
            0x02, 0x60, // 2: "" (key 1 is required but missing)
        ]);
        assert!(result.is_err());

        // Nullable field missing (key 3 must always be present)
        let result = decode::<TestMapOptional>(&vec![
            0xa1, // map with 1 entry
            0x01, 0x18, 0x2a, // 1: 42 (key 3 missing)
        ]);
        assert!(result.is_err());
    }

    // Tests that Raw encodes correctly (passthrough of inner bytes).
    #[test]
    fn test_raw_encoding() {
        // Unsigned integer (42)
        let raw = Raw(vec![0x18, 0x2a]);
        assert_eq!(encode(&raw).unwrap(), vec![0x18, 0x2a]);

        // String "hello"
        let raw = Raw(vec![0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
        assert_eq!(
            encode(&raw).unwrap(),
            vec![0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]
        );

        // Tuple with Raw inside: ("method", <raw bytes for u64 1>)
        let raw = Raw(vec![0x01]);
        let encoded = encode(&("method", raw)).unwrap();
        assert_eq!(
            encoded,
            vec![
                0x82, // array of 2
                0x66, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // "method"
                0x01  // raw: u64 1
            ]
        );
    }

    // Tests that Raw decodes correctly (captures raw CBOR bytes).
    #[test]
    fn test_raw_decoding() {
        // Unsigned integer (42)
        let data = vec![0x18, 0x2a];
        let raw: Raw = decode(&data).unwrap();
        assert_eq!(raw.0, vec![0x18, 0x2a]);

        // String "hello"
        let data = vec![0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let raw: Raw = decode(&data).unwrap();
        assert_eq!(raw.0, vec![0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);

        // Tuple with Raw: ("method", <raw params>)
        let data = vec![
            0x82, // array of 2
            0x66, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // "method"
            0x82, 0x01, 0x63, 0x61, 0x72, 0x67, // (1, "arg")
        ];
        let (method, params): (String, Raw) = decode(&data).unwrap();
        assert_eq!(method, "method");
        assert_eq!(params.0, vec![0x82, 0x01, 0x63, 0x61, 0x72, 0x67]);
    }

    // Tests that Raw rejects unsupported major types.
    #[test]
    fn test_raw_rejection() {
        // Major type 6 (tags) - unsupported
        let data = vec![0xc0, 0x01]; // tag(0) followed by 1
        assert!(matches!(
            decode::<Raw>(&data),
            Err(Error::UnsupportedType(6))
        ));

        // Major type 7 (floats) - unsupported, but bools/null are now supported
        let data = vec![0xf5]; // true - now valid
        assert!(decode::<Raw>(&data).is_ok());

        // Float16 is still unsupported
        let data = vec![0xf9, 0x3c, 0x00]; // 1.0 as float16
        assert!(matches!(
            decode::<Raw>(&data),
            Err(Error::UnsupportedType(7))
        ));

        // Trailing bytes
        let data = vec![0x18, 0x2a, 0x00]; // u64 42 + trailing 0x00
        assert!(matches!(decode::<Raw>(&data), Err(Error::TrailingBytes)));
    }

    // Tests that the dry-decoding verifier properly restricts the allowed types.
    #[test]
    fn test_verify() {
        // Valid types should pass
        assert!(verify(&encode(&42u64).unwrap()).is_ok());
        assert!(verify(&encode(&-42i64).unwrap()).is_ok());
        assert!(verify(&encode(&"hello").unwrap()).is_ok());
        assert!(verify(&encode(&vec![1u8, 2, 3]).unwrap()).is_ok());
        assert!(verify(&encode(&()).unwrap()).is_ok());
        assert!(verify(&encode(&(42u64, "test")).unwrap()).is_ok());
        assert!(verify(&encode(&(-42i64, "test")).unwrap()).is_ok());
        assert!(
            verify(
                &encode(&TestMap {
                    key1: 1,
                    key2: 2,
                    key_neg1: 3,
                })
                .unwrap()
            )
            .is_ok()
        );

        // Large integers are valid at verify time (overflow is checked at decode)
        let mut large_uint = vec![MAJOR_UINT << 5 | INFO_UINT64];
        large_uint.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(verify(&large_uint).is_ok());

        let mut large_nint = vec![MAJOR_NINT << 5 | INFO_UINT64];
        large_nint.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(verify(&large_nint).is_ok());

        // Trailing bytes
        let mut bad_data = encode(&42u64).unwrap();
        bad_data.push(0x00);
        assert!(verify(&bad_data).is_err());
        match verify(&bad_data).unwrap_err() {
            Error::TrailingBytes => {}
            other => panic!("Expected TrailingBytes error, got {:?}", other),
        }

        // Maps with string keys are rejected (key decoding fails)
        let map_str_key = vec![0xa1, 0x61, 0x61, 0x61, 0x62]; // {"a": "b"}
        assert!(verify(&map_str_key).is_err());
        match verify(&map_str_key).unwrap_err() {
            Error::InvalidMajorType(3, 0) => {} // text key when expecting int
            other => panic!(
                "Expected InvalidMajorType error for string key, got {:?}",
                other
            ),
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

        // Booleans and null are now supported
        assert!(verify(&encode(&false).unwrap()).is_ok());
        assert!(verify(&encode(&true).unwrap()).is_ok());
        assert!(verify(&encode(&None::<u64>).unwrap()).is_ok());

        // undefined (0xf7) is still unsupported
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

        // Nested arrays with booleans are now valid
        let nested_bool = vec![0x81, 0xf4]; // [false]
        assert!(verify(&nested_bool).is_ok());

        // Nested arrays with floats are still invalid
        let nested_float = vec![0x81, 0xf9, 0x3c, 0x00]; // [1.0 as float16]
        assert!(verify(&nested_float).is_err());
        match verify(&nested_float).unwrap_err() {
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

    // Tests a length overflow issue caught by the fuzzer:
    //  - https://github.com/dark-bio/crypto-rs/pull/3
    #[test]
    fn test_issue_3() {
        let encoded = vec![123, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];
        let result = decode::<String>(&encoded);
        assert!(result.is_err());
    }

    // Inner struct used for embed tests.
    #[derive(Debug, Clone, PartialEq, Cbor)]
    struct Inner {
        #[cbor(key = 1)]
        a: u64,
        #[cbor(key = 2)]
        b: String,
    }

    // Flat equivalent of embedded struct for byte-identity comparison.
    #[derive(Debug, PartialEq, Cbor)]
    struct Flat {
        #[cbor(key = 1)]
        a: u64,
        #[cbor(key = 2)]
        b: String,
        #[cbor(key = 3)]
        c: u64,
    }

    // Tests that an embedded struct produces identical CBOR to a flat struct
    // with the same fields and keys.
    #[test]
    fn test_map_embed_flat() {
        #[derive(Debug, PartialEq, Cbor)]
        struct Embedded {
            #[cbor(embed)]
            inner: Inner,
            #[cbor(key = 3)]
            c: u64,
        }
        let embedded = Embedded {
            inner: Inner {
                a: 1,
                b: "two".to_string(),
            },
            c: 3,
        };
        let flat = Flat {
            a: 1,
            b: "two".to_string(),
            c: 3,
        };
        assert_eq!(encode(&embedded).unwrap(), encode(&flat).unwrap());

        // Decode back
        let decoded = decode::<Embedded>(&encode(&embedded).unwrap()).unwrap();
        assert_eq!(decoded, embedded);
    }

    // Tests that embedded fields are correctly sorted with direct fields.
    #[test]
    fn test_map_embed_key_order() {
        // Embed field has keys 1,2 and direct field has key -1 (sorts after positives)
        #[derive(Debug, PartialEq, Cbor)]
        struct WithNeg {
            #[cbor(embed)]
            inner: Inner,
            #[cbor(key = -1)]
            neg: u64,
        }
        let val = WithNeg {
            inner: Inner {
                a: 10,
                b: "hi".to_string(),
            },
            neg: 99,
        };
        let data = encode(&val).unwrap();
        // Keys should be sorted: 1, 2, -1
        assert_eq!(data[0], 0xa3); // map with 3 entries
        let decoded = decode::<WithNeg>(&data).unwrap();
        assert_eq!(decoded, val);
    }

    // Tests that an embedded struct with optional fields works correctly.
    #[test]
    fn test_map_embed_optional() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct OptInner {
            #[cbor(key = 1)]
            id: u64,
            #[cbor(key = 2)]
            extra: Option<Vec<u8>>,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct Outer {
            #[cbor(embed)]
            base: OptInner,
            #[cbor(key = 3)]
            name: String,
        }
        // With optional present
        let val = Outer {
            base: OptInner {
                id: 42,
                extra: Some(vec![0xab]),
            },
            name: "test".to_string(),
        };
        let data = encode(&val).unwrap();
        assert_eq!(data[0], 0xa3); // 3 entries
        let decoded = decode::<Outer>(&data).unwrap();
        assert_eq!(decoded, val);

        // Without optional
        let val = Outer {
            base: OptInner {
                id: 42,
                extra: None,
            },
            name: "test".to_string(),
        };
        let data = encode(&val).unwrap();
        assert_eq!(data[0], 0xa2); // 2 entries
        let decoded = decode::<Outer>(&data).unwrap();
        assert_eq!(decoded, val);
    }

    // Tests that duplicate keys between direct and embed fields are detected
    // during encoding (the embed merge returns an error on collision).
    #[test]
    fn test_map_embed_duplicate_key_encode() {
        #[derive(Debug, PartialEq, Cbor)]
        struct Clash {
            #[cbor(key = 1)] // same key as Inner.a
            x: u64,
            #[cbor(embed)]
            inner: Inner,
        }
        let val = Clash {
            x: 99,
            inner: Inner {
                a: 1,
                b: "hi".to_string(),
            },
        };
        // Encoding a struct with overlapping direct + embed keys returns an error.
        match encode(&val) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected Err(DuplicateMapKey(1)), got {:?}", other),
        }
    }

    // Tests that duplicate keys between direct and embed fields are detected
    // during decoding when receiving hand-crafted CBOR with a collision.
    #[test]
    fn test_map_embed_duplicate_key_decode() {
        #[derive(Debug, PartialEq, Cbor)]
        struct Clash {
            #[cbor(key = 1)] // same key as Inner.a
            x: u64,
            #[cbor(embed)]
            inner: Inner,
        }
        // Hand-craft CBOR: {1: 99, 2: "hi"} — key 1 collides between direct
        // field x and embed field inner.a. Decode must reject with DuplicateMapKey.
        let mut enc = Encoder::new();
        enc.encode_map_header(2);
        enc.encode_int(1);
        enc.encode_uint(99);
        enc.encode_int(2);
        enc.extend(&"hi".to_string().encode_cbor().unwrap());
        let data = enc.finish();
        match decode::<Clash>(&data) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected DuplicateMapKey(1), got {:?}", other),
        }
    }

    // Tests that multiple embedded structs round-trip correctly: two embeds
    // with non-overlapping key ranges plus a direct field.
    #[test]
    fn test_map_embed_multiple() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct EmbedA {
            #[cbor(key = 1)]
            a: u64,
            #[cbor(key = 2)]
            b: String,
        }
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct EmbedB {
            #[cbor(key = 3)]
            c: Vec<u8>,
            #[cbor(key = 4)]
            d: u64,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct Multi {
            #[cbor(embed)]
            first: EmbedA,
            #[cbor(embed)]
            second: EmbedB,
            #[cbor(key = -1)]
            extra: String,
        }
        let val = Multi {
            first: EmbedA {
                a: 10,
                b: "hello".to_string(),
            },
            second: EmbedB {
                c: vec![0xDE, 0xAD],
                d: 42,
            },
            extra: "world".to_string(),
        };
        let data = encode(&val).unwrap();
        // All 5 keys should be present: 1, 2, 3, 4, -1
        assert_eq!(data[0], 0xa5); // map with 5 entries
        let decoded = decode::<Multi>(&data).unwrap();
        assert_eq!(decoded, val);
    }

    // Tests that nested embeds (an embed containing another embed) work.
    #[test]
    fn test_map_embed_nested() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct Base {
            #[cbor(key = 1)]
            x: u64,
        }
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct Mid {
            #[cbor(embed)]
            base: Base,
            #[cbor(key = 2)]
            y: String,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct Top {
            #[cbor(embed)]
            mid: Mid,
            #[cbor(key = 3)]
            z: u64,
        }
        let val = Top {
            mid: Mid {
                base: Base { x: 1 },
                y: "two".to_string(),
            },
            z: 3,
        };
        let data = encode(&val).unwrap();
        assert_eq!(data[0], 0xa3); // 3 entries
        let decoded = decode::<Top>(&data).unwrap();
        assert_eq!(decoded, val);
    }

    // Tests mixed positive/negative embed keys decode correctly.
    #[test]
    fn test_map_embed_mixed_sign_keys_decode() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct SignedInner {
            #[cbor(key = 1)]
            pos: u64,
            #[cbor(key = -1)]
            neg: u64,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct SignedOuter {
            #[cbor(embed)]
            inner: SignedInner,
            #[cbor(key = 2)]
            c: u64,
        }
        let val = SignedOuter {
            inner: SignedInner { pos: 11, neg: 22 },
            c: 33,
        };
        let data = encode(&val).unwrap();
        let decoded = decode::<SignedOuter>(&data).unwrap();
        assert_eq!(decoded, val);
    }

    // Tests that overlapping keys between two embeds are detected on decode.
    #[test]
    fn test_map_embed_embed_collision() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct Left {
            #[cbor(key = 1)]
            a: u64,
            #[cbor(key = 2)]
            b: u64,
        }
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct Right {
            #[cbor(key = 2)] // collides with Left.b
            c: u64,
            #[cbor(key = 3)]
            d: u64,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct Both {
            #[cbor(embed)]
            left: Left,
            #[cbor(embed)]
            right: Right,
        }
        // Hand-craft CBOR with keys 1, 2, 3 (no wire-level duplicate, but
        // embeds Left and Right both claim key 2).
        let mut enc = Encoder::new();
        enc.encode_map_header(3);
        enc.encode_int(1);
        enc.encode_uint(10);
        enc.encode_int(2);
        enc.encode_uint(20);
        enc.encode_int(3);
        enc.encode_uint(30);
        let data = enc.finish();
        match decode::<Both>(&data) {
            Err(Error::DuplicateMapKey(2)) => {}
            other => panic!("expected DuplicateMapKey(2), got {:?}", other),
        }
    }

    // Tests that unknown keys in the wire data are rejected during decode.
    #[test]
    fn test_map_embed_unknown_key() {
        // Hand-craft CBOR: {1: 1, 2: "two", 3: 3, 99: 0} where key 99 is
        // not claimed by any direct field or embed.
        #[derive(Debug, PartialEq, Cbor)]
        struct Embedded {
            #[cbor(embed)]
            inner: Inner,
            #[cbor(key = 3)]
            c: u64,
        }
        let mut enc = Encoder::new();
        enc.encode_map_header(4);
        enc.encode_int(1);
        enc.encode_uint(1);
        enc.encode_int(2);
        enc.extend(&"two".to_string().encode_cbor().unwrap());
        enc.encode_int(3);
        enc.encode_uint(3);
        enc.encode_int(99);
        enc.encode_uint(0);
        let data = enc.finish();
        match decode::<Embedded>(&data) {
            Err(Error::DecodeFailed(msg)) if msg.contains("unknown") => {}
            other => panic!("expected DecodeFailed with 'unknown', got {:?}", other),
        }
    }

    // Tests that out-of-order keys in wire data are rejected during embed decode.
    #[test]
    fn test_map_embed_key_order_rejected() {
        #[derive(Debug, PartialEq, Cbor)]
        struct Embedded {
            #[cbor(embed)]
            inner: Inner,
            #[cbor(key = 3)]
            c: u64,
        }
        // Hand-craft CBOR with keys out of order: {2: "x", 1: 1, 3: 3}
        let mut enc = Encoder::new();
        enc.encode_map_header(3);
        enc.encode_int(2);
        enc.extend(&"x".to_string().encode_cbor().unwrap());
        enc.encode_int(1);
        enc.encode_uint(1);
        enc.encode_int(3);
        enc.encode_uint(3);
        let data = enc.finish();
        match decode::<Embedded>(&data) {
            Err(Error::InvalidMapKeyOrder(1, 2)) => {}
            other => panic!("expected InvalidMapKeyOrder(1, 2), got {:?}", other),
        }
    }

    // Tests that wire-level duplicate keys are rejected during embed decode.
    #[test]
    fn test_map_embed_wire_duplicate_key() {
        #[derive(Debug, PartialEq, Cbor)]
        struct Embedded {
            #[cbor(embed)]
            inner: Inner,
            #[cbor(key = 3)]
            c: u64,
        }
        // Hand-craft CBOR with duplicate key 1: {1: 1, 1: 2, 2: "x", 3: 3}
        let mut enc = Encoder::new();
        enc.encode_map_header(4);
        enc.encode_int(1);
        enc.encode_uint(1);
        enc.encode_int(1);
        enc.encode_uint(2);
        enc.encode_int(2);
        enc.extend(&"x".to_string().encode_cbor().unwrap());
        enc.encode_int(3);
        enc.encode_uint(3);
        let data = enc.finish();
        match decode::<Embedded>(&data) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected DuplicateMapKey(1), got {:?}", other),
        }
    }

    // Tests that schema-level collision between an optional direct field and
    // an embed field is caught on encode even when the optional is None.
    #[test]
    fn test_map_embed_optional_overlap_encode() {
        #[derive(Debug, Clone, PartialEq, Cbor)]
        struct EmbedInner {
            #[cbor(key = 1)]
            a: u64,
        }
        #[derive(Debug, PartialEq, Cbor)]
        struct Broken {
            #[cbor(key = 1)]
            x: Option<u64>, // collides with EmbedInner.a
            #[cbor(embed)]
            inner: EmbedInner,
        }
        match encode(&Broken {
            x: None,
            inner: EmbedInner { a: 42 },
        }) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected Err(DuplicateMapKey(1)), got {:?}", other),
        }
    }

    // Tests that embed encoding validates actual merged keys too, not only
    // keys reported by the embed's schema declaration.
    #[test]
    fn test_map_embed_runtime_key_mismatch_rejected() {
        #[derive(Debug, Clone, PartialEq)]
        struct RogueEmbed;

        impl MapEncode for RogueEmbed {
            fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), Error> {
                enc.push(1i64, &7u64)?;
                Ok(())
            }
        }

        impl MapDecode for RogueEmbed {
            fn cbor_map_keys() -> &'static [i64] {
                // Intentionally dishonest: claims key 2.
                &[2]
            }

            fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, Error> {
                let _ = entries.take(2);
                Ok(Self)
            }
        }

        #[derive(Debug, PartialEq, Cbor)]
        struct Parent {
            #[cbor(key = 1)]
            x: u64,
            #[cbor(embed)]
            rogue: RogueEmbed,
        }

        match encode(&Parent {
            x: 42,
            rogue: RogueEmbed,
        }) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected Err(DuplicateMapKey(1)), got {:?}", other),
        }
    }

    // Tests the entry helper functions round-trip correctly.
    #[test]
    fn test_map_entries_roundtrip() {
        let original = TestMap {
            key1: 42,
            key2: 67,
            key_neg1: 100,
        };
        let data = encode(&original).unwrap();
        let entries = decode_map_entries(&data).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, 1);
        assert_eq!(entries[1].0, 2);
        assert_eq!(entries[2].0, -1);

        let re_encoded = encode_map_entries(&entries);
        assert_eq!(data, re_encoded);
    }

    // Tests that decode_map_entries rejects out-of-order and duplicate keys.
    #[test]
    fn test_map_entries_rejection() {
        // Out-of-order keys: 2 before 1.
        let mut enc = Encoder::new();
        enc.encode_map_header(2);
        enc.encode_int(2);
        enc.encode_uint(67);
        enc.encode_int(1);
        enc.encode_uint(42);
        match decode_map_entries(&enc.finish()) {
            Err(Error::InvalidMapKeyOrder(1, 2)) => {}
            other => panic!("expected InvalidMapKeyOrder(1, 2), got {:?}", other),
        }

        // Duplicate keys: 1 appears twice.
        let mut enc = Encoder::new();
        enc.encode_map_header(2);
        enc.encode_int(1);
        enc.encode_uint(1);
        enc.encode_int(1);
        enc.encode_uint(2);
        match decode_map_entries(&enc.finish()) {
            Err(Error::DuplicateMapKey(1)) => {}
            other => panic!("expected DuplicateMapKey(1), got {:?}", other),
        }
    }

    // Tests that deeply nested CBOR structures are rejected with an error
    // instead of causing a stack overflow, but nesting up to the maximum
    // depth is still accepted.
    #[test]
    fn test_max_nesting_depth() {
        let mut at_limit = vec![0x81u8; MAX_DEPTH - 1];
        at_limit.push(0x00);
        assert!(verify(&at_limit).is_ok());

        let mut over_limit = vec![0x81u8; MAX_DEPTH + 1];
        over_limit.push(0x00);
        assert_eq!(verify(&over_limit), Err(Error::MaxDepthExceeded(MAX_DEPTH)));
    }
}
