// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CBOR encoding helpers for compile-time key sorting.

/// Encodes an integer key to its CBOR byte representation for sorting.
/// Positive integers use major type 0, negative use major type 1.
pub fn cbor_key_bytes(key: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    if key >= 0 {
        let val = key as u64;
        encode_length(&mut buf, 0, val);
    } else {
        let val = (-1 - key) as u64;
        encode_length(&mut buf, 1, val);
    }
    buf
}

/// Encodes a CBOR type header with major type and length/value.
/// Uses the minimal encoding based on the value size.
fn encode_length(buf: &mut Vec<u8>, major: u8, len: u64) {
    if len < 24 {
        buf.push(major << 5 | len as u8);
    } else if len <= 0xFF {
        buf.push(major << 5 | 24);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(major << 5 | 25);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFFFFFF {
        buf.push(major << 5 | 26);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        buf.push(major << 5 | 27);
        buf.extend_from_slice(&len.to_be_bytes());
    }
}
