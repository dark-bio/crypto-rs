// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use ciborium::{de, ser, Value};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Cursor, Error};

/// encode CBOR encodes an arbitrary value into a freshly allocated byte slice
/// and returns it along with any error. After encoding, it will do a sanity
/// decode to ensure no forbidden types were used. This might make sense to do
/// with less overhead, but we're aiming for correctness, not speed now.
///
/// If either encoding or type restriction fails, the method panics. It will be
/// considered a programming error at the call site and there's no meaningful
/// way to recover from.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    // Encode the value into a new buffer
    let mut buf = Vec::new();
    ser::into_writer(value, &mut buf).unwrap();

    // Decode it as a generic value and validate type restrictions
    let mut cur = Cursor::new(&buf);
    let dec: Value = de::from_reader(&mut cur).unwrap();
    restrict(&dec).unwrap();

    buf
}

/// decode CBOR decodes a byte slice into an arbitrary type, ensuring that all
/// data is fully consumed and that it contains only allowed types. This is done
/// by first decoding into a generic container and restricting the types, after
/// which it is re-encoded to ensure it was in a canonical format. This might
/// make sense to do with less overhead, but we're aiming for correctness, not
/// speed now.
pub fn decode<T: Serialize + DeserializeOwned>(blob: &[u8]) -> Result<T, de::Error<Error>> {
    // Verify the CBOR blob before even touching it
    verify(blob)?;

    // Canonical and typ-restricted, parse it
    let mut cur = Cursor::new(blob);
    let res: T = de::from_reader(&mut cur)?;
    Ok(res)
}

/// verify attempts to decode and re-encode a CBOR blob to verify that it has a
/// canonical encoding and contains only allowed types. This is meant to be used
/// in FFI settings to allow using CBOR libraries from arbitrary languages but
/// still ensure they conform to the same enforced specs.
pub fn verify(blob: &[u8]) -> Result<(), de::Error<Error>> {
    // Validate that the blob only contains allowed types
    let mut cur = Cursor::new(blob);
    let dec: Value = de::from_reader(&mut cur)?;
    restrict(&dec)?;

    // Re-encode it to verify canonical-ness (also ensuring all bytes were used)
    let enc = encode(&dec);
    if enc != blob {
        return Err(de::Error::Io(Error::new(
            std::io::ErrorKind::InvalidData,
            "non-canonical CBOR (re-encode mismatch)",
        )));
    }
    Ok(())
}

/// restrict checks that a ciborium::Value only contains allowed types.
///
/// Currently, types disallowed are:
///   - Null:  We want to encode data, not encode not-data
///   - Bool:  Hard to reason about across languages, 0, 1, special?
///   - Float: Not fully defined (CPU dependent), canonicalness issues
///   - Map:   Has 3 "canonical standards", varied fields not needed
///   - Tag:   No magic fields, our use case is cryptography
fn restrict(val: &Value) -> Result<(), de::Error<Error>> {
    match val {
        Value::Integer(_) => Ok(()),
        Value::Text(_) => Ok(()),
        Value::Bytes(_) => Ok(()),
        Value::Array(arr) => {
            for item in arr {
                restrict(item)?;
            }
            Ok(())
        }
        _ => Err(de::Error::Io(Error::new(
            std::io::ErrorKind::InvalidData,
            format!("disallowed CBOR value type: {:?}", val),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Person {
        name: String,
        age: u8,
        phones: Vec<String>,
    }

    // Tests that allowed types can be encoded and decoded.
    #[test]
    fn test_roundtrip() {
        let p_in: u64 = 42;
        let p_enc = encode(&p_in);
        let p_out: u64 = decode(&p_enc).expect("decode u64");
        verify(&p_enc).expect("verify u64");
        assert_eq!(p_out, p_in);

        let n_in: i64 = -42;
        let n_enc = encode(&n_in);
        let n_out: i64 = decode(&n_enc).expect("decode i64");
        verify(&n_enc).expect("verify i64");
        assert_eq!(n_out, n_in);

        let s_in = String::from("hello");
        let s_enc = encode(&s_in);
        let s_out: String = decode(&s_enc).expect("decode string");
        verify(&s_enc).expect("verify string");
        assert_eq!(s_out, s_in);

        let b_in = vec![1u8, 2, 3, 4];
        let b_enc = encode(&b_in);
        let b_out: Vec<u8> = decode(&b_enc).expect("decode binary");
        verify(&b_enc).expect("verify binary");
        assert_eq!(b_out, b_in);

        let a_in = vec!["Peter".to_string(), "says".to_string(), "Hi!".to_string()];
        let a_enc = encode(&a_in);
        let a_out: Vec<String> = decode(&a_enc).expect("decode array");
        verify(&a_enc).expect("verify array");
        assert_eq!(a_out, a_in);

        let t_in = ("Ark".to_string(), 1);
        let t_enc = encode(&t_in);
        let t_out: (String, u64) = decode(&t_enc).expect("decode tuple");
        verify(&t_enc).expect("verify tuple");
        assert_eq!(t_out, t_in);
    }

    // Tests that trailing bytes are rejected during decoding.
    #[test]
    fn test_reject_trailing_byte() {
        // Create a good encoding and stuff a byte into it
        let mut blob = encode(&0u32);
        blob.push(0x00);

        // Sanity check that it's detected
        decode::<u32>(&blob).expect_err("decode should fail on trailing bytes");
        verify(&blob).expect_err("verify should fail on trailing bytes");
    }

    // Tests that 0 padded positive integers are rejected.
    #[test]
    fn test_reject_overlong_positive() {
        let blob: &[u8] = &[0x18, 0x00]; // should be just 0x00
        decode::<u64>(blob).expect_err("overlong 0 must be rejected");
        verify(blob).expect_err("overlong 0 must be rejected");
    }

    // Tests that 0 padded negative integers are rejected.
    #[test]
    fn test_reject_overlong_negative() {
        let blob: &[u8] = &[0x38, 0x00]; // should be 0x20
        decode::<i64>(blob).expect_err("overlong -1 must be rejected");
        verify(blob).expect_err("overlong -1 must be rejected");
    }

    // Tests that indefinite-length text are rejected.
    #[test]
    fn test_reject_indefinite_text() {
        // Construct a CBOR indefinite-length text string "hello":
        //   0x7f = start indefinite-length text, then two chunks
        //   0x62 'h' 'e' (length 2)
        //   0x63 'l' 'l' 'o' (length 3)
        //   0xff = break
        let blob: &[u8] = &[0x7f, 0x62, b'h', b'e', 0x63, b'l', b'l', b'o', 0xff];

        decode::<String>(blob).expect_err("decode should fail on indefinite-length text");
        verify(blob).expect_err("verify should fail on indefinite-length text");
    }

    // Tests that indefinite-length bytes are rejected.
    #[test]
    fn test_reject_indefinite_bytes() {
        // Construct a CBOR indefinite-length byte string "hello":
        //   0x5f = start indefinite-length byte string, then two chunks
        //   0x42 b'h' b'e' (length 2)
        //   0x43 b'l' b'l' b'o' (length 3)
        //   0xff = break
        let blob: &[u8] = &[0x5f, 0x42, b'h', b'e', 0x43, b'l', b'l', b'o', 0xff];

        decode::<Vec<u8>>(blob).expect_err("decode should fail on indefinite-length bytes");
        verify(blob).expect_err("verify should fail on indefinite-length bytes");
    }
}
