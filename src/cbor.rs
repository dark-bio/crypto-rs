// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use ciborium::{de, ser};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Cursor, Error};

/// encode CBOR encodes an arbitrary value into a freshly allocated byte slice
/// and returns it along with any error. It's sugar-coating to avoid having to
/// manually do the boilerplate allocations.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ser::Error<Error>> {
    let mut buf = Vec::new();
    ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// decode CBOR decodes a byte slice into an arbitrary type, ensuring that all
/// data is fully consumed. Furthermore, it also re-encodes the derided data to
/// ensure that it was in canonical format (expensive, but avoids stuffing games
/// with the signatures).
pub fn decode<T: Serialize + DeserializeOwned>(blob: &[u8]) -> Result<T, de::Error<Error>> {
    // Consume the object from the binary blob
    let mut cur = Cursor::new(blob);
    let res: T = de::from_reader(&mut cur)?;

    // Decoding looks ok, re-encode to verify canonical-ness (this also ensures
    // that all bytes were consumed; without this, that's an extra step needed
    // in the decoding above).
    match encode(&res) {
        Err(err) => {
            return Err(de::Error::Io(Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-canonical CBOR (re-encode failure: {})", err),
            )));
        }
        Ok(enc) => {
            if enc != blob {
                return Err(de::Error::Io(Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-canonical CBOR (re-encode mismatch)",
                )));
            }
        }
    };
    Ok(res)
}

/// verify attempts to decode and re-encode a CBOR blob to verify that it has a
/// canonical encoding. This is meant to be used in FFI settings to allow using
/// CBOR libraries from arbitrary languages but still ensure they conform to the
/// same enforced specs.
pub fn verify(blob: &[u8]) -> Result<(), de::Error<Error>> {
    let _ = decode::<ciborium::Value>(blob)?;
    Ok(())
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

    // Tests that some primitive types can be encoded and decoded. This is not
    // meant to be some exhaustive battle-test, rather just sanity checks around
    // the API surface.
    #[test]
    fn test_primitive_roundtrip() {
        let x_in: u64 = 42;
        let blob = encode(&x_in).expect("encode u64");
        let x_out: u64 = decode(&blob).expect("decode u64");
        verify(&blob).expect("verify u64");
        assert_eq!(x_out, x_in);

        let s_in = String::from("hello");
        let blob = encode(&s_in).expect("encode string");
        let s_out: String = decode(&blob).expect("decode string");
        verify(&blob).expect("verify string");
        assert_eq!(s_out, s_in);

        let p_in = Person {
            name: "Peter".into(),
            age: 18, // lol
            phones: vec!["+41 123".into(), "+41 456".into()],
        };
        let blob = encode(&p_in).expect("encode struct");
        let p_out: Person = decode(&blob).expect("decode struct");
        verify(&blob).expect("verify struct");
        assert_eq!(p_out, p_in);
    }

    // Tests that trailing bytes are rejected during decoding.
    #[test]
    fn test_trailing_byte() {
        // Create a good encoding and stuff a byte into it
        let mut blob = encode(&0u32).expect("encode u32");
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
