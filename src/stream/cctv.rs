// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! STREAM conformance tests against the C2SP CCTV age testkit.
//!
//! https://github.com/C2SP/CCTV/tree/main/age

use super::{PayloadKey, Stream};
use crate::hkdf;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

// Test vectors from the C2SP CCTV age testkit, stream family, vendored at
// commit 1e3d2860d46e94e777e1b17c7a6f2436387e3ecc.
const VECTORS: &[(&str, &[u8])] = &[
    (
        "stream_257_chunks",
        include_bytes!("testdata/cctv/stream_257_chunks"),
    ),
    (
        "stream_257_chunks_full",
        include_bytes!("testdata/cctv/stream_257_chunks_full"),
    ),
    (
        "stream_258_chunks",
        include_bytes!("testdata/cctv/stream_258_chunks"),
    ),
    (
        "stream_bad_tag",
        include_bytes!("testdata/cctv/stream_bad_tag"),
    ),
    (
        "stream_bad_tag_second_chunk",
        include_bytes!("testdata/cctv/stream_bad_tag_second_chunk"),
    ),
    (
        "stream_bad_tag_second_chunk_full",
        include_bytes!("testdata/cctv/stream_bad_tag_second_chunk_full"),
    ),
    (
        "stream_empty_payload",
        include_bytes!("testdata/cctv/stream_empty_payload"),
    ),
    (
        "stream_last_chunk_empty",
        include_bytes!("testdata/cctv/stream_last_chunk_empty"),
    ),
    (
        "stream_last_chunk_full",
        include_bytes!("testdata/cctv/stream_last_chunk_full"),
    ),
    (
        "stream_last_chunk_full_second",
        include_bytes!("testdata/cctv/stream_last_chunk_full_second"),
    ),
    (
        "stream_missing_tag",
        include_bytes!("testdata/cctv/stream_missing_tag"),
    ),
    (
        "stream_no_chunks",
        include_bytes!("testdata/cctv/stream_no_chunks"),
    ),
    (
        "stream_no_final",
        include_bytes!("testdata/cctv/stream_no_final"),
    ),
    (
        "stream_no_final_full",
        include_bytes!("testdata/cctv/stream_no_final_full"),
    ),
    (
        "stream_no_final_two_chunks",
        include_bytes!("testdata/cctv/stream_no_final_two_chunks"),
    ),
    (
        "stream_no_final_two_chunks_full",
        include_bytes!("testdata/cctv/stream_no_final_two_chunks_full"),
    ),
    (
        "stream_no_nonce",
        include_bytes!("testdata/cctv/stream_no_nonce"),
    ),
    (
        "stream_short_chunk",
        include_bytes!("testdata/cctv/stream_short_chunk"),
    ),
    (
        "stream_short_nonce",
        include_bytes!("testdata/cctv/stream_short_nonce"),
    ),
    (
        "stream_short_second_chunk",
        include_bytes!("testdata/cctv/stream_short_second_chunk"),
    ),
    (
        "stream_three_chunks",
        include_bytes!("testdata/cctv/stream_three_chunks"),
    ),
    (
        "stream_trailing_garbage_long",
        include_bytes!("testdata/cctv/stream_trailing_garbage_long"),
    ),
    (
        "stream_trailing_garbage_short",
        include_bytes!("testdata/cctv/stream_trailing_garbage_short"),
    ),
    (
        "stream_two_chunks",
        include_bytes!("testdata/cctv/stream_two_chunks"),
    ),
    (
        "stream_two_final_chunks",
        include_bytes!("testdata/cctv/stream_two_final_chunks"),
    ),
    (
        "stream_two_final_chunks_full",
        include_bytes!("testdata/cctv/stream_two_final_chunks_full"),
    ),
    (
        "stream_two_final_chunks_second",
        include_bytes!("testdata/cctv/stream_two_final_chunks_second"),
    ),
    (
        "stream_two_final_chunks_short",
        include_bytes!("testdata/cctv/stream_two_final_chunks_short"),
    ),
];

// Tests the STREAM implementation against the CCTV age testkit vectors:
// success vectors must decrypt fully to the expected payload hash and
// re-encrypt byte for byte; failure vectors must error with only the
// expected prefix released.
#[test]
fn test_cctv_vectors() {
    for (name, data) in VECTORS {
        // Split the vector into its textual header and the age file body
        let sep = find(data, b"\n\n").unwrap();
        let header = std::str::from_utf8(&data[..sep]).unwrap();

        let mut expect = "";
        let mut payload = None;
        let mut filekey = Vec::new();
        let mut compressed = false;
        for line in header.lines() {
            match line.split_once(": ").unwrap() {
                ("expect", v) => expect = v,
                ("payload", v) => payload = Some(v),
                ("file key", v) => filekey = hex::decode(v).unwrap(),
                ("compressed", v) => compressed = v == "zlib",
                _ => {}
            }
        }
        // Decompress the body if needed and slice off the header and MAC
        let mut body = data[sep + 2..].to_vec();
        if compressed {
            body = miniz_oxide::inflate::decompress_to_vec_zlib(&body).unwrap();
        }
        let mac = find(&body, b"\n--- ").unwrap();
        let nl = mac + 1 + find(&body[mac + 1..], b"\n").unwrap();
        let paysec = &body[nl + 1..];

        // A payload too short for the nonce must never be a success vector
        if paysec.len() < 16 {
            assert_ne!(expect, "success", "{name}");
            continue;
        }
        // Derive the payload key and decrypt, collecting released plaintext
        let key = hkdf::key::<32>(&filekey, &paysec[..16], b"payload");
        let ciphertext = &paysec[16..];

        let mut reader = Stream::decrypt(PayloadKey::from_bytes(&key), ciphertext);
        let mut released = Vec::new();
        let mut buf = [0u8; 65536];
        let result = loop {
            match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => released.extend_from_slice(&buf[..n]),
                Err(err) => break Err(err),
            }
        };
        // Whatever was handed out must match the expected payload hash
        if let Some(hash) = payload {
            assert_eq!(hex::encode(Sha256::digest(&released)), hash, "{name}");
        }
        if expect == "success" {
            // Decryption must succeed and re-encrypting the recovered
            // plaintext must reproduce the ciphertext byte for byte
            result.unwrap_or_else(|err| panic!("{name}: {err}"));

            let mut reencrypted = Vec::new();
            let mut writer = Stream::encrypt(PayloadKey::from_bytes(&key), &mut reencrypted);
            writer.write_all(&released).unwrap();
            writer.finish().unwrap();
            assert_eq!(reencrypted, ciphertext, "{name}");
        } else {
            assert!(result.is_err(), "{name}");
        }
    }
}

// find locates the first occurrence of a pattern in a byte slice.
fn find(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}
