// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#![no_main]

use darkbio_crypto::cbor::{decode, encode};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

macro_rules! roundtrip {
    ($data:expr, $( $typ:ty ),+ $(,)?) => {
        $(
            if let Ok(decoded) = decode::<$typ>($data) {
                let encoded = encode(&decoded);
                let decoded2 = decode::<$typ>(&encoded)
                    .expect(concat!("Failed to decode re-encoded data for ", stringify!($typ)));
                assert_eq!(decoded, decoded2, "Roundtrip failed for type: {}", stringify!($typ));
            }
        )+
    };
}

fuzz_target!(|data: &[u8]| {
    roundtrip!(
        data,
        String,
        u64,
        i64,
        Vec<u8>,
        (),
        (String,),
        (u64,),
        (i64,),
        (String, u64),
        (String, i64),
        (u64, String),
        (i64, String),
        (String, String),
        (u64, i64),
        (i64, u64),
        [u8; 1],
        [u8; 2],
        [u8; 4],
        [u8; 8],
        ((u64, [u8; 4]), (String, u64)),
        ((i64, [u8; 4]), (String, i64)),
        HashMap<i64, u64>,
        HashMap<i64, String>,
        HashMap<i64, Vec<u8>>,
        HashMap<i64, HashMap<i64, u64>>,
    );
});
