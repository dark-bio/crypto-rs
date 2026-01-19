// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#![no_main]

use darkbio_crypto::cbor::{decode, encode, Cbor, Null, Raw};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq, Cbor)]
struct MapSimple {
    #[cbor(key = 1)]
    a: u64,
    #[cbor(key = 2)]
    b: String,
}

#[derive(Debug, PartialEq, Cbor)]
struct MapNested {
    #[cbor(key = 1)]
    x: MapSimple,
    #[cbor(key = -1)]
    y: Vec<u8>,
}

#[derive(Debug, PartialEq, Cbor)]
#[cbor(array)]
struct ArraySimple {
    a: u64,
    b: String,
}

#[derive(Debug, PartialEq, Cbor)]
#[cbor(array)]
struct ArrayWithRaw {
    method: String,
    params: Raw,
}

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
        bool,
        String,
        u64,
        i64,
        Vec<u8>,
        Null,
        Option<u64>,
        Option<i64>,
        Option<String>,
        Option<Vec<u8>>,
        Option<bool>,
        (),
        (String,),
        (u64,),
        (i64,),
        (bool,),
        (String, u64),
        (String, i64),
        (String, bool),
        (u64, String),
        (i64, String),
        (bool, String),
        (String, String),
        (u64, i64),
        (i64, u64),
        (bool, u64),
        (u64, bool),
        [u8; 1],
        [u8; 2],
        [u8; 4],
        [u8; 8],
        ((u64, [u8; 4]), (String, u64)),
        ((i64, [u8; 4]), (String, i64)),
        ((bool, [u8; 4]), (String, bool)),
        Raw,
        (String, Raw),
        (Raw, u64),
        (Raw, bool),
        (Option<String>, u64),
        (u64, Option<String>),
        MapSimple,
        MapNested,
        ArraySimple,
        ArrayWithRaw,
    );
});
