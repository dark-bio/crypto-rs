// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! DarkBio Object Encryption (and Authentication).

use crate::cbor;
use crate::hpke::Context;
use ciborium::{de, ser};
use hpke::HpkeError;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Envelope contains all the information that will be used as the authentication
/// message for a HPKE seal or sign operation:
///   - Timestamp: 64 bit Unix timestamp
///   - Payload: user supplied payload (CBOR)
#[allow(type_alias_bounds)]
type Envelope<'a, T: Serialize> = (u64, &'a T);

/// DoeError is a container for the different errors that can happen during the
/// object sealing and opening.
#[derive(Debug)]
pub enum DoeError {
    Hpke(HpkeError),
    CborEnc(ser::Error<std::io::Error>),
    CborDec(de::Error<std::io::Error>),
}

impl From<HpkeError> for DoeError {
    fn from(e: HpkeError) -> Self {
        DoeError::Hpke(e)
    }
}
impl From<ser::Error<std::io::Error>> for DoeError {
    fn from(e: ser::Error<std::io::Error>) -> Self {
        DoeError::CborEnc(e)
    }
}
impl From<de::Error<std::io::Error>> for DoeError {
    fn from(e: de::Error<std::io::Error>) -> Self {
        DoeError::CborDec(e)
    }
}
impl core::fmt::Display for DoeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DoeError::Hpke(e) => write!(f, "HPKE error: {e}"),
            DoeError::CborEnc(e) => write!(f, "CBOR encode error: {e}"),
            DoeError::CborDec(e) => write!(f, "CBOR decode error: {e}"),
        }
    }
}
impl std::error::Error for DoeError {}

/// seal serializes an object and encrypts it, authenticating over the timestamp
/// and a user-provided authentication payload.
pub fn seal<S: Serialize, A: Serialize>(
    ctx: &Context,
    timestamp: u64,
    obj_to_seal: &S,
    obj_to_auth: &A,
) -> Result<Vec<u8>, DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, obj_to_auth);

    // Serialize the components and seal them
    let msg_to_seal = cbor::encode(obj_to_seal)?;
    let msg_to_auth = cbor::encode(&envelope)?;

    Ok(ctx.seal(&msg_to_seal, &msg_to_auth)?)
}

/// seal_raw is an expensive (!) helper method that seals already CBOR encoded
/// objects. Internally it will actually parse the given objects and re-encode
/// them to ensure canonicalness.
///
/// The purpose of this method is to be used in FFI settings where generic data
/// types cannot be crossed over to call the original seal method.
pub fn seal_raw(
    ctx: &Context,
    timestamp: u64,
    obj_to_seal: &[u8],
    obj_to_auth: &[u8],
) -> Result<Vec<u8>, DoeError> {
    // Parse the already encoded CBOR objects
    let val_to_seal = cbor::decode::<ciborium::Value>(obj_to_seal)?;
    let val_to_auth = cbor::decode::<ciborium::Value>(obj_to_auth)?;

    // Seal them, re-encoded with the upstream codec
    seal(ctx, timestamp, &val_to_seal, &val_to_auth)
}

/// open decrypts and deserializes an object, authenticating over the timestamp
/// and a user-provided payload.
pub fn open<D: Serialize + DeserializeOwned, A: Serialize>(
    ctx: &Context,
    timestamp: u64,
    msg_to_open: &[u8],
    obj_to_auth: &A,
) -> Result<D, DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, obj_to_auth);

    // Open the sealed message
    let msg_to_auth = cbor::encode(&envelope)?;
    let opened = ctx.open(&msg_to_open, &msg_to_auth)?;

    Ok(cbor::decode::<D>(&opened)?)
}

/// open_raw is an expensive (!) helper method that decrypts and deserializes
/// an object, authenticating over the timestamp and an already CBOR encoded
/// user-provided payload. Internally it will actually parse the given payload
/// and re-encode it to ensure canonicalness. Further the decrypted object is
/// re-encoded to CBOR and returned like that to the user.
///
/// The purpose of this method is to be used in FFI settings where generic data
/// types cannot be crossed over to call the original open method.
pub fn open_raw(
    ctx: &Context,
    timestamp: u64,
    msg_to_open: &[u8],
    obj_to_auth: &[u8],
) -> Result<Vec<u8>, DoeError> {
    // Parse the already encoded CBOR authentication object
    let val_to_auth = cbor::decode::<ciborium::Value>(obj_to_auth)?;

    // Open the sealed message and turn it back into a CBOR encoding
    let opened = open::<ciborium::Value, _>(ctx, timestamp, msg_to_open, &val_to_auth)?;

    Ok(cbor::encode(&opened)?)
}

/// sign is a subset of seal where no object is provided to be encrypted, rather
/// only authentication is done.
///
/// This is analogous to digital signatures, but only the receiving key can prove
/// anything about the message (without revealing their private key).
pub fn sign<A: Serialize>(
    ctx: &Context,
    timestamp: u64,
    obj_to_auth: &A,
) -> Result<Vec<u8>, DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, obj_to_auth);

    // Serialize the object and authenticate
    let msg_to_auth = cbor::encode(&envelope)?;
    Ok(ctx.sign(&msg_to_auth)?)
}

/// sign_raw is an expensive (!) helper method that is a subset of seal where no
/// object is provided to be encrypted, rather only authentication is done on an
/// already CBOR encoded message. Internally it will actually parse the given
/// object and re-encode it to ensure canonicalness.
///
/// The purpose of this method is to be used in FFI settings where generic data
/// types cannot be crossed over to call the original seal method.
///
/// This is analogous to digital signatures, but only the receiving key can prove
/// anything about the message (without revealing their private key).
pub fn sign_raw(ctx: &Context, timestamp: u64, obj_to_auth: &[u8]) -> Result<Vec<u8>, DoeError> {
    // Parse the already encoded CBOR object
    let val_to_auth = cbor::decode::<ciborium::Value>(obj_to_auth)?;

    // Sign it, re-encoded with the upstream codec
    sign(ctx, timestamp, &val_to_auth)
}

/// verify is a subset of open where no object is expected to be decrypted, rather
/// only authenticity verification is done.
///
/// This is analogous to digital signatures, but only the receiving key can prove
/// anything about the message (without revealing their private key).
pub fn verify<A: Serialize>(
    ctx: &Context,
    timestamp: u64,
    obj_to_auth: &A,
    signature: &[u8],
) -> Result<(), DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, obj_to_auth);

    // Serialize the object and verify the message
    let msg_to_auth = cbor::encode(&envelope)?;
    Ok(ctx.verify(&msg_to_auth, signature)?)
}

/// verify_raw is an expensive (!) helper method that is a subset of open where no
/// object is expected to be decrypted, rather only authenticity verification is
/// done on an already CBOR encoded message. Internally it will actually parse the
/// given object and re-encode it to ensure canonicalness.
///
/// The purpose of this method is to be used in FFI settings where generic data
/// types cannot be crossed over to call the original seal method.
///
/// This is analogous to digital signatures, but only the receiving key can prove
/// anything about the message (without revealing their private key).
pub fn verify_raw(
    ctx: &Context,
    timestamp: u64,
    obj_to_auth: &[u8],
    signature: &[u8],
) -> Result<(), DoeError> {
    // Parse the already encoded CBOR object
    let val_to_auth = cbor::decode::<ciborium::Value>(obj_to_auth)?;

    // Verify it, re-encoded with the upstream codec
    verify(ctx, timestamp, &val_to_auth, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::SecretKey;

    // Tests sealing and opening objects with authentication.
    //
    // Note, this test is not meant to test cryptography, it is mostly an API
    // sanity check to verify that everything seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
    #[test]
    fn test_seal_open() {
        // Create the keys for Alice and Bobby
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        let alice_context = Context::new(alice_secret, bobby_public, "test");
        let bobby_context = Context::new(bobby_secret, alice_public, "test");

        // Create an object to encrypt and another to authenticate
        type TestObj = (u64, String, Vec<String>);

        let obj_to_seal: TestObj = (1u64, "foo".into(), vec!["bar".into(), "baz".into()]);
        let obj_to_auth = (1, (2, (3, 4)));

        let cbor_to_seal = cbor::encode(&obj_to_seal).unwrap();
        let cbor_to_auth = cbor::encode(&obj_to_auth).unwrap();

        // Round trip sealing and opening the objects
        {
            let enc = seal(&alice_context, 314, &obj_to_seal, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to seal object: {}", e));

            let dec: TestObj = open(&bobby_context, 314, &enc, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to open object: {}", e));

            assert_eq!(obj_to_seal, dec, "object mismatch");
        }
        // Round trip sealing raw and opening real objects
        {
            let enc = seal_raw(&alice_context, 314, &cbor_to_seal, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to seal object: {}", e));

            let dec: TestObj = open(&bobby_context, 314, &enc, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to open object: {}", e));

            assert_eq!(obj_to_seal, dec, "object mismatch");
        }
        // Round trip sealing real and opening raw objects
        {
            let enc = seal(&alice_context, 314, &obj_to_seal, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to seal object: {}", e));

            let cbor_dec = open_raw(&bobby_context, 314, &enc, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to open object: {}", e));
            let dec: TestObj = cbor::decode(&cbor_dec).unwrap();

            assert_eq!(obj_to_seal, dec, "object mismatch");
        }
        // Round trip sealing raw and opening raw objects
        {
            let enc = seal_raw(&alice_context, 314, &cbor_to_seal, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to seal object: {}", e));

            let cbor_dec = open_raw(&bobby_context, 314, &enc, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to open object: {}", e));
            let dec: TestObj = cbor::decode(&cbor_dec).unwrap();

            assert_eq!(obj_to_seal, dec, "object mismatch");
        }
    }

    // Tests authenticating and verifying objects.
    //
    // Note, this test is not meant to test cryptography, it is mostly an API
    // sanity check to verify that everything seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
    #[test]
    fn test_auth_verify() {
        // Create the keys for Alice and Bobby
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        let alice_context = Context::new(alice_secret, bobby_public, "test");
        let bobby_context = Context::new(bobby_secret, alice_public, "test");

        // Create an object to authenticate
        let obj_to_auth = (1, (2, (3, 4)));
        let cbor_to_auth = cbor::encode(&obj_to_auth).unwrap();

        // Round trip signing and verifying the message
        {
            let sig = sign(&alice_context, 314, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to sign object: {}", e));

            verify(&bobby_context, 314, &obj_to_auth, &sig)
                .unwrap_or_else(|e| panic!("failed to verify object: {}", e));
        }
        // Round trip signing the raw- and verifying the real message
        {
            let sig = sign_raw(&alice_context, 314, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to sign object: {}", e));

            verify(&bobby_context, 314, &obj_to_auth, &sig)
                .unwrap_or_else(|e| panic!("failed to verify object: {}", e));
        }
        // Round trip signing the real- and verifying the raw message
        {
            let sig = sign(&alice_context, 314, &obj_to_auth)
                .unwrap_or_else(|e| panic!("failed to sign object: {}", e));

            verify_raw(&bobby_context, 314, &cbor_to_auth, &sig)
                .unwrap_or_else(|e| panic!("failed to verify object: {}", e));
        }
        // Round trip signing the raw- and verifying the raw message
        {
            let sig = sign_raw(&alice_context, 314, &cbor_to_auth)
                .unwrap_or_else(|e| panic!("failed to sign object: {}", e));

            verify_raw(&bobby_context, 314, &cbor_to_auth, &sig)
                .unwrap_or_else(|e| panic!("failed to verify object: {}", e));
        }
    }
}
