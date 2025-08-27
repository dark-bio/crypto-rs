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

/// seal serializes an object and encrypts it, authenticating over the sender,
/// recipient, timestamp and a user-provided authentication payload.
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

/// open decrypts and deserializes an object, authenticating over the sender,
/// recipient, timestamp and a user-provided authentication payload.
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

/// sign is a subset of seal where no object is provided to be encrypted, rather
/// only authentication is done.
///
/// This is analogous to digital signatures, but the identity isn't tied to one
/// participant, rather between two parties. Both parties can create and verify
/// arbitrary messages between them (i.e. no directionality or origin).
pub fn sign<A: Serialize>(ctx: &Context, timestamp: u64, object: &A) -> Result<Vec<u8>, DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, object);

    // Serialize the object and authenticate
    let msg_to_auth = cbor::encode(&envelope)?;
    Ok(ctx.sign(&msg_to_auth)?)
}

/// verify is a subset of open where no object is expected to be decrypted, rather
/// only authenticity verification is done.
///
/// This is analogous to verifying digital signatures, but the identity isn't tied
/// to one participant, rather between two parties. Both parties can create and
/// verify arbitrary messages between them (i.e. no directionality or origin).
pub fn verify<A: Serialize>(
    ctx: &Context,
    timestamp: u64,
    object: &A,
    signature: &[u8],
) -> Result<(), DoeError> {
    // Construct the full authentication envelope
    let envelope: Envelope<A> = (timestamp, object);

    // Serialize the object and verify the message
    let msg_to_auth = cbor::encode(&envelope)?;
    Ok(ctx.verify(&msg_to_auth, signature)?)
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

        // Round trip sealing and opening the objects
        let enc = seal(&alice_context, 314, &obj_to_seal, &obj_to_auth)
            .unwrap_or_else(|e| panic!("failed to seal object: {}", e));

        let dec: TestObj = open(&bobby_context, 314, &enc, &obj_to_auth)
            .unwrap_or_else(|e| panic!("failed to open object: {}", e));

        // Validate that the cleartext matches our expected encrypted payload.
        assert_eq!(obj_to_seal, dec, "object mismatch");
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

        // Round trip sealing and opening the objects
        let sig = sign(&alice_context, 314, &obj_to_auth)
            .unwrap_or_else(|e| panic!("failed to auth object: {}", e));

        verify(&bobby_context, 314, &obj_to_auth, &sig)
            .unwrap_or_else(|e| panic!("failed to verify object: {}", e));
    }
}
