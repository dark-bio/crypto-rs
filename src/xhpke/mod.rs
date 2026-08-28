// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9180

// We can't use Kem for our own type, it clashes with the hpke lib stuff. Let us
// keep our all-caps abbreviations.
#![allow(clippy::upper_case_acronyms)]

pub mod xwing;

use crate::pem;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hpke::rand_core::SeedableRng;
use hpke::{Deserializable, Kem, Serializable};
use pkcs8::PrivateKeyInfo;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Digest;
use spki::der::asn1::BitStringRef;
use spki::der::{AnyRef, Decode, Encode};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

/// OID is the ASN.1 object identifier for X-Wing.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62253.25722");

// KEM, AEAD and KDF are the HPKE crypto suite parameters. They are all 256 bit
// variants, which should be enough for current purposes. Some details:
//
// - For the key exchange, X-Wing was chosen as a hybrid post-quantum KEM that
//   combines X25519 with ML-KEM-768 for quantum resistance.
// - For symmetric encryption, ChaCha20 was chosen, authenticated with Poly1305,
//   which should be more portable to systems without AES hardware acceleration.
// - For key derivation, HKDF was chosen (pretty much the only contender).
type KEM = xwing::Kem;
type AEAD = hpke::aead::ChaCha20Poly1305;
type KDF = hpke::kdf::HkdfSha256;

/// DOMAIN_PREFIX is the prefix prepended to all domain strings before they are
/// used in HPKE operations. This binds every encryption to the dark-bio application
/// context, preventing cross-protocol attacks.
///
/// The final domain will be this prefix concatenated with the caller-supplied
/// domain string.
pub const DOMAIN_PREFIX: &[u8] = b"dark-bio-v1:";

/// Size of the secret key seed in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1216;

/// Size of the encapsulated key in bytes.
pub const ENCAP_KEY_SIZE: usize = 1120;

/// Size of the fingerprint in bytes.
pub const FINGERPRINT_SIZE: usize = 32;

/// Error is the failures that can occur during xHPKE operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("pem: {0}")]
    Pem(#[from] pem::Error),
    #[error("invalid PEM tag {0}")]
    UnexpectedPemTag(String),
    #[error("not an X-Wing key")]
    UnexpectedAlgorithm,
    #[error("malformed key: {0}")]
    MalformedKey(String),
    #[error("trailing data in key encoding")]
    TrailingData,
    #[error("sealing failed: {0}")]
    SealFailed(String),
    #[error("opening failed: {0}")]
    OpenFailed(String),
}

/// SecretKey contains a private key of the type bound to the configured crypto.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    inner: <KEM as Kem>::PrivateKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut rng = rand::rng();

        let (key, _) = KEM::gen_keypair(&mut rng);
        Self { inner: key }
    }

    /// from_bytes converts a 32-byte seed into a private key.
    pub fn from_bytes(bin: &[u8; SECRET_KEY_SIZE]) -> Self {
        let inner = <KEM as Kem>::PrivateKey::from_bytes(bin).unwrap();
        Self { inner }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Parse the DER encoded container
        let info =
            PrivateKeyInfo::from_der(der).map_err(|err| Error::MalformedKey(err.to_string()))?;

        // Reject trailing data by verifying re-encoded length matches input
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Ensure the algorithm OID matches X-Wing and extract the actual private key
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        // Reject v2 keys. The decoder only ever yields v1 keys without or v2
        // keys with an embedded public key, all other combinations fail to
        // parse, so public key presence is an exact v2 marker.
        if info.public_key.is_some() {
            return Err(Error::MalformedKey("unsupported PKCS#8 version".into()));
        }
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            info.private_key
                .try_into()
                .map_err(|_| Error::MalformedKey("private key not 32 bytes".into()))?,
        );
        Ok(SecretKey::from_bytes(&bytes))
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        // Crack open the PEM to get to the private key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        // Parse the DER content
        Self::from_der(&Zeroizing::new(data))
    }

    /// to_bytes converts a private key into a 32-byte seed.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        Zeroizing::new(self.inner.to_bytes().into())
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        let bytes = Zeroizing::new(<[u8; SECRET_KEY_SIZE]>::from(self.inner.to_bytes()));

        // Create the X-Wing algorithm identifier; parameters MUST be absent
        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        // Per RFC, privateKey contains the raw 32-byte seed directly
        let info = PrivateKeyInfo {
            algorithm: alg,
            private_key: bytes.as_slice(),
            public_key: None,
        };
        Zeroizing::new(info.to_der().unwrap())
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem::encode("PRIVATE KEY", &self.to_der()))
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: KEM::sk_to_pk(&self.inner),
        }
    }

    /// fingerprint returns a 256bit unique identifier for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// open consumes a standalone cryptographic construct encrypted to this secret
    /// key. The method will deconstruct the given encapsulated key and ciphertext
    /// and will also verify the authenticity of the (unencrypted) message-to-auth
    /// (not included in the ciphertext).
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The sender's identity
    /// cannot be verified from the ciphertext alone.
    pub fn open(
        &self,
        session_key: &[u8; ENCAP_KEY_SIZE],
        msg_to_open: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Restrict the user's domain to the context of this library
        let info = [DOMAIN_PREFIX, domain].concat();

        // Parse the encapsulated session key
        let session = <KEM as Kem>::EncappedKey::from_bytes(session_key)
            .map_err(|err| Error::OpenFailed(err.to_string()))?;

        // Create a receiver session using Base mode (X-Wing doesn't support Auth mode)
        let mut ctx = hpke::setup_receiver::<AEAD, KDF, KEM>(
            &hpke::OpModeR::Base,
            &self.inner,
            &session,
            &info,
        )
        .map_err(|err| Error::OpenFailed(err.to_string()))?;
        // Verify the construct and decrypt the message if everything checks out
        ctx.open(msg_to_open, msg_to_auth)
            .map_err(|err| Error::OpenFailed(err.to_string()))
    }

    /// new_receiver creates an HPKE receiver context for multi-message decryption
    /// using the given encapsulated key. Messages must be decrypted in the same
    /// order they were encrypted by the corresponding sender.
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The sender's
    /// identity cannot be verified from the context alone.
    pub fn new_receiver(
        &self,
        encap_key: &[u8; ENCAP_KEY_SIZE],
        domain: &[u8],
    ) -> Result<Receiver, Error> {
        // Restrict the user's domain to the context of this library
        let info = [DOMAIN_PREFIX, domain].concat();

        let encapped_key = <KEM as Kem>::EncappedKey::from_bytes(encap_key)
            .map_err(|err| Error::OpenFailed(err.to_string()))?;
        let ctx = hpke::setup_receiver::<AEAD, KDF, KEM>(
            &hpke::OpModeR::Base,
            &self.inner,
            &encapped_key,
            &info,
        )
        .map_err(|err| Error::OpenFailed(err.to_string()))?;
        Ok(Receiver { inner: ctx })
    }
}

/// PublicKey contains a public key of the type bound to the configured crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: <KEM as Kem>::PublicKey,
}

impl PublicKey {
    /// from_bytes converts a 1216-byte array into a public key.
    ///
    /// This validates the ML-KEM-768 component by checking that all polynomial
    /// coefficients are in the valid range [0, 3329). This matches Go's validation.
    pub fn from_bytes(bin: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        // Validate ML-KEM-768 encapsulation key (first 1184 bytes).
        // The key contains 3 polynomials of 256 coefficients each, encoded as 12-bit values.
        // Each coefficient must be < 3329 (the modulus q).
        validate_mlkem768_encapsulation_key(&bin[..1184])?;

        let inner = <KEM as Kem>::PublicKey::from_bytes(bin)
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        Ok(Self { inner })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        // Parse the DER encoded container
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)
                .map_err(|err| Error::MalformedKey(err.to_string()))?;

        // Reject trailing data by verifying re-encoded length matches input
        let length = info
            .encoded_len()
            .map_err(|err| Error::MalformedKey(err.to_string()))?;
        if length.try_into() != Ok(der.len()) {
            return Err(Error::TrailingData);
        }
        // Ensure the algorithm OID matches X-Wing and extract the actual public key
        if info.algorithm.oid != OID {
            return Err(Error::UnexpectedAlgorithm);
        }
        let key = info.subject_public_key.as_bytes().unwrap();

        // Public key extracted, return the wrapper
        let bytes: [u8; 1216] = key
            .try_into()
            .map_err(|_| Error::MalformedKey("public key not 1216 bytes".into()))?;
        PublicKey::from_bytes(&bytes)
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
        // Crack open the PEM to get to the public key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(Error::UnexpectedPemTag(kind));
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes converts a public key into a 1216-byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut result = [0u8; 1216];
        result.copy_from_slice(&self.inner.to_bytes());
        result
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let bytes = self.inner.to_bytes();

        // Create the X-Wing algorithm identifier; parameters MUST be absent
        let alg = AlgorithmIdentifier::<AnyRef> {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        // The subject public key is simply the BITSTRING of the pubkey
        let info = SubjectPublicKeyInfo::<AnyRef, BitStringRef> {
            algorithm: alg,
            subject_public_key: BitStringRef::from_bytes(&bytes).unwrap(),
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identifier for this key. For HPKE,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.to_bytes());
        Fingerprint(hasher.finalize().into())
    }

    /// seal creates a standalone cryptographic construct encrypted to this public
    /// key. The construct will contain the given message-to-seal (encrypted) and
    /// also an authenticity proof for the (unencrypted) message-to-auth (message
    /// not included).
    ///
    /// The method returns the encapsulated session key and the ciphertext separately.
    /// To open it on the other side needs transmitting both components along with
    /// `msg_to_auth`.
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The recipient cannot
    /// verify the sender's identity from the ciphertext alone.
    pub fn seal(
        &self,
        msg_to_seal: &[u8],
        msg_to_auth: &[u8],
        domain: &[u8],
    ) -> Result<([u8; ENCAP_KEY_SIZE], Vec<u8>), Error> {
        // Restrict the user's domain to the context of this library
        let info = [DOMAIN_PREFIX, domain].concat();

        // Create a random number stream that works in WASM
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("Failed to get random seed");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        // Create a sender session using Base mode (X-Wing doesn't support Auth mode)
        let (key, mut ctx) = hpke::setup_sender::<AEAD, KDF, KEM, _>(
            &hpke::OpModeS::Base,
            &self.inner,
            &info,
            &mut rng,
        )
        .map_err(|err| Error::SealFailed(err.to_string()))?;

        // Encrypt the messages and seal all the crypto details into a nice box
        let enc = ctx
            .seal(msg_to_seal, msg_to_auth)
            .map_err(|err| Error::SealFailed(err.to_string()))?;

        let mut encap_key = [0u8; 1120];
        encap_key.copy_from_slice(&key.to_bytes());
        Ok((encap_key, enc))
    }

    /// new_sender creates an HPKE sender context for multi-message encryption
    /// to this public key. Returns the sender context and the encapsulated key
    /// that must be transmitted to the recipient.
    ///
    /// Messages encrypted with the returned context must be decrypted in order
    /// by the corresponding receiver context.
    ///
    /// Note: X-Wing uses Base mode (no sender authentication). The recipient
    /// cannot verify the sender's identity from the context alone.
    pub fn new_sender(&self, domain: &[u8]) -> Result<(Sender, [u8; ENCAP_KEY_SIZE]), Error> {
        // Restrict the user's domain to the context of this library
        let info = [DOMAIN_PREFIX, domain].concat();

        // Create a random number stream that works in WASM
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("Failed to get random seed");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        let (key, ctx) = hpke::setup_sender::<AEAD, KDF, KEM, _>(
            &hpke::OpModeS::Base,
            &self.inner,
            &info,
            &mut rng,
        )
        .map_err(|err| Error::SealFailed(err.to_string()))?;

        let mut encap_key = [0u8; ENCAP_KEY_SIZE];
        encap_key.copy_from_slice(&key.to_bytes());
        Ok((Sender { inner: ctx }, encap_key))
    }
}

/// Sender wraps an HPKE sender encryption context for multi-message
/// communication. Each call to [`seal`](Sender::seal) encrypts a message
/// using an auto-incrementing nonce, ensuring unique ciphertexts even for
/// identical plaintexts.
///
/// The corresponding [`Receiver`] must process messages in the same order
/// they were sealed.
pub struct Sender {
    inner: hpke::aead::AeadCtxS<AEAD, KDF, KEM>,
}

impl Sender {
    /// seal encrypts a message using the next nonce in the sequence.
    pub fn seal(&mut self, msg_to_seal: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .seal(msg_to_seal, msg_to_auth)
            .map_err(|err| Error::SealFailed(err.to_string()))
    }
}

/// Receiver wraps an HPKE receiver decryption context for multi-message
/// communication. Each call to [`open`](Receiver::open) decrypts a
/// message using an auto-incrementing nonce.
///
/// Messages must be provided in the same order they were sealed by the
/// corresponding [`Sender`].
pub struct Receiver {
    inner: hpke::aead::AeadCtxR<AEAD, KDF, KEM>,
}

impl Receiver {
    /// open decrypts a message using the next nonce in the sequence.
    pub fn open(&mut self, msg_to_open: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .open(msg_to_open, msg_to_auth)
            .map_err(|err| Error::OpenFailed(err.to_string()))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid public key length"))?;
        PublicKey::from_bytes(&arr).map_err(de::Error::custom)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for PublicKey {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for PublicKey {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; PUBLIC_KEY_SIZE]>::decode_cbor(data)?;
        Self::from_bytes(&bytes).map_err(|e| crate::cbor::Error::DecodeFailed(e.to_string()))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<PUBLIC_KEY_SIZE>()?;
        Self::from_bytes(&bytes).map_err(|e| crate::cbor::Error::DecodeFailed(e.to_string()))
    }
}

/// Fingerprint contains a 256-bit unique identifier for an HPKE key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl Fingerprint {
    /// from_bytes converts a 32-byte array into a fingerprint.
    pub fn from_bytes(bytes: &[u8; FINGERPRINT_SIZE]) -> Self {
        Self(*bytes)
    }

    /// to_bytes converts a fingerprint into a 32-byte array.
    pub fn to_bytes(&self) -> [u8; FINGERPRINT_SIZE] {
        self.0
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; FINGERPRINT_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid fingerprint length"))?;
        Ok(Fingerprint::from_bytes(&arr))
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for Fingerprint {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for Fingerprint {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; FINGERPRINT_SIZE]>::decode_cbor(data)?;
        Ok(Self::from_bytes(&bytes))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<FINGERPRINT_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// Validates an ML-KEM-768 encapsulation key by checking that all polynomial
/// coefficients are in the valid range [0, 3329).
///
/// The encapsulation key is 1184 bytes: 3 polynomials × 256 coefficients × 12 bits
/// = 1152 bytes for the coefficient vectors, plus 32 bytes for the seed ρ.
fn validate_mlkem768_encapsulation_key(key: &[u8]) -> Result<(), Error> {
    const Q: u16 = 3329;

    // Process 3 bytes at a time (24 bits = 2 coefficients of 12 bits each)
    // Only validate the first 1152 bytes (the polynomial coefficients)
    let coeff_bytes = &key[..1152];
    for chunk in coeff_bytes.chunks(3) {
        // Decode two 12-bit coefficients from 3 bytes (little-endian)
        let coeff1 = u16::from(chunk[0]) | ((u16::from(chunk[1]) & 0x0F) << 8);
        let coeff2 = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);

        if coeff1 >= Q {
            return Err(Error::MalformedKey(format!(
                "invalid ML-KEM coefficient: {} >= {}",
                coeff1, Q
            )));
        }
        if coeff2 >= Q {
            return Err(Error::MalformedKey(format!(
                "invalid ML-KEM coefficient: {} >= {}",
                coeff2, Q
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from draft-connolly-cfrg-xwing-kem-10 Appendix D
    // https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
    mod ietf_vectors {
        pub const SECKEY_SEED: &str =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        pub const SECKEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MDQCAQAwDQYLKwYBBAGD5i2ByHoEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----";

        pub const PUBKEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MIIE1DANBgsrBgEEAYPmLYHIegOCBMEAb1QJigoOZBFGYUtpYLpg2GA9YvRH+atJ
m0e9aQbMQLBh2GNKPoiQbyhJWOdEHKbHJcu5cJW3ZxpGK2aByeZYC7yNYLFJ+mAm
EEOvu6UvIFpgKDhIUVlq3zcavqmNM0c4PSu2c0OPZ4NhK/hwFPe5Gol0AmU0XfZ5
NARz0cTBdohuXim48Fi7fHNTFmhs/1w764wmHLAJcKacGvzFS5TLhuHOY7pjbjlc
pFEB4hx70EwxPqGa8kFB79KtREFqJbpPZZEO99iAnDCT8EqvAOPNluNcSqPIAsGK
1vOdpLS42YyL15Atg6B7pFOWZ0pgJDyrk+gP2bHId3N2qcwNb6EV4mOTgLnGvnhI
vRNYjGRwOgU10ZoPgWM6l2oKEFtm7ihdD9JV6CwDMZJfQ4O278dh72CZI1oLmHJj
WKqdAbi4llGfkhR0u3wUuyIlK1wvENQSRsmyPnZEhJNn9UGhX2O8koo5u3vHPwe2
ZcSWu2VYyPRUiacuxLrNNOnFlMM4cbcj8DSV6ItDkasm5DBD3rYRezkZ5FxMGxar
KOR93XI2Y4VHZhkvwYBspwq7eGy9swky5oyKNwvPsHmDoBLDJmuT76YmV/S4ODdM
sLuV4OwGVBsHZdmc8VO8a5YTXKeApVs2R3ieMZFeRig8+ce7boRT+2aCEFFB8dwN
ANhe7XA7bGyWH3nIRSdrQkiUnAZ4LlE+spkbldlgQuOMvto1JEmytQhOvaUiamIG
QAeJEwowlkSYSLYp/upKLCp0PEoN3Jyz89Z2/FY3MbJsShpm3IRZFwBW1XaX8UQ7
gamjRBK7e/BfMydXWlkR3TAdYFOGfzwwgHEfG/EVh7C7KYQnayaF53ViEOSz+JVT
hCMeVYxvUQyR4PxWtdGIX/KUnpWka8G+4fpx9QJ+EMRDsOkdD9dED0Z6JyISEuiP
XGumQpbK4NIHv8YPiMfPtcRaoYOdGMs3xFhD5UJqSpDIArZCj5U8NZxKwGA0UvrA
tzYeL9NdzIhakhRdT8oBWPG31wtLzRGOSipBVEON8xDESpobmepBWQcmeoiwYkJB
V5wXIvRu1hwuPspUXJlwUXF1OZuADbJdo5WT0GSQ1xQsAOiNLbBH6YmL23rLftkH
9uMEFswN5UokLAohJjAvXVTIW8Zqwvg8eXlFtQZ8qkK9LgwZypdQblB6sKXJ9WM3
CEmcGfJK7FE705A6XXO27EmR98cuuZHBw3iJgFyx6jigzAIXayfFjWOM5aMmaEV8
+bm+AnygIUBXlxcl1UEC6JlnFusq2CNFO2BbhVNwsbIbOTLN7UFgqplzx+uuWsR2
TZTPfMlQbwd7rXMBLbtKyBQKOHRkEuszyVFFliBfcHY1hiIX2bYJGMYmjZNEkVuE
eiR2waJw8VSlyEI0FlrPyGk5hwLOqemgfnsOmeqb3LeEH+nA+iXIM4CSVho+3dxw
AfR4rWV4GmAkqtFl2baXmtrESKRGL1ZGhVJ/diQ0/ppCWoRDe0VzkuyoDJE1BhUe
OhMjnzQvynZVtuquhFoiHOs+Z/VjnGGT9v3u9X45m4CLfzqitXQKre2QFj3F13XJ
+vfx+9B12rNE6dfRRmRygfu6ezxWyv1YM7epMOxCBufDptd2T+gdeg==
-----END PUBLIC KEY-----";
    }

    // Tests operations with IETF test vectors: the private key must parse into
    // the published raw seed, re-encode into the published PEM and DER, and
    // expand to the draft's matching public key.
    #[test]
    fn test_ietf_vectors() {
        // Round trip the secret key pem and verify the expected seed
        let key = SecretKey::from_pem(ietf_vectors::SECKEY_PEM).unwrap();
        assert_eq!(hex::encode(*key.to_bytes()), ietf_vectors::SECKEY_SEED);
        assert_eq!(key.to_pem().trim(), ietf_vectors::SECKEY_PEM.trim());

        // Round trip the secret key der
        let (_, der) = pem::decode(ietf_vectors::SECKEY_PEM.as_bytes()).unwrap();
        assert_eq!(*key.to_der(), der);

        // Verify the expected public key
        assert_eq!(
            key.public_key().to_pem().trim(),
            ietf_vectors::PUBKEY_PEM.trim()
        );

        // Round trip the public key pem
        let key = PublicKey::from_pem(ietf_vectors::PUBKEY_PEM).unwrap();
        assert_eq!(key.to_pem().trim(), ietf_vectors::PUBKEY_PEM.trim());

        // Round trip the public key der
        let (_, der) = pem::decode(ietf_vectors::PUBKEY_PEM.as_bytes()).unwrap();
        assert_eq!(key.to_der(), der);
    }

    // Tests that a private key can be serialized to bytes and parsed back.
    #[test]
    fn test_secretkey_bytes_roundtrip() {
        let key = SecretKey::generate();
        let bytes = key.to_bytes();
        let parsed = SecretKey::from_bytes(&bytes);
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to bytes and parsed back.
    #[test]
    fn test_publickey_bytes_roundtrip() {
        let key = SecretKey::generate().public_key();
        let bytes = key.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a private key can be serialized to DER and parsed back.
    #[test]
    fn test_secretkey_der_roundtrip() {
        let key = SecretKey::generate();
        let der = key.to_der();
        let parsed = SecretKey::from_der(&der).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a private key can be serialized to PEM and parsed back.
    #[test]
    fn test_secretkey_pem_roundtrip() {
        let key = SecretKey::generate();
        let pem = key.to_pem();
        let parsed = SecretKey::from_pem(&pem).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to DER and parsed back.
    #[test]
    fn test_publickey_der_roundtrip() {
        let key = SecretKey::generate().public_key();
        let der = key.to_der();
        let parsed = PublicKey::from_der(&der).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests that a public key can be serialized to PEM and parsed back.
    #[test]
    fn test_publickey_pem_roundtrip() {
        let key = SecretKey::generate().public_key();
        let pem = key.to_pem();
        let parsed = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(key.to_bytes(), parsed.to_bytes());
    }

    // Tests sealing and opening various combinations of messages (authenticate,
    // encrypt, both). Note, this test is not meant to test cryptography, it is
    // mostly an API sanity check to verify that everything seems to work.
    #[test]
    fn test_seal_open() {
        // Create the keys
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Run a bunch of different authentication/encryption combinations
        struct TestCase<'a> {
            seal_msg: &'a [u8],
            auth_msg: &'a [u8],
        }
        let tests = [
            // Only message to authenticate
            TestCase {
                seal_msg: &[],
                auth_msg: b"message to authenticate",
            },
            // Only message to encrypt
            TestCase {
                seal_msg: b"message to encrypt",
                auth_msg: &[],
            },
            // Both message to authenticate and to encrypt
            TestCase {
                seal_msg: b"message to encrypt",
                auth_msg: b"message to authenticate",
            },
        ];

        for tt in &tests {
            // Seal the message to the public key
            let (sess_key, seal_msg) = public
                .seal(tt.seal_msg, tt.auth_msg, b"test")
                .unwrap_or_else(|e| panic!("failed to seal message: {}", e));

            // Open the sealed message with the secret key
            let cleartext = secret
                .open(&sess_key, &seal_msg, tt.auth_msg, b"test")
                .unwrap_or_else(|e| panic!("failed to open message: {}", e));

            // Validate that the cleartext matches our expected encrypted payload
            assert_eq!(cleartext, tt.seal_msg, "unexpected cleartext");
        }
    }

    // Tests that a sender/receiver context can be established and used to
    // encrypt/decrypt multiple messages in sequence.
    #[test]
    fn test_context_seal_open() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Set up the sender and receiver contexts
        let (mut sender, encap_key) = public
            .new_sender(b"test-session")
            .expect("failed to setup sender");
        let mut receiver = secret
            .new_receiver(&encap_key, b"test-session")
            .expect("failed to setup receiver");

        // Encrypt and decrypt multiple messages in sequence
        let messages: &[(&[u8], &[u8])] = &[
            (b"first message", b"auth-1"),
            (b"second message", b"auth-2"),
            (b"third message", b""),
            (b"", b"auth-only"), // empty message
            (b"fifth message after empty", b"auth-5"),
        ];
        for (i, (msg, aad)) in messages.iter().enumerate() {
            let ciphertext = sender
                .seal(msg, aad)
                .unwrap_or_else(|e| panic!("failed to seal message {}: {}", i, e));
            let plaintext = receiver
                .open(&ciphertext, aad)
                .unwrap_or_else(|e| panic!("failed to open message {}: {}", i, e));
            assert_eq!(plaintext, *msg, "message {} mismatch", i);
        }
    }

    // Tests that a receiver context rejects messages decrypted out of order.
    // The HPKE sequence counter is only advanced on success, so after a failed
    // open the context remains usable for the correct next message.
    #[test]
    fn test_context_rejects_out_of_order() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let (mut sender, encap_key) = public
            .new_sender(b"test-order")
            .expect("failed to setup sender");
        let mut receiver = secret
            .new_receiver(&encap_key, b"test-order")
            .expect("failed to setup receiver");

        // Seal two messages
        let ct0 = sender.seal(b"message 0", b"aad-0").unwrap();
        let ct1 = sender.seal(b"message 1", b"aad-1").unwrap();

        // Try to open the second message first (should fail: wrong nonce)
        assert!(
            receiver.open(&ct1, b"aad-1").is_err(),
            "should reject out-of-order message"
        );

        // The sequence counter doesn't advance on failure, so the correct
        // next message (ct0) should still work
        let pt0 = receiver
            .open(&ct0, b"aad-0")
            .expect("should open in-order message");
        assert_eq!(pt0, b"message 0");

        // And now ct1 should work since the counter has advanced
        let pt1 = receiver
            .open(&ct1, b"aad-1")
            .expect("should open next message");
        assert_eq!(pt1, b"message 1");
    }

    // Tests that mismatched domains between sender and receiver prevent
    // decryption (the HPKE contexts derive different keys).
    #[test]
    fn test_context_rejects_wrong_domain() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let (mut sender, encap_key) = public
            .new_sender(b"domain-a")
            .expect("failed to setup sender");
        let mut receiver = secret
            .new_receiver(&encap_key, b"domain-b")
            .expect("failed to setup receiver");

        let ciphertext = sender.seal(b"secret", b"aad").unwrap();
        assert!(
            receiver.open(&ciphertext, b"aad").is_err(),
            "should reject mismatched domain"
        );
    }

    // Tests that mismatched additional authenticated data between seal and open
    // prevents decryption for both single-shot and context-based APIs.
    #[test]
    fn test_rejects_wrong_auth() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Single-shot: wrong AAD must fail
        let (sess_key, ciphertext) = public
            .seal(b"secret", b"correct-aad", b"domain")
            .expect("failed to seal");
        assert!(
            secret
                .open(&sess_key, &ciphertext, b"wrong-aad", b"domain")
                .is_err(),
            "single-shot should reject wrong AAD"
        );

        // Context-based: wrong AAD must fail
        let (mut sender, encap_key) = public
            .new_sender(b"domain")
            .expect("failed to setup sender");
        let mut receiver = secret
            .new_receiver(&encap_key, b"domain")
            .expect("failed to setup receiver");

        let ct = sender.seal(b"secret", b"correct-aad").unwrap();
        assert!(
            receiver.open(&ct, b"wrong-aad").is_err(),
            "context should reject wrong AAD"
        );

        // Verify recovery: correct AAD still works after failed attempt
        let pt = receiver
            .open(&ct, b"correct-aad")
            .expect("should open with correct AAD");
        assert_eq!(pt, b"secret");
    }
}
