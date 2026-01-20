// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! RSA cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc8017

use crate::pem;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, Error};
use rsa::rand_core::OsRng;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Size of the raw secret key in bytes.
/// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes)
pub const SECRET_KEY_SIZE: usize = 520;

/// Size of the raw public key in bytes.
/// Format: n (256 bytes) || e (8 bytes)
pub const PUBLIC_KEY_SIZE: usize = 264;

/// Size of an RSA-2048 signature.
pub const SIGNATURE_SIZE: usize = 256;

/// Size of an RSA key fingerprint (SHA256 hash).
pub const FINGERPRINT_SIZE: usize = 32;

/// SecretKey contains a 2048-bit RSA private key usable for signing, with SHA256
/// as the underlying hash algorithm. Whilst RSA could also be used for encryption,
/// that is not exposed on the API as it's not required by the project.
#[derive(Clone)]
pub struct SecretKey {
    inner: rsa::pkcs1v15::SigningKey<Sha256>,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut rng = OsRng;

        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let sig = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
        Self { inner: sig }
    }

    /// from_bytes parses a 520-byte array into a private key.
    ///
    /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
    /// all in big-endian.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Result<Self, rsa::Error> {
        let p = BigUint::from_bytes_be(&bytes[0..128]);
        let q = BigUint::from_bytes_be(&bytes[128..256]);
        let d = BigUint::from_bytes_be(&bytes[256..512]);
        let e = BigUint::from_bytes_be(&bytes[512..520]);

        let n = &p * &q;

        // The modulus must be exactly 2048 bits
        if n.bits() != 2048 {
            return Err(rsa::Error::InvalidModulus);
        }
        // Whilst the RSA algorithm permits different exponents, every modern
        // system only ever uses 65537 and most also enforce this. Might as
        // well do the same.
        if e != BigUint::from(65537u32) {
            return Err(rsa::Error::InvalidExponent);
        }
        let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])?;
        let sig = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
        Ok(Self { inner: sig })
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = rsa::pkcs1v15::SigningKey::<Sha256>::from_pkcs8_der(der)?;

        // The modulus must be exactly 2048 bits
        let key: &RsaPrivateKey = inner.as_ref();
        if key.n().bits() != 2048 {
            return Err(Error::KeyMalformed.into());
        }
        // Whilst the RSA algorithm permits different exponents, every modern
        // system only ever uses 65537 and most also enforce this. Might as
        // well do the same.
        if *key.e() != BigUint::from(65537u32) {
            return Err(Error::KeyMalformed.into());
        }
        // The upstream rsa crate ignores CRT parameters (dP, dQ, qInv) and
        // recomputes them, accepting malformed values. We don't want to allow
        // that, so just round trip the format and see if it's matching or not.
        let recoded = rsa::pkcs1v15::SigningKey::<Sha256>::to_pkcs8_der(&inner)?;
        if recoded.as_bytes() != der {
            return Err(Error::KeyMalformed.into());
        }
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Crack open the PEM to get to the private key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes serializes a private key into a 520-byte array.
    ///
    /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
    /// all in big-endian.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let key: &RsaPrivateKey = self.inner.as_ref();
        let primes = key.primes();

        let mut out = [0u8; 520];

        let p_bytes = primes[0].to_bytes_be();
        out[128 - p_bytes.len()..128].copy_from_slice(&p_bytes);

        let q_bytes = primes[1].to_bytes_be();
        out[256 - q_bytes.len()..256].copy_from_slice(&q_bytes);

        let d_bytes = key.d().to_bytes_be();
        out[512 - d_bytes.len()..512].copy_from_slice(&d_bytes);

        let e_bytes = key.e().to_bytes_be();
        out[520 - e_bytes.len()..520].copy_from_slice(&e_bytes);

        out
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        rsa::pkcs1v15::SigningKey::<Sha256>::to_pkcs8_der(&self.inner)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PRIVATE KEY", &self.to_der())
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        let key = self.inner.verifying_key();
        PublicKey { inner: key }
    }

    /// fingerprint returns a 256bit unique identified for this key. For RSA, that
    /// is the SHA256 hash of the raw (le modulus || le exponent) public key.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// sign creates a digital signature of the message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.inner.sign(message);
        Signature(sig.to_bytes().as_ref().try_into().unwrap())
    }
}

/// PublicKey contains a 2048-bit RSA public key usable for verification, with
/// SHA256 as the underlying hash algorithm. Whilst RSA could also be used for
/// decryption, that is not exposed on the API as it's not required by the
/// project.
#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: rsa::pkcs1v15::VerifyingKey<Sha256>,
}

impl PublicKey {
    /// from_bytes parses a 264-byte array into a public key.
    ///
    /// Format: n (256 bytes) || e (8 bytes), all in big-endian.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, rsa::Error> {
        let n = BigUint::from_bytes_be(&bytes[0..256]);
        let e = BigUint::from_bytes_be(&bytes[256..264]);

        // The modulus must be exactly 2048 bits
        if n.bits() != 2048 {
            return Err(rsa::Error::InvalidModulus);
        }
        // Whilst the RSA algorithm permits different exponents, every modern
        // system only ever uses 65537 and most also enforce this. Might as
        // well do the same.
        if e != BigUint::from(65537u32) {
            return Err(rsa::Error::InvalidExponent);
        }
        let key = RsaPublicKey::new(n, e)?;
        let inner = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
        Ok(Self { inner })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let inner = rsa::pkcs1v15::VerifyingKey::<Sha256>::from_public_key_der(der)?;

        // The modulus must be exactly 2048 bits
        let key: &RsaPublicKey = inner.as_ref();
        if key.n().bits() != 2048 {
            return Err(Error::KeyMalformed.into());
        }
        // Whilst the RSA algorithm permits different exponents, every modern
        // system only ever uses 65537 and most also enforce this. Might as
        // well do the same.
        if *key.e() != BigUint::from(65537u32) {
            return Err(Error::KeyMalformed.into());
        }
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Crack open the PEM to get to the public key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes serializes a public key into a 264-byte array.
    ///
    /// Format: n (256 bytes) || e (8 bytes), all in big-endian.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let key: &RsaPublicKey = self.inner.as_ref();

        let mut out = [0u8; 264];

        let n_bytes = key.n().to_bytes_be();
        out[256 - n_bytes.len()..256].copy_from_slice(&n_bytes);

        let e_bytes = key.e().to_bytes_be();
        out[264 - e_bytes.len()..264].copy_from_slice(&e_bytes);

        out
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        rsa::pkcs1v15::VerifyingKey::<Sha256>::to_public_key_der(&self.inner)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identified for this key. For RSA, that
    /// is the SHA256 hash of the raw (le modulus || le exponent) public key.
    pub fn fingerprint(&self) -> Fingerprint {
        let pubkey: RsaPublicKey = self.inner.as_ref().clone();

        let mut mod_le = pubkey.n().to_bytes_le();
        mod_le.resize(256, 0);
        let mut exp_le = pubkey.e().to_bytes_le();
        exp_le.resize(8, 0);

        let mut hasher = Sha256::new();
        hasher.update(&mod_le);
        hasher.update(&exp_le);
        Fingerprint(hasher.finalize().into())
    }

    /// verify verifies a digital signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), rsa::signature::Error> {
        let sig = rsa::pkcs1v15::Signature::try_from(signature.to_bytes().as_slice())?;
        self.inner.verify(message, &sig)
    }

    /// verify_hash verifies a digital signature on an already hashed message.
    pub fn verify_hash(
        &self,
        hash: &[u8],
        signature: &Signature,
    ) -> Result<(), rsa::signature::Error> {
        let sig = rsa::pkcs1v15::Signature::try_from(signature.to_bytes().as_slice())?;
        self.inner.verify_prehash(hash, &sig)
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
    fn encode_cbor(&self) -> Vec<u8> {
        self.to_bytes().encode_cbor()
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

/// Signature contains an RSA-2048 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// from_bytes converts a 256-byte array into a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// to_bytes converts a signature into a 256-byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(&s).map_err(de::Error::custom)?;
        let arr: [u8; SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("invalid signature length"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Encode for Signature {
    fn encode_cbor(&self) -> Vec<u8> {
        self.to_bytes().encode_cbor()
    }
}

#[cfg(feature = "cbor")]
impl crate::cbor::Decode for Signature {
    fn decode_cbor(data: &[u8]) -> Result<Self, crate::cbor::Error> {
        let bytes = <[u8; SIGNATURE_SIZE]>::decode_cbor(data)?;
        Ok(Self::from_bytes(&bytes))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<SIGNATURE_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// Fingerprint contains an RSA key fingerprint (SHA256 hash).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn encode_cbor(&self) -> Vec<u8> {
        self.to_bytes().encode_cbor()
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

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that a raw byte encoded RSA private key can be decoded and re-encoded
    // to the same bytes. The purpose is not to battle-test the implementation,
    // rather to ensure that the code implements the format other subsystems expect.
    #[test]
    fn test_secretkey_bytes_codec() {
        // Generated with:
        //   openssl genrsa -out test.key 2048
        //   openssl rsa -in test.key -text -noout
        let part_prime1 = "\
ed9792f021b214b57fc6230d051da0783673475d9b9cf9f9003367b6362a\
62201852f112cbb6fcadb00b17470e21dfa39ec2eef58ea2ff7e27b9e63b\
90af84e482b53ea79760196bbd226627038d84eb16e75e2efacb9f432dbf\
b93ec3f6fea10ec9c9b984e8c7d4e95fa76befc2f46e42c86d8479586b36\
7cb49499b37bf01d";
        let part_prime2 = "\
da885d75be231c04ebf195455fcec9449044b212f2044ddeeb49c0c14898\
35f8e91e56a6418570a9f50c2734c4fadb7f2eb2c50cff4ab0b34e389568\
12f9b42632c66a248e09e52af8eb5e1c8cdd21fe65b86242fdf1e838235d\
a1bf37ced6ae0e117c8dac77c34917a711bc6ecc949d0f000dae8f22dadf\
46153c64d5ef7521";
        let part_priv_exp = "\
02d864d6371a3586977264fa905c01495adbeba2fbab49cc1ea22d6d5c17\
71b0a31b2a58c546e81990fa861e0954a4d9119d3698f41ca66b37c0b4a8\
756f4efdd814d36393e3fb8b9662f1dc7725222565c95eb5389e3caa28e5\
429608b898d677e9feffbb66207d3e881949dc0b53568a0ea9c6ae06bef3\
6f74422960d8447b194ebff8ab5f08842153661278bbeb115dd131d26746\
7315402b5d75560d4c20390499887f3d33021f4dda1cb36bfb9b54ed80c5\
9bd3213f42a4ca7025d59a64e53d559e14ac84f8438b771c1ac94fb90aa4\
1c7708e073510ad063bada4a261bc0b311a42b8d482d26b39fb82d44f133\
c9ab9ccdd77b098fc6c0c647ed663781";
        let part_pub_exp = "0000000000010001";

        let input = [part_prime1, part_prime2, part_priv_exp, part_pub_exp].concat();

        let bytes: [u8; 520] = hex::decode(&input).unwrap().try_into().unwrap();
        let key = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(hex::encode(key.to_bytes()), input);
    }

    // Tests that a raw byte encoded RSA public key can be decoded and re-encoded
    // to the same bytes. The purpose is not to battle-test the implementation,
    // rather to ensure that the code implements the format other subsystems expect.
    #[test]
    fn test_publickey_bytes_codec() {
        // Generated with:
        //   openssl genrsa -out test.key 2048
        //   openssl rsa -in test.key -text -noout
        let part_mod = "\
cad1a263e36205031c65b1befe8b1f65ac0af10c72aeb69ad295d1a651a3\
f1191d4af8afdef14ab2d66d0253ef98228ee9f85fb822f92fccb3f6c23b\
4745ac743e002fc81c63dc04531fc176f3cdcb5aebaa2797903fd791b9c8\
474eb7b999295cf64935d9a5a4626849e77c472a6e00b8ff73d0f1a3b7c4\
4da7e7bae4726b4f2f7f05741d576a13c1bc9077ee14d7e9af5192f8e7dc\
2ffb212d4ef9c7fff4e87c3debf9a48346ac3618b24d7932d8e7cf6b266c\
dce0ad59b16fce0a8420aebd332e28294862ef288917eacabf330cb29161\
f78fcdf089bc2cb4086af8a7980637fb9cf0b4ed86d6a21208ae5a4e49d1\
7ab6d945b65cef700217ada913ca34bd";
        let part_pub_exp = "0000000000010001";

        let input = [part_mod, part_pub_exp].concat();

        let bytes: [u8; 264] = hex::decode(&input).unwrap().try_into().unwrap();
        let key = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(hex::encode(key.to_bytes()), input);
    }

    // Tests that a PEM encoded RSA private key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_secretkey_pem_codec() {
        // Generated with:
        //   openssl genrsa -out test.key 2048
        let input = "\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCwLLXTHaYT57yN
HZT6BTnJIDaJ8GTnu05PnwQQcV7Xgom164T52qaMmvsK/PGlzMzQdo9YjYKsExZE
EllJe4O1mVA1T/LyKLkPZgKqcp11/9UAkk3pHsPkb0YOb3g1721K6tQ78ufjeIOt
5WJ+n+HJHOvhvyjmO0aQ51eh0jSyUu6U9fA+qrtPO4D/mUVRDJmCLSyGzIMd4Xan
zTSWZ8JWLjahIdMPOZYUrGpICOxwt9Jaow37ogAalRVHnTb8PkklOo9pr0a3ZdQQ
P3yV/A5gmgXXLi2BkQ0b2y8FOuD/JjBXL4Ks9nUVn/nMMaFhDxmL3ZZ9AuvB94AR
B0MvuZh9AgMBAAECggEABoVaB1dURJhZDBV0OcI5iVWakr63md/F3kdDnlu+koDd
/V63rG76izDmsQQYP3Zgt0TW1ehDcmP3ziDG2blycF5WKM2tqGcwlfBvypn8WEnH
5eWEcEul5JFZ09C8b61N8sOALq01PzVOv8dCPu9jKzL19mfPofX4myKt4esKX2gy
psId9QmgsrRRsCSvQeUxOA3Sqaa0a+atALZByPKZN8XzmZu1Ie5QPQvh/xYDJU1D
GEiNgwZGy0eXL2Se5OjKAR40f4SzArbs/Jb2gRFHTjpdJ9g33GqoP94jZPcogtm2
FHgI5vl9jL4uXiSJLkgl4FfFvoIXWuUi1xAC5NDT4QKBgQDnaxGFvt6vW8JKEyEq
6Nf9K2Y2nQbvEmqnvS/RPwuqKuh66KCNG2rePFzXLHCplbYHt9hhF+Ity9lFzxSK
ipRC6BD9aqaqF6qhm1nZWnXsPWjWDsFYzQHv8LA4pL8gmxbz+IOs1jbbIQAdq8X5
uv7C1YSCrPkpm/nTljzwU/d/gwKBgQDC42in2DURf1+cU9Qw+hNDCy0EgkB7STzV
dCreCAFXhSIzFwq9bjzOeSFtvZlWxKNJKNUiDXgN/grRREG/m1kW7EdHAMiOVVNK
SbQ/+zHy6SMKNu0ArkokaCAEludVVRjkwh5GsyFvFaBINJBnp/zDYhNkkxStjCRf
rW0/fmcH/wKBgF/IA9+caWShEOBB3Kd66fKiJNMT2QvYToaQmhr8AiLzUXeVkuX0
ZB4JU8/HV/YIveeh4xAEp5uW1J29IN5ajxTGIkoQ+1xJIVl0CBMbCtW1cQ+v2byc
VWHu97DqFyUyq6RcxnshymCV3wtozi8Xg1w2rXq8hv/+y78UXrKFvllrAoGAItrb
F9GyRAvcxK+1boD7Ou1fwsOs1p/VknNxSz5xRv7Xi/2d/R0fIOpHEUJsjzkh3u6/
l5SDGTWLJ7wmaidVeqUNZmR8egBGoi2mYB8D4ubRTn1eS9XgCrzYpRl8DCXpCtiw
44IcA6sBfIhyHyfLLAJ5Z25qr1M2GiqBNG7d7G8CgYBoIYe3OeuqZn2T+eA3rmMv
djLUQsO3CvmFYBDvNqmiwNx3OOV/YFQVvSAGaEP/5pJGVmAKUDaALgTveToLV6jq
bS99QZDnrW+xkvJi6N1ZAlQpIOX5Y/Q2qyBa1Hf2Z21mnqZSN3HHC6aQl+83uety
JJXbL24vf1AajzeJk6CpdQ==
-----END PRIVATE KEY-----";

        let key = SecretKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a PEM encoded RSA public key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_publickey_pem_codec() {
        // Generated with:
        //   openssl rsa -in test.key -pubout -out test.pub
        let input = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCy10x2mE+e8jR2U+gU5
ySA2ifBk57tOT58EEHFe14KJteuE+dqmjJr7CvzxpczM0HaPWI2CrBMWRBJZSXuD
tZlQNU/y8ii5D2YCqnKddf/VAJJN6R7D5G9GDm94Ne9tSurUO/Ln43iDreVifp/h
yRzr4b8o5jtGkOdXodI0slLulPXwPqq7TzuA/5lFUQyZgi0shsyDHeF2p800lmfC
Vi42oSHTDzmWFKxqSAjscLfSWqMN+6IAGpUVR502/D5JJTqPaa9Gt2XUED98lfwO
YJoF1y4tgZENG9svBTrg/yYwVy+CrPZ1FZ/5zDGhYQ8Zi92WfQLrwfeAEQdDL7mY
fQIDAQAB
-----END PUBLIC KEY-----";

        let key = PublicKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a DER encoded RSA private key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_privatekey_der_codec() {
        // Generated with:
        //   openssl rsa -in test.key -outform DER -out test.key.der
        //   cat test.key.der | xxd -p
        let input = "\
308204bc020100300d06092a864886f70d0101010500048204a6308204a2\
0201000282010100b02cb5d31da613e7bc8d1d94fa0539c9203689f064e7\
bb4e4f9f0410715ed78289b5eb84f9daa68c9afb0afcf1a5ccccd0768f58\
8d82ac1316441259497b83b59950354ff2f228b90f6602aa729d75ffd500\
924de91ec3e46f460e6f7835ef6d4aead43bf2e7e37883ade5627e9fe1c9\
1cebe1bf28e63b4690e757a1d234b252ee94f5f03eaabb4f3b80ff994551\
0c99822d2c86cc831de176a7cd349667c2562e36a121d30f399614ac6a48\
08ec70b7d25aa30dfba2001a9515479d36fc3e49253a8f69af46b765d410\
3f7c95fc0e609a05d72e2d81910d1bdb2f053ae0ff2630572f82acf67515\
9ff9cc31a1610f198bdd967d02ebc1f7801107432fb9987d020301000102\
82010006855a0757544498590c157439c23989559a92beb799dfc5de4743\
9e5bbe9280ddfd5eb7ac6efa8b30e6b104183f7660b744d6d5e8437263f7\
ce20c6d9b972705e5628cdada8673095f06fca99fc5849c7e5e584704ba5\
e49159d3d0bc6fad4df2c3802ead353f354ebfc7423eef632b32f5f667cf\
a1f5f89b22ade1eb0a5f6832a6c21df509a0b2b451b024af41e531380dd2\
a9a6b46be6ad00b641c8f29937c5f3999bb521ee503d0be1ff1603254d43\
18488d830646cb47972f649ee4e8ca011e347f84b302b6ecfc96f6811147\
4e3a5d27d837dc6aa83fde2364f72882d9b6147808e6f97d8cbe2e5e2489\
2e4825e057c5be82175ae522d71002e4d0d3e102818100e76b1185bedeaf\
5bc24a13212ae8d7fd2b66369d06ef126aa7bd2fd13f0baa2ae87ae8a08d\
1b6ade3c5cd72c70a995b607b7d86117e22dcbd945cf148a8a9442e810fd\
6aa6aa17aaa19b59d95a75ec3d68d60ec158cd01eff0b038a4bf209b16f3\
f883acd636db21001dabc5f9bafec2d58482acf9299bf9d3963cf053f77f\
8302818100c2e368a7d835117f5f9c53d430fa13430b2d0482407b493cd5\
742ade080157852233170abd6e3cce79216dbd9956c4a34928d5220d780d\
fe0ad14441bf9b5916ec474700c88e55534a49b43ffb31f2e9230a36ed00\
ae4a2468200496e7555518e4c21e46b3216f15a048349067a7fcc3621364\
9314ad8c245fad6d3f7e6707ff0281805fc803df9c6964a110e041dca77a\
e9f2a224d313d90bd84e86909a1afc0222f351779592e5f4641e0953cfc7\
57f608bde7a1e31004a79b96d49dbd20de5a8f14c6224a10fb5c49215974\
08131b0ad5b5710fafd9bc9c5561eef7b0ea172532aba45cc67b21ca6095\
df0b68ce2f17835c36ad7abc86fffecbbf145eb285be596b02818022dadb\
17d1b2440bdcc4afb56e80fb3aed5fc2c3acd69fd59273714b3e7146fed7\
8bfd9dfd1d1f20ea4711426c8f3921deeebf97948319358b27bc266a2755\
7aa50d66647c7a0046a22da6601f03e2e6d14e7d5e4bd5e00abcd8a5197c\
0c25e90ad8b0e3821c03ab017c88721f27cb2c0279676e6aaf53361a2a81\
346eddec6f028180682187b739ebaa667d93f9e037ae632f7632d442c3b7\
0af9856010ef36a9a2c0dc7738e57f605415bd20066843ffe6924656600a\
5036802e04ef793a0b57a8ea6d2f7d4190e7ad6fb192f262e8dd59025429\
20e5f963f436ab205ad477f6676d669ea6523771c70ba69097ef37b9eb72\
2495db2f6e2f7f501a8f378993a0a975";

        let der = hex::decode(&input).unwrap();
        let key = SecretKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
    }

    // Tests that a DER encoded RSA public key can be decoded and re-encoded to
    // the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_publickey_der_codec() {
        // Generated with:
        //   openssl rsa -in test.key -pubout -outform DER -out test.pub.der
        //   cat test.pub.der | xxd -p
        let input = "\
30820122300d06092a864886f70d01010105000382010f003082010a0282\
010100b02cb5d31da613e7bc8d1d94fa0539c9203689f064e7bb4e4f9f04\
10715ed78289b5eb84f9daa68c9afb0afcf1a5ccccd0768f588d82ac1316\
441259497b83b59950354ff2f228b90f6602aa729d75ffd500924de91ec3\
e46f460e6f7835ef6d4aead43bf2e7e37883ade5627e9fe1c91cebe1bf28\
e63b4690e757a1d234b252ee94f5f03eaabb4f3b80ff9945510c99822d2c\
86cc831de176a7cd349667c2562e36a121d30f399614ac6a4808ec70b7d2\
5aa30dfba2001a9515479d36fc3e49253a8f69af46b765d4103f7c95fc0e\
609a05d72e2d81910d1bdb2f053ae0ff2630572f82acf675159ff9cc31a1\
610f198bdd967d02ebc1f7801107432fb9987d0203010001";

        let der = hex::decode(&input).unwrap();
        let key = PublicKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
    }

    // Tests that the implemented fingerprint algorithm produces the expected
    // checksum. The purpose is not to battle-test the implementation, rather
    // to ensure that the code implements the format other subsystems expect.
    #[test]
    fn test_fingerprint() {
        // Generated with:
        //   from Cryptodome.PublicKey import RSA
        //   import hashlib
        //
        //   with open('key.pem') as f:
        //       key = RSA.importKey(f.read())
        //   mod_le = key.n.to_bytes(256, 'little')
        //   exp_le = key.e.to_bytes(8, 'little')
        //
        //   print(hashlib.sha256(mod_le + exp_le).hexdigest())
        let input = "1e2eaa59f13165ce5c3b4e028fd259767c2ee8d43d5d5ba7debf9d31834b46db";

        let key = PublicKey::from_pem(
            "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCy10x2mE+e8jR2U+gU5
ySA2ifBk57tOT58EEHFe14KJteuE+dqmjJr7CvzxpczM0HaPWI2CrBMWRBJZSXuD
tZlQNU/y8ii5D2YCqnKddf/VAJJN6R7D5G9GDm94Ne9tSurUO/Ln43iDreVifp/h
yRzr4b8o5jtGkOdXodI0slLulPXwPqq7TzuA/5lFUQyZgi0shsyDHeF2p800lmfC
Vi42oSHTDzmWFKxqSAjscLfSWqMN+6IAGpUVR502/D5JJTqPaa9Gt2XUED98lfwO
YJoF1y4tgZENG9svBTrg/yYwVy+CrPZ1FZ/5zDGhYQ8Zi92WfQLrwfeAEQdDL7mY
fQIDAQAB
-----END PUBLIC KEY-----",
        )
        .unwrap();
        assert_eq!(hex::encode(key.fingerprint().to_bytes()), input);
    }

    // Tests signing and verifying messages. Note, this test is not meant to test
    // cryptography, it is mostly an API sanity check to verify that everything
    // seems to work.
    //
    // TODO(karalabe): Get some live test vectors for a bit more sanity
    #[test]
    fn test_sign_verify() {
        // Create the keys for Alice
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Run a bunch of different authentication/encryption combinations
        struct TestCase<'a> {
            message: &'a [u8],
        }
        let tests = [TestCase {
            message: b"message to authenticate",
        }];

        for tt in &tests {
            // Sign the message using the test case data
            let signature = secret.sign(tt.message);

            // Verify the signature message
            public
                .verify(tt.message, &signature)
                .unwrap_or_else(|e| panic!("failed to verify message: {}", e));
        }
    }
}
