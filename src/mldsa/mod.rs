// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! ML-DSA cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9881

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::asn1::OctetString;
use der::{Decode, Encode, Sequence};
use ml_dsa::{EncodedVerifyingKey, MlDsa65};
use pkcs8::PrivateKeyInfo;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Digest;
use spki::der::AnyRef;
use spki::der::asn1::BitStringRef;
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use std::error::Error;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::pem;

/// OID is the ASN.1 object identifier for ML-DSA-65.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// Size of the secret key seed in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Size of a signature in bytes.
pub const SIGNATURE_SIZE: usize = 3309;

/// Size of a fingerprint in bytes.
pub const FINGERPRINT_SIZE: usize = 32;

/// ML-DSA-65 private key inner structure.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct MlDsa65PrivateKeyInner {
    seed: OctetString,
    expanded: OctetString,
}

/// SecretKey contains an ML-DSA-65 private key usable for signing.
#[derive(Clone)]
pub struct SecretKey {
    inner: ml_dsa::SigningKey<MlDsa65>,
    seed: ml_dsa::Seed,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        let mut seed = ml_dsa::Seed::default();
        getrandom::fill(&mut seed).unwrap();

        let inner = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
        Self { inner, seed }
    }

    /// from_bytes creates a private key from a 32-byte seed.
    pub fn from_bytes(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        let array = ml_dsa::Seed::try_from(seed.as_slice()).unwrap();
        let inner = ml_dsa::SigningKey::<MlDsa65>::from_seed(&array);
        Self { inner, seed: array }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info = PrivateKeyInfo::from_der(der)?;

        // Reject trailing data by verifying re-encoded length matches input
        if info.encoded_len()?.try_into() != Ok(der.len()) {
            return Err("trailing data in private key".into());
        }
        // Ensure the algorithm OID matches ML_DSA_65 (OID: 2.16.840.1.101.3.4.3.18)
        if info.algorithm.oid != OID {
            return Err("not an ML-DSA-65 private key".into());
        }
        // Wrap the private key in a SEQUENCE containing:
        //   - OCTET STRING (32 bytes): seed
        //   - OCTET STRING (4032 bytes): expanded key
        let inner_key = MlDsa65PrivateKeyInner::from_der(info.private_key)?;

        let seed: ml_dsa::Seed = inner_key
            .seed
            .as_bytes()
            .try_into()
            .map_err(|_| "seed not 32 bytes")?;
        let expanded: [u8; 4032] = inner_key
            .expanded
            .as_bytes()
            .try_into()
            .map_err(|_| "expanded key not 4032 bytes")?;

        // Generate key from seed and validate it matches the expanded key in DER
        let inner = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);

        #[allow(deprecated)] // to_expanded is wasteful, but that's the DER spec
        let enc = inner.to_expanded();
        if enc.as_slice().ct_ne(&expanded).into() {
            return Err("expanded key does not match seed".into());
        }
        Ok(Self { inner, seed })
    }

    /// from_pem parses a PEM string into a private key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the private key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PRIVATE KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes returns the 32-byte seed of the private key.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.seed.as_slice());
        out
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        #[allow(deprecated)] // to_expanded is wasteful, but that's the DER spec
        let enc = self.inner.to_expanded();

        let inner_key = MlDsa65PrivateKeyInner {
            seed: OctetString::new(self.seed.as_slice()).unwrap(),
            expanded: OctetString::new(enc.as_slice()).unwrap(),
        };
        let inner = inner_key.to_der().unwrap();

        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        let info = PrivateKeyInfo {
            algorithm: alg,
            private_key: &inner,
            public_key: None,
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a private key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PRIVATE KEY", &self.to_der())
    }

    /// public_key retrieves the public counterpart of the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// fingerprint returns a 256bit unique identified for this key. For ML-DSA,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key().fingerprint()
    }

    /// sign creates a digital signature of the message with an optional context string.
    pub fn sign(&self, message: &[u8], ctx: &[u8]) -> Signature {
        let sig = self.inner.sign_deterministic(message, ctx).unwrap();
        let encoded = sig.encode();
        let slice: &[u8] = encoded.as_ref();
        Signature(slice.try_into().unwrap())
    }
}

/// PublicKey contains an ML-DSA-65 public key usable for verification.
#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: ml_dsa::VerifyingKey<MlDsa65>,
}

impl PublicKey {
    /// from_bytes converts a 1952-byte array into a public key.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).unwrap();
        let inner = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
        Self { inner }
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)?;

        // Reject trailing data by verifying re-encoded length matches input
        if info.encoded_len()?.try_into() != Ok(der.len()) {
            return Err("trailing data in public key".into());
        }
        if info.algorithm.oid != OID {
            return Err("not an ML-DSA-65 public key".into());
        }
        let key = info.subject_public_key.as_bytes().unwrap();
        if key.len() != 1952 {
            return Err("public key not 1952 bytes".into());
        }
        let bytes: [u8; 1952] = key.try_into()?;
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).unwrap();
        let inner = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
        Ok(Self { inner })
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        Self::from_der(&data)
    }

    /// to_bytes converts a public key into a 1952-byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let enc = self.inner.encode();
        let mut out = [0u8; 1952];
        out.copy_from_slice(enc.as_slice());
        out
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        let enc = self.inner.encode();
        let bytes = enc.as_slice();

        let alg = AlgorithmIdentifier::<AnyRef> {
            oid: OID,
            parameters: None::<AnyRef>,
        };
        let info = SubjectPublicKeyInfo::<AnyRef, BitStringRef> {
            algorithm: alg,
            subject_public_key: BitStringRef::from_bytes(bytes).unwrap(),
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identified for this key. For ML-DSA,
    /// that is the SHA256 hash of the raw public key.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.inner.encode().as_slice());
        Fingerprint(hasher.finalize().into())
    }

    /// verify verifies a digital signature with an optional context string.
    pub fn verify(
        &self,
        message: &[u8],
        ctx: &[u8],
        signature: &Signature,
    ) -> Result<(), ml_dsa::Error> {
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature.to_bytes().as_slice())?;
        if self.inner.verify_with_context(message, ctx, &sig) {
            Ok(())
        } else {
            Err(ml_dsa::Error::default())
        }
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
        Ok(PublicKey::from_bytes(&arr))
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
        Ok(Self::from_bytes(&bytes))
    }

    fn decode_cbor_notrail(
        decoder: &mut crate::cbor::Decoder<'_>,
    ) -> Result<Self, crate::cbor::Error> {
        let bytes = decoder.decode_bytes_fixed::<PUBLIC_KEY_SIZE>()?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// Signature contains an ML-DSA-65 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// from_bytes converts a 3309-byte array into a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// to_bytes converts a signature into a 3309-byte array.
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
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), crate::cbor::Error> {
        self.to_bytes().encode_cbor_to(buf)
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

/// Fingerprint contains a 32-byte unique identifier for an ML-DSA-65 key.
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

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that a PEM encoded ML-DSA-65 private key can be decoded and re-encoded
    // to the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_secretkey_pem_codec() {
        // Generated with:
        //   openssl genpkey -algorithm mldsa65 -out test.key
        let input = "\
-----BEGIN PRIVATE KEY-----
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
sufdPOOp/GHJAqEQz7n/Owe/
-----END PRIVATE KEY-----";

        let key = SecretKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a PEM encoded ML-DSA-65 public key can be decoded and re-encoded
    // to the same string. The purpose is not to battle-test the PEM implementation,
    // rather to ensure that the code implements the PEM format other subsystems
    // expect.
    #[test]
    fn test_publickey_pem_codec() {
        // Generated with:
        //   openssl pkey -in test.key -pubout -out test.pub
        let input = "\
-----BEGIN PUBLIC KEY-----
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
9w5RU0Pq
-----END PUBLIC KEY-----";

        let key = PublicKey::from_pem(input).unwrap();
        assert_eq!(key.to_pem().trim(), input.trim());
    }

    // Tests that a DER encoded ML-DSA-65 private key can be decoded and re-encoded
    // to the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_secretkey_der_codec() {
        // Generated with:
        //   openssl pkey -in test.key -outform DER -out test.der
        //   cat test.der | xxd -p
        let input = "\
30820ffe020100300b060960864801650304031204820fea30820fe60420
1c8c861052c0a87dc2354e9786e2979b74bd90ccf4ca593b621cdcdd5ac3
3cf904820fc058cc31abeb220f121b1f81fe955cb544416bf8ab1e5f9083
3b2f94cb4a7bec4dabc97e7bdab615f3f3880d25c6f274a6c935bcb9c107
b533633c170514365b012dc98b1ced341e43c01d070166637f2d01021cac
ffbcc8dd869c0b6ea3ee6cdf1495e58d8f4cae8bf45104b25652d7bab381
6485c23de053c4b4d790a25f429870407712601340300584081034332068
614418125728223031622702145512165128731856864625548002388518
073482068401241773173780541554226728313070806004387030568443
571131467863623258884082048655217450612136110411708344680082
767808238641361653573388167381487256172370746444247503230647
468501334153744156888770746470162663502254182218368500228556
103434715416507316156715700865600278563700401416767833424226
233430280441811612022353483637701653711888161026481353324677
082116648064142870267705868634642763736506840818703627673141
706614140473010370417224061680450776772382834260381106867616
364412261424586606437808678633583217808668422835731856363028
454177430651220758281660716062380064622584472668828701621216
851152365331616307422641446373732506162841041456605233214156
548412761718782827647344200147135777887483534471863347230128
113174438245853245157011115288857400761010601280604608142786
245437365538332605307164643173702555370045000734531082246257
723072126400468333714651042488385506110534030612366477681587
577002412226442148885565373110851045400083576378062170252805
781785378704517185103804445261601873467814062861031534111208
733238258886062062538136475605485526883246402480471078264315
485234672576223575148432458624537103547267173433750122665830
152306435033640075723360628640336054523225483282530287267424
322812665777513031560250831252585337430034818337552858765750
280876811865322103771531783612364722560865065583510838663768
572342461348330451824512255034374388482238424140845141658056
071821370835151517515578172026037122757372455651445036823642
363433505344447387740447178530605846728205174864857010682638
484317162264886282585237284163638444130465588544034166868117
638225211508081700542353653757770313376110712100063736412527
616484813617636302268667853302244081277785767856026267576486
778448473427032744824504816632367188410618257142655140807470
455226243652665665531308122538236716166864551606232115280366
182566817033431310807766188008387861806284718081010448103756
168662775682613362536416232338732247641724856286268022280772
701771375608621272133437540167440307018700804452263305118614
707751257533006560522260525216028180673254772254864348736085
046786625522274825664317608486342843854776518258274034736822
858386428004378721706155845481321402014823223102407872032865
002363747024054785537126127835471101022411750428142466788885
170874142304025840118035606644665770755805681420402536072454
388305071877608680170374338346117277433111817481320244553118
232313587440137270122751271614887186755020578740843403332422
427351881018741003557634071787600558816708240064460461732316
171450276357514254787467215272342878726132070425748646677658
771504257758808348331806870357175258612846610524564025407326
153848734147053437242745772240824841080767627126250025262122
115043011340234886136401837153214213712240824331368758384185
8071707642855313325353583fb51a1d66528878c0902ccd88bbdd3278b5
4adf60e1ecdded58e0401f10d080b908006a5c3588614e3b0555b11e0d7b
a11ad5a877420e5b197b2e6faf02ac19d27603f44b3b371d80d28034026b
b55f19b913d659e431788f3a834d74cc094d1c104687e8a69ed6a239c778
453544a8a7def10be3dcfa8bbf6bda9164aa2e0d4482fd882bdca467f2fb
d10795be2b90ddd202ad5821373038a7ab744a923e28f1ff146e42d70679
7ee41dae3bf972e85a3c8d6c8230638bf5bbb9211ca5735f2698cdc7db0c
4291d72f1c816614bbf4cf28811844fc2837f4ba4f941ede90fd22bdb022
112b285a30183b31fd4d77cb4f72b75827652394ea33fe93ae83c6995c64
554e21d099eddc3c143c6da53153174a24da20928127a2482989026b3329
af4791056b41f149456cd5a20d01b95b9b2d95baae52f22cc78cc82400ab
77a8c5804891e8d3c2eabd1b79364c629721cdc561157e373b73e655f8f8
018421538ed11b3426a203bd146794c33e2d03f5de55f0104fe182b73721
e650f66b3f696198798c922ef8313e196c34d4f8fc9c50a89fdf9ba99b51
ab3691dbfa9adf5f5d219e48ad2d06a387e3b44edfffabfd535374d576af
bcbee84bf31f8ae4e788e701ec5d3d457eaa957dfa2f2a056ab57c446e5d
3e9d1a3a1d6f01796756395bc5e3940ac830c5af36abfeea58f37bf02421
f774576498475953089b471030e679acbc1cb113789f1cf1f37b80e333b2
890e1537c37be96d61b55ab05dfc33f4ea7f21a3769c963a30a629104ae8
c8e02bfc1e4b6ef358559bc502ebc04e77ba3f0f8cf79b21feacedfd3f91
0e9dc4528322f1b0e595cc000a2493593fb3d8aeffbe51aba39cd7f89ccf
0225cfa3cbbc9595cb71acf2d85b4f6493d563aad224c9dcd0f3ddab5d71
36acb7cf8797cbe36721961db28405d5c54a5a49b597bef687972b26beb2
6830a1f1e1d2a291e1b715326316118e125d7991afcdebc5fa7e7bcd1211
3a702f677b16df4ba750644fb90c6abd2779d90a0be0c14cc94ad74972e5
ed804e84936dce1eeb2168655bcd463255ddd3703b65d442cc6101dc1855
8eab72e38498d297262c077de6165dfd7b18a3981e885125d558e8776828
19ce113d30119cded255a4f23a860751db1f0ce4c2cf9a159dd1b3b0b3b9
1526239912f4f76c3d8cf68370c92a3f6e73b24f3d5161d10ede7847eede
d15cbf6c77ade44995048da619d91842d5039f8517781424c0a0b38d9232
41ad9df6b3fcfea6ed4a4e7b8eef62f34846912b2b413aa290fc66a89f16
868eb140283149926a2e307ef21449151b630a5ddcd1d979cc1d0fbf7bf2
a8c444b2d4a40f810702d4dc2cfb2c837a6475c05c87d1b17fa0d4be03ab
9232bc790ac177609936ad741185d53d9248c7bc7b82fe764dab0bc4051d
b890f9996a26b55a33f1359fbd2a08c273609a652a0dd75c7eac3b0b677a
ccff51f5a8898e41c374f478010f86e4d5847eb03edbae397abdb6deb588
910c67d6d2a1df0acfc6df7fae4b8b09b1f844f522fbc0a5698bf7d61d90
63430cb64c6af994e45ccb2cd3e22f19a80da1014189ff565af15c3f4f0f
b9e38060dbce788853491458f94b53dee37e3712ecc26779dcf079fa79dc
5aeed5b95c01cf4a864cc2e5739a524b65da677848709dfc841bec4d296d
cd59801c984d30e18958068798271c50763ee5c99acdb6ad6791f0792a3f
d3feee5f120bb510b7f4c7ac47e5cee537655c7bf292ad2d0e80ffe3af92
2c1ac0a8ce60387e6a0fd8ce120b67c0dbd0f02bcd0a4cd05b9ecf9c0f45
7cc63dff146df07f8ebc85508308b04aab436e0b5f19d728d5529e2f10a7
80d169b1ccef7bf97c76dac909a788de50c30b7fb5c2cd726530dce3d43b
ad932c90f6c8c611efb03c677fbd6213989899ad553a7994a4a9dd2aa809
f11852a9b0e6bba479d3ba26d2a06773d7fb431060e5d7da62f124cbd7d1
50eb67ce833d70ef5c6f2779f20c6a3f449dc8b47bbb606cc118d7d3eac7
26d6ab73990543f70f2212c3c5574e6cbdb956507940138525e95917fccf
0358b1cc47aab70988bdd8964bb0c98f3fb5718190c2c0a7f17f6342d333
f0c79cae76989aff5b1acb16e6b07cb28bb306e03b375feb2d02005f8ebc
3ec70a8ba65a501e73fcb59f507a3fbc02f60f4e3d893895cd223cfc90ea
c08179a1442e1f808f8dc3edd3fa16379bd4d2dd2da134a52e145fa81490
62131c8d9273bc8e044ff4197265761aaa83468540b910ace8476ceb4f00
a37c023cae7c321f7f771fab180896f1bf1d7de119ed66bc07d595f2c5cf
64408ead30e0b114c4db472e877f88d7c6d5148e0626b5e5737d1ec75371
c1a11ff757a16995fed5eb1871a60fa844da47acee368c90275f232e5091
bddd83fcf493603dd7296f97ca19583b43770cfef0cd570df2630c354376
e9b3af6831d51e9b0317092164a4512a26f290eb313a7298b52d2b8cf575
17950b772de6690ff946785b068882fa186b5c1654f1266e93401c3c4b6b
f365b2dca4387395672675e4eaee5a2c3e758c6ec5699d601fe817b4d1aa
981a98c975f29fddd7b883c04a0ca6ac24cea36835d6f41d3dd1f3df06d3
30d1cc84921530b73dee77b120321e26a33eb2972c5e753c8a1e50fab7cd
6c6e7ca3457bc4673901de867b8cba139cfd9d0c31a1a56268db6de9e955
724ba1a6aca866ed8abb2566a65ec8f34fe3ab1e29fb9f98a8dc81460fd3
88a6ecdd2b05165cfc2ff29198ad92024e1eb34a501a93586c56378993bc
9b13767f1099e0d8b731ae70f96dd1237b98ce0304df1f7c8dcb11d48319
e52112f415889c5ea859121a797cb19480fb3179ac3087f3e892b51eae03
a8fd356d925253ed68b9f2a077a0e84b8adb1477cef35ae1616e36821fc6
0dd67c54de4d93e6883e25573ba191754281b20c3334e9d89b3135f91355
235189d58206dceefa4e106af0c9aa4b83b8e5723de7cf3530e44c079fa5
e4edef4d23fea71a5fc0c6fb64bbccc206bcd615ee23c14f232940fd131d
7b6d0ec824065734d2ed73134a2bde6be8de4d3adc751be9c110f35dd05a
ee1923a5619d2985dda8e81d73aa0a2dc2949570a2adabf3781662e517aa
7772aba7acfb33787d9741da5f6acbf51302e62ec50af170a81d62a09fea
127324907108b54c95817787326a02271a5911a2a76f3c027c4a758ab272
e14ca6199fb118e9e7d847cc6e0d3aef32e32437812221bf5c2a6982e2f1
48d44382adc12d9c09a427448c60affae93d838f33a36325f4252fcfa5ba
6a5e4184fdfdfea8f1b5b3edbe71204aafc532e30fafb33dd88677158872
32b3fa6cd81e238f4822ba24379d95dc0da2f18ea5aac31840d6a7baf5a6
163c54c750908e249e2f794757fd2357c3916caeba4ec2fbbb4f0d2f42fa
b4d4ddf03d3f6ef18fd7543c395409fa43a375b8c86247c7303270cc4355
ff8ef5f8aa1245dabdd21b7145f37e06bb6e8eccf132f5ca1b4e30a6ea15
b2e7dd3ce3a9fc61c902a110cfb9ff3b07bf"
            .trim()
            .replace("\n", "");

        let der = hex::decode(&input).unwrap();
        let key = SecretKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
    }

    // Tests that a DER encoded ML-DSA-65 public key can be decoded and re-encoded
    // to the same string. The purpose is not to battle-test the DER implementation,
    // rather to ensure that the code implements the DER format other subsystems
    // expect.
    #[test]
    fn test_publickey_der_codec() {
        // Generated with:
        //   openssl pkey -in test.key -outform DER -pubout -out test.pub
        //   cat test.pub | xxd -p
        let input = "\
308207b2300b0609608648016503040312038207a10058cc31abeb220f12
1b1f81fe955cb544416bf8ab1e5f90833b2f94cb4a7bec4d233a14ca86b6
5061675fb6d1d63453a0b83a3b38db3d96737d7c36573538209609b8b430
613624bf08de2d70b5ff1542fc4ae0ee3f99b18febecd97a47277c35ce35
72c96250c7f8b3984a1b65ce5f5fc3a541b418a6e37a59b3454b3c8ebc94
fb450160d404c10a2afd721f8ee29c90194919bf852d445adee0635ff4e1
0ae3d9d2419bcf99903112b3c3f897c0f918b8a3879d1cd88a89daee61d2
77f311e57abde344530236d0a784aba1c8c0f12d9a756256a392fc782463
8549f2b6f4ca979b6f055a97332df266cd57c4f1f0eec7ec57b30049b1e5
1bd925679debe71271041a1bff25044bc2ccdd01c0c4930683cd7f4887ad
e6aea3841f80da75f01d090aa073a67be8c825138d6e2b1cf0cdb19fbc83
91dbc45fff69f4ff4c2e60f110a24f5c1e118e8f9369b3d2562194e6747c
66154ba398134bdda177aca7637236e754b3089ddaf9edbc59abcb52be5e
f34aa5dc2ef86e9f6c168a1a34f1d6efc4f02c4061af5baba25eb3d801ba
cd2d40d05e377dc2e9dde162e4f38043c0ee4be9307da863bc7a069707eb
9363675d84548b77b9a00b6e18be146b0e1ea46d3e130f5bf6d8454b7541
0f4c334a475e66745877a80f5d8f99d2d81a72b00edea72519dfeff774d4
9793b40af1767ac0c8b25ab021fa9a9256d4ef8c0dc8c115a651f669475f
0b98c1e71cda8b253cd765f1280b3506d7b30e7f9bf85afcd7ec8f06e649
2a48ff59f92e357801d5a3ca359efede736caffb5b79a09db82c9f8c6636
f67163833e288530692ce0a74a1754206275cde79a1dbcc798e2bc873831
7d4411e7a4290be027a72210abb906ee18f0ed575a7e321196406f959c39
685d6c4c8de7bcf0589823690ca87b0baeea09e57cb0e4bdebbfe1e7cdc5
105977b608d1dd0ed4c27d7c4c51da09c0239adc5cda1a93157e8039f6ab
c55b9d9d083c54a3da2f58b806e85e715d54c126481be8cf9dd39590f707
43ab12da8a186a0e1a7198c66e48e56c984a99dc055e66b85b324cc02707
2e382b0dae7d540c8ae721f099ce70d0710d2b7f1e7f7e97b4d0645ea4d1
9531166c71ed5f3e373808213581f19c645e765807419f82e7ce7a9c1f67
5000ea96df79d20c0c401f861ae30c6770330e480a56149fcdec8a764d4c
7f246e48c1a482c28aebcc6ff305e3e1fdf644a8a675737b118a93b1e77f
bfc800ad67d342dc2a141fccb9793878e73b93301b4658231e4593c488ee
7482503e7438a913fd9a297d7604ae1e990cf8a2c79347ae455d704fc526
a5efc9a2c50dec9037866e9b63f46ac84aa985cdc28e99f223a3c034ac05
ce8b4d229a24dd5649a1d69e7abf0d89240e8428c248811b38f42d5d447d
1add4348009c3b687d27d8c1f13652d378385bb3c026e14cf93b4e9b2d1f
8f7f0aee76dd151b447c70fa58290cb24ea7b97c6036b6f0d2a1b30376de
44d304d7c81680d4c5a671e60e19892408e755d90bbaf958e2e79d3b2c88
f4dc2381183f3f30eb02a5a756061a98d2313542aba8c775b111ddf5f50d
830e5c5077abaede047abb114abf8442422b6cbe852b5dd289d5f0a331af
2caa725c4a0f8565eb2eb330cb7b4e972ebc3c585e24a28ffcde7fdea7fb
854d5bace20cd3e5403f162347b1b24217a5716217067fe367b15c2e6ba7
3e773df977a0ce2b13097c31fcd16526ef41341d5ec38aa8abaef8051df7
6fb00d4a8b5748036b2e1622b9736a6bcada3a01e18f9dbd989c48d806f1
3d622be3c373818cf33b7916b54dd7876ee6bea8080e35e76d64c4aa672d
b9c037d42f7ba8bc168923bf9a1dd187093a4acfda33eab5f70d303158e9
20bff261a3f34c6a261683013256ca8b03f0c7670810a10b9bdb60d8e8e6
4f2d63e9f9d456f0679efc1237b08a5ee915de30f92106562c083fbc5df3
7116e3a9b03a9716691270548e040e22988e622a80a1310994779f6578c1
3102688150d0c3a7bf7850b98995a02bc013f799e8d35d08941167e533a6
60a9472e4acdb606051b83921ab086fb3d613c1f57094c593dfb8fb713ac
740d321807d6c1c5e62bf7d3afcf930c941b50870eb26e18eaf4c63f3184
01ce196e10994c4502ed8b7dcc58c4e086c7bd18324ddc193f7551ffeb30
9fa28ad2168269ad9692e53c9940540162891e9f854ba4145d5102f40d81
f81c8744ee8fd97983163784c1c43016daa0de55a2e16c5949fe3737ee84
d04f881f20fd50d1f8bbc58dd5db3eb4357393e4859183f62db69cff2eb3
706ad5c9e3dea63441c39d175d97f659d3dc0c2e0d206991e4fad0b861e8
cc8f898658bb0ab8eac53e3add5d1b0eeff2497b259db6cde0f6dcda6a7a
272f19ffe749e14ab8b0bf208a5b45fd67b3d0e3723f6f94b1196b0771d8
94a4a1607ea66d79e0409867a66d4c255523c8bd3ae1efe7189d6c1bf1ce
62eee5cc73e247e9a07b25a4a3cbd51aad22c31d87f11bd452a8d7131fe3
a080d67bec8528778cf48d001dd81b5358adb6c40c11527685e5dc135fdd
24fab0b25e746ce1a7c826234a14606ed6d021f160974dfe68e98eb98019
dbdfd1dd95f38d72218ceeae2461974019c705ef7d2d16a56e7b50a0cd51
8aa9f4772c47a5209f7033bd3191b017eb083f94615abcb3c777d661383c
891ce8c5a6e2e35cd9b025ae41b1909dbe79bb3bb2da7675cd3b96b629e5
98005f4479c0a9be004a433553f69a081c15f70e515343ea"
            .trim()
            .replace("\n", "");

        let der = hex::decode(&input).unwrap();
        let key = PublicKey::from_der(&der).unwrap();
        assert_eq!(hex::encode(key.to_der()), input);
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
            ctx: &'a [u8],
        }
        let tests = [
            TestCase {
                message: b"message to authenticate",
                ctx: b"",
            },
            TestCase {
                message: b"message to authenticate",
                ctx: b"application context",
            },
        ];

        for tt in &tests {
            // Sign and verify the message
            let signature = secret.sign(tt.message, tt.ctx);
            public.verify(tt.message, tt.ctx, &signature).unwrap();

            // Verify wrong context fails
            assert!(
                public
                    .verify(tt.message, b"wrong context", &signature)
                    .is_err()
            );
        }
    }

    #[test]
    fn test_bad_pubkey_does_not_panic() {
        // Ensure malformed public keys don't crash
        let zeros = [0u8; 1952];
        let _ = PublicKey::from_bytes(&zeros);

        let ones = [0xFFu8; 1952];
        let _ = PublicKey::from_bytes(&ones);
    }
}
