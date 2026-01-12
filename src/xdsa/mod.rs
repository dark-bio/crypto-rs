// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composite ML-DSA cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs

mod cert;

use crate::pem;
use crate::{eddsa, mldsa};
use der::asn1::BitStringRef;
use der::{AnyRef, Decode, Encode};
use sha2::Digest;
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use std::error::Error;

/// Prefix is the byte encoding of "CompositeAlgorithmSignatures2025" per the
/// IETF composite signature spec.
const SIGNATURE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Label is the signature label for ML-DSA-65-Ed25519-SHA512.
const SIGNATURE_DOMAIN: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// OID is the ASN.1 object identifier for MLDSA65-Ed25519-SHA512.
pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48");

/// Size of the secret key in bytes.
/// Format: ML-DSA seed (32 bytes) || Ed25519 seed (32 bytes)
pub const SECRET_KEY_SIZE: usize = 64;

/// Size of the public key in bytes.
/// Format: ML-DSA (1952 bytes) || Ed25519 (32 bytes)
pub const PUBLIC_KEY_SIZE: usize = 1984;

/// Size of a composite signature in bytes.
/// Format: ML-DSA (3309 bytes) || Ed25519 (64 bytes)
pub const SIGNATURE_SIZE: usize = 3373;

/// SecretKey is an ML-DSA-65 private key paired with an Ed25519 private key for
/// creating and verifying quantum resistant digital signatures.    
#[derive(Clone)]
pub struct SecretKey {
    ml_key: mldsa::SecretKey,
    ed_key: eddsa::SecretKey,
}

impl SecretKey {
    /// generate creates a new, random private key.
    pub fn generate() -> SecretKey {
        SecretKey {
            ml_key: mldsa::SecretKey::generate(),
            ed_key: eddsa::SecretKey::generate(),
        }
    }

    /// compose creates a secret key from its constituent ML-DSA-65 and Ed25519
    /// secret keys.
    pub fn compose(ml_key: mldsa::SecretKey, ed_key: eddsa::SecretKey) -> Self {
        Self { ml_key, ed_key }
    }

    /// split decomposes a secret key into its constituent ML-DSA-65 and Ed25519
    /// secret keys.
    pub fn split(self) -> (mldsa::SecretKey, eddsa::SecretKey) {
        (self.ml_key, self.ed_key)
    }

    /// from_bytes creates a private key from a 64-byte seed.
    pub fn from_bytes(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        let ml_seed: [u8; 32] = seed[..32].try_into().unwrap();
        let ed_seed: [u8; 32] = seed[32..].try_into().unwrap();

        Self {
            ml_key: mldsa::SecretKey::from_bytes(&ml_seed),
            ed_key: eddsa::SecretKey::from_bytes(&ed_seed),
        }
    }

    /// from_der parses a DER buffer into a private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info = pkcs8::PrivateKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512
        if info.algorithm.oid != OID {
            return Err("not a composite ML-DSA-65-Ed25519-SHA512 private key".into());
        }
        // Private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
        let seed: [u8; 64] = info
            .private_key
            .try_into()
            .map_err(|_| "composite private key must be 64 bytes")?;

        Ok(Self::from_bytes(&seed))
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

    /// to_bytes converts a secret key into a 64-byte array.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ml_key.to_bytes());
        out[32..].copy_from_slice(&self.ed_key.to_bytes());
        out
    }

    /// to_der serializes a private key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        // Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
        // MUST be absent
        let alg = pkcs8::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None,
        };
        // The private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
        let key_bytes = self.to_bytes();

        let info = pkcs8::PrivateKeyInfo {
            algorithm: alg,
            private_key: &key_bytes,
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
            ml_key: self.ml_key.public_key(),
            ed_key: self.ed_key.public_key(),
        }
    }

    /// fingerprint returns a 256bit unique identifier for this key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.public_key().fingerprint()
    }

    /// sign creates a digital signature of the message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
        // where ctx is empty and PH is SHA512
        let mut hasher = sha2::Sha512::new();
        hasher.update(message);
        let prehash: [u8; 64] = hasher.finalize().into();

        let mut m_prime =
            Vec::with_capacity(SIGNATURE_PREFIX.len() + SIGNATURE_DOMAIN.len() + 1 + 64);
        m_prime.extend_from_slice(SIGNATURE_PREFIX);
        m_prime.extend_from_slice(SIGNATURE_DOMAIN);
        m_prime.push(0); // len(ctx) = 0, no ctx bytes follow
        m_prime.extend_from_slice(&prehash);

        // Sign M' with both algorithms
        let ml_sig = self.ml_key.sign(&m_prime, SIGNATURE_DOMAIN);
        let ed_sig = self.ed_key.sign(&m_prime);

        Signature::compose(ml_sig, ed_sig)
    }
}

/// PublicKey is an ML-DSA-65 public key paired with an Ed25519 public key for
/// verifying quantum resistant digital signatures.
#[derive(Debug, Clone)]
pub struct PublicKey {
    ml_key: mldsa::PublicKey,
    ed_key: eddsa::PublicKey,
}

impl PublicKey {
    /// compose creates a public key from its constituent ML-DSA-65 and Ed25519
    /// public keys.
    pub fn compose(ml_key: mldsa::PublicKey, ed_key: eddsa::PublicKey) -> Self {
        Self { ml_key, ed_key }
    }

    /// split decomposes a public key into its constituent ML-DSA-65 and Ed25519
    /// public keys.
    pub fn split(self) -> (mldsa::PublicKey, eddsa::PublicKey) {
        (self.ml_key, self.ed_key)
    }

    /// from_bytes converts a 1984-byte array into a public key.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Box<dyn Error>> {
        let ml_bytes: [u8; 1952] = bytes[..1952].try_into().unwrap();
        let ed_bytes: [u8; 32] = bytes[1952..].try_into().unwrap();

        Ok(Self {
            ml_key: mldsa::PublicKey::from_bytes(&ml_bytes),
            ed_key: eddsa::PublicKey::from_bytes(&ed_bytes)?,
        })
    }

    /// from_der parses a DER buffer into a public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Parse the DER encoded container
        let info: SubjectPublicKeyInfo<AlgorithmIdentifier<AnyRef>, BitStringRef> =
            SubjectPublicKeyInfo::from_der(der)?;

        // Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512
        if info.algorithm.oid != OID {
            return Err("not a composite ML-DSA-65-Ed25519-SHA512 public key".into());
        }
        // Public key is ML-DSA-65 (1952 bytes) || Ed25519 (32 bytes) = 1984 bytes
        let key_bytes: [u8; 1984] = info
            .subject_public_key
            .as_bytes()
            .ok_or("invalid public key bit string")?
            .try_into()
            .map_err(|_| "composite public key must be 1984 bytes")?;

        Self::from_bytes(&key_bytes)
    }

    /// from_pem parses a PEM string into a public key.
    pub fn from_pem(pem_str: &str) -> Result<Self, Box<dyn Error>> {
        // Crack open the PEM to get to the public key info
        let (kind, data) = pem::decode(pem_str.as_bytes())?;
        if kind != "PUBLIC KEY" {
            return Err(format!("invalid PEM tag {}", kind).into());
        }
        // Parse the DER content
        Self::from_der(&data)
    }

    /// to_bytes converts a public key into a 1984-byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut out = [0u8; 1984];
        out[..1952].copy_from_slice(&self.ml_key.to_bytes());
        out[1952..].copy_from_slice(&self.ed_key.to_bytes());
        out
    }

    /// to_der serializes a public key into a DER buffer.
    pub fn to_der(&self) -> Vec<u8> {
        // Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
        // MUST be absent
        let alg = spki::AlgorithmIdentifierRef {
            oid: OID,
            parameters: None,
        };
        // The public key info is the BITSTRING of the two keys concatenated
        let key_bytes = self.to_bytes();

        let info = SubjectPublicKeyInfo::<AnyRef, BitStringRef> {
            algorithm: alg,
            subject_public_key: BitStringRef::from_bytes(&key_bytes).unwrap(),
        };
        info.to_der().unwrap()
    }

    /// to_pem serializes a public key into a PEM string.
    pub fn to_pem(&self) -> String {
        pem::encode("PUBLIC KEY", &self.to_der())
    }

    /// fingerprint returns a 256bit unique identifier for this key.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.ml_key.to_bytes());
        hasher.update(self.ed_key.to_bytes());
        hasher.finalize().into()
    }

    /// verify verifies a digital signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Box<dyn Error>> {
        // Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
        // where ctx is empty and PH is SHA512
        let mut hasher = sha2::Sha512::new();
        hasher.update(message);
        let prehash: [u8; 64] = hasher.finalize().into();

        let mut m_prime =
            Vec::with_capacity(SIGNATURE_PREFIX.len() + SIGNATURE_DOMAIN.len() + 1 + 64);
        m_prime.extend_from_slice(SIGNATURE_PREFIX);
        m_prime.extend_from_slice(SIGNATURE_DOMAIN);
        m_prime.push(0); // len(ctx) = 0, no ctx bytes follow
        m_prime.extend_from_slice(&prehash);

        // Split and verify both signatures
        let (ml_sig, ed_sig) = signature.split();

        self.ml_key.verify(&m_prime, SIGNATURE_DOMAIN, &ml_sig)?;
        self.ed_key.verify(&m_prime, &ed_sig)?;

        Ok(())
    }
}

/// Signature is an ML-DSA-65 signature paired with an Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    ml_sig: mldsa::Signature,
    ed_sig: eddsa::Signature,
}

impl Signature {
    /// compose creates a signature from its constituent ML-DSA-65 and Ed25519
    /// signatures.
    pub fn compose(ml_sig: mldsa::Signature, ed_sig: eddsa::Signature) -> Self {
        Self { ml_sig, ed_sig }
    }

    /// split decomposes a signature into its constituent ML-DSA-65 and Ed25519
    /// signatures.
    pub fn split(&self) -> (mldsa::Signature, eddsa::Signature) {
        (self.ml_sig.clone(), self.ed_sig)
    }

    /// from_bytes converts a 3373-byte array into a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        let ml_bytes: [u8; 3309] = bytes[..3309].try_into().unwrap();
        let ed_bytes: [u8; 64] = bytes[3309..].try_into().unwrap();

        Self {
            ml_sig: mldsa::Signature::from_bytes(&ml_bytes),
            ed_sig: eddsa::Signature::from_bytes(&ed_bytes),
        }
    }

    /// to_bytes converts a signature into a 3373-byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..3309].copy_from_slice(&self.ml_sig.to_bytes());
        out[3309..].copy_from_slice(&self.ed_sig.to_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from draft-ietf-lamps-pq-composite-sigs-latest Appendix E
    // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
    mod ietf_vectors {
        pub const TEST_SECKEY: &str = "\
d79b8541af185b7bb61ea99c302df11d2b760cb8aa1d0628be8882a82d87\
589c84210cb6f19c6ebb32992b59440eb7f4d5c75d50ebe1c18f55ed16e8\
565e3529";

        pub const TEST_SECKEY_PKCS8: &str = "\
3051020100300a06082b060105050706300440d79b8541af185b7bb61ea9\
9c302df11d2b760cb8aa1d0628be8882a82d87589c84210cb6f19c6ebb32\
992b59440eb7f4d5c75d50ebe1c18f55ed16e8565e3529";

        pub const TEST_PUBKEY: &str = "\
a22f268082309f80fecf71f1dcc699e1d0be28d8d66a07fe7c8b75922e5a\
200254b56376d3be068859929674b34b9bbebbf5fc5a295d2fd2a41b0d33\
a8444b90a31deb699f41a8d7787d0ca5f42c2b054411ed71e732b60ab5f7\
58e80c19323e4f7aa734e39755683dc5e864df71e18151bba49e1e8fed11\
0d9149df05a46938d3e2e33b2391df6d8580e9c395f3bedd9277c2bf6b1b\
77e669de20ba1b5434eff5c2bc9b58d54b26cc4580e98bd07e2b5fa0ed80\
0a811a758ff89f63aff652b9488ea064862dc220ed0bc8104535d32ea0a4\
62f033bb34b7031cfff70f2513c294c7c72959980d97244365988d37aefd\
a8901c4d77ebf462bba17fab6feb68d8cfbf7e3aaa08cd2544b1fc6d95e9\
3f51a87cdbf908ad9ec058070b80f0f5d32b40a912ffbc504d401921e247\
be6a72c2148f67932dacb3b309e27aac2d6370b558980e6ec5aa1b771c81\
f038b0ecbbc9065ec256b243e40c178655fd1864ea72a09244264c48e6e2\
f15363826a33a8f350f5685c276145a296901d3bc67a8adba0bab5374bd0\
0d8a96350943565a65e383ae5e4deb3580a2a0b3330ada29679e90b648cc\
1585aeffb8d1a7df77760f9bd16c20ee1fd6076d394be1af5d927e123c4b\
d07065c14c11f1c1b1d3d215601345aeb75d7a7bac91526efd2a65b75c08\
5c37de26d22570a0852c3aa55d5387a93777390c6487bcbd8dcc743f66d1\
bc65ead105a08905e3ccb49072e06f9bd60fea721f52a80f399a94c89515\
0fa71ba5a00cec39abd51f6423bb04dcc232d86f9f251c25e82e1304d812\
963d3378c5778fc26ad7cef6dc168037dae0c1eb2d079fc6e97e639b3207\
84ded4b36547ec7cbac8b04b69189b80ce958897dff748af1602f1fa3e03\
f6e61b84816b2017222bb96de2a3e6649cd84a4a52d1ed7dde44701ce304\
7134bb9403f2fb546af1101ffeda8d0318c1c87df1a4dbcfd821336ffb9e\
1e3c707695b6dfe6173caa17e5e6b4a69e8f2334be2c5c033887f17c0135\
c2ee3e70b88dcfda85e6ed8ee4603d3f45b620dd819d15f2821f5b0d9ee9\
28d6d76bd799dd7a5dd7a98392a174af6a45274ea99d444884bf26744c15\
9c9a609d136c1348906a095da0b5fa696575ea4712e17bbbe1b003cd3254\
e93fd9325ee7d5e22fb34ae3b075558275bccce9d50a32bd62e8b78c7b6c\
f0563a488ff5c456229881facc237bc365351f8f6c7094e6fc608f7937bb\
7dbf6ddc57bc9f6e817db3fb9b998fe2a9b17131cf412bc5e75044620573\
cbc53b4215181553717e0952a81bc0b520cd4b4a1d00750b550b372ecb16\
113cb451fd6799c3d45c8c70e8209d41259369770389aa50c6689ad30263\
01126fb8c3c34ffc04bea31f44e1ee98be0cfa70d8ee42c0497bf9194f3f\
edf078520195b30e84540f0ff73b92d9dea48db5315a0db57cd10c0f53da\
989245a3cffc593cbacf8063283b23b22b2a10bfc4b4b250b7388ddaa014\
4d960c3f738cc10342133bf3d0f0e0a6179554b04ab0119e1b3111818065\
cbc1b0b64cdf26b2f0c74f985e17d0e4f871a34c487bff2097f5f848b29b\
8d50bb86e64b30f0031bb14ee6986a4b17be781d9dc0afdf6075365b6951\
ec211e55ba5df0a484ffcffd33cade8394dbba38c2f4017cc1eb6f3f16b0\
41fe1a53ac5427d5b5071f5ee37fd1bb57722985ef4510faca5e457666a7\
c00cb15727401f5898ae2a5fa2da6c60813b0903fbdcf521b92ad2fa4b87\
361e344a1998963c536691caecd3bea1028bfcec0a0b9738976f77631405\
f3b351893b55a1c9138abd33d7432cc1f80bd403a1655e341af8b02e9890\
edcdcae965ba31991ec8bcb9ca5ae1359ca208835a469ff0f4678ccd3680\
9770b7ecef4a479431ba10fd19fce57d99e70ab77fff245a531b2225de01\
341d4f10d96d46171c4ba59003fea32121c9ec60ac33247c4cc21b32a117\
8f3a3769fee54bb6d6a88c3a2fedbbb4bcdd899bc396d89e8c2556c3562c\
af606468265ae58c823125402e7e8046b94c3c6412c89410376d4804bae4\
8004688e7541e33ac98e23ea0d1851e65a41694e8e38a7901f713e13945a\
c8b8adf75964ec284e2713747342fb0cefa2b48e1f80c993f34c4384b967\
02241c3a4138744eee23f69b2bfcfe9d20aa615b0dd23e944eb423133a8a\
b3cbb5bc9978d54544a7c1caa501da9e390d18f04771c334f1c689e20052\
4880644863b4c21295bebe59fe6b940c2e0112e0f8731e6fc7ab60914835\
d53dd82339be25551b430edadc20ed9927f29c1cb6a8ef278527fd05e982\
1037bacf11888f6a63cb2ef82fd6635f3bc83bca351ac9f6bb6e5bef2f9e\
a15436e2b9b5506dfdfc82de2b20dc093e955bfc305e870bd040c1d2d8ff\
463847c1ffa09e7e21a6c9c4517702d23281037238675eff574a2dd420ca\
0416a0ec8c5d7c596713df2b2352b5976f6381f4f88fcc8ea4fb47fc3287\
4bdabf1637545dc6fa9ba8fa04156dd225debf9899e065f48275c51832bf\
e70483fe6303f5f1854f5bfc99fe5828a0ae414e24e75b7abaab17db01b9\
ebf3c067396eb161ee168ce6a7620b3be3def3ee2ea6e74e99f76f56cab0\
4384b1462d251d0db511d2caf73bfb49fb05a95dfc9756ae3b61b2ef6f95\
31933a016417e0f82fb05dfc9f53a89b29f64b8844757bb320d80be22c2d\
117b95dea731f26dc933b9c6812d5b8a4c720df37682e53da2d9ef0605a6\
8683c182a56a108000f87532623a8c35967c549a4893c5304e6b00059abc\
a5a0339ce946319a92ae0d18d2a98659605081c8a3c1d4afa788c6d971f2\
1a90c207";
        pub const TEST_MSG: &str = "\
The quick brown fox jumps over the lazy dog.";

        pub const TEST_SIG: &str = "\
12bcef243d7f459a3350bce36b4aac5195ccebcffd770f9e4222c7fade93\
f462f0e6a1d128bd23d5526b967008db4501f5ae2fcf24cdac114ee479d6\
9ae79ce2aaf6109109aa8fe04cfa0c25a1a5cba1ece496185d4af532e75e\
64d63427fb2e18c442d35c899e7ede69743b9dc034838bd6729a48b54fab\
f4253c2cd0f667b30c03521d551bfe7ae1693f992842f0ef3a9093cee7a7\
b6e409279b414d32422543e1db594924dcfe2e67d20bdfb751a874a1bb8b\
3374372f26ccf31c69400fed3768b886867157f913468708e20354b7bbec\
65b61dd5ac4f91cbc1cbb8616343cf8e084abffc2a7e129a929fcfaba430\
619eb0036fe90d58baa7c06bc4e4ecaa730861564eb6337e964575652b01\
ce15c074157dc66cc019ccc1d795a0a18579f81e865d0be73907b71dc40a\
85a5d144d375d09a0cdde5caaa2dd869887896256813731d13e997f3021b\
c0d67f9dfc2722a8e5f81537021e40adc9226a9260d6049825c9b2c79a14\
3308cfdc7067e20696354eca8cb9ae1b77d24672189f05b1921936d31e12\
f0808dbde49d8c8c5829010bbc854fa9d2d6f5587ee61b31e6b4287b8952\
d9c731f056ffe596472899f366621c5450e2b9bc794c0d6666ae696271b4\
62641403726e746b03a7c25aefec434141200eea151ca3037aaf14d84fc2\
ce5d4c988079be85905da052258d248b36e07cbb4caa248be0f39c33ff21\
4f6c1c8b28ff00a71322b4ee9519f2979aded2e61695b55dc9b6912d9fc5\
1edd84561eb4621d3b93addaaad7a888b74c945dd215242d51dd8534784b\
19c8eafded273632b4bdbbd50a2720b7b65a13d5af09921ed5ee8b16d85d\
826172db5af6714df20ed3bf9d22ceaeab3d68005d97b1b89f2e1f0ce39d\
5ce83327c2306fb4531baa507623ee869fc6b023bdecae705c45f604f56c\
5384a01017f09c47acb6bdb8d41114fc4ff7617cb781190cb3521164c309\
2467097d3d41a9bb4ecc85d1ab604daa3322e4f1d48bf44f7b016b90ae77\
1ed1ea4f155e58a47e42001c529595b3d3e21641a22e1d0e386f6e5b96cb\
6d1b74ac4d462883a0dd7001af58d4e78ab3d18991d044e4ef6e670445df\
bad8d4a86fe78edaa5bdd6a57c9daa484ffd6fa7281e92a64c74d90de38f\
33f4fa001780df159eef9774c50bf6790c6db3444c3871da1c27c8d09145\
697b27bd73f03fabe77842d17abe014f8e1194e27a0944af9b0719d4a11a\
5fcf560a5a27503ad9cddb36750b558ee90d910089e18c6a9a6b460917c3\
e5f37ecf914237c567f9d91ee17c800f00bf449545565a0ea6f79fe700bb\
f0e978a2d582d4d7812763cad8e165cbc0ff39ab016e70988d1a70c74ec7\
7fa8701725148078931599f8ea95c964f5a9770814397ec3273df3c282f9\
1c05974c7716a5c02c4a116303f59e9cb2e986a9f8793685b7e5aedc983d\
43776cfadeeb2867333bbd3cde86461985f8be1612c7495a4b94387d8ec4\
6ad8808ecd1922e0e67e616e3b374d8e644674ad88a80c2d207facc47ca5\
668cf91967c4adaeb453d48fa6cad2a8ada3206a465116486fdb8d518784\
e36d88836065807152dbb6fac7edf6d2be9fb6838a6ce4aee789d24aae89\
5b42b0b03323e98f54a497dc965c143d108b7854d172b01da36524821150\
351eb0b55a4be62afc9524540cfcea88162896d1826f03e11356fa216170\
b1f47ea84a3cd3a1a135524d32a8a24069ff6181e84ff13096768fccc3f2\
d98038106b416ee0d00109d0e85834b5f4f06a08c0891d2b17cf1d4bfe74\
e2a5336da9fa8d8293fe1a9d46e79ef2267f48df18bb14cef525e1b39a7c\
b3c3e8b973ed15f6ac088850e12f9b532822e6c51c75a691897a63d48476\
1f18846db014045f6cff76628c975a0ffbfeb7242032092610bc5c68249b\
799629a7de8c9441d5f5fc0a413edb1d5f61679ff58d9df47596ebb0eb66\
cf1e68173233a179b3f90e3bab4f8c812e584e6259110c759c951fa8e92a\
e82092e6c9f058d3c6f958abb07784f128aae38dae47646bdfb141d58480\
2fa3e6ccaf569e0e0cd9d563ece2fa1c33c17092fc9ca997d05221224328\
f4697ec17c8ce771328d09d159044e07ec9b4b3f559b3048b646b7a4fd38\
9e0d26857af0f8f8a2554cc5572a951933bfbda8dda69bbc66b85cbddd01\
2f30bd268799848f6c5521336ece4ec917778edafb78e2c5ae901b7dc48d\
db0d0c839ab51e2877d0578f91a377536de9f97d349e726c718357069bc1\
9ebca2ae4d11a9f551b6e017939cf249dfa0808584aa823fa088f55fa8ba\
eb3a6b125087c2ba38fd54fa7e93cfd2b97badf2f968d1608ca42d5e3fb9\
b7c08c917d698a8f936ad65ad4b4c3b397e81adaf22f73d387086b548a2d\
be19bd47804f52a729f15e2648218078147f77c6fee0ea3b6411d4f25df1\
a3bd0afdeb8ae4a8a74d949de9e5df02c92450ebf049d5de98bb6deb59b2\
acca0845c1076eeee24ac6cf96d61354d84d121af91c7a41972b26a5a440\
dfb8480c31715404d82ca02974ff8c2bf57146a3f567a48ccd22ca23c932\
0170bf34c5ddb24ef27912f6c5a7d56edde5fda364f8e0b9a0315d4c056d\
6eca02168212b5ad61018b7b9b4391a78250f45f9c9499ee01d9429a92fe\
1222a02c02730703f5cf51dbb9ee976db18cf910b6c9c6f8e5f75a22a358\
f287e485b614659cca962ee6a89e947b4ce61c24ee3fc7446da2d54ca9aa\
59c92ee74ecbb7f50ea92a87b925b506737eaf8efbb955fd3c5ed1e17a40\
58fc66bcefe73e2323b075c5ddc5a57af76aa51aebbca34c777b809ad2c5\
ad7b8b2d6f927539783ff3cc770d84f00cbc2eb1f8183536ee25c84b7c3f\
111c151b561403680b1c3079a6ac4e5d41f9a5685962f15bbeaa3466d720\
1e376a0f8628969e06ed7bf54128b4c46345113fcde67c3bb5d407a40b76\
9254354f236bd5853b8f4c765b24db9738b2fc98b04fe4d52fb332d157a3\
813183a275a083386e6856285319477e2ba481261d8792b0258035be52aa\
a46b28dacffd7a728c3cda63df02b17f567797b359fd10415381af2d95c2\
77eab3cf0024bdd0853c7e18184586561d3e03a97ecde07b5a2f5026858d\
5e3459805bddfe235ca5f44376c4ebfe32815e3f9ad6fd4fc116e7dfd459\
1770282a94b517ba16d37f5439b90f4bba87692fff70aad4dd23cefaaec3\
650ba160a90ef719965330904677ed6a10a91f9e56fe5ded5b8d25421ea6\
087584ee379b370b4b1175f1c0fbcf1b36850a7e02e453ace8a6258184b4\
0cd3c9a81caed79e5b3f965f7d373f800ba5505a804c67d218ba34b79c51\
3581846c4a04a9015dfdf5d6df009c7eea672e5aea85513fb9745b89d546\
a4ed8a1a2ad5a44b4696a01c8d9c46293f280162d87067ae65b624f9f93c\
a48fe7c9a1585a06ec69b3a98da627894bb6f366ba1007f95987aa1aebdb\
d070b92240a2b5f75260a4395c2d3698eefe1c4929f27e6e48e11f14c701\
290be0d32ee1f08f4ee3db089170fa7516da8038c1e0530336c3b29d7309\
3081f270dc62d8b5e3e57fe49f4eee0cbbf81b9e5f5ba77f321d2d65e862\
a1d534aa71cea5413904e3660235e8edcf4a3618140dfd2f620126978fe0\
e74367b70475a6ddea3bf8454f152b0d8b695dff664957841e31d87f289d\
8fff23e81c9654bf1548260ada4c037fb242d8612ae92051820355dc58c7\
acc0f8f0326542b869f69e5e2f6b81abfbe62703c8b4b9b1a0d425f36c44\
2d07d17a3d933e9d8475dc06f9de63195f21b76669f67d87ce63a734f86a\
a28e62034c7b3828fc33921466216289a58eaf0fe727dc3bc77e1b984a83\
30994092f553912134069211355e5c7ccfc5da62b777008995ce876131ed\
5627ece154d8821dc256e6d6aa4613c1c9857cb75425199f35172d7d91e8\
e255741ba00a983bdae35932d6c2f0da0b999bf329870a33396b0f3f0b4e\
e93dad49db64573bde5864a4b9551b9b9b4234002e2d98bd95b633d70409\
df6aba73c961b23a9a069db136cb33917401ef57417b222240f0d3cc5067\
d25d7f67d702fb811dbcd6f39ea9d934412d43c8519f3a869226b5ab302e\
0bd763536a3efc81b7fcf61a4b53dcfdfb71ffedf0a25d8b993c303f0291\
7ff6fec362eae004cfd5c218c0b20c46e961cc4bb0930584c30872f2587f\
ee1de36a22d1bb1e20da1c6959ee4dc3a85f4a9c893c481014edcee883d7\
4699e1495d26b3babe06c3f783262d37c9ba382a12775cf35b1455560ea6\
d0b1d52d1e3982fa4bee2a6d0efbb722ef49a02566b2ed3a3813ea4021ae\
53b565a0762ba4094d7b94b930a93d46f5603dd81e1ea77700d56dc884d5\
40bf5ddf489034fb779b20e057212c52f648be96acc20f1765354541696b\
0d688b7fda355b9473484b1f6f08a6b6f77747c6a6b0d5836211de5d75b1\
70ee1ac62c04b099bd10853563b942642afcf93c65e3237d39b27dab2e8f\
d98e504b099330ad254c0c0d5b5cd1ab94fcbe87ebe0d57173d8f5be4d8e\
a0aba0c732747c1c195962ae28617f8519c7cf406e2487a4f6adc3083997\
58785271d9aa265bb2f67b7e95f49360a2c77ad4147240ff0f51b1ad16a8\
f6e178bcc044204110444ea2b7e80548769ae5010c22707493adb0baf55f\
6b979dd5154780b6213d467faefb00000000000000000000000000000000\
000000060b151a1e24b3def33dabca143013e721533f4f1c5d432de001b3\
0c452425971fb2f50f5fac02fa24aa22312c4859efbef5066c8affabfc69\
1c11ef8c1bbec178a532505506";
    }

    // Tests operations with IETF test vectors.
    #[test]
    fn test_ietf_vectors() {
        // Parse the secret key seed (ML-DSA seed || Ed25519 seed)
        let seed_bytes = hex::decode(ietf_vectors::TEST_SECKEY).unwrap();
        let seed: [u8; 64] = seed_bytes.try_into().unwrap();
        let seckey = SecretKey::from_bytes(&seed);

        // Verify the public key matches (ML-DSA || Ed25519)
        let expected_pubkey = hex::decode(ietf_vectors::TEST_PUBKEY).unwrap();
        let pubkey = seckey.public_key();
        assert_eq!(pubkey.to_bytes().to_vec(), expected_pubkey);

        // Sign and verify (ML-DSA uses randomized signing, so we can't compare bytes)
        let signature = seckey.sign(ietf_vectors::TEST_MSG.as_bytes());
        pubkey
            .verify(ietf_vectors::TEST_MSG.as_bytes(), &signature)
            .unwrap();

        // Verify the IETF test signature can be verified
        let expected_sig = hex::decode(ietf_vectors::TEST_SIG).unwrap();
        let expected_sig_array: [u8; 3373] = expected_sig.try_into().unwrap();
        let expected_signature = Signature::from_bytes(&expected_sig_array);
        pubkey
            .verify(ietf_vectors::TEST_MSG.as_bytes(), &expected_signature)
            .unwrap();
    }

    #[test]
    fn test_pkcs8_encoding() {
        // Parse the secret key from seed and from PKCS8
        let seed_bytes = hex::decode(ietf_vectors::TEST_SECKEY).unwrap();
        let seed: [u8; 64] = seed_bytes.try_into().unwrap();
        let seckey_from_seed = SecretKey::from_bytes(&seed);

        let pkcs8_bytes = hex::decode(ietf_vectors::TEST_SECKEY_PKCS8).unwrap();
        let seckey_from_pkcs8 = SecretKey::from_der(&pkcs8_bytes).unwrap();

        // Both should produce the same public key
        assert_eq!(
            seckey_from_seed.public_key().to_bytes(),
            seckey_from_pkcs8.public_key().to_bytes()
        );

        // Re-encoding to DER should match the test vector
        let encoded_der = seckey_from_seed.to_der();
        assert_eq!(encoded_der, pkcs8_bytes);

        // Round-trip: decode and re-encode
        let roundtrip = SecretKey::from_der(&encoded_der).unwrap();
        assert_eq!(roundtrip.to_der(), encoded_der);
    }

    #[test]
    fn test_secretkey_compose_split() {
        let ml_key = mldsa::SecretKey::generate();
        let ed_key = eddsa::SecretKey::generate();

        let ml_bytes = ml_key.to_bytes();
        let ed_bytes = ed_key.to_bytes();

        let composite = SecretKey::compose(ml_key, ed_key);
        let (ml_key2, ed_key2) = composite.split();

        assert_eq!(ml_key2.to_bytes(), ml_bytes);
        assert_eq!(ed_key2.to_bytes(), ed_bytes);
    }

    #[test]
    fn test_publickey_compose_split() {
        let ml_key = mldsa::SecretKey::generate().public_key();
        let ed_key = eddsa::SecretKey::generate().public_key();

        let ml_bytes = ml_key.to_bytes();
        let ed_bytes = ed_key.to_bytes();

        let composite = PublicKey::compose(ml_key, ed_key);
        let (ml_key2, ed_key2) = composite.split();

        assert_eq!(ml_key2.to_bytes(), ml_bytes);
        assert_eq!(ed_key2.to_bytes(), ed_bytes);
    }

    #[test]
    fn test_signature_compose_split() {
        let ml_sec = mldsa::SecretKey::generate();
        let ed_sec = eddsa::SecretKey::generate();

        let message = b"test message";
        let ml_sig = ml_sec.sign(message, b"");
        let ed_sig = ed_sec.sign(message);

        let ml_bytes = ml_sig.to_bytes();
        let ed_bytes = ed_sig.to_bytes();

        let composite = Signature::compose(ml_sig, ed_sig);
        let (ml_sig2, ed_sig2) = composite.split();

        assert_eq!(ml_sig2.to_bytes(), ml_bytes);
        assert_eq!(ed_sig2.to_bytes(), ed_bytes);
    }

    #[test]
    fn test_compose_sign_verify() {
        let ml_sec = mldsa::SecretKey::generate();
        let ed_sec = eddsa::SecretKey::generate();

        let composite_sec = SecretKey::compose(ml_sec.clone(), ed_sec.clone());
        let composite_pub = composite_sec.public_key();

        let message = b"message to sign with composite key";
        let signature = composite_sec.sign(message);

        composite_pub.verify(message, &signature).unwrap();
    }
}
