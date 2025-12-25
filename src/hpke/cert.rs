// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE + x509 cryptography wrappers and parametrization.

use crate::eddsa;
use super::PublicKey;
use bcder::Mode;
use bcder::encode::Values;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use std::error::Error;
use x509_certificate::asn1time::Time;
use x509_certificate::rfc3280::Name;
use x509_certificate::rfc5280::AlgorithmIdentifier;
use x509_certificate::{
    InMemorySigningKeyPair, KeyAlgorithm, SignatureAlgorithm, Signer, X509Certificate, rfc5280,
};

impl PublicKey {
    /// from_cert_pem parses a public key out of a PEM encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_pem(
        pem: &str,
        signer: eddsa::PublicKey,
    ) -> Result<(Self, u64, u64), Box<dyn Error>> {
        let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
        PublicKey::from_cert_der(der.contents.as_slice(), signer)
    }

    /// from_cert_der parses a public key out of a DER encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_der(
        der: &[u8],
        signer: eddsa::PublicKey,
    ) -> Result<(Self, u64, u64), Box<dyn Error>> {
        // Parse the certificate
        let (_, cert) = x509_parser::parse_x509_certificate(der)?;

        // Validate the content against the provided signer
        let tbs = cert.tbs_certificate.as_ref();
        signer.verify(tbs, cert.signature_value.data.as_ref())?;

        // Extract the embedded public key
        let key = PublicKey::from_bytes(
            cert.tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .as_ref()
                .try_into()?,
        );

        // Extract the validity period
        let start = cert.tbs_certificate.validity.not_before.timestamp() as u64;
        let until = cert.tbs_certificate.validity.not_after.timestamp() as u64;

        Ok((key, start, until))
    }

    /// to_test_cert_pem generates a PEM encoded certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produces certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert_pem(&self, start: u64, until: u64, signer: eddsa::SecretKey) -> String {
        self.to_test_cert(start, until, signer)
            .encode_pem()
            .unwrap()
    }

    /// to_test_cert_der generates a DER encoded certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produces certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert_der(&self, start: u64, until: u64, signer: eddsa::SecretKey) -> Vec<u8> {
        self.to_test_cert(start, until, signer)
            .encode_der()
            .unwrap()
    }

    /// to_test_cert generates a certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produced certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert(
        &self,
        start: u64,
        until: u64,
        signer: eddsa::SecretKey,
    ) -> X509Certificate {
        // Create the certificate configuration
        let tbs_certificate = rfc5280::TbsCertificate {
            version: Some(rfc5280::Version::V3),
            serial_number: 0.into(),
            signature: SignatureAlgorithm::Ed25519.into(),
            issuer: Name::default(),
            validity: rfc5280::Validity {
                not_before: Time::from(Utc.timestamp_opt(start as i64, 0).unwrap()),
                not_after: Time::from(Utc.timestamp_opt(until as i64, 0).unwrap()),
            },
            subject: Name::default(),
            subject_public_key_info: rfc5280::SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: KeyAlgorithm::Ed25519.into(),
                    parameters: None,
                },
                subject_public_key: bcder::BitString::new(
                    0,
                    Bytes::copy_from_slice(self.to_bytes().as_slice()),
                ),
            },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
            raw_data: None,
        };

        // Encode and sign the content
        let mut tbs_der = Vec::<u8>::new();
        tbs_certificate
            .encode_ref()
            .write_encoded(Mode::Der, &mut tbs_der)
            .unwrap();

        let key_pair = InMemorySigningKeyPair::from_pkcs8_pem(signer.to_pem()).unwrap();
        let signature = key_pair.try_sign(&tbs_der).unwrap();
        let signature_algorithm = SignatureAlgorithm::Ed25519;

        // Create the wrapper with the attached signature
        X509Certificate::from(rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm: signature_algorithm.into(),
            signature: bcder::BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::eddsa;
    use crate::hpke::{PublicKey, SecretKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Tests that certificates can be created (for testing purposes) and then
    // parsed and verified.
    #[test]
    fn test_cert_parse() {
        // Create the keys for Alice (X25519) and Bobby (Ed25519)
        let alice_secret = SecretKey::generate();
        let bobby_secret = eddsa::SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        // Create a certificate for Alice, signed by Bobby
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let until = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let pem = alice_public.to_test_cert_pem(start, until, bobby_secret.clone());
        PublicKey::from_cert_pem(pem.as_str(), bobby_public.clone()).unwrap();

        let der = alice_public.to_test_cert_der(start, until, bobby_secret.clone());
        PublicKey::from_cert_der(der.as_slice(), bobby_public.clone()).unwrap();
    }
}
