// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE + x509 cryptography wrappers and parametrization.

use super::PublicKey;
use crate::xdsa;
use bcder::Mode;
use bcder::Oid;
use bcder::encode::Values;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use std::error::Error;
use x509_certificate::asn1time::Time;
use x509_certificate::rfc3280::Name;
use x509_certificate::rfc5280::AlgorithmIdentifier;
use x509_certificate::{X509Certificate, rfc5280};

/// OID for id-MLDSA65-Ed25519-SHA512: 1.3.6.1.5.5.7.6.48
const CERT_OID: &[u8] = &[43, 6, 1, 5, 5, 7, 6, 48];

impl PublicKey {
    /// from_cert_pem parses a public key out of a PEM encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_pem(
        pem: &str,
        signer: xdsa::PublicKey,
    ) -> Result<(Self, u64, u64), Box<dyn Error>> {
        let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
        PublicKey::from_cert_der(der.contents.as_slice(), signer)
    }

    /// from_cert_der parses a public key out of a DER encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_der(
        der: &[u8],
        signer: xdsa::PublicKey,
    ) -> Result<(Self, u64, u64), Box<dyn Error>> {
        // Parse the certificate
        let (_, cert) = x509_parser::parse_x509_certificate(der)?;

        // Validate the content against the provided signer (composite signature)
        let tbs = cert.tbs_certificate.as_ref();
        let sig: [u8; 3373] = cert
            .signature_value
            .data
            .as_ref()
            .try_into()
            .map_err(|_| "invalid signature length")?;
        signer.verify(tbs, &sig)?;

        // Extract the embedded public key
        let pk_bytes: [u8; 1216] = cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
            .try_into()?;
        let key = PublicKey::from_bytes(&pk_bytes);

        // Extract the validity period
        let start = cert.tbs_certificate.validity.not_before.timestamp() as u64;
        let until = cert.tbs_certificate.validity.not_after.timestamp() as u64;

        Ok((key, start, until))
    }

    /// to_test_cert_pem generates a PEM encoded certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produced certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert_pem(&self, start: u64, until: u64, signer: xdsa::SecretKey) -> String {
        self.to_test_cert(start, until, signer)
            .encode_pem()
            .unwrap()
    }

    /// to_test_cert_der generates a DER encoded certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produced certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert_der(&self, start: u64, until: u64, signer: xdsa::SecretKey) -> Vec<u8> {
        self.to_test_cert(start, until, signer)
            .encode_der()
            .unwrap()
    }

    /// to_test_cert generates a certificate out of a public key.
    ///
    /// Note, this method is only for testing, most of the contained data will be
    /// junk; and also the produced certificate is not fully spec-adhering:
    ///   <https://github.com/indygreg/cryptography-rs/issues/26>
    pub fn to_test_cert(&self, start: u64, until: u64, signer: xdsa::SecretKey) -> X509Certificate {
        // Create the composite algorithm identifier (no parameters)
        let composite_oid = Oid(Bytes::from_static(CERT_OID));
        let composite_alg = AlgorithmIdentifier {
            algorithm: composite_oid.clone(),
            parameters: None,
        };

        // Create the certificate configuration
        let tbs_certificate = rfc5280::TbsCertificate {
            version: Some(rfc5280::Version::V3),
            serial_number: 0.into(),
            signature: composite_alg.clone(),
            issuer: Name::default(),
            validity: rfc5280::Validity {
                not_before: Time::from(Utc.timestamp_opt(start as i64, 0).unwrap()),
                not_after: Time::from(Utc.timestamp_opt(until as i64, 0).unwrap()),
            },
            subject: Name::default(),
            subject_public_key_info: rfc5280::SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: composite_oid,
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

        // Encode and sign the content with composite signature
        let mut tbs_der = Vec::<u8>::new();
        tbs_certificate
            .encode_ref()
            .write_encoded(Mode::Der, &mut tbs_der)
            .unwrap();

        let signature = signer.sign(&tbs_der);

        // Create the wrapper with the attached composite signature
        X509Certificate::from(rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm: composite_alg,
            signature: bcder::BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::xdsa;
    use crate::xhpke::{PublicKey, SecretKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Tests that certificates can be created (for testing purposes) and then
    // parsed and verified.
    #[test]
    fn test_cert_parse() {
        // Create the keys for Alice (HPKE) and Bobby (CMLDSA signer)
        let alice_secret = SecretKey::generate();
        let bobby_secret = xdsa::SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        // Create a certificate for Alice, signed by Bobby
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let until = start + 3600;

        let pem = alice_public.to_test_cert_pem(start, until, bobby_secret.clone());
        PublicKey::from_cert_pem(pem.as_str(), bobby_public.clone()).unwrap();

        let der = alice_public.to_test_cert_der(start, until, bobby_secret.clone());
        PublicKey::from_cert_der(der.as_slice(), bobby_public.clone()).unwrap();
    }
}
