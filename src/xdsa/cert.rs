// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CMLDSA + x509 cryptography wrappers and parametrization.

use crate::x509;
use crate::xdsa::{PublicKey, SecretKey};
use std::error::Error;
use x509_certificate::X509Certificate;

// Implement the needed subject trait for the public key.
impl x509::Subject for PublicKey {
    type Bytes = [u8; 1984];

    /// Returns the public key bytes.
    fn to_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    /// Returns the id-MLDSA65-Ed25519-SHA512 OID, 1.3.6.1.5.5.7.6.48.
    fn algorithm_oid(&self) -> &'static [u8] {
        &[43, 6, 1, 5, 5, 7, 6, 48]
    }
}

impl PublicKey {
    /// from_cert_pem parses a public key out of a PEM encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_pem(pem: &str, signer: PublicKey) -> Result<(Self, u64, u64), Box<dyn Error>> {
        let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
        PublicKey::from_cert_der(der.contents.as_slice(), signer)
    }

    /// from_cert_der parses a public key out of a DER encoded, authenticated
    /// certificate, verifying the signature and returning both the key, and the
    /// validity interval.
    pub fn from_cert_der(
        der: &[u8],
        signer: PublicKey,
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

        // Extract the embedded public key (ML-DSA-65 1952 bytes || Ed25519 32 bytes)
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

    /// to_cert_pem generates a PEM encoded X.509 certificate for this public
    /// key, signed by an xDSA issuer.
    pub fn to_cert_pem(&self, signer: &SecretKey, params: &x509::Params) -> String {
        self.to_cert(signer, params).encode_pem().unwrap()
    }

    /// to_cert_der generates a DER encoded X.509 certificate for this public
    /// key, signed by an xDSA issuer.
    pub fn to_cert_der(&self, signer: &SecretKey, params: &x509::Params) -> Vec<u8> {
        self.to_cert(signer, params).encode_der().unwrap()
    }

    /// to_cert generates an X.509 certificate for this public key, signed by an
    /// xDSA issuer.
    pub fn to_cert(&self, signer: &SecretKey, params: &x509::Params) -> X509Certificate {
        x509::new(self, signer, params)
    }
}

#[cfg(test)]
mod test {
    use crate::x509::Params;
    use crate::xdsa::{PublicKey, SecretKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Tests that certificates can be created and then parsed and verified.
    #[test]
    fn test_cert_parse() {
        // Create the keys for Alice (subject) and Bobby (issuer)
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bobby_public = bobby_secret.public_key();

        // Create a certificate for alice, signed by bobby
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let until = start + 3600;

        // Test PEM roundtrip (end-entity cert)
        let pem = alice_public.to_cert_pem(
            &bobby_secret,
            &Params {
                subject_name: "Alice",
                issuer_name: "Bobby",
                not_before: start,
                not_after: until,
                is_ca: false,
                path_len: None,
            },
        );
        let (parsed_key, parsed_start, parsed_until) =
            PublicKey::from_cert_pem(pem.as_str(), bobby_public.clone()).unwrap();
        assert_eq!(parsed_key.to_bytes(), alice_public.to_bytes());
        assert_eq!(parsed_start, start);
        assert_eq!(parsed_until, until);

        // Test DER roundtrip (CA cert with path_len=0)
        let der = alice_public.to_cert_der(
            &bobby_secret,
            &Params {
                subject_name: "Alice",
                issuer_name: "Bobby",
                not_before: start,
                not_after: until,
                is_ca: true,
                path_len: Some(0),
            },
        );
        let (parsed_key, parsed_start, parsed_until) =
            PublicKey::from_cert_der(der.as_slice(), bobby_public.clone()).unwrap();
        assert_eq!(parsed_key.to_bytes(), alice_public.to_bytes());
        assert_eq!(parsed_start, start);
        assert_eq!(parsed_until, until);
    }

    // Tests that certificates signed by one key cannot be verified by another.
    #[test]
    fn test_cert_invalid_signer() {
        // Create the keys for Alice (subject), Bobby (issuer) and Wrong (3rd party)
        let alice_secret = SecretKey::generate();
        let bobby_secret = SecretKey::generate();
        let wrong_secret = SecretKey::generate();

        let alice_public = alice_secret.public_key();

        // Create a certificate for alice, signed by bobby
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let until = start + 3600;

        // Sign a new certificate and verify with the wrong signer
        let pem = alice_public.to_cert_pem(
            &bobby_secret,
            &Params {
                subject_name: "Alice",
                issuer_name: "Bobby",
                not_before: start,
                not_after: until,
                is_ca: false,
                path_len: None,
            },
        );
        let result = PublicKey::from_cert_pem(pem.as_str(), wrong_secret.public_key());
        assert!(result.is_err());
    }
}
