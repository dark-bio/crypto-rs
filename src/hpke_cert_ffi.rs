// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::os::raw::{c_char, c_int};
use std::ptr;

// Export the HPKE functions from the hpke.rs module
pub use crate::hpke::*;

/// Result structure for certificate-based public key extraction operations.
///
/// Contains either a successfully extracted public key with validity period or an error message.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CPublicKeyFromCertResult {
    pub success: c_int,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub error: *mut c_char,
}

/// Extracts an HPKE public key from a DER-encoded certificate.
///
/// Verifies the certificate signature using the provided signer public key and
/// extracts the HPKE public key along with its validity period.
///
/// All pointer parameters must either be null or point to valid memory:
/// - `cert_der` must point to valid DER-encoded certificate data of `cert_der_len` bytes
/// - `signer_public_key_pem` must point to a valid null-terminated PEM-encoded Ed25519 public key
///
/// Returns a `CPublicKeyFromCertResult` with the extracted public key and validity timestamps
/// (Unix epoch seconds) on success.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_publickey_from_cert(
    cert_der: *const u8,
    cert_der_len: usize,
    signer_public_key_pem: *const c_char,
) -> CPublicKeyFromCertResult {
    let result = (|| -> Result<([u8; 32], u64, u64), Box<dyn std::error::Error>> {
        // Check for null pointers
        if cert_der.is_null() || cert_der_len == 0 {
            return Err("Null or empty certificate DER data".into());
        }

        let signer_public_key_pem_str =
            unsafe { crate::hpke_ffi::c_char_to_string(signer_public_key_pem) };

        // Get certificate DER bytes directly from pointer
        let cert_der_bytes = unsafe { std::slice::from_raw_parts(cert_der, cert_der_len).to_vec() };
        let signer = crate::eddsa::PublicKey::from_pem(&signer_public_key_pem_str)?;

        let (public_key, not_before, not_after) =
            PublicKey::from_cert_der(&cert_der_bytes, signer)?;

        Ok((public_key.to_bytes(), not_before, not_after))
    })();

    match result {
        Ok((public_key, not_before, not_after)) => CPublicKeyFromCertResult {
            success: 1,
            public_key,
            not_before,
            not_after,
            error: ptr::null_mut(),
        },
        Err(e) => CPublicKeyFromCertResult {
            success: 0,
            public_key: [0u8; 32],
            not_before: 0,
            not_after: 0,
            error: crate::hpke_ffi::string_to_c_char(e.to_string()),
        },
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use std::ffi::CString;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_ffi_publickey_from_cert() {
        // Create the keys for Alice (X25519) and Bobby (Ed25519)
        let alice_secret = SecretKey::generate();
        let bobby_secret = crate::eddsa::SecretKey::generate();
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

        let der = alice_public.to_test_cert_der(start, until, bobby_secret.clone());

        // Test the certificate parsing via FFI
        let result = rust_hpke_publickey_from_cert(
            der.as_ptr(),
            der.len(),
            CString::new(bobby_public.to_pem()).unwrap().as_ptr(),
        );

        assert_eq!(result.success, 1);

        // Verify results
        assert_eq!(result.public_key, alice_public.to_bytes());
        assert_eq!(result.not_before, start);
        assert_eq!(result.not_after, until);
    }
}
