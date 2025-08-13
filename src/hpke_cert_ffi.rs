// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

// Export the HPKE functions from the hpke.rs module
pub use crate::hpke::*;

#[repr(C)]
pub struct CPublicKeyFromCertResult {
    pub success: c_int,
    pub public_key: *mut c_char,
    pub not_before: u64,
    pub not_after: u64,
    pub error: *mut c_char,
}

// Extract public key from certificate with validity period
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_publickey_from_cert(
    cert_der: *const c_char,
    signer_public_key_pem: *const c_char,
) -> CPublicKeyFromCertResult {
    let result = (|| -> Result<(String, u64, u64), Box<dyn std::error::Error>> {
        let cert_der_hex = unsafe { crate::hpke_ffi::c_str_to_string(cert_der)? };
        let signer_public_key_pem_str =
            unsafe { crate::hpke_ffi::c_str_to_string(signer_public_key_pem)? };

        let cert_der_bytes = hex::decode(&cert_der_hex)?;
        let signer = crate::eddsa::PublicKey::from_pem(&signer_public_key_pem_str)?;

        let (public_key, not_before, not_after) =
            PublicKey::from_cert_der(&cert_der_bytes, signer)?;

        Ok((hex::encode(&public_key.to_bytes()), not_before, not_after))
    })();

    match result {
        Ok((public_key, not_before, not_after)) => CPublicKeyFromCertResult {
            success: 1,
            public_key: crate::hpke_ffi::string_to_c_char(public_key),
            not_before,
            not_after,
            error: ptr::null_mut(),
        },
        Err(e) => CPublicKeyFromCertResult {
            success: 0,
            public_key: ptr::null_mut(),
            not_before: 0,
            not_after: 0,
            error: crate::hpke_ffi::string_to_c_char(e.to_string()),
        },
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
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
            CString::new(hex::encode(&der)).unwrap().as_ptr(),
            CString::new(bobby_public.to_pem()).unwrap().as_ptr(),
        );

        assert_eq!(result.success, 1);
        let public_key_hex =
            unsafe { CStr::from_ptr(result.public_key).to_str().unwrap() };

        // Verify results
        assert_eq!(public_key_hex, hex::encode(alice_public.to_bytes()));
        assert_eq!(result.not_before, start);
        assert_eq!(result.not_after, until);
    }
}
