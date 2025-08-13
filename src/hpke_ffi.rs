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

// C-compatible response structs
#[repr(C)]
pub struct CSecretKeyResult {
    pub success: c_int,
    pub secret_key: [u8; 32],
    pub error: *mut c_char,
}

#[repr(C)]
pub struct CPublicKeyResult {
    pub success: c_int,
    pub public_key: [u8; 32],
    pub error: *mut c_char,
}

#[repr(C)]
pub struct CSealResult {
    pub success: c_int,
    pub sealed: *mut c_char,
    pub error: *mut c_char,
}

#[repr(C)]
pub struct COpenResult {
    pub success: c_int,
    pub message: *mut c_char,
    pub error: *mut c_char,
}

#[repr(C)]
pub struct CSignResult {
    pub success: c_int,
    pub signature: *mut c_char,
    pub error: *mut c_char,
}

#[repr(C)]
pub struct CVerifyResult {
    pub success: c_int,
    pub valid: c_int,
    pub error: *mut c_char,
}

// String conversion utilities for FFI
pub(crate) fn string_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

pub(crate) unsafe fn c_str_to_string(ptr: *const c_char) -> Result<String, Box<dyn std::error::Error>> {
    if ptr.is_null() {
        return Err("Null pointer".into());
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    Ok(c_str.to_str()?.to_string())
}



// Free string allocated by Rust
#[unsafe(no_mangle)]
pub extern "C" fn rust_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// Generate a new secret key and return as a byte array in C struct.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_generate() -> CSecretKeyResult {
    let secret_key = SecretKey::generate();
    CSecretKeyResult {
        success: 1,
        secret_key: secret_key.to_bytes(),
        error: ptr::null_mut(),
    }
}

// Generate public key from secret key and return as a byte array in C struct.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_publickey(secret_key: *const [u8; 32]) -> CPublicKeyResult {
    if secret_key.is_null() {
        return CPublicKeyResult {
            success: 0,
            public_key: [0u8; 32],
            error: string_to_c_char("Null secret key pointer".to_string()),
        };
    }

    let secret_key_bytes = unsafe { *secret_key };
    let secret_key = SecretKey::from_bytes(&secret_key_bytes);
    let public_key = secret_key.public_key();

    CPublicKeyResult {
        success: 1,
        public_key: public_key.to_bytes(),
        error: ptr::null_mut(),
    }
}

// Seal a message (encrypt + authenticate)
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_seal(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    msg_to_seal: *const c_char,
    msg_to_auth: *const c_char,
) -> CSealResult {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() || remote_public_key.is_null() {
            return Err("Null key pointer".into());
        }

        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Decode the cryptographic messages
        let domain_str = unsafe { c_str_to_string(domain)? };

        let msg_to_seal_hex = unsafe { c_str_to_string(msg_to_seal)? };
        let msg_to_auth_hex = unsafe { c_str_to_string(msg_to_auth)? };

        let msg_to_seal_bytes = hex::decode(&msg_to_seal_hex)?;
        let msg_to_auth_bytes = hex::decode(&msg_to_auth_hex)?;

        // Create context and seal
        let context = Context::new(local, remote, &domain_str);
        let sealed = context.seal(&msg_to_seal_bytes, &msg_to_auth_bytes)?;

        Ok(hex::encode(&sealed))
    })();

    match result {
        Ok(sealed) => CSealResult {
            success: 1,
            sealed: string_to_c_char(sealed),
            error: ptr::null_mut(),
        },
        Err(e) => CSealResult {
            success: 0,
            sealed: ptr::null_mut(),
            error: string_to_c_char(e.to_string()),
        },
    }
}

// Open a sealed message (decrypt + verify)
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_open(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    msg_to_open: *const c_char,
    msg_to_auth: *const c_char,
) -> COpenResult {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() || remote_public_key.is_null() {
            return Err("Null key pointer".into());
        }

        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Decode the cryptographic messages
        let domain_str = unsafe { c_str_to_string(domain)? };
        let msg_to_open_hex = unsafe { c_str_to_string(msg_to_open)? };
        let msg_to_auth_hex = unsafe { c_str_to_string(msg_to_auth)? };

        let msg_to_open_bytes = hex::decode(&msg_to_open_hex)?;
        let msg_to_auth_bytes = hex::decode(&msg_to_auth_hex)?;

        // Create context and open
        let context = Context::new(local, remote, &domain_str);
        let opened = context.open(&msg_to_open_bytes, &msg_to_auth_bytes)?;

        Ok(hex::encode(&opened))
    })();

    match result {
        Ok(message) => COpenResult {
            success: 1,
            message: string_to_c_char(message),
            error: ptr::null_mut(),
        },
        Err(e) => COpenResult {
            success: 0,
            message: ptr::null_mut(),
            error: string_to_c_char(e.to_string()),
        },
    }
}

// Sign a message
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_sign(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    message: *const c_char,
) -> CSignResult {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() || remote_public_key.is_null() {
            return Err("Null key pointer".into());
        }

        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Decode the cryptographic messages
        let domain_str = unsafe { c_str_to_string(domain)? };
        let message_hex = unsafe { c_str_to_string(message)? };
        let message_bytes = hex::decode(&message_hex)?;

        // Create context and sign
        let context = Context::new(local, remote, &domain_str);
        let signature = context.sign(&message_bytes)?;

        Ok(hex::encode(&signature))
    })();

    match result {
        Ok(signature) => CSignResult {
            success: 1,
            signature: string_to_c_char(signature),
            error: ptr::null_mut(),
        },
        Err(e) => CSignResult {
            success: 0,
            signature: ptr::null_mut(),
            error: string_to_c_char(e.to_string()),
        },
    }
}

// Verify a signature
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_verify(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    message: *const c_char,
    signature: *const c_char,
) -> CVerifyResult {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() || remote_public_key.is_null() {
            return Err("Null key pointer".into());
        }

        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Decode the cryptographic messages
        let domain_str = unsafe { c_str_to_string(domain)? };
        let msg_hex = unsafe { c_str_to_string(message)? };
        let sig_hex = unsafe { c_str_to_string(signature)? };

        let msg_bytes = hex::decode(&msg_hex)?;
        let sig_bytes = hex::decode(&sig_hex)?;

        // Create context and verify
        let context = Context::new(local, remote, &domain_str);
        context.verify(&msg_bytes, &sig_bytes)?;

        Ok(())
    })();

    // Special handling for verify - return false on error instead of error message
    match result {
        Ok(()) => CVerifyResult {
            success: 1,
            valid: 1,
            error: ptr::null_mut(),
        },
        Err(_) => CVerifyResult {
            success: 1,
            valid: 0,
            error: ptr::null_mut(),
        },
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;

    #[test]
    fn test_ffi_seal_open() {
        // Generate secret keys for Alice and Bob
        let alice_secret_result = rust_hpke_generate();
        let bob_secret_result = rust_hpke_generate();

        assert_eq!(alice_secret_result.success, 1);
        assert_eq!(bob_secret_result.success, 1);

        // Get secret keys as byte arrays
        let alice_secret_key = alice_secret_result.secret_key;
        let bob_secret_key = bob_secret_result.secret_key;

        // Generate public keys from secret keys
        let alice_public_result = rust_hpke_publickey(&alice_secret_key);
        let bob_public_result = rust_hpke_publickey(&bob_secret_key);

        assert_eq!(alice_public_result.success, 1);
        assert_eq!(bob_public_result.success, 1);

        let alice_public_key = alice_public_result.public_key;
        let bob_public_key = bob_public_result.public_key;

        let domain = "test";

        // Test case structure
        struct TestCase<'a> {
            seal_msg: &'a str,
            auth_msg: &'a str,
        }

        let tests = [
            // Only message to authenticate
            TestCase {
                seal_msg: "", // Empty message hex-encoded
                auth_msg: &hex::encode("message to authenticate"),
            },
            // Only message to encrypt
            TestCase {
                seal_msg: &hex::encode("message to encrypt"),
                auth_msg: "", // Empty message hex-encoded
            },
            // Both message to authenticate and to encrypt
            TestCase {
                seal_msg: &hex::encode("message to encrypt"),
                auth_msg: &hex::encode("message to authenticate"),
            },
        ];

        for test_case in &tests {
            // Alice seals a message for Bob
            let sealed_result = rust_hpke_seal(
                &alice_secret_key,
                &bob_public_key,
                CString::new(domain).unwrap().as_ptr(),
                CString::new(test_case.seal_msg).unwrap().as_ptr(),
                CString::new(test_case.auth_msg).unwrap().as_ptr(),
            );

            assert_eq!(sealed_result.success, 1);
            let sealed_data = unsafe { CStr::from_ptr(sealed_result.sealed).to_str().unwrap() };

            // Bob opens the sealed message
            let opened_result = rust_hpke_open(
                &bob_secret_key,
                &alice_public_key,
                CString::new(domain).unwrap().as_ptr(),
                CString::new(sealed_data).unwrap().as_ptr(),
                CString::new(test_case.auth_msg).unwrap().as_ptr(),
            );

            assert_eq!(opened_result.success, 1);
            let opened_message = unsafe { CStr::from_ptr(opened_result.message).to_str().unwrap() };

            // Verify the opened message matches (decode hex to compare with original)
            assert_eq!(opened_message, test_case.seal_msg);
        }
    }

    #[test]
    fn test_ffi_sign_verify() {
        // Generate secret keys for Alice and Bob
        let alice_secret_result = rust_hpke_generate();
        let bob_secret_result = rust_hpke_generate();

        assert_eq!(alice_secret_result.success, 1);
        assert_eq!(bob_secret_result.success, 1);

        // Get secret keys as byte arrays
        let alice_secret_key = alice_secret_result.secret_key;
        let bob_secret_key = bob_secret_result.secret_key;

        // Generate public keys from secret keys
        let alice_public_result = rust_hpke_publickey(&alice_secret_key);
        let bob_public_result = rust_hpke_publickey(&bob_secret_key);

        assert_eq!(alice_public_result.success, 1);
        assert_eq!(bob_public_result.success, 1);

        let alice_public_key = alice_public_result.public_key;
        let bob_public_key = bob_public_result.public_key;

        let domain = "test";
        let message = &hex::encode("message to sign");

        // Alice signs a message for Bob
        let signature_result = rust_hpke_sign(
            &alice_secret_key,
            &bob_public_key,
            CString::new(domain).unwrap().as_ptr(),
            CString::new(message.as_str()).unwrap().as_ptr(),
        );

        assert_eq!(signature_result.success, 1);
        let signature = unsafe { CStr::from_ptr(signature_result.signature).to_str().unwrap() };

        // Bob verifies the signature
        let verify_result = rust_hpke_verify(
            &bob_secret_key,
            &alice_public_key,
            CString::new(domain).unwrap().as_ptr(),
            CString::new(message.as_str()).unwrap().as_ptr(),
            CString::new(signature).unwrap().as_ptr(),
        );

        assert_eq!(verify_result.success, 1);
        assert_eq!(verify_result.valid, 1);
    }
}
