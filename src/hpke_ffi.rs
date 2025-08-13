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

/// Result structure for secret key generation operations.
///
/// Contains either a successfully generated 32-byte secret key or an error message.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CSecretKeyResult {
    pub success: c_int,
    pub secret_key: [u8; 32],
    pub error: *mut c_char,
}

/// Result structure for public key derivation operations.
///
/// Contains either a successfully derived 32-byte public key or an error message.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CPublicKeyResult {
    pub success: c_int,
    pub public_key: [u8; 32],
    pub error: *mut c_char,
}

/// Result structure for message sealing (encryption + authentication) operations.
///
/// Contains either successfully sealed data or an error message.
/// The `sealed` pointer must be freed with `rust_free_bytes` if not null.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CSealResult {
    pub success: c_int,
    pub sealed: *mut u8,
    pub sealed_len: usize,
    pub error: *mut c_char,
}

/// Result structure for message opening (decryption + verification) operations.
///
/// Contains either successfully opened message data or an error message.
/// The `message` pointer must be freed with `rust_free_bytes` if not null.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct COpenResult {
    pub success: c_int,
    pub message: *mut u8,
    pub message_len: usize,
    pub error: *mut c_char,
}

/// Result structure for message signing operations.
///
/// Contains either a successfully generated signature or an error message.
/// The `signature` pointer must be freed with `rust_free_bytes` if not null.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CSignResult {
    pub success: c_int,
    pub signature: *mut u8,
    pub signature_len: usize,
    pub error: *mut c_char,
}

/// Result structure for signature verification operations.
///
/// Contains verification status and validity flag. Unlike other result structs,
/// this returns `valid: 0` for invalid signatures rather than setting an error.
/// The `error` pointer must be freed with `rust_free_string` if not null.
#[repr(C)]
pub struct CVerifyResult {
    pub success: c_int,
    pub valid: c_int,
    pub error: *mut c_char,
}

/// Converts a Rust String to a C-compatible null-terminated string pointer.
///
/// Returns a raw pointer to the C string that must be freed with `rust_free_string`.
/// Returns null pointer if the string contains null bytes.
pub(crate) fn string_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Converts a Rust Vec<u8> to a C-compatible byte array pointer.
///
/// Takes ownership of the Vec and returns a raw pointer that must be freed with `rust_free_bytes`.
/// The caller is responsible for tracking the length separately.
pub(crate) fn bytes_to_c_array(bytes: Vec<u8>) -> *mut u8 {
    let ptr = bytes.as_ptr() as *mut u8;
    std::mem::forget(bytes);
    ptr
}

/// Converts a C null-terminated string pointer to a Rust String.
///
/// The pointer must either be null or point to a valid null-terminated C string.
/// Returns an empty string if the pointer is null or if UTF-8 conversion fails.
pub(crate) unsafe fn c_char_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().unwrap_or("").to_string()
}

/// Converts a C byte array pointer to a Rust Vec<u8>.
///
/// The pointer must either be null or point to valid memory of at least `len` bytes.
/// Returns an empty vector if the pointer is null or length is zero.
pub(crate) unsafe fn c_array_to_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }
    }
}

/// Frees a C string pointer that was allocated by Rust.
///
/// The pointer must either be null or have been returned by `string_to_c_char`.
/// Calling this function with invalid pointers will cause undefined behavior.
/// Safe to call with null pointers.
#[unsafe(no_mangle)]
pub extern "C" fn rust_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Frees a byte array pointer that was allocated by Rust.
///
/// The pointer must either be null or have been returned by `bytes_to_c_array`.
/// The `len` parameter must match the original length of the allocated array.
/// Calling this function with invalid pointers or incorrect length will cause undefined behavior.
/// Safe to call with null pointers or zero length.
#[unsafe(no_mangle)]
pub extern "C" fn rust_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

/// Generates a new HPKE secret key.
///
/// Returns a `CSecretKeyResult` containing a randomly generated 32-byte secret key.
/// This function cannot fail and always returns success.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_generate() -> CSecretKeyResult {
    let secret_key = SecretKey::generate();
    CSecretKeyResult {
        success: 1,
        secret_key: secret_key.to_bytes(),
        error: ptr::null_mut(),
    }
}

/// Derives a public key from a secret key.
///
/// The `secret_key` pointer must either be null or point to a valid 32-byte array.
///
/// Returns a `CPublicKeyResult` with the derived public key on success,
/// or an error if the secret key pointer is null.
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

/// Seals a message using HPKE (encrypts and authenticates).
///
/// All pointer parameters must either be null or point to valid memory:
/// - `local_private_key` and `remote_public_key` must point to valid 32-byte arrays
/// - `domain` must point to a valid null-terminated C string
/// - `msg_to_seal` must point to valid memory of `msg_to_seal_len` bytes (can be empty)
/// - `msg_to_auth` must point to valid memory of `msg_to_auth_len` bytes (can be empty)
///
/// Returns a `CSealResult` with the sealed data on success. The sealed data pointer
/// must be freed with `rust_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_seal(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    msg_to_seal: *const u8,
    msg_to_seal_len: usize,
    msg_to_auth: *const u8,
    msg_to_auth_len: usize,
) -> CSealResult {
    let result = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() {
            return Err("Null local private key pointer".into());
        }
        if remote_public_key.is_null() {
            return Err("Null remote public key pointer".into());
        }
        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Get domain string
        let domain_str = unsafe { c_char_to_string(domain) };

        // Get message bytes directly from pointers
        let msg_to_seal_bytes = unsafe { c_array_to_bytes(msg_to_seal, msg_to_seal_len) };
        let msg_to_auth_bytes = unsafe { c_array_to_bytes(msg_to_auth, msg_to_auth_len) };

        // Create context and seal
        let context = Context::new(local, remote, &domain_str);
        let sealed = context.seal(&msg_to_seal_bytes, &msg_to_auth_bytes)?;

        Ok(sealed)
    })();

    match result {
        Ok(sealed) => {
            let sealed_len = sealed.len();
            CSealResult {
                success: 1,
                sealed: bytes_to_c_array(sealed),
                sealed_len,
                error: ptr::null_mut(),
            }
        }
        Err(e) => CSealResult {
            success: 0,
            sealed: ptr::null_mut(),
            sealed_len: 0,
            error: string_to_c_char(e.to_string()),
        },
    }
}

/// Opens a sealed message using HPKE (decrypts and verifies).
///
/// All pointer parameters must either be null or point to valid memory:
/// - `local_private_key` and `remote_public_key` must point to valid 32-byte arrays
/// - `domain` must point to a valid null-terminated C string
/// - `msg_to_open` must point to valid memory of `msg_to_open_len` bytes
/// - `msg_to_auth` must point to valid memory of `msg_to_auth_len` bytes (can be empty)
///
/// Returns a `COpenResult` with the opened message data on success. The message pointer
/// must be freed with `rust_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_open(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    msg_to_open: *const u8,
    msg_to_open_len: usize,
    msg_to_auth: *const u8,
    msg_to_auth_len: usize,
) -> COpenResult {
    let result = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() {
            return Err("Null local private key pointer".into());
        }
        if remote_public_key.is_null() {
            return Err("Null remote public key pointer".into());
        }
        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Get domain string
        let domain_str = unsafe { c_char_to_string(domain) };

        // Get message bytes directly from pointers
        let msg_to_open_bytes = unsafe { c_array_to_bytes(msg_to_open, msg_to_open_len) };
        let msg_to_auth_bytes = unsafe { c_array_to_bytes(msg_to_auth, msg_to_auth_len) };

        // Create context and open
        let context = Context::new(local, remote, &domain_str);
        let opened = context.open(&msg_to_open_bytes, &msg_to_auth_bytes)?;

        Ok(opened)
    })();

    match result {
        Ok(message) => {
            let message_len = message.len();
            COpenResult {
                success: 1,
                message: bytes_to_c_array(message),
                message_len,
                error: ptr::null_mut(),
            }
        }
        Err(e) => COpenResult {
            success: 0,
            message: ptr::null_mut(),
            message_len: 0,
            error: string_to_c_char(e.to_string()),
        },
    }
}

/// Signs a message using HPKE.
///
/// All pointer parameters must either be null or point to valid memory:
/// - `local_private_key` and `remote_public_key` must point to valid 32-byte arrays
/// - `domain` must point to a valid null-terminated C string
/// - `message` must point to valid memory of `message_len` bytes
///
/// Returns a `CSignResult` with the signature on success. The signature pointer
/// must be freed with `rust_free_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_sign(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    message: *const u8,
    message_len: usize,
) -> CSignResult {
    let result = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() {
            return Err("Null local private key pointer".into());
        }
        if remote_public_key.is_null() {
            return Err("Null remote public key pointer".into());
        }
        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Get domain string
        let domain_str = unsafe { c_char_to_string(domain) };

        // Get message bytes directly from pointer
        let message_bytes = unsafe { c_array_to_bytes(message, message_len) };

        // Create context and sign
        let context = Context::new(local, remote, &domain_str);
        let signature = context.sign(&message_bytes)?;

        Ok(signature)
    })();

    match result {
        Ok(signature) => {
            let signature_len = signature.len();
            CSignResult {
                success: 1,
                signature: bytes_to_c_array(signature),
                signature_len,
                error: ptr::null_mut(),
            }
        }
        Err(e) => CSignResult {
            success: 0,
            signature: ptr::null_mut(),
            signature_len: 0,
            error: string_to_c_char(e.to_string()),
        },
    }
}

/// Verifies a message signature using HPKE.
///
/// All pointer parameters must either be null or point to valid memory:
/// - `local_private_key` and `remote_public_key` must point to valid 32-byte arrays
/// - `domain` must point to a valid null-terminated C string
/// - `message` must point to valid memory of `message_len` bytes
/// - `signature` must point to valid memory of `signature_len` bytes
///
/// Returns a `CVerifyResult` with `valid: 1` for valid signatures and `valid: 0`
/// for invalid signatures. Both cases return `success: 1`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_hpke_verify(
    local_private_key: *const [u8; 32],
    remote_public_key: *const [u8; 32],
    domain: *const c_char,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> CVerifyResult {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Check for null pointers
        if local_private_key.is_null() {
            return Err("Null local private key pointer".into());
        }
        if remote_public_key.is_null() {
            return Err("Null remote public key pointer".into());
        }
        // Get keys directly from byte arrays
        let local_bytes = unsafe { *local_private_key };
        let remote_bytes = unsafe { *remote_public_key };

        let local = SecretKey::from_bytes(&local_bytes);
        let remote = PublicKey::from_bytes(&remote_bytes);

        // Get domain string
        let domain_str = unsafe { c_char_to_string(domain) };

        // Get message and signature bytes directly from pointers
        let msg_bytes = unsafe { c_array_to_bytes(message, message_len) };
        let sig_bytes = unsafe { c_array_to_bytes(signature, signature_len) };

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
        struct TestCase {
            seal_msg: Vec<u8>,
            auth_msg: Vec<u8>,
        }

        let tests = [
            // Only message to authenticate
            TestCase {
                seal_msg: Vec::new(), // Empty message
                auth_msg: b"message to authenticate".to_vec(),
            },
            // Only message to encrypt
            TestCase {
                seal_msg: b"message to encrypt".to_vec(),
                auth_msg: Vec::new(), // Empty message
            },
            // Both message to authenticate and to encrypt
            TestCase {
                seal_msg: b"message to encrypt".to_vec(),
                auth_msg: b"message to authenticate".to_vec(),
            },
        ];

        for test_case in &tests {
            // Alice seals a message for Bob
            let sealed_result = rust_hpke_seal(
                &alice_secret_key,
                &bob_public_key,
                CString::new(domain).unwrap().as_ptr(),
                test_case.seal_msg.as_ptr(),
                test_case.seal_msg.len(),
                test_case.auth_msg.as_ptr(),
                test_case.auth_msg.len(),
            );

            assert_eq!(sealed_result.success, 1);
            let sealed_data = unsafe {
                std::slice::from_raw_parts(sealed_result.sealed, sealed_result.sealed_len).to_vec()
            };

            // Bob opens the sealed message
            let opened_result = rust_hpke_open(
                &bob_secret_key,
                &alice_public_key,
                CString::new(domain).unwrap().as_ptr(),
                sealed_data.as_ptr(),
                sealed_data.len(),
                test_case.auth_msg.as_ptr(),
                test_case.auth_msg.len(),
            );

            assert_eq!(opened_result.success, 1);
            let opened_message = unsafe {
                std::slice::from_raw_parts(opened_result.message, opened_result.message_len)
                    .to_vec()
            };

            // Verify the opened message matches
            assert_eq!(opened_message, test_case.seal_msg);

            // Clean up allocated memory
            unsafe {
                rust_free_bytes(sealed_result.sealed, sealed_result.sealed_len);
                rust_free_bytes(opened_result.message, opened_result.message_len);
            }
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
        let message = b"message to sign".to_vec();

        // Alice signs a message for Bob
        let signature_result = rust_hpke_sign(
            &alice_secret_key,
            &bob_public_key,
            CString::new(domain).unwrap().as_ptr(),
            message.as_ptr(),
            message.len(),
        );

        assert_eq!(signature_result.success, 1);
        let signature = unsafe {
            std::slice::from_raw_parts(signature_result.signature, signature_result.signature_len)
                .to_vec()
        };

        // Bob verifies the signature
        let verify_result = rust_hpke_verify(
            &bob_secret_key,
            &alice_public_key,
            CString::new(domain).unwrap().as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(verify_result.success, 1);
        assert_eq!(verify_result.valid, 1);

        // Clean up allocated memory
        unsafe {
            rust_free_bytes(signature_result.signature, signature_result.signature_len);
        }
    }
}
