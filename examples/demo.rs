// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Demo: Root authority, identity chain, HPKE encryption and signing.
//!
//! This example demonstrates:
//! 1. Creating a root authority (xDSA identity)
//! 2. Alice and Bob create their own xDSA identities (signed by root)
//! 3. Alice and Bob generate xHPKE identities (signed by their xDSA keys)
//! 4. Verifying identity chains through the root
//! 5. Sign and encrypt a message, then decrypt and verify on the other side

use darkbio_crypto::{cose, x509, xdsa, xhpke};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Get current time for certificate validity
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = now + 86400; // Valid for 24 hours

    // =========================================================================
    // Step 1: Create the Root Authority (self-signed xDSA identity)
    // =========================================================================
    println!("1. Creating Root Authority (xDSA)...");
    let root_secret = xdsa::SecretKey::generate();
    let root_public = root_secret.public_key();
    println!(
        "   Root fingerprint: {}",
        hex::encode(&root_public.fingerprint())
    );

    // =========================================================================
    // Step 2: Alice creates her xDSA identity, certified by the root
    // =========================================================================
    println!("\n2. Creating Alice's xDSA identity (signed by root)...");
    let alice_xdsa_secret = xdsa::SecretKey::generate();
    let alice_xdsa_public = alice_xdsa_secret.public_key();

    // Create a certificate for Alice's xDSA key, signed by the root (intermediate CA)
    let alice_xdsa_params = x509::Params {
        subject_name: "Alice Identity",
        issuer_name: "Root",
        not_before: now,
        not_after: end,
        is_ca: true,
        path_len: Some(0),
    };
    let alice_xdsa_cert = alice_xdsa_public.to_cert_pem(&root_secret, &alice_xdsa_params);
    println!(
        "   Alice xDSA fingerprint: {}",
        hex::encode(&alice_xdsa_public.fingerprint())
    );

    // =========================================================================
    // Step 3: Bob creates his xDSA identity, certified by the root
    // =========================================================================
    println!("\n3. Creating Bob's xDSA identity (signed by root)...");
    let bob_xdsa_secret = xdsa::SecretKey::generate();
    let bob_xdsa_public = bob_xdsa_secret.public_key();

    // Create a certificate for Bob's xDSA key, signed by the root (intermediate CA)
    let bob_xdsa_params = x509::Params {
        subject_name: "Bob Identity",
        issuer_name: "Root",
        not_before: now,
        not_after: end,
        is_ca: true,
        path_len: Some(0),
    };
    let bob_xdsa_cert = bob_xdsa_public.to_cert_pem(&root_secret, &bob_xdsa_params);
    println!(
        "   Bob xDSA fingerprint: {}",
        hex::encode(&bob_xdsa_public.fingerprint())
    );

    // =========================================================================
    // Step 4: Alice generates her xHPKE identity, signed by her xDSA key
    // =========================================================================
    println!("\n4. Alice generates xHPKE identity (signed by her xDSA)...");
    let alice_xhpke_secret = xhpke::SecretKey::generate();
    let alice_xhpke_public = alice_xhpke_secret.public_key();

    // Create a certificate for Alice's HPKE key, signed by her xDSA key
    let alice_xhpke_params = x509::Params {
        subject_name: "Alice Encryption",
        issuer_name: "Alice",
        not_before: now,
        not_after: end,
        is_ca: false,
        path_len: None,
    };
    let alice_xhpke_cert = alice_xhpke_public.to_cert_pem(&alice_xdsa_secret, &alice_xhpke_params);
    println!(
        "   Alice xHPKE fingerprint: {}",
        hex::encode(&alice_xhpke_public.fingerprint())
    );

    // =========================================================================
    // Step 5: Bob generates his xHPKE identity, signed by his xDSA key
    // =========================================================================
    println!("\n5. Bob generates xHPKE identity (signed by his xDSA)...");
    let bob_xhpke_secret = xhpke::SecretKey::generate();
    let bob_xhpke_public = bob_xhpke_secret.public_key();

    // Create a certificate for Bob's HPKE key, signed by his xDSA key
    let bob_xhpke_params = x509::Params {
        subject_name: "Bob Encryption",
        issuer_name: "Bob",
        not_before: now,
        not_after: end,
        is_ca: false,
        path_len: None,
    };
    let bob_xhpke_cert = bob_xhpke_public.to_cert_pem(&bob_xdsa_secret, &bob_xhpke_params);
    println!(
        "   Bob xHPKE fingerprint: {}",
        hex::encode(&bob_xhpke_public.fingerprint())
    );

    // =========================================================================
    // Step 6: Alice verifies Bob's identity chain through the root
    // =========================================================================
    println!("\n6. Alice verifies Bob's identity chain...");

    // Alice verifies Bob's xDSA certificate against the root
    let (verified_bob_xdsa, _, _) =
        xdsa::PublicKey::from_cert_pem(&bob_xdsa_cert, root_public.clone())
            .expect("Failed to verify Bob's xDSA cert against root");
    println!("   ✓ Bob's xDSA cert verified against root");

    // Alice verifies Bob's xHPKE certificate against Bob's xDSA key
    let (verified_bob_xhpke, _, _) =
        xhpke::PublicKey::from_cert_pem(&bob_xhpke_cert, verified_bob_xdsa.clone())
            .expect("Failed to verify Bob's xHPKE cert against his xDSA");
    println!("   ✓ Bob's xHPKE cert verified against his xDSA");

    // =========================================================================
    // Step 7: Bob verifies Alice's identity chain through the root
    // =========================================================================
    println!("\n7. Bob verifies Alice's identity chain...");

    // Bob verifies Alice's xDSA certificate against the root
    let (verified_alice_xdsa, _, _) =
        xdsa::PublicKey::from_cert_pem(&alice_xdsa_cert, root_public.clone())
            .expect("Failed to verify Alice's xDSA cert against root");
    println!("   ✓ Alice's xDSA cert verified against root");

    // Bob verifies Alice's xHPKE certificate against Alice's xDSA key
    let (_verified_alice_xhpke, _, _) =
        xhpke::PublicKey::from_cert_pem(&alice_xhpke_cert, verified_alice_xdsa.clone())
            .expect("Failed to verify Alice's xHPKE cert against her xDSA");
    println!("   ✓ Alice's xHPKE cert verified against her xDSA");

    // =========================================================================
    // Step 8: Alice signs and encrypts a message to Bob
    // =========================================================================
    println!("\n8. Alice sends a signed & encrypted message to Bob...");

    let message = b"Hello Bob! This is a secret message from Alice.";
    println!(
        "   Original message: {:?}",
        String::from_utf8_lossy(message)
    );

    // Alice signs and encrypts the message to Bob using cose
    let ciphertext = cose::seal(
        message,
        &[],
        &alice_xdsa_secret,
        &verified_bob_xhpke,
        b"demo-crypto-domain",
    )
    .expect("Failed to sign and encrypt message");
    println!(
        "   ✓ Message signed & encrypted to Bob ({} bytes ciphertext)",
        ciphertext.len()
    );

    // =========================================================================
    // Step 9: Bob decrypts and verifies the message from Alice
    // =========================================================================
    println!("\n9. Bob receives and verifies the message...");

    // Bob decrypts and verifies the message using cose
    let decrypted = cose::open(
        &ciphertext,
        &[],
        &bob_xhpke_secret,
        &verified_alice_xdsa,
        b"demo-crypto-domain",
    )
    .expect("Failed to decrypt and verify message");
    println!("   ✓ Message decrypted & verified");

    println!(
        "   Decrypted message: {:?}",
        String::from_utf8_lossy(&decrypted)
    );
}
