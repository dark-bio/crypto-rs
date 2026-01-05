// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! PEM parsing with strict format validation.

use std::error::Error;

/// Parses a PEM string with strict format validation matching Go's encoding/pem:
/// requires BEGIN/END markers to be on their own lines. The implementation is a
/// bit brute force, but it's only used internally, so it's fine.
pub fn parse(input: &str) -> Result<pem::Pem, Box<dyn Error>> {
    // Ignore leading or trailing whitespace
    let input = input.trim();

    // Check BEGIN marker is on its own line (handle both Unix and Windows line endings)
    if !input.starts_with("-----BEGIN PRIVATE KEY-----\n")
        && !input.starts_with("-----BEGIN PRIVATE KEY-----\r\n")
        && !input.starts_with("-----BEGIN PUBLIC KEY-----\n")
        && !input.starts_with("-----BEGIN PUBLIC KEY-----\r\n")
    {
        return Err("invalid PEM: BEGIN marker must be on its own line".into());
    }
    // Check END marker is on its own line (handle both Unix and Windows line endings)
    if !input.ends_with("\n-----END PRIVATE KEY-----")
        && !input.ends_with("\r\n-----END PRIVATE KEY-----")
        && !input.ends_with("\n-----END PUBLIC KEY-----")
        && !input.ends_with("\r\n-----END PUBLIC KEY-----")
    {
        return Err("invalid PEM: END marker must be on its own line".into());
    }
    // Remove whitespace-only lines from base64
    // TODO(karalabe): delete after https://github.com/jcreekmore/pem-rs/issues/61
    let normalized: String = input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(pem::parse(normalized.as_bytes())?)
}
