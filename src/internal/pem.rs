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

    // Check BEGIN marker is on its own line
    if !input.starts_with("-----BEGIN PRIVATE KEY-----\n")
        && !input.starts_with("-----BEGIN PUBLIC KEY-----\n")
    {
        return Err("invalid PEM: BEGIN marker must be on its own line".into());
    }
    // Check END marker is on its own line
    if !input.ends_with("\n-----END PRIVATE KEY-----")
        && !input.ends_with("\n-----END PUBLIC KEY-----")
    {
        return Err("invalid PEM: END marker must be on its own line".into());
    }
    Ok(pem::parse(input.as_bytes())?)
}
