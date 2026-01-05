// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Strict PEM encoding and decoding.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::error::Error;

const PEM_HEADER: &[u8] = b"-----BEGIN ";
const PEM_FOOTER: &[u8] = b"-----END ";
const PEM_ENDING: &[u8] = b"-----";

/// Decodes a single PEM block with strict validation.
///
/// Rules:
///   - Header must start at byte 0 (no leading whitespace)
///   - Footer must end the data (only optional line ending after)
///   - Line endings must be consistent (\n or \r\n throughout)
///   - Base64 lines contain only base64 characters
///   - Strict base64 decoding (no padding errors, etc.)
///   - No trailing data after the PEM block
///
/// Returns (kind, data) tuple on success.
pub fn decode(data: &[u8]) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    // Must start with header immediately (no leading whitespace)
    if !data.starts_with(PEM_HEADER) {
        return Err("pem: missing PEM header".into());
    }
    // Find the end of header line (first \n)
    let header_end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("pem: incomplete PEM header")?;

    // Detect line ending style from first line
    let line_ending: &[u8] = if header_end > 0 && data[header_end - 1] == b'\r' {
        b"\r\n"
    } else {
        b"\n"
    };

    // Extract header (without line ending)
    let header = if line_ending.len() == 2 {
        &data[..header_end - 1]
    } else {
        &data[..header_end]
    };

    // Parse the block type from the header
    if !header.starts_with(PEM_HEADER) || !header.ends_with(PEM_ENDING) {
        return Err("pem: malformed PEM header".into());
    }
    let block_type = &header[PEM_HEADER.len()..header.len() - PEM_ENDING.len()];
    if block_type.is_empty() {
        return Err("pem: empty PEM block type".into());
    }
    let kind = String::from_utf8(block_type.to_vec())?;

    // Build expected footer
    let mut footer = Vec::with_capacity(PEM_FOOTER.len() + block_type.len() + PEM_ENDING.len());
    footer.extend_from_slice(PEM_FOOTER);
    footer.extend_from_slice(block_type);
    footer.extend_from_slice(PEM_ENDING);

    // Find the footer
    let search_area = &data[header_end + 1..];
    let footer_idx = search_area
        .windows(footer.len())
        .position(|w| w == footer.as_slice())
        .ok_or("pem: missing PEM footer")?;
    let footer_start = header_end + 1 + footer_idx;
    let footer_end = footer_start + footer.len();

    // Validate what comes after footer: nothing or same line ending
    let rest = &data[footer_end..];
    if !rest.is_empty() && rest != line_ending {
        return Err("pem: trailing data after PEM block".into());
    }

    // Extract body (between header and footer)
    let body = &data[header_end + 1..footer_start];

    // Body must end with the line ending (the line before footer)
    if body.is_empty() {
        return Err("pem: empty PEM body".into());
    }
    if !body.ends_with(line_ending) {
        return Err("pem: body must end with newline before footer".into());
    }
    let body = &body[..body.len() - line_ending.len()];

    // Strip line endings and decode
    let b64: Vec<u8> = body
        .split(|&b| b == b'\n')
        .flat_map(|line| {
            if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            }
        })
        .copied()
        .collect();

    let decoded = STANDARD.decode(&b64)?;

    Ok((kind, decoded))
}

/// Encodes data as a PEM block with the given type.
/// Lines are 64 characters, using \n line endings.
pub fn encode(kind: &str, data: &[u8]) -> String {
    let b64 = STANDARD.encode(data);

    let mut buf = String::new();
    buf.push_str("-----BEGIN ");
    buf.push_str(kind);
    buf.push_str("-----\n");

    for chunk in b64.as_bytes().chunks(64) {
        buf.push_str(std::str::from_utf8(chunk).unwrap());
        buf.push('\n');
    }

    buf.push_str("-----END ");
    buf.push_str(kind);
    buf.push_str("-----\n");

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"hello world";
        let encoded = encode("TEST", data);
        let (kind, decoded) = decode(encoded.as_bytes()).unwrap();
        assert_eq!(kind, "TEST");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_valid_lf() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n";
        let (kind, data) = decode(pem).unwrap();
        assert_eq!(kind, "PRIVATE KEY");
        assert_eq!(data, b"abc");
    }

    #[test]
    fn test_decode_valid_crlf() {
        let pem = b"-----BEGIN PRIVATE KEY-----\r\nYWJj\r\n-----END PRIVATE KEY-----\r\n";
        let (kind, data) = decode(pem).unwrap();
        assert_eq!(kind, "PRIVATE KEY");
        assert_eq!(data, b"abc");
    }

    #[test]
    fn test_decode_no_trailing_newline() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----";
        let (kind, data) = decode(pem).unwrap();
        assert_eq!(kind, "PRIVATE KEY");
        assert_eq!(data, b"abc");
    }

    #[test]
    fn test_decode_missing_header() {
        let pem = b"YWJj\n-----END PRIVATE KEY-----\n";
        assert!(decode(pem).is_err());
    }

    #[test]
    fn test_decode_missing_footer() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nYWJj\n";
        assert!(decode(pem).is_err());
    }

    #[test]
    fn test_decode_trailing_data() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\nextra";
        assert!(decode(pem).is_err());
    }

    #[test]
    fn test_decode_empty_body() {
        let pem = b"-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----\n";
        assert!(decode(pem).is_err());
    }

    #[test]
    fn test_decode_leading_whitespace() {
        let pem = b" -----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n";
        assert!(decode(pem).is_err());
    }

    #[test]
    fn test_decode_invalid_base64() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
        assert!(decode(pem).is_err());
    }
}
