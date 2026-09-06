// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Strict PEM encoding and decoding.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

const PEM_HEADER: &[u8] = b"-----BEGIN ";
const PEM_FOOTER: &[u8] = b"-----END ";
const PEM_ENDING: &[u8] = b"-----";

/// Error is the failures that can occur during PEM operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("missing PEM header")]
    MissingHeader,
    #[error("malformed PEM header: {0}")]
    MalformedHeader(String),
    #[error("empty PEM block type")]
    EmptyBlockType,
    #[error("malformed PEM block type")]
    MalformedBlockType,
    #[error("missing PEM footer")]
    MissingFooter,
    #[error("trailing data after PEM block")]
    TrailingData,
    #[error("malformed PEM body: {0}")]
    MalformedBody(String),
    #[error("malformed base64 payload: {0}")]
    MalformedPayload(String),
}

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
/// Returns (kind, data) tuple on success, with the data wiped on drop.
pub fn decode(data: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
    // Must start with header immediately (no leading whitespace)
    if !data.starts_with(PEM_HEADER) {
        return Err(Error::MissingHeader);
    }
    // Find the end of header line (first \n)
    let header_end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::MalformedHeader("incomplete header line".into()))?;

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
        return Err(Error::MalformedHeader("unterminated block type".into()));
    }
    let block_type = &header[PEM_HEADER.len()..header.len() - PEM_ENDING.len()];
    if block_type.is_empty() {
        return Err(Error::EmptyBlockType);
    }
    let kind = String::from_utf8(block_type.to_vec()).map_err(|_| Error::MalformedBlockType)?;

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
        .ok_or(Error::MissingFooter)?;
    let footer_start = header_end + 1 + footer_idx;
    let footer_end = footer_start + footer.len();

    // Validate what comes after footer: nothing or same line ending
    let rest = &data[footer_end..];
    if !rest.is_empty() && rest != line_ending {
        return Err(Error::TrailingData);
    }

    // Extract body (between header and footer)
    let body = &data[header_end + 1..footer_start];

    // Body must end with the line ending (the line before footer)
    if body.is_empty() {
        return Err(Error::MalformedBody("empty body".into()));
    }
    if !body.ends_with(line_ending) {
        return Err(Error::MalformedBody("missing newline before footer".into()));
    }
    let body = &body[..body.len() - line_ending.len()];

    // Reserve the full body length so stripping line endings cannot reallocate
    // and leave unwiped copies of the encoded secret behind.
    let mut b64 = Zeroizing::new(Vec::with_capacity(body.len()));
    for line in body.split(|&b| b == b'\n') {
        b64.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
    }

    // Guard the destination before decoding so partial output is wiped on error.
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(&b64, &mut decoded)
        .map_err(|err| Error::MalformedPayload(err.to_string()))?;

    Ok((kind, decoded))
}

/// Encodes data as a PEM block with the given type.
/// Lines are 64 characters, using \n line endings.
pub fn encode(kind: &str, data: &[u8]) -> String {
    let b64 = Zeroizing::new(STANDARD.encode(data));

    // Size the output up front so appending never leaves stale copies behind
    let lines = b64.len().div_ceil(64);
    let mut buf = String::with_capacity(
        PEM_HEADER.len()
            + PEM_FOOTER.len()
            + 2 * (kind.len() + PEM_ENDING.len() + 1)
            + b64.len()
            + lines,
    );
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
