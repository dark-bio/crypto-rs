// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Strict PEM encoding and decoding.
//!
//! <https://datatracker.ietf.org/doc/html/rfc7468>
//!
//! Accepts one block per input, no leading whitespace, consistent LF or CRLF
//! line endings, and strict base64. Only an optional matching newline may
//! follow the footer; see [`decode`] for the full rule set. Decoded payloads
//! are wiped on drop because PEM blocks typically carry private keys.
//!
//! ```
//! use darkbio_crypto::pem;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let encoded = pem::encode("EXAMPLE", b"hello");
//! assert!(encoded.starts_with("-----BEGIN EXAMPLE-----\n"));
//!
//! let (kind, data) = pem::decode(encoded.as_bytes())?;
//! assert_eq!(kind, "EXAMPLE");
//! assert_eq!(*data, b"hello");
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

/// Opening prefix of a PEM header line.
const PEM_HEADER: &[u8] = b"-----BEGIN ";
/// Opening prefix of a PEM footer line.
const PEM_FOOTER: &[u8] = b"-----END ";
/// Closing suffix of a PEM header or footer line.
const PEM_ENDING: &[u8] = b"-----";

/// Failures returned by [`decode`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input does not start with `-----BEGIN `; leading whitespace counts as
    /// missing.
    #[error("missing PEM header")]
    MissingHeader,
    /// First line is not a complete `-----BEGIN TYPE-----` header.
    #[error("malformed PEM header: {0}")]
    MalformedHeader(String),
    /// Header specifies an empty block type.
    #[error("empty PEM block type")]
    EmptyBlockType,
    /// Block type contains invalid characters or spacing.
    #[error("malformed PEM block type")]
    MalformedBlockType,
    /// No `-----END TYPE-----` footer matches the header's block type.
    #[error("missing PEM footer")]
    MissingFooter,
    /// Unexpected bytes follow the footer beyond an optional matching newline.
    #[error("trailing data after PEM block")]
    TrailingData,
    /// Body between header and footer is empty, contains a blank line, or lacks
    /// a line ending before the footer.
    #[error("malformed PEM body: {0}")]
    MalformedBody(String),
    /// Body is not valid strict base64, or a line uses a different line ending
    /// from the header.
    #[error("malformed base64 payload: {0}")]
    MalformedPayload(String),
}

/// Reports whether `kind` is a valid PEM block label.
///
/// A label is non-empty and consists of printable ASCII bytes other than
/// hyphens, with single spaces allowed between words.
fn valid_label(kind: &str) -> bool {
    kind.split(' ')
        .all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_graphic() && b != b'-'))
}

/// Decodes a single PEM block with strict validation, returning `(kind, data)`
/// with `data` wiped on drop.
///
/// Validation rules:
///
/// - Header starts at byte 0 with no leading whitespace.
/// - Label contains printable ASCII other than hyphens, with single spaces
///   allowed between words.
/// - Footer ends the input, apart from an optional newline matching the
///   header's LF or CRLF.
/// - Every line ends with the header's line ending, LF or CRLF throughout.
/// - Base64 lines are non-empty, use strict padding, and contain only base64
///   characters.
/// - Payload is non-empty.
pub fn decode(data: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
    // Reject inputs without an immediate header (no leading whitespace)
    if !data.starts_with(PEM_HEADER) {
        return Err(Error::MissingHeader);
    }
    // Locate the end of the header line
    let header_end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::MalformedHeader("incomplete header line".into()))?;

    // Detect line ending style from the first line
    let line_ending: &[u8] = if header_end > 0 && data[header_end - 1] == b'\r' {
        b"\r\n"
    } else {
        b"\n"
    };

    // Strip the line ending from the header
    let header = if line_ending.len() == 2 {
        &data[..header_end - 1]
    } else {
        &data[..header_end]
    };

    // Parse and validate the block label from the header
    if !header.starts_with(PEM_HEADER) || !header.ends_with(PEM_ENDING) {
        return Err(Error::MalformedHeader("unterminated block type".into()));
    }
    let block_type = &header[PEM_HEADER.len()..header.len() - PEM_ENDING.len()];
    if block_type.is_empty() {
        return Err(Error::EmptyBlockType);
    }
    let kind = String::from_utf8(block_type.to_vec()).map_err(|_| Error::MalformedBlockType)?;
    if !valid_label(&kind) {
        return Err(Error::MalformedBlockType);
    }

    // Build and locate the matching footer
    let mut footer = Vec::with_capacity(PEM_FOOTER.len() + block_type.len() + PEM_ENDING.len());
    footer.extend_from_slice(PEM_FOOTER);
    footer.extend_from_slice(block_type);
    footer.extend_from_slice(PEM_ENDING);

    let search_area = &data[header_end + 1..];
    let footer_idx = search_area
        .windows(footer.len())
        .position(|w| w == footer.as_slice())
        .ok_or(Error::MissingFooter)?;
    let footer_start = header_end + 1 + footer_idx;
    let footer_end = footer_start + footer.len();

    // Allow only EOF or a single matching line ending after the footer
    let rest = &data[footer_end..];
    if !rest.is_empty() && rest != line_ending {
        return Err(Error::TrailingData);
    }

    // Extract the body and require a line ending before the footer
    let body = &data[header_end + 1..footer_start];
    if body.is_empty() {
        return Err(Error::MalformedBody("empty body".into()));
    }
    if !body.ends_with(line_ending) {
        return Err(Error::MalformedBody("missing newline before footer".into()));
    }
    let body = &body[..body.len() - line_ending.len()];

    // Reserve the full body length so stripping line endings never reallocates
    // and leaves unwiped copies of the encoded secret behind
    let mut b64 = Zeroizing::new(Vec::with_capacity(body.len()));

    // Verify every line uses the header's line ending and reject blank lines
    let mut lines = body.split(|&b| b == b'\n').peekable();
    while let Some(mut line) = lines.next() {
        if line_ending.len() == 2 && lines.peek().is_some() {
            line = line
                .strip_suffix(b"\r")
                .ok_or_else(|| Error::MalformedPayload("stray line endings".into()))?;
        }
        if line.contains(&b'\r') {
            return Err(Error::MalformedPayload("stray line endings".into()));
        }
        if line.is_empty() {
            return Err(Error::MalformedBody("blank line".into()));
        }
        b64.extend_from_slice(line);
    }

    // Guard the output buffer before decoding so partial bytes are wiped on error
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(&b64, &mut decoded)
        .map_err(|err| Error::MalformedPayload(err.to_string()))?;

    Ok((kind, decoded))
}

/// Encodes `data` as a PEM block with label `kind`, wrapping base64 lines at
/// 64 characters with `\n` line endings.
///
/// # Panics
///
/// Panics if `data` is empty or `kind` is not a valid PEM block label.
pub fn encode(kind: &str, data: &[u8]) -> String {
    assert!(!data.is_empty(), "empty PEM payload");
    assert!(valid_label(kind), "invalid PEM block label");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that blank lines anywhere inside the base64 body are rejected.
    #[test]
    fn test_blank_body_lines() {
        for newline in ["\n", "\r\n"] {
            for lines in [["", "YW", "Jj"], ["YW", "", "Jj"], ["YW", "Jj", ""]] {
                let body = lines.join(newline);
                let pem = format!("-----BEGIN TEST-----{newline}{body}{newline}-----END TEST-----");
                assert_eq!(
                    decode(pem.as_bytes()),
                    Err(Error::MalformedBody("blank line".into()))
                );
            }
        }
    }

    /// Tests that invalid PEM block labels are rejected by both `decode` and
    /// `encode`, while valid printable ASCII labels round-trip cleanly.
    #[test]
    fn test_block_labels() {
        let invalid = [
            ("", Error::EmptyBlockType),
            (" A", Error::MalformedBlockType),
            ("A ", Error::MalformedBlockType),
            ("A  B", Error::MalformedBlockType),
            ("A-B", Error::MalformedBlockType),
            ("A\rB", Error::MalformedBlockType),
            ("A\tB", Error::MalformedBlockType),
            ("A\0B", Error::MalformedBlockType),
            ("\x7f", Error::MalformedBlockType),
            ("é", Error::MalformedBlockType),
        ];
        for (kind, want) in invalid {
            let pem = format!("-----BEGIN {kind}-----\nYQ==\n-----END {kind}-----\n");
            assert_eq!(decode(pem.as_bytes()), Err(want), "{kind:?}");

            // Check that encoding rejects the same labels on native targets
            #[cfg(not(target_arch = "wasm32"))]
            {
                let err = std::panic::catch_unwind(|| encode(kind, b"a")).expect_err(kind);
                let msg = err
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| err.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("");
                assert!(msg.contains("invalid PEM block label"), "{kind:?}: {msg}");
            }
        }
        let kind = "!A #~";
        assert_eq!(decode(encode(kind, b"a").as_bytes()).unwrap().0, kind);
    }

    /// Tests that a body without any base64 text is rejected, whether it has no
    /// lines or only blank ones.
    #[test]
    fn test_decode_empty_payload() {
        let tests = [
            (
                "no body",
                "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
            ),
            (
                "blank line",
                "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n",
            ),
            (
                "blank crlf line",
                "-----BEGIN PUBLIC KEY-----\r\n\r\n-----END PUBLIC KEY-----\r\n",
            ),
            (
                "two blank lines",
                "-----BEGIN PUBLIC KEY-----\n\n\n-----END PUBLIC KEY-----\n",
            ),
        ];
        for (name, input) in tests {
            assert!(
                matches!(decode(input.as_bytes()), Err(Error::MalformedBody(_))),
                "{name}"
            );
        }
    }

    /// Tests that encoding an empty payload panics, since decoding rejects it.
    #[test]
    #[should_panic]
    fn test_encode_empty_payload() {
        encode("PUBLIC KEY", &[]);
    }

    /// Tests that payloads around the 64-character line length survive encoding
    /// and decoding unchanged.
    #[test]
    fn test_round_trip() {
        for size in [1, 47, 48, 49, 96, 97] {
            let payload = vec![0xa5; size];
            let (kind, decoded) = decode(encode("PUBLIC KEY", &payload).as_bytes()).unwrap();
            assert_eq!(kind, "PUBLIC KEY", "{size}");
            assert_eq!(decoded.as_slice(), payload.as_slice(), "{size}");
        }
    }
}
