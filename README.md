# Rust Cryptography Wrappers

[![](https://img.shields.io/crates/v/darkbio-crypto.svg)](https://crates.io/crates/darkbio-crypto)
[![](https://docs.rs/darkbio-crypto/badge.svg)](https://docs.rs/darkbio-crypto)
[![](https://github.com/dark-bio/crypto-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/crypto-rs/actions/workflows/ci.yml)

This repository is parameter selection and lightweight wrapper around a number of Rust cryptographic libraries. Its purpose isn't to implement primitives, rather to unify the API surface of existing libraries; limited to the tiny subset needed by the Dark Bio project.

- Digital signatures
  - **CDSA ([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs))**: `ML-DSA-65`, `Ed25519`, `SHA512`
    - **EdDSA ([RFC-8032](https://datatracker.ietf.org/doc/html/rfc8032))**: `Ed25519`
    - **MLDSA ([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates))**: Security level 3 (`ML-DSA-65`)
  - **RSA ([RFC-8017](https://datatracker.ietf.org/doc/html/rfc8017))**: 2048-bit, `SHA256`
- Encryption
  - **HPKE ([RFC-9180](https://datatracker.ietf.org/doc/html/rfc9180))**: `X25519`, `HKDF`, `SH256`, `ChaCha20`, `Poly1305`, `dark-bio-v1:` prefix
  - **STREAM (*RFC N/A*)**: `ChaCha20`, `Poly1305`, `16B` tag, `64KB` chunk
- Key derivation
  - **Argon2 ([RFC-9106](https://datatracker.ietf.org/doc/html/rfc9106))**: `id` variant
- Serialization
  - **CBOR ([RFC-8949](https://datatracker.ietf.org/doc/html/rfc8949))**: restricted to `integer`, `text`, `bytes`, `array`

All functionality is WASM ready.

*The entire library is hidden behind feature flags to allow selectively depending on it from the firmware, cloud and mobile app, each cherry-picking only what's needed. Please consult the docs on how to enable them.*
