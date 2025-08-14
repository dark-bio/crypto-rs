# Rust Cryptography Wrappers

[![](https://img.shields.io/crates/v/darkbio-crypto.svg)](https://crates.io/crates/darkbio-crypto)
[![](https://docs.rs/darkbio-crypto/badge.svg)](https://docs.rs/darkbio-crypto)

This repository is parameter selection, lightweight wrapper and foreign function interface (FFI) around a number of Rust
cryptographic libraries. Its purpose isn't to implement primitives, rather to unify the API surface of existing
libraries; limited to the tiny subset needed by the Dark Bio project.

It contains the following primitives and parameters:

- **RSA** via `RSA2048`,
- **EdDSA** via `Ed25519`,
- **STREAM** via `ChaCha20` and `Poly1305` at `16B` tags and `64KiB` chunks,
- **HPKE** via `X25519`, `HKDF`, `SHA256`, `ChaCha20` and `Poly1305` at `dark-bio-v1:` info prefix.

## Feature flags

The entire library is hidden behind feature flags:

- `rsa` enables the RSA cryptography
- `hpke` enables the HPKE cryptography
- `eddsa` enables the EdDSA cryptography
- `stream` enables the STREAM cryptography

Some base features can be expanded with further flags:

- `cert` can expand `hpke` with certificate support, pulls in `eddsa`
- `ffi` can expand `hpke` and `cert` with C FFI interfacing support
