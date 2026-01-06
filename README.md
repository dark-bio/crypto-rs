# Rust Cryptography Wrappers

[![](https://img.shields.io/crates/v/darkbio-crypto.svg)](https://crates.io/crates/darkbio-crypto)
[![](https://docs.rs/darkbio-crypto/badge.svg)](https://docs.rs/darkbio-crypto)
[![](https://github.com/dark-bio/crypto-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/crypto-rs/actions/workflows/ci.yml)

This repository is parameter selection and lightweight wrapper around a number of Rust cryptographic libraries. Its purpose isn't to implement primitives, rather to unify the API surface of existing libraries; limited to the tiny subset needed by the Dark Bio project.

![](./docs/overview.png)

- Certificates
  - **x509 ([RFC-5280](https://datatracker.ietf.org/doc/html/rfc5280))**: `xDSA`, `xHPKE`
- Digital signatures
  - **xDSA ([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs))**: `MLDSA`, `EdDSA`, `SHA512`
    - **EdDSA ([RFC-8032](https://datatracker.ietf.org/doc/html/rfc8032))**: `Ed25519`
    - **MLDSA ([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates))**: Security level 3 (`ML-DSA-65`)
  - **RSA ([RFC-8017](https://datatracker.ietf.org/doc/html/rfc8017))**: 2048-bit, `SHA256`
- Encryption
  - **xHPKE ([RFC-9180](https://datatracker.ietf.org/doc/html/rfc9180))**: `X-WING`, `HKDF`, `SHA256`, `ChaCha20`, `Poly1305`, `dark-bio-v1:` prefix
    - **X-WING ([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem))**: `MLKEM`, `ECC`
      - **ECC ([RFC-7748](https://datatracker.ietf.org/doc/html/rfc7748))**: `X25519`
      - **MLKEM([RFC-DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-ikev2-mlkem))**: Security level 3 (`ML-KEM-768`)
  - **STREAM (*RFC N/A*, [Rage](https://github.com/str4d/rage))**: `ChaCha20`, `Poly1305`, `16B` tag, `64KB` chunk
- Key derivation
  - **Argon2 ([RFC-9106](https://datatracker.ietf.org/doc/html/rfc9106))**: `id` variant
  - **HKDF ([RFC-5869](https://datatracker.ietf.org/doc/html/rfc5869))**: `SHA256`
- Serialization
  - **CBOR ([RFC-8949](https://datatracker.ietf.org/doc/html/rfc8949))**: restricted to `integer`, `text`, `bytes`, `array`, `map[int]`
  - **COSE ([RFC-8152](https://datatracker.ietf.org/doc/html/rfc8152))**: `COSE_Sign1`, `COSE_Encrypt0`

All functionality is WASM ready.

*The entire library is hidden behind feature flags to allow selectively depending on it from the firmware, cloud and mobile app, each cherry-picking only what's needed. Please consult the docs on how to enable them.*

## Siblings

This is a sibling package with the Go [`github.com/dark-bio/crypto-go`](https://github.com/dark-bio/crypto-go); as in, both repositories implement the same feature sets and API surfaces at the same version points. This naturally means PRs merged into one project necessarily have to have a counter-PR in the other project.
