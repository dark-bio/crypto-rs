# Security policy

This crate wraps cryptographic libraries and selects their parameters. It is
the foundation of the Dark Bio ecosystem, so reports are taken seriously and
handled quickly.

## Reporting a vulnerability

Please do not open a public issue for anything that looks like a security
problem. Send a private email to peter@dark.bio instead, with a description of
the issue, the affected version and, if you have one, a way to reproduce it.
You will get an acknowledgement within a few days, and updates as the fix
progresses.

Findings in the underlying libraries belong with their own maintainers, but a
report here is still welcome. We track the RustSec advisory database daily and
ship dependency fixes as new releases.

## Supported versions

Only the latest release on crates.io receives fixes. Versions are 0.x and every
minor bump may change the API, so fixes ship as new versions rather than
backports. Consumers should track the latest release.

## Disclosure

Fixes are released first and disclosed afterwards. Once a fixed version is on
crates.io, an advisory is filed with the RustSec database so that `cargo audit`
users learn about it, and the report is credited unless you prefer otherwise.

The Go, TypeScript and Flutter siblings of this crate share its design and
version numbers. A report affecting the design is coordinated across all of
them before disclosure.
