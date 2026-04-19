# Changelog

All notable changes to this repository will be documented here.

The Rust crate is named `privacy-pools-sdk`. The repository remains
`privacy-pools-sdk-rs` to identify the Rust implementation.

## Unreleased

### Security hardening

- Fail closed on dynamic fee drift, signed manifest bounds, and browser/runtime
  execution regressions.
- Harden FFI background-job recovery, relay data handling, and typed preflight
  reporting.

### Assurance and fuzz

- Add TS parity fixtures, wrong-chain fuzz seed coverage, preflight tooling,
  cycle detection, cargo-audit config generation, and toolchain canary checks.
- Add generated-artifact freshness, action pinning, and advisory-policy CI
  ratchets.

### Bindings

- Refresh checked-in browser WASM artifacts and mobile bindings under a pinned
  binaryen toolchain.
- Add shared non-crypto bindings-core parser and limit foundations for web,
  node, and ffi surfaces.

### CI

- Pin Linux runners to `ubuntu-22.04`, add nextest/JUnit preparation, and
  expand release and PR workflow coverage.

### Docs

- Add preflight, regeneration, CI triage, binding parity, flake triage, and
  toolchain upgrade runbooks.
