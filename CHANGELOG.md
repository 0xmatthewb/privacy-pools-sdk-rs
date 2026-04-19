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

- Add TS parity fixtures and wrong-chain fuzz seed coverage, and skip the
  merkle proof tamper fuzz harness when the input is entirely zero bytes.
- Add a local `xtask preflight` alias and a unified `xtask regenerate-generated`
  command for browser and mobile artifact refreshes.

### Bindings

- Refresh checked-in browser WASM artifacts and mobile bindings under a pinned
  binaryen toolchain.
- Add shared non-crypto bindings-core parser and limit foundations for web,
  node, and ffi surfaces.

### CI

- Keep the PR merge gate focused on required Rust, parity, generated-artifact,
  symbol-scan, and Solidity-verifier jobs.
- Mark mobile, benchmark, fuzz, and browser-worker lanes advisory on pull
  requests while keeping them visible.

### Docs

- Add consolidated CI guidance and contributing notes for preflight,
  regeneration, toolchain bumps, and advisory-lane triage.
