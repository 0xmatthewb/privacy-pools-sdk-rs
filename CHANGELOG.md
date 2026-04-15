# Changelog

All notable changes to this repository will be documented here.

The Rust crate is named `privacy-pools-sdk`. The repository remains
`privacy-pools-sdk-rs` to identify the Rust implementation.

## Unreleased

- Prepare the Rust SDK for a publish-ready alpha without publishing crates.
- Add crate metadata and versioned local dependencies for Cargo packaging.
- Add redacted secret field-element types for Rust secret material.
- Prefer the Rust-facing `processor` spelling inside `Withdrawal` while
  preserving the protocol wire key `processooor`.
- Add request/config object APIs for common derivation, commitment, proving,
  and transaction-planning flows.
- Add stable SDK error codes and broad error categories.
- Add Rustdoc examples, a Rust SDK example, security policy, and release notes.
