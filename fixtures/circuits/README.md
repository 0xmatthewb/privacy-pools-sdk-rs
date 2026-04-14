# Pinned Circuit Inputs

This directory contains pinned circuit-side inputs used by the Rust SDK build
and test pipeline.

- `withdraw/withdraw.wasm`
  Source: `privacy-pools-core/packages/circuits/build/withdraw/withdraw_js/withdraw.wasm`
  Compatibility target: `@0xbow/privacy-pools-core-sdk@1.2.0`
  SHA-256: `36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10`

The Rust prover crate transpiles the pinned withdraw witness generator wasm into
native code so the SDK can own a compiled `rust-witness + arkworks` withdraw
path without changing contracts or circuits.
