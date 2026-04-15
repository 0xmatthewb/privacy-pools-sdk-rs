# Multi-Runtime Status

This document tracks branch-head progress against the multi-runtime expansion
plan.

## Current Surfaces

- Rust crate
- Swift/iOS bindings
- Kotlin/Android bindings
- React Native package

## In Progress

- browser package for local client-side proving
- plain Node package for JS/server-side DX

## Completed

- Rust remains the single protocol implementation. There is no TypeScript
  reimplementation of proving, verification, or circuit logic in this repo.
- Verified in-memory artifact bundles are available in the Rust core.
- Withdrawal circuit sessions can preload verified artifacts and reuse prepared
  proving and verification state.
- The Rust SDK prefers manifest-bound `vkey` verification for the hot path while
  keeping `zkey` as the canonical proving artifact and trust anchor.
- Internal prove-then-verify execution flows reuse a single session instead of
  resolving and hashing artifacts twice.
- Benchmark docs require `cargo run --release`, and the benchmark CLI refuses
  debug builds unless explicitly overridden.
- Swift/iOS, Kotlin/Android, and React Native now expose reusable withdrawal
  circuit session APIs on top of the shared Rust session layer.
- The React Native package now uses the explicit runtime-specific package name
  `@0xmatthewb/privacy-pools-sdk-react-native`.

## Partially Completed

- The mobile surfaces share the Rust session/caching model, but current smoke
  coverage is still lighter than the target plan. The Rust and FFI layers are
  tested directly, while the React Native smoke app still validates packaging
  and typechecking rather than running a full native prove/verify flow.
- The runtime matrix is now documented explicitly, but browser and Node remain
  planned rather than shipped.
- Fast-backend benchmarking exists, but the broader release-mode benchmark
  matrix across surfaces and environments is not complete yet.

## Not Yet Completed

- No browser-targeted Rust binding crate has shipped yet.
- No unified browser+Node JS package has shipped yet.
- No browser worker entrypoint has shipped yet.
- No browser integration tests have shipped yet.
- No Node integration tests have shipped yet.
- No production-ready browser proving path has shipped yet.

## Current Browser Blocker

The proving stack is still native-oriented. The current workspace does not yet
contain a `wasm32` target path, and the proving dependencies still rely on the
native `rust-witness` toolchain. Browser support should be built on the same
Rust-first foundation, but it still needs a WASM-capable prover path before a
real browser package can be shipped safely.
