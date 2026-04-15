# Multi-Runtime Status

This document tracks branch-head progress against the multi-runtime expansion
plan.

## Current Surfaces

- Rust crate
- Node package
- Swift/iOS bindings
- Kotlin/Android bindings
- React Native package

## In Progress

- browser package for local client-side proving

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
- A unified JS package now ships a real Node runtime backed by the Rust
  `privacy-pools-sdk-node` addon crate, published as
  `@0xmatthewb/privacy-pools-sdk`.
- A browser-facing package surface and `./worker` entrypoint now exist, and the
  repo contains a dedicated `privacy-pools-sdk-web` Rust binding crate for the
  browser-safe helper and artifact APIs that do not depend on proving yet.
- The Rust protocol/core crates still keep the workspace `unsafe_code = forbid`
  posture. The only exception is the thin Node addon wrapper crate, which needs
  generated `unsafe` for N-API module registration.

## Partially Completed

- The mobile surfaces share the Rust session/caching model, but current smoke
  coverage is still lighter than the target plan. The Rust and FFI layers are
  tested directly, while the React Native smoke app still validates packaging
  and typechecking rather than running a full native prove/verify flow.
- The runtime matrix is now documented explicitly, and Node is shipped, but the
  browser surface is still only partially implemented.
- Fast-backend benchmarking exists, but the broader release-mode benchmark
  matrix across surfaces and environments is not complete yet.
- The browser package exports the intended worker-facing API shape, but the
  worker still reports the real current blocker instead of performing proving.

## Not Yet Completed

- No browser integration tests have shipped yet.
- No production-ready browser proving path has shipped yet.
- No production-ready browser verification path has shipped yet.

## Current Browser Blocker

The proving stack is still native-oriented. The workspace now contains a
browser-focused Rust binding crate, but the prover dependencies still rely on
the native `rust-witness` toolchain. Browser support should be built on the
same Rust-first foundation, and it still needs a WASM-capable prover path
before real local browser proving and verification can ship safely.
