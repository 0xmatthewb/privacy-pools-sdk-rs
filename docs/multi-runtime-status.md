# Multi-Runtime Status

This document tracks branch-head progress against the multi-runtime expansion
plan.

## Current Surfaces

- Rust crate
- browser package
- Node package
- Swift/iOS bindings
- Kotlin/Android bindings
- React Native package

## In Progress

- browser local client-side proving

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
  repo contains a dedicated `privacy-pools-sdk-web` Rust binding crate.
- The browser package now uses Rust/WASM for key derivation, commitments,
  Merkle helpers, withdrawal input shaping, manifest-bound artifact
  verification, and proof verification instead of a blanket JS-side
  unavailability stub.
- The browser package worker now executes those supported Rust/WASM helper and
  artifact APIs off-thread instead of returning placeholder responses.
- The browser runtime now supports real proof verification and verification
  session reuse against manifest-bound `vkey` artifacts through the shared Rust
  verifier layer.
- The Rust protocol/core crates still keep the workspace `unsafe_code = forbid`
  posture. The only exception is the thin Node addon wrapper crate, which needs
  generated `unsafe` for N-API module registration.

## Partially Completed

- The mobile surfaces share the Rust session/caching model, but current smoke
  coverage is still lighter than the target plan. The Rust and FFI layers are
  tested directly, while the React Native smoke app still validates packaging
  and typechecking rather than running a full native prove/verify flow.
- The runtime matrix is now documented explicitly, and Node is shipped, but the
  browser surface is still only partially implemented because proving remains
  unavailable there.
- Fast-backend benchmarking exists, but the broader release-mode benchmark
  matrix across surfaces and environments is not complete yet.
- The browser package exports the intended worker-facing API shape, and the
  worker now performs the currently supported helper/artifact methods, but
  proving-specific methods still fail closed.

## Not Yet Completed

- No production-ready browser proving path has shipped yet.
- Mobile app-level smoke coverage still does not execute a full native
  prove/verify fixture in React Native, iOS, and Android sample apps.

## Current Browser Blocker

The proving stack is still native-oriented. The workspace now contains a
browser-focused Rust binding crate plus real browser helper, artifact, and
verification APIs, but the prover dependencies still rely on the native
`rust-witness` toolchain. Browser support should stay on the same Rust-first
foundation, and it still needs a WASM-capable prover path before real local
browser proving can ship safely.
