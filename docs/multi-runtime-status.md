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

- browser/Node v1 facade parity for network/event-backed account-data behavior
  and CI confirmation for browser-safe contract planning. A compatibility
  matrix, contract tests, Rust-backed crypto/proof/recovery wrappers, browser
  Rust/WASM offline contract planning, and typed compatibility boundaries now
  exist; the remaining work is explicit event/RPC transport and a green CI run
  for the new browser contract planning coverage.
- mobile app-process prove/verify coverage for React Native simulator/emulator
  apps. Native iOS XCTest, Android instrumentation, and React Native
  app-process smoke jobs are wired in the manual/nightly `mobile-smoke`
  workflow and should move to completed only after that workflow is green.
- React Native iOS and Android app-process smoke harnesses now install the
  packed package tarball into generated consumer apps, copy deterministic
  fixture artifacts into app storage, and run native prepare/prove/verify
  session flows from JavaScript before emitting a deterministic success marker.
  This remains in progress until the CI simulator/emulator jobs are green.

## Completed

- Rust remains the single protocol implementation. There is no TypeScript
  reimplementation of proving, verification, or circuit logic in this repo.
- Verified in-memory artifact bundles are available in the Rust core.
- Withdrawal circuit sessions can preload verified artifacts and reuse prepared
  proving and verification state.
- The Rust SDK prefers manifest-bound `vkey` verification for the hot path while
  keeping `zkey` as the canonical proving artifact and trust anchor.
- Native withdrawal session preload now parses the canonical `zkey` before
  creating a cached session and only prepares the manifest-bound `vkey`
  verifier after confirming it matches the verifying key embedded in that
  `zkey`.
- Internal prove-then-verify execution flows reuse a single session instead of
  resolving and hashing artifacts twice.
- Benchmark docs require `cargo run --release`, and the benchmark CLI refuses
  debug builds unless explicitly overridden.
- Benchmark reports now separate cold verified-bundle loading/hash-check time,
  session preload time, first proof/verify latency, and warm proof/verify
  iteration summaries.
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
- The browser runtime now supports local client-side proving for withdrawal and
  commitment circuits. It generates witnesses by executing the
  manifest-pinned circuit `.wasm` artifact in the browser WebAssembly engine,
  then passes witness values into the portable Rust/WASM Groth16 proving path
  that consumes verified `zkey` bytes. The browser build does not compile or
  link the `rust-witness` generated C/native witness path.
- Direct browser proving now prepares a Rust/WASM-verified proof-capable
  session before witness generation, so fetched circuit `.wasm` bytes are
  manifest-hash checked before the browser instantiates them.
- The browser worker now performs real preload, witness, prove, verify, done,
  and error status reporting for proof jobs while keeping the final promise
  result shape unchanged.
- The SDK package now includes Chromium Playwright coverage for a real browser
  module worker, browser-native wasm-bindgen initialization, cross-origin CORS
  artifact fetching, and browser `WebAssembly.instantiate` witness execution.
- SDK CI now checks browser generated WASM binding freshness after `build:web`
  so committed generated assets cannot drift silently.
- Verified artifact bundle fields are sealed behind accessors so callers cannot
  forge a verified bundle by directly constructing public fields.
- The Rust SDK now includes an explicit bounded `SessionCache` for callers that
  want automatic session reuse without a hidden global cache or unbounded
  artifact retention.
- The browser runtime keeps proof-capable session `.wasm` bytes in a bounded
  four-entry cache and exposes `clearCircuitSessionCache()` /
  `clearBrowserCircuitSessionCache()` to explicitly remove cached JS artifacts
  and their matching Rust/WASM sessions.
- The fixture set now pins the v1.2.0 withdrawal `wasm`, `zkey`, and `vkey`
  artifacts, so CI can exercise real withdrawal proof generation and
  verification instead of only static verification fixtures.
- Rust core, Node, browser verification, and the Swift/Kotlin/React Native FFI
  substrate now all exercise real v1.2.0 withdrawal proof compatibility in
  automated tests.
- Artifact/session safety coverage now includes fail-closed tests for incomplete
  bundles, unexpected bundle bytes, unknown circuits, tampered browser
  artifacts, tampered browser proofs, mismatched verification keys, stale
  browser sessions, stale Node sessions, and invalid Node/native proving
  artifacts.
- The unified JS client classes now expose runtime capabilities consistently
  across browser, browser worker, and Node runtimes.
- The JS package now exposes the v1 compatibility names and Rust-backed facade
  wrappers for `Circuits`, `PrivacyPoolSDK`, commitment/withdrawal services,
  crypto helpers including `hashPrecommitment`, log-fetch constants, and typed
  compatibility errors.
- The JS package now exposes Rust-backed recovery keyset and account-state DTO
  wrappers in Node, browser, and browser-worker runtimes. Recovered state is
  returned to the caller and must be passed explicitly to spendable commitment
  helpers so facade services do not retain nullifier/secret material
  implicitly.
- The Node JS package now exposes Rust-backed offline contract planning,
  root-read, Groth16 formatting, current-root, and recovery checkpoint wrappers
  used by the v1 facade. Browser Rust/WASM contract planning is implemented in
  this branch but should move to completed only after CI confirms it green.
  RPC preflight/submission remains app-owned transport rather than bundled SDK
  behavior.
- The fast React Native consumer smoke app now typechecks the reusable withdrawal
  circuit session APIs instead of only importing the older path-based proving
  and verification methods.
- The Rust protocol/core crates still keep the workspace `unsafe_code = forbid`
  posture. The only exception is the thin Node addon wrapper crate, which needs
  generated `unsafe` for N-API module registration.

## Partially Completed

- The mobile surfaces share the Rust session/caching model, and the shared FFI
  layer now runs full real prove/verify fixtures. React Native app-process
  prove/verify smoke is wired for iOS and Android in the manual/nightly
  `mobile-smoke` workflow, but should remain partially complete until that
  workflow is green.
- The runtime matrix is now documented explicitly, Node is shipped, and browser
  proving is available, but the browser/Node package still needs network-backed
  v1 account-data behavior.
- Fast-backend benchmarking exists, but the broader release-mode benchmark
  matrix across surfaces and environments is not complete yet.

## Not Yet Completed

- Browser/Node package parity with the website-used v1 network/event account-data
  facade is not complete yet.
- Mobile app-level smoke coverage still needs green confirmation from the
  `mobile-smoke` workflow for the newly wired React Native iOS and Android
  app-process prove/verify jobs.

## Browser Proving Acceptance

The browser prover must generate witnesses from the manifest-pinned circuit
`.wasm`, then pass witness values into a portable Rust/WASM Groth16 proving path
that consumes verified `zkey` bytes, without compiling or linking the
`rust-witness` generated C/native path. Rust/WASM must own artifact
verification, `zkey` parsing, proof construction from witness values,
manifest-bound `vkey` verification, and final proof verification. The browser
worker is transport, artifact fetching, witness execution, and progress/status
events; it must not reimplement Privacy Pools protocol logic.
