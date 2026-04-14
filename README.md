# privacy-pools-sdk-rs

Rust-first Privacy Pools SDK.

This repository is the canonical SDK implementation for:

- Rust consumers
- native iOS and Android applications
- React Native applications via a thin package wrapper

Contracts and circuits remain unchanged. The implementation target is the
published `@0xbow/privacy-pools-core-sdk@1.2.0` behavior plus the corrected
state-root semantics proposed in
[`0xbow-io/privacy-pools-core#122`](https://github.com/0xbow-io/privacy-pools-core/pull/122).

## Design principles

- Safety of user funds is the top priority.
- Rust is the source of truth for proving, Merkle logic, recovery, and chain
  interaction planning.
- Artifacts are pinned and hash verified.
- Signers are explicit abstractions, not raw private-key-first APIs.
- React Native is a delivery surface, not a second implementation.

## Workspace

- `crates/privacy-pools-sdk`: public Rust API
- `crates/privacy-pools-sdk-ffi`: FFI surface for mobile bindings
- internal crates for crypto, tree logic, artifacts, prover, chain, recovery,
  and signer policy
- `packages/react-native`: thin JS/TS wrapper over native bindings
- `fixtures/`: golden vectors and artifact manifests
- `xtask`: release and maintenance automation

## Local prerequisites

- Rust stable toolchain
- Node.js 22+ for the React Native package and smoke app
- Full Xcode for any iOS target build or XCFramework packaging
- Android SDK, NDK, Java 17, and `cargo-ndk` for Android native packaging

Important iOS note:

- `xcrun --sdk iphoneos --show-sdk-path` must succeed before local iOS builds
  will work
- Command Line Tools alone do not ship the `iphoneos` or `iphonesimulator` SDKs
- after installing Xcode, switch the active developer directory to the app
  bundle:

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
xcrun --sdk iphoneos --show-sdk-path
```

## Current Status

Implemented now:

- Rust workspace and crate boundaries for the end-state architecture
- compatibility vectors for key derivation, commitments, context hashing,
  Merkle proof shape, proof formatting, and corrected state-root reads
- public Rust API wrappers for crypto, tree, recovery checkpointing, and root
  read planning
- explicit distinction between pool state-root reads and ASP-root reads
- artifact manifest resolution and SHA-256 verification helpers
- explicit local artifact status and verified bundle resolution helpers
- typed withdraw witness requests and normalized circuit-input serialization for
  the default Rust proving backend
- verified-zkey proving request preparation for the `withdraw` circuit
- compiled `rust-witness + arkworks` withdraw proving path owned by the Rust
  SDK, including local proof verification hooks
- offline withdraw and relay transaction planners with typed calldata output
- provider-backed withdraw and relay execution preflight built on top of the
  typed plans, including live chain-id checks, code-hash checks, root
  freshness checks, and `eth_call`/gas-estimate simulation before execution
- high-level prepared execution flows that compose proof generation, local
  proof verification, transaction planning, and provider-backed preflight into
  one Rust-owned safety boundary
- signer-backed prepared transaction submission that re-confirms the saved
  preflight checks immediately before broadcast and returns typed receipt
  summaries
- finalized transaction requests for host-provided or mobile secure-storage
  signers, including nonce and fee resolution on top of refreshed preflight
- concrete signer-handle registration for `local_dev`, `host_provided`, and
  `mobile_secure_storage` flows, plus signer-aware finalization helpers that
  keep external signing on the finalized Rust-owned request boundary
- validated raw signed-transaction submission that checks signer identity and
  transaction fields against the finalized Rust-owned request before broadcast
- UniFFI-exported FFI surface for versioning, backend discovery, key derivation,
  typed withdraw circuit inputs, withdraw proof generation/verification,
  prepared execution flows, finalized signing requests, signer-handle
  registration, prepared submission, signed submission, transaction planning,
  root-read planning, proof formatting, and artifact verification/resolution
- React Native package updated to a native-module facade instead of a fake JS
  implementation, including typed withdraw-circuit input, withdraw proof
  generation/verification, prepared execution helpers, finalized signing
  helpers, signer-handle based submission, signed submission, and transaction
  planning
- consumer-style React Native smoke harness that installs the packed npm tarball
  into a lightweight sample app and typechecks the public package surface
- additive mobile job APIs for long-running withdraw proof generation and
  prepared withdraw/relay execution, with Rust-owned status polling,
  callback-style progress helpers in the wrapper layers, best-effort
  cancellation, typed result retrieval, and explicit job cleanup
- React Native package assembly now stages package-local generated Swift/Kotlin
  bindings, with optional release staging for iOS XCFramework and Android JNI
  libraries
- CI expanded to include clippy, tests, cargo-deny, cargo-audit, RN package
  smoke packaging, RN sample-app smoke, and platform-split native release
  packaging smoke for iOS and Android
- CLI benchmark entrypoint for the Rust withdraw proving path, driven by the
  checked-in compatibility fixtures and real verified artifact bundles, with
  artifact-resolution timing, cold first-proof latency, verify timing,
  best-effort peak memory, and structured JSON report output for device
  comparisons
- manual release workflow with channel validation and packaged React Native
  release artifacts for alpha/beta/rc/stable promotion

Benchmarking:

- see `docs/benchmarking.md` for the `privacy-pools-sdk-cli benchmark-withdraw`
  workflow
- see `docs/release-process.md` for release-channel validation and packaging
- see `cargo run -p xtask -- evidence-check --channel <channel> --dir <evidence-dir>`
  for release-evidence validation
- see `docs/canary-rollout.md` for the benchmark/canary evidence required before
  promotion

Next milestone:

- mobile-device benchmark captures and canary rollout evidence for alpha/beta/rc
  promotion
