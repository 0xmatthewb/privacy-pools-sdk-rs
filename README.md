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
- offline withdraw and relay transaction planners with typed calldata output
- UniFFI-exported FFI surface for versioning, backend discovery, key derivation,
  typed withdraw circuit inputs, transaction planning, root-read planning,
  proof formatting, and artifact verification/resolution
- React Native package updated to a native-module facade instead of a fake JS
  implementation, including typed withdraw-circuit input and transaction
  planning helpers
- React Native package assembly now stages package-local generated Swift/Kotlin
  bindings, with optional release staging for iOS XCFramework and Android JNI
  libraries
- CI expanded to include clippy, tests, cargo-deny, cargo-audit, and RN package
  smoke packaging

Next milestone:

- real `circom-prover` execution wired to a compiled withdraw witness adapter
- provider-backed transaction simulation, signing, and broadcast flows
- publishable React Native release builds with staged native binaries and
  mobile smoke builds
