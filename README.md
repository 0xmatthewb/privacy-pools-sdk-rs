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
- UniFFI-exported FFI surface for versioning, backend discovery, key derivation,
  root-read planning, and artifact verification
- React Native package updated to a native-module facade instead of a fake JS
  implementation
- CI expanded to include clippy, tests, cargo-deny, cargo-audit, and RN package
  smoke packaging

Next milestone:

- real `circom-prover` execution wired to a circuit-specific witness adapter
- generated iOS and Android bindings plus packaging automation
- provider-backed transaction simulation, signing, and broadcast flows
- mobile smoke builds once native entry points exist
