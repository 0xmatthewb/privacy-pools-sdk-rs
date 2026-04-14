# Privacy Pools SDK

Privacy Pools SDK for Rust, iOS, Android, and React Native.

> [!CAUTION]
> Experimental software. Use at your own risk.

## What Is Privacy Pools?

Privacy Pools is a non-custodial privacy protocol for Ethereum and compatible
chains. Users deposit publicly and withdraw privately by proving they belong to
an approved association set, while retaining the ability to exit publicly via
ragequit at any time.

Privacy Pools is defined by its deployed contracts and circuits. This repository
does not change either of those. It implements the client-side SDK around them:
proving, witness preparation, Merkle logic, artifact handling, account
recovery, transaction planning, and mobile bindings.

## SDK Surfaces

This repository provides the canonical SDK implementation for:

- Rust applications
- iOS and Android applications through generated native bindings
- React Native applications through `@0xbow/privacy-pools-sdk`

Compatibility is anchored to the published
`@0xbow/privacy-pools-core-sdk@1.2.0` behavior, plus the `getStateRoot()`
correction proposed in
[`0xbow-io/privacy-pools-core#122`](https://github.com/0xbow-io/privacy-pools-core/pull/122).

## Capabilities

- generates keys, commitments, nullifiers, and witness inputs
- builds LeanIMT proofs and normalizes circuit-facing Merkle witnesses
- proves and verifies the Privacy Pools `withdraw` circuit locally
- resolves and hash-verifies pinned circuit artifacts
- reconstructs account state from onchain events, including legacy migration
  flows
- plans withdraw and relay transactions against the existing Privacy Pools
  contracts
- performs execution preflight checks before signing or broadcast
- exposes the same core logic across every supported surface

## Safety Model

Safety of user funds is the top priority for this SDK. The current design keeps
that boundary explicit:

- contracts and circuits are treated as protocol source of truth
- circuit artifacts are versioned, pinned, and hash verified
- pool state roots and ASP roots are handled as distinct concepts
- proving, verification, recovery, and transaction planning live in one native
  implementation
- signer interfaces are explicit abstractions, not raw private-key-first
  convenience APIs
- prepared execution flows re-check chain identity, contract code, roots, and
  transaction parameters before broadcast

## Workspace Layout

- `crates/privacy-pools-sdk`: public Rust API
- `crates/privacy-pools-sdk-ffi`: FFI layer for mobile bindings
- `crates/privacy-pools-sdk-crypto`: key derivation, Poseidon helpers,
  commitments, context hashing
- `crates/privacy-pools-sdk-tree`: LeanIMT handling and circuit witness shaping
- `crates/privacy-pools-sdk-prover`: proving backend integration
- `crates/privacy-pools-sdk-artifacts`: manifest resolution and artifact
  verification
- `crates/privacy-pools-sdk-chain`: ABI formatting, planning, preflight, and
  submission helpers
- `crates/privacy-pools-sdk-recovery`: checkpointing and account recovery replay
- `crates/privacy-pools-sdk-signer`: signer abstractions and validation helpers
- `packages/react-native`: React Native package backed by the native bindings
- `bindings/ios`, `bindings/android`: generated platform bindings
- `fixtures/`: compatibility vectors and artifact manifests
- `xtask`: build, packaging, release, and smoke-test automation

## Local Development

Prerequisites:

- Rust stable
- Node.js 22+ for the React Native package and smoke app
- full Xcode for iOS builds and XCFramework packaging
- Android SDK, NDK, Java 17, and `cargo-ndk` for Android native packaging

If iOS builds fail locally, verify that full Xcode is active instead of Command
Line Tools only:

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
xcrun --sdk iphoneos --show-sdk-path
```

Common commands:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run -p xtask -- bindings
cargo run -p xtask -- react-native-smoke
```

Further documentation:

- [`docs/benchmarking.md`](docs/benchmarking.md)
- [`docs/release-process.md`](docs/release-process.md)
- [`docs/canary-rollout.md`](docs/canary-rollout.md)
- [`docs/compatibility-baseline.md`](docs/compatibility-baseline.md)

## License

Apache-2.0
