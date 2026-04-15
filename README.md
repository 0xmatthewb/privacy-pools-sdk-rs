# Privacy Pools SDK

Privacy Pools SDK for Rust, browser, Node, iOS, Android, and React Native
apps, with local proving and verification kept on the same Rust core.

> [!CAUTION]
> Experimental software. Use at your own risk.

## What Is Privacy Pools?

Privacy Pools is a non-custodial privacy protocol for Ethereum and compatible
chains. Users deposit publicly and withdraw privately by proving they belong to
an approved association set, while retaining the ability to exit publicly via
ragequit at any time.

This repository is the client SDK for that protocol. It does not change the
deployed Privacy Pools contracts or circuits. Instead, it gives applications one
implementation for the work around them: key and commitment derivation, Merkle
witness handling, local proof generation and verification, artifact
verification, account recovery, transaction planning, and mobile bindings.

## SDK Surfaces

Current first-class surfaces:

- Rust crate published as `privacy-pools-sdk` from this `privacy-pools-sdk-rs`
  repository
- browser and Node package published as `@0xmatthewb/privacy-pools-sdk`
- generated iOS bindings
- generated Android bindings
- React Native package published as `@0xmatthewb/privacy-pools-sdk-react-native`

Remaining package milestones:

- green manual/nightly mobile app-process smoke confirmation for React Native
  iOS and Android simulator/emulator prove/verify coverage
- broader release-mode benchmark evidence across runtime surfaces

Compatibility is anchored to the published
`@0xbow/privacy-pools-core-sdk@1.2.0` behavior, plus the `getStateRoot()`
correction proposed in
[`0xbow-io/privacy-pools-core#122`](https://github.com/0xbow-io/privacy-pools-core/pull/122).

## Capabilities

At the protocol layer, the SDK derives keys, commitments, nullifiers, and
LeanIMT witnesses in the shapes expected by the deployed Privacy Pools circuits.
It resolves pinned circuit artifacts, builds `withdraw` inputs, generates proofs
locally, and verifies those proofs before any execution flow moves forward.
Mnemonics, nullifier secrets, witnesses, and proof material stay in the client
process; the JS network facade only fetches public chain logs through
application-provided RPC/client transport.

At the application layer, it reconstructs account state from onchain events,
including legacy migration cases, plans withdraw and relay transactions against
the deployed contracts, and keeps signing as an explicit boundary. The same core
logic is shared across Rust, browser, Node, iOS, Android, and React Native so
different app surfaces are working from the same implementation.

## Safety Model

Safety of user funds is the top priority for this SDK. The current design keeps
that boundary explicit. The deployed contracts and circuits are treated as the
source of truth. Circuit artifacts are versioned, pinned, and hash verified.
Pool state roots and ASP roots are handled as distinct concepts. Prepared
execution flows re-check chain identity, contract code hashes, roots, and
transaction parameters before broadcast, and signer integrations remain explicit
interfaces rather than raw private-key convenience paths hidden inside the SDK.

## Rust SDK Naming

The Rust package is `privacy-pools-sdk`, imported as `privacy_pools_sdk`. The
repository name includes `-rs` only to distinguish this implementation from the
browser, Node, mobile, and React Native package surfaces.

Rust-facing APIs should make the protocol legible. Application workflows use
protocol action names such as deposit, withdrawal, relay, and ragequit. The
cryptographic state object remains `Commitment`, because that is the object
inserted into the pool tree and carried through withdrawal/ragequit proofs.
Prefer `DepositCommitmentRequest` and `create_deposit_commitment*` for the
deposit happy path, and `prove_ragequit*` for the public exit path backed by the
underlying `commitment` circuit. The SDK uses the preferred Rust spelling
`processor` for the processor address inside a withdrawal, while serialization
keeps the deployed protocol key `processooor`.
See the
[protocol legibility note](https://github.com/0xmatthewb/privacy-pools-sdk-rs/blob/main/docs/protocol-legibility.md)
for the naming mapping against `@0xbow/privacy-pools-core-sdk@1.2.0`.

## Workspace Layout

Most of the implementation lives in the public Rust crate,
`crates/privacy-pools-sdk`, plus the mobile-facing FFI crate,
`crates/privacy-pools-sdk-ffi`. Supporting internal crates cover the focused
protocol concerns: crypto, Merkle logic, proving, artifacts, chain interaction,
recovery, and signer validation.

Generated iOS and Android bindings live in `bindings/`. The unified Node and
browser package lives in `packages/sdk`, while the React Native package lives in
`packages/react-native`. Compatibility fixtures and sample artifact manifests
live in `fixtures/`, and `xtask` drives binding generation, packaging, release
validation, and smoke tests.

## Local Development

Prerequisites:

- Rust stable
- Node.js 22+ for the JS packages and smoke tests
- Rust `wasm32-unknown-unknown` target plus `wasm-bindgen-cli` for browser package builds
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
cargo run -p xtask -- react-native-app-smoke-ios
cargo run -p xtask -- react-native-app-smoke-android
cargo run -p xtask -- sdk-smoke
```

The regular CI workflow runs the fast Rust, SDK, browser-worker, React Native
package, and React Native typecheck gates on every push. The real simulator and
emulator app-process mobile smokes run in the manual/nightly `mobile-smoke`
workflow because they are intentionally heavyweight release/promotion gates.

Further documentation:

- [`docs/benchmarking.md`](docs/benchmarking.md)
- [`docs/release-process.md`](docs/release-process.md)
- [`docs/canary-rollout.md`](docs/canary-rollout.md)
- [`docs/compatibility-baseline.md`](docs/compatibility-baseline.md)
- [`docs/v1-js-compatibility-matrix.md`](docs/v1-js-compatibility-matrix.md)
- [`docs/dependency-audit.md`](docs/dependency-audit.md)
- [`docs/multi-runtime-status.md`](docs/multi-runtime-status.md)

## License

Apache-2.0
