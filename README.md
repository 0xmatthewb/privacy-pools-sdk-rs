# Privacy Pools SDK

Privacy Pools SDK for Rust, browser, Node, iOS, Android, and React Native
apps, with local proving and verification kept on the same Rust core.

> [!CAUTION]
> Experimental software. Use at your own risk.

- **Rust-first:** one protocol implementation shared across Rust, browser, Node,
  iOS, Android, and React Native
- **Local proving:** key derivation, witnesses, proofs, and proof verification
  stay on the client
- **Trusted artifacts:** signed manifests and artifact hash verification gate
  runtime proving assets
- **Continuous assurance:** fast PR checks, scheduled nightly assessment, and
  release-grade audit bundles all run from one shared assurance catalog

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

- matching local all-surface mobile evidence for each promoted release, with
  optional hosted `mobile-smoke-evidence` as secondary clean-runner confirmation
- green release assurance bundles for promoted runtime surfaces

Compatibility is anchored to the published
`@0xbow/privacy-pools-core-sdk@1.2.0` behavior, plus the `getStateRoot()`
correction proposed in
[`0xbow-io/privacy-pools-core#122`](https://github.com/0xbow-io/privacy-pools-core/pull/122).
Rust callers should use the protocol-legible Rust API rather than unreleased
alias names; the npm migration guide maps familiar JS names to Rust names.

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
Prefer `prepare_deposit*` for the deposit happy path: deposits submit a
precommitment hash, and commitments are built once value and label are known.
Use `build_commitment*` for commitment construction, `prove_ragequit*` for the
public exit path backed by the underlying `commitment` circuit, and
`calculate_withdrawal_context*` for withdrawal context hashing. The SDK uses the
preferred Rust spelling `processor` for the processor address inside a
withdrawal, while serialization keeps the deployed protocol key `processooor`.
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

- Rust 1.93.0
- Node.js 22+ for the JS packages and smoke tests
- Rust `wasm32-unknown-unknown` target plus `wasm-bindgen-cli 0.2.118` for
  browser package builds
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
cargo fmt --all --check
cargo test --workspace
cargo test --doc --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo run -p xtask -- examples-check
cargo run -p xtask -- feature-check
cargo run -p xtask -- package-check
cargo run -p xtask -- dependency-check
cargo run -p xtask -- release-check --channel alpha
cargo run -p xtask -- assurance --profile pr --runtime all
cargo run -p xtask -- assurance --profile nightly --runtime all --skip-fuzz
cargo run -p xtask -- bindings
cargo run -p xtask -- react-native-smoke
cargo run -p xtask -- mobile-smoke-local --platform all --surface all
cargo run -p xtask -- mobile-smoke-local --platform all --surface all --evidence-out-dir target/mobile-smoke-evidence
cargo run -p xtask -- sdk-smoke
```

The regular CI workflow runs the fast Rust, Node, browser, and React Native
assurance lanes on every push and pull request.
`assurance-nightly.yml` is the scheduled continuous assessment path for the
shared assurance catalog and can optionally ingest manually supplied mobile
evidence. The heavyweight producer workflows remain on-demand:
`mobile-smoke.yml` emits the `mobile-smoke-evidence` artifact with
`mobile-smoke.json` and `mobile-parity.json` covering iOS native, iOS React
Native, Android native, and Android React Native surfaces, and
`reference-benchmarks.yml` emits optional `reference-benchmarks-stable`
artifacts for informational performance review. Local
`xtask mobile-smoke-local --platform all --surface all --evidence-out-dir ...`
is the primary maintainer mobile gate before merge and release-sensitive
promotion. `assurance-fuzz.yml` is the dedicated scheduled fuzz lane for the
Rust parser/wire/manifest surfaces and replays checked-in corpus seeds from
`fuzz/corpus/**`. The manual `release.yml` workflow now produces
`release-evidence-inputs-${channel}` so the final release audit can be
assembled locally around maintainer-generated mobile evidence.

Further documentation:

- [`docs/benchmarking.md`](docs/benchmarking.md)
- [`docs/feature-matrix.md`](docs/feature-matrix.md)
- [`docs/crate-architecture.md`](docs/crate-architecture.md)
- [`docs/crates-publish-order.md`](docs/crates-publish-order.md)
- [`docs/rust-migration-from-npm.md`](docs/rust-migration-from-npm.md)
- [`docs/release-process.md`](docs/release-process.md)
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
- [`docs/canary-rollout.md`](docs/canary-rollout.md)
- [`docs/compatibility-baseline.md`](docs/compatibility-baseline.md)
- [`docs/v1-js-compatibility-matrix.md`](docs/v1-js-compatibility-matrix.md)
- [`docs/assurance.md`](docs/assurance.md)
- [`docs/assurance-review-guide.md`](docs/assurance-review-guide.md)
- [`docs/dependency-audit.md`](docs/dependency-audit.md)
- [`docs/audit-pack.md`](docs/audit-pack.md)
- [`security/audit-ledger.md`](security/audit-ledger.md)
- [`docs/multi-runtime-status.md`](docs/multi-runtime-status.md)

## License

Apache-2.0
