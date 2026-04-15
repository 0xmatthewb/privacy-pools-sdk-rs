# Feature Matrix

The public Rust crate keeps the current alpha default proving behavior: native
witness generation is enabled for supported non-wasm targets. Browser, mobile,
and package surfaces are checked as explicit target combinations rather than
hidden feature side effects.

| Surface or feature | Default | Intended use | CI coverage |
| --- | --- | --- | --- |
| `privacy-pools-sdk` | enabled | Rust facade for protocol helpers, proving, recovery, and transaction planning. | workspace fmt, clippy, tests, docs, examples, package checks |
| `privacy-pools-sdk-prover/native-witness` | enabled by default | Native Rust witness generation for supported non-wasm targets. | workspace all-features clippy/tests plus `xtask feature-check` |
| `privacy-pools-sdk-prover/rapidsnark` | opt-in | Fast proving backend on supported native targets. | `cargo hack` targeted feature checks and all-features compile path |
| `privacy-pools-sdk-prover --no-default-features` | opt-in | Verification and artifact workflows without compiled native witnesses. | `xtask feature-check` |
| `wasm32-unknown-unknown` | target-specific | Browser package and worker-backed proving/verification flows. | CI wasm target check, WASM package build, and browser package smoke |
| Node native addon | package surface | v1-compatible Node exports backed by Rust. | SDK smoke and npm package checks |
| UniFFI mobile bindings | package surface | iOS and Android bindings generated from the Rust core. | binding generation, package checks, manual/nightly app-process smoke |
| React Native package | package surface | Mobile app integration over generated native bindings. | package smoke, typecheck, manual/nightly app-process smoke evidence |

## Tested Commands

Fast push and release validation run these Rust gates:

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
cargo run -p xtask -- sdk-smoke
```

`xtask feature-check` currently expands to:

```sh
cargo hack check -p privacy-pools-sdk-prover --each-feature --no-dev-deps
cargo check -p privacy-pools-sdk-prover --no-default-features
cargo check -p privacy-pools-sdk-prover --all-features
cargo check -p privacy-pools-sdk-web --target wasm32-unknown-unknown
```

The CI job installs `cargo-hack` and the `wasm32-unknown-unknown` target before
running the gate.

## Supported Target Assumptions

- Native Rust targets use the default `native-witness` feature unless a caller
  explicitly opts out.
- Browser WASM builds route through `privacy-pools-sdk-web`, which depends on
  the prover without default features and uses `getrandom/js`.
- iOS release packaging requires full Xcode, accepted licenses, and the
  `iphoneos` and `iphonesimulator` SDKs.
- Android release packaging requires Java 17, Android SDK/NDK 27, and
  `cargo-ndk`.
- Rapidsnark is treated as a fast backend behind policy checks. It must compile
  for supported native targets, but applications still opt in at runtime.

Unsupported combinations should fail clearly rather than silently falling back:
native witness generation is not expected in browser WASM, mobile simulator
smoke is not run on every push, and private-key signing is not hidden inside the
high-level client.

## Docs.rs

Publishable Rust crates include docs.rs metadata and build documentation with
all features enabled. Crates that are package surfaces only, such as Node,
browser, FFI, CLI, and `xtask`, remain unpublished.

## Release Evidence

Alpha promotion requires the release check, dependency check, SDK smoke, docs,
examples, feature checks, package checks, and the current accepted advisory list
to remain intentional. Mobile simulator/emulator app-process smoke is a heavier
release evidence gate and is tracked through `mobile-smoke.json` in
`release/evidence/<channel>` for the same commit being promoted.
