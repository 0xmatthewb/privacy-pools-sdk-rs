# Feature Matrix

The public Rust crate keeps the current default proving behavior for alpha:
native witness generation is enabled where the target supports it.

| Surface or feature | Default | Intended use | CI coverage |
| --- | --- | --- | --- |
| `privacy-pools-sdk` | enabled | Rust facade for protocol helpers, proving, recovery, and transaction planning. | workspace fmt, clippy, tests, docs, package checks |
| `privacy-pools-sdk-prover/native-witness` | enabled by default | Native Rust witness generation for supported non-wasm targets. | workspace all-features clippy/tests |
| `privacy-pools-sdk-prover/rapidsnark` | opt-in | Fast proving backend on supported native targets. | all-features compile/lint path plus release checks |
| `wasm32-unknown-unknown` | target-specific | Browser package and worker-backed proving/verification flows. | CI wasm build and browser package smoke |
| Node native addon | package surface | v1-compatible Node exports backed by Rust. | SDK smoke and npm package checks |
| UniFFI mobile bindings | package surface | iOS and Android bindings generated from the Rust core. | binding generation, package checks, manual/nightly app-process smoke |
| React Native package | package surface | Mobile app integration over generated native bindings. | package smoke, typecheck, manual/nightly app-process smoke |

## Docs.rs

Publishable Rust crates include docs.rs metadata and build documentation with
all features enabled. Crates that are package surfaces only, such as Node,
browser, FFI, CLI, and `xtask`, remain unpublished.

## Release Evidence

Alpha promotion requires the release check, dependency check, SDK smoke, docs,
package checks, and the current accepted advisory list to remain intentional.
Mobile simulator/emulator app-process smoke is a heavier release evidence gate
and is tracked separately from the fast push workflow.
