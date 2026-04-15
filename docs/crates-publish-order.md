# Crates Publish Order

The root Rust package is `privacy-pools-sdk`. The repository remains
`privacy-pools-sdk-rs`.

The SDK is not published to crates.io yet. When publishing starts, publish the
runtime library crates before the root facade so the crates.io dependency
closure exists for `privacy-pools-sdk`.

Recommended order:

1. `privacy-pools-sdk-core`
2. `privacy-pools-sdk-artifacts`
3. `privacy-pools-sdk-verifier`
4. `privacy-pools-sdk-tree`
5. `privacy-pools-sdk-signer`
6. `privacy-pools-sdk-crypto`
7. `privacy-pools-sdk-prover`
8. `privacy-pools-sdk-chain`
9. `privacy-pools-sdk-circuits`
10. `privacy-pools-sdk-recovery`
11. `privacy-pools-sdk`

Keep Node, browser, FFI, CLI, examples, and `xtask` unpublished unless a future
dependency closure explicitly requires a published crate.

Before publishing, run the workspace package check. The exact single-crate
package check for `privacy-pools-sdk` depends on the internal dependency
closure being available from crates.io.
