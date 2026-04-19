# CI Workflow

This document is the maintainer-facing reference for the minimum PR gate, local
preflight, and the advisory CI lanes that stay visible without blocking merge.

## Preflight

Run the local Rust PR gate before pushing:

```sh
cargo run -p xtask -- preflight
```

The opt-in Git hook runs the same command:

```sh
ln -s ../../scripts/hooks/pre-push.sh .git/hooks/pre-push
```

## Regeneration

Checked-in browser and mobile bindings must be regenerated together:

```sh
cargo run -p xtask -- regenerate-generated
```

To verify freshness without rewriting files:

```sh
cargo run -p xtask -- regenerate-generated --check
```

The command refreshes:

- `packages/sdk/src/browser/generated/`
- `packages/sdk/src/browser/generated-threaded/`
- `bindings/ios/generated/`
- `bindings/android/generated/src/main/`

## Toolchain Bump Protocol

When bumping Rust toolchains or CI helper versions:

1. Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
   locally with the new toolchain.
2. Fix new lints or add narrowly scoped `#[allow(...)]` annotations with
   rationale in the same PR.
3. Run `cargo run -p xtask -- regenerate-generated`.
4. Land the bump in an isolated PR.

## Flake Triage

The advisory jobs exist for signal, not for merge gating. When one flakes:

1. Reproduce the failing command locally before changing retries or timeouts.
2. Prefer fixing the race over relaxing the job.
3. If the flake is mobile-only or benchmark-only, keep the PR gate focused on
   the required checks and fix the advisory lane separately.

## CI Runbook

When CI is red:

1. Start with the first failing required job.
2. If `check:generated` drifts, run `cargo run -p xtask -- regenerate-generated`
   and commit the resulting diff.
3. If `default-artifact-symbols` fails, rebuild the release artifacts locally
   before changing the symbol allowlist.
4. If `solidity-verifier` fails, rerun the Rust proof generation and the Foundry
   acceptance test together.
5. Treat `mobile-smoke`, `reference-benchmarks`, `assurance-fuzz`, and browser
   worker Playwright as advisory signals, not merge blockers.
