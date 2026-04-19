# Contributing

## Local Gate

Before pushing, run:

```sh
cargo run -p xtask -- preflight
```

The optional Git hook at `scripts/hooks/pre-push.sh` runs the same command.

## Toolchain Bumps

When bumping `rust-toolchain.toml` or CI helper tool versions:

1. Run `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
   locally with the new toolchain.
2. Fix new lints or add narrowly scoped `#[allow(...)]` annotations with
   rationale in the same change.
3. Run `cargo run -p xtask -- regenerate-generated`.
4. Land the bump in an isolated PR.

## FFI / Binding Entry Points

For any new FFI, Node, or Web entry point that accepts JSON or raw bytes:

1. Apply an explicit size bound at the boundary.
2. Route parsing through the shared bounded helpers (`parse_json_with_limit`,
   `validate_json_boundary`, or the binding/core equivalents).
3. Add or update tests that exercise malformed input, oversize input, and typed
   error propagation.

## Safe Surface Reviews

Changes to safe-surface exports in `packages/sdk/src/{safe,index}.d.ts`,
`packages/sdk/src/{browser,node}/safe.mjs`, or `packages/react-native/src/safe.ts`
should keep the generated/runtime surfaces aligned and request the reviewers
listed in `.github/CODEOWNERS`.

## Advisory CI Jobs

`mobile-smoke`, `reference-benchmarks`, `assurance-fuzz`, and browser worker
Playwright stay visible on pull requests but are intentionally non-blocking.
Do not treat an advisory lane as a substitute for the required merge gate.
