# Release Checklist

Use this checklist before publishing any alpha, beta, rc, or stable candidate.
Do not publish crates or packages until every required gate is green for the
same commit.

## Local Gates

Run from the repository root:

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

Install local gate tools as needed:

```sh
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-hack cargo-audit cargo-deny wasm-bindgen-cli
```

## CI Gates

- Push/PR CI must pass Rust fmt, clippy, tests, doctests, examples, feature
  checks, package dry run, binding generation drift checks, dependency checks,
  browser SDK smoke, React Native package smoke, and React Native typecheck.
- The manual `release` workflow must pass `xtask evidence-check`, dependency
  checks, release version checks, examples, feature checks, package dry run,
  SDK smoke, iOS native packaging, Android native packaging, and final React
  Native package assembly.
- The manual or nightly `mobile-smoke` workflow must pass for the same commit
  before promotion.

## Evidence Bundle

Each channel keeps release evidence in `release/evidence/<channel>`. The bundle
must include:

- `commit.txt` with the short or full commit being promoted
- `release-artifacts.txt` with release workflow artifact names or URLs
- `canary-notes.md` with rollout observations and approval notes
- `desktop-withdraw-stable.json`
- `ios-withdraw-stable.json`
- `android-withdraw-stable.json`
- `mobile-smoke.json`

`mobile-smoke.json` must contain the same commit, workflow name
`mobile-smoke`, a workflow run URL, and passed statuses for both `ios` and
`android`.

## Dependency And Security Gates

- `docs/dependency-audit.md` is the accepted advisory source of truth.
- `xtask dependency-check` must fail if the accepted advisory ID set changes.
- `cargo deny check bans licenses sources advisories` must pass.
- `SECURITY.md` must reflect current audit status, supported alpha line, and
  private reporting expectations.

## Package Dry Runs

- Run `cargo run -p xtask -- package-check` before publishing any Rust crate.
- Confirm `docs/crates-publish-order.md` before crates.io publication.
- Run `npm pack --dry-run --json` in `packages/sdk` and
  `packages/react-native` before publishing package surfaces.
- Do not publish from a dirty generated package surface unless the generated
  drift is intentional and reviewed.

## Publish Order

Publish runtime Rust crates first in dependency order, then package surfaces.
The package-surface crates for FFI, web, Node, CLI, examples, and `xtask` remain
unpublished unless a release plan explicitly changes that boundary.
