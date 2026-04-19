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
cargo vet
cargo run -p xtask -- dependency-check
cargo run -p xtask -- docs-check
cargo run -p xtask -- release-check --channel alpha
cargo run -p xtask -- sdk-smoke
```

Install local gate tools as needed:

```sh
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-hack cargo-audit cargo-deny cargo-vet cargo-geiger wasm-bindgen-cli
```

## CI Gates

- Push/PR CI must pass Rust fmt, clippy, tests, doctests, examples, feature
  checks, package dry run, binding generation drift checks, dependency checks,
  docs checks, browser SDK smoke, React Native package smoke, and React Native
  typecheck through `xtask assurance --profile pr`.
- PR CI must also pass `cargo-deny-policy`, `rust-v1 parity`,
  `check:generated`, `check:default-artifact-symbols`, `rust-fuzz-smoke`,
  `solidity-verifier`, `mobile-smoke`, `dependency-cycles`, and `cargo-audit`.
- `reference-benchmarks` is required for same-repo release-sensitive validation
  when benchmark regression review is part of the promotion criteria.
- The manual `release` workflow must pass release version checks, dependency
  checks, SBOM generation, packaging, and release evidence input bundling.
- Local all-surface mobile smoke must pass for the same commit before
  promotion and emit local mobile evidence through
  `cargo run -p xtask -- mobile-smoke-local --platform all --surface all --evidence-out-dir ...`.
- The on-demand `mobile-smoke` workflow is optional manual clean-runner
  confirmation and may also provide a `mobile-smoke-evidence` artifact for the
  same commit.
- The on-demand `reference-benchmarks` workflow is optional. When present, it
  should produce the `reference-benchmarks-stable` artifact for informational
  performance review.
- The scheduled `assurance-fuzz` workflow should be green on the candidate
  branch or the release branch tip before promotion work begins.
- `cargo run -p xtask -- preflight` should be green locally before promotion
  work starts from a maintainer workstation.

## Evidence Bundle

Release promotion uses one artifact-backed external evidence bundle. The bundle
must include:

- `mobile-smoke.json`
- `mobile-parity.json`
- `packages/sdk/*.tgz`
- `packages/sdk/privacy_pools_sdk_web_bg.wasm`
- `packages/react-native/*.tgz`
- `packages/circuits/*.tar.gz`
- `sbom/rust.cdx.json`
- `sbom/sdk.spdx.json`
- `sbom/react-native.spdx.json`
- `signed-manifest/payload.json`
- `signed-manifest/signature`
- `signed-manifest/artifacts/...`
- `attestations.json`
- `attestation-verification/**/*.json`

Optional informational benchmark reports can also be present under
`benchmarks/*.json`.

`mobile-smoke.json` must contain the same commit, an explicit `source`,
matching `workflow`, `run_url`, and passed statuses for both `ios` and
`android`, plus the required `surfaces` object with `iosNative`,
`iosReactNative`, `androidNative`, and `androidReactNative`. Each platform
aggregate is only `passed` when both of that platform's surfaces pass. Valid
mobile evidence identities are:

- hosted: `source=github-workflow`, `workflow=mobile-smoke`, `run_url=https://...`
- local: `source=local-xtask`, `workflow=mobile-smoke-local`, `run_url=local://mobile-smoke-local`

`mobile-parity.json` must roll those same four structured surface reports into
`ios.native`, `ios.reactNative`, `android.native`, and `android.reactNative`
with no failed smoke or parity checks.

To stage the authoritative release layout locally, first generate local mobile
evidence:

```sh
cargo run -p xtask -- mobile-smoke-local \
  --platform all \
  --surface all \
  --out-dir /absolute/path/to/mobile-smoke-reports \
  --evidence-out-dir /absolute/path/to/mobile-smoke-evidence
```

Then download `release-evidence-inputs-${channel}` from the matching
`release.yml` run and assemble the external evidence directory:

```sh
cargo run -p xtask -- external-evidence-assemble \
  --mode release \
  --out-dir /absolute/path/to/external-evidence \
  --mobile-evidence-dir /absolute/path/to/mobile-smoke-evidence \
  --sbom-dir /absolute/path/to/release-evidence-inputs/sbom \
  --packages-dir /absolute/path/to/release-evidence-inputs/packages \
  --attestation-metadata-dir /absolute/path/to/release-evidence-inputs/attestation-metadata
```

Add `--reference-benchmarks-dir /absolute/path/to/release-evidence-inputs/benchmarks`
only when optional benchmark evidence is available.

Then validate it with the shared release assurance path:

```sh
cargo run -p xtask -- assurance \
  --profile release \
  --runtime all \
  --skip-fuzz \
  --report-mode audit \
  --external-evidence-dir /absolute/path/to/external-evidence
```

`xtask evidence-check` remains available only as a compatibility alias for the
same external evidence validation.

When signed-manifest payloads are present, the local release audit must read
the non-secret Ed25519 public key from
`PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY` or receive it through
`--signed-manifest-public-key`, and it must fail closed if the key is absent or
does not verify the exact payload bytes.

Each `attestations.json` record must also reference a saved verified-attestation
result through `verificationPath`. Release assurance checks those saved
verification results offline in addition to re-hashing the local packaged
subjects.

The `release-sboms-*` artifact should also contain
`auditable/privacy-pools-sdk-cli` from `cargo auditable build --release`.

The manual `release` workflow consumes:

- the target release `channel`
- optional `reference_benchmarks_run_id` for the
  `reference-benchmarks-stable` artifact

It produces:

- published package artifacts
- attestation metadata artifacts
- SBOM artifacts
- `release-evidence-inputs-${channel}` for local release-audit assembly

## Dependency And Security Gates

- `security/advisories.toml` is the accepted advisory source of truth.
- `xtask dependency-check` must fail if the accepted advisory ID set changes.
- `cargo vet` must pass for the workspace.
- `cargo deny check bans licenses sources advisories` must pass.
- `SECURITY.md` must reflect current audit status, supported alpha line, and
  private reporting expectations.
- [`security/audit-ledger.md`](security/audit-ledger.md) must be current for the
  target commit.

## Reviewer Sign-Off

- Confirm the invariant map in
  [`docs/assurance-review-guide.md`](docs/assurance-review-guide.md) still
  matches the checks and workflows that passed.
- Confirm there are no unresolved blocking entries in
  [`security/audit-ledger.md`](security/audit-ledger.md) for the target commit.
- Confirm release provenance, SBOM, package, signed-manifest, and mobile
  evidence artifacts are present and reviewed.

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
