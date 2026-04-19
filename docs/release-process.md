# Release Process

Use the manual release workflow at `.github/workflows/release.yml` to assemble
release artifacts for a chosen channel.

The workflow:

- validates that all Rust crates share one version
- validates that the React Native package and both podspecs share one version
- validates that the selected channel matches the mobile prerelease suffix
- builds release iOS native artifacts on macOS
- builds release Android native artifacts on Linux
- assembles a publishable React Native tarball that includes both native asset sets
- assembles one final `release-evidence-inputs-${channel}` artifact for local
  audit assembly
- emits an auditable release CLI binary alongside the SBOM bundle so downstream
  reviewers can inspect a build with embedded dependency metadata

GitHub artifact attestations cover workflow provenance for uploaded build
outputs. SDK signed artifact manifests are a separate check: the SDK verifies an
Ed25519 detached signature over the exact manifest payload bytes, then verifies
the SHA-256 hashes of the circuit artifacts declared by the unsigned manifest
inside that signed payload.

## Channel Rules

- `alpha`: mobile version must use an `-alpha.N` prerelease suffix
- `beta`: mobile version must use a `-beta.N` prerelease suffix
- `rc`: mobile version must use an `-rc.N` prerelease suffix
- `stable`: mobile version must not use a prerelease suffix

The Rust crate version is validated against the same base version as the mobile
package surface. For example, Rust `0.1.0` is compatible with mobile
`0.1.0-alpha.1`, but not with mobile `0.2.0-alpha.1`.

## Local Validation

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

Local native packaging prerequisites:

- iOS packaging requires a full Xcode install with an active developer
  directory that exposes `iphoneos` and `iphonesimulator` through `xcrun`
- Android packaging requires Java 17, Android SDK/NDK, and `cargo-ndk`

Quick iOS sanity check:

```sh
sudo xcodebuild -license accept
xcrun --sdk iphoneos --show-sdk-path
xcrun --sdk iphonesimulator --show-sdk-path
```

Once the external evidence directory exists for a candidate release, validate it
with the shared assurance path. The directory must include:

- `mobile-smoke.json`
- `mobile-parity.json`
- `packages/sdk/*.tgz`
- `packages/sdk/privacy_pools_sdk_web_bg.wasm`
- `packages/react-native/*.tgz`
- `packages/circuits/*.tar.gz`
- `signed-manifest/payload.json`, `signed-manifest/signature`, and `signed-manifest/artifacts/...`
- `sbom/rust.cdx.json`
- `sbom/sdk.spdx.json`
- `sbom/react-native.spdx.json`
- `attestations.json`
- `attestation-verification/**/*.json`

Optional informational benchmark reports can also be present under
`benchmarks/*.json`.

To stage that directory locally with the current authoritative flow:

1. run local all-surface mobile smoke and emit local evidence
2. run the manual `release.yml` workflow for the same commit and download
   `release-evidence-inputs-${channel}`
3. assemble the external evidence directory locally
4. run the shared release assurance path locally

Generate local mobile evidence first:

```sh
cargo run -p xtask -- mobile-smoke-local \
  --platform all \
  --surface all \
  --out-dir /absolute/path/to/mobile-smoke-reports \
  --evidence-out-dir /absolute/path/to/mobile-smoke-evidence
```

Then assemble the release evidence layout:

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

Use either the compatibility alias:

```sh
cargo run -p xtask -- evidence-check \
  --channel alpha \
  --dir /absolute/path/to/external-evidence
```

or the full assurance runner:

```sh
cargo run -p xtask -- assurance \
  --profile release \
  --runtime all \
  --report-mode audit \
  --external-evidence-dir /absolute/path/to/external-evidence
```

That gives the local release audit flow:

1. generate local mobile evidence with `xtask mobile-smoke-local`
2. download `release-evidence-inputs-${channel}` from the matching release run
3. collect optional benchmark reports when available
4. run `xtask external-evidence-assemble --mode release`
5. run `xtask assurance --profile release --report-mode audit`

If the evidence includes a signed manifest, configure
`PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY` locally or pass
`--signed-manifest-public-key`. The assurance runner verifies that Ed25519 key
against the exact payload bytes, then verifies each SHA-256 artifact hash
inside the signed payload.

## GitHub Workflow

Trigger the `release` workflow manually and provide:

- the target channel
- optional `reference_benchmarks_run_id` for the
  `reference-benchmarks-stable` artifact

The workflow validates versions first, then uploads:

- iOS XCFramework archive
- Android JNI archive
- fully assembled React Native package tarball
- `release-evidence-inputs-${channel}`

`release-evidence-inputs-${channel}` bundles the exact hosted inputs needed for
the local release audit:

- same-run package artifacts
- same-run attestation metadata artifacts emitted by the packaging jobs
- same-run SBOM artifacts
- `reference-benchmarks-stable` downloaded from `reference_benchmarks_run_id`
  when provided

The release packaging jobs emit small metadata artifacts that carry the
exact attestation URL, workflow run URL, final SHA-256, and a referenced
verified-attestation result for each packaged subject. The local
`xtask external-evidence-assemble --mode release` step merges those records
into `attestations.json`, stages the matching `attestation-verification/` tree,
and validates the saved verification results offline instead of synthesizing
provenance links.

The SBOM job also builds an auditable release CLI binary at
`target/release-sbom/auditable/privacy-pools-sdk-cli`. That binary is not a
publishable release artifact by itself, but it gives downstream reviewers a
concrete release-mode binary with embedded dependency metadata to inspect
alongside the SBOM bundle.

The canonical browser artifact comes from `release.yml`'s Linux
`sdk-web-package` job. Release assurance compares the npm tarball's embedded
`package/src/browser/generated/privacy_pools_sdk_web_bg.wasm` against the
exported `packages/sdk/privacy_pools_sdk_web_bg.wasm` artifact from that same
job and requires attestation metadata for both. PR CI does not require raw
browser `.wasm` byte-for-byte git drift.

Before promoting a candidate, run local all-surface mobile smoke for the same
commit. That is the authoritative mobile correctness gate for this pre-public
repo. The local evidence directory must include structured reports for all four
mobile surfaces: iOS native, iOS React Native, Android native, and Android
React Native. The manual `mobile-smoke` workflow remains available as optional
clean-runner confirmation when you want hosted simulator/emulator proof.

`mobile-smoke.json` records an explicit evidence `source`, workflow identity,
run URL, aggregate platform pass/fail, and per-surface status. `mobile-parity.json`
rolls those four surface reports into `ios` and `android` parity summaries.
Local evidence uses `source=local-xtask`, `workflow=mobile-smoke-local`, and
`run_url=local://mobile-smoke-local`. Hosted evidence uses
`source=github-workflow`, `workflow=mobile-smoke`, and an `https://` run URL.

Optional benchmark evidence is produced separately by the
manual `reference-benchmarks` workflow. Use the run id from that workflow when
you want performance context attached to the release bundle, but benchmark
evidence is not a promotion blocker.

The dedicated fuzz workflow is `assurance-fuzz.yml`. It is not part of the
interactive release trigger, but it should stay healthy on the release branch
because fuzz findings are intended to surface before promotion work starts.

Build artifacts are only part of promotion readiness. Pair them with rollout
notes described in `docs/canary-rollout.md` before promoting alpha, beta, rc,
or stable.

Use `RELEASE_CHECKLIST.md` as the promotion checklist for local gates, CI gates,
evidence contents, dependency advisories, package dry runs, and publish order.
