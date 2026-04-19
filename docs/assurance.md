# Assurance

Use `xtask assurance` as the shared entrypoint for the SDK's regular test suite
and deeper assurance lanes.

## Default Profiles

```sh
cargo run -p xtask -- assurance --profile pr --runtime all
cargo run -p xtask -- assurance --profile nightly --runtime all
cargo run -p xtask -- assurance --profile release --runtime all --report-mode audit --external-evidence-dir /absolute/path/to/external-evidence
```

The runner keeps one shared catalog of checks and filters it by:

- `--profile pr|nightly|release`
- `--runtime rust|node|browser|react-native|all`
- `--report-mode standard|audit`
- `--external-evidence-dir <path>` for release evidence ingestion and audit mode

## Assurance Categories

The catalog is organized around five kinds of signal:

- correctness
- policy and supply-chain
- heavy runtime integration
- fuzz
- release evidence

The important design choice is lane separation, not five separate tools. PRs
stay deterministic, nightly carries broader regression depth, the dedicated fuzz
workflow exercises libFuzzer targets, and release bundles ingest external
evidence rather than rebuilding trust from scratch.

To materialize the shared external evidence layout locally without hand-building
directories, use:

```sh
cargo run -p xtask -- external-evidence-assemble \
  --mode nightly \
  --out-dir /absolute/path/to/nightly-external-evidence \
  --mobile-evidence-dir /absolute/path/to/mobile-smoke-evidence
```

For a strict release-grade bundle, first generate local all-surface mobile
evidence:

```sh
cargo run -p xtask -- mobile-smoke-local \
  --platform all \
  --surface all \
  --out-dir /absolute/path/to/mobile-smoke-reports \
  --evidence-out-dir /absolute/path/to/mobile-smoke-evidence
```

Then assemble the hosted release inputs around that local mobile evidence:

```sh
cargo run -p xtask -- external-evidence-assemble \
  --mode release \
  --out-dir /absolute/path/to/release-external-evidence \
  --mobile-evidence-dir /absolute/path/to/mobile-smoke-evidence \
  --sbom-dir /absolute/path/to/release-evidence-inputs/sbom \
  --packages-dir /absolute/path/to/release-evidence-inputs/packages \
  --attestation-metadata-dir /absolute/path/to/release-evidence-inputs/attestation-metadata
```

Add `--reference-benchmarks-dir /absolute/path/to/release-evidence-inputs/benchmarks`
only when optional benchmark evidence is available.

## Workflow Hygiene

GitHub Actions are pinned manually rather than through a bot. When bumping an
action:

1. resolve the current tag to a full commit SHA
2. update the `uses:` line and keep the major tag as an inline comment
3. rerun `zizmor .github/workflows`

Every workflow checkout step should also keep `persist-credentials: false` and
`fetch-depth: 1` unless a job has a documented need for more history.

## Profile Intent

- `pr`
  - fast deterministic suite for local development and pull requests
  - Rust tests, docs tests, feature/package/dependency/docs checks, runtime
    smoke tests, generated interface drift checks, browser WASM structural
    hygiene, and lightweight parity coverage
- `nightly`
  - everything in `pr`, plus full browser parity comparison, CI trend
    performance capture, optional manual mobile evidence ingestion, and other
    slower regression checks
- `release`
  - release-mode evidence capture on top of the nightly assurance catalog,
    including richer parity evidence, signed-manifest validation, SBOMs,
    verified attestations, canonical Linux browser package artifact validation,
    packaged-artifact smoke, and optional benchmark ingestion
- `audit`
  - not a separate execution profile; use `--report-mode audit` with
    `--profile release` for grouped findings and raw evidence references

Dedicated fuzz execution now lives in `.github/workflows/assurance-fuzz.yml`
instead of being buried inside the generic nightly workflow. The shared catalog
still owns the fuzz checks, but nightly and release can skip them explicitly
when the signal belongs in the dedicated fuzz lane.

## Outputs

The output directory contains:

- `assurance-index.json`
- `environment.json`
- `findings.md`
- `checks/*.json`
- `logs/*.log`

Depending on the selected profile and runtime, it may also include:

- `*-withdraw-stable.json`
- `*-goldens-comparison.json`
- `react-native-goldens-comparison.json`
- `v1-rust-comparison.json`
- `v1-rust-parity-rust.json`
- `v1-npm-comparison.json`
- `v1-npm-comparison-smoke.json`

## External Evidence Layout

Release and audit mode ingest one external evidence directory with this layout:

```text
external-evidence/
  mobile-smoke.json
  mobile-parity.json
  attestations.json
  attestation-verification/
    **/*.json
  packages/
    sdk/
      *.tgz
      privacy_pools_sdk_web_bg.wasm
    react-native/
      *.tgz
      ios/
      android/
    circuits/
      *.tar.gz
  signed-manifest/
    payload.json
    signature
    artifacts/
  sbom/
    rust.cdx.json
    sdk.spdx.json
    react-native.spdx.json
  benchmarks/                # optional informational reports
    *.json
```

Nightly assurance uses the same `mobile-smoke.json` and `mobile-parity.json`
contract and can optionally ingest `reference-benchmarks-stable`. Missing,
stale, or incomplete benchmark artifacts are reported as informational
freshness status rather than blocking the run.

`mobile-smoke.json` records aggregate `ios` and `android` status plus explicit
surface status for `iosNative`, `iosReactNative`, `androidNative`, and
`androidReactNative`. Each platform passes only when both of that platform's
surfaces pass. It also carries an explicit evidence identity:

- hosted: `source=github-workflow`, `workflow=mobile-smoke`, `run_url=https://...`
- local: `source=local-xtask`, `workflow=mobile-smoke-local`, `run_url=local://mobile-smoke-local`

`mobile-parity.json` now rolls up the same four structured surface reports
under `ios.native`, `ios.reactNative`, `android.native`, and
`android.reactNative`. Those nested reports carry the machine-readable smoke,
parity, and benchmark sections used by `mobile-evidence-check`.

`attestations.json` is an array of records with:

- `subjectPath`
- `sha256`
- `attestationUrl`
- `workflowRunUrl`
- `verificationPath`

Each `verificationPath` points at a saved verified-attestation JSON file inside
`attestation-verification/`. Release assurance validates those saved
verification results offline and still re-hashes the local packaged subjects as
an independent guardrail.

In fast PR browser runs, the generated check only enforces deterministic
interface outputs (`.js`, `.d.ts`, `.wasm.d.ts`) plus raw WASM structural
invariants. Exact packaged browser `privacy_pools_sdk_web_bg.wasm` identity is
validated in the canonical Linux release packaging path by comparing the npm
tarball's embedded artifact against the exported browser WASM artifact and its
attestation metadata.

## Current Assessment

Standard-mode `findings.md` now begins with a `Current Assessment` section. For
nightly runs, it is the default human-readable answer to “is the SDK healthy
right now?” and records:

- `fundsSafety`
- `semanticAlignment`
- `mobileAppEvidence`
- `ciTrendPerformance`
- `referencePerformance`

`referencePerformance` is:

- `fresh` when manually supplied benchmark evidence matches the nightly commit
- `stale` when benchmark evidence exists but was produced for a different commit
- `missing` when no benchmark artifact is supplied, or when an incomplete set of
  benchmark reports is supplied

`mobileAppEvidence` can be `not-run` in nightly when no same-head mobile
evidence directory is supplied. Nightly still emits the rest of the assurance
bundle so the current safety and semantic-alignment assessment is not blocked
on mobile artifact availability.

Release and audit mode can ingest benchmark evidence when it is available, but
benchmark freshness and threshold failures are informational rather than
blocking.

## Continuous Use

`assurance-nightly.yml` is the scheduled continuous assessment workflow. It
optionally enriches the nightly bundle with manually supplied:

- `mobile-smoke-evidence` or a local directory with the same
  `mobile-smoke.json` / `mobile-parity.json` schema
- `reference-benchmarks-stable`

The heavyweight producer workflows remain on-demand only:

- `mobile-smoke.yml`
- `reference-benchmarks.yml`

Local `cargo run -p xtask -- mobile-smoke-local --platform all --surface all
--evidence-out-dir ...` is the authoritative mobile release gate for this
pre-public repo. `mobile-smoke.yml` remains an optional manual clean-runner
confirmation path for native Swift/XCTest, native Kotlin instrumentation, and
React Native app-process smoke on both platforms.

`assurance-fuzz.yml` is the dedicated scheduled and manually triggerable fuzz
lane. It runs only the
`fuzz-*` catalog checks against the checked-in `fuzz/corpus/**` seed set and
emits a self-contained assurance bundle instead of hiding fuzz depth inside a
broader nightly job.

## Reviewer Guide

For reviewer-facing threat model, invariant, and enforcement guidance, use
[`docs/assurance-review-guide.md`](./assurance-review-guide.md).

## Audit And Governance Sources

- [`security/audit-ledger.md`](../security/audit-ledger.md)
- [`security/advisories.toml`](../security/advisories.toml)
- [`security/assurance-matrix.json`](../security/assurance-matrix.json)
- [`security/unsafe-allowlist.json`](../security/unsafe-allowlist.json)

## Audit Pack Alias

`xtask audit-pack` remains available as a compatibility alias for:

```sh
cargo run -p xtask -- assurance --profile release --runtime all --report-mode audit --external-evidence-dir /absolute/path/to/external-evidence
```

That alias still writes `audit-index.json` alongside `assurance-index.json`.

`xtask evidence-check` remains available as a compatibility alias for validating
that external evidence directory on its own.
