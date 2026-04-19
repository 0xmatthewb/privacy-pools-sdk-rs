# Canary Rollout

Use this guide to collect the release evidence required for alpha, beta, rc,
and stable promotion.

## Required Evidence

Before promoting a release channel, collect:

- `mobile-smoke.json` from local `xtask mobile-smoke-local --evidence-out-dir ...`
- `mobile-parity.json` from the same local evidence directory
- the matching SBOMs for Rust, the JS SDK, and React Native
- the matching signed manifest payload, signature, and artifact directory
- the matching release workflow artifacts and attestation records for the same commit
- canary notes covering the rollout scope, success criteria, and any incidents

Optional informational benchmark reports can be attached when they are
available.

## Suggested Evidence Layout

Store evidence in one external bundle that can be uploaded as workflow
artifacts. The current authoritative flow expects:

- local mobile evidence from `xtask mobile-smoke-local --evidence-out-dir ...`
- `release-evidence-inputs-${channel}` from a matching `release.yml` run
- optional `reference-benchmarks-stable` for informational performance review

The assembled external evidence directory still uses this layout:

```text
external-evidence/
  mobile-smoke.json
  mobile-parity.json
  attestations.json
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

`mobile-smoke.json` and `mobile-parity.json` must come from a passing local
all-surface `mobile-smoke-local` run for the same commit. Hosted
`mobile-smoke-evidence` remains optional secondary confirmation when you want a
clean-runner check. `mobile-smoke.json` records the evidence source, workflow
name, run URL, and passed iOS and Android platform statuses, plus per-surface
status for iOS native, iOS React Native, Android native, and Android React
Native. `mobile-parity.json` adds the machine-readable parity rollups for
those same four surface reports.

SDK signed artifact manifests are separate from GitHub artifact attestations.
When `signed-manifest/payload.json` is present, the assurance runner verifies
the Ed25519 detached signature over those exact UTF-8 payload bytes using the
configured public key, then verifies each artifact SHA-256 from the unsigned
`ArtifactManifest` embedded in the signed payload.

For the local release audit, configure
`PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY` or pass
`--signed-manifest-public-key`.

## Benchmark Capture

Use the benchmark CLI documented in `docs/benchmarking.md` with a real verified
artifact manifest:

```sh
cargo run --release -p privacy-pools-sdk-cli -- benchmark-withdraw \
  --manifest /absolute/path/to/artifact-manifest.json \
  --artifacts-root /absolute/path/to/artifacts \
  --backend stable \
  --warmup 1 \
  --iterations 5 \
  --report-json ./desktop-withdraw-stable.json \
  --device-label desktop \
  --device-model "apple-m4-max"
```

After the benchmark reports, mobile smoke/parity evidence, SBOMs, signed
manifest, and attestations are assembled in one directory, validate the bundle
with:

```sh
cargo run -p xtask -- evidence-check \
  --channel alpha \
  --dir /absolute/path/to/external-evidence \
  --signed-manifest-public-key <ed25519-public-key-hex>
```

or:

```sh
cargo run -p xtask -- assurance \
  --profile release \
  --runtime all \
  --report-mode audit \
  --external-evidence-dir /absolute/path/to/external-evidence
```

`assurance-nightly.yml` is the scheduled continuous assessment workflow, but it
does not replace these release evidence requirements. Promotion still requires
matching local mobile evidence for the candidate commit. Optional benchmark
artifacts can be attached to the same bundle when you want performance context.

## Canary Stages

Use the rollout order from the execution plan:

1. read-only and recovery
2. proving and verification
3. transaction planning
4. limited sign/broadcast canary
5. general availability

For each stage, record:

- commit and package version
- target network and pool addresses
- number of sessions or test runs
- whether all preflight/root checks passed
- any proof failures, signing mismatches, or broadcast issues

## Promotion Rule

Do not promote a channel on build status alone. Promotion should require:

- green CI for Rust and release packaging
- passed local `mobile-smoke.json` and `mobile-parity.json` evidence for the
  same commit
- acceptable canary notes for the current rollout stage

Hosted `mobile-smoke.yml` is an optional manual clean-runner confirmation, not
the primary promotion gate.
