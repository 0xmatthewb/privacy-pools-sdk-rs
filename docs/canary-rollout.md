# Canary Rollout

This repository now has the build, packaging, and smoke-test plumbing needed to
collect real release evidence. The remaining work for alpha, beta, rc, and
stable promotion is operational: run the SDK on real devices, record benchmark
reports, and capture limited canary usage evidence before widening rollout.

## Required evidence

Before promoting a release channel, collect:

- a desktop `benchmark-withdraw --report-json` report
- an iOS device `benchmark-withdraw --report-json` report
- an Android device `benchmark-withdraw --report-json` report
- the matching release workflow artifacts for the same commit
- canary notes covering the rollout scope, success criteria, and any incidents

## Suggested evidence layout

Store evidence outside the repo or in an internal release bucket using a layout
like:

```text
release-evidence/
  0.1.0-alpha.1/
    commit.txt
    desktop-withdraw-stable.json
    ios-withdraw-stable.json
    android-withdraw-stable.json
    release-artifacts.txt
    canary-notes.md
```

## Benchmark capture

Use the benchmark CLI documented in `docs/benchmarking.md` with a real verified
artifact manifest:

```sh
cargo run -p privacy-pools-sdk-cli -- benchmark-withdraw \
  --manifest /absolute/path/to/artifact-manifest.json \
  --artifacts-root /absolute/path/to/artifacts \
  --backend stable \
  --warmup 1 \
  --iterations 5 \
  --report-json ./desktop-withdraw-stable.json
```

Repeat the same capture on one recent iPhone and one recent Android flagship.

## Canary stages

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

## Promotion rule

Do not promote a channel on build status alone. Promotion should require:

- green CI for Rust, RN packaging, RN sample-app smoke, and native release smoke
- benchmark reports from desktop, iOS, and Android for the same commit
- acceptable canary notes for the current rollout stage
