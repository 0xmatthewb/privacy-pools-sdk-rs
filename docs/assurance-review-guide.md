# Assurance Review Guide

Use this guide when reviewing changes that touch proving, artifacts, execution
policy, wrappers, or release automation. It is intentionally reviewer-facing:
[`docs/assurance.md`](./assurance.md) explains how to run the suite, while this
document explains what the suite is defending.

## Scope And Threat Model

The SDK is security-sensitive client infrastructure. Review with the assumption
that a regression can affect:

- funds safety
- artifact authenticity and circuit integrity
- proof correctness or fail-closed behavior
- transaction execution policy
- signer boundary integrity
- wrapper parity across Rust, browser, Node, iOS, Android, and React Native
- release provenance and artifact trust

The SDK does not own deployed contracts or circuits, but it does decide whether
to trust local artifacts, RPC responses, signed manifests, prepared proofs, and
execution metadata before a transaction is signed or broadcast.

## Attack Surfaces

- Rust core protocol types and wire conversions
- signed-manifest verification and artifact hash binding
- prover and verifier input shaping
- Merkle witness derivation and canonicalization
- transaction planning, preflight, finalization, and submission validation
- browser, Node, FFI, and React Native wrapper boundaries
- GitHub workflow trust, package metadata, SBOMs, and provenance evidence

## Non-Negotiable Invariants

- Funds safety:
  malformed proofs, malformed public signals, malformed manifests, and mismatched
  artifacts must fail closed.
- Signed-manifest binding:
  payload signature verification and artifact SHA-256 verification must remain
  coupled.
- Artifact integrity:
  packaged artifacts, signed-manifest fixtures, and release evidence must agree
  on digests and subject paths.
- Execution-policy rejection:
  wrong chain id, wrong root, wrong code hash, and wrong signer must fail before
  submission.
- Secret hygiene:
  secret-bearing Rust types must stay redacted in debug/serde surfaces.
- Wrapper parity:
  runtime surfaces must preserve the same typed behavior, error semantics, and
  fail-closed guarantees as the Rust core.
- Release trust:
  release evidence must bind packaged subjects to verified provenance, SBOMs,
  signed-manifest evidence, and mobile/browser package validation.

## Enforcement Map

Use these files as the source of truth for where invariants are enforced:

- [`security/assurance-matrix.json`](../security/assurance-matrix.json)
  maps scenario tags to runtime/profile coverage.
- [`security/advisories.toml`](../security/advisories.toml)
  is the accepted advisory policy source of truth.
- [`security/unsafe-allowlist.json`](../security/unsafe-allowlist.json)
  tracks the narrow unsafe surface policy.
- [`docs/release-process.md`](./release-process.md)
  explains the release evidence contract.

High-signal enforcement layers today:

- Rust deterministic safety checks:
  `rust-malformed-input-check`, `rust-secret-hardening-check`,
  `rust-verified-proof-safety-check`, `rust-chain-rejection-checks`
- Artifact and manifest integrity:
  `artifact-fingerprints`, `signed-manifest-sample-check`,
  `mobile-evidence-check`, release evidence validation in `xtask`
- Wrapper/runtime parity:
  `compare-rust-goldens-rust`, `compare-rust-goldens-browser`,
  `compare-rust-goldens-react-native`, browser/mobile app evidence
- Deep assurance:
  nightly/release browser suites, mobile four-surface evidence,
  `cargo-deny-advisories`, `cargo-vet`, mutation testing
- Dedicated fuzz:
  `.github/workflows/assurance-fuzz.yml` and `fuzz/corpus/**`

## How To Review A Risky Change

- Proving, verifier, or wire-shape change:
  confirm deterministic vector tests still pass, property/fuzz coverage still
  exists, and wrapper-visible shapes remain stable.
- Artifact or manifest change:
  confirm signed-manifest verification still binds exact payload bytes and exact
  artifact digests; check packaged-artifact validation, not just source-tree
  tests.
- Execution or chain logic change:
  confirm wrong root / chain id / code hash / signer rejections still exist in
  Rust and mobile/browser release evidence.
- Wrapper or FFI change:
  confirm generated surface drift checks, parity comparisons, and app-process
  smoke evidence still map to the same scenarios.
- Workflow or release change:
  confirm provenance verification, attestation subject paths, SBOMs, package
  smoke, and audit bundle review steps still line up.

## What Must Block Merge

- Any regression in a non-negotiable invariant above.
- Any PR-lane failure for deterministic correctness, packaging, docs-policy, or
  fail-closed behavior.
- Any change that narrows reviewability or removes attribution from assurance
  output without replacing the signal elsewhere.

These are not merge blockers for every PR, but they are release blockers:

- mobile four-surface evidence
- release provenance / SBOM / package evidence
- dedicated fuzz coverage
- `cargo-vet`
- `cargo-deny advisories`

## Known Gaps And Follow-Ups

- No external cryptographic or application security audit has completed yet.
- Stateful Rust-vs-wrapper differential testing now exists for Node and React
  Native, but it still needs same-head nightly/release workflow proof and
  eventual expansion to broader wrapper lifecycle surfaces.
- Fuzz coverage is now first-class, but it is still concentrated on parsing,
  manifest, and wire boundaries rather than full end-to-end session lifecycles.

Track those gaps in [`security/audit-ledger.md`](../security/audit-ledger.md)
and use
[`security/external-audit-readiness.md`](../security/external-audit-readiness.md)
when preparing an external review.
