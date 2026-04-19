# External Audit Readiness

This document tracks how the SDK should be handed to an external auditor before
public production promotion. It does not claim an audit has happened. It exists
to keep the repo auditable and to make the eventual engagement reproducible.

## Target Audit Scope

Audit the highest-risk security surfaces first:

- Rust core protocol types, wire conversions, and fail-closed behavior
- signed-manifest verification and artifact-bundle binding
- prover and verifier request shaping
- session, handle, and cache invalidation behavior
- execution planning, preflight, finalization, and signer-bound submission
- wrapper parity for Node, browser, iOS, Android, and React Native
- release provenance, SBOM, package validation, and workflow trust

Out of scope unless explicitly expanded:

- deployed contract correctness
- circuit construction correctness outside the shipped verifier/artifact contract
- application custody flows built on top of the SDK
- backend services or wallets not owned by this repository

## Auditor Inputs

Prepare these materials for every audit engagement:

- reviewed commit SHA and immutable source archive
- [`docs/assurance-review-guide.md`](../docs/assurance-review-guide.md)
- [`docs/assurance.md`](../docs/assurance.md)
- [`docs/release-process.md`](../docs/release-process.md)
- [`security/assurance-matrix.json`](./assurance-matrix.json)
- [`security/audit-ledger.md`](./audit-ledger.md)
- current `cargo-deny`, `dependency-check`, `zizmor`, provenance, SBOM, and
  mobile/browser evidence artifacts for the reviewed SHA
- current spec fixtures from [`fixtures/spec`](../fixtures/spec)
- current fuzz corpora from [`fuzz/corpus`](../fuzz/corpus)

## Invariants Auditors Should Pressure-Test

- malformed proofs, manifests, artifacts, and public signals fail closed
- signed-manifest verification remains bound to exact artifact digests
- packaged artifacts match verified provenance and release evidence
- session and verified-proof handles cannot be reused after invalidation
- wrong chain id, root, code hash, and signer all fail before submission
- wrapper-visible behavior stays aligned with Rust core semantics
- CI and release automation do not weaken trust boundaries or reviewer clarity

## Engagement Checklist

Before handing the repo to an auditor:

- freeze the reviewed commit/tag and record it in the audit ledger
- generate a fresh release/audit bundle for that exact SHA
- run PR CI, nightly, fuzz, mobile-smoke, and release workflows on that SHA
- confirm the uplift checklist is current and every non-audit engineering row is
  `done`
- bundle open findings, accepted residual risks, and known non-goals
- document any intentionally deferred work so the auditor can distinguish
  backlog from accidental omissions

## Findings Intake

Record every external finding in [`security/audit-ledger.md`](./audit-ledger.md)
with:

- auditor
- reviewed SHA or tag
- finding severity and surface
- remediation owner
- fixed-in commit
- follow-up verification notes

Do not mark the external-audit maturity row complete until:

- at least one external audit has finished
- all blocking findings are remediated or explicitly accepted with rationale
- the release checklist links to the finished audit record

## Exit Criteria

This repo can claim meaningful external-audit process maturity only when:

- the repo has an external audit recorded in the ledger
- the audit scope matches the highest-risk SDK surfaces above
- the reviewed SHA is reproducible from the evidence bundle
- findings are reflected in the assurance matrix, docs, or release process
