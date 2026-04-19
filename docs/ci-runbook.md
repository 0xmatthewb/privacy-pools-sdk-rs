# CI Runbook

When CI is red, classify the failure first:

- Phase A/B style merge blockers: deterministic Rust, browser artifact, mobile smoke, or fuzz failures.
- Phase C/D structural drift: bindings, error-surface, parser, or `xtask` regressions.
- Phase E/F guardrail drift: generated freshness, cycle checks, lockfile policy, nextest, or toolchain canary failures.

Suggested triage order:

1. Reproduce with `cargo run -p xtask -- preflight` when the failure is part of the Rust PR lane.
2. If generated artifacts drifted, run `cargo run -p xtask -- regenerate-generated` and inspect the diff before retrying CI.
3. If CI-only policy checks fail, run the corresponding `xtask` command directly:
   `action-pins`, `check-internal-cycles`, `write-cargo-audit-config`, or `artifact-fingerprints`.
4. If the failure is mobile-only, review `mobile-smoke` evidence before changing code paths that are already green on desktop.
5. If the failure is toolchain-related, consult [`toolchain-upgrade-protocol.md`](toolchain-upgrade-protocol.md).

Map recurring failure classes back to the preventive controls:

- Schema drift: `generated-freshness`, schema-aware freshness, and binding parity.
- Tool drift: `--locked`, canary clippy, and the upgrade sweep.
- Local-vs-CI mismatch: `preflight`.
- Flake: nextest retries, JUnit artifacts, and `mobile-smoke` evidence.
