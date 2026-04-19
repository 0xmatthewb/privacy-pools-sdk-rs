# Dependency Audit Notes

The workspace runs both `cargo deny` and `cargo audit` in CI. The accepted
advisory policy lives in [`security/advisories.toml`](../security/advisories.toml)
and is mirrored into `deny.toml`, `xtask dependency-check`, and this doc by the
same advisory IDs. Each accepted advisory in that file must also carry an
`owner`, `review_date`, and `exit_condition`.

Broader assurance governance and open security findings are tracked separately
in [`security/audit-ledger.md`](../security/audit-ledger.md).

## Current Policy

Accepted advisories are tracked in three buckets:

- `cargo_audit.ignore`
  - `RUSTSEC-2025-0055`
- `cargo_deny.ignore`
  - `RUSTSEC-2025-0055`
  - `RUSTSEC-2026-0097`
- `dependency_check.warnings`
  - `RUSTSEC-2024-0388` for `derivative`
  - `RUSTSEC-2024-0436` for `paste`
  - `RUSTSEC-2026-0097` for `rand 0.8.5`

These are not direct workspace dependencies. They currently enter through the
proving stack (`circom-prover` and arkworks), the Ethereum client stack
(`alloy` and related crates), and a tolerated transitive advisory that remains
blocked from `cargo audit` and `cargo deny` separately.

`xtask dependency-check` verifies that the advisory policy file, `deny.toml`,
and this doc all agree. The check fails if a new advisory appears, if one of
the accepted warnings changes unexpectedly, if an advisory metadata section is
missing required ownership/review/exit fields, or if `cargo audit` starts
reporting blocking vulnerabilities. For `RUSTSEC-2026-0097`, the check also
verifies that the reachable unsound condition is still absent by asserting
that `rand 0.8.5` is not built with the `log` feature.

## What This Does Not Solve

This does not eliminate the upstream risk. To fully remove these warnings, one
or more of the following must happen:

- `circom-prover` / arkworks move off `derivative`
- `alloy` and other macro-heavy transitive crates move off `paste`
- the signer and proving stacks move to `rand >= 0.9.3` or otherwise remove the
  affected `rand 0.8.5` path

If a production rollout requires eliminating those warnings entirely, that work
likely means upstream upgrades, maintained forks, or both.
