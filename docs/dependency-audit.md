# Dependency Audit Notes

The workspace runs both `cargo deny` and `cargo audit` in CI. Today, the audit
output still contains three accepted transitive warnings:

- `RUSTSEC-2024-0388` for `derivative`
- `RUSTSEC-2024-0436` for `paste`
- `RUSTSEC-2026-0097` for `rand 0.8.5`

These are not direct workspace dependencies. They currently enter through the
proving stack (`circom-prover` and arkworks) and the Ethereum client stack
(`alloy` and related crates).

## Current Policy

The repo treats these warnings as explicit residual risk, not silent ignores:

- `deny.toml` suppresses the accepted advisory IDs that do not have a safe
  semver-compatible fix yet
- `xtask dependency-check` verifies that the advisory set is exactly the one
  listed above
- the check fails if a new advisory appears, if one of the accepted warnings
  changes unexpectedly, or if `cargo audit` starts reporting blocking
  vulnerabilities
- for `RUSTSEC-2026-0097`, the check also verifies that the reachable unsound
  condition is still absent by asserting that `rand 0.8.5` is not built with
  the `log` feature

## What This Does Not Solve

This does not eliminate the upstream risk. To fully remove these warnings, one
or more of the following must happen:

- `circom-prover` / arkworks move off `derivative`
- `alloy` and other macro-heavy transitive crates move off `paste`
- the signer and proving stacks move to `rand >= 0.9.3` or otherwise remove the
  affected `rand 0.8.5` path

If a production rollout requires eliminating those warnings entirely, that work
likely means upstream upgrades, maintained forks, or both.
