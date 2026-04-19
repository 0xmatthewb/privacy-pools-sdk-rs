# Security Policy

## Supported Versions

The SDK is currently in alpha. Security fixes are made on the latest published
alpha line only unless a production integrator coordinates a backport with the
maintainers. Pre-release package surfaces should be pinned exactly by
applications.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately to the maintainers before
opening a public issue or posting exploit details. Include:

- affected SDK version or commit
- affected runtime surface, such as Rust, Node, browser, iOS, Android, or React Native
- a minimal reproduction or proof sketch
- whether funds, keys, witnesses, proofs, or transaction execution can be affected
- whether the issue requires a malicious artifact, compromised RPC response,
  malformed event stream, or application signer misuse

The maintainers will acknowledge receipt, investigate impact, and coordinate a
fix and disclosure timeline.

## Current Security Posture

This repository has not completed an external cryptographic or application
security audit. The SDK implements defensive checks, but it is not a substitute
for an audit of Privacy Pools applications, deployment configuration, custody
flows, or the deployed contracts and circuits.

Current safeguards include:

- pinned circuit artifact manifests and hash verification
- witness and public-signal compatibility checks before execution planning
- redacted Rust secret and nullifier types for debug output
- explicit signer/client boundaries with no hidden private-key custody shortcuts
- chain preflight checks for chain identity, roots, code hashes, calldata, and
  execution assumptions
- shared Rust protocol logic across browser, Node, iOS, Android, and React
  Native package surfaces

Dependency advisory status is tracked in
[`security/advisories.toml`](security/advisories.toml). Release checks fail if
the accepted advisory ID set drifts without updating that policy and the
derived `deny.toml` / docs checks.

## Security Governance

- Reviewer-facing invariant and threat-model guidance:
  [`docs/assurance-review-guide.md`](docs/assurance-review-guide.md)
- Internal audit and risk tracking:
  [`security/audit-ledger.md`](security/audit-ledger.md)
- External audit handoff checklist:
  [`security/external-audit-readiness.md`](security/external-audit-readiness.md)
- Machine-readable assurance coverage policy:
  [`security/assurance-matrix.json`](security/assurance-matrix.json)
- Unsafe surface policy:
  [`security/unsafe-allowlist.json`](security/unsafe-allowlist.json)

## Audit Status

The SDK is publish-ready alpha software, not audited production custody
software. Treat the Rust SDK, JS package, mobile bindings, and React Native
package as security-sensitive infrastructure that requires application-level
review before mainnet funds are exposed.

See [`security/audit-ledger.md`](security/audit-ledger.md) for the current
internal review record, open findings, and accepted residual risks.
