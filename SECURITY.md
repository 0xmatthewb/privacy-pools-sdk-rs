# Security Policy

## Supported Versions

The SDK is currently in alpha. Security fixes are made on the latest published
alpha line only unless a production integrator coordinates a backport with the
maintainers.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately to the maintainers before
opening a public issue. Include:

- affected SDK version or commit
- affected runtime surface, such as Rust, Node, browser, iOS, Android, or React Native
- a minimal reproduction or proof sketch
- whether funds, keys, witnesses, proofs, or transaction execution can be affected

The maintainers will acknowledge receipt, investigate impact, and coordinate a
fix and disclosure timeline.

## Current Security Posture

This repository has not completed an external cryptographic or application
security audit. The SDK verifies pinned circuit artifacts, validates witnesses
and proof public signals before transaction planning, and keeps signer
boundaries explicit, but these checks do not replace an audit of an application
that builds on Privacy Pools.

Dependency advisory status is tracked in
[`docs/dependency-audit.md`](docs/dependency-audit.md).
