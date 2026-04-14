# Compatibility Baseline

This repository targets protocol and wire compatibility with the published
`@0xbow/privacy-pools-core-sdk@1.2.0` package, with one mandatory semantic fix
from `0xbow-io/privacy-pools-core#122`.

## Baseline rules

- Preserve commitment, withdrawal, Merkle, proof-shaping, and calldata behavior
  expected by the deployed contracts and circuits.
- Preserve LeanIMT proof semantics, including dynamic sibling omission and
  circuit-facing sibling padding.
- Preserve mnemonic-to-account derivation behavior compatible with the existing
  SDK account index usage.
- Do not preserve known SDK bugs or unsafe defaults.

## Mandatory corrections carried forward

### State root semantics

The Rust SDK must treat the pool state root as:

- read from the Privacy Pool contract
- using `currentRoot()`
- not read from Entrypoint `latestRoot()`

This is the behavior proposed in `privacy-pools-core#122`, and it is a required
baseline even if the upstream TypeScript SDK has not yet released it.

### Unsafe defaults not carried forward

- No mutable `latest` artifact resolution in trusted paths
- No raw private-key-first signing API as the primary SDK experience
- No ambiguous root helpers that blur pool state roots and ASP roots

## Reference sources

- Local npm bundle:
  `/Users/matthewb/Documents/0xbow/v1 SDK/npm/privacy-pools-core-sdk-1.2.0/package`
- Upstream source workspace:
  `/Users/matthewb/Documents/0xbow/v1 SDK/privacy-pools-core`
