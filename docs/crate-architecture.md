# Crate Architecture

The repository is named `privacy-pools-sdk-rs`; the public Rust crate is named
`privacy-pools-sdk` and is imported as `privacy_pools_sdk`. The Rust crate graph
keeps protocol concepts in small crates, then exposes one facade for
application developers and agents.

## Crate Roles

| Crate | Role | Publish policy | Notes |
| --- | --- | --- | --- |
| `privacy-pools-sdk` | Rust facade for deposits, commitments, withdrawals, ragequit, recovery, proving, transaction planning, and client defaults. | Publishable | Main developer entry point. |
| `privacy-pools-sdk-core` | Protocol data types, ABI-compatible payloads, redacted secret types, public proof and transaction shapes. | Publishable | Keeps wire compatibility such as serialized `processooor`. |
| `privacy-pools-sdk-crypto` | Key derivation, precommitment hashing, nullifier hashing, commitment construction, and withdrawal context hashing. | Publishable | Cryptographic helpers stay protocol-named. |
| `privacy-pools-sdk-tree` | LeanIMT proof helpers. | Publishable | Focused Merkle witness crate. |
| `privacy-pools-sdk-artifacts` | Artifact manifest parsing, pinning, and hash verification. | Publishable | Shared by Rust and package surfaces. |
| `privacy-pools-sdk-prover` | Arkworks proving, optional native witness generation, optional Rapidsnark backend policy, and proof verification hooks. | Publishable | Default feature includes `native-witness` on supported native targets. |
| `privacy-pools-sdk-verifier` | Verification key parsing and Groth16 verifier preparation. | Publishable | Used by proving and runtime preflight. |
| `privacy-pools-sdk-circuits` | Circuit input validation and signal compatibility checks. | Publishable | Enforces protocol shape before proving and execution. |
| `privacy-pools-sdk-recovery` | Account recovery replay from deposit, withdrawal, and ragequit events. | Publishable | Preserves the v1 migration behavior while exposing Rust-native names. |
| `privacy-pools-sdk-chain` | Contract bindings, transaction planning, preflight, and chain-client traits. | Publishable | Owns chain interaction without owning private keys. |
| `privacy-pools-sdk-signer` | Explicit signer trait integration and signed transaction boundaries. | Publishable | No hidden private-key custody shortcuts. |
| `privacy-pools-sdk-ffi` | UniFFI surface for iOS and Android. | Not published to crates.io | Package surface generated from the Rust core. |
| `privacy-pools-sdk-web` | Browser WASM package surface. | Not published to crates.io | Compiled and bundled through `packages/sdk`. |
| `privacy-pools-sdk-node` | Node native package surface. | Not published to crates.io | The single documented unsafe exception for N-API bindings. |
| `privacy-pools-sdk-cli` | Local tooling and smoke helpers. | Not published to crates.io | Developer tool, not a runtime dependency. |
| `xtask` | Workspace automation for bindings, package checks, release checks, and smoke tests. | Not published to crates.io | CI and release command surface. |

## Architectural Boundaries

- Protocol names live in Rust: `prepare_deposit`, `build_commitment`,
  `calculate_withdrawal_context`, `Withdrawal`, `RelayData`, and `Ragequit`
  follow the contracts and circuits rather than package compatibility aliases.
- Wire compatibility remains explicit. Serialized withdrawal payloads still use
  `processooor`, and deserialization accepts the friendlier `processor` spelling
  where payloads cross package or protocol boundaries.
- Secret material uses redacted Rust types. Raw bytes or field elements are only
  exported through explicitly named serialization/export paths.
- Signing is an application boundary. The SDK can plan, preflight, finalize, and
  submit transactions through traits, but it does not hide private-key custody
  inside convenience methods.
- Package surfaces call into the Rust implementation instead of maintaining
  separate protocol logic for browser, Node, iOS, Android, or React Native.

## Lint And Unsafe Policy

Workspace crates inherit the root lint policy with `[lints] workspace = true`.
The default policy forbids unsafe Rust. The only package surface with an unsafe
exception is the Node N-API crate, where native binding glue requires it. Any
new unsafe exception should be documented here with its owning crate, reason,
and review plan before release.

## Publish Closure

Publishable runtime crates carry versioned dependencies alongside local paths so
`privacy-pools-sdk` has a clear crates.io dependency closure. Package-surface
crates, examples, and `xtask` remain unpublished unless a future release plan
requires changing that boundary. See `docs/crates-publish-order.md` for the
publish sequence.
