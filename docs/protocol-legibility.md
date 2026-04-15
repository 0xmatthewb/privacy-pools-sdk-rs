# Protocol Legibility

This note records the Rust SDK naming pass against the npm-published
`@0xbow/privacy-pools-core-sdk@1.2.0` package. On April 15, 2026, npm reported
`1.2.0` as the `latest` dist-tag.

The goal is for human developers and coding agents to read the SDK in the same
shape as the Privacy Pools protocol: deposit, withdraw, relay, ragequit, recover.
Lower-level names remain when they are real cryptographic, circuit, artifact, or
wire objects.

## Naming Rules

| Protocol contour | npm v1.2.0 language | Rust SDK decision |
| --- | --- | --- |
| Deposit setup | `generateDepositSecrets`, `createDepositSecrets` | Keep `generate_deposit_secrets*`; prefer `DepositCommitmentRequest` and `create_deposit_commitment*` for constructing the commitment created by a deposit. |
| Commitment object | `Commitment`, `CommitmentPreimage`, `Precommitment` | Keep `Commitment`, `CommitmentPreimage`, and `Precommitment`; these are protocol state and witness objects, not user actions. |
| Commitment circuit | `CommitmentService.proveCommitment` | Keep `prove_commitment*` as the circuit-facing API, but add `prove_ragequit*` aliases because the public protocol action that consumes this proof is ragequit. |
| Withdrawal | `Withdrawal`, `WithdrawalService.proveWithdrawal` | Keep `Withdrawal` and withdrawal-named APIs. Rust uses `processor`; serde preserves the deployed `processooor` key. |
| Relay | `relay(withdrawal, proof, scope)` | Keep relay transaction planning separate from direct withdrawal planning, because relay targets Entrypoint while direct withdraw targets the pool. |
| Ragequit | `ragequit(commitmentProof, privacyPoolAddress)` | Keep `plan_ragequit_transaction*`; prefer `prove_ragequit*` when producing the proof for that transaction. |
| Recovery | `PoolAccount.deposit`, `children`, `ragequit`, spendable commitments | Keep explicit deposit/children/ragequit account state instead of flattening recovered state into opaque balances. |

## Decision

Do not rename the `Commitment` type to `Deposit`. A deposit creates an initial
commitment, but withdrawals also create child commitments, and ragequit proves a
commitment publicly. Renaming the state object would make withdrawal and
recovery flows less legible.

Instead, the Rust facade exposes action-facing helpers where developers start:

- derive deposit secrets
- create a deposit commitment
- prove withdrawal or ragequit
- plan withdraw, relay, or ragequit transactions
- recover account state from deposit, withdrawal, and ragequit events

The lower-level `commitment` name remains visible around the circuit artifact and
cryptographic state object so agents can still map Rust code back to deployed
circuits, public signals, and npm v1.2.0 compatibility behavior.
