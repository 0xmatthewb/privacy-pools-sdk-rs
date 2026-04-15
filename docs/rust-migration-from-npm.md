# Rust Migration From npm v1.2.0

This guide maps the mental model from `@0xbow/privacy-pools-core-sdk@1.2.0`
to the Rust crate published as `privacy-pools-sdk`.

The Rust API is intentionally not a source-compatible port of the TypeScript
surface. It keeps wire/package compatibility where applications exchange
payloads with existing JS, Node, browser, mobile, contract, or circuit flows,
but it uses protocol-legible Rust names for new code.

## Name Mapping

| npm v1.2.0 habit | Preferred Rust API | Why |
| --- | --- | --- |
| `generateMasterKeys` | `PrivacyPoolsSdk::generate_master_keys` | Same full-width key derivation semantics as npm v1.2.0. |
| `generateDepositSecrets` | `PrivacyPoolsSdk::prepare_deposit` | Deposits submit a precommitment hash; the prepared deposit retains redacted material for later proving. |
| `getCommitment` | `PrivacyPoolsSdk::build_commitment` | A commitment is built once value, label, nullifier, and secret are known. |
| `calculateContext` | `PrivacyPoolsSdk::calculate_withdrawal_context` | The context is specifically the withdrawal context public signal. |
| `Withdrawal.processooor` | `Withdrawal::processor` / `Withdrawal::direct` / `Withdrawal::relayed` | Rust uses the correct spelling while serde keeps the deployed wire key. |
| `nullifierHash` on commitments | `Commitment::precommitment_hash` field | This hash is `Poseidon(nullifier, secret)`, not the true spent-nullifier hash. |
| spent nullifier hash | `PrivacyPoolsSdk::compute_nullifier_hash` | This is the public signal used for spend detection. |

## Example Translation

```rust
use alloy_primitives::{U256, address};
use privacy_pools_sdk::{DepositRequest, PrivacyPoolsSdk, core::Withdrawal};

let sdk = PrivacyPoolsSdk::default();
let keys = sdk.generate_master_keys(
    "test test test test test test test test test test test junk",
)?;

let prepared = sdk.prepare_deposit_with(DepositRequest {
    keys: &keys,
    scope: U256::from(123_u64),
    index: U256::ZERO,
})?;

let commitment = sdk.build_commitment_with(
    prepared.commitment_request(U256::from(1_000_u64), U256::from(456_u64)),
)?;

let withdrawal = Withdrawal::direct(address!("1111111111111111111111111111111111111111"));
let context = sdk.calculate_withdrawal_context(&withdrawal, U256::from(123_u64))?;

assert_eq!(commitment.precommitment_hash, prepared.precommitment_hash());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Compatibility Boundary

The JS, Node, browser, FFI, and mobile surfaces may keep v1-compatible exported
names such as `getCommitment` where that helps existing applications migrate.
The Rust API does not keep unreleased aliases like `get_commitment` or
`calculate_context`; Rust callers should use the protocol names above.

Serialized payloads remain compatible where the protocol requires it. For
example, `Withdrawal` serializes the deployed `processooor` key and accepts
`processor` during deserialization.
