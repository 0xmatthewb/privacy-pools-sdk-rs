use alloy_primitives::{U256, b256};
use privacy_pools_sdk::{
    PrivacyPoolsSdk, crypto,
    recovery::{
        CompatibilityMode, DepositEvent, PoolRecoveryInput, RecoveryPolicy, WithdrawalEvent,
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    let sdk = PrivacyPoolsSdk::default();
    let safe_keys = sdk.generate_master_keys(MNEMONIC)?;
    let legacy_keys = crypto::generate_legacy_master_keys(MNEMONIC)?;
    let scope = U256::from(123_u64);
    let label = U256::from(777_u64);
    let value = U256::from(1_000_u64);

    let (legacy_nullifier, legacy_secret) =
        crypto::generate_deposit_secrets(&legacy_keys, scope, U256::ZERO)?;
    let legacy_deposit = sdk.build_commitment(value, label, &legacy_nullifier, legacy_secret)?;

    let (safe_nullifier, safe_secret) =
        crypto::generate_withdrawal_secrets(&safe_keys, label, U256::ZERO)?;
    let migrated_commitment = sdk.build_commitment(value, label, safe_nullifier, safe_secret)?;

    let pool = PoolRecoveryInput {
        scope,
        deposit_events: vec![DepositEvent {
            commitment_hash: legacy_deposit.hash,
            label,
            value,
            precommitment_hash: legacy_deposit.preimage.precommitment.hash,
            block_number: 10,
            transaction_hash: b256!(
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
        }],
        withdrawal_events: vec![WithdrawalEvent {
            withdrawn_value: U256::ZERO,
            spent_nullifier_hash: sdk.compute_nullifier_hash(&legacy_nullifier)?,
            new_commitment_hash: migrated_commitment.hash,
            block_number: 20,
            transaction_hash: b256!(
                "0000000000000000000000000000000000000000000000000000000000000002"
            ),
        }],
        ragequit_events: Vec::new(),
    };

    let recovered = sdk.recover_account_state(
        MNEMONIC,
        &[pool],
        RecoveryPolicy {
            compatibility_mode: CompatibilityMode::Legacy,
            fail_closed: true,
        },
    )?;
    let spendable = recovered.safe_spendable_commitments();

    println!("safe recovery scopes: {}", recovered.safe_scopes.len());
    println!("legacy recovery scopes: {}", recovered.legacy_scopes.len());
    println!("safe spendable scopes: {}", spendable.len());
    println!(
        "recovered current commitment: {}",
        spendable[0].commitments[0].hash
    );

    Ok(())
}
