use alloy_primitives::{U256, address};
use privacy_pools_sdk::{DepositRequest, PrivacyPoolsSdk, core::Withdrawal};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk = PrivacyPoolsSdk::default();
    let keys =
        sdk.generate_master_keys("test test test test test test test test test test test junk")?;

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

    println!("sdk version: {}", PrivacyPoolsSdk::version());
    println!(
        "deposit precommitment hash: {}",
        prepared.precommitment_hash()
    );
    println!("commitment hash: {}", commitment.hash);
    println!("withdrawal context: {context}");
    println!("withdrawal processor: {}", withdrawal.processor());

    Ok(())
}
