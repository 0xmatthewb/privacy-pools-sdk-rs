use alloy_primitives::{U256, address, bytes};
use privacy_pools_sdk::{
    CommitmentRequest, DepositSecretsRequest, PrivacyPoolsSdk, core::Withdrawal,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk = PrivacyPoolsSdk::default();
    let keys =
        sdk.generate_master_keys("test test test test test test test test test test test junk")?;

    let (nullifier, secret) = sdk.generate_deposit_secrets_with(DepositSecretsRequest {
        keys: &keys,
        scope: U256::from(123_u64),
        index: U256::ZERO,
    })?;

    let commitment = sdk.get_commitment_with(CommitmentRequest::new(
        U256::from(1_000_u64),
        U256::from(456_u64),
        nullifier,
        secret,
    ))?;

    let withdrawal = Withdrawal::new(
        address!("1111111111111111111111111111111111111111"),
        bytes!("1234"),
    );
    let context = sdk.calculate_context(&withdrawal, U256::from(123_u64))?;

    println!("sdk version: {}", PrivacyPoolsSdk::version());
    println!("commitment hash: {}", commitment.hash);
    println!("withdrawal context: {context}");
    println!("withdrawal processor: {}", withdrawal.processor());

    Ok(())
}
