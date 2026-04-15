use alloy_primitives::{U256, address};
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    core::{RelayData, Withdrawal},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk = PrivacyPoolsSdk::default();
    let scope = U256::from(123_u64);
    let recipient = address!("1111111111111111111111111111111111111111");
    let fee_recipient = address!("2222222222222222222222222222222222222222");
    let entrypoint = address!("3333333333333333333333333333333333333333");

    let direct = Withdrawal::direct(recipient);
    let relay_data = RelayData::new(recipient, fee_recipient, U256::from(25_u64));
    let relayed = Withdrawal::relayed(entrypoint, &relay_data);

    let direct_context = sdk.calculate_withdrawal_context(&direct, scope)?;
    let relayed_context = sdk.calculate_withdrawal_context(&relayed, scope)?;

    println!("direct processor: {}", direct.processor());
    println!("direct withdrawal context: {direct_context}");
    println!("relayed processor: {}", relayed.processor());
    println!("relayed data bytes: {}", relayed.data.len());
    println!("relayed withdrawal context: {relayed_context}");

    Ok(())
}
