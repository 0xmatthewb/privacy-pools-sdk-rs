use alloy_primitives::U256;
use privacy_pools_sdk_core::Nullifier;

fn require_serialize<T: serde::Serialize>(_: &T) {}

fn main() {
    let nullifier = Nullifier::new(U256::from(1_u64));
    require_serialize(&nullifier);
}
