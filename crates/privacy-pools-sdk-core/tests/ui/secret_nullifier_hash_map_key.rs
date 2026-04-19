use alloy_primitives::U256;
use privacy_pools_sdk_core::Nullifier;
use std::collections::HashMap;

fn main() {
    let mut values = HashMap::new();
    values.insert(Nullifier::new(U256::from(1_u64)), "nullifier");
}
