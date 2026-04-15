use alloy_primitives::U256;
use privacy_pools_sdk_core::{Nullifier, Secret};

fn main() {
    let _ = Secret::new(U256::from(1_u64)) < Secret::new(U256::from(2_u64));
    let _ = Nullifier::new(U256::from(1_u64)) < Nullifier::new(U256::from(2_u64));
}
