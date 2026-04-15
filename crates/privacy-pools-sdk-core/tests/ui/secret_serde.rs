use alloy_primitives::U256;
use privacy_pools_sdk_core::{MasterKeys, Secret};

fn main() {
    let secret = Secret::new(U256::from(1_u64));
    let _ = serde_json::to_string(&secret).unwrap();

    let keys = MasterKeys {
        master_nullifier: Secret::new(U256::from(2_u64)),
        master_secret: Secret::new(U256::from(3_u64)),
    };
    let _ = serde_json::to_string(&keys).unwrap();
}
