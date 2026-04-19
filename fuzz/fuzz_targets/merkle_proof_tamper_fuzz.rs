#![no_main]

use alloy_primitives::U256;
use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_tree::{generate_merkle_proof, verify_merkle_proof};

const LEAVES: [U256; 5] = [
    U256::from_limbs([11, 0, 0, 0]),
    U256::from_limbs([22, 0, 0, 0]),
    U256::from_limbs([33, 0, 0, 0]),
    U256::from_limbs([44, 0, 0, 0]),
    U256::from_limbs([55, 0, 0, 0]),
];
const TARGET_LEAF: U256 = U256::from_limbs([44, 0, 0, 0]);

fuzz_target!(|data: &[u8]| {
    let proof = generate_merkle_proof(&LEAVES, TARGET_LEAF).expect("fixture proof should build");
    let mut tampered = proof.clone();

    for (index, byte) in data.iter().take(64).enumerate() {
        match index % 4 {
            0 => tampered.root ^= U256::from(*byte),
            1 => tampered.leaf ^= U256::from(*byte),
            2 => tampered.index ^= usize::from(*byte & 0x0f),
            _ => {
                let sibling_index = index % tampered.siblings.len();
                if let Some(sibling) = tampered.siblings.get_mut(sibling_index) {
                    *sibling ^= U256::from(*byte);
                }
            }
        }
    }

    if data.is_empty() || data.iter().all(|byte| *byte == 0) {
        assert!(
            verify_merkle_proof(&tampered),
            "untampered proof should verify"
        );
    } else {
        assert!(
            !verify_merkle_proof(&tampered),
            "tampered proof should be rejected"
        );
    }
});
