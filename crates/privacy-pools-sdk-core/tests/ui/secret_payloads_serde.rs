use alloy_primitives::U256;
use privacy_pools_sdk_core::{
    Commitment, CommitmentCircuitInput, CommitmentPreimage, CommitmentWitnessRequest,
    Precommitment, Secret, WithdrawalCircuitInput, WithdrawalWitnessRequest,
};

fn require_serialize<T: serde::Serialize>(_: &T) {}

fn main() {
    let commitment = Commitment {
        hash: U256::from(1_u64),
        precommitment_hash: U256::from(2_u64),
        preimage: CommitmentPreimage {
            value: U256::from(3_u64),
            label: U256::from(4_u64),
            precommitment: Precommitment {
                hash: U256::from(2_u64),
                nullifier: U256::from(5_u64).into(),
                secret: Secret::new(U256::from(6_u64)),
            },
        },
    };
    let commitment_request = CommitmentWitnessRequest {
        commitment: commitment.clone(),
    };
    let commitment_input = CommitmentCircuitInput {
        value: U256::from(7_u64),
        label: U256::from(8_u64),
        nullifier: U256::from(9_u64).into(),
        secret: Secret::new(U256::from(10_u64)),
    };
    let withdrawal_request = WithdrawalWitnessRequest {
        commitment,
        withdrawal: privacy_pools_sdk_core::Withdrawal::direct(
            alloy_primitives::address!("1111111111111111111111111111111111111111"),
        ),
        scope: U256::from(11_u64),
        withdrawal_amount: U256::from(12_u64),
        state_witness: privacy_pools_sdk_core::CircuitMerkleWitness {
            root: U256::from(13_u64),
            leaf: U256::from(14_u64),
            index: 0,
            siblings: vec![],
            depth: 0,
        },
        asp_witness: privacy_pools_sdk_core::CircuitMerkleWitness {
            root: U256::from(15_u64),
            leaf: U256::from(16_u64),
            index: 0,
            siblings: vec![],
            depth: 0,
        },
        new_nullifier: U256::from(17_u64).into(),
        new_secret: Secret::new(U256::from(18_u64)),
    };
    let withdrawal_input = WithdrawalCircuitInput {
        withdrawn_value: U256::from(19_u64),
        state_root: U256::from(20_u64),
        state_tree_depth: 1,
        asp_root: U256::from(21_u64),
        asp_tree_depth: 2,
        context: U256::from(22_u64),
        label: U256::from(23_u64),
        existing_value: U256::from(24_u64),
        existing_nullifier: U256::from(25_u64).into(),
        existing_secret: Secret::new(U256::from(26_u64)),
        new_nullifier: U256::from(27_u64).into(),
        new_secret: Secret::new(U256::from(28_u64)),
        state_siblings: vec![],
        state_index: 0,
        asp_siblings: vec![],
        asp_index: 0,
    };

    require_serialize(&commitment);
    require_serialize(&commitment_request);
    require_serialize(&commitment_input);
    require_serialize(&withdrawal_request);
    require_serialize(&withdrawal_input);
}
