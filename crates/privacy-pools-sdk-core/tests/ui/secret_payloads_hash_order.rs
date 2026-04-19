use std::hash::Hash;

use privacy_pools_sdk_core::{
    Commitment, CommitmentCircuitInput, CommitmentWitnessRequest, WithdrawalCircuitInput,
    WithdrawalWitnessRequest,
};

fn require_hash<T: Hash>(_: &T) {}
fn require_order<T: Ord>(_: &T) {}
fn value<T>() -> T {
    panic!("compile-fail placeholder")
}

fn main() {
    let commitment: Commitment = value();
    let commitment_request: CommitmentWitnessRequest = value();
    let withdrawal_request: WithdrawalWitnessRequest = value();
    let commitment_input: CommitmentCircuitInput = value();
    let withdrawal_input: WithdrawalCircuitInput = value();

    require_hash(&commitment);
    require_hash(&commitment_request);
    require_hash(&withdrawal_request);
    require_hash(&commitment_input);
    require_hash(&withdrawal_input);

    require_order(&commitment);
    require_order(&commitment_request);
    require_order(&withdrawal_request);
    require_order(&commitment_input);
    require_order(&withdrawal_input);
}
