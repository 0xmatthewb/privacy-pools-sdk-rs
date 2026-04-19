use alloy_primitives::address;
use privacy_pools_sdk::{PrivacyPoolsSdk, chain, core};

fn safe_preflight_rejects_raw_proofs<C: chain::ExecutionClient>(
    sdk: &PrivacyPoolsSdk,
    client: &C,
    withdrawal_config: &core::WithdrawalExecutionConfig,
    relay_config: &core::RelayExecutionConfig,
    ragequit_config: &core::RagequitExecutionConfig,
    proof: &core::ProofBundle,
) {
    let _ = sdk.preflight_verified_withdrawal_transaction_with_client(
        withdrawal_config,
        proof,
        client,
    );
    let _ = sdk.preflight_verified_relay_transaction_with_client(relay_config, proof, client);
    let _ = sdk.preflight_verified_ragequit_transaction_with_client(ragequit_config, proof, client);
}

fn main() {
    let sdk = PrivacyPoolsSdk::default();
    let proof = core::ProofBundle {
        proof: core::SnarkJsProof {
            pi_a: ["1".to_owned(), "2".to_owned()],
            pi_b: [
                ["3".to_owned(), "4".to_owned()],
                ["5".to_owned(), "6".to_owned()],
            ],
            pi_c: ["7".to_owned(), "8".to_owned()],
            protocol: "groth16".to_owned(),
            curve: "bn254".to_owned(),
        },
        public_signals: vec!["1".to_owned()],
    };
    let withdrawal = core::Withdrawal::direct(address!("1111111111111111111111111111111111111111"));

    let _ = sdk.plan_verified_withdrawal_transaction(1, address!("2222222222222222222222222222222222222222"), &proof);
    let _ = sdk.plan_verified_relay_transaction(1, address!("2222222222222222222222222222222222222222"), &proof);
    let _ = sdk.plan_verified_ragequit_transaction(1, address!("2222222222222222222222222222222222222222"), &proof);
    let _ = sdk.plan_withdrawal_transaction(1, address!("2222222222222222222222222222222222222222"), &withdrawal, &proof);
}
