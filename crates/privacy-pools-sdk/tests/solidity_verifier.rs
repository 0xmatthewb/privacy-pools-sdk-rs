use alloy_primitives::{U256, address, bytes};
use alloy_sol_types::SolValue;
use privacy_pools_sdk::{
    PrivacyPoolsSdk, artifacts::ArtifactManifest, chain, core, prover::BackendProfile,
};
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command, str::FromStr};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn read_fixture_json(relative: &str) -> Value {
    serde_json::from_slice(&fs::read(workspace_path(relative)).expect("fixture exists"))
        .expect("fixture parses")
}

fn reference_withdrawal_request(sdk: &PrivacyPoolsSdk) -> core::WithdrawalWitnessRequest {
    let crypto_fixture = read_fixture_json("fixtures/vectors/crypto-compatibility.json");
    let withdrawal_fixture = read_fixture_json("fixtures/vectors/withdrawal-circuit-input.json");
    let keys = sdk
        .generate_master_keys(crypto_fixture["mnemonic"].as_str().expect("mnemonic"))
        .expect("master keys derive");
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(
            &keys,
            U256::from_str(crypto_fixture["scope"].as_str().expect("scope")).expect("scope"),
            U256::ZERO,
        )
        .expect("deposit secrets derive");

    core::WithdrawalWitnessRequest {
        commitment: sdk
            .build_commitment(
                U256::from_str(
                    withdrawal_fixture["existingValue"]
                        .as_str()
                        .expect("existing value"),
                )
                .expect("existing value"),
                U256::from_str(withdrawal_fixture["label"].as_str().expect("label"))
                    .expect("label"),
                deposit_nullifier,
                deposit_secret,
            )
            .expect("commitment builds"),
        withdrawal: core::Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        },
        scope: U256::from_str(crypto_fixture["scope"].as_str().expect("scope")).expect("scope"),
        withdrawal_amount: U256::from_str(
            withdrawal_fixture["withdrawalAmount"]
                .as_str()
                .expect("withdrawal amount"),
        )
        .expect("withdrawal amount"),
        state_witness: witness_from_fixture(&withdrawal_fixture["stateWitness"]),
        asp_witness: witness_from_fixture(&withdrawal_fixture["aspWitness"]),
        new_nullifier: U256::from_str(
            withdrawal_fixture["newNullifier"]
                .as_str()
                .expect("new nullifier"),
        )
        .expect("new nullifier")
        .into(),
        new_secret: U256::from_str(
            withdrawal_fixture["newSecret"]
                .as_str()
                .expect("new secret"),
        )
        .expect("new secret")
        .into(),
    }
}

fn witness_from_fixture(value: &Value) -> core::CircuitMerkleWitness {
    core::CircuitMerkleWitness {
        root: U256::from_str(value["root"].as_str().expect("root")).expect("root"),
        leaf: U256::from_str(value["leaf"].as_str().expect("leaf")).expect("leaf"),
        index: value["index"].as_u64().expect("index") as usize,
        siblings: value["siblings"]
            .as_array()
            .expect("siblings")
            .iter()
            .map(|entry| U256::from_str(entry.as_str().expect("sibling")).expect("sibling"))
            .collect(),
        depth: value["depth"].as_u64().expect("depth") as usize,
    }
}

fn proof_coordinates(proof: &core::ProofBundle) -> ([U256; 2], [[U256; 2]; 2], [U256; 2]) {
    let parse = |value: &str, field: &str| {
        core::parse_decimal_field(value)
            .unwrap_or_else(|error| panic!("failed to parse {field}: {error}"))
    };

    (
        [
            parse(&proof.proof.pi_a[0], "pi_a[0]"),
            parse(&proof.proof.pi_a[1], "pi_a[1]"),
        ],
        [
            [
                parse(&proof.proof.pi_b[0][1], "pi_b[0][1]"),
                parse(&proof.proof.pi_b[0][0], "pi_b[0][0]"),
            ],
            [
                parse(&proof.proof.pi_b[1][1], "pi_b[1][1]"),
                parse(&proof.proof.pi_b[1][0], "pi_b[1][0]"),
            ],
        ],
        [
            parse(&proof.proof.pi_c[0], "pi_c[0]"),
            parse(&proof.proof.pi_c[1], "pi_c[1]"),
        ],
    )
}

#[test]
#[ignore = "requires forge to run the vendored Solidity verifier acceptance test"]
fn rust_generated_withdrawal_proof_is_accepted_by_solidity_verifier() {
    let sdk = PrivacyPoolsSdk::default();
    let manifest: ArtifactManifest = serde_json::from_str(include_str!(
        "../../../fixtures/artifacts/withdrawal-proving-manifest.json"
    ))
    .expect("proving manifest parses");
    let artifacts_root = workspace_path("fixtures/artifacts");
    let request = reference_withdrawal_request(&sdk);
    let session = sdk
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .expect("withdrawal session prepares");
    let proving = sdk
        .prove_withdrawal_with_session(BackendProfile::Stable, &session, &request)
        .expect("rust prover succeeds");

    sdk.validate_withdrawal_proof_against_request(&request, &proving.proof)
        .expect("proof matches request");
    assert!(
        sdk.verify_withdrawal_proof_with_session(BackendProfile::Stable, &session, &proving.proof)
            .expect("proof verifies natively"),
        "rust-generated withdrawal proof should verify in Rust before Solidity"
    );

    let (p_a, p_b, p_c) = proof_coordinates(&proving.proof);
    let public_signals = chain::withdraw_public_signals(&proving.proof).expect("public signals");
    let encoded = (p_a, p_b, p_c, public_signals).abi_encode();

    let forge_root = workspace_path("solidity-verifier");
    let temp_root = forge_root.join("tmp");
    fs::create_dir_all(&temp_root).expect("forge temp directory exists");
    let tmp = tempfile::Builder::new()
        .prefix("withdrawal-proof-")
        .tempdir_in(&temp_root)
        .expect("forge tempdir allocates");
    let proof_path = tmp.path().join("withdrawal-proof.abi");
    fs::write(&proof_path, encoded).expect("writes ABI proof fixture");

    let output = Command::new("forge")
        .args([
            "test",
            "--match-test",
            "testRustGeneratedWithdrawalProofAccepted",
            "-vv",
        ])
        .env("PRIVACY_POOLS_PROOF_PATH", &proof_path)
        .current_dir(&forge_root)
        .output()
        .expect("forge command launches");

    assert!(
        output.status.success(),
        "forge verifier acceptance failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
