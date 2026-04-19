use alloy_primitives::{U256, address, bytes};
use privacy_pools_sdk::{
    PrivacyPoolsSdk, SessionCache, SessionCacheKey,
    artifacts::ArtifactManifest,
    core::{self, CommitmentWitnessRequest, WithdrawalWitnessRequest},
    prover::BackendProfile,
};
use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::PathBuf, str::FromStr};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionLifecycleFixture {
    crypto_fixture_path: String,
    withdrawal_fixture_path: String,
    artifacts_root: String,
    withdrawal_manifest_path: String,
    commitment_manifest_path: String,
    expected: SessionLifecycleExpected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionLifecycleExpected {
    withdrawal_circuit: String,
    commitment_circuit: String,
    withdrawal_public_signals: usize,
    commitment_public_signals: usize,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn read_json<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let bytes = fs::read(workspace_path(relative)).expect("fixture exists");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

fn build_reference_withdrawal_request(
    sdk: &PrivacyPoolsSdk,
    crypto_fixture_path: &str,
    withdrawal_fixture_path: &str,
) -> WithdrawalWitnessRequest {
    let crypto_fixture: Value =
        serde_json::from_slice(&fs::read(workspace_path(crypto_fixture_path)).unwrap()).unwrap();
    let withdrawal_fixture: Value =
        serde_json::from_slice(&fs::read(workspace_path(withdrawal_fixture_path)).unwrap())
            .unwrap();
    let keys = sdk
        .generate_master_keys(crypto_fixture["mnemonic"].as_str().unwrap())
        .unwrap();
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(
            &keys,
            U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
            U256::ZERO,
        )
        .unwrap();

    WithdrawalWitnessRequest {
        commitment: sdk
            .build_commitment(
                U256::from_str(withdrawal_fixture["existingValue"].as_str().unwrap()).unwrap(),
                U256::from_str(withdrawal_fixture["label"].as_str().unwrap()).unwrap(),
                deposit_nullifier,
                deposit_secret,
            )
            .unwrap(),
        withdrawal: core::Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        },
        scope: U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
        withdrawal_amount: U256::from_str(withdrawal_fixture["withdrawalAmount"].as_str().unwrap())
            .unwrap(),
        state_witness: core::CircuitMerkleWitness {
            root: U256::from_str(withdrawal_fixture["stateWitness"]["root"].as_str().unwrap())
                .unwrap(),
            leaf: U256::from_str(withdrawal_fixture["stateWitness"]["leaf"].as_str().unwrap())
                .unwrap(),
            index: withdrawal_fixture["stateWitness"]["index"]
                .as_u64()
                .unwrap() as usize,
            siblings: withdrawal_fixture["stateWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| U256::from_str(value.as_str().unwrap()).unwrap())
                .collect(),
            depth: withdrawal_fixture["stateWitness"]["depth"]
                .as_u64()
                .unwrap() as usize,
        },
        asp_witness: core::CircuitMerkleWitness {
            root: U256::from_str(withdrawal_fixture["aspWitness"]["root"].as_str().unwrap())
                .unwrap(),
            leaf: U256::from_str(withdrawal_fixture["aspWitness"]["leaf"].as_str().unwrap())
                .unwrap(),
            index: withdrawal_fixture["aspWitness"]["index"].as_u64().unwrap() as usize,
            siblings: withdrawal_fixture["aspWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| U256::from_str(value.as_str().unwrap()).unwrap())
                .collect(),
            depth: withdrawal_fixture["aspWitness"]["depth"].as_u64().unwrap() as usize,
        },
        new_nullifier: U256::from_str(withdrawal_fixture["newNullifier"].as_str().unwrap())
            .unwrap()
            .into(),
        new_secret: U256::from_str(withdrawal_fixture["newSecret"].as_str().unwrap())
            .unwrap()
            .into(),
    }
}

#[test]
fn withdrawal_session_reference_trace_proves_verifies_and_invalidates_cache() {
    let fixture: SessionLifecycleFixture = read_json("fixtures/spec/session-lifecycle.json");
    let sdk = PrivacyPoolsSdk::default();
    let request = build_reference_withdrawal_request(
        &sdk,
        &fixture.crypto_fixture_path,
        &fixture.withdrawal_fixture_path,
    );
    let manifest: ArtifactManifest = read_json(&fixture.withdrawal_manifest_path);
    let root = workspace_path(&fixture.artifacts_root);
    let bundle = sdk
        .load_verified_artifact_bundle(&manifest, &root, "withdraw")
        .expect("withdrawal bundle loads");
    let key = SessionCacheKey::from_verified_bundle(BackendProfile::Stable, &bundle);

    let mut cache = SessionCache::new(2);
    let session = cache
        .get_or_prepare_withdrawal_from_bundle(&sdk, BackendProfile::Stable, bundle.clone())
        .expect("withdrawal session prepares");
    let reused = cache
        .get_or_prepare_withdrawal_from_bundle(&sdk, BackendProfile::Stable, bundle)
        .expect("withdrawal session reuses");

    assert_eq!(session.circuit(), fixture.expected.withdrawal_circuit);
    assert_eq!(reused.circuit(), fixture.expected.withdrawal_circuit);
    assert!(cache.withdrawal(&key).is_some());

    let proving = sdk
        .prove_withdrawal_with_session(BackendProfile::Stable, &session, &request)
        .expect("withdrawal proof generates");
    let verified = sdk
        .verify_withdrawal_proof_for_request_with_session(
            BackendProfile::Stable,
            &session,
            &request,
            &proving.proof,
        )
        .expect("withdrawal proof verifies against request");

    assert_eq!(
        verified.proof().public_signals.len(),
        fixture.expected.withdrawal_public_signals
    );
    assert_eq!(verified.scope(), request.scope);
    assert_eq!(verified.withdrawal(), &request.withdrawal);

    let mut tampered = proving.proof.clone();
    tampered.public_signals[2] = "999".to_owned();
    assert!(
        sdk.verify_withdrawal_proof_for_request_with_session(
            BackendProfile::Stable,
            &session,
            &request,
            &tampered,
        )
        .is_err()
    );

    assert!(cache.remove(&key));
    assert!(cache.withdrawal(&key).is_none());
}

#[test]
fn commitment_session_reference_trace_proves_verifies_and_rejects_tampering() {
    let fixture: SessionLifecycleFixture = read_json("fixtures/spec/session-lifecycle.json");
    let sdk = PrivacyPoolsSdk::default();
    let withdrawal_request = build_reference_withdrawal_request(
        &sdk,
        &fixture.crypto_fixture_path,
        &fixture.withdrawal_fixture_path,
    );
    let request = CommitmentWitnessRequest {
        commitment: withdrawal_request.commitment.clone(),
    };
    let manifest: ArtifactManifest = read_json(&fixture.commitment_manifest_path);
    let root = workspace_path(&fixture.artifacts_root);
    let bundle = sdk
        .load_verified_artifact_bundle(&manifest, &root, "commitment")
        .expect("commitment bundle loads");
    let key = SessionCacheKey::from_verified_bundle(BackendProfile::Stable, &bundle);

    let mut cache = SessionCache::new(1);
    let session = cache
        .get_or_prepare_commitment_from_bundle(&sdk, BackendProfile::Stable, bundle)
        .expect("commitment session prepares");
    assert_eq!(session.circuit(), fixture.expected.commitment_circuit);

    let proving = sdk
        .prove_commitment_with_session(BackendProfile::Stable, &session, &request)
        .expect("commitment proof generates");
    let verified = sdk
        .verify_commitment_proof_for_request_with_session(
            BackendProfile::Stable,
            &session,
            &request,
            &proving.proof,
        )
        .expect("commitment proof verifies against request");

    assert_eq!(
        verified.proof().public_signals.len(),
        fixture.expected.commitment_public_signals
    );
    assert_eq!(
        verified.proof().public_signals[0],
        request.commitment.hash.to_string()
    );

    let mut tampered = proving.proof.clone();
    tampered.public_signals[0] = "999".to_owned();
    assert!(
        sdk.verify_commitment_proof_for_request_with_session(
            BackendProfile::Stable,
            &session,
            &request,
            &tampered,
        )
        .is_err()
    );

    assert!(cache.remove(&key));
    assert!(cache.commitment(&key).is_none());
}
