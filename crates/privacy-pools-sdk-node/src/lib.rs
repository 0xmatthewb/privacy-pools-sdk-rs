use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use napi::{Error, Result as NapiResult};
use napi_derive::napi;
use privacy_pools_sdk::{
    CommitmentCircuitSession, PrivacyPoolsSdk, WithdrawalCircuitSession,
    artifacts::{ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle},
    core::{
        CircuitMerkleWitness, Commitment, CommitmentCircuitInput, CommitmentPreimage,
        CommitmentWitnessRequest, FormattedGroth16Proof, MasterKeys, MerkleProof, Precommitment,
        ProofBundle, RootRead, RootReadKind, SnarkJsProof, TransactionKind, TransactionPlan,
        Withdrawal, WithdrawalCircuitInput, WithdrawalWitnessRequest,
    },
    prover::{BackendPolicy, BackendProfile, ProverBackend, ProvingResult},
    recovery::{CompatibilityMode, PoolEvent, RecoveryPolicy},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

static SDK: LazyLock<PrivacyPoolsSdk> = LazyLock::new(|| {
    PrivacyPoolsSdk::new(BackendPolicy {
        allow_fast_backend: true,
    })
});
static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static WITHDRAWAL_SESSION_REGISTRY: LazyLock<RwLock<HashMap<String, WithdrawalCircuitSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static COMMITMENT_SESSION_REGISTRY: LazyLock<RwLock<HashMap<String, CommitmentCircuitSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsMasterKeys {
    master_nullifier: String,
    master_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsSecrets {
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCommitment {
    hash: String,
    nullifier_hash: String,
    precommitment_hash: String,
    value: String,
    label: String,
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsWithdrawal {
    processooor: String,
    data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSnarkJsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: String,
    curve: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsProofBundle {
    proof: JsSnarkJsProof,
    public_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsProvingResult {
    backend: String,
    proof: JsProofBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsMerkleProof {
    root: String,
    leaf: String,
    index: u64,
    siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCircuitMerkleWitness {
    root: String,
    leaf: String,
    index: u64,
    siblings: Vec<String>,
    depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsWithdrawalWitnessRequest {
    commitment: JsCommitment,
    withdrawal: JsWithdrawal,
    scope: String,
    withdrawal_amount: String,
    state_witness: JsCircuitMerkleWitness,
    asp_witness: JsCircuitMerkleWitness,
    new_nullifier: String,
    new_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsWithdrawalCircuitInput {
    withdrawn_value: String,
    state_root: String,
    state_tree_depth: u64,
    asp_root: String,
    asp_tree_depth: u64,
    context: String,
    label: String,
    existing_value: String,
    existing_nullifier: String,
    existing_secret: String,
    new_nullifier: String,
    new_secret: String,
    state_siblings: Vec<String>,
    state_index: u64,
    asp_siblings: Vec<String>,
    asp_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCommitmentWitnessRequest {
    commitment: JsCommitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsCommitmentCircuitInput {
    value: String,
    label: String,
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsArtifactBytes {
    kind: String,
    bytes_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsArtifactStatus {
    version: String,
    circuit: String,
    kind: String,
    filename: String,
    path: String,
    exists: bool,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsResolvedArtifact {
    circuit: String,
    kind: String,
    filename: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsResolvedArtifactBundle {
    version: String,
    circuit: String,
    artifacts: Vec<JsResolvedArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsVerifiedArtifactDescriptor {
    circuit: String,
    kind: String,
    filename: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JsVerifiedArtifactBundle {
    version: String,
    circuit: String,
    artifacts: Vec<JsVerifiedArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsWithdrawalCircuitSessionHandle {
    handle: String,
    circuit: String,
    artifact_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCommitmentCircuitSessionHandle {
    handle: String,
    circuit: String,
    artifact_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFormattedGroth16Proof {
    p_a: Vec<String>,
    p_b: Vec<Vec<String>>,
    p_c: Vec<String>,
    pub_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsTransactionPlan {
    kind: String,
    chain_id: u64,
    target: String,
    calldata: String,
    value: String,
    proof: JsFormattedGroth16Proof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRootRead {
    kind: String,
    contract_address: String,
    pool_address: String,
    call_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsPoolEvent {
    block_number: u64,
    transaction_index: u64,
    log_index: u64,
    pool_address: String,
    commitment_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveryPolicy {
    compatibility_mode: String,
    fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveryCheckpoint {
    latest_block: u64,
    commitments_seen: u64,
}

#[napi]
pub fn get_version() -> String {
    PrivacyPoolsSdk::version().to_owned()
}

#[napi]
pub fn get_stable_backend_name() -> NapiResult<String> {
    SDK.stable_backend_name().map_err(to_napi_error)
}

#[napi]
pub fn fast_backend_supported_on_target() -> bool {
    SDK.fast_backend_supported_on_target()
}

#[napi]
pub fn derive_master_keys(mnemonic: String) -> NapiResult<String> {
    let keys = SDK.generate_master_keys(&mnemonic).map_err(to_napi_error)?;
    to_json_string(&to_js_master_keys(keys)).map_err(to_napi_error)
}

#[napi]
pub fn derive_deposit_secrets(
    master_keys_json: String,
    scope: String,
    index: String,
) -> NapiResult<String> {
    let master_keys = parse_json::<JsMasterKeys>(&master_keys_json)
        .and_then(to_master_keys)
        .map_err(to_napi_error)?;
    let secrets = SDK
        .generate_deposit_secrets(
            &master_keys,
            parse_field(&scope).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: field_label(secrets.1),
    })
    .map_err(to_napi_error)
}

#[napi]
pub fn derive_withdrawal_secrets(
    master_keys_json: String,
    label: String,
    index: String,
) -> NapiResult<String> {
    let master_keys = parse_json::<JsMasterKeys>(&master_keys_json)
        .and_then(to_master_keys)
        .map_err(to_napi_error)?;
    let secrets = SDK
        .generate_withdrawal_secrets(
            &master_keys,
            parse_field(&label).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: field_label(secrets.1),
    })
    .map_err(to_napi_error)
}

#[napi]
pub fn get_commitment(
    value: String,
    label: String,
    nullifier: String,
    secret: String,
) -> NapiResult<String> {
    let commitment = SDK
        .get_commitment(
            parse_field(&value).map_err(to_napi_error)?,
            parse_field(&label).map_err(to_napi_error)?,
            parse_field(&nullifier).map_err(to_napi_error)?,
            parse_field(&secret).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_commitment(commitment)).map_err(to_napi_error)
}

#[napi]
pub fn calculate_withdrawal_context(withdrawal_json: String, scope: String) -> NapiResult<String> {
    let withdrawal = parse_json::<JsWithdrawal>(&withdrawal_json)
        .and_then(from_js_withdrawal)
        .map_err(to_napi_error)?;
    SDK.calculate_context(&withdrawal, parse_field(&scope).map_err(to_napi_error)?)
        .map_err(to_napi_error)
}

#[napi]
pub fn generate_merkle_proof(leaves_json: String, leaf: String) -> NapiResult<String> {
    let leaves = parse_json::<Vec<String>>(&leaves_json).map_err(to_napi_error)?;
    let leaves = leaves
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>>>()
        .map_err(to_napi_error)?;
    let proof = SDK
        .generate_merkle_proof(&leaves, parse_field(&leaf).map_err(to_napi_error)?)
        .map_err(to_napi_error)?;
    let proof = to_js_merkle_proof(proof).map_err(to_napi_error)?;
    to_json_string(&proof).map_err(to_napi_error)
}

#[napi]
pub fn build_circuit_merkle_witness(proof_json: String, depth: u32) -> NapiResult<String> {
    let proof = parse_json::<JsMerkleProof>(&proof_json)
        .and_then(from_js_merkle_proof)
        .map_err(to_napi_error)?;
    let witness = SDK
        .to_circuit_witness(
            &proof,
            usize::try_from(depth)
                .map_err(anyhow::Error::from)
                .map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    let witness = to_js_circuit_merkle_witness(witness).map_err(to_napi_error)?;
    to_json_string(&witness).map_err(to_napi_error)
}

#[napi]
pub fn build_withdrawal_circuit_input(request_json: String) -> NapiResult<String> {
    let request = parse_json::<JsWithdrawalWitnessRequest>(&request_json)
        .and_then(from_js_withdrawal_witness_request)
        .map_err(to_napi_error)?;
    let input = SDK
        .build_withdrawal_circuit_input(&request)
        .map_err(to_napi_error)?;
    let input = to_js_withdrawal_circuit_input(input).map_err(to_napi_error)?;
    to_json_string(&input).map_err(to_napi_error)
}

#[napi]
pub fn build_commitment_circuit_input(request_json: String) -> NapiResult<String> {
    let request = parse_json::<JsCommitmentWitnessRequest>(&request_json)
        .and_then(from_js_commitment_witness_request)
        .map_err(to_napi_error)?;
    let input = SDK
        .build_commitment_circuit_input(&request)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_commitment_circuit_input(&input)).map_err(to_napi_error)
}

#[napi]
pub fn get_artifact_statuses(manifest_json: String, artifacts_root: String) -> NapiResult<String> {
    artifact_statuses_json(manifest_json, artifacts_root, "withdraw")
}

#[napi]
pub fn get_commitment_artifact_statuses(
    manifest_json: String,
    artifacts_root: String,
) -> NapiResult<String> {
    artifact_statuses_json(manifest_json, artifacts_root, "commitment")
}

fn artifact_statuses_json(
    manifest_json: String,
    artifacts_root: String,
    circuit: &str,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let statuses = SDK
        .artifact_statuses(&manifest, &artifacts_root, circuit)
        .into_iter()
        .map(|status| to_js_artifact_status(&manifest.version, status))
        .collect::<Vec<_>>();
    to_json_string(&statuses).map_err(to_napi_error)
}

#[napi]
pub fn resolve_verified_artifact_bundle(
    manifest_json: String,
    artifacts_root: String,
) -> NapiResult<String> {
    resolve_verified_artifact_bundle_json(manifest_json, artifacts_root, "withdraw")
}

#[napi]
pub fn resolve_verified_commitment_artifact_bundle(
    manifest_json: String,
    artifacts_root: String,
) -> NapiResult<String> {
    resolve_verified_artifact_bundle_json(manifest_json, artifacts_root, "commitment")
}

fn resolve_verified_artifact_bundle_json(
    manifest_json: String,
    artifacts_root: String,
    circuit: &str,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let bundle = SDK
        .resolve_verified_artifact_bundle(&manifest, &artifacts_root, circuit)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_resolved_artifact_bundle(bundle)).map_err(to_napi_error)
}

#[napi]
pub fn verify_artifact_bytes(
    manifest_json: String,
    circuit: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let artifacts = parse_json::<Vec<JsArtifactBytes>>(&artifacts_json)
        .and_then(from_js_artifact_bytes)
        .map_err(to_napi_error)?;
    let bundle = SDK
        .verify_artifact_bundle_bytes(&manifest, &circuit, artifacts)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_verified_artifact_bundle(bundle)).map_err(to_napi_error)
}

#[napi]
pub fn prepare_withdrawal_circuit_session(
    manifest_json: String,
    artifacts_root: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let session = SDK
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .map_err(to_napi_error)?;
    let handle = next_withdrawal_session_handle();
    let result = JsWithdrawalCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    WITHDRAWAL_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .insert(handle, session);
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn prepare_withdrawal_circuit_session_from_bytes(
    manifest_json: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let artifacts = parse_json::<Vec<JsArtifactBytes>>(&artifacts_json)
        .and_then(from_js_artifact_bytes)
        .map_err(to_napi_error)?;
    let bundle = SDK
        .verify_artifact_bundle_bytes(&manifest, "withdraw", artifacts)
        .map_err(to_napi_error)?;
    let session = SDK
        .prepare_withdrawal_circuit_session_from_bundle(bundle)
        .map_err(to_napi_error)?;
    let handle = next_withdrawal_session_handle();
    let result = JsWithdrawalCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    WITHDRAWAL_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .insert(handle, session);
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn remove_withdrawal_circuit_session(session_handle: String) -> NapiResult<bool> {
    Ok(WITHDRAWAL_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .remove(&session_handle)
        .is_some())
}

#[napi]
pub fn prepare_commitment_circuit_session(
    manifest_json: String,
    artifacts_root: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let session = SDK
        .prepare_commitment_circuit_session(&manifest, &artifacts_root)
        .map_err(to_napi_error)?;
    let handle = next_commitment_session_handle();
    let result = JsCommitmentCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    COMMITMENT_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .insert(handle, session);
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn prepare_commitment_circuit_session_from_bytes(
    manifest_json: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let artifacts = parse_json::<Vec<JsArtifactBytes>>(&artifacts_json)
        .and_then(from_js_artifact_bytes)
        .map_err(to_napi_error)?;
    let bundle = SDK
        .verify_artifact_bundle_bytes(&manifest, "commitment", artifacts)
        .map_err(to_napi_error)?;
    let session = SDK
        .prepare_commitment_circuit_session_from_bundle(bundle)
        .map_err(to_napi_error)?;
    let handle = next_commitment_session_handle();
    let result = JsCommitmentCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    COMMITMENT_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .insert(handle, session);
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn remove_commitment_circuit_session(session_handle: String) -> NapiResult<bool> {
    Ok(COMMITMENT_SESSION_REGISTRY
        .write()
        .map_err(lock_error)
        .map_err(to_napi_error)?
        .remove(&session_handle)
        .is_some())
}

#[napi]
pub fn prove_withdrawal(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let request = parse_json::<JsWithdrawalWitnessRequest>(&request_json)
        .and_then(from_js_withdrawal_witness_request)
        .map_err(to_napi_error)?;
    SDK.prove_withdrawal(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &manifest,
        &artifacts_root,
        &request,
    )
    .map_err(to_napi_error)
    .and_then(|result| to_json_string(&to_js_proving_result(result)).map_err(to_napi_error))
}

#[napi]
pub fn prove_withdrawal_with_session(
    backend_profile: String,
    session_handle: String,
    request_json: String,
) -> NapiResult<String> {
    let request = parse_json::<JsWithdrawalWitnessRequest>(&request_json)
        .and_then(from_js_withdrawal_witness_request)
        .map_err(to_napi_error)?;
    let session = get_withdrawal_session(&session_handle).map_err(to_napi_error)?;
    SDK.prove_withdrawal_with_session(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &session,
        &request,
    )
    .map_err(to_napi_error)
    .and_then(|result| to_json_string(&to_js_proving_result(result)).map_err(to_napi_error))
}

#[napi]
pub fn verify_withdrawal_proof(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    proof_json: String,
) -> NapiResult<bool> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    SDK.verify_withdrawal_proof(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &manifest,
        &artifacts_root,
        &proof,
    )
    .map_err(to_napi_error)
}

#[napi]
pub fn verify_withdrawal_proof_with_session(
    backend_profile: String,
    session_handle: String,
    proof_json: String,
) -> NapiResult<bool> {
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let session = get_withdrawal_session(&session_handle).map_err(to_napi_error)?;
    SDK.verify_withdrawal_proof_with_session(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &session,
        &proof,
    )
    .map_err(to_napi_error)
}

#[napi]
pub fn prove_commitment(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let request = parse_json::<JsCommitmentWitnessRequest>(&request_json)
        .and_then(from_js_commitment_witness_request)
        .map_err(to_napi_error)?;
    SDK.prove_commitment(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &manifest,
        &artifacts_root,
        &request,
    )
    .map_err(to_napi_error)
    .and_then(|result| to_json_string(&to_js_proving_result(result)).map_err(to_napi_error))
}

#[napi]
pub fn prove_commitment_with_session(
    backend_profile: String,
    session_handle: String,
    request_json: String,
) -> NapiResult<String> {
    let request = parse_json::<JsCommitmentWitnessRequest>(&request_json)
        .and_then(from_js_commitment_witness_request)
        .map_err(to_napi_error)?;
    let session = get_commitment_session(&session_handle).map_err(to_napi_error)?;
    SDK.prove_commitment_with_session(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &session,
        &request,
    )
    .map_err(to_napi_error)
    .and_then(|result| to_json_string(&to_js_proving_result(result)).map_err(to_napi_error))
}

#[napi]
pub fn verify_commitment_proof(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    proof_json: String,
) -> NapiResult<bool> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    SDK.verify_commitment_proof(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &manifest,
        &artifacts_root,
        &proof,
    )
    .map_err(to_napi_error)
}

#[napi]
pub fn verify_commitment_proof_with_session(
    backend_profile: String,
    session_handle: String,
    proof_json: String,
) -> NapiResult<bool> {
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let session = get_commitment_session(&session_handle).map_err(to_napi_error)?;
    SDK.verify_commitment_proof_with_session(
        parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
        &session,
        &proof,
    )
    .map_err(to_napi_error)
}

#[napi]
pub fn format_groth16_proof_bundle(proof_json: String) -> NapiResult<String> {
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let formatted = SDK.format_groth16_proof(&proof).map_err(to_napi_error)?;
    to_json_string(&to_js_formatted_groth16_proof(formatted)).map_err(to_napi_error)
}

#[napi]
pub fn plan_withdrawal_transaction(
    chain_id: String,
    pool_address: String,
    withdrawal_json: String,
    proof_json: String,
) -> NapiResult<String> {
    let withdrawal = parse_json::<JsWithdrawal>(&withdrawal_json)
        .and_then(from_js_withdrawal)
        .map_err(to_napi_error)?;
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let plan = SDK
        .plan_withdrawal_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&pool_address).map_err(to_napi_error)?,
            &withdrawal,
            &proof,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub fn plan_relay_transaction(
    chain_id: String,
    entrypoint_address: String,
    withdrawal_json: String,
    proof_json: String,
    scope: String,
) -> NapiResult<String> {
    let withdrawal = parse_json::<JsWithdrawal>(&withdrawal_json)
        .and_then(from_js_withdrawal)
        .map_err(to_napi_error)?;
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let plan = SDK
        .plan_relay_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&entrypoint_address).map_err(to_napi_error)?,
            &withdrawal,
            &proof,
            parse_field(&scope).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub fn plan_ragequit_transaction(
    chain_id: String,
    pool_address: String,
    proof_json: String,
) -> NapiResult<String> {
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let plan = SDK
        .plan_ragequit_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&pool_address).map_err(to_napi_error)?,
            &proof,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub fn plan_pool_state_root_read(pool_address: String) -> NapiResult<String> {
    let read = SDK.plan_pool_state_root_read(parse_address(&pool_address).map_err(to_napi_error)?);
    to_json_string(&to_js_root_read(read)).map_err(to_napi_error)
}

#[napi]
pub fn plan_asp_root_read(entrypoint_address: String, pool_address: String) -> NapiResult<String> {
    let read = SDK.plan_asp_root_read(
        parse_address(&entrypoint_address).map_err(to_napi_error)?,
        parse_address(&pool_address).map_err(to_napi_error)?,
    );
    to_json_string(&to_js_root_read(read)).map_err(to_napi_error)
}

#[napi]
pub fn is_current_state_root(expected_root: String, current_root: String) -> NapiResult<bool> {
    Ok(SDK.is_current_state_root(
        parse_field(&expected_root).map_err(to_napi_error)?,
        parse_field(&current_root).map_err(to_napi_error)?,
    ))
}

#[napi]
pub fn checkpoint_recovery(events_json: String, policy_json: String) -> NapiResult<String> {
    let events = parse_json::<Vec<JsPoolEvent>>(&events_json)
        .and_then(from_js_pool_events)
        .map_err(to_napi_error)?;
    let policy = parse_json::<JsRecoveryPolicy>(&policy_json)
        .and_then(from_js_recovery_policy)
        .map_err(to_napi_error)?;
    let checkpoint = SDK
        .checkpoint_recovery(&events, policy)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_recovery_checkpoint(checkpoint)).map_err(to_napi_error)
}

fn parse_json<T>(value: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(value).context("failed to parse JSON payload")
}

fn to_json_string(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).context("failed to serialize JSON payload")
}

fn parse_manifest(manifest_json: &str) -> Result<ArtifactManifest> {
    serde_json::from_str(manifest_json).context("failed to parse artifact manifest JSON")
}

fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).with_context(|| format!("invalid address `{value}`"))
}

fn parse_field(value: &str) -> Result<U256> {
    U256::from_str(value).with_context(|| format!("invalid field element `{value}`"))
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("invalid u64 `{value}`"))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => bail!("invalid artifact kind: {value}"),
    }
}

fn parse_backend_profile(value: &str) -> Result<BackendProfile> {
    match value {
        "stable" => Ok(BackendProfile::Stable),
        "fast" => Ok(BackendProfile::Fast),
        _ => bail!("invalid backend profile: {value}"),
    }
}

fn artifact_kind_label(kind: ArtifactKind) -> String {
    match kind {
        ArtifactKind::Wasm => "wasm".to_owned(),
        ArtifactKind::Zkey => "zkey".to_owned(),
        ArtifactKind::Vkey => "vkey".to_owned(),
    }
}

fn prover_backend_label(kind: ProverBackend) -> String {
    match kind {
        ProverBackend::Arkworks => "arkworks".to_owned(),
        ProverBackend::Rapidsnark => "rapidsnark".to_owned(),
    }
}

fn root_read_kind_label(kind: RootReadKind) -> String {
    match kind {
        RootReadKind::PoolState => "pool_state".to_owned(),
        RootReadKind::Asp => "asp".to_owned(),
    }
}

fn transaction_kind_label(kind: TransactionKind) -> String {
    match kind {
        TransactionKind::Withdraw => "withdraw".to_owned(),
        TransactionKind::Relay => "relay".to_owned(),
        TransactionKind::Ragequit => "ragequit".to_owned(),
    }
}

fn field_label(value: U256) -> String {
    value.to_string()
}

fn next_withdrawal_session_handle() -> String {
    format!(
        "withdraw-session-{}",
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn next_commitment_session_handle() -> String {
    format!(
        "commitment-session-{}",
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn get_withdrawal_session(handle: &str) -> Result<WithdrawalCircuitSession> {
    WITHDRAWAL_SESSION_REGISTRY
        .read()
        .map_err(lock_error)?
        .get(handle)
        .cloned()
        .ok_or_else(|| anyhow!("withdrawal circuit session handle not found: {handle}"))
}

fn get_commitment_session(handle: &str) -> Result<CommitmentCircuitSession> {
    COMMITMENT_SESSION_REGISTRY
        .read()
        .map_err(lock_error)?
        .get(handle)
        .cloned()
        .ok_or_else(|| anyhow!("commitment circuit session handle not found: {handle}"))
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow!("session registry lock poisoned: {error}")
}

fn to_napi_error(error: impl std::fmt::Display) -> Error {
    Error::from_reason(error.to_string())
}

fn to_master_keys(keys: JsMasterKeys) -> Result<MasterKeys> {
    Ok(MasterKeys {
        master_nullifier: parse_field(&keys.master_nullifier)?,
        master_secret: parse_field(&keys.master_secret)?,
    })
}

fn to_js_master_keys(keys: MasterKeys) -> JsMasterKeys {
    JsMasterKeys {
        master_nullifier: field_label(keys.master_nullifier),
        master_secret: field_label(keys.master_secret),
    }
}

fn to_js_commitment(commitment: Commitment) -> JsCommitment {
    JsCommitment {
        hash: field_label(commitment.hash),
        nullifier_hash: field_label(commitment.nullifier_hash),
        precommitment_hash: field_label(commitment.preimage.precommitment.hash),
        value: field_label(commitment.preimage.value),
        label: field_label(commitment.preimage.label),
        nullifier: field_label(commitment.preimage.precommitment.nullifier),
        secret: field_label(commitment.preimage.precommitment.secret),
    }
}

fn from_js_commitment(commitment: JsCommitment) -> Result<Commitment> {
    Ok(Commitment {
        hash: parse_field(&commitment.hash)?,
        nullifier_hash: parse_field(&commitment.nullifier_hash)?,
        preimage: CommitmentPreimage {
            value: parse_field(&commitment.value)?,
            label: parse_field(&commitment.label)?,
            precommitment: Precommitment {
                hash: parse_field(&commitment.precommitment_hash)?,
                nullifier: parse_field(&commitment.nullifier)?,
                secret: parse_field(&commitment.secret)?,
            },
        },
    })
}

fn from_js_withdrawal(withdrawal: JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processooor: parse_address(&withdrawal.processooor)?,
        data: data.into(),
    })
}

fn to_js_root_read(read: RootRead) -> JsRootRead {
    JsRootRead {
        kind: root_read_kind_label(read.kind),
        contract_address: read.contract_address.to_string(),
        pool_address: read.pool_address.to_string(),
        call_data: format!("0x{}", hex::encode(read.call_data)),
    }
}

fn to_js_merkle_proof(proof: MerkleProof) -> Result<JsMerkleProof> {
    Ok(JsMerkleProof {
        root: field_label(proof.root),
        leaf: field_label(proof.leaf),
        index: u64::try_from(proof.index).context("merkle proof index does not fit into u64")?,
        siblings: proof.siblings.into_iter().map(field_label).collect(),
    })
}

fn from_js_merkle_proof(proof: JsMerkleProof) -> Result<MerkleProof> {
    Ok(MerkleProof {
        root: parse_field(&proof.root)?,
        leaf: parse_field(&proof.leaf)?,
        index: usize::try_from(proof.index)
            .context("merkle proof index does not fit into usize")?,
        siblings: proof
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn to_js_circuit_merkle_witness(witness: CircuitMerkleWitness) -> Result<JsCircuitMerkleWitness> {
    Ok(JsCircuitMerkleWitness {
        root: field_label(witness.root),
        leaf: field_label(witness.leaf),
        index: u64::try_from(witness.index)
            .context("circuit witness index does not fit into u64")?,
        siblings: witness.siblings.into_iter().map(field_label).collect(),
        depth: u64::try_from(witness.depth)
            .context("circuit witness depth does not fit into u64")?,
    })
}

fn from_js_circuit_merkle_witness(witness: JsCircuitMerkleWitness) -> Result<CircuitMerkleWitness> {
    Ok(CircuitMerkleWitness {
        root: parse_field(&witness.root)?,
        leaf: parse_field(&witness.leaf)?,
        index: usize::try_from(witness.index)
            .context("circuit witness index does not fit into usize")?,
        siblings: witness
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>>>()?,
        depth: usize::try_from(witness.depth)
            .context("circuit witness depth does not fit into usize")?,
    })
}

fn from_js_withdrawal_witness_request(
    request: JsWithdrawalWitnessRequest,
) -> Result<WithdrawalWitnessRequest> {
    Ok(WithdrawalWitnessRequest {
        commitment: from_js_commitment(request.commitment)?,
        withdrawal: from_js_withdrawal(request.withdrawal)?,
        scope: parse_field(&request.scope)?,
        withdrawal_amount: parse_field(&request.withdrawal_amount)?,
        state_witness: from_js_circuit_merkle_witness(request.state_witness)?,
        asp_witness: from_js_circuit_merkle_witness(request.asp_witness)?,
        new_nullifier: parse_field(&request.new_nullifier)?,
        new_secret: parse_field(&request.new_secret)?,
    })
}

fn from_js_commitment_witness_request(
    request: JsCommitmentWitnessRequest,
) -> Result<CommitmentWitnessRequest> {
    Ok(CommitmentWitnessRequest {
        commitment: from_js_commitment(request.commitment)?,
    })
}

fn to_js_withdrawal_circuit_input(
    input: WithdrawalCircuitInput,
) -> Result<JsWithdrawalCircuitInput> {
    Ok(JsWithdrawalCircuitInput {
        withdrawn_value: field_label(input.withdrawn_value),
        state_root: field_label(input.state_root),
        state_tree_depth: u64::try_from(input.state_tree_depth)
            .context("state tree depth does not fit into u64")?,
        asp_root: field_label(input.asp_root),
        asp_tree_depth: u64::try_from(input.asp_tree_depth)
            .context("asp tree depth does not fit into u64")?,
        context: field_label(input.context),
        label: field_label(input.label),
        existing_value: field_label(input.existing_value),
        existing_nullifier: field_label(input.existing_nullifier),
        existing_secret: field_label(input.existing_secret),
        new_nullifier: field_label(input.new_nullifier),
        new_secret: field_label(input.new_secret),
        state_siblings: input.state_siblings.into_iter().map(field_label).collect(),
        state_index: u64::try_from(input.state_index)
            .context("state index does not fit into u64")?,
        asp_siblings: input.asp_siblings.into_iter().map(field_label).collect(),
        asp_index: u64::try_from(input.asp_index).context("asp index does not fit into u64")?,
    })
}

fn to_js_commitment_circuit_input(input: &CommitmentCircuitInput) -> JsCommitmentCircuitInput {
    JsCommitmentCircuitInput {
        value: field_label(input.value),
        label: field_label(input.label),
        nullifier: field_label(input.nullifier),
        secret: field_label(input.secret),
    }
}

fn from_js_proof_bundle(bundle: JsProofBundle) -> Result<ProofBundle> {
    Ok(ProofBundle {
        proof: SnarkJsProof {
            pi_a: validate_pair(bundle.proof.pi_a, "pi_a")?,
            pi_b: validate_pair_rows(bundle.proof.pi_b, "pi_b")?,
            pi_c: validate_pair(bundle.proof.pi_c, "pi_c")?,
            protocol: bundle.proof.protocol,
            curve: bundle.proof.curve,
        },
        public_signals: bundle.public_signals,
    })
}

fn to_js_proof_bundle(bundle: ProofBundle) -> JsProofBundle {
    JsProofBundle {
        proof: JsSnarkJsProof {
            pi_a: bundle.proof.pi_a.into_iter().collect(),
            pi_b: bundle
                .proof
                .pi_b
                .into_iter()
                .map(|row| row.into_iter().collect())
                .collect(),
            pi_c: bundle.proof.pi_c.into_iter().collect(),
            protocol: bundle.proof.protocol,
            curve: bundle.proof.curve,
        },
        public_signals: bundle.public_signals,
    }
}

fn to_js_proving_result(result: ProvingResult) -> JsProvingResult {
    JsProvingResult {
        backend: prover_backend_label(result.backend),
        proof: to_js_proof_bundle(result.proof),
    }
}

fn to_js_formatted_groth16_proof(proof: FormattedGroth16Proof) -> JsFormattedGroth16Proof {
    JsFormattedGroth16Proof {
        p_a: proof.p_a.into_iter().collect(),
        p_b: proof
            .p_b
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect(),
        p_c: proof.p_c.into_iter().collect(),
        pub_signals: proof.pub_signals,
    }
}

fn to_js_transaction_plan(plan: TransactionPlan) -> JsTransactionPlan {
    JsTransactionPlan {
        kind: transaction_kind_label(plan.kind),
        chain_id: plan.chain_id,
        target: plan.target.to_string(),
        calldata: format!("0x{}", hex::encode(plan.calldata)),
        value: field_label(plan.value),
        proof: to_js_formatted_groth16_proof(plan.proof),
    }
}

fn validate_pair(values: Vec<String>, label: &str) -> Result<[String; 2]> {
    values.try_into().map_err(|values: Vec<String>| {
        anyhow!("{label} must have exactly 2 elements, got {}", values.len())
    })
}

fn validate_pair_rows(values: Vec<Vec<String>>, label: &str) -> Result<[[String; 2]; 2]> {
    let rows = values
        .into_iter()
        .map(|row| validate_pair(row, label))
        .collect::<Result<Vec<_>>>()?;
    rows.try_into().map_err(|rows: Vec<[String; 2]>| {
        anyhow!("{label} must have exactly 2 rows, got {}", rows.len())
    })
}

fn from_js_artifact_bytes(
    artifacts: Vec<JsArtifactBytes>,
) -> Result<Vec<privacy_pools_sdk::artifacts::ArtifactBytes>> {
    let engine = base64::engine::general_purpose::STANDARD;
    artifacts
        .into_iter()
        .map(|artifact| {
            Ok(privacy_pools_sdk::artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&artifact.kind)?,
                bytes: engine
                    .decode(artifact.bytes_base64)
                    .context("failed to decode base64 artifact bytes")?,
            })
        })
        .collect()
}

fn to_js_artifact_status(version: &str, status: ArtifactStatus) -> JsArtifactStatus {
    JsArtifactStatus {
        version: version.to_owned(),
        circuit: status.descriptor.circuit,
        kind: artifact_kind_label(status.descriptor.kind),
        filename: status.descriptor.filename,
        path: status.path.to_string_lossy().into_owned(),
        exists: status.exists,
        verified: status.verified,
    }
}

fn to_js_resolved_artifact_bundle(bundle: ResolvedArtifactBundle) -> JsResolvedArtifactBundle {
    JsResolvedArtifactBundle {
        version: bundle.version,
        circuit: bundle.circuit,
        artifacts: bundle
            .artifacts
            .into_iter()
            .map(|artifact| JsResolvedArtifact {
                circuit: artifact.descriptor.circuit,
                kind: artifact_kind_label(artifact.descriptor.kind),
                filename: artifact.descriptor.filename,
                path: artifact.path.to_string_lossy().into_owned(),
            })
            .collect(),
    }
}

fn to_js_verified_artifact_bundle(
    bundle: privacy_pools_sdk::artifacts::VerifiedArtifactBundle,
) -> JsVerifiedArtifactBundle {
    JsVerifiedArtifactBundle {
        version: bundle.version().to_owned(),
        circuit: bundle.circuit().to_owned(),
        artifacts: bundle
            .artifacts()
            .iter()
            .map(|artifact| JsVerifiedArtifactDescriptor {
                circuit: artifact.descriptor().circuit.clone(),
                kind: artifact_kind_label(artifact.descriptor().kind),
                filename: artifact.descriptor().filename.clone(),
                sha256: artifact.descriptor().sha256.clone(),
            })
            .collect(),
    }
}

fn from_js_pool_events(events: Vec<JsPoolEvent>) -> Result<Vec<PoolEvent>> {
    events
        .into_iter()
        .map(|event| {
            Ok(PoolEvent {
                block_number: event.block_number,
                transaction_index: event.transaction_index,
                log_index: event.log_index,
                pool_address: parse_address(&event.pool_address)?,
                commitment_hash: parse_field(&event.commitment_hash)?,
            })
        })
        .collect()
}

fn from_js_recovery_policy(policy: JsRecoveryPolicy) -> Result<RecoveryPolicy> {
    let compatibility_mode = match policy.compatibility_mode.as_str() {
        "strict" => CompatibilityMode::Strict,
        "legacy" => CompatibilityMode::Legacy,
        other => bail!("invalid compatibility mode: {other}"),
    };
    Ok(RecoveryPolicy {
        compatibility_mode,
        fail_closed: policy.fail_closed,
    })
}

fn to_js_recovery_checkpoint(
    checkpoint: privacy_pools_sdk::recovery::RecoveryCheckpoint,
) -> JsRecoveryCheckpoint {
    JsRecoveryCheckpoint {
        latest_block: checkpoint.latest_block,
        commitments_seen: u64::try_from(checkpoint.commitments_seen).unwrap_or(u64::MAX),
    }
}
