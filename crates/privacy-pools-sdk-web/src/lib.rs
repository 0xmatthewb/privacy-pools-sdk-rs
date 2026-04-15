use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, SolValue, sol};
use anyhow::{Context, Result, bail};
use base64::Engine;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect, Uint8Array};
use privacy_pools_sdk_artifacts::{
    ArtifactBytes, ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
};
use privacy_pools_sdk_circuits as circuits;
use privacy_pools_sdk_core::{
    CircuitMerkleWitness, Commitment, CommitmentCircuitInput, CommitmentWitnessRequest,
    FormattedGroth16Proof, MasterKeys, MerkleProof, ProofBundle, RootRead, RootReadKind,
    TransactionKind, TransactionPlan, Withdrawal, WithdrawalCircuitInput, WithdrawalWitnessRequest,
    field_to_hex_32, parse_decimal_field,
};
use privacy_pools_sdk_prover::{self as prover, ProverBackend, ProvingResult};
use privacy_pools_sdk_recovery::{
    CompatibilityMode, DepositEvent, PoolEvent, PoolRecoveryInput, RagequitEvent,
    RecoveredAccountState, RecoveredCommitment, RecoveredPoolAccount, RecoveredScope,
    RecoveryCheckpoint, RecoveryKeyset, RecoveryPolicy, SpendableScope, WithdrawalEvent,
};
use privacy_pools_sdk_verifier::PreparedVerifier;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

sol! {
    struct WithdrawalAbi {
        address processooor;
        bytes data;
    }

    struct RelayDataAbi {
        address recipient;
        address feeRecipient;
        uint256 relayFeeBPS;
    }

    struct WithdrawProofAbi {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[8] pubSignals;
    }

    struct RagequitProofAbi {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[4] pubSignals;
    }

    interface IPrivacyPool {
        function currentRoot() external view returns (uint256);
        function withdraw(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof) external;
        function ragequit(RagequitProofAbi _proof) external;
    }

    interface IEntrypoint {
        function latestRoot() external view returns (uint256);
        function relay(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof, uint256 scope) external;
    }
}

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
struct JsRecoveryKeyset {
    safe: JsMasterKeys,
    legacy: Option<JsMasterKeys>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsDepositEvent {
    commitment_hash: String,
    label: String,
    value: String,
    precommitment_hash: String,
    block_number: u64,
    transaction_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsWithdrawalEvent {
    withdrawn_value: String,
    spent_nullifier_hash: String,
    new_commitment_hash: String,
    block_number: u64,
    transaction_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRagequitEvent {
    commitment_hash: String,
    label: String,
    value: String,
    block_number: u64,
    transaction_hash: String,
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
struct JsPoolRecoveryInput {
    scope: String,
    deposit_events: Vec<JsDepositEvent>,
    withdrawal_events: Vec<JsWithdrawalEvent>,
    ragequit_events: Vec<JsRagequitEvent>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveredCommitment {
    hash: String,
    value: String,
    label: String,
    nullifier: String,
    secret: String,
    block_number: u64,
    transaction_hash: String,
    is_migration: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveredPoolAccount {
    label: String,
    deposit: JsRecoveredCommitment,
    children: Vec<JsRecoveredCommitment>,
    ragequit: Option<JsRagequitEvent>,
    is_migrated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveredScope {
    scope: String,
    accounts: Vec<JsRecoveredPoolAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSpendableScope {
    scope: String,
    commitments: Vec<JsRecoveredCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecoveredAccountState {
    safe_master_keys: JsMasterKeys,
    legacy_master_keys: Option<JsMasterKeys>,
    safe_scopes: Vec<JsRecoveredScope>,
    legacy_scopes: Vec<JsRecoveredScope>,
    safe_spendable_commitments: Vec<JsSpendableScope>,
    legacy_spendable_commitments: Vec<JsSpendableScope>,
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
    proving_available: bool,
    verification_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSupportStatus {
    pub runtime: String,
    pub proving_available: bool,
    pub verification_available: bool,
    pub reason: String,
}

#[derive(Clone)]
struct BrowserCircuitSession {
    handle: String,
    circuit: String,
    artifact_version: String,
    verifier: PreparedVerifier,
    prepared: Option<prover::PreparedCircuitArtifacts>,
}

static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static SESSION_REGISTRY: LazyLock<RwLock<HashMap<String, BrowserCircuitSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[must_use]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[must_use]
pub fn get_browser_support_status() -> BrowserSupportStatus {
    BrowserSupportStatus {
        runtime: "browser".to_owned(),
        proving_available: true,
        verification_available: true,
        reason: "browser proving and verification are available through Rust/WASM with browser-native circuit witness execution"
            .to_owned(),
    }
}

#[must_use]
pub fn get_stable_backend_name() -> &'static str {
    "Arkworks"
}

#[must_use]
pub fn fast_backend_supported_on_target() -> bool {
    false
}

pub fn derive_master_keys_json(mnemonic: &str) -> Result<String> {
    let keys = privacy_pools_sdk_crypto::generate_master_keys(mnemonic)?;
    to_json_string(&to_js_master_keys(&keys))
}

pub fn derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> Result<String> {
    let master_keys = parse_json::<JsMasterKeys>(master_keys_json)?;
    let master_keys = to_master_keys(&master_keys)?;
    let secrets = privacy_pools_sdk_crypto::generate_deposit_secrets(
        &master_keys,
        parse_field(scope)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: secrets.1.to_decimal_string(),
    })
}

pub fn derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> Result<String> {
    let master_keys = parse_json::<JsMasterKeys>(master_keys_json)?;
    let master_keys = to_master_keys(&master_keys)?;
    let secrets = privacy_pools_sdk_crypto::generate_withdrawal_secrets(
        &master_keys,
        parse_field(label)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: field_label(secrets.0),
        secret: secrets.1.to_decimal_string(),
    })
}

pub fn get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> Result<String> {
    let commitment = privacy_pools_sdk_crypto::get_commitment(
        parse_field(value)?,
        parse_field(label)?,
        parse_field(nullifier)?,
        parse_field(secret)?,
    )?;
    to_json_string(&to_js_commitment(&commitment))
}

pub fn calculate_withdrawal_context_json(withdrawal_json: &str, scope: &str) -> Result<String> {
    let withdrawal = parse_json::<JsWithdrawal>(withdrawal_json)?;
    let withdrawal = from_js_withdrawal(&withdrawal)?;
    privacy_pools_sdk_crypto::calculate_context(&withdrawal, parse_field(scope)?)
        .map_err(Into::into)
}

pub fn generate_merkle_proof_json(leaves_json: &str, leaf: &str) -> Result<String> {
    let leaves = parse_json::<Vec<String>>(leaves_json)?;
    let leaves = leaves
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>>>()?;
    let proof = privacy_pools_sdk_tree::generate_merkle_proof(&leaves, parse_field(leaf)?)?;
    let proof = to_js_merkle_proof(proof)?;
    to_json_string(&proof)
}

pub fn build_circuit_merkle_witness_json(proof_json: &str, depth: u32) -> Result<String> {
    let proof = parse_json::<JsMerkleProof>(proof_json)?;
    let proof = from_js_merkle_proof(&proof)?;
    let witness = privacy_pools_sdk_tree::to_circuit_witness(
        &proof,
        usize::try_from(depth).context("merkle witness depth does not fit into usize")?,
    )?;
    let witness = to_js_circuit_merkle_witness(witness)?;
    to_json_string(&witness)
}

pub fn build_withdrawal_circuit_input_json(request_json: &str) -> Result<String> {
    let request = parse_json::<JsWithdrawalWitnessRequest>(request_json)?;
    let request = from_js_withdrawal_witness_request(&request)?;
    let input = circuits::build_withdrawal_circuit_input(&request)?;
    let input = to_js_withdrawal_circuit_input(input)?;
    to_json_string(&input)
}

pub fn build_withdrawal_witness_input_json(request_json: &str) -> Result<String> {
    let request = parse_json::<JsWithdrawalWitnessRequest>(request_json)?;
    let request = from_js_withdrawal_witness_request(&request)?;
    let input = circuits::build_withdrawal_circuit_input(&request)?;
    prover::serialize_withdrawal_circuit_input(&input).map_err(Into::into)
}

pub fn build_commitment_circuit_input_json(request_json: &str) -> Result<String> {
    let request = parse_json::<JsCommitmentWitnessRequest>(request_json)?;
    let request = from_js_commitment_witness_request(&request)?;
    let input = circuits::build_commitment_circuit_input(&request)?;
    to_json_string(&to_js_commitment_circuit_input(&input))
}

pub fn build_commitment_witness_input_json(request_json: &str) -> Result<String> {
    let request = parse_json::<JsCommitmentWitnessRequest>(request_json)?;
    let request = from_js_commitment_witness_request(&request)?;
    let input = circuits::build_commitment_circuit_input(&request)?;
    prover::serialize_commitment_circuit_input(&input).map_err(Into::into)
}

pub fn checkpoint_recovery_json(events_json: &str, policy_json: &str) -> Result<String> {
    let events = parse_json::<Vec<JsPoolEvent>>(events_json).and_then(from_js_pool_events)?;
    let policy = parse_json::<JsRecoveryPolicy>(policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))?;
    let checkpoint = privacy_pools_sdk_recovery::checkpoint(&events, policy)?;
    to_json_string(&to_js_recovery_checkpoint(&checkpoint))
}

pub fn derive_recovery_keyset_json(mnemonic: &str, policy_json: &str) -> Result<String> {
    let policy = parse_json::<JsRecoveryPolicy>(policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))?;
    let keyset = privacy_pools_sdk_recovery::derive_recovery_keyset(mnemonic, policy)?;
    to_json_string(&to_js_recovery_keyset(&keyset))
}

pub fn recover_account_state_json(
    mnemonic: &str,
    pools_json: &str,
    policy_json: &str,
) -> Result<String> {
    let pools = parse_json::<Vec<JsPoolRecoveryInput>>(pools_json)
        .and_then(from_js_pool_recovery_inputs)?;
    let policy = parse_json::<JsRecoveryPolicy>(policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))?;
    let state = privacy_pools_sdk_recovery::recover_account_state(mnemonic, &pools, policy)?;
    to_json_string(&to_js_recovered_account_state(&state))
}

pub fn recover_account_state_with_keyset_json(
    keyset_json: &str,
    pools_json: &str,
    policy_json: &str,
) -> Result<String> {
    let keyset = parse_json::<JsRecoveryKeyset>(keyset_json)
        .and_then(|keyset| from_js_recovery_keyset(&keyset))?;
    let pools = parse_json::<Vec<JsPoolRecoveryInput>>(pools_json)
        .and_then(from_js_pool_recovery_inputs)?;
    let policy = parse_json::<JsRecoveryPolicy>(policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))?;
    let state =
        privacy_pools_sdk_recovery::recover_account_state_with_keyset(&keyset, &pools, policy)?;
    to_json_string(&to_js_recovered_account_state(&state))
}

pub fn is_current_state_root(expected_root: &str, current_root: &str) -> Result<bool> {
    Ok(parse_field(expected_root)? == parse_field(current_root)?)
}

pub fn format_groth16_proof_bundle_json(proof_json: &str) -> Result<String> {
    let proof = parse_json::<ProofBundle>(proof_json)?;
    to_json_string(&to_js_formatted_groth16_proof(format_groth16_proof(
        &proof,
    )?))
}

pub fn plan_pool_state_root_read_json(pool_address: &str) -> Result<String> {
    to_json_string(&to_js_root_read(state_root_read(parse_address(
        pool_address,
    )?)))
}

pub fn plan_asp_root_read_json(entrypoint_address: &str, pool_address: &str) -> Result<String> {
    to_json_string(&to_js_root_read(asp_root_read(
        parse_address(entrypoint_address)?,
        parse_address(pool_address)?,
    )))
}

pub fn plan_withdrawal_transaction_json(
    chain_id: u64,
    pool_address: &str,
    withdrawal_json: &str,
    proof_json: &str,
) -> Result<String> {
    let withdrawal = parse_json::<JsWithdrawal>(withdrawal_json)?;
    let withdrawal = from_js_withdrawal(&withdrawal)?;
    let proof = parse_json::<ProofBundle>(proof_json)?;
    let plan =
        plan_withdrawal_transaction(chain_id, parse_address(pool_address)?, &withdrawal, &proof)?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn plan_relay_transaction_json(
    chain_id: u64,
    entrypoint_address: &str,
    withdrawal_json: &str,
    proof_json: &str,
    scope: &str,
) -> Result<String> {
    let withdrawal = parse_json::<JsWithdrawal>(withdrawal_json)?;
    let withdrawal = from_js_withdrawal(&withdrawal)?;
    let proof = parse_json::<ProofBundle>(proof_json)?;
    let plan = plan_relay_transaction(
        chain_id,
        parse_address(entrypoint_address)?,
        &withdrawal,
        &proof,
        parse_field(scope)?,
    )?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn plan_ragequit_transaction_json(
    chain_id: u64,
    pool_address: &str,
    proof_json: &str,
) -> Result<String> {
    let proof = parse_json::<ProofBundle>(proof_json)?;
    let plan = plan_ragequit_transaction(chain_id, parse_address(pool_address)?, &proof)?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let bundle = manifest.verify_bundle_bytes(circuit, artifacts)?;
    to_json_string(&to_js_verified_artifact_bundle(&bundle))
}

pub fn get_artifact_statuses_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let statuses =
        privacy_pools_sdk_artifacts::artifact_statuses(&manifest, artifacts_root, circuit)
            .into_iter()
            .map(|status| to_js_artifact_status(&manifest.version, status))
            .collect::<Vec<_>>();
    to_json_string(&statuses)
}

pub fn resolve_verified_artifact_bundle_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let bundle = manifest.resolve_verified_bundle(artifacts_root, circuit)?;
    to_json_string(&to_js_resolved_artifact_bundle(bundle))
}

pub fn prepare_withdrawal_circuit_session_from_bytes_json(
    manifest_json: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")?;
    to_json_string(&to_js_session_handle(&session))
}

pub fn prepare_commitment_circuit_session_from_bytes_json(
    manifest_json: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "commitment")?;
    to_json_string(&to_js_session_handle(&session))
}

pub fn verify_withdrawal_proof_json(
    manifest_json: &str,
    artifacts_json: &str,
    proof_json: &str,
) -> Result<bool> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")?;
    let proof =
        parse_json::<ProofBundle>(proof_json).context("failed to parse proof JSON payload")?;
    session.verifier.verify(&proof).map_err(Into::into)
}

pub fn verify_commitment_proof_json(
    manifest_json: &str,
    artifacts_json: &str,
    proof_json: &str,
) -> Result<bool> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "commitment")?;
    let proof =
        parse_json::<ProofBundle>(proof_json).context("failed to parse proof JSON payload")?;
    session.verifier.verify(&proof).map_err(Into::into)
}

pub fn prove_withdrawal_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")?;
    prove_with_session_witness(&session, witness_json).and_then(|result| to_json_string(&result))
}

pub fn prove_commitment_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "commitment")?;
    prove_with_session_witness(&session, witness_json).and_then(|result| to_json_string(&result))
}

pub fn prove_withdrawal_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> Result<String> {
    let registry = SESSION_REGISTRY
        .read()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    let session = registry.get(session_handle).cloned().with_context(|| {
        format!("unknown browser withdrawal circuit session `{session_handle}`")
    })?;
    if session.circuit != "withdraw" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    prove_with_session_witness(&session, witness_json).and_then(|result| to_json_string(&result))
}

pub fn prove_commitment_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> Result<String> {
    let registry = SESSION_REGISTRY
        .read()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    let session = registry.get(session_handle).cloned().with_context(|| {
        format!("unknown browser commitment circuit session `{session_handle}`")
    })?;
    if session.circuit != "commitment" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    prove_with_session_witness(&session, witness_json).and_then(|result| to_json_string(&result))
}

pub fn verify_withdrawal_proof_with_session_json(
    session_handle: &str,
    proof_json: &str,
) -> Result<bool> {
    let proof =
        parse_json::<ProofBundle>(proof_json).context("failed to parse proof JSON payload")?;
    let registry = SESSION_REGISTRY
        .read()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    let session = registry.get(session_handle).cloned().with_context(|| {
        format!("unknown browser withdrawal circuit session `{session_handle}`")
    })?;
    if session.circuit != "withdraw" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    session.verifier.verify(&proof).map_err(Into::into)
}

pub fn verify_commitment_proof_with_session_json(
    session_handle: &str,
    proof_json: &str,
) -> Result<bool> {
    let proof =
        parse_json::<ProofBundle>(proof_json).context("failed to parse proof JSON payload")?;
    let registry = SESSION_REGISTRY
        .read()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    let session = registry.get(session_handle).cloned().with_context(|| {
        format!("unknown browser commitment circuit session `{session_handle}`")
    })?;
    if session.circuit != "commitment" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    session.verifier.verify(&proof).map_err(Into::into)
}

pub fn remove_withdrawal_circuit_session(session_handle: &str) -> Result<bool> {
    let mut registry = SESSION_REGISTRY
        .write()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    Ok(registry
        .get(session_handle)
        .is_some_and(|session| session.circuit == "withdraw")
        && registry.remove(session_handle).is_some())
}

pub fn remove_commitment_circuit_session(session_handle: &str) -> Result<bool> {
    let mut registry = SESSION_REGISTRY
        .write()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?;
    Ok(registry
        .get(session_handle)
        .is_some_and(|session| session.circuit == "commitment")
        && registry.remove(session_handle).is_some())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getVersion)]
pub fn wasm_get_version() -> String {
    get_version()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getBrowserSupportStatusJson)]
pub fn wasm_get_browser_support_status_json() -> String {
    to_json_string(&get_browser_support_status()).expect("browser support status must serialize")
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getStableBackendName)]
pub fn wasm_get_stable_backend_name() -> String {
    get_stable_backend_name().to_owned()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = fastBackendSupportedOnTarget)]
pub fn wasm_fast_backend_supported_on_target() -> bool {
    fast_backend_supported_on_target()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveMasterKeysJson)]
pub fn wasm_derive_master_keys_json(mnemonic: &str) -> std::result::Result<String, JsValue> {
    derive_master_keys_json(mnemonic).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveDepositSecretsJson)]
pub fn wasm_derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> std::result::Result<String, JsValue> {
    derive_deposit_secrets_json(master_keys_json, scope, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveWithdrawalSecretsJson)]
pub fn wasm_derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> std::result::Result<String, JsValue> {
    derive_withdrawal_secrets_json(master_keys_json, label, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getCommitmentJson)]
pub fn wasm_get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> std::result::Result<String, JsValue> {
    get_commitment_json(value, label, nullifier, secret).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = calculateWithdrawalContextJson)]
pub fn wasm_calculate_withdrawal_context_json(
    withdrawal_json: &str,
    scope: &str,
) -> std::result::Result<String, JsValue> {
    calculate_withdrawal_context_json(withdrawal_json, scope).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateMerkleProofJson)]
pub fn wasm_generate_merkle_proof_json(
    leaves_json: &str,
    leaf: &str,
) -> std::result::Result<String, JsValue> {
    generate_merkle_proof_json(leaves_json, leaf).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCircuitMerkleWitnessJson)]
pub fn wasm_build_circuit_merkle_witness_json(
    proof_json: &str,
    depth: u32,
) -> std::result::Result<String, JsValue> {
    build_circuit_merkle_witness_json(proof_json, depth).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildWithdrawalCircuitInputJson)]
pub fn wasm_build_withdrawal_circuit_input_json(
    request_json: &str,
) -> std::result::Result<String, JsValue> {
    build_withdrawal_circuit_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildWithdrawalWitnessInputJson)]
pub fn wasm_build_withdrawal_witness_input_json(
    request_json: &str,
) -> std::result::Result<String, JsValue> {
    build_withdrawal_witness_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCommitmentCircuitInputJson)]
pub fn wasm_build_commitment_circuit_input_json(
    request_json: &str,
) -> std::result::Result<String, JsValue> {
    build_commitment_circuit_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCommitmentWitnessInputJson)]
pub fn wasm_build_commitment_witness_input_json(
    request_json: &str,
) -> std::result::Result<String, JsValue> {
    build_commitment_witness_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = checkpointRecoveryJson)]
pub fn wasm_checkpoint_recovery_json(
    events_json: &str,
    policy_json: &str,
) -> std::result::Result<String, JsValue> {
    checkpoint_recovery_json(events_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveRecoveryKeysetJson)]
pub fn wasm_derive_recovery_keyset_json(
    mnemonic: &str,
    policy_json: &str,
) -> std::result::Result<String, JsValue> {
    derive_recovery_keyset_json(mnemonic, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = recoverAccountStateJson)]
pub fn wasm_recover_account_state_json(
    mnemonic: &str,
    pools_json: &str,
    policy_json: &str,
) -> std::result::Result<String, JsValue> {
    recover_account_state_json(mnemonic, pools_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = recoverAccountStateWithKeysetJson)]
pub fn wasm_recover_account_state_with_keyset_json(
    keyset_json: &str,
    pools_json: &str,
    policy_json: &str,
) -> std::result::Result<String, JsValue> {
    recover_account_state_with_keyset_json(keyset_json, pools_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = isCurrentStateRoot)]
pub fn wasm_is_current_state_root(
    expected_root: &str,
    current_root: &str,
) -> std::result::Result<bool, JsValue> {
    is_current_state_root(expected_root, current_root).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = formatGroth16ProofBundleJson)]
pub fn wasm_format_groth16_proof_bundle_json(
    proof_json: &str,
) -> std::result::Result<String, JsValue> {
    format_groth16_proof_bundle_json(proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planPoolStateRootReadJson)]
pub fn wasm_plan_pool_state_root_read_json(
    pool_address: &str,
) -> std::result::Result<String, JsValue> {
    plan_pool_state_root_read_json(pool_address).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planAspRootReadJson)]
pub fn wasm_plan_asp_root_read_json(
    entrypoint_address: &str,
    pool_address: &str,
) -> std::result::Result<String, JsValue> {
    plan_asp_root_read_json(entrypoint_address, pool_address).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planWithdrawalTransactionJson)]
pub fn wasm_plan_withdrawal_transaction_json(
    chain_id: u64,
    pool_address: &str,
    withdrawal_json: &str,
    proof_json: &str,
) -> std::result::Result<String, JsValue> {
    plan_withdrawal_transaction_json(chain_id, pool_address, withdrawal_json, proof_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planRelayTransactionJson)]
pub fn wasm_plan_relay_transaction_json(
    chain_id: u64,
    entrypoint_address: &str,
    withdrawal_json: &str,
    proof_json: &str,
    scope: &str,
) -> std::result::Result<String, JsValue> {
    plan_relay_transaction_json(
        chain_id,
        entrypoint_address,
        withdrawal_json,
        proof_json,
        scope,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planRagequitTransactionJson)]
pub fn wasm_plan_ragequit_transaction_json(
    chain_id: u64,
    pool_address: &str,
    proof_json: &str,
) -> std::result::Result<String, JsValue> {
    plan_ragequit_transaction_json(chain_id, pool_address, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyArtifactBytesJson)]
pub fn wasm_verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> std::result::Result<String, JsValue> {
    verify_artifact_bytes_json(manifest_json, circuit, artifacts_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyArtifactBytes)]
pub fn wasm_verify_artifact_bytes(
    manifest_json: &str,
    circuit: &str,
    artifacts: Array,
) -> std::result::Result<String, JsValue> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let bundle = manifest
        .verify_bundle_bytes(circuit, artifacts)
        .map_err(|error| js_error(error.into()))?;
    to_json_string(&to_js_verified_artifact_bundle(&bundle)).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = prepareWithdrawalCircuitSessionFromBytes)]
pub fn wasm_prepare_withdrawal_circuit_session_from_bytes(
    manifest_json: &str,
    artifacts: Array,
) -> std::result::Result<String, JsValue> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")
        .map_err(js_error)?;
    to_json_string(&to_js_session_handle(&session)).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = prepareCommitmentCircuitSessionFromBytes)]
pub fn wasm_prepare_commitment_circuit_session_from_bytes(
    manifest_json: &str,
    artifacts: Array,
) -> std::result::Result<String, JsValue> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "commitment")
        .map_err(js_error)?;
    to_json_string(&to_js_session_handle(&session)).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyWithdrawalProof)]
pub fn wasm_verify_withdrawal_proof(
    manifest_json: &str,
    artifacts: Array,
    proof_json: &str,
) -> std::result::Result<bool, JsValue> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")
        .map_err(js_error)?;
    let proof = parse_json::<ProofBundle>(proof_json).map_err(js_error)?;
    session
        .verifier
        .verify(&proof)
        .map_err(|error| js_error(error.into()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyCommitmentProof)]
pub fn wasm_verify_commitment_proof(
    manifest_json: &str,
    artifacts: Array,
    proof_json: &str,
) -> std::result::Result<bool, JsValue> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "commitment")
        .map_err(js_error)?;
    let proof = parse_json::<ProofBundle>(proof_json).map_err(js_error)?;
    session
        .verifier
        .verify(&proof)
        .map_err(|error| js_error(error.into()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyWithdrawalProofWithSession)]
pub fn wasm_verify_withdrawal_proof_with_session(
    session_handle: &str,
    proof_json: &str,
) -> std::result::Result<bool, JsValue> {
    verify_withdrawal_proof_with_session_json(session_handle, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveWithdrawalWithWitnessJson)]
pub fn wasm_prove_withdrawal_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> std::result::Result<String, JsValue> {
    prove_withdrawal_with_witness_json(manifest_json, artifacts_json, witness_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveWithdrawalWithSessionWitnessJson)]
pub fn wasm_prove_withdrawal_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> std::result::Result<String, JsValue> {
    prove_withdrawal_with_session_witness_json(session_handle, witness_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyCommitmentProofWithSession)]
pub fn wasm_verify_commitment_proof_with_session(
    session_handle: &str,
    proof_json: &str,
) -> std::result::Result<bool, JsValue> {
    verify_commitment_proof_with_session_json(session_handle, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveCommitmentWithWitnessJson)]
pub fn wasm_prove_commitment_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> std::result::Result<String, JsValue> {
    prove_commitment_with_witness_json(manifest_json, artifacts_json, witness_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveCommitmentWithSessionWitnessJson)]
pub fn wasm_prove_commitment_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> std::result::Result<String, JsValue> {
    prove_commitment_with_session_witness_json(session_handle, witness_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeWithdrawalCircuitSession)]
pub fn wasm_remove_withdrawal_circuit_session(
    session_handle: &str,
) -> std::result::Result<bool, JsValue> {
    remove_withdrawal_circuit_session(session_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeCommitmentCircuitSession)]
pub fn wasm_remove_commitment_circuit_session(
    session_handle: &str,
) -> std::result::Result<bool, JsValue> {
    remove_commitment_circuit_session(session_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getArtifactStatusesJson)]
pub fn wasm_get_artifact_statuses_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, JsValue> {
    get_artifact_statuses_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = resolveVerifiedArtifactBundleJson)]
pub fn wasm_resolve_verified_artifact_bundle_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, JsValue> {
    resolve_verified_artifact_bundle_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: anyhow::Error) -> JsValue {
    JsValue::from_str(&error.to_string())
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

fn parse_b256(value: &str) -> Result<B256> {
    B256::from_str(value).with_context(|| format!("invalid bytes32 `{value}`"))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => bail!("invalid artifact kind: {value}"),
    }
}

fn artifact_kind_label(kind: ArtifactKind) -> String {
    match kind {
        ArtifactKind::Wasm => "wasm".to_owned(),
        ArtifactKind::Zkey => "zkey".to_owned(),
        ArtifactKind::Vkey => "vkey".to_owned(),
    }
}

fn field_label(value: U256) -> String {
    value.to_string()
}

fn to_master_keys(keys: &JsMasterKeys) -> Result<MasterKeys> {
    Ok(MasterKeys {
        master_nullifier: parse_field(&keys.master_nullifier)?.into(),
        master_secret: parse_field(&keys.master_secret)?.into(),
    })
}

fn to_js_master_keys(keys: &MasterKeys) -> JsMasterKeys {
    JsMasterKeys {
        master_nullifier: keys.master_nullifier.to_decimal_string(),
        master_secret: keys.master_secret.to_decimal_string(),
    }
}

fn to_js_commitment(commitment: &Commitment) -> JsCommitment {
    JsCommitment {
        hash: field_label(commitment.hash),
        nullifier_hash: field_label(commitment.nullifier_hash),
        precommitment_hash: field_label(commitment.preimage.precommitment.hash),
        value: field_label(commitment.preimage.value),
        label: field_label(commitment.preimage.label),
        nullifier: field_label(commitment.preimage.precommitment.nullifier),
        secret: commitment.preimage.precommitment.secret.to_decimal_string(),
    }
}

fn from_js_withdrawal(withdrawal: &JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processor: parse_address(&withdrawal.processooor)?,
        data: data.into(),
    })
}

fn to_js_merkle_proof(proof: MerkleProof) -> Result<JsMerkleProof> {
    Ok(JsMerkleProof {
        root: field_label(proof.root),
        leaf: field_label(proof.leaf),
        index: u64::try_from(proof.index).context("merkle proof index does not fit into u64")?,
        siblings: proof.siblings.into_iter().map(field_label).collect(),
    })
}

fn from_js_merkle_proof(proof: &JsMerkleProof) -> Result<MerkleProof> {
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

fn from_js_commitment(commitment: &JsCommitment) -> Result<Commitment> {
    Ok(Commitment {
        hash: parse_field(&commitment.hash)?,
        nullifier_hash: parse_field(&commitment.nullifier_hash)?,
        preimage: privacy_pools_sdk_core::CommitmentPreimage {
            value: parse_field(&commitment.value)?,
            label: parse_field(&commitment.label)?,
            precommitment: privacy_pools_sdk_core::Precommitment {
                hash: parse_field(&commitment.precommitment_hash)?,
                nullifier: parse_field(&commitment.nullifier)?,
                secret: parse_field(&commitment.secret)?.into(),
            },
        },
    })
}

fn from_js_commitment_witness_request(
    request: &JsCommitmentWitnessRequest,
) -> Result<CommitmentWitnessRequest> {
    Ok(CommitmentWitnessRequest {
        commitment: from_js_commitment(&request.commitment)?,
    })
}

fn from_js_circuit_merkle_witness(
    witness: &JsCircuitMerkleWitness,
) -> Result<CircuitMerkleWitness> {
    Ok(CircuitMerkleWitness {
        root: parse_field(&witness.root)?,
        leaf: parse_field(&witness.leaf)?,
        index: usize::try_from(witness.index).context("circuit witness index does not fit")?,
        siblings: witness
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>>>()?,
        depth: usize::try_from(witness.depth).context("circuit witness depth does not fit")?,
    })
}

fn from_js_withdrawal_witness_request(
    request: &JsWithdrawalWitnessRequest,
) -> Result<WithdrawalWitnessRequest> {
    Ok(WithdrawalWitnessRequest {
        commitment: from_js_commitment(&request.commitment)?,
        withdrawal: from_js_withdrawal(&request.withdrawal)?,
        scope: parse_field(&request.scope)?,
        withdrawal_amount: parse_field(&request.withdrawal_amount)?,
        state_witness: from_js_circuit_merkle_witness(&request.state_witness)?,
        asp_witness: from_js_circuit_merkle_witness(&request.asp_witness)?,
        new_nullifier: parse_field(&request.new_nullifier)?.into(),
        new_secret: parse_field(&request.new_secret)?.into(),
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
        existing_nullifier: input.existing_nullifier.to_decimal_string(),
        existing_secret: input.existing_secret.to_decimal_string(),
        new_nullifier: input.new_nullifier.to_decimal_string(),
        new_secret: input.new_secret.to_decimal_string(),
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
        nullifier: input.nullifier.to_decimal_string(),
        secret: input.secret.to_decimal_string(),
    }
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

fn format_groth16_proof(proof: &ProofBundle) -> Result<FormattedGroth16Proof> {
    Ok(FormattedGroth16Proof {
        p_a: [
            field_to_hex_32(parse_bn254_proof_coordinate(
                &proof.proof.pi_a[0],
                "piA[0]",
            )?),
            field_to_hex_32(parse_bn254_proof_coordinate(
                &proof.proof.pi_a[1],
                "piA[1]",
            )?),
        ],
        p_b: [
            [
                field_to_hex_32(parse_bn254_proof_coordinate(
                    &proof.proof.pi_b[0][1],
                    "piB[0][1]",
                )?),
                field_to_hex_32(parse_bn254_proof_coordinate(
                    &proof.proof.pi_b[0][0],
                    "piB[0][0]",
                )?),
            ],
            [
                field_to_hex_32(parse_bn254_proof_coordinate(
                    &proof.proof.pi_b[1][1],
                    "piB[1][1]",
                )?),
                field_to_hex_32(parse_bn254_proof_coordinate(
                    &proof.proof.pi_b[1][0],
                    "piB[1][0]",
                )?),
            ],
        ],
        p_c: [
            field_to_hex_32(parse_bn254_proof_coordinate(
                &proof.proof.pi_c[0],
                "piC[0]",
            )?),
            field_to_hex_32(parse_bn254_proof_coordinate(
                &proof.proof.pi_c[1],
                "piC[1]",
            )?),
        ],
        pub_signals: proof
            .public_signals
            .iter()
            .enumerate()
            .map(|(index, value)| parse_bn254_public_signal(value, index).map(field_to_hex_32))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn parse_bn254_proof_coordinate(value: &str, field: &str) -> Result<U256> {
    let parsed = parse_decimal_field(value)?;
    ensure_canonical_proof_field(field, parsed, bn254_base_field_modulus())?;
    Ok(parsed)
}

fn parse_bn254_public_signal(value: &str, index: usize) -> Result<U256> {
    let parsed = parse_decimal_field(value)?;
    ensure_canonical_proof_field(
        &format!("publicSignals[{index}]"),
        parsed,
        bn254_scalar_field_modulus(),
    )?;
    Ok(parsed)
}

fn ensure_canonical_proof_field(field: &str, value: U256, modulus: U256) -> Result<()> {
    if value >= modulus {
        bail!("proof field `{field}` is not canonical: {value} >= {modulus}");
    }
    Ok(())
}

fn bn254_base_field_modulus() -> U256 {
    parse_decimal_field(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .expect("valid BN254 base field modulus")
}

fn bn254_scalar_field_modulus() -> U256 {
    parse_decimal_field(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("valid BN254 scalar field modulus")
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

fn to_js_root_read(read: RootRead) -> JsRootRead {
    JsRootRead {
        kind: root_read_kind_label(read.kind),
        contract_address: read.contract_address.to_string(),
        pool_address: read.pool_address.to_string(),
        call_data: format!("0x{}", hex::encode(read.call_data)),
    }
}

fn state_root_read(pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        call_data: Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode()),
    }
}

fn asp_root_read(entrypoint_address: Address, pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::Asp,
        contract_address: entrypoint_address,
        pool_address,
        call_data: Bytes::from(IEntrypoint::latestRootCall {}.abi_encode()),
    }
}

fn plan_withdrawal_transaction(
    chain_id: u64,
    pool_address: Address,
    withdrawal: &Withdrawal,
    proof: &ProofBundle,
) -> Result<TransactionPlan> {
    ensure_non_zero_address(pool_address, "pool address")?;
    ensure_non_zero_address(withdrawal.processor, "withdrawal processor")?;
    let formatted = format_groth16_proof(proof)?;
    let calldata = Bytes::from(
        IPrivacyPool::withdrawCall {
            _withdrawal: withdrawal_abi(withdrawal),
            _proof: withdraw_proof_abi(proof)?,
        }
        .abi_encode(),
    );

    Ok(TransactionPlan {
        kind: TransactionKind::Withdraw,
        chain_id,
        target: pool_address,
        calldata,
        value: U256::ZERO,
        proof: formatted,
    })
}

fn plan_relay_transaction(
    chain_id: u64,
    entrypoint_address: Address,
    withdrawal: &Withdrawal,
    proof: &ProofBundle,
    scope: U256,
) -> Result<TransactionPlan> {
    ensure_non_zero_address(entrypoint_address, "entrypoint address")?;
    if withdrawal.processor != entrypoint_address {
        bail!(
            "relay withdrawal processor mismatch: expected {entrypoint_address}, got {}",
            withdrawal.processor
        );
    }
    parse_relay_data(&withdrawal.data)?;
    let public_signals = withdraw_public_signals(proof)?;
    if public_signals[2].is_zero() {
        bail!("relay transactions require a non-zero withdrawn value");
    }

    let formatted = format_groth16_proof(proof)?;
    let calldata = Bytes::from(
        IEntrypoint::relayCall {
            _withdrawal: withdrawal_abi(withdrawal),
            _proof: withdraw_proof_abi(proof)?,
            scope,
        }
        .abi_encode(),
    );

    Ok(TransactionPlan {
        kind: TransactionKind::Relay,
        chain_id,
        target: entrypoint_address,
        calldata,
        value: U256::ZERO,
        proof: formatted,
    })
}

fn plan_ragequit_transaction(
    chain_id: u64,
    pool_address: Address,
    proof: &ProofBundle,
) -> Result<TransactionPlan> {
    ensure_non_zero_address(pool_address, "pool address")?;
    let formatted = format_groth16_proof(proof)?;
    let calldata = Bytes::from(
        IPrivacyPool::ragequitCall {
            _proof: ragequit_proof_abi(proof)?,
        }
        .abi_encode(),
    );

    Ok(TransactionPlan {
        kind: TransactionKind::Ragequit,
        chain_id,
        target: pool_address,
        calldata,
        value: U256::ZERO,
        proof: formatted,
    })
}

fn withdrawal_abi(withdrawal: &Withdrawal) -> WithdrawalAbi {
    WithdrawalAbi {
        processooor: withdrawal.processor,
        data: withdrawal.data.clone(),
    }
}

fn withdraw_public_signals(proof: &ProofBundle) -> Result<[U256; 8]> {
    let public_signals = proof
        .public_signals
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_public_signal(value, index))
        .collect::<Result<Vec<_>>>()?;
    public_signals.try_into().map_err(|signals: Vec<U256>| {
        anyhow::anyhow!(
            "withdraw proof must contain exactly 8 public signals, got {}",
            signals.len()
        )
    })
}

fn ragequit_public_signals(proof: &ProofBundle) -> Result<[U256; 4]> {
    let public_signals = proof
        .public_signals
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_public_signal(value, index))
        .collect::<Result<Vec<_>>>()?;
    public_signals.try_into().map_err(|signals: Vec<U256>| {
        anyhow::anyhow!(
            "ragequit proof must contain exactly 4 public signals, got {}",
            signals.len()
        )
    })
}

fn withdraw_proof_abi(proof: &ProofBundle) -> Result<WithdrawProofAbi> {
    let public_signals = withdraw_public_signals(proof)?;
    Ok(WithdrawProofAbi {
        pA: [
            parse_bn254_proof_coordinate(&proof.proof.pi_a[0], "piA[0]")?,
            parse_bn254_proof_coordinate(&proof.proof.pi_a[1], "piA[1]")?,
        ],
        pB: [
            [
                parse_bn254_proof_coordinate(&proof.proof.pi_b[0][1], "piB[0][1]")?,
                parse_bn254_proof_coordinate(&proof.proof.pi_b[0][0], "piB[0][0]")?,
            ],
            [
                parse_bn254_proof_coordinate(&proof.proof.pi_b[1][1], "piB[1][1]")?,
                parse_bn254_proof_coordinate(&proof.proof.pi_b[1][0], "piB[1][0]")?,
            ],
        ],
        pC: [
            parse_bn254_proof_coordinate(&proof.proof.pi_c[0], "piC[0]")?,
            parse_bn254_proof_coordinate(&proof.proof.pi_c[1], "piC[1]")?,
        ],
        pubSignals: public_signals,
    })
}

fn ragequit_proof_abi(proof: &ProofBundle) -> Result<RagequitProofAbi> {
    let public_signals = ragequit_public_signals(proof)?;
    Ok(RagequitProofAbi {
        pA: [
            parse_bn254_proof_coordinate(&proof.proof.pi_a[0], "piA[0]")?,
            parse_bn254_proof_coordinate(&proof.proof.pi_a[1], "piA[1]")?,
        ],
        pB: [
            [
                parse_bn254_proof_coordinate(&proof.proof.pi_b[0][1], "piB[0][1]")?,
                parse_bn254_proof_coordinate(&proof.proof.pi_b[0][0], "piB[0][0]")?,
            ],
            [
                parse_bn254_proof_coordinate(&proof.proof.pi_b[1][1], "piB[1][1]")?,
                parse_bn254_proof_coordinate(&proof.proof.pi_b[1][0], "piB[1][0]")?,
            ],
        ],
        pC: [
            parse_bn254_proof_coordinate(&proof.proof.pi_c[0], "piC[0]")?,
            parse_bn254_proof_coordinate(&proof.proof.pi_c[1], "piC[1]")?,
        ],
        pubSignals: public_signals,
    })
}

fn parse_relay_data(data: &Bytes) -> Result<RelayDataAbi> {
    let relay_data = RelayDataAbi::abi_decode(data.as_ref())
        .map_err(|error| anyhow::anyhow!("relay withdrawal data is invalid: {error}"))?;
    if relay_data.recipient.is_zero() {
        bail!("relay withdrawal data is invalid: recipient must be non-zero");
    }
    if relay_data.feeRecipient.is_zero() {
        bail!("relay withdrawal data is invalid: fee recipient must be non-zero");
    }
    Ok(relay_data)
}

fn ensure_non_zero_address(address: Address, field: &'static str) -> Result<()> {
    if address.is_zero() {
        bail!("{field} must be non-zero");
    }
    Ok(())
}

fn from_js_artifact_bytes(
    artifacts: Vec<JsArtifactBytes>,
) -> Result<Vec<privacy_pools_sdk_artifacts::ArtifactBytes>> {
    let engine = base64::engine::general_purpose::STANDARD;
    artifacts
        .into_iter()
        .map(|artifact| {
            Ok(privacy_pools_sdk_artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&artifact.kind)?,
                bytes: engine
                    .decode(artifact.bytes_base64)
                    .context("failed to decode base64 artifact bytes")?,
            })
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn from_wasm_artifact_bytes(
    artifacts: Array,
) -> Result<Vec<privacy_pools_sdk_artifacts::ArtifactBytes>> {
    artifacts
        .iter()
        .map(|artifact| {
            let kind = Reflect::get(&artifact, &JsValue::from_str("kind"))
                .map_err(|error| anyhow::anyhow!("failed to read artifact kind: {error:?}"))?
                .as_string()
                .context("artifact kind must be a string")?;
            let bytes = Reflect::get(&artifact, &JsValue::from_str("bytes"))
                .map_err(|error| anyhow::anyhow!("failed to read artifact bytes: {error:?}"))?;

            Ok(privacy_pools_sdk_artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&kind)?,
                bytes: Uint8Array::new(&bytes).to_vec(),
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
    bundle: &privacy_pools_sdk_artifacts::VerifiedArtifactBundle,
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

fn from_js_recovery_policy(policy: &JsRecoveryPolicy) -> Result<RecoveryPolicy> {
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

fn to_js_recovery_checkpoint(checkpoint: &RecoveryCheckpoint) -> JsRecoveryCheckpoint {
    JsRecoveryCheckpoint {
        latest_block: checkpoint.latest_block,
        commitments_seen: u64::try_from(checkpoint.commitments_seen).unwrap_or(u64::MAX),
    }
}

fn from_js_recovery_keyset(keyset: &JsRecoveryKeyset) -> Result<RecoveryKeyset> {
    Ok(RecoveryKeyset {
        safe: to_master_keys(&keyset.safe)?,
        legacy: keyset.legacy.as_ref().map(to_master_keys).transpose()?,
    })
}

fn to_js_recovery_keyset(keyset: &RecoveryKeyset) -> JsRecoveryKeyset {
    JsRecoveryKeyset {
        safe: to_js_master_keys(&keyset.safe),
        legacy: keyset.legacy.as_ref().map(to_js_master_keys),
    }
}

fn from_js_pool_recovery_inputs(
    inputs: Vec<JsPoolRecoveryInput>,
) -> Result<Vec<PoolRecoveryInput>> {
    inputs
        .into_iter()
        .map(|input| {
            Ok(PoolRecoveryInput {
                scope: parse_field(&input.scope)?,
                deposit_events: input
                    .deposit_events
                    .iter()
                    .map(from_js_deposit_event)
                    .collect::<Result<Vec<_>>>()?,
                withdrawal_events: input
                    .withdrawal_events
                    .iter()
                    .map(from_js_withdrawal_event)
                    .collect::<Result<Vec<_>>>()?,
                ragequit_events: input
                    .ragequit_events
                    .iter()
                    .map(from_js_ragequit_event)
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect()
}

fn from_js_deposit_event(event: &JsDepositEvent) -> Result<DepositEvent> {
    Ok(DepositEvent {
        commitment_hash: parse_field(&event.commitment_hash)?,
        label: parse_field(&event.label)?,
        value: parse_field(&event.value)?,
        precommitment_hash: parse_field(&event.precommitment_hash)?,
        block_number: event.block_number,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn from_js_withdrawal_event(event: &JsWithdrawalEvent) -> Result<WithdrawalEvent> {
    Ok(WithdrawalEvent {
        withdrawn_value: parse_field(&event.withdrawn_value)?,
        spent_nullifier_hash: parse_field(&event.spent_nullifier_hash)?,
        new_commitment_hash: parse_field(&event.new_commitment_hash)?,
        block_number: event.block_number,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn from_js_ragequit_event(event: &JsRagequitEvent) -> Result<RagequitEvent> {
    Ok(RagequitEvent {
        commitment_hash: parse_field(&event.commitment_hash)?,
        label: parse_field(&event.label)?,
        value: parse_field(&event.value)?,
        block_number: event.block_number,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn to_js_ragequit_event(event: &RagequitEvent) -> JsRagequitEvent {
    JsRagequitEvent {
        commitment_hash: field_label(event.commitment_hash),
        label: field_label(event.label),
        value: field_label(event.value),
        block_number: event.block_number,
        transaction_hash: event.transaction_hash.to_string(),
    }
}

fn to_js_recovered_commitment(commitment: &RecoveredCommitment) -> JsRecoveredCommitment {
    JsRecoveredCommitment {
        hash: field_label(commitment.hash),
        value: field_label(commitment.value),
        label: field_label(commitment.label),
        nullifier: field_label(commitment.nullifier),
        secret: commitment.secret.to_decimal_string(),
        block_number: commitment.block_number,
        transaction_hash: commitment.transaction_hash.to_string(),
        is_migration: commitment.is_migration,
    }
}

fn to_js_recovered_pool_account(account: &RecoveredPoolAccount) -> JsRecoveredPoolAccount {
    JsRecoveredPoolAccount {
        label: field_label(account.label),
        deposit: to_js_recovered_commitment(&account.deposit),
        children: account
            .children
            .iter()
            .map(to_js_recovered_commitment)
            .collect(),
        ragequit: account.ragequit.as_ref().map(to_js_ragequit_event),
        is_migrated: account.is_migrated,
    }
}

fn to_js_recovered_scope(scope: &RecoveredScope) -> JsRecoveredScope {
    JsRecoveredScope {
        scope: field_label(scope.scope),
        accounts: scope
            .accounts
            .iter()
            .map(to_js_recovered_pool_account)
            .collect(),
    }
}

fn to_js_spendable_scope(scope: &SpendableScope) -> JsSpendableScope {
    JsSpendableScope {
        scope: field_label(scope.scope),
        commitments: scope
            .commitments
            .iter()
            .map(to_js_recovered_commitment)
            .collect(),
    }
}

fn to_js_recovered_account_state(state: &RecoveredAccountState) -> JsRecoveredAccountState {
    let safe_spendable_commitments = state.safe_spendable_commitments();
    let legacy_spendable_commitments = state.legacy_spendable_commitments();
    JsRecoveredAccountState {
        safe_master_keys: to_js_master_keys(&state.safe_master_keys),
        legacy_master_keys: state.legacy_master_keys.as_ref().map(to_js_master_keys),
        safe_scopes: state
            .safe_scopes
            .iter()
            .map(to_js_recovered_scope)
            .collect(),
        legacy_scopes: state
            .legacy_scopes
            .iter()
            .map(to_js_recovered_scope)
            .collect(),
        safe_spendable_commitments: safe_spendable_commitments
            .iter()
            .map(to_js_spendable_scope)
            .collect(),
        legacy_spendable_commitments: legacy_spendable_commitments
            .iter()
            .map(to_js_spendable_scope)
            .collect(),
    }
}

fn prove_with_session_witness(
    session: &BrowserCircuitSession,
    witness_json: &str,
) -> Result<JsProvingResult> {
    let witness = parse_json::<Vec<String>>(witness_json)?;
    let witness = prover::parse_witness_values(&witness)?;
    let prepared = session.prepared.as_ref().with_context(|| {
        format!(
            "browser {} circuit session `{}` was prepared for verification only",
            session.circuit, session.handle
        )
    })?;
    let proving = prepared.prove_with_witness_values(witness)?;
    if !session.verifier.verify(&proving.proof)? {
        bail!("browser proof verification failed after proving");
    }
    Ok(to_js_proving_result(proving))
}

fn prepare_circuit_session_from_artifacts(
    manifest: &ArtifactManifest,
    artifacts: Vec<ArtifactBytes>,
    circuit: &str,
) -> Result<BrowserCircuitSession> {
    let bundle = manifest.verify_bundle_bytes(circuit, artifacts)?;
    let vkey = bundle.artifact(ArtifactKind::Vkey).with_context(|| {
        format!("verified artifact bundle is missing the {circuit} verification key")
    })?;
    let prepared = if bundle.artifact(ArtifactKind::Zkey).is_ok() {
        Some(prover::PreparedCircuitArtifacts::from_verified_bundle(
            &bundle,
        )?)
    } else {
        None
    };
    let verifier = PreparedVerifier::from_vkey_bytes(vkey.bytes())?;

    let handle = format!(
        "browser-{circuit}-session-{}",
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let session = BrowserCircuitSession {
        handle: handle.clone(),
        circuit: bundle.circuit().to_owned(),
        artifact_version: bundle.version().to_owned(),
        verifier,
        prepared,
    };

    SESSION_REGISTRY
        .write()
        .map_err(|error| anyhow::anyhow!("browser session registry poisoned: {error}"))?
        .insert(handle, session.clone());

    Ok(session)
}

fn to_js_session_handle(session: &BrowserCircuitSession) -> JsWithdrawalCircuitSessionHandle {
    JsWithdrawalCircuitSessionHandle {
        handle: session.handle.clone(),
        circuit: session.circuit.clone(),
        artifact_version: session.artifact_version.clone(),
        proving_available: session.prepared.is_some(),
        verification_available: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_status_reports_proving_available() {
        let status = get_browser_support_status();
        assert_eq!(status.runtime, "browser");
        assert!(status.proving_available);
        assert!(status.reason.contains("browser proving"));
    }

    #[test]
    fn derives_reference_keys() {
        let json =
            derive_master_keys_json("test test test test test test test test test test test junk")
                .expect("keys should derive");
        let keys: JsMasterKeys = parse_json(&json).expect("json should parse");
        assert_eq!(
            keys.master_nullifier,
            "20068762160393292801596226195912281868434195939362930533775271887246872084568"
        );
    }
}
