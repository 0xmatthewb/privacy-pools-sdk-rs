use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use base64::Engine;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect, Uint8Array};
use privacy_pools_sdk_artifacts::{
    ArtifactBytes, ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
};
use privacy_pools_sdk_circuits as circuits;
use privacy_pools_sdk_core::{
    CircuitMerkleWitness, Commitment, CommitmentCircuitInput, CommitmentWitnessRequest, MasterKeys,
    MerkleProof, ProofBundle, Withdrawal, WithdrawalCircuitInput, WithdrawalWitnessRequest,
};
use privacy_pools_sdk_prover::{self as prover, ProverBackend, ProvingResult};
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
        secret: field_label(secrets.1),
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
        secret: field_label(secrets.1),
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

pub fn verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts =
        parse_json::<Vec<JsArtifactBytes>>(artifacts_json).and_then(from_js_artifact_bytes)?;
    let bundle = manifest.verify_bundle_bytes(circuit, artifacts)?;
    to_json_string(&to_js_verified_artifact_bundle(bundle))
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
    to_json_string(&to_js_verified_artifact_bundle(bundle)).map_err(js_error)
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
        master_nullifier: parse_field(&keys.master_nullifier)?,
        master_secret: parse_field(&keys.master_secret)?,
    })
}

fn to_js_master_keys(keys: &MasterKeys) -> JsMasterKeys {
    JsMasterKeys {
        master_nullifier: field_label(keys.master_nullifier),
        master_secret: field_label(keys.master_secret),
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
        secret: field_label(commitment.preimage.precommitment.secret),
    }
}

fn from_js_withdrawal(withdrawal: &JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processooor: parse_address(&withdrawal.processooor)?,
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
                secret: parse_field(&commitment.secret)?,
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
        new_nullifier: parse_field(&request.new_nullifier)?,
        new_secret: parse_field(&request.new_secret)?,
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

fn prover_backend_label(kind: ProverBackend) -> String {
    match kind {
        ProverBackend::Arkworks => "arkworks".to_owned(),
        ProverBackend::Rapidsnark => "rapidsnark".to_owned(),
    }
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
    bundle: privacy_pools_sdk_artifacts::VerifiedArtifactBundle,
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
