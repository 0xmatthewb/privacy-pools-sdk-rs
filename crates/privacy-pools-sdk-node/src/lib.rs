use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use napi::{Error, Result as NapiResult, bindgen_prelude::Buffer};
use napi_derive::napi;
use privacy_pools_sdk::{
    CommitmentCircuitSession, FinalizedPreflightedTransaction, PreflightedTransaction,
    PrivacyPoolsSdk, SubmittedPreflightedTransaction, VerifiedCommitmentProof,
    VerifiedRagequitProof, VerifiedWithdrawalProof, WithdrawalCircuitSession,
    artifacts::{
        ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
        SignedManifestArtifactBytes,
    },
    core::{
        CircuitMerkleWitness, CodeHashCheck, Commitment, CommitmentPreimage,
        CommitmentWitnessRequest, ExecutionPolicy, ExecutionPolicyMode, ExecutionPreflightReport,
        FinalizedTransactionRequest, FormattedGroth16Proof, MasterKeys, MerkleProof, Precommitment,
        ProofBundle, RagequitExecutionConfig, RelayExecutionConfig, RootCheck, RootRead,
        RootReadKind, SnarkJsProof, TransactionKind, TransactionPlan, TransactionReceiptSummary,
        Withdrawal, WithdrawalExecutionConfig, WithdrawalWitnessRequest,
        wire::{
            WireCommitment, WireCommitmentWitnessRequest, WireWithdrawal,
            WireWithdrawalWitnessRequest,
        },
    },
    prover::{BackendProfile, ProverBackend, ProvingResult},
    recovery::{
        CompatibilityMode, DepositEvent, PoolEvent, PoolRecoveryInput, RagequitEvent,
        RecoveredAccountState, RecoveredCommitment, RecoveredPoolAccount, RecoveredScope,
        RecoveryKeyset, RecoveryPolicy, SpendableScope, WithdrawalEvent,
    },
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
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_CONTROL_JSON_INPUT_BYTES: usize = 1024 * 1024;
const MAX_RECOVERY_JSON_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_JSON_INPUT_BYTES: usize = 96 * 1024 * 1024;
const MAX_SECRET_HANDLES: usize = 512;
const MAX_VERIFIED_PROOF_HANDLES: usize = 256;
const MAX_EXECUTION_HANDLES: usize = 256;
const MAX_CIRCUIT_SESSIONS_PER_TYPE: usize = 64;

static SDK: LazyLock<PrivacyPoolsSdk> = LazyLock::new(PrivacyPoolsSdk::default);
static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static WITHDRAWAL_SESSION_REGISTRY: LazyLock<RwLock<HashMap<String, WithdrawalCircuitSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static COMMITMENT_SESSION_REGISTRY: LazyLock<RwLock<HashMap<String, CommitmentCircuitSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static SECRET_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, SecretHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static VERIFIED_PROOF_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, VerifiedProofHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static EXECUTION_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, ExecutionHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn evict_lowest_key_if_needed<T>(registry: &mut HashMap<String, T>, capacity: usize) {
    while registry.len() >= capacity {
        let Some(handle) = registry.keys().min().cloned() else {
            break;
        };
        registry.remove(&handle);
    }
}

#[derive(Debug, Clone)]
enum SecretHandleEntry {
    MasterKeys(MasterKeys),
    Secrets {
        nullifier: privacy_pools_sdk::core::Nullifier,
        secret: privacy_pools_sdk::core::Secret,
    },
    CommitmentRequest(privacy_pools_sdk::core::CommitmentWitnessRequest),
    WithdrawalRequest(Box<privacy_pools_sdk::core::WithdrawalWitnessRequest>),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum VerifiedProofHandleEntry {
    Commitment(VerifiedCommitmentProof),
    Ragequit(VerifiedRagequitProof),
    Withdrawal(VerifiedWithdrawalProof),
}

#[derive(Debug, Clone)]
enum ExecutionHandleEntry {
    Preflighted(PreflightedTransaction),
    Finalized(FinalizedPreflightedTransaction),
    Submitted(SubmittedPreflightedTransaction),
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
#[allow(dead_code)]
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
#[allow(dead_code)]
struct JsCommitmentWitnessRequest {
    commitment: JsCommitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsArtifactBytes {
    kind: String,
    bytes_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSignedManifestArtifactBytes {
    filename: String,
    bytes_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct JsVerifiedSignedManifest {
    payload: privacy_pools_sdk::artifacts::SignedArtifactManifestPayload,
    artifact_count: usize,
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
    transaction_index: u64,
    log_index: u64,
    transaction_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsWithdrawalEvent {
    withdrawn_value: String,
    spent_nullifier_hash: String,
    new_commitment_hash: String,
    block_number: u64,
    transaction_index: u64,
    log_index: u64,
    transaction_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRagequitEvent {
    commitment_hash: String,
    label: String,
    value: String,
    block_number: u64,
    transaction_index: u64,
    log_index: u64,
    transaction_hash: String,
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
struct JsExecutionPolicy {
    expected_chain_id: u64,
    caller: String,
    expected_pool_code_hash: Option<String>,
    expected_entrypoint_code_hash: Option<String>,
    read_consistency: Option<String>,
    max_fee_quote_wei: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCodeHashCheck {
    address: String,
    expected_code_hash: Option<String>,
    actual_code_hash: String,
    matches_expected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRootCheck {
    kind: String,
    contract_address: String,
    pool_address: String,
    expected_root: String,
    actual_root: String,
    matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsExecutionPreflightReport {
    kind: String,
    caller: String,
    target: String,
    expected_chain_id: u64,
    actual_chain_id: u64,
    chain_id_matches: bool,
    simulated: bool,
    estimated_gas: u64,
    read_consistency: Option<String>,
    max_fee_quote_wei: Option<String>,
    mode: Option<String>,
    code_hash_checks: Vec<JsCodeHashCheck>,
    root_checks: Vec<JsRootCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsPreflightedTransaction {
    transaction: JsTransactionPlan,
    preflight: JsExecutionPreflightReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFinalizedTransactionRequest {
    kind: String,
    chain_id: u64,
    from: String,
    to: String,
    nonce: u64,
    gas_limit: u64,
    value: String,
    data: String,
    gas_price: Option<String>,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFinalizedPreflightedTransaction {
    preflighted: JsPreflightedTransaction,
    request: JsFinalizedTransactionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsTransactionReceiptSummary {
    transaction_hash: String,
    block_hash: Option<String>,
    block_number: Option<u64>,
    transaction_index: Option<u64>,
    success: bool,
    gas_used: u64,
    effective_gas_price: String,
    from: String,
    to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSubmittedPreflightedTransaction {
    preflighted: JsPreflightedTransaction,
    receipt: JsTransactionReceiptSummary,
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
#[cfg(feature = "dangerous-key-export")]
pub fn derive_master_keys(mnemonic: String) -> NapiResult<String> {
    let keys = SDK.generate_master_keys(&mnemonic).map_err(to_napi_error)?;
    to_json_string(&privacy_pools_sdk::core::wire::WireMasterKeys::from(&keys))
        .map_err(to_napi_error)
}

fn derive_master_keys_from_utf8_bytes(mut mnemonic: Vec<u8>) -> NapiResult<String> {
    let result = (|| {
        let phrase = std::str::from_utf8(&mnemonic)
            .map_err(|error| to_napi_error(anyhow!(error.to_string())))?;
        let keys = SDK.generate_master_keys(phrase).map_err(to_napi_error)?;
        register_secret_handle(SecretHandleEntry::MasterKeys(keys)).map_err(to_napi_error)
    })();
    mnemonic.zeroize();
    result
}

#[napi]
pub fn derive_master_keys_handle(mnemonic: String) -> NapiResult<String> {
    let keys = SDK.generate_master_keys(&mnemonic).map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::MasterKeys(keys)).map_err(to_napi_error)
}

#[napi]
pub fn derive_master_keys_handle_bytes(mnemonic: Buffer) -> NapiResult<String> {
    derive_master_keys_from_utf8_bytes(mnemonic.to_vec())
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_master_keys(handle: String) -> NapiResult<String> {
    match get_secret_handle(&handle).map_err(to_napi_error)? {
        SecretHandleEntry::MasterKeys(keys) => {
            to_json_string(&to_js_master_keys(&keys)).map_err(to_napi_error)
        }
        _ => Err(to_napi_error(anyhow::anyhow!(
            "secret handle does not contain master keys"
        ))),
    }
}

#[napi]
#[cfg(feature = "dangerous-key-export")]
pub fn derive_deposit_secrets(
    master_keys_json: String,
    scope: String,
    index: String,
) -> NapiResult<String> {
    let master_keys =
        parse_json::<privacy_pools_sdk::core::wire::WireMasterKeys>(&master_keys_json)
            .and_then(|keys| MasterKeys::try_from(keys).map_err(Into::into))
            .map_err(to_napi_error)?;
    let secrets = SDK
        .generate_deposit_secrets(
            &master_keys,
            parse_field(&scope).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&JsSecrets {
        nullifier: secrets.0.to_decimal_string(),
        secret: secrets.1.to_decimal_string(),
    })
    .map_err(to_napi_error)
}

#[napi]
pub fn generate_deposit_secrets_handle(
    master_keys_handle: String,
    scope: String,
    index: String,
) -> NapiResult<String> {
    let master_keys = match get_secret_handle(&master_keys_handle).map_err(to_napi_error)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain master keys"
            )));
        }
    };
    let secrets = SDK
        .generate_deposit_secrets(
            &master_keys,
            parse_field(&scope).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::Secrets {
        nullifier: secrets.0,
        secret: secrets.1,
    })
    .map_err(to_napi_error)
}

#[napi]
#[cfg(feature = "dangerous-key-export")]
pub fn derive_withdrawal_secrets(
    master_keys_json: String,
    label: String,
    index: String,
) -> NapiResult<String> {
    let master_keys =
        parse_json::<privacy_pools_sdk::core::wire::WireMasterKeys>(&master_keys_json)
            .and_then(|keys| MasterKeys::try_from(keys).map_err(Into::into))
            .map_err(to_napi_error)?;
    let secrets = SDK
        .generate_withdrawal_secrets(
            &master_keys,
            parse_field(&label).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&JsSecrets {
        nullifier: secrets.0.to_decimal_string(),
        secret: secrets.1.to_decimal_string(),
    })
    .map_err(to_napi_error)
}

#[napi]
pub fn generate_withdrawal_secrets_handle(
    master_keys_handle: String,
    label: String,
    index: String,
) -> NapiResult<String> {
    let master_keys = match get_secret_handle(&master_keys_handle).map_err(to_napi_error)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain master keys"
            )));
        }
    };
    let secrets = SDK
        .generate_withdrawal_secrets(
            &master_keys,
            parse_field(&label).map_err(to_napi_error)?,
            parse_field(&index).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::Secrets {
        nullifier: secrets.0,
        secret: secrets.1,
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
        .build_commitment(
            parse_field(&value).map_err(to_napi_error)?,
            parse_field(&label).map_err(to_napi_error)?,
            parse_field(&nullifier).map_err(to_napi_error)?,
            parse_field(&secret).map_err(to_napi_error)?,
        )
        .map_err(to_napi_error)?;
    to_json_string(&privacy_pools_sdk::core::wire::WireCommitment::from(
        &commitment,
    ))
    .map_err(to_napi_error)
}

#[napi]
pub fn get_commitment_from_handles(
    value: String,
    label: String,
    secrets_handle: String,
) -> NapiResult<String> {
    let (nullifier, secret) = match get_secret_handle(&secrets_handle).map_err(to_napi_error)? {
        SecretHandleEntry::Secrets { nullifier, secret } => (nullifier, secret),
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain deposit or withdrawal secrets"
            )));
        }
    };
    let commitment = SDK
        .build_commitment(
            parse_field(&value).map_err(to_napi_error)?,
            parse_field(&label).map_err(to_napi_error)?,
            nullifier,
            secret,
        )
        .map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::CommitmentRequest(
        privacy_pools_sdk::core::CommitmentWitnessRequest { commitment },
    ))
    .map_err(to_napi_error)
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_commitment_preimage(handle: String) -> NapiResult<String> {
    match get_secret_handle(&handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => {
            to_json_string(&to_js_commitment(request.commitment)).map_err(to_napi_error)
        }
        _ => Err(to_napi_error(anyhow::anyhow!(
            "secret handle does not contain a commitment witness request"
        ))),
    }
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_secret(handle: String) -> NapiResult<String> {
    match get_secret_handle(&handle).map_err(to_napi_error)? {
        SecretHandleEntry::Secrets { nullifier, secret } => to_json_string(&JsSecrets {
            nullifier: nullifier.to_decimal_string(),
            secret: secret.to_decimal_string(),
        })
        .map_err(to_napi_error),
        _ => Err(to_napi_error(anyhow::anyhow!(
            "secret handle does not contain secret pair material"
        ))),
    }
}

#[napi]
pub fn build_withdrawal_witness_request_handle(request_json: String) -> NapiResult<String> {
    let request =
        parse_wire_withdrawal_witness_request_json(&request_json).map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::WithdrawalRequest(Box::new(request)))
        .map_err(to_napi_error)
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn build_withdrawal_witness_request_handle_from_handles(
    commitment_handle: String,
    withdrawal_json: String,
    scope: String,
    withdrawal_amount: String,
    state_witness_json: String,
    asp_witness_json: String,
    new_secrets_handle: String,
) -> NapiResult<String> {
    let commitment = match get_secret_handle(&commitment_handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => request.commitment,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a commitment witness request"
            )));
        }
    };
    let (new_nullifier, new_secret) =
        match get_secret_handle(&new_secrets_handle).map_err(to_napi_error)? {
            SecretHandleEntry::Secrets { nullifier, secret } => (nullifier, secret),
            _ => {
                return Err(to_napi_error(anyhow::anyhow!(
                    "secret handle does not contain withdrawal secret material"
                )));
            }
        };
    let withdrawal = parse_json::<WireWithdrawal>(&withdrawal_json).map_err(to_napi_error)?;
    let state_witness = parse_json(&state_witness_json).map_err(to_napi_error)?;
    let asp_witness = parse_json(&asp_witness_json).map_err(to_napi_error)?;
    let request = WireWithdrawalWitnessRequest {
        commitment: WireCommitment::from(&commitment),
        withdrawal,
        scope,
        withdrawal_amount,
        state_witness,
        asp_witness,
        new_nullifier: new_nullifier.to_decimal_string(),
        new_secret: new_secret.to_decimal_string(),
    };
    let request = WithdrawalWitnessRequest::try_from(request).map_err(to_napi_error)?;
    register_secret_handle(SecretHandleEntry::WithdrawalRequest(Box::new(request)))
        .map_err(to_napi_error)
}

#[napi]
pub fn calculate_withdrawal_context(withdrawal_json: String, scope: String) -> NapiResult<String> {
    let withdrawal = parse_json::<JsWithdrawal>(&withdrawal_json)
        .and_then(from_js_withdrawal)
        .map_err(to_napi_error)?;
    SDK.calculate_withdrawal_context(&withdrawal, parse_field(&scope).map_err(to_napi_error)?)
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
    let request =
        parse_json::<privacy_pools_sdk::core::wire::WireWithdrawalWitnessRequest>(&request_json)
            .and_then(|request| WithdrawalWitnessRequest::try_from(request).map_err(Into::into))
            .map_err(to_napi_error)?;
    let input = SDK
        .build_withdrawal_circuit_input(&request)
        .map_err(to_napi_error)?;
    let input = privacy_pools_sdk::core::wire::WireWithdrawalCircuitInput::from(&input);
    to_json_string(&input).map_err(to_napi_error)
}

#[napi]
pub fn build_commitment_circuit_input(request_json: String) -> NapiResult<String> {
    let request =
        parse_json::<privacy_pools_sdk::core::wire::WireCommitmentWitnessRequest>(&request_json)
            .and_then(|request| CommitmentWitnessRequest::try_from(request).map_err(Into::into))
            .map_err(to_napi_error)?;
    let input = SDK
        .build_commitment_circuit_input(&request)
        .map_err(to_napi_error)?;
    let input = privacy_pools_sdk::core::wire::WireCommitmentCircuitInput::from(&input);
    to_json_string(&input).map_err(to_napi_error)
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
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        &artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_artifact_bytes)
    .map_err(to_napi_error)?;
    let bundle = SDK
        .verify_artifact_bundle_bytes(&manifest, &circuit, artifacts)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_verified_artifact_bundle(bundle)).map_err(to_napi_error)
}

#[napi(js_name = "verifySignedManifest")]
pub fn verify_signed_manifest(
    payload_json: String,
    signature_hex: String,
    public_key_hex: String,
) -> NapiResult<String> {
    let payload = privacy_pools_sdk::artifacts::verify_signed_manifest_bytes(
        payload_json.as_bytes(),
        &signature_hex,
        &public_key_hex,
    )
    .map_err(to_napi_error)?;
    to_json_string(&JsVerifiedSignedManifest {
        payload,
        artifact_count: 0,
    })
    .map_err(to_napi_error)
}

#[napi(js_name = "verifySignedManifestArtifacts")]
pub fn verify_signed_manifest_artifacts(
    payload_json: String,
    signature_hex: String,
    public_key_hex: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let artifacts = parse_json_with_limit::<Vec<JsSignedManifestArtifactBytes>>(
        &artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_signed_manifest_artifact_bytes)
    .map_err(to_napi_error)?;
    let verified = privacy_pools_sdk::artifacts::verify_signed_manifest_artifact_bytes(
        payload_json.as_bytes(),
        &signature_hex,
        &public_key_hex,
        artifacts,
    )
    .map_err(to_napi_error)?;
    to_json_string(&JsVerifiedSignedManifest {
        payload: verified.payload().clone(),
        artifact_count: verified.artifact_count(),
    })
    .map_err(to_napi_error)
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
        .map_err(to_napi_error)
        .map(|mut registry| {
            evict_lowest_key_if_needed(&mut registry, MAX_CIRCUIT_SESSIONS_PER_TYPE);
            registry.insert(handle, session);
        })?;
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn prepare_withdrawal_circuit_session_from_bytes(
    manifest_json: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        &artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
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
        .map_err(to_napi_error)
        .map(|mut registry| {
            evict_lowest_key_if_needed(&mut registry, MAX_CIRCUIT_SESSIONS_PER_TYPE);
            registry.insert(handle, session);
        })?;
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
        .map_err(to_napi_error)
        .map(|mut registry| {
            evict_lowest_key_if_needed(&mut registry, MAX_CIRCUIT_SESSIONS_PER_TYPE);
            registry.insert(handle, session);
        })?;
    to_json_string(&result).map_err(to_napi_error)
}

#[napi]
pub fn prepare_commitment_circuit_session_from_bytes(
    manifest_json: String,
    artifacts_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        &artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
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
        .map_err(to_napi_error)
        .map(|mut registry| {
            evict_lowest_key_if_needed(&mut registry, MAX_CIRCUIT_SESSIONS_PER_TYPE);
            registry.insert(handle, session);
        })?;
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
pub fn remove_secret_handle(handle: String) -> NapiResult<bool> {
    remove_secret_handle_entry(&handle).map_err(to_napi_error)
}

#[napi]
pub fn clear_secret_handles() -> NapiResult<bool> {
    clear_secret_handle_registry().map_err(to_napi_error)?;
    Ok(true)
}

#[napi]
pub fn prove_withdrawal(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_json: String,
) -> NapiResult<String> {
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let request =
        parse_wire_withdrawal_witness_request_json(&request_json).map_err(to_napi_error)?;
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
pub fn prove_withdrawal_with_handles(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a withdrawal witness request"
            )));
        }
    };
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
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
    let request =
        parse_wire_withdrawal_witness_request_json(&request_json).map_err(to_napi_error)?;
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
    let request =
        parse_wire_commitment_witness_request_json(&request_json).map_err(to_napi_error)?;
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
pub fn prove_commitment_with_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a commitment witness request"
            )));
        }
    };
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
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
    let request =
        parse_wire_commitment_witness_request_json(&request_json).map_err(to_napi_error)?;
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
pub fn prove_and_verify_commitment_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a commitment witness request"
            )));
        }
    };
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let verified = SDK
        .prove_and_verify_commitment(
            parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
            &manifest,
            &artifacts_root,
            &request,
        )
        .map_err(to_napi_error)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Commitment(verified))
        .map_err(to_napi_error)
}

#[napi]
pub fn prove_and_verify_withdrawal_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a withdrawal witness request"
            )));
        }
    };
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let verified = SDK
        .prove_and_verify_withdrawal(
            parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
            &manifest,
            &artifacts_root,
            &request,
        )
        .map_err(to_napi_error)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Withdrawal(verified))
        .map_err(to_napi_error)
}

#[napi]
pub fn verify_commitment_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof_json: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a commitment witness request"
            )));
        }
    };
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let verified = SDK
        .verify_commitment_proof_for_request(
            parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
            &manifest,
            &artifacts_root,
            &request,
            &proof,
        )
        .map_err(to_napi_error)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Commitment(verified))
        .map_err(to_napi_error)
}

#[napi]
pub fn verify_ragequit_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof_json: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a commitment witness request"
            )));
        }
    };
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let verified = SDK
        .verify_ragequit_proof_for_request(
            parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
            &manifest,
            &artifacts_root,
            &request,
            &proof,
        )
        .map_err(to_napi_error)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Ragequit(verified))
        .map_err(to_napi_error)
}

#[napi]
pub fn verify_withdrawal_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof_json: String,
) -> NapiResult<String> {
    let request = match get_secret_handle(&request_handle).map_err(to_napi_error)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "secret handle does not contain a withdrawal witness request"
            )));
        }
    };
    let proof = parse_json::<JsProofBundle>(&proof_json)
        .and_then(from_js_proof_bundle)
        .map_err(to_napi_error)?;
    let manifest = parse_manifest(&manifest_json).map_err(to_napi_error)?;
    let verified = SDK
        .verify_withdrawal_proof_for_request(
            parse_backend_profile(&backend_profile).map_err(to_napi_error)?,
            &manifest,
            &artifacts_root,
            &request,
            &proof,
        )
        .map_err(to_napi_error)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Withdrawal(verified))
        .map_err(to_napi_error)
}

#[napi]
pub fn remove_verified_proof_handle(handle: String) -> NapiResult<bool> {
    remove_verified_proof_handle_entry(&handle).map_err(to_napi_error)
}

#[napi]
pub fn clear_verified_proof_handles() -> NapiResult<bool> {
    clear_verified_proof_handle_registry().map_err(to_napi_error)?;
    Ok(true)
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
pub fn plan_verified_withdrawal_transaction_with_handle(
    chain_id: String,
    pool_address: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a withdrawal proof"
            )));
        }
    };
    let plan = SDK
        .plan_verified_withdrawal_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&pool_address).map_err(to_napi_error)?,
            &proof,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub fn plan_verified_relay_transaction_with_handle(
    chain_id: String,
    entrypoint_address: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a withdrawal proof"
            )));
        }
    };
    let plan = SDK
        .plan_verified_relay_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&entrypoint_address).map_err(to_napi_error)?,
            &proof,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub fn plan_verified_ragequit_transaction_with_handle(
    chain_id: String,
    pool_address: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a ragequit proof"
            )));
        }
    };
    let plan = SDK
        .plan_verified_ragequit_transaction(
            parse_u64(&chain_id).map_err(to_napi_error)?,
            parse_address(&pool_address).map_err(to_napi_error)?,
            &proof,
        )
        .map_err(to_napi_error)?;
    to_json_string(&to_js_transaction_plan(plan)).map_err(to_napi_error)
}

#[napi]
pub async fn preflight_verified_withdrawal_transaction_with_handle(
    chain_id: String,
    pool_address: String,
    rpc_url: String,
    policy_json: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a withdrawal proof"
            )));
        }
    };
    let policy = parse_json::<JsExecutionPolicy>(&policy_json)
        .and_then(from_js_execution_policy)
        .map_err(to_napi_error)?;
    let client =
        privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url).map_err(to_napi_error)?;
    let config = WithdrawalExecutionConfig {
        chain_id: parse_u64(&chain_id).map_err(to_napi_error)?,
        pool_address: parse_address(&pool_address).map_err(to_napi_error)?,
        policy,
    };
    let preflighted = SDK
        .preflight_verified_withdrawal_transaction_with_client(&config, &proof, &client)
        .await
        .map_err(to_napi_error)?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted)).map_err(to_napi_error)
}

#[napi]
pub async fn preflight_verified_relay_transaction_with_handle(
    chain_id: String,
    entrypoint_address: String,
    pool_address: String,
    rpc_url: String,
    policy_json: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a withdrawal proof"
            )));
        }
    };
    let policy = parse_json::<JsExecutionPolicy>(&policy_json)
        .and_then(from_js_execution_policy)
        .map_err(to_napi_error)?;
    let client =
        privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url).map_err(to_napi_error)?;
    let config = RelayExecutionConfig {
        chain_id: parse_u64(&chain_id).map_err(to_napi_error)?,
        entrypoint_address: parse_address(&entrypoint_address).map_err(to_napi_error)?,
        pool_address: parse_address(&pool_address).map_err(to_napi_error)?,
        policy,
    };
    let preflighted = SDK
        .preflight_verified_relay_transaction_with_client(&config, &proof, &client)
        .await
        .map_err(to_napi_error)?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted)).map_err(to_napi_error)
}

#[napi]
pub async fn preflight_verified_ragequit_transaction_with_handle(
    chain_id: String,
    pool_address: String,
    rpc_url: String,
    policy_json: String,
    proof_handle: String,
) -> NapiResult<String> {
    let proof = match get_verified_proof_handle(&proof_handle).map_err(to_napi_error)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "verified proof handle does not contain a ragequit proof"
            )));
        }
    };
    let policy = parse_json::<JsExecutionPolicy>(&policy_json)
        .and_then(from_js_execution_policy)
        .map_err(to_napi_error)?;
    let client =
        privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url).map_err(to_napi_error)?;
    let config = RagequitExecutionConfig {
        chain_id: parse_u64(&chain_id).map_err(to_napi_error)?,
        pool_address: parse_address(&pool_address).map_err(to_napi_error)?,
        policy,
    };
    let preflighted = SDK
        .preflight_verified_ragequit_transaction_with_client(&config, &proof, &client)
        .await
        .map_err(to_napi_error)?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted)).map_err(to_napi_error)
}

#[napi]
pub async fn finalize_preflighted_transaction_handle(
    rpc_url: String,
    preflighted_handle: String,
) -> NapiResult<String> {
    let preflighted = match get_execution_handle(&preflighted_handle).map_err(to_napi_error)? {
        ExecutionHandleEntry::Preflighted(preflighted) => preflighted,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "execution handle does not contain a preflighted transaction"
            )));
        }
    };
    let client =
        privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url).map_err(to_napi_error)?;
    let finalized = SDK
        .finalize_preflighted_transaction_with_client(preflighted, &client)
        .await
        .map_err(to_napi_error)?;
    register_execution_handle(ExecutionHandleEntry::Finalized(finalized)).map_err(to_napi_error)
}

#[napi]
pub fn submit_preflighted_transaction_handle(
    _rpc_url: String,
    _preflighted_handle: String,
) -> NapiResult<String> {
    Err(to_napi_error(anyhow::anyhow!(
        "submitPreflightedTransactionHandle requires an in-process signer; default Node builds support finalizePreflightedTransactionHandle plus submitFinalizedPreflightedTransactionHandle with an externally signed transaction"
    )))
}

#[napi]
pub async fn submit_finalized_preflighted_transaction_handle(
    rpc_url: String,
    finalized_handle: String,
    signed_transaction: String,
) -> NapiResult<String> {
    let finalized = match get_execution_handle(&finalized_handle).map_err(to_napi_error)? {
        ExecutionHandleEntry::Finalized(finalized) => finalized,
        _ => {
            return Err(to_napi_error(anyhow::anyhow!(
                "execution handle does not contain a finalized preflighted transaction"
            )));
        }
    };
    let encoded_tx =
        hex::decode(signed_transaction.trim_start_matches("0x")).map_err(to_napi_error)?;
    privacy_pools_sdk::chain::validate_signed_transaction_request(&encoded_tx, finalized.request())
        .map_err(to_napi_error)?;
    let client =
        privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url).map_err(to_napi_error)?;
    let submitted = SDK
        .submit_finalized_preflighted_transaction_with_client(finalized, &encoded_tx, &client)
        .await
        .map_err(to_napi_error)?;
    register_execution_handle(ExecutionHandleEntry::Submitted(submitted)).map_err(to_napi_error)
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_preflighted_transaction(handle: String) -> NapiResult<String> {
    match get_execution_handle(&handle).map_err(to_napi_error)? {
        ExecutionHandleEntry::Preflighted(preflighted) => {
            to_json_string(&to_js_preflighted_transaction(&preflighted)).map_err(to_napi_error)
        }
        _ => Err(to_napi_error(anyhow::anyhow!(
            "execution handle does not contain a preflighted transaction"
        ))),
    }
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_finalized_preflighted_transaction(handle: String) -> NapiResult<String> {
    match get_execution_handle(&handle).map_err(to_napi_error)? {
        ExecutionHandleEntry::Finalized(finalized) => {
            to_json_string(&to_js_finalized_preflighted_transaction(&finalized))
                .map_err(to_napi_error)
        }
        _ => Err(to_napi_error(anyhow::anyhow!(
            "execution handle does not contain a finalized preflighted transaction"
        ))),
    }
}

#[napi]
#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_submitted_preflighted_transaction(handle: String) -> NapiResult<String> {
    match get_execution_handle(&handle).map_err(to_napi_error)? {
        ExecutionHandleEntry::Submitted(submitted) => {
            to_json_string(&to_js_submitted_preflighted_transaction(&submitted))
                .map_err(to_napi_error)
        }
        _ => Err(to_napi_error(anyhow::anyhow!(
            "execution handle does not contain a submitted preflighted transaction"
        ))),
    }
}

#[napi]
pub fn remove_execution_handle(handle: String) -> NapiResult<bool> {
    remove_execution_handle_entry(&handle).map_err(to_napi_error)
}

#[napi]
pub fn clear_execution_handles() -> NapiResult<bool> {
    clear_execution_handle_registry().map_err(to_napi_error)?;
    Ok(true)
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
    let events =
        parse_json_with_limit::<Vec<JsPoolEvent>>(&events_json, MAX_RECOVERY_JSON_INPUT_BYTES)
            .and_then(from_js_pool_events)
            .map_err(to_napi_error)?;
    let policy = parse_json::<JsRecoveryPolicy>(&policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))
        .map_err(to_napi_error)?;
    let checkpoint = SDK
        .checkpoint_recovery(&events, policy)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_recovery_checkpoint(&checkpoint)).map_err(to_napi_error)
}

#[napi]
pub fn derive_recovery_keyset(mnemonic: String, policy_json: String) -> NapiResult<String> {
    let policy = parse_json::<JsRecoveryPolicy>(&policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))
        .map_err(to_napi_error)?;
    let keyset = SDK
        .derive_recovery_keyset(&mnemonic, policy)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_recovery_keyset(&keyset)).map_err(to_napi_error)
}

#[napi]
pub fn recover_account_state(
    mnemonic: String,
    pools_json: String,
    policy_json: String,
) -> NapiResult<String> {
    let pools = parse_json_with_limit::<Vec<JsPoolRecoveryInput>>(
        &pools_json,
        MAX_RECOVERY_JSON_INPUT_BYTES,
    )
    .and_then(from_js_pool_recovery_inputs)
    .map_err(to_napi_error)?;
    let policy = parse_json::<JsRecoveryPolicy>(&policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))
        .map_err(to_napi_error)?;
    let state = SDK
        .recover_account_state(&mnemonic, &pools, policy)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_recovered_account_state(&state)).map_err(to_napi_error)
}

#[napi]
pub fn recover_account_state_with_keyset(
    keyset_json: String,
    pools_json: String,
    policy_json: String,
) -> NapiResult<String> {
    let keyset = parse_json::<JsRecoveryKeyset>(&keyset_json)
        .and_then(|keyset| from_js_recovery_keyset(&keyset))
        .map_err(to_napi_error)?;
    let pools = parse_json_with_limit::<Vec<JsPoolRecoveryInput>>(
        &pools_json,
        MAX_RECOVERY_JSON_INPUT_BYTES,
    )
    .and_then(from_js_pool_recovery_inputs)
    .map_err(to_napi_error)?;
    let policy = parse_json::<JsRecoveryPolicy>(&policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))
        .map_err(to_napi_error)?;
    let state = SDK
        .recover_account_state_with_keyset(&keyset, &pools, policy)
        .map_err(to_napi_error)?;
    to_json_string(&to_js_recovered_account_state(&state)).map_err(to_napi_error)
}

fn parse_json<T>(value: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    parse_json_with_limit(value, MAX_CONTROL_JSON_INPUT_BYTES)
}

fn parse_json_with_limit<T>(value: &str, max_bytes: usize) -> Result<T>
where
    T: DeserializeOwned,
{
    if value.len() > max_bytes {
        bail!(
            "JSON payload exceeds maximum size: {} > {} bytes",
            value.len(),
            max_bytes
        );
    }
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

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("invalid u64 `{value}`"))
}

fn parse_u128(value: &str) -> Result<u128> {
    value
        .parse::<u128>()
        .with_context(|| format!("invalid u128 `{value}`"))
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

fn hash_label(value: B256) -> String {
    value.to_string()
}

fn execution_policy_mode_label(mode: ExecutionPolicyMode) -> String {
    match mode {
        ExecutionPolicyMode::Strict => "strict".to_owned(),
        ExecutionPolicyMode::InsecureDev => "insecure_dev".to_owned(),
    }
}

fn parse_read_consistency(value: &str) -> Result<privacy_pools_sdk::core::ReadConsistency> {
    match value {
        "latest" => Ok(privacy_pools_sdk::core::ReadConsistency::Latest),
        "finalized" => Ok(privacy_pools_sdk::core::ReadConsistency::Finalized),
        other => bail!("invalid read consistency: {other}"),
    }
}

fn read_consistency_label(consistency: privacy_pools_sdk::core::ReadConsistency) -> String {
    match consistency {
        privacy_pools_sdk::core::ReadConsistency::Latest => "latest".to_owned(),
        privacy_pools_sdk::core::ReadConsistency::Finalized => "finalized".to_owned(),
    }
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

fn next_secret_handle() -> String {
    Uuid::new_v4().to_string()
}

fn register_secret_handle(entry: SecretHandleEntry) -> Result<String> {
    let handle = next_secret_handle();
    let mut registry = SECRET_HANDLE_REGISTRY.write().map_err(lock_error)?;
    evict_lowest_key_if_needed(&mut registry, MAX_SECRET_HANDLES);
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn get_secret_handle(handle: &str) -> Result<SecretHandleEntry> {
    SECRET_HANDLE_REGISTRY
        .read()
        .map_err(lock_error)?
        .get(handle)
        .cloned()
        .ok_or_else(|| anyhow!("secret handle not found: {handle}"))
}

fn remove_secret_handle_entry(handle: &str) -> Result<bool> {
    Ok(SECRET_HANDLE_REGISTRY
        .write()
        .map_err(lock_error)?
        .remove(handle)
        .is_some())
}

fn clear_secret_handle_registry() -> Result<()> {
    SECRET_HANDLE_REGISTRY.write().map_err(lock_error)?.clear();
    Ok(())
}

fn register_verified_proof_handle(entry: VerifiedProofHandleEntry) -> Result<String> {
    let handle = Uuid::new_v4().to_string();
    let mut registry = VERIFIED_PROOF_HANDLE_REGISTRY.write().map_err(lock_error)?;
    evict_lowest_key_if_needed(&mut registry, MAX_VERIFIED_PROOF_HANDLES);
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn get_verified_proof_handle(handle: &str) -> Result<VerifiedProofHandleEntry> {
    VERIFIED_PROOF_HANDLE_REGISTRY
        .read()
        .map_err(lock_error)?
        .get(handle)
        .cloned()
        .ok_or_else(|| anyhow!("verified proof handle not found: {handle}"))
}

fn remove_verified_proof_handle_entry(handle: &str) -> Result<bool> {
    Ok(VERIFIED_PROOF_HANDLE_REGISTRY
        .write()
        .map_err(lock_error)?
        .remove(handle)
        .is_some())
}

fn clear_verified_proof_handle_registry() -> Result<()> {
    VERIFIED_PROOF_HANDLE_REGISTRY
        .write()
        .map_err(lock_error)?
        .clear();
    Ok(())
}

fn register_execution_handle(entry: ExecutionHandleEntry) -> Result<String> {
    let handle = Uuid::new_v4().to_string();
    let mut registry = EXECUTION_HANDLE_REGISTRY.write().map_err(lock_error)?;
    evict_lowest_key_if_needed(&mut registry, MAX_EXECUTION_HANDLES);
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn get_execution_handle(handle: &str) -> Result<ExecutionHandleEntry> {
    EXECUTION_HANDLE_REGISTRY
        .read()
        .map_err(lock_error)?
        .get(handle)
        .cloned()
        .ok_or_else(|| anyhow!("execution handle not found: {handle}"))
}

fn remove_execution_handle_entry(handle: &str) -> Result<bool> {
    Ok(EXECUTION_HANDLE_REGISTRY
        .write()
        .map_err(lock_error)?
        .remove(handle)
        .is_some())
}

fn clear_execution_handle_registry() -> Result<()> {
    EXECUTION_HANDLE_REGISTRY
        .write()
        .map_err(lock_error)?
        .clear();
    Ok(())
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

fn to_js_commitment(commitment: Commitment) -> JsCommitment {
    JsCommitment {
        hash: field_label(commitment.hash),
        nullifier_hash: field_label(commitment.precommitment_hash),
        precommitment_hash: field_label(commitment.precommitment_hash),
        value: field_label(commitment.preimage.value),
        label: field_label(commitment.preimage.label),
        nullifier: commitment
            .preimage
            .precommitment
            .nullifier
            .to_decimal_string(),
        secret: commitment.preimage.precommitment.secret.to_decimal_string(),
    }
}

fn from_js_commitment(commitment: JsCommitment) -> Result<Commitment> {
    let precommitment_hash = parse_field(&commitment.precommitment_hash)?;
    let compatibility_hash = parse_field(&commitment.nullifier_hash)?;
    if compatibility_hash != precommitment_hash {
        bail!("commitment nullifierHash compatibility field must match precommitmentHash");
    }

    Ok(Commitment {
        hash: parse_field(&commitment.hash)?,
        precommitment_hash,
        preimage: CommitmentPreimage {
            value: parse_field(&commitment.value)?,
            label: parse_field(&commitment.label)?,
            precommitment: Precommitment {
                hash: precommitment_hash,
                nullifier: parse_field(&commitment.nullifier)?.into(),
                secret: parse_field(&commitment.secret)?.into(),
            },
        },
    })
}

fn from_js_withdrawal(withdrawal: JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processor: parse_address(&withdrawal.processooor)?,
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

#[allow(dead_code)]
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
        new_nullifier: parse_field(&request.new_nullifier)?.into(),
        new_secret: parse_field(&request.new_secret)?.into(),
    })
}

#[allow(dead_code)]
fn from_js_commitment_witness_request(
    request: JsCommitmentWitnessRequest,
) -> Result<CommitmentWitnessRequest> {
    Ok(CommitmentWitnessRequest {
        commitment: from_js_commitment(request.commitment)?,
    })
}

fn parse_wire_withdrawal_witness_request_json(
    request_json: &str,
) -> Result<WithdrawalWitnessRequest> {
    parse_json::<WireWithdrawalWitnessRequest>(request_json)
        .and_then(|request| WithdrawalWitnessRequest::try_from(request).map_err(Into::into))
}

fn parse_wire_commitment_witness_request_json(
    request_json: &str,
) -> Result<CommitmentWitnessRequest> {
    parse_json::<WireCommitmentWitnessRequest>(request_json)
        .and_then(|request| CommitmentWitnessRequest::try_from(request).map_err(Into::into))
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

fn to_js_code_hash_check(check: CodeHashCheck) -> JsCodeHashCheck {
    JsCodeHashCheck {
        address: check.address.to_string(),
        expected_code_hash: check.expected_code_hash.map(hash_label),
        actual_code_hash: hash_label(check.actual_code_hash),
        matches_expected: check.matches_expected,
    }
}

fn to_js_root_check(check: RootCheck) -> JsRootCheck {
    JsRootCheck {
        kind: root_read_kind_label(check.kind),
        contract_address: check.contract_address.to_string(),
        pool_address: check.pool_address.to_string(),
        expected_root: field_label(check.expected_root),
        actual_root: field_label(check.actual_root),
        matches: check.matches,
    }
}

fn to_js_execution_preflight(report: ExecutionPreflightReport) -> JsExecutionPreflightReport {
    JsExecutionPreflightReport {
        kind: transaction_kind_label(report.kind),
        caller: report.caller.to_string(),
        target: report.target.to_string(),
        expected_chain_id: report.expected_chain_id,
        actual_chain_id: report.actual_chain_id,
        chain_id_matches: report.chain_id_matches,
        simulated: report.simulated,
        estimated_gas: report.estimated_gas,
        read_consistency: Some(read_consistency_label(report.read_consistency)),
        max_fee_quote_wei: report.max_fee_quote_wei.map(|value| value.to_string()),
        mode: Some(execution_policy_mode_label(report.mode)),
        code_hash_checks: report
            .code_hash_checks
            .into_iter()
            .map(to_js_code_hash_check)
            .collect(),
        root_checks: report
            .root_checks
            .into_iter()
            .map(to_js_root_check)
            .collect(),
    }
}

fn to_js_preflighted_transaction(preflighted: &PreflightedTransaction) -> JsPreflightedTransaction {
    JsPreflightedTransaction {
        transaction: to_js_transaction_plan(preflighted.plan().clone()),
        preflight: to_js_execution_preflight(preflighted.preflight().clone()),
    }
}

fn to_js_finalized_request(request: &FinalizedTransactionRequest) -> JsFinalizedTransactionRequest {
    JsFinalizedTransactionRequest {
        kind: transaction_kind_label(request.kind),
        chain_id: request.chain_id,
        from: request.from.to_string(),
        to: request.to.to_string(),
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        value: field_label(request.value),
        data: format!("0x{}", hex::encode(&request.data)),
        gas_price: request.gas_price.map(|value| value.to_string()),
        max_fee_per_gas: request.max_fee_per_gas.map(|value| value.to_string()),
        max_priority_fee_per_gas: request
            .max_priority_fee_per_gas
            .map(|value| value.to_string()),
    }
}

fn to_js_finalized_preflighted_transaction(
    finalized: &FinalizedPreflightedTransaction,
) -> JsFinalizedPreflightedTransaction {
    JsFinalizedPreflightedTransaction {
        preflighted: to_js_preflighted_transaction(finalized.transaction()),
        request: to_js_finalized_request(finalized.request()),
    }
}

fn to_js_receipt_summary(receipt: &TransactionReceiptSummary) -> JsTransactionReceiptSummary {
    JsTransactionReceiptSummary {
        transaction_hash: hash_label(receipt.transaction_hash),
        block_hash: receipt.block_hash.map(hash_label),
        block_number: receipt.block_number,
        transaction_index: receipt.transaction_index,
        success: receipt.success,
        gas_used: receipt.gas_used,
        effective_gas_price: receipt.effective_gas_price.clone(),
        from: receipt.from.to_string(),
        to: receipt.to.map(|address| address.to_string()),
    }
}

fn to_js_submitted_preflighted_transaction(
    submitted: &SubmittedPreflightedTransaction,
) -> JsSubmittedPreflightedTransaction {
    JsSubmittedPreflightedTransaction {
        preflighted: to_js_preflighted_transaction(submitted.transaction()),
        receipt: to_js_receipt_summary(submitted.receipt()),
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

fn from_js_signed_manifest_artifact_bytes(
    artifacts: Vec<JsSignedManifestArtifactBytes>,
) -> Result<Vec<SignedManifestArtifactBytes>> {
    let engine = base64::engine::general_purpose::STANDARD;
    artifacts
        .into_iter()
        .map(|artifact| {
            Ok(SignedManifestArtifactBytes {
                filename: artifact.filename,
                bytes: engine
                    .decode(artifact.bytes_base64)
                    .context("failed to decode base64 signed manifest artifact bytes")?,
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

fn from_js_execution_policy(policy: JsExecutionPolicy) -> Result<ExecutionPolicy> {
    let mode = match policy.mode.as_deref().unwrap_or("strict") {
        "strict" => ExecutionPolicyMode::Strict,
        "insecure_dev" => ExecutionPolicyMode::InsecureDev,
        other => bail!("invalid execution policy mode: {other}"),
    };
    Ok(ExecutionPolicy {
        expected_chain_id: policy.expected_chain_id,
        caller: parse_address(&policy.caller)?,
        expected_pool_code_hash: policy
            .expected_pool_code_hash
            .as_deref()
            .map(parse_b256)
            .transpose()?,
        expected_entrypoint_code_hash: policy
            .expected_entrypoint_code_hash
            .as_deref()
            .map(parse_b256)
            .transpose()?,
        read_consistency: policy
            .read_consistency
            .as_deref()
            .map(parse_read_consistency)
            .transpose()?
            .unwrap_or(privacy_pools_sdk::core::ReadConsistency::Latest),
        max_fee_quote_wei: policy
            .max_fee_quote_wei
            .as_deref()
            .map(parse_u128)
            .transpose()?,
        mode,
    })
}

fn to_js_recovery_checkpoint(
    checkpoint: &privacy_pools_sdk::recovery::RecoveryCheckpoint,
) -> JsRecoveryCheckpoint {
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
        transaction_index: event.transaction_index,
        log_index: event.log_index,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn from_js_withdrawal_event(event: &JsWithdrawalEvent) -> Result<WithdrawalEvent> {
    Ok(WithdrawalEvent {
        withdrawn_value: parse_field(&event.withdrawn_value)?,
        spent_nullifier_hash: parse_field(&event.spent_nullifier_hash)?,
        new_commitment_hash: parse_field(&event.new_commitment_hash)?,
        block_number: event.block_number,
        transaction_index: event.transaction_index,
        log_index: event.log_index,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn from_js_ragequit_event(event: &JsRagequitEvent) -> Result<RagequitEvent> {
    Ok(RagequitEvent {
        commitment_hash: parse_field(&event.commitment_hash)?,
        label: parse_field(&event.label)?,
        value: parse_field(&event.value)?,
        block_number: event.block_number,
        transaction_index: event.transaction_index,
        log_index: event.log_index,
        transaction_hash: parse_b256(&event.transaction_hash)?,
    })
}

fn to_js_ragequit_event(event: &RagequitEvent) -> JsRagequitEvent {
    JsRagequitEvent {
        commitment_hash: field_label(event.commitment_hash),
        label: field_label(event.label),
        value: field_label(event.value),
        block_number: event.block_number,
        transaction_index: event.transaction_index,
        log_index: event.log_index,
        transaction_hash: event.transaction_hash.to_string(),
    }
}

fn to_js_recovered_commitment(commitment: &RecoveredCommitment) -> JsRecoveredCommitment {
    JsRecoveredCommitment {
        hash: field_label(commitment.hash),
        value: field_label(commitment.value),
        label: field_label(commitment.label),
        nullifier: commitment.nullifier.to_decimal_string(),
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
