use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, SolValue, sol};
use anyhow::{Context, Result, bail};
use base64::Engine;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect, Uint8Array, Uint32Array};
#[cfg(target_arch = "wasm32")]
use num_bigint::BigUint;
use privacy_pools_sdk_artifacts::{
    ArtifactBytes, ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
    SignedManifestArtifactBytes,
};
use privacy_pools_sdk_bindings_core::parsers::{
    parse_artifact_kind as parse_binding_artifact_kind,
    parse_compatibility_mode as parse_binding_compatibility_mode,
};
use privacy_pools_sdk_bindings_core::{EvictionPolicy, HandleRegistry};
use privacy_pools_sdk_circuits as circuits;
#[cfg(target_arch = "wasm32")]
use privacy_pools_sdk_core::limits::{MAX_ARTIFACT_BYTES, MAX_TOTAL_ARTIFACT_BYTES};
use privacy_pools_sdk_core::{
    CircuitMerkleWitness, CodeHashCheck, Commitment, CommitmentWitnessRequest, ExecutionPolicyMode,
    ExecutionPreflightReport, FinalizedTransactionRequest, FormattedGroth16Proof, MasterKeys,
    MerkleProof, Nullifier, ProofBundle, RootCheck, RootRead, RootReadKind, Secret,
    TransactionKind, TransactionPlan, TransactionReceiptSummary, Withdrawal,
    WithdrawalWitnessRequest, field_to_hex_32,
    limits::{
        LimitError, MAX_ARTIFACT_JSON_INPUT_BYTES, MAX_CIRCUIT_SESSIONS_PER_TYPE,
        MAX_CONTROL_JSON_INPUT_BYTES, MAX_EXECUTION_HANDLES, MAX_RECOVERY_JSON_INPUT_BYTES,
        MAX_SECRET_HANDLES, MAX_VERIFIED_PROOF_HANDLES, MAX_WITNESS_JSON_INPUT_BYTES,
        parse_json_with_limit as parse_json_with_limit_capped,
    },
    parse_decimal_field,
    wire::{
        WireCommitment, WireCommitmentCircuitInput, WireCommitmentWitnessRequest, WireMasterKeys,
        WireWithdrawalCircuitInput, WireWithdrawalWitnessRequest,
    },
};
use privacy_pools_sdk_prover::{self as prover, ProverBackend, ProvingResult};
use privacy_pools_sdk_recovery::{
    DepositEvent, PoolEvent, PoolRecoveryInput, RagequitEvent, RecoveredAccountState,
    RecoveredCommitment, RecoveredPoolAccount, RecoveredScope, RecoveryCheckpoint, RecoveryKeyset,
    RecoveryPolicy, SpendableScope, WithdrawalEvent,
};
use privacy_pools_sdk_verifier::PreparedVerifier;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    str::FromStr,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};
use uuid::Uuid;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(all(target_arch = "wasm32", feature = "threaded"))]
pub use wasm_bindgen_rayon::init_thread_pool;
use zeroize::Zeroizing;

mod error;

#[cfg(target_arch = "wasm32")]
use error::WebError;

static BN254_BASE_FIELD_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    parse_decimal_field(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .expect("valid BN254 base field modulus")
});

static BN254_SCALAR_FIELD_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    parse_decimal_field(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("valid BN254 scalar field modulus")
});

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
    payload: privacy_pools_sdk_artifacts::SignedArtifactManifestPayload,
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
    read_consistency: String,
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

#[derive(Clone)]
enum SecretHandleEntry {
    MasterKeys(MasterKeys),
    Secrets {
        nullifier: Nullifier,
        secret: Secret,
    },
    Commitment(Commitment),
}

#[derive(Clone)]
#[allow(dead_code)]
enum VerifiedProofHandleEntry {
    Commitment(ProofBundle),
    Ragequit(ProofBundle),
    Withdrawal {
        proof: ProofBundle,
        withdrawal: Withdrawal,
        scope: U256,
    },
}

#[derive(Clone)]
struct BrowserPreflightedTransaction {
    plan: TransactionPlan,
    preflight: ExecutionPreflightReport,
}

#[derive(Clone)]
struct BrowserFinalizedPreflightedTransaction {
    transaction: BrowserPreflightedTransaction,
    request: FinalizedTransactionRequest,
}

#[derive(Clone)]
struct BrowserSubmittedPreflightedTransaction {
    transaction: BrowserPreflightedTransaction,
    receipt: TransactionReceiptSummary,
}

#[derive(Clone)]
enum ExecutionHandleEntry {
    Preflighted(BrowserPreflightedTransaction),
    Finalized(BrowserFinalizedPreflightedTransaction),
    Submitted(BrowserSubmittedPreflightedTransaction),
}

static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static SESSION_REGISTRY: LazyLock<HandleRegistry<BrowserCircuitSession>> = LazyLock::new(|| {
    HandleRegistry::new(MAX_CIRCUIT_SESSIONS_PER_TYPE, EvictionPolicy::LruLowestKey)
});
static SECRET_HANDLE_REGISTRY: LazyLock<HandleRegistry<SecretHandleEntry>> =
    LazyLock::new(|| HandleRegistry::new(MAX_SECRET_HANDLES, EvictionPolicy::LruLowestKey));
static VERIFIED_PROOF_HANDLE_REGISTRY: LazyLock<HandleRegistry<VerifiedProofHandleEntry>> =
    LazyLock::new(|| HandleRegistry::new(MAX_VERIFIED_PROOF_HANDLES, EvictionPolicy::LruLowestKey));
static EXECUTION_HANDLE_REGISTRY: LazyLock<HandleRegistry<ExecutionHandleEntry>> =
    LazyLock::new(|| HandleRegistry::new(MAX_EXECUTION_HANDLES, EvictionPolicy::LruLowestKey));

fn next_secret_handle() -> String {
    Uuid::new_v4().to_string()
}

fn register_secret_handle(entry: SecretHandleEntry) -> Result<String> {
    let handle = next_secret_handle();
    SECRET_HANDLE_REGISTRY
        .insert(handle, entry)
        .map_err(Into::into)
}

fn secret_handle(handle: &str) -> Result<SecretHandleEntry> {
    SECRET_HANDLE_REGISTRY
        .get(handle)
        .with_context(|| format!("unknown browser secret handle `{handle}`"))
}

fn register_verified_proof_handle(entry: VerifiedProofHandleEntry) -> Result<String> {
    let handle = Uuid::new_v4().to_string();
    VERIFIED_PROOF_HANDLE_REGISTRY
        .insert(handle, entry)
        .map_err(Into::into)
}

fn verified_proof_handle(handle: &str) -> Result<VerifiedProofHandleEntry> {
    VERIFIED_PROOF_HANDLE_REGISTRY
        .get(handle)
        .with_context(|| format!("unknown browser verified proof handle `{handle}`"))
}

pub fn remove_verified_proof_handle(handle: &str) -> Result<bool> {
    Ok(VERIFIED_PROOF_HANDLE_REGISTRY.remove(handle).is_some())
}

pub fn clear_verified_proof_handles() -> Result<bool> {
    Ok(VERIFIED_PROOF_HANDLE_REGISTRY.clear() > 0)
}

fn register_execution_handle(entry: ExecutionHandleEntry) -> Result<String> {
    let handle = Uuid::new_v4().to_string();
    EXECUTION_HANDLE_REGISTRY
        .insert(handle, entry)
        .map_err(Into::into)
}

fn execution_handle(handle: &str) -> Result<ExecutionHandleEntry> {
    EXECUTION_HANDLE_REGISTRY
        .get(handle)
        .with_context(|| format!("unknown browser execution handle `{handle}`"))
}

pub fn remove_execution_handle(handle: &str) -> Result<bool> {
    Ok(EXECUTION_HANDLE_REGISTRY.remove(handle).is_some())
}

pub fn clear_execution_handles() -> Result<bool> {
    Ok(EXECUTION_HANDLE_REGISTRY.clear() > 0)
}

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

#[cfg(feature = "dangerous-key-export")]
pub fn derive_master_keys_json(mnemonic: &str) -> Result<String> {
    let keys = privacy_pools_sdk_crypto::generate_master_keys(mnemonic)?;
    to_json_string(&WireMasterKeys::from(&keys))
}

#[cfg(feature = "dangerous-key-export")]
pub fn derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> Result<String> {
    let master_keys: MasterKeys = parse_json::<WireMasterKeys>(master_keys_json)?.try_into()?;
    let secrets = privacy_pools_sdk_crypto::generate_deposit_secrets(
        &master_keys,
        parse_field(scope)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: secrets.0.to_decimal_string(),
        secret: secrets.1.to_decimal_string(),
    })
}

#[cfg(feature = "dangerous-key-export")]
pub fn derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> Result<String> {
    let master_keys: MasterKeys = parse_json::<WireMasterKeys>(master_keys_json)?.try_into()?;
    let secrets = privacy_pools_sdk_crypto::generate_withdrawal_secrets(
        &master_keys,
        parse_field(label)?,
        parse_field(index)?,
    )?;
    to_json_string(&JsSecrets {
        nullifier: secrets.0.to_decimal_string(),
        secret: secrets.1.to_decimal_string(),
    })
}

pub fn get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> Result<String> {
    let commitment = privacy_pools_sdk_crypto::build_commitment(
        parse_field(value)?,
        parse_field(label)?,
        parse_field(nullifier)?,
        parse_field(secret)?,
    )?;
    to_json_string(&WireCommitment::from(&commitment))
}

pub fn import_master_keys_handle_json(master_keys_json: &str) -> Result<String> {
    let keys: MasterKeys = parse_json::<WireMasterKeys>(master_keys_json)?.try_into()?;
    register_secret_handle(SecretHandleEntry::MasterKeys(keys))
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn derive_master_keys_handle_from_utf8_bytes(mnemonic: Vec<u8>) -> Result<String> {
    let mnemonic = Zeroizing::new(mnemonic);
    (|| {
        let phrase = std::str::from_utf8(&mnemonic)?;
        let keys = privacy_pools_sdk_crypto::generate_master_keys(phrase)?;
        register_secret_handle(SecretHandleEntry::MasterKeys(keys))
    })()
}

pub fn derive_master_keys_handle(mnemonic: &str) -> Result<String> {
    let keys = privacy_pools_sdk_crypto::generate_master_keys(mnemonic)?;
    register_secret_handle(SecretHandleEntry::MasterKeys(keys))
}

pub fn generate_deposit_secrets_handle(
    master_keys_handle: &str,
    scope: &str,
    index: &str,
) -> Result<String> {
    let master_keys = match secret_handle(master_keys_handle)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => bail!("browser secret handle `{master_keys_handle}` is not a master-keys handle"),
    };
    let (nullifier, secret) = privacy_pools_sdk_crypto::generate_deposit_secrets(
        &master_keys,
        parse_field(scope)?,
        parse_field(index)?,
    )?;
    register_secret_handle(SecretHandleEntry::Secrets { nullifier, secret })
}

pub fn generate_withdrawal_secrets_handle(
    master_keys_handle: &str,
    label: &str,
    index: &str,
) -> Result<String> {
    let master_keys = match secret_handle(master_keys_handle)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => bail!("browser secret handle `{master_keys_handle}` is not a master-keys handle"),
    };
    let (nullifier, secret) = privacy_pools_sdk_crypto::generate_withdrawal_secrets(
        &master_keys,
        parse_field(label)?,
        parse_field(index)?,
    )?;
    register_secret_handle(SecretHandleEntry::Secrets { nullifier, secret })
}

pub fn get_commitment_from_handles(
    value: &str,
    label: &str,
    secrets_handle: &str,
) -> Result<String> {
    let (nullifier, secret) = match secret_handle(secrets_handle)? {
        SecretHandleEntry::Secrets { nullifier, secret } => (nullifier, secret),
        _ => bail!("browser secret handle `{secrets_handle}` is not a secrets handle"),
    };
    let commitment = privacy_pools_sdk_crypto::build_commitment(
        parse_field(value)?,
        parse_field(label)?,
        nullifier,
        secret,
    )?;
    register_secret_handle(SecretHandleEntry::Commitment(commitment))
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_master_keys(handle: &str) -> Result<String> {
    match secret_handle(handle)? {
        SecretHandleEntry::MasterKeys(keys) => to_json_string(&WireMasterKeys::from(&keys)),
        _ => bail!("browser secret handle `{handle}` is not a master-keys handle"),
    }
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_commitment_preimage(handle: &str) -> Result<String> {
    match secret_handle(handle)? {
        SecretHandleEntry::Commitment(commitment) => {
            to_json_string(&WireCommitment::from(&commitment))
        }
        _ => bail!("browser secret handle `{handle}` is not a commitment handle"),
    }
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_secret(handle: &str) -> Result<String> {
    match secret_handle(handle)? {
        SecretHandleEntry::Secrets { nullifier, secret } => to_json_string(&JsSecrets {
            nullifier: nullifier.to_decimal_string(),
            secret: secret.to_decimal_string(),
        }),
        _ => bail!("browser secret handle `{handle}` is not a secrets handle"),
    }
}

pub fn remove_secret_handle(handle: &str) -> Result<bool> {
    Ok(SECRET_HANDLE_REGISTRY.remove(handle).is_some())
}

pub fn clear_secret_handles() -> Result<bool> {
    Ok(SECRET_HANDLE_REGISTRY.clear() > 0)
}

pub fn calculate_withdrawal_context_json(withdrawal_json: &str, scope: &str) -> Result<String> {
    let withdrawal = parse_json::<JsWithdrawal>(withdrawal_json)?;
    let withdrawal = from_js_withdrawal(&withdrawal)?;
    privacy_pools_sdk_crypto::calculate_withdrawal_context(&withdrawal, parse_field(scope)?)
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
    let request: WithdrawalWitnessRequest =
        parse_json::<WireWithdrawalWitnessRequest>(request_json)?.try_into()?;
    let input = circuits::build_withdrawal_circuit_input(&request)?;
    let input = WireWithdrawalCircuitInput::from(&input);
    to_json_string(&input)
}

pub fn build_withdrawal_witness_input_json(request_json: &str) -> Result<String> {
    let request: WithdrawalWitnessRequest =
        parse_json::<WireWithdrawalWitnessRequest>(request_json)?.try_into()?;
    let input = circuits::build_withdrawal_circuit_input(&request)?;
    prover::serialize_withdrawal_circuit_input(&input).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub fn build_withdrawal_witness_input_from_handles_json(
    commitment_handle: &str,
    withdrawal_json: &str,
    scope: &str,
    withdrawal_amount: &str,
    state_witness_json: &str,
    asp_witness_json: &str,
    new_secrets_handle: &str,
) -> Result<String> {
    let request = withdrawal_request_from_handles(
        commitment_handle,
        withdrawal_json,
        scope,
        withdrawal_amount,
        state_witness_json,
        asp_witness_json,
        new_secrets_handle,
    )?;
    let input = circuits::build_withdrawal_circuit_input(&request)?;
    prover::serialize_withdrawal_circuit_input(&input).map_err(Into::into)
}

pub fn build_commitment_circuit_input_json(request_json: &str) -> Result<String> {
    let request: CommitmentWitnessRequest =
        parse_json::<WireCommitmentWitnessRequest>(request_json)?.try_into()?;
    let input = circuits::build_commitment_circuit_input(&request)?;
    to_json_string(&WireCommitmentCircuitInput::from(&input))
}

pub fn build_commitment_witness_input_json(request_json: &str) -> Result<String> {
    let request: CommitmentWitnessRequest =
        parse_json::<WireCommitmentWitnessRequest>(request_json)?.try_into()?;
    let input = circuits::build_commitment_circuit_input(&request)?;
    prover::serialize_commitment_circuit_input(&input).map_err(Into::into)
}

pub fn build_commitment_witness_input_from_handle_json(commitment_handle: &str) -> Result<String> {
    let request = commitment_request_from_handle(commitment_handle)?;
    let input = circuits::build_commitment_circuit_input(&request)?;
    prover::serialize_commitment_circuit_input(&input).map_err(Into::into)
}

pub fn verify_commitment_proof_for_handle_json(
    proof_json: &str,
    commitment_handle: &str,
) -> Result<String> {
    let request = commitment_request_from_handle(commitment_handle)?;
    let proof = parse_json::<ProofBundle>(proof_json)?;
    validate_commitment_proof_against_request(&request, &proof)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Commitment(proof))
}

pub fn verify_ragequit_proof_for_handle_json(
    proof_json: &str,
    commitment_handle: &str,
) -> Result<String> {
    let request = commitment_request_from_handle(commitment_handle)?;
    let proof = parse_json::<ProofBundle>(proof_json)?;
    validate_commitment_proof_against_request(&request, &proof)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Ragequit(proof))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_withdrawal_proof_for_handles_json(
    proof_json: &str,
    commitment_handle: &str,
    withdrawal_json: &str,
    scope: &str,
    withdrawal_amount: &str,
    state_witness_json: &str,
    asp_witness_json: &str,
    new_secrets_handle: &str,
) -> Result<String> {
    let request = withdrawal_request_from_handles(
        commitment_handle,
        withdrawal_json,
        scope,
        withdrawal_amount,
        state_witness_json,
        asp_witness_json,
        new_secrets_handle,
    )?;
    let proof = parse_json::<ProofBundle>(proof_json)?;
    validate_withdrawal_proof_against_request(&request, &proof)?;
    register_verified_proof_handle(VerifiedProofHandleEntry::Withdrawal {
        proof,
        withdrawal: request.withdrawal,
        scope: request.scope,
    })
}

pub fn checkpoint_recovery_json(events_json: &str, policy_json: &str) -> Result<String> {
    let events =
        parse_json_with_limit::<Vec<JsPoolEvent>>(events_json, MAX_RECOVERY_JSON_INPUT_BYTES)
            .and_then(from_js_pool_events)?;
    let policy = parse_json::<JsRecoveryPolicy>(policy_json)
        .and_then(|policy| from_js_recovery_policy(&policy))?;
    let checkpoint = privacy_pools_sdk_recovery::checkpoint(&events, policy)?;
    to_json_string(&to_js_recovery_checkpoint(&checkpoint))
}

fn ensure_recovery_secret_exports_enabled() -> Result<()> {
    #[cfg(not(feature = "dangerous-key-export"))]
    {
        bail!("recovery secret export requires the dangerous-key-export feature");
    }

    #[cfg(feature = "dangerous-key-export")]
    {
        Ok(())
    }
}

pub fn derive_recovery_keyset_json(mnemonic: &str, policy_json: &str) -> Result<String> {
    ensure_recovery_secret_exports_enabled()?;
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
    ensure_recovery_secret_exports_enabled()?;
    let pools = parse_json_with_limit::<Vec<JsPoolRecoveryInput>>(
        pools_json,
        MAX_RECOVERY_JSON_INPUT_BYTES,
    )
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
    ensure_recovery_secret_exports_enabled()?;
    let keyset = parse_json::<JsRecoveryKeyset>(keyset_json)
        .and_then(|keyset| from_js_recovery_keyset(&keyset))?;
    let pools = parse_json_with_limit::<Vec<JsPoolRecoveryInput>>(
        pools_json,
        MAX_RECOVERY_JSON_INPUT_BYTES,
    )
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

pub fn plan_verified_withdrawal_transaction_with_handle_json(
    chain_id: u64,
    pool_address: &str,
    proof_handle: &str,
) -> Result<String> {
    let (proof, withdrawal) = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal {
            proof, withdrawal, ..
        } => (proof, withdrawal),
        _ => bail!("browser verified proof handle `{proof_handle}` is not a withdrawal proof"),
    };
    let plan =
        plan_withdrawal_transaction(chain_id, parse_address(pool_address)?, &withdrawal, &proof)?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn plan_verified_relay_transaction_with_handle_json(
    chain_id: u64,
    entrypoint_address: &str,
    proof_handle: &str,
) -> Result<String> {
    let (proof, withdrawal, scope) = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal {
            proof,
            withdrawal,
            scope,
        } => (proof, withdrawal, scope),
        _ => bail!("browser verified proof handle `{proof_handle}` is not a withdrawal proof"),
    };
    let plan = plan_relay_transaction(
        chain_id,
        parse_address(entrypoint_address)?,
        &withdrawal,
        &proof,
        scope,
    )?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn plan_verified_ragequit_transaction_with_handle_json(
    chain_id: u64,
    pool_address: &str,
    proof_handle: &str,
) -> Result<String> {
    let proof = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => bail!("browser verified proof handle `{proof_handle}` is not a ragequit proof"),
    };
    let plan = plan_ragequit_transaction(chain_id, parse_address(pool_address)?, &proof)?;
    to_json_string(&to_js_transaction_plan(plan))
}

pub fn register_verified_withdrawal_preflighted_transaction_json(
    proof_handle: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> Result<String> {
    let (proof, withdrawal) = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal {
            proof, withdrawal, ..
        } => (proof, withdrawal),
        _ => bail!("browser verified proof handle `{proof_handle}` is not a withdrawal proof"),
    };
    let transaction =
        parse_json::<JsTransactionPlan>(transaction_json).and_then(from_js_transaction_plan)?;
    let preflight = parse_json::<JsExecutionPreflightReport>(preflight_json)
        .and_then(from_js_execution_preflight)?;
    let pool_address = parse_address(pool_address)?;
    let expected =
        plan_withdrawal_transaction(transaction.chain_id, pool_address, &withdrawal, &proof)?;
    ensure_matching_transaction_plan(&transaction, &expected)?;
    let signals = withdraw_public_signals(&proof)?;
    ensure_preflight_matches_plan(
        &transaction,
        &preflight,
        Some(pool_address),
        None,
        Some(signals[3]),
        Some(signals[5]),
    )?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(
        BrowserPreflightedTransaction {
            plan: transaction,
            preflight,
        },
    ))
}

pub fn register_verified_relay_preflighted_transaction_json(
    proof_handle: &str,
    entrypoint_address: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> Result<String> {
    let (proof, withdrawal, scope) = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal {
            proof,
            withdrawal,
            scope,
        } => (proof, withdrawal, scope),
        _ => bail!("browser verified proof handle `{proof_handle}` is not a withdrawal proof"),
    };
    let transaction =
        parse_json::<JsTransactionPlan>(transaction_json).and_then(from_js_transaction_plan)?;
    let preflight = parse_json::<JsExecutionPreflightReport>(preflight_json)
        .and_then(from_js_execution_preflight)?;
    let entrypoint_address = parse_address(entrypoint_address)?;
    let pool_address = parse_address(pool_address)?;
    let expected = plan_relay_transaction(
        transaction.chain_id,
        entrypoint_address,
        &withdrawal,
        &proof,
        scope,
    )?;
    ensure_matching_transaction_plan(&transaction, &expected)?;
    let signals = withdraw_public_signals(&proof)?;
    ensure_preflight_matches_plan(
        &transaction,
        &preflight,
        Some(pool_address),
        Some(entrypoint_address),
        Some(signals[3]),
        Some(signals[5]),
    )?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(
        BrowserPreflightedTransaction {
            plan: transaction,
            preflight,
        },
    ))
}

pub fn register_verified_ragequit_preflighted_transaction_json(
    proof_handle: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> Result<String> {
    let proof = match verified_proof_handle(proof_handle)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => bail!("browser verified proof handle `{proof_handle}` is not a ragequit proof"),
    };
    let transaction =
        parse_json::<JsTransactionPlan>(transaction_json).and_then(from_js_transaction_plan)?;
    let preflight = parse_json::<JsExecutionPreflightReport>(preflight_json)
        .and_then(from_js_execution_preflight)?;
    let pool_address = parse_address(pool_address)?;
    let expected = plan_ragequit_transaction(transaction.chain_id, pool_address, &proof)?;
    ensure_matching_transaction_plan(&transaction, &expected)?;
    ensure_preflight_matches_plan(
        &transaction,
        &preflight,
        Some(pool_address),
        None,
        None,
        None,
    )?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(
        BrowserPreflightedTransaction {
            plan: transaction,
            preflight,
        },
    ))
}

pub fn register_reconfirmed_preflighted_transaction_json(
    preflighted_handle: &str,
    preflight_json: &str,
) -> Result<String> {
    let transaction = match execution_handle(preflighted_handle)? {
        ExecutionHandleEntry::Preflighted(transaction) => transaction,
        _ => bail!("browser execution handle `{preflighted_handle}` is not preflighted"),
    };
    let preflight = parse_json::<JsExecutionPreflightReport>(preflight_json)
        .and_then(from_js_execution_preflight)?;
    ensure_preflight_matches_existing(&transaction.plan, &preflight)?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(
        BrowserPreflightedTransaction {
            plan: transaction.plan,
            preflight,
        },
    ))
}

pub fn register_finalized_preflighted_transaction_json(
    preflighted_handle: &str,
    request_json: &str,
) -> Result<String> {
    let transaction = match execution_handle(preflighted_handle)? {
        ExecutionHandleEntry::Preflighted(transaction) => transaction,
        _ => bail!("browser execution handle `{preflighted_handle}` is not preflighted"),
    };
    let request = parse_json::<JsFinalizedTransactionRequest>(request_json)
        .and_then(from_js_finalized_request)?;
    ensure_finalized_request_matches_preflighted(&transaction, &request)?;
    register_execution_handle(ExecutionHandleEntry::Finalized(
        BrowserFinalizedPreflightedTransaction {
            transaction,
            request,
        },
    ))
}

pub fn register_submitted_preflighted_transaction_json(
    finalized_handle: &str,
    preflight_json: &str,
    receipt_json: &str,
) -> Result<String> {
    let transaction = match execution_handle(finalized_handle)? {
        ExecutionHandleEntry::Finalized(finalized) => finalized.transaction,
        ExecutionHandleEntry::Preflighted(_) => {
            bail!("browser execution handle `{finalized_handle}` is not finalized")
        }
        ExecutionHandleEntry::Submitted(_) => {
            bail!("browser execution handle `{finalized_handle}` cannot be submitted again")
        }
    };
    let preflight = parse_json::<JsExecutionPreflightReport>(preflight_json)
        .and_then(from_js_execution_preflight)?;
    ensure_preflight_matches_existing(&transaction.plan, &preflight)?;
    let transaction = BrowserPreflightedTransaction {
        plan: transaction.plan,
        preflight,
    };
    let receipt = parse_json::<JsTransactionReceiptSummary>(receipt_json)
        .and_then(from_js_receipt_summary)?;
    ensure_receipt_matches_preflighted(&transaction, &receipt)?;
    register_execution_handle(ExecutionHandleEntry::Submitted(
        BrowserSubmittedPreflightedTransaction {
            transaction,
            receipt,
        },
    ))
}

fn export_preflighted_transaction_json_internal(handle: &str) -> Result<String> {
    match execution_handle(handle)? {
        ExecutionHandleEntry::Preflighted(transaction) => {
            to_json_string(&to_js_preflighted_transaction(&transaction))
        }
        _ => bail!("browser execution handle `{handle}` is not preflighted"),
    }
}

fn export_finalized_preflighted_transaction_json_internal(handle: &str) -> Result<String> {
    match execution_handle(handle)? {
        ExecutionHandleEntry::Finalized(finalized) => {
            to_json_string(&to_js_finalized_preflighted_transaction(&finalized))
        }
        _ => bail!("browser execution handle `{handle}` is not finalized"),
    }
}

fn export_submitted_preflighted_transaction_json_internal(handle: &str) -> Result<String> {
    match execution_handle(handle)? {
        ExecutionHandleEntry::Submitted(submitted) => {
            to_json_string(&to_js_submitted_preflighted_transaction(&submitted))
        }
        _ => bail!("browser execution handle `{handle}` is not submitted"),
    }
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_preflighted_transaction_json(handle: &str) -> Result<String> {
    export_preflighted_transaction_json_internal(handle)
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_finalized_preflighted_transaction_json(handle: &str) -> Result<String> {
    export_finalized_preflighted_transaction_json_internal(handle)
}

#[cfg(feature = "dangerous-exports")]
pub fn dangerously_export_submitted_preflighted_transaction_json(handle: &str) -> Result<String> {
    export_submitted_preflighted_transaction_json_internal(handle)
}

pub fn verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_artifact_bytes)?;
    let bundle = manifest.verify_bundle_bytes(circuit, artifacts)?;
    to_json_string(&to_js_verified_artifact_bundle(&bundle))
}

pub fn verify_signed_manifest_json(
    payload_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<String> {
    let payload = privacy_pools_sdk_artifacts::verify_signed_manifest_bytes(
        payload_json.as_bytes(),
        signature_hex,
        public_key_hex,
    )?;
    to_json_string(&JsVerifiedSignedManifest {
        payload,
        artifact_count: 0,
    })
}

pub fn verify_signed_manifest_artifacts_json(
    payload_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
    artifacts_json: &str,
) -> Result<String> {
    let artifacts = parse_json_with_limit::<Vec<JsSignedManifestArtifactBytes>>(
        artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_signed_manifest_artifact_bytes)?;
    let verified = privacy_pools_sdk_artifacts::verify_signed_manifest_artifact_bytes(
        payload_json.as_bytes(),
        signature_hex,
        public_key_hex,
        artifacts,
    )?;
    to_json_string(&JsVerifiedSignedManifest {
        payload: verified.payload().clone(),
        artifact_count: verified.artifact_count(),
    })
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
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_artifact_bytes)?;
    let session = prepare_circuit_session_from_artifacts(&manifest, artifacts, "withdraw")?;
    to_json_string(&to_js_session_handle(&session))
}

pub fn prepare_commitment_circuit_session_from_bytes_json(
    manifest_json: &str,
    artifacts_json: &str,
) -> Result<String> {
    let manifest = parse_manifest(manifest_json)?;
    let artifacts = parse_json_with_limit::<Vec<JsArtifactBytes>>(
        artifacts_json,
        MAX_ARTIFACT_JSON_INPUT_BYTES,
    )
    .and_then(from_js_artifact_bytes)?;
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
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
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

#[cfg(target_arch = "wasm32")]
pub fn prove_withdrawal_with_session_witness_binary(
    session_handle: &str,
    witness_binary: Uint32Array,
) -> Result<String> {
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
        format!("unknown browser withdrawal circuit session `{session_handle}`")
    })?;
    if session.circuit != "withdraw" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    prove_with_session_witness_binary(&session, witness_binary)
        .and_then(|result| to_json_string(&result))
}

pub fn prove_commitment_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> Result<String> {
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
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

#[cfg(target_arch = "wasm32")]
pub fn prove_commitment_with_session_witness_binary(
    session_handle: &str,
    witness_binary: Uint32Array,
) -> Result<String> {
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
        format!("unknown browser commitment circuit session `{session_handle}`")
    })?;
    if session.circuit != "commitment" {
        bail!(
            "browser session `{session_handle}` is for circuit `{}`",
            session.circuit
        );
    }
    prove_with_session_witness_binary(&session, witness_binary)
        .and_then(|result| to_json_string(&result))
}

pub fn verify_withdrawal_proof_with_session_json(
    session_handle: &str,
    proof_json: &str,
) -> Result<bool> {
    let proof =
        parse_json::<ProofBundle>(proof_json).context("failed to parse proof JSON payload")?;
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
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
    let session = SESSION_REGISTRY.get(session_handle).with_context(|| {
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
    let session = SESSION_REGISTRY.get(session_handle);
    Ok(session.is_some_and(|entry| entry.circuit == "withdraw")
        && SESSION_REGISTRY.remove(session_handle).is_some())
}

pub fn remove_commitment_circuit_session(session_handle: &str) -> Result<bool> {
    let session = SESSION_REGISTRY.get(session_handle);
    Ok(session.is_some_and(|entry| entry.circuit == "commitment")
        && SESSION_REGISTRY.remove(session_handle).is_some())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getVersion)]
pub fn wasm_get_version() -> String {
    get_version()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getBrowserSupportStatusJson)]
pub fn wasm_get_browser_support_status_json() -> std::result::Result<String, WebError> {
    to_json_string(&get_browser_support_status()).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getStableBackendName)]
pub fn wasm_get_stable_backend_name() -> String {
    get_stable_backend_name().to_owned()
}

#[cfg(target_arch = "wasm32")]
#[cfg(feature = "dangerous-key-export")]
#[wasm_bindgen(js_name = deriveMasterKeysJson)]
pub fn wasm_derive_master_keys_json(mnemonic: &str) -> std::result::Result<String, WebError> {
    derive_master_keys_json(mnemonic).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[cfg(feature = "dangerous-key-export")]
#[wasm_bindgen(js_name = deriveDepositSecretsJson)]
pub fn wasm_derive_deposit_secrets_json(
    master_keys_json: &str,
    scope: &str,
    index: &str,
) -> std::result::Result<String, WebError> {
    derive_deposit_secrets_json(master_keys_json, scope, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[cfg(feature = "dangerous-key-export")]
#[wasm_bindgen(js_name = deriveWithdrawalSecretsJson)]
pub fn wasm_derive_withdrawal_secrets_json(
    master_keys_json: &str,
    label: &str,
    index: &str,
) -> std::result::Result<String, WebError> {
    derive_withdrawal_secrets_json(master_keys_json, label, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getCommitmentJson)]
pub fn wasm_get_commitment_json(
    value: &str,
    label: &str,
    nullifier: &str,
    secret: &str,
) -> std::result::Result<String, WebError> {
    get_commitment_json(value, label, nullifier, secret).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = importMasterKeysHandleJson)]
pub fn wasm_import_master_keys_handle_json(
    master_keys_json: &str,
) -> std::result::Result<String, WebError> {
    import_master_keys_handle_json(master_keys_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveMasterKeysHandle)]
pub fn wasm_derive_master_keys_handle(mnemonic: &str) -> std::result::Result<String, WebError> {
    derive_master_keys_handle(mnemonic).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveMasterKeysHandleBytes)]
pub fn wasm_derive_master_keys_handle_bytes(
    mnemonic: Uint8Array,
) -> std::result::Result<String, WebError> {
    derive_master_keys_handle_from_utf8_bytes(mnemonic.to_vec()).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateDepositSecretsHandle)]
pub fn wasm_generate_deposit_secrets_handle(
    master_keys_handle: &str,
    scope: &str,
    index: &str,
) -> std::result::Result<String, WebError> {
    generate_deposit_secrets_handle(master_keys_handle, scope, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateWithdrawalSecretsHandle)]
pub fn wasm_generate_withdrawal_secrets_handle(
    master_keys_handle: &str,
    label: &str,
    index: &str,
) -> std::result::Result<String, WebError> {
    generate_withdrawal_secrets_handle(master_keys_handle, label, index).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getCommitmentFromHandles)]
pub fn wasm_get_commitment_from_handles(
    value: &str,
    label: &str,
    secrets_handle: &str,
) -> std::result::Result<String, WebError> {
    get_commitment_from_handles(value, label, secrets_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportMasterKeys)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_master_keys(handle: &str) -> std::result::Result<String, WebError> {
    dangerously_export_master_keys(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportCommitmentPreimage)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_commitment_preimage(
    handle: &str,
) -> std::result::Result<String, WebError> {
    dangerously_export_commitment_preimage(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportSecret)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_secret(handle: &str) -> std::result::Result<String, WebError> {
    dangerously_export_secret(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeSecretHandle)]
pub fn wasm_remove_secret_handle(handle: &str) -> std::result::Result<bool, WebError> {
    remove_secret_handle(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = clearSecretHandles)]
pub fn wasm_clear_secret_handles() -> std::result::Result<bool, WebError> {
    clear_secret_handles().map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeVerifiedProofHandle)]
pub fn wasm_remove_verified_proof_handle(handle: &str) -> std::result::Result<bool, WebError> {
    remove_verified_proof_handle(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = clearVerifiedProofHandles)]
pub fn wasm_clear_verified_proof_handles() -> std::result::Result<bool, WebError> {
    clear_verified_proof_handles().map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeExecutionHandle)]
pub fn wasm_remove_execution_handle(handle: &str) -> std::result::Result<bool, WebError> {
    remove_execution_handle(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = clearExecutionHandles)]
pub fn wasm_clear_execution_handles() -> std::result::Result<bool, WebError> {
    clear_execution_handles().map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = calculateWithdrawalContextJson)]
pub fn wasm_calculate_withdrawal_context_json(
    withdrawal_json: &str,
    scope: &str,
) -> std::result::Result<String, WebError> {
    calculate_withdrawal_context_json(withdrawal_json, scope).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = generateMerkleProofJson)]
pub fn wasm_generate_merkle_proof_json(
    leaves_json: &str,
    leaf: &str,
) -> std::result::Result<String, WebError> {
    generate_merkle_proof_json(leaves_json, leaf).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCircuitMerkleWitnessJson)]
pub fn wasm_build_circuit_merkle_witness_json(
    proof_json: &str,
    depth: u32,
) -> std::result::Result<String, WebError> {
    build_circuit_merkle_witness_json(proof_json, depth).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildWithdrawalCircuitInputJson)]
pub fn wasm_build_withdrawal_circuit_input_json(
    request_json: &str,
) -> std::result::Result<String, WebError> {
    build_withdrawal_circuit_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildWithdrawalWitnessInputJson)]
pub fn wasm_build_withdrawal_witness_input_json(
    request_json: &str,
) -> std::result::Result<String, WebError> {
    build_withdrawal_witness_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildWithdrawalWitnessInputFromHandlesJson)]
#[allow(clippy::too_many_arguments)]
pub fn wasm_build_withdrawal_witness_input_from_handles_json(
    commitment_handle: &str,
    withdrawal_json: &str,
    scope: &str,
    withdrawal_amount: &str,
    state_witness_json: &str,
    asp_witness_json: &str,
    new_secrets_handle: &str,
) -> std::result::Result<String, WebError> {
    build_withdrawal_witness_input_from_handles_json(
        commitment_handle,
        withdrawal_json,
        scope,
        withdrawal_amount,
        state_witness_json,
        asp_witness_json,
        new_secrets_handle,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCommitmentCircuitInputJson)]
pub fn wasm_build_commitment_circuit_input_json(
    request_json: &str,
) -> std::result::Result<String, WebError> {
    build_commitment_circuit_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCommitmentWitnessInputJson)]
pub fn wasm_build_commitment_witness_input_json(
    request_json: &str,
) -> std::result::Result<String, WebError> {
    build_commitment_witness_input_json(request_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = buildCommitmentWitnessInputFromHandleJson)]
pub fn wasm_build_commitment_witness_input_from_handle_json(
    commitment_handle: &str,
) -> std::result::Result<String, WebError> {
    build_commitment_witness_input_from_handle_json(commitment_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyCommitmentProofForHandleJson)]
pub fn wasm_verify_commitment_proof_for_handle_json(
    proof_json: &str,
    commitment_handle: &str,
) -> std::result::Result<String, WebError> {
    verify_commitment_proof_for_handle_json(proof_json, commitment_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyRagequitProofForHandleJson)]
pub fn wasm_verify_ragequit_proof_for_handle_json(
    proof_json: &str,
    commitment_handle: &str,
) -> std::result::Result<String, WebError> {
    verify_ragequit_proof_for_handle_json(proof_json, commitment_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyWithdrawalProofForHandlesJson)]
#[allow(clippy::too_many_arguments)]
pub fn wasm_verify_withdrawal_proof_for_handles_json(
    proof_json: &str,
    commitment_handle: &str,
    withdrawal_json: &str,
    scope: &str,
    withdrawal_amount: &str,
    state_witness_json: &str,
    asp_witness_json: &str,
    new_secrets_handle: &str,
) -> std::result::Result<String, WebError> {
    verify_withdrawal_proof_for_handles_json(
        proof_json,
        commitment_handle,
        withdrawal_json,
        scope,
        withdrawal_amount,
        state_witness_json,
        asp_witness_json,
        new_secrets_handle,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = checkpointRecoveryJson)]
pub fn wasm_checkpoint_recovery_json(
    events_json: &str,
    policy_json: &str,
) -> std::result::Result<String, WebError> {
    checkpoint_recovery_json(events_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = deriveRecoveryKeysetJson)]
pub fn wasm_derive_recovery_keyset_json(
    mnemonic: &str,
    policy_json: &str,
) -> std::result::Result<String, WebError> {
    derive_recovery_keyset_json(mnemonic, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = recoverAccountStateJson)]
pub fn wasm_recover_account_state_json(
    mnemonic: &str,
    pools_json: &str,
    policy_json: &str,
) -> std::result::Result<String, WebError> {
    recover_account_state_json(mnemonic, pools_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = recoverAccountStateWithKeysetJson)]
pub fn wasm_recover_account_state_with_keyset_json(
    keyset_json: &str,
    pools_json: &str,
    policy_json: &str,
) -> std::result::Result<String, WebError> {
    recover_account_state_with_keyset_json(keyset_json, pools_json, policy_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = isCurrentStateRoot)]
pub fn wasm_is_current_state_root(
    expected_root: &str,
    current_root: &str,
) -> std::result::Result<bool, WebError> {
    is_current_state_root(expected_root, current_root).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = formatGroth16ProofBundleJson)]
pub fn wasm_format_groth16_proof_bundle_json(
    proof_json: &str,
) -> std::result::Result<String, WebError> {
    format_groth16_proof_bundle_json(proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planPoolStateRootReadJson)]
pub fn wasm_plan_pool_state_root_read_json(
    pool_address: &str,
) -> std::result::Result<String, WebError> {
    plan_pool_state_root_read_json(pool_address).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planAspRootReadJson)]
pub fn wasm_plan_asp_root_read_json(
    entrypoint_address: &str,
    pool_address: &str,
) -> std::result::Result<String, WebError> {
    plan_asp_root_read_json(entrypoint_address, pool_address).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planWithdrawalTransactionJson)]
pub fn wasm_plan_withdrawal_transaction_json(
    chain_id: u64,
    pool_address: &str,
    withdrawal_json: &str,
    proof_json: &str,
) -> std::result::Result<String, WebError> {
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
) -> std::result::Result<String, WebError> {
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
) -> std::result::Result<String, WebError> {
    plan_ragequit_transaction_json(chain_id, pool_address, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planVerifiedWithdrawalTransactionWithHandleJson)]
pub fn wasm_plan_verified_withdrawal_transaction_with_handle_json(
    chain_id: u64,
    pool_address: &str,
    proof_handle: &str,
) -> std::result::Result<String, WebError> {
    plan_verified_withdrawal_transaction_with_handle_json(chain_id, pool_address, proof_handle)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planVerifiedRelayTransactionWithHandleJson)]
pub fn wasm_plan_verified_relay_transaction_with_handle_json(
    chain_id: u64,
    entrypoint_address: &str,
    proof_handle: &str,
) -> std::result::Result<String, WebError> {
    plan_verified_relay_transaction_with_handle_json(chain_id, entrypoint_address, proof_handle)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = planVerifiedRagequitTransactionWithHandleJson)]
pub fn wasm_plan_verified_ragequit_transaction_with_handle_json(
    chain_id: u64,
    pool_address: &str,
    proof_handle: &str,
) -> std::result::Result<String, WebError> {
    plan_verified_ragequit_transaction_with_handle_json(chain_id, pool_address, proof_handle)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerVerifiedWithdrawalPreflightedTransactionJson)]
pub fn wasm_register_verified_withdrawal_preflighted_transaction_json(
    proof_handle: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> std::result::Result<String, WebError> {
    register_verified_withdrawal_preflighted_transaction_json(
        proof_handle,
        pool_address,
        transaction_json,
        preflight_json,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerVerifiedRelayPreflightedTransactionJson)]
pub fn wasm_register_verified_relay_preflighted_transaction_json(
    proof_handle: &str,
    entrypoint_address: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> std::result::Result<String, WebError> {
    register_verified_relay_preflighted_transaction_json(
        proof_handle,
        entrypoint_address,
        pool_address,
        transaction_json,
        preflight_json,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerVerifiedRagequitPreflightedTransactionJson)]
pub fn wasm_register_verified_ragequit_preflighted_transaction_json(
    proof_handle: &str,
    pool_address: &str,
    transaction_json: &str,
    preflight_json: &str,
) -> std::result::Result<String, WebError> {
    register_verified_ragequit_preflighted_transaction_json(
        proof_handle,
        pool_address,
        transaction_json,
        preflight_json,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerReconfirmedPreflightedTransactionJson)]
pub fn wasm_register_reconfirmed_preflighted_transaction_json(
    preflighted_handle: &str,
    preflight_json: &str,
) -> std::result::Result<String, WebError> {
    register_reconfirmed_preflighted_transaction_json(preflighted_handle, preflight_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerFinalizedPreflightedTransactionJson)]
pub fn wasm_register_finalized_preflighted_transaction_json(
    preflighted_handle: &str,
    request_json: &str,
) -> std::result::Result<String, WebError> {
    register_finalized_preflighted_transaction_json(preflighted_handle, request_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = registerSubmittedPreflightedTransactionJson)]
pub fn wasm_register_submitted_preflighted_transaction_json(
    finalized_handle: &str,
    preflight_json: &str,
    receipt_json: &str,
) -> std::result::Result<String, WebError> {
    register_submitted_preflighted_transaction_json(finalized_handle, preflight_json, receipt_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = exportPreflightedTransactionInternal)]
pub fn wasm_export_preflighted_transaction_internal(
    handle: &str,
) -> std::result::Result<String, WebError> {
    export_preflighted_transaction_json_internal(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = exportFinalizedPreflightedTransactionInternal)]
pub fn wasm_export_finalized_preflighted_transaction_internal(
    handle: &str,
) -> std::result::Result<String, WebError> {
    export_finalized_preflighted_transaction_json_internal(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = exportSubmittedPreflightedTransactionInternal)]
pub fn wasm_export_submitted_preflighted_transaction_internal(
    handle: &str,
) -> std::result::Result<String, WebError> {
    export_submitted_preflighted_transaction_json_internal(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportPreflightedTransaction)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_preflighted_transaction(
    handle: &str,
) -> std::result::Result<String, WebError> {
    dangerously_export_preflighted_transaction_json(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportFinalizedPreflightedTransaction)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_finalized_preflighted_transaction(
    handle: &str,
) -> std::result::Result<String, WebError> {
    dangerously_export_finalized_preflighted_transaction_json(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = dangerouslyExportSubmittedPreflightedTransaction)]
#[cfg(feature = "dangerous-exports")]
pub fn wasm_dangerously_export_submitted_preflighted_transaction(
    handle: &str,
) -> std::result::Result<String, WebError> {
    dangerously_export_submitted_preflighted_transaction_json(handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyArtifactBytesJson)]
pub fn wasm_verify_artifact_bytes_json(
    manifest_json: &str,
    circuit: &str,
    artifacts_json: &str,
) -> std::result::Result<String, WebError> {
    verify_artifact_bytes_json(manifest_json, circuit, artifacts_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyArtifactBytes)]
pub fn wasm_verify_artifact_bytes(
    manifest_json: &str,
    circuit: &str,
    artifacts: Array,
) -> std::result::Result<String, WebError> {
    let manifest = parse_manifest(manifest_json).map_err(js_error)?;
    let artifacts = from_wasm_artifact_bytes(artifacts).map_err(js_error)?;
    let bundle = manifest
        .verify_bundle_bytes(circuit, artifacts)
        .map_err(|error| js_error(error.into()))?;
    to_json_string(&to_js_verified_artifact_bundle(&bundle)).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifySignedManifest)]
pub fn wasm_verify_signed_manifest(
    payload_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> std::result::Result<String, WebError> {
    verify_signed_manifest_json(payload_json, signature_hex, public_key_hex).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifySignedManifestArtifactsJson)]
pub fn wasm_verify_signed_manifest_artifacts_json(
    payload_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
    artifacts_json: &str,
) -> std::result::Result<String, WebError> {
    verify_signed_manifest_artifacts_json(
        payload_json,
        signature_hex,
        public_key_hex,
        artifacts_json,
    )
    .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = prepareWithdrawalCircuitSessionFromBytes)]
pub fn wasm_prepare_withdrawal_circuit_session_from_bytes(
    manifest_json: &str,
    artifacts: Array,
) -> std::result::Result<String, WebError> {
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
) -> std::result::Result<String, WebError> {
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
) -> std::result::Result<bool, WebError> {
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
) -> std::result::Result<bool, WebError> {
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
) -> std::result::Result<bool, WebError> {
    verify_withdrawal_proof_with_session_json(session_handle, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveWithdrawalWithWitnessJson)]
pub fn wasm_prove_withdrawal_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> std::result::Result<String, WebError> {
    prove_withdrawal_with_witness_json(manifest_json, artifacts_json, witness_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveWithdrawalWithSessionWitnessJson)]
pub fn wasm_prove_withdrawal_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> std::result::Result<String, WebError> {
    prove_withdrawal_with_session_witness_json(session_handle, witness_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveWithdrawalWithSessionWitnessBinary)]
pub fn wasm_prove_withdrawal_with_session_witness_binary(
    session_handle: &str,
    witness_binary: Uint32Array,
) -> std::result::Result<String, WebError> {
    prove_withdrawal_with_session_witness_binary(session_handle, witness_binary).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyCommitmentProofWithSession)]
pub fn wasm_verify_commitment_proof_with_session(
    session_handle: &str,
    proof_json: &str,
) -> std::result::Result<bool, WebError> {
    verify_commitment_proof_with_session_json(session_handle, proof_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveCommitmentWithWitnessJson)]
pub fn wasm_prove_commitment_with_witness_json(
    manifest_json: &str,
    artifacts_json: &str,
    witness_json: &str,
) -> std::result::Result<String, WebError> {
    prove_commitment_with_witness_json(manifest_json, artifacts_json, witness_json)
        .map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveCommitmentWithSessionWitnessJson)]
pub fn wasm_prove_commitment_with_session_witness_json(
    session_handle: &str,
    witness_json: &str,
) -> std::result::Result<String, WebError> {
    prove_commitment_with_session_witness_json(session_handle, witness_json).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = proveCommitmentWithSessionWitnessBinary)]
pub fn wasm_prove_commitment_with_session_witness_binary(
    session_handle: &str,
    witness_binary: Uint32Array,
) -> std::result::Result<String, WebError> {
    prove_commitment_with_session_witness_binary(session_handle, witness_binary).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeWithdrawalCircuitSession)]
pub fn wasm_remove_withdrawal_circuit_session(
    session_handle: &str,
) -> std::result::Result<bool, WebError> {
    remove_withdrawal_circuit_session(session_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = removeCommitmentCircuitSession)]
pub fn wasm_remove_commitment_circuit_session(
    session_handle: &str,
) -> std::result::Result<bool, WebError> {
    remove_commitment_circuit_session(session_handle).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = getArtifactStatusesJson)]
pub fn wasm_get_artifact_statuses_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, WebError> {
    get_artifact_statuses_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = resolveVerifiedArtifactBundleJson)]
pub fn wasm_resolve_verified_artifact_bundle_json(
    manifest_json: &str,
    artifacts_root: &str,
    circuit: &str,
) -> std::result::Result<String, WebError> {
    resolve_verified_artifact_bundle_json(manifest_json, artifacts_root, circuit).map_err(js_error)
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: anyhow::Error) -> WebError {
    WebError::from(error)
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
    parse_json_with_limit_capped(value, max_bytes, "json_payload", |error| match error {
        LimitError::PayloadTooLarge { limit, actual, .. } => {
            anyhow::anyhow!("JSON payload exceeds maximum size: {actual} > {limit} bytes")
        }
        LimitError::Parse(message) => anyhow::anyhow!("failed to parse JSON payload: {message}"),
    })
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

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    hex::decode(value.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex bytes `{value}`"))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind> {
    parse_binding_artifact_kind(value)
        .map_err(|_| anyhow::anyhow!("invalid artifact kind: {value}"))
}

fn parse_transaction_kind(value: &str) -> Result<TransactionKind> {
    match value {
        "withdraw" => Ok(TransactionKind::Withdraw),
        "relay" => Ok(TransactionKind::Relay),
        "ragequit" => Ok(TransactionKind::Ragequit),
        _ => bail!("invalid transaction kind: {value}"),
    }
}

fn parse_root_read_kind(value: &str) -> Result<RootReadKind> {
    match value {
        "pool_state" => Ok(RootReadKind::PoolState),
        "asp" => Ok(RootReadKind::Asp),
        _ => bail!("invalid root read kind: {value}"),
    }
}

fn parse_execution_policy_mode(value: &str) -> Result<ExecutionPolicyMode> {
    privacy_pools_sdk_core::parsers::parse_execution_policy_mode(value)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn parse_read_consistency(value: &str) -> Result<privacy_pools_sdk_core::ReadConsistency> {
    privacy_pools_sdk_core::parsers::parse_read_consistency(value)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn read_consistency_label(consistency: privacy_pools_sdk_core::ReadConsistency) -> String {
    match consistency {
        privacy_pools_sdk_core::ReadConsistency::Latest => "latest".to_owned(),
        privacy_pools_sdk_core::ReadConsistency::Finalized => "finalized".to_owned(),
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

fn hash_label(value: B256) -> String {
    value.to_string()
}

fn execution_policy_mode_label(mode: ExecutionPolicyMode) -> String {
    match mode {
        ExecutionPolicyMode::Strict => "strict".to_owned(),
        ExecutionPolicyMode::InsecureDev => "insecure_dev".to_owned(),
    }
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

fn from_js_withdrawal(withdrawal: &JsWithdrawal) -> Result<Withdrawal> {
    let data = hex::decode(withdrawal.data.trim_start_matches("0x"))
        .with_context(|| format!("invalid hex withdrawal data `{}`", withdrawal.data))?;
    Ok(Withdrawal {
        processor: parse_address(&withdrawal.processooor)?,
        data: data.into(),
    })
}

fn commitment_request_from_handle(commitment_handle: &str) -> Result<CommitmentWitnessRequest> {
    let commitment = match secret_handle(commitment_handle)? {
        SecretHandleEntry::Commitment(commitment) => commitment,
        _ => bail!("browser secret handle `{commitment_handle}` is not a commitment handle"),
    };
    Ok(CommitmentWitnessRequest { commitment })
}

#[allow(clippy::too_many_arguments)]
fn withdrawal_request_from_handles(
    commitment_handle: &str,
    withdrawal_json: &str,
    scope: &str,
    withdrawal_amount: &str,
    state_witness_json: &str,
    asp_witness_json: &str,
    new_secrets_handle: &str,
) -> Result<WithdrawalWitnessRequest> {
    let commitment = commitment_request_from_handle(commitment_handle)?.commitment;
    let (new_nullifier, new_secret) = match secret_handle(new_secrets_handle)? {
        SecretHandleEntry::Secrets { nullifier, secret } => (nullifier, secret),
        _ => bail!("browser secret handle `{new_secrets_handle}` is not a secrets handle"),
    };
    WireWithdrawalWitnessRequest {
        commitment: WireCommitment::from(&commitment),
        withdrawal: parse_json::<privacy_pools_sdk_core::wire::WireWithdrawal>(withdrawal_json)?,
        scope: scope.to_owned(),
        withdrawal_amount: withdrawal_amount.to_owned(),
        state_witness: parse_json(state_witness_json)?,
        asp_witness: parse_json(asp_witness_json)?,
        new_nullifier: new_nullifier.to_decimal_string(),
        new_secret: new_secret.to_decimal_string(),
    }
    .try_into()
    .map_err(Into::into)
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
    *BN254_BASE_FIELD_MODULUS
}

fn bn254_scalar_field_modulus() -> U256 {
    *BN254_SCALAR_FIELD_MODULUS
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

fn ensure_matching_transaction_plan(
    actual: &TransactionPlan,
    expected: &TransactionPlan,
) -> Result<()> {
    if actual != expected {
        bail!("browser execution handle plan does not match verified proof handle");
    }
    Ok(())
}

fn ensure_preflight_matches_plan(
    plan: &TransactionPlan,
    preflight: &ExecutionPreflightReport,
    pool_address: Option<Address>,
    entrypoint_address: Option<Address>,
    expected_state_root: Option<U256>,
    expected_asp_root: Option<U256>,
) -> Result<()> {
    ensure_preflight_matches_existing(plan, preflight)?;

    if preflight.mode.is_strict() {
        for check in &preflight.code_hash_checks {
            if check.expected_code_hash.is_none() {
                bail!("strict browser preflight is missing a code-hash expectation");
            }
            if check.matches_expected != Some(true) {
                bail!("strict browser preflight code-hash expectation failed");
            }
        }
    }

    if let Some(pool_address) = pool_address {
        ensure_code_hash_check(preflight, pool_address, "pool")?;
    }
    if let Some(entrypoint_address) = entrypoint_address {
        ensure_code_hash_check(preflight, entrypoint_address, "entrypoint")?;
    }
    if let Some(root) = expected_state_root {
        ensure_root_check(preflight, RootReadKind::PoolState, pool_address, root)?;
    }
    if let Some(root) = expected_asp_root {
        ensure_root_check(preflight, RootReadKind::Asp, pool_address, root)?;
    }

    Ok(())
}

fn ensure_preflight_matches_existing(
    plan: &TransactionPlan,
    preflight: &ExecutionPreflightReport,
) -> Result<()> {
    if preflight.kind != plan.kind {
        bail!("browser preflight kind does not match transaction plan");
    }
    if preflight.target != plan.target {
        bail!("browser preflight target does not match transaction plan");
    }
    if preflight.expected_chain_id != plan.chain_id || preflight.actual_chain_id != plan.chain_id {
        bail!("browser preflight chain id does not match transaction plan");
    }
    if !preflight.chain_id_matches {
        bail!("browser preflight chain id check failed");
    }
    if !preflight.simulated {
        bail!("browser preflight must include a successful simulation");
    }
    Ok(())
}

fn ensure_code_hash_check(
    preflight: &ExecutionPreflightReport,
    address: Address,
    label: &str,
) -> Result<()> {
    let Some(check) = preflight
        .code_hash_checks
        .iter()
        .find(|check| check.address == address)
    else {
        bail!("browser preflight is missing {label} code-hash check");
    };

    if preflight.mode.is_strict() && check.expected_code_hash.is_none() {
        bail!("strict browser preflight is missing {label} code-hash expectation");
    }
    if preflight.mode.is_strict() && check.matches_expected != Some(true) {
        bail!("strict browser preflight {label} code-hash expectation failed");
    }
    Ok(())
}

fn ensure_root_check(
    preflight: &ExecutionPreflightReport,
    kind: RootReadKind,
    pool_address: Option<Address>,
    expected_root: U256,
) -> Result<()> {
    let Some(check) = preflight.root_checks.iter().find(|check| {
        check.kind == kind
            && Some(check.pool_address) == pool_address
            && check.expected_root == expected_root
    }) else {
        bail!("browser preflight is missing expected root check");
    };

    if !check.matches || check.actual_root != expected_root {
        bail!("browser preflight root check failed");
    }
    Ok(())
}

fn ensure_finalized_request_matches_preflighted(
    transaction: &BrowserPreflightedTransaction,
    request: &FinalizedTransactionRequest,
) -> Result<()> {
    if request.kind != transaction.plan.kind {
        bail!("finalized request kind does not match preflighted transaction");
    }
    if request.chain_id != transaction.plan.chain_id {
        bail!("finalized request chain id does not match preflighted transaction");
    }
    if request.from != transaction.preflight.caller {
        bail!("finalized request sender does not match preflight caller");
    }
    if request.to != transaction.plan.target {
        bail!("finalized request target does not match preflighted transaction");
    }
    if request.value != transaction.plan.value {
        bail!("finalized request value does not match preflighted transaction");
    }
    if request.data != transaction.plan.calldata {
        bail!("finalized request calldata does not match preflighted transaction");
    }
    Ok(())
}

fn ensure_receipt_matches_preflighted(
    transaction: &BrowserPreflightedTransaction,
    receipt: &TransactionReceiptSummary,
) -> Result<()> {
    if !receipt.success {
        bail!("submitted browser transaction receipt was not successful");
    }
    if receipt.from != transaction.preflight.caller {
        bail!("submitted browser transaction sender does not match preflight caller");
    }
    if receipt.to != Some(transaction.plan.target) {
        bail!("submitted browser transaction target does not match preflighted transaction");
    }
    Ok(())
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
        read_consistency: read_consistency_label(report.read_consistency),
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

fn to_js_preflighted_transaction(
    transaction: &BrowserPreflightedTransaction,
) -> JsPreflightedTransaction {
    JsPreflightedTransaction {
        transaction: to_js_transaction_plan(transaction.plan.clone()),
        preflight: to_js_execution_preflight(transaction.preflight.clone()),
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
    finalized: &BrowserFinalizedPreflightedTransaction,
) -> JsFinalizedPreflightedTransaction {
    JsFinalizedPreflightedTransaction {
        preflighted: to_js_preflighted_transaction(&finalized.transaction),
        request: to_js_finalized_request(&finalized.request),
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
    submitted: &BrowserSubmittedPreflightedTransaction,
) -> JsSubmittedPreflightedTransaction {
    JsSubmittedPreflightedTransaction {
        preflighted: to_js_preflighted_transaction(&submitted.transaction),
        receipt: to_js_receipt_summary(&submitted.receipt),
    }
}

fn from_js_formatted_groth16_proof(
    proof: JsFormattedGroth16Proof,
) -> Result<FormattedGroth16Proof> {
    Ok(FormattedGroth16Proof {
        p_a: proof.p_a.try_into().map_err(|values: Vec<String>| {
            anyhow::anyhow!("pA must have exactly 2 elements, got {}", values.len())
        })?,
        p_b: proof
            .p_b
            .into_iter()
            .map(|row| {
                row.try_into().map_err(|values: Vec<String>| {
                    anyhow::anyhow!("pB rows must have exactly 2 elements, got {}", values.len())
                })
            })
            .collect::<Result<Vec<[String; 2]>>>()?
            .try_into()
            .map_err(|rows: Vec<[String; 2]>| {
                anyhow::anyhow!("pB must have exactly 2 rows, got {}", rows.len())
            })?,
        p_c: proof.p_c.try_into().map_err(|values: Vec<String>| {
            anyhow::anyhow!("pC must have exactly 2 elements, got {}", values.len())
        })?,
        pub_signals: proof.pub_signals,
    })
}

fn from_js_transaction_plan(plan: JsTransactionPlan) -> Result<TransactionPlan> {
    Ok(TransactionPlan {
        kind: parse_transaction_kind(&plan.kind)?,
        chain_id: plan.chain_id,
        target: parse_address(&plan.target)?,
        calldata: parse_hex_bytes(&plan.calldata)?.into(),
        value: parse_field(&plan.value)?,
        proof: from_js_formatted_groth16_proof(plan.proof)?,
    })
}

fn from_js_code_hash_check(check: JsCodeHashCheck) -> Result<CodeHashCheck> {
    Ok(CodeHashCheck {
        address: parse_address(&check.address)?,
        expected_code_hash: check
            .expected_code_hash
            .as_deref()
            .map(parse_b256)
            .transpose()?,
        actual_code_hash: parse_b256(&check.actual_code_hash)?,
        matches_expected: check.matches_expected,
    })
}

fn from_js_root_check(check: JsRootCheck) -> Result<RootCheck> {
    Ok(RootCheck {
        kind: parse_root_read_kind(&check.kind)?,
        contract_address: parse_address(&check.contract_address)?,
        pool_address: parse_address(&check.pool_address)?,
        expected_root: parse_field(&check.expected_root)?,
        actual_root: parse_field(&check.actual_root)?,
        matches: check.matches,
    })
}

fn from_js_execution_preflight(
    report: JsExecutionPreflightReport,
) -> Result<ExecutionPreflightReport> {
    Ok(ExecutionPreflightReport {
        kind: parse_transaction_kind(&report.kind)?,
        caller: parse_address(&report.caller)?,
        target: parse_address(&report.target)?,
        expected_chain_id: report.expected_chain_id,
        actual_chain_id: report.actual_chain_id,
        chain_id_matches: report.chain_id_matches,
        simulated: report.simulated,
        estimated_gas: report.estimated_gas,
        read_consistency: parse_read_consistency(&report.read_consistency)?,
        max_fee_quote_wei: report
            .max_fee_quote_wei
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .context("invalid maxFeeQuoteWei")?,
        mode: parse_execution_policy_mode(report.mode.as_deref().unwrap_or("strict"))?,
        code_hash_checks: report
            .code_hash_checks
            .into_iter()
            .map(from_js_code_hash_check)
            .collect::<Result<Vec<_>>>()?,
        root_checks: report
            .root_checks
            .into_iter()
            .map(from_js_root_check)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn from_js_finalized_request(
    request: JsFinalizedTransactionRequest,
) -> Result<FinalizedTransactionRequest> {
    Ok(FinalizedTransactionRequest {
        kind: parse_transaction_kind(&request.kind)?,
        chain_id: request.chain_id,
        from: parse_address(&request.from)?,
        to: parse_address(&request.to)?,
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        value: parse_field(&request.value)?,
        data: parse_hex_bytes(&request.data)?.into(),
        gas_price: request
            .gas_price
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .context("invalid gasPrice")?,
        max_fee_per_gas: request
            .max_fee_per_gas
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .context("invalid maxFeePerGas")?,
        max_priority_fee_per_gas: request
            .max_priority_fee_per_gas
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .context("invalid maxPriorityFeePerGas")?,
    })
}

fn from_js_receipt_summary(
    receipt: JsTransactionReceiptSummary,
) -> Result<TransactionReceiptSummary> {
    Ok(TransactionReceiptSummary {
        transaction_hash: parse_b256(&receipt.transaction_hash)?,
        block_hash: receipt.block_hash.as_deref().map(parse_b256).transpose()?,
        block_number: receipt.block_number,
        transaction_index: receipt.transaction_index,
        success: receipt.success,
        gas_used: receipt.gas_used,
        effective_gas_price: receipt.effective_gas_price,
        from: parse_address(&receipt.from)?,
        to: receipt.to.as_deref().map(parse_address).transpose()?,
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

fn state_root_read(pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        consistency: privacy_pools_sdk_core::ReadConsistency::Latest,
        call_data: Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode()),
    }
}

fn asp_root_read(entrypoint_address: Address, pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::Asp,
        contract_address: entrypoint_address,
        pool_address,
        consistency: privacy_pools_sdk_core::ReadConsistency::Latest,
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

fn validate_commitment_proof_against_request(
    request: &CommitmentWitnessRequest,
    proof: &ProofBundle,
) -> Result<()> {
    circuits::validate_commitment_request(request)?;
    let public_signals = ragequit_public_signals(proof)?;
    let expected_signals = [
        ("commitmentHash", request.commitment.hash),
        (
            "nullifierHash",
            privacy_pools_sdk_crypto::hash_nullifier(
                &request.commitment.preimage.precommitment.nullifier,
            )?,
        ),
        ("value", request.commitment.preimage.value),
        ("label", request.commitment.preimage.label),
    ];

    for ((field, expected), actual) in expected_signals.into_iter().zip(public_signals) {
        if expected != actual {
            bail!(
                "commitment proof public signal `{field}` mismatch: expected {expected}, got {actual}"
            );
        }
    }
    Ok(())
}

fn validate_withdrawal_proof_against_request(
    request: &WithdrawalWitnessRequest,
    proof: &ProofBundle,
) -> Result<()> {
    circuits::validate_withdrawal_request(request)?;
    let public_signals = withdraw_public_signals(proof)?;
    let remaining_value = request.commitment.preimage.value - request.withdrawal_amount;
    let new_commitment = privacy_pools_sdk_crypto::build_commitment(
        remaining_value,
        request.commitment.preimage.label,
        request.new_nullifier.clone(),
        request.new_secret.clone(),
    )?;
    let expected_context = privacy_pools_sdk_crypto::calculate_withdrawal_context_field(
        &request.withdrawal,
        request.scope,
    )?;
    let expected_signals = [
        ("newCommitmentHash", new_commitment.hash),
        (
            "existingNullifierHash",
            privacy_pools_sdk_crypto::hash_nullifier(
                &request.commitment.preimage.precommitment.nullifier,
            )?,
        ),
        ("withdrawnValue", request.withdrawal_amount),
        ("stateRoot", request.state_witness.root),
        (
            "stateTreeDepth",
            U256::from(request.state_witness.depth as u64),
        ),
        ("ASPRoot", request.asp_witness.root),
        ("ASPTreeDepth", U256::from(request.asp_witness.depth as u64)),
        ("context", expected_context),
    ];

    for ((field, expected), actual) in expected_signals.into_iter().zip(public_signals) {
        if expected != actual {
            bail!(
                "withdrawal proof public signal `{field}` mismatch: expected {expected}, got {actual}"
            );
        }
    }
    Ok(())
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

#[cfg(target_arch = "wasm32")]
fn from_wasm_artifact_bytes(
    artifacts: Array,
) -> Result<Vec<privacy_pools_sdk_artifacts::ArtifactBytes>> {
    let artifacts = artifacts
        .iter()
        .map(|artifact| {
            let kind = Reflect::get(&artifact, &JsValue::from_str("kind"))
                .map_err(|error| anyhow::anyhow!("failed to read artifact kind: {error:?}"))?
                .as_string()
                .context("artifact kind must be a string")?;
            let bytes = Reflect::get(&artifact, &JsValue::from_str("bytes"))
                .map_err(|error| anyhow::anyhow!("failed to read artifact bytes: {error:?}"))?;
            let bytes = Uint8Array::new(&bytes).to_vec();
            if bytes.len() > MAX_ARTIFACT_BYTES {
                bail!(
                    "artifact bytes exceed maximum size: {} > {} bytes",
                    bytes.len(),
                    MAX_ARTIFACT_BYTES
                );
            }

            Ok(privacy_pools_sdk_artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&kind)?,
                bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let total_bytes = artifacts
        .iter()
        .map(|artifact| artifact.bytes.len())
        .sum::<usize>();
    if total_bytes > MAX_TOTAL_ARTIFACT_BYTES {
        bail!(
            "artifact bundle exceeds maximum size: {} > {} bytes",
            total_bytes,
            MAX_TOTAL_ARTIFACT_BYTES
        );
    }
    Ok(artifacts)
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
    let compatibility_mode =
        parse_binding_compatibility_mode(&policy.compatibility_mode).map_err(|_| {
            anyhow::anyhow!("invalid compatibility mode: {}", policy.compatibility_mode)
        })?;
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

fn prove_with_session_witness(
    session: &BrowserCircuitSession,
    witness_json: &str,
) -> Result<JsProvingResult> {
    let witness = parse_json_with_limit::<Vec<String>>(witness_json, MAX_WITNESS_JSON_INPUT_BYTES)?;
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

#[cfg(target_arch = "wasm32")]
fn prove_with_session_witness_binary(
    session: &BrowserCircuitSession,
    witness_binary: Uint32Array,
) -> Result<JsProvingResult> {
    let prepared = session.prepared.as_ref().with_context(|| {
        format!(
            "browser {} circuit session `{}` was prepared for verification only",
            session.circuit, session.handle
        )
    })?;
    let witness_format = prepared.witness_format()?;
    let witness = parse_binary_witness_values(
        witness_binary,
        witness_format.witness_count,
        &witness_format.field_modulus,
    )?;
    let proving = prepared.prove_with_witness_values(witness)?;
    if !session.verifier.verify(&proving.proof)? {
        bail!("browser proof verification failed after proving");
    }
    Ok(to_js_proving_result(proving))
}

#[cfg(target_arch = "wasm32")]
fn parse_binary_witness_values(
    witness_binary: Uint32Array,
    expected_witness_count: usize,
    field_modulus: &BigUint,
) -> Result<Vec<BigUint>> {
    const LIMBS_PER_FIELD: usize = 8;
    let limbs = witness_binary.to_vec();
    if limbs.is_empty() || limbs.len() % LIMBS_PER_FIELD != 0 {
        bail!(
            "binary witness must contain a whole number of field elements encoded as {LIMBS_PER_FIELD} little-endian u32 limbs"
        );
    }
    let actual_witness_count = limbs.len() / LIMBS_PER_FIELD;
    if actual_witness_count != expected_witness_count {
        bail!(
            "invalid binary witness length: expected {expected_witness_count} field elements, got {actual_witness_count}"
        );
    }

    let witness = limbs
        .chunks_exact(LIMBS_PER_FIELD)
        .map(|chunk| BigUint::new(chunk.to_vec()))
        .collect::<Vec<_>>();
    if let Some((index, _)) = witness
        .iter()
        .enumerate()
        .find(|(_, value)| *value >= field_modulus)
    {
        bail!("binary witness field element at index {index} is not canonical");
    }
    Ok(witness)
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

    SESSION_REGISTRY.insert(handle, session.clone())?;

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
    use privacy_pools_sdk_verifier::PreparedVerifier;

    fn verification_only_session() -> BrowserCircuitSession {
        BrowserCircuitSession {
            handle: "browser-test-session".to_owned(),
            circuit: "withdraw".to_owned(),
            artifact_version: "test".to_owned(),
            verifier: PreparedVerifier::from_vkey_bytes(include_bytes!(
                "../../../fixtures/artifacts/browser-verification.vkey.json"
            ))
            .expect("browser verification key fixture parses"),
            prepared: None,
        }
    }

    fn padded_witness_payload(target_len: usize) -> String {
        assert!(target_len >= 5, "witness payload must fit [\"1\"]");
        format!("[{}\"1\"]", " ".repeat(target_len - 5))
    }

    #[test]
    fn browser_status_reports_proving_available() {
        let status = get_browser_support_status();
        assert_eq!(status.runtime, "browser");
        assert!(status.proving_available);
        assert!(status.reason.contains("browser proving"));
    }

    #[test]
    fn prove_with_session_witness_accepts_just_under_limit_payloads() {
        let session = verification_only_session();
        let witness_json = padded_witness_payload(MAX_WITNESS_JSON_INPUT_BYTES - 1);
        let error = prove_with_session_witness(&session, &witness_json).unwrap_err();

        assert!(error.to_string().contains("prepared for verification only"));
    }

    #[test]
    fn prove_with_session_witness_rejects_payloads_above_limit() {
        let session = verification_only_session();
        let witness_json = padded_witness_payload(MAX_WITNESS_JSON_INPUT_BYTES + 1);
        let error = prove_with_session_witness(&session, &witness_json).unwrap_err();

        assert!(error.to_string().contains("exceeds maximum size"));
    }

    #[cfg(feature = "dangerous-key-export")]
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
