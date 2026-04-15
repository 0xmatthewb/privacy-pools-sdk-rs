use alloy_primitives::{Address, B256, U256};
use privacy_pools_sdk::{
    FinalizedTransactionExecution, PreparedTransactionExecution, PrivacyPoolsSdk,
    SubmittedTransactionExecution,
    artifacts::{ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle},
    core::{
        CircuitMerkleWitness, CodeHashCheck, Commitment, ExecutionPolicy, ExecutionPreflightReport,
        FinalizedTransactionRequest, FormattedGroth16Proof, MasterKeys, MerkleProof, ProofBundle,
        RootCheck, RootReadKind, SnarkJsProof, TransactionPlan, TransactionReceiptSummary,
        Withdrawal, WithdrawalCircuitInput, WithdrawalWitnessRequest,
    },
    prover::{BackendProfile, ProverBackend, ProvingResult},
    recovery::{CompatibilityMode, PoolEvent, RecoveryPolicy},
    signer::{ExternalSigner, LocalMnemonicSigner, SignerAdapter, SignerKind},
};
use std::{
    collections::HashMap,
    future::Future,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, LazyLock, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid field element: {0}")]
    InvalidField(String),
    #[error("invalid hash: {0}")]
    InvalidHash(String),
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(String),
    #[error("invalid artifact kind: {0}")]
    InvalidArtifactKind(String),
    #[error("invalid compatibility mode: {0}")]
    InvalidCompatibilityMode(String),
    #[error("withdrawal circuit session handle not found: {0}")]
    SessionNotFound(String),
    #[error("signer handle not found: {0}")]
    SignerNotFound(String),
    #[error("job handle not found: {0}")]
    JobNotFound(String),
    #[error("signer handle requires external signing: {0}")]
    SignerRequiresExternalSigning(String),
    #[error("artifact manifest parse failed: {0}")]
    InvalidManifest(String),
    #[error("sdk operation failed: {0}")]
    OperationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMasterKeys {
    pub master_nullifier: String,
    pub master_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSecrets {
    pub nullifier: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCommitment {
    pub hash: String,
    pub nullifier_hash: String,
    pub precommitment_hash: String,
    pub value: String,
    pub label: String,
    pub nullifier: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWithdrawal {
    pub processooor: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSnarkJsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiProofBundle {
    pub proof: FfiSnarkJsProof,
    pub public_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiProvingResult {
    pub backend: String,
    pub proof: FfiProofBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFormattedGroth16Proof {
    pub p_a: Vec<String>,
    pub p_b: Vec<Vec<String>>,
    pub p_c: Vec<String>,
    pub pub_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTransactionPlan {
    pub kind: String,
    pub chain_id: u64,
    pub target: String,
    pub calldata: String,
    pub value: String,
    pub proof: FfiFormattedGroth16Proof,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiExecutionPolicy {
    pub expected_chain_id: u64,
    pub caller: String,
    pub expected_pool_code_hash: Option<String>,
    pub expected_entrypoint_code_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCodeHashCheck {
    pub address: String,
    pub expected_code_hash: Option<String>,
    pub actual_code_hash: String,
    pub matches_expected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRootCheck {
    pub kind: String,
    pub contract_address: String,
    pub pool_address: String,
    pub expected_root: String,
    pub actual_root: String,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiExecutionPreflightReport {
    pub kind: String,
    pub caller: String,
    pub target: String,
    pub expected_chain_id: u64,
    pub actual_chain_id: u64,
    pub chain_id_matches: bool,
    pub simulated: bool,
    pub estimated_gas: u64,
    pub code_hash_checks: Vec<FfiCodeHashCheck>,
    pub root_checks: Vec<FfiRootCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPreparedTransactionExecution {
    pub proving: FfiProvingResult,
    pub transaction: FfiTransactionPlan,
    pub preflight: FfiExecutionPreflightReport,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFinalizedTransactionRequest {
    pub kind: String,
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub value: String,
    pub data: String,
    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFinalizedTransactionExecution {
    pub prepared: FfiPreparedTransactionExecution,
    pub request: FfiFinalizedTransactionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSignerHandle {
    pub handle: String,
    pub address: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTransactionReceiptSummary {
    pub transaction_hash: String,
    pub block_hash: Option<String>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub success: bool,
    pub gas_used: u64,
    pub effective_gas_price: String,
    pub from: String,
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSubmittedTransactionExecution {
    pub prepared: FfiPreparedTransactionExecution,
    pub receipt: FfiTransactionReceiptSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRootRead {
    pub kind: String,
    pub contract_address: String,
    pub pool_address: String,
    pub call_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiArtifactVerification {
    pub version: String,
    pub circuit: String,
    pub kind: String,
    pub filename: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiArtifactStatus {
    pub version: String,
    pub circuit: String,
    pub kind: String,
    pub filename: String,
    pub path: String,
    pub exists: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiResolvedArtifact {
    pub circuit: String,
    pub kind: String,
    pub filename: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiResolvedArtifactBundle {
    pub version: String,
    pub circuit: String,
    pub artifacts: Vec<FfiResolvedArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiArtifactBytes {
    pub kind: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWithdrawalCircuitSessionHandle {
    pub handle: String,
    pub circuit: String,
    pub artifact_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMerkleProof {
    pub root: String,
    pub leaf: String,
    pub index: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCircuitMerkleWitness {
    pub root: String,
    pub leaf: String,
    pub index: u64,
    pub siblings: Vec<String>,
    pub depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWithdrawalWitnessRequest {
    pub commitment: FfiCommitment,
    pub withdrawal: FfiWithdrawal,
    pub scope: String,
    pub withdrawal_amount: String,
    pub state_witness: FfiCircuitMerkleWitness,
    pub asp_witness: FfiCircuitMerkleWitness,
    pub new_nullifier: String,
    pub new_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWithdrawalCircuitInput {
    pub withdrawn_value: String,
    pub state_root: String,
    pub state_tree_depth: u64,
    pub asp_root: String,
    pub asp_tree_depth: u64,
    pub context: String,
    pub label: String,
    pub existing_value: String,
    pub existing_nullifier: String,
    pub existing_secret: String,
    pub new_nullifier: String,
    pub new_secret: String,
    pub state_siblings: Vec<String>,
    pub state_index: u64,
    pub asp_siblings: Vec<String>,
    pub asp_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPoolEvent {
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub pool_address: String,
    pub commitment_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRecoveryPolicy {
    pub compatibility_mode: String,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRecoveryCheckpoint {
    pub latest_block: u64,
    pub commitments_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAsyncJobHandle {
    pub job_id: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAsyncJobStatus {
    pub job_id: String,
    pub kind: String,
    pub state: String,
    pub stage: Option<String>,
    pub error: Option<String>,
    pub cancel_requested: bool,
}

fn sdk() -> PrivacyPoolsSdk {
    PrivacyPoolsSdk::default()
}

#[derive(Debug, Clone)]
enum RegisteredSigner {
    LocalMnemonic(LocalMnemonicSigner),
    External(ExternalSigner),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackgroundJobKind {
    ProveWithdrawal,
    PrepareWithdrawalExecution,
    PrepareRelayExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackgroundJobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
enum BackgroundJobResult {
    Proving(Box<FfiProvingResult>),
    PreparedExecution(Box<FfiPreparedTransactionExecution>),
}

#[derive(Debug)]
struct BackgroundJobEntry {
    kind: BackgroundJobKind,
    state: BackgroundJobState,
    stage: Option<String>,
    error: Option<String>,
    cancel_requested: bool,
    result: Option<BackgroundJobResult>,
}

#[derive(Debug, Clone)]
struct PrepareWithdrawalJobConfig {
    chain_id: u64,
    pool_address: Address,
    rpc_url: String,
    policy: ExecutionPolicy,
}

#[derive(Debug, Clone)]
struct PrepareRelayJobConfig {
    chain_id: u64,
    entrypoint_address: Address,
    pool_address: Address,
    rpc_url: String,
    policy: ExecutionPolicy,
}

impl RegisteredSigner {
    fn address(&self) -> Address {
        match self {
            Self::LocalMnemonic(signer) => signer.address(),
            Self::External(signer) => signer.address(),
        }
    }

    fn kind(&self) -> SignerKind {
        match self {
            Self::LocalMnemonic(signer) => signer.kind(),
            Self::External(signer) => signer.kind(),
        }
    }

    fn sign_transaction_request(
        &self,
        handle: &str,
        request: &FinalizedTransactionRequest,
    ) -> Result<alloy_primitives::Bytes, FfiError> {
        match self {
            Self::LocalMnemonic(signer) => signer
                .sign_transaction_request(request)
                .map_err(|error| FfiError::OperationFailed(error.to_string())),
            Self::External(_) => Err(FfiError::SignerRequiresExternalSigning(handle.to_owned())),
        }
    }
}

static SIGNER_REGISTRY: LazyLock<RwLock<HashMap<String, RegisteredSigner>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static JOB_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static JOB_REGISTRY: LazyLock<RwLock<HashMap<String, Arc<Mutex<BackgroundJobEntry>>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static WITHDRAWAL_SESSION_REGISTRY: LazyLock<
    RwLock<HashMap<String, privacy_pools_sdk::WithdrawalCircuitSession>>,
> = LazyLock::new(|| RwLock::new(HashMap::new()));

fn parse_manifest(manifest_json: &str) -> Result<ArtifactManifest, FfiError> {
    serde_json::from_str(manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))
}

fn parse_address(value: &str) -> Result<Address, FfiError> {
    Address::from_str(value).map_err(|_| FfiError::InvalidAddress(value.to_owned()))
}

fn parse_field(value: &str) -> Result<U256, FfiError> {
    U256::from_str(value).map_err(|_| FfiError::InvalidField(value.to_owned()))
}

fn parse_hash(value: &str) -> Result<B256, FfiError> {
    B256::from_str(value).map_err(|_| FfiError::InvalidHash(value.to_owned()))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind, FfiError> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => Err(FfiError::InvalidArtifactKind(value.to_owned())),
    }
}

fn parse_compatibility_mode(value: &str) -> Result<CompatibilityMode, FfiError> {
    match value {
        "strict" => Ok(CompatibilityMode::Strict),
        "legacy" => Ok(CompatibilityMode::Legacy),
        _ => Err(FfiError::InvalidCompatibilityMode(value.to_owned())),
    }
}

fn parse_backend_profile(value: &str) -> Result<BackendProfile, FfiError> {
    match value {
        "stable" => Ok(BackendProfile::Stable),
        "fast" => Ok(BackendProfile::Fast),
        _ => Err(FfiError::OperationFailed(format!(
            "invalid backend profile: {value}"
        ))),
    }
}

fn to_master_keys(master_nullifier: &str, master_secret: &str) -> Result<MasterKeys, FfiError> {
    Ok(MasterKeys {
        master_nullifier: parse_field(master_nullifier)?,
        master_secret: parse_field(master_secret)?,
    })
}

fn validate_pair(values: Vec<String>, label: &str) -> Result<[String; 2], FfiError> {
    values.try_into().map_err(|values: Vec<String>| {
        FfiError::InvalidProofShape(format!(
            "{label} must have exactly 2 elements, got {}",
            values.len()
        ))
    })
}

fn validate_pair_rows(values: Vec<Vec<String>>, label: &str) -> Result<[[String; 2]; 2], FfiError> {
    let rows: Vec<[String; 2]> = values
        .into_iter()
        .map(|row| validate_pair(row, label))
        .collect::<Result<Vec<_>, _>>()?;

    rows.try_into().map_err(|rows: Vec<[String; 2]>| {
        FfiError::InvalidProofShape(format!(
            "{label} must have exactly 2 rows, got {}",
            rows.len()
        ))
    })
}

fn root_read_kind_label(kind: RootReadKind) -> String {
    match kind {
        RootReadKind::PoolState => "pool_state".to_owned(),
        RootReadKind::Asp => "asp".to_owned(),
    }
}

fn transaction_kind_label(kind: privacy_pools_sdk::core::TransactionKind) -> String {
    match kind {
        privacy_pools_sdk::core::TransactionKind::Withdraw => "withdraw".to_owned(),
        privacy_pools_sdk::core::TransactionKind::Relay => "relay".to_owned(),
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

fn signer_kind_label(kind: SignerKind) -> String {
    match kind {
        SignerKind::LocalDev => "local_dev".to_owned(),
        SignerKind::HostProvided => "host_provided".to_owned(),
        SignerKind::MobileSecureStorage => "mobile_secure_storage".to_owned(),
    }
}

fn background_job_kind_label(kind: BackgroundJobKind) -> String {
    match kind {
        BackgroundJobKind::ProveWithdrawal => "prove_withdrawal".to_owned(),
        BackgroundJobKind::PrepareWithdrawalExecution => "prepare_withdrawal_execution".to_owned(),
        BackgroundJobKind::PrepareRelayExecution => "prepare_relay_execution".to_owned(),
    }
}

fn background_job_state_label(state: BackgroundJobState) -> String {
    match state {
        BackgroundJobState::Queued => "queued".to_owned(),
        BackgroundJobState::Running => "running".to_owned(),
        BackgroundJobState::Completed => "completed".to_owned(),
        BackgroundJobState::Failed => "failed".to_owned(),
        BackgroundJobState::Cancelled => "cancelled".to_owned(),
    }
}

fn field_label(value: U256) -> String {
    value.to_string()
}

fn hash_label(value: B256) -> String {
    value.to_string()
}

fn build_runtime() -> Result<tokio::runtime::Runtime, FfiError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

fn block_on_sdk<F, T>(future: F) -> Result<T, FfiError>
where
    F: Future<Output = Result<T, privacy_pools_sdk::SdkError>>,
{
    let runtime = build_runtime()?;

    runtime
        .block_on(future)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

fn register_signer(handle: String, signer: RegisteredSigner) -> Result<FfiSignerHandle, FfiError> {
    let ffi = to_ffi_signer_handle(handle.clone(), &signer);
    let mut registry = SIGNER_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle, signer);
    Ok(ffi)
}

fn remove_signer(handle: &str) -> Result<bool, FfiError> {
    let mut registry = SIGNER_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(handle).is_some())
}

fn registered_signer(handle: &str) -> Result<RegisteredSigner, FfiError> {
    let registry = SIGNER_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::SignerNotFound(handle.to_owned()))
}

fn register_withdrawal_session(
    session: privacy_pools_sdk::WithdrawalCircuitSession,
) -> Result<FfiWithdrawalCircuitSessionHandle, FfiError> {
    let handle = format!(
        "withdraw-session-{}",
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let ffi = FfiWithdrawalCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    let mut registry = WITHDRAWAL_SESSION_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle, session);
    Ok(ffi)
}

fn registered_withdrawal_session(
    handle: &str,
) -> Result<privacy_pools_sdk::WithdrawalCircuitSession, FfiError> {
    let registry = WITHDRAWAL_SESSION_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::SessionNotFound(handle.to_owned()))
}

fn remove_withdrawal_session(handle: &str) -> Result<bool, FfiError> {
    let mut registry = WITHDRAWAL_SESSION_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(handle).is_some())
}

fn register_job(
    kind: BackgroundJobKind,
) -> Result<(FfiAsyncJobHandle, Arc<Mutex<BackgroundJobEntry>>), FfiError> {
    let job_id = format!("job-{}", JOB_COUNTER.fetch_add(1, Ordering::Relaxed));
    let entry = Arc::new(Mutex::new(BackgroundJobEntry {
        kind,
        state: BackgroundJobState::Queued,
        stage: None,
        error: None,
        cancel_requested: false,
        result: None,
    }));
    let handle = FfiAsyncJobHandle {
        job_id: job_id.clone(),
        kind: background_job_kind_label(kind),
    };
    let mut registry = JOB_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(job_id, Arc::clone(&entry));
    Ok((handle, entry))
}

fn lookup_job(job_id: &str) -> Result<Arc<Mutex<BackgroundJobEntry>>, FfiError> {
    let registry = JOB_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(job_id)
        .cloned()
        .ok_or_else(|| FfiError::JobNotFound(job_id.to_owned()))
}

fn set_job_stage(entry: &Arc<Mutex<BackgroundJobEntry>>, stage: impl Into<String>) {
    if let Ok(mut entry) = entry.lock() {
        entry.state = BackgroundJobState::Running;
        entry.stage = Some(stage.into());
        entry.error = None;
    }
}

fn job_cancel_requested(entry: &Arc<Mutex<BackgroundJobEntry>>) -> bool {
    entry
        .lock()
        .map(|entry| entry.cancel_requested)
        .unwrap_or(false)
}

fn ensure_job_not_cancelled(entry: &Arc<Mutex<BackgroundJobEntry>>) -> Result<(), FfiError> {
    if job_cancel_requested(entry) {
        Err(FfiError::OperationFailed("job cancelled".to_owned()))
    } else {
        Ok(())
    }
}

fn complete_job(entry: &Arc<Mutex<BackgroundJobEntry>>, result: BackgroundJobResult) {
    if let Ok(mut entry) = entry.lock() {
        if entry.cancel_requested {
            entry.state = BackgroundJobState::Cancelled;
            entry.stage = None;
            entry.result = None;
            entry.error = None;
            return;
        }

        entry.state = BackgroundJobState::Completed;
        entry.stage = None;
        entry.error = None;
        entry.result = Some(result);
    }
}

fn fail_job(entry: &Arc<Mutex<BackgroundJobEntry>>, error: impl Into<String>) {
    if let Ok(mut entry) = entry.lock() {
        if entry.cancel_requested {
            entry.state = BackgroundJobState::Cancelled;
            entry.stage = None;
            entry.error = None;
            entry.result = None;
            return;
        }

        entry.state = BackgroundJobState::Failed;
        entry.stage = None;
        entry.error = Some(error.into());
        entry.result = None;
    }
}

fn cancel_job_entry(entry: &Arc<Mutex<BackgroundJobEntry>>) -> bool {
    if let Ok(mut entry) = entry.lock() {
        if matches!(
            entry.state,
            BackgroundJobState::Completed
                | BackgroundJobState::Failed
                | BackgroundJobState::Cancelled
        ) {
            return false;
        }

        entry.cancel_requested = true;
        if matches!(entry.state, BackgroundJobState::Queued) {
            entry.state = BackgroundJobState::Cancelled;
            entry.stage = None;
            entry.error = None;
            entry.result = None;
        }
        return true;
    }

    false
}

fn remove_job_entry(job_id: &str) -> Result<bool, FfiError> {
    let mut registry = JOB_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(job_id).is_some())
}

fn poll_job(job_id: &str) -> Result<FfiAsyncJobStatus, FfiError> {
    let entry = lookup_job(job_id)?;
    let entry = entry
        .lock()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(FfiAsyncJobStatus {
        job_id: job_id.to_owned(),
        kind: background_job_kind_label(entry.kind),
        state: background_job_state_label(entry.state),
        stage: entry.stage.clone(),
        error: entry.error.clone(),
        cancel_requested: entry.cancel_requested,
    })
}

fn spawn_background_job<F>(
    kind: BackgroundJobKind,
    worker: F,
) -> Result<FfiAsyncJobHandle, FfiError>
where
    F: FnOnce(Arc<Mutex<BackgroundJobEntry>>) -> Result<BackgroundJobResult, FfiError>
        + Send
        + 'static,
{
    let (handle, entry) = register_job(kind)?;
    std::thread::spawn({
        let entry = Arc::clone(&entry);
        move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if job_cancel_requested(&entry) {
                    return Err(FfiError::OperationFailed("job cancelled".to_owned()));
                }

                worker(Arc::clone(&entry))
            }));

            match outcome {
                Ok(Ok(result)) => complete_job(&entry, result),
                Ok(Err(error)) => fail_job(&entry, error.to_string()),
                Err(_) => fail_job(&entry, "background job panicked"),
            }
        }
    });

    Ok(handle)
}

fn proving_job_result(job_id: &str) -> Result<Option<FfiProvingResult>, FfiError> {
    let entry = lookup_job(job_id)?;
    let entry = entry
        .lock()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    if entry.kind != BackgroundJobKind::ProveWithdrawal {
        return Err(FfiError::OperationFailed(format!(
            "job {job_id} is {}, not prove_withdrawal",
            background_job_kind_label(entry.kind)
        )));
    }

    Ok(match &entry.result {
        Some(BackgroundJobResult::Proving(result)) => Some((**result).clone()),
        _ => None,
    })
}

fn prepared_execution_job_result(
    job_id: &str,
    expected_kind: BackgroundJobKind,
) -> Result<Option<FfiPreparedTransactionExecution>, FfiError> {
    let entry = lookup_job(job_id)?;
    let entry = entry
        .lock()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    if entry.kind != expected_kind {
        return Err(FfiError::OperationFailed(format!(
            "job {job_id} is {}, not {}",
            background_job_kind_label(entry.kind),
            background_job_kind_label(expected_kind)
        )));
    }

    Ok(match &entry.result {
        Some(BackgroundJobResult::PreparedExecution(result)) => Some((**result).clone()),
        _ => None,
    })
}

fn finalize_for_signer_handle(
    rpc_url: &str,
    signer_handle: &str,
    prepared: FfiPreparedTransactionExecution,
) -> Result<FfiFinalizedTransactionExecution, FfiError> {
    let signer = registered_signer(signer_handle)?;
    let finalized = block_on_sdk(
        sdk().finalize_prepared_transaction(rpc_url, from_ffi_prepared_execution(prepared)?),
    )?;

    if finalized.request.from != signer.address() {
        return Err(FfiError::OperationFailed(format!(
            "finalized transaction signer mismatch for handle {signer_handle}: expected {}, got {}",
            signer.address(),
            finalized.request.from
        )));
    }

    Ok(to_ffi_finalized_execution(finalized))
}

fn to_ffi_secrets(
    (nullifier, secret): (
        privacy_pools_sdk::core::Nullifier,
        privacy_pools_sdk::core::Secret,
    ),
) -> FfiSecrets {
    FfiSecrets {
        nullifier: field_label(nullifier),
        secret: field_label(secret),
    }
}

fn to_ffi_root_read(read: privacy_pools_sdk::core::RootRead) -> FfiRootRead {
    FfiRootRead {
        kind: root_read_kind_label(read.kind),
        contract_address: read.contract_address.to_string(),
        pool_address: read.pool_address.to_string(),
        call_data: format!("0x{}", hex::encode(read.call_data)),
    }
}

fn to_ffi_commitment(commitment: privacy_pools_sdk::core::Commitment) -> FfiCommitment {
    FfiCommitment {
        hash: field_label(commitment.hash),
        nullifier_hash: field_label(commitment.nullifier_hash),
        precommitment_hash: field_label(commitment.preimage.precommitment.hash),
        value: field_label(commitment.preimage.value),
        label: field_label(commitment.preimage.label),
        nullifier: field_label(commitment.preimage.precommitment.nullifier),
        secret: field_label(commitment.preimage.precommitment.secret),
    }
}

fn from_ffi_commitment(commitment: FfiCommitment) -> Result<Commitment, FfiError> {
    Ok(Commitment {
        hash: parse_field(&commitment.hash)?,
        nullifier_hash: parse_field(&commitment.nullifier_hash)?,
        preimage: privacy_pools_sdk::core::CommitmentPreimage {
            value: parse_field(&commitment.value)?,
            label: parse_field(&commitment.label)?,
            precommitment: privacy_pools_sdk::core::Precommitment {
                hash: parse_field(&commitment.precommitment_hash)?,
                nullifier: parse_field(&commitment.nullifier)?,
                secret: parse_field(&commitment.secret)?,
            },
        },
    })
}

fn to_ffi_formatted_groth16_proof(proof: FormattedGroth16Proof) -> FfiFormattedGroth16Proof {
    FfiFormattedGroth16Proof {
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

fn to_ffi_proof_bundle(bundle: ProofBundle) -> FfiProofBundle {
    FfiProofBundle {
        proof: FfiSnarkJsProof {
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

fn to_ffi_proving_result(result: ProvingResult) -> FfiProvingResult {
    FfiProvingResult {
        backend: prover_backend_label(result.backend),
        proof: to_ffi_proof_bundle(result.proof),
    }
}

fn to_ffi_transaction_plan(plan: TransactionPlan) -> FfiTransactionPlan {
    FfiTransactionPlan {
        kind: transaction_kind_label(plan.kind),
        chain_id: plan.chain_id,
        target: plan.target.to_string(),
        calldata: format!("0x{}", hex::encode(plan.calldata)),
        value: field_label(plan.value),
        proof: to_ffi_formatted_groth16_proof(plan.proof),
    }
}

fn from_ffi_execution_policy(policy: FfiExecutionPolicy) -> Result<ExecutionPolicy, FfiError> {
    Ok(ExecutionPolicy {
        expected_chain_id: policy.expected_chain_id,
        caller: parse_address(&policy.caller)?,
        expected_pool_code_hash: policy
            .expected_pool_code_hash
            .as_deref()
            .map(parse_hash)
            .transpose()?,
        expected_entrypoint_code_hash: policy
            .expected_entrypoint_code_hash
            .as_deref()
            .map(parse_hash)
            .transpose()?,
    })
}

fn to_ffi_code_hash_check(check: CodeHashCheck) -> FfiCodeHashCheck {
    FfiCodeHashCheck {
        address: check.address.to_string(),
        expected_code_hash: check.expected_code_hash.map(hash_label),
        actual_code_hash: hash_label(check.actual_code_hash),
        matches_expected: check.matches_expected,
    }
}

fn to_ffi_root_check(check: RootCheck) -> FfiRootCheck {
    FfiRootCheck {
        kind: root_read_kind_label(check.kind),
        contract_address: check.contract_address.to_string(),
        pool_address: check.pool_address.to_string(),
        expected_root: field_label(check.expected_root),
        actual_root: field_label(check.actual_root),
        matches: check.matches,
    }
}

fn to_ffi_execution_preflight(report: ExecutionPreflightReport) -> FfiExecutionPreflightReport {
    FfiExecutionPreflightReport {
        kind: transaction_kind_label(report.kind),
        caller: report.caller.to_string(),
        target: report.target.to_string(),
        expected_chain_id: report.expected_chain_id,
        actual_chain_id: report.actual_chain_id,
        chain_id_matches: report.chain_id_matches,
        simulated: report.simulated,
        estimated_gas: report.estimated_gas,
        code_hash_checks: report
            .code_hash_checks
            .into_iter()
            .map(to_ffi_code_hash_check)
            .collect(),
        root_checks: report
            .root_checks
            .into_iter()
            .map(to_ffi_root_check)
            .collect(),
    }
}

fn to_ffi_prepared_execution(
    prepared: PreparedTransactionExecution,
) -> FfiPreparedTransactionExecution {
    FfiPreparedTransactionExecution {
        proving: to_ffi_proving_result(prepared.proving),
        transaction: to_ffi_transaction_plan(prepared.transaction),
        preflight: to_ffi_execution_preflight(prepared.preflight),
    }
}

fn to_ffi_finalized_request(
    request: FinalizedTransactionRequest,
) -> FfiFinalizedTransactionRequest {
    FfiFinalizedTransactionRequest {
        kind: transaction_kind_label(request.kind),
        chain_id: request.chain_id,
        from: request.from.to_string(),
        to: request.to.to_string(),
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        value: field_label(request.value),
        data: format!("0x{}", hex::encode(request.data)),
        gas_price: request.gas_price.map(|value| value.to_string()),
        max_fee_per_gas: request.max_fee_per_gas.map(|value| value.to_string()),
        max_priority_fee_per_gas: request
            .max_priority_fee_per_gas
            .map(|value| value.to_string()),
    }
}

fn to_ffi_finalized_execution(
    finalized: FinalizedTransactionExecution,
) -> FfiFinalizedTransactionExecution {
    FfiFinalizedTransactionExecution {
        prepared: to_ffi_prepared_execution(finalized.prepared),
        request: to_ffi_finalized_request(finalized.request),
    }
}

fn to_ffi_signer_handle(handle: String, signer: &RegisteredSigner) -> FfiSignerHandle {
    FfiSignerHandle {
        handle,
        address: signer.address().to_string(),
        kind: signer_kind_label(signer.kind()),
    }
}

fn to_ffi_receipt_summary(receipt: TransactionReceiptSummary) -> FfiTransactionReceiptSummary {
    FfiTransactionReceiptSummary {
        transaction_hash: hash_label(receipt.transaction_hash),
        block_hash: receipt.block_hash.map(hash_label),
        block_number: receipt.block_number,
        transaction_index: receipt.transaction_index,
        success: receipt.success,
        gas_used: receipt.gas_used,
        effective_gas_price: receipt.effective_gas_price,
        from: receipt.from.to_string(),
        to: receipt.to.map(|address| address.to_string()),
    }
}

fn to_ffi_submitted_execution(
    submitted: SubmittedTransactionExecution,
) -> FfiSubmittedTransactionExecution {
    FfiSubmittedTransactionExecution {
        prepared: to_ffi_prepared_execution(submitted.prepared),
        receipt: to_ffi_receipt_summary(submitted.receipt),
    }
}

fn from_ffi_withdrawal(withdrawal: FfiWithdrawal) -> Result<Withdrawal, FfiError> {
    Ok(Withdrawal {
        processooor: parse_address(&withdrawal.processooor)?,
        data: withdrawal.data.into(),
    })
}

fn from_ffi_proof_bundle(bundle: FfiProofBundle) -> Result<ProofBundle, FfiError> {
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

fn from_ffi_formatted_groth16_proof(
    proof: FfiFormattedGroth16Proof,
) -> Result<FormattedGroth16Proof, FfiError> {
    let p_a = validate_pair(proof.p_a, "p_a")?;
    let p_b = validate_pair_rows(proof.p_b, "p_b")?;
    let p_c = validate_pair(proof.p_c, "p_c")?;

    Ok(FormattedGroth16Proof {
        p_a,
        p_b,
        p_c,
        pub_signals: proof.pub_signals,
    })
}

fn from_ffi_transaction_plan(plan: FfiTransactionPlan) -> Result<TransactionPlan, FfiError> {
    let kind = match plan.kind.as_str() {
        "withdraw" => privacy_pools_sdk::core::TransactionKind::Withdraw,
        "relay" => privacy_pools_sdk::core::TransactionKind::Relay,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid transaction kind: {}",
                plan.kind
            )));
        }
    };
    let calldata = hex::decode(plan.calldata.trim_start_matches("0x"))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(TransactionPlan {
        kind,
        chain_id: plan.chain_id,
        target: parse_address(&plan.target)?,
        calldata: calldata.into(),
        value: parse_field(&plan.value)?,
        proof: from_ffi_formatted_groth16_proof(plan.proof)?,
    })
}

fn from_ffi_root_check(check: FfiRootCheck) -> Result<RootCheck, FfiError> {
    let kind = match check.kind.as_str() {
        "pool_state" => RootReadKind::PoolState,
        "asp" => RootReadKind::Asp,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid root read kind: {}",
                check.kind
            )));
        }
    };

    Ok(RootCheck {
        kind,
        contract_address: parse_address(&check.contract_address)?,
        pool_address: parse_address(&check.pool_address)?,
        expected_root: parse_field(&check.expected_root)?,
        actual_root: parse_field(&check.actual_root)?,
        matches: check.matches,
    })
}

fn from_ffi_code_hash_check(check: FfiCodeHashCheck) -> Result<CodeHashCheck, FfiError> {
    Ok(CodeHashCheck {
        address: parse_address(&check.address)?,
        expected_code_hash: check
            .expected_code_hash
            .as_deref()
            .map(parse_hash)
            .transpose()?,
        actual_code_hash: parse_hash(&check.actual_code_hash)?,
        matches_expected: check.matches_expected,
    })
}

fn from_ffi_execution_preflight(
    report: FfiExecutionPreflightReport,
) -> Result<ExecutionPreflightReport, FfiError> {
    let kind = match report.kind.as_str() {
        "withdraw" => privacy_pools_sdk::core::TransactionKind::Withdraw,
        "relay" => privacy_pools_sdk::core::TransactionKind::Relay,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid transaction kind: {}",
                report.kind
            )));
        }
    };

    Ok(ExecutionPreflightReport {
        kind,
        caller: parse_address(&report.caller)?,
        target: parse_address(&report.target)?,
        expected_chain_id: report.expected_chain_id,
        actual_chain_id: report.actual_chain_id,
        chain_id_matches: report.chain_id_matches,
        simulated: report.simulated,
        estimated_gas: report.estimated_gas,
        code_hash_checks: report
            .code_hash_checks
            .into_iter()
            .map(from_ffi_code_hash_check)
            .collect::<Result<Vec<_>, _>>()?,
        root_checks: report
            .root_checks
            .into_iter()
            .map(from_ffi_root_check)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn from_ffi_proving_result(result: FfiProvingResult) -> Result<ProvingResult, FfiError> {
    let backend = match result.backend.as_str() {
        "arkworks" => ProverBackend::Arkworks,
        "rapidsnark" => ProverBackend::Rapidsnark,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid prover backend: {}",
                result.backend
            )));
        }
    };

    Ok(ProvingResult {
        backend,
        proof: from_ffi_proof_bundle(result.proof)?,
    })
}

fn from_ffi_prepared_execution(
    prepared: FfiPreparedTransactionExecution,
) -> Result<PreparedTransactionExecution, FfiError> {
    Ok(PreparedTransactionExecution {
        proving: from_ffi_proving_result(prepared.proving)?,
        transaction: from_ffi_transaction_plan(prepared.transaction)?,
        preflight: from_ffi_execution_preflight(prepared.preflight)?,
    })
}

fn from_ffi_finalized_request(
    request: FfiFinalizedTransactionRequest,
) -> Result<FinalizedTransactionRequest, FfiError> {
    let kind = match request.kind.as_str() {
        "withdraw" => privacy_pools_sdk::core::TransactionKind::Withdraw,
        "relay" => privacy_pools_sdk::core::TransactionKind::Relay,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid transaction kind: {}",
                request.kind
            )));
        }
    };
    let data = hex::decode(request.data.trim_start_matches("0x"))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FinalizedTransactionRequest {
        kind,
        chain_id: request.chain_id,
        from: parse_address(&request.from)?,
        to: parse_address(&request.to)?,
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        value: parse_field(&request.value)?,
        data: data.into(),
        gas_price: request
            .gas_price
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        max_fee_per_gas: request
            .max_fee_per_gas
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        max_priority_fee_per_gas: request
            .max_priority_fee_per_gas
            .as_deref()
            .map(str::parse::<u128>)
            .transpose()
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn from_ffi_finalized_execution(
    finalized: FfiFinalizedTransactionExecution,
) -> Result<FinalizedTransactionExecution, FfiError> {
    Ok(FinalizedTransactionExecution {
        prepared: from_ffi_prepared_execution(finalized.prepared)?,
        request: from_ffi_finalized_request(finalized.request)?,
    })
}

fn to_ffi_merkle_proof(proof: MerkleProof) -> Result<FfiMerkleProof, FfiError> {
    Ok(FfiMerkleProof {
        root: field_label(proof.root),
        leaf: field_label(proof.leaf),
        index: u64::try_from(proof.index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        siblings: proof.siblings.into_iter().map(field_label).collect(),
    })
}

fn from_ffi_merkle_proof(proof: FfiMerkleProof) -> Result<MerkleProof, FfiError> {
    Ok(MerkleProof {
        root: parse_field(&proof.root)?,
        leaf: parse_field(&proof.leaf)?,
        index: usize::try_from(proof.index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        siblings: proof
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn to_ffi_circuit_merkle_witness(
    witness: CircuitMerkleWitness,
) -> Result<FfiCircuitMerkleWitness, FfiError> {
    Ok(FfiCircuitMerkleWitness {
        root: field_label(witness.root),
        leaf: field_label(witness.leaf),
        index: u64::try_from(witness.index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        siblings: witness.siblings.into_iter().map(field_label).collect(),
        depth: u64::try_from(witness.depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn from_ffi_circuit_merkle_witness(
    witness: FfiCircuitMerkleWitness,
) -> Result<CircuitMerkleWitness, FfiError> {
    Ok(CircuitMerkleWitness {
        root: parse_field(&witness.root)?,
        leaf: parse_field(&witness.leaf)?,
        index: usize::try_from(witness.index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        siblings: witness
            .siblings
            .iter()
            .map(|value| parse_field(value))
            .collect::<Result<Vec<_>, _>>()?,
        depth: usize::try_from(witness.depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn to_ffi_recovery_checkpoint(
    checkpoint: privacy_pools_sdk::recovery::RecoveryCheckpoint,
) -> Result<FfiRecoveryCheckpoint, FfiError> {
    Ok(FfiRecoveryCheckpoint {
        latest_block: checkpoint.latest_block,
        commitments_seen: u64::try_from(checkpoint.commitments_seen)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn to_ffi_withdrawal_circuit_input(
    input: WithdrawalCircuitInput,
) -> Result<FfiWithdrawalCircuitInput, FfiError> {
    Ok(FfiWithdrawalCircuitInput {
        withdrawn_value: field_label(input.withdrawn_value),
        state_root: field_label(input.state_root),
        state_tree_depth: u64::try_from(input.state_tree_depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        asp_root: field_label(input.asp_root),
        asp_tree_depth: u64::try_from(input.asp_tree_depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        context: field_label(input.context),
        label: field_label(input.label),
        existing_value: field_label(input.existing_value),
        existing_nullifier: field_label(input.existing_nullifier),
        existing_secret: field_label(input.existing_secret),
        new_nullifier: field_label(input.new_nullifier),
        new_secret: field_label(input.new_secret),
        state_siblings: input.state_siblings.into_iter().map(field_label).collect(),
        state_index: u64::try_from(input.state_index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        asp_siblings: input.asp_siblings.into_iter().map(field_label).collect(),
        asp_index: u64::try_from(input.asp_index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn to_ffi_artifact_status(version: &str, status: ArtifactStatus) -> FfiArtifactStatus {
    FfiArtifactStatus {
        version: version.to_owned(),
        circuit: status.descriptor.circuit.clone(),
        kind: artifact_kind_label(status.descriptor.kind),
        filename: status.descriptor.filename.clone(),
        path: status.path.to_string_lossy().into_owned(),
        exists: status.exists,
        verified: status.verified,
    }
}

fn to_ffi_resolved_artifact_bundle(bundle: ResolvedArtifactBundle) -> FfiResolvedArtifactBundle {
    FfiResolvedArtifactBundle {
        version: bundle.version,
        circuit: bundle.circuit,
        artifacts: bundle
            .artifacts
            .into_iter()
            .map(|artifact| FfiResolvedArtifact {
                circuit: artifact.descriptor.circuit,
                kind: artifact_kind_label(artifact.descriptor.kind),
                filename: artifact.descriptor.filename,
                path: artifact.path.to_string_lossy().into_owned(),
            })
            .collect(),
    }
}

fn from_ffi_recovery_policy(policy: FfiRecoveryPolicy) -> Result<RecoveryPolicy, FfiError> {
    Ok(RecoveryPolicy {
        compatibility_mode: parse_compatibility_mode(&policy.compatibility_mode)?,
        fail_closed: policy.fail_closed,
    })
}

fn from_ffi_withdrawal_witness_request(
    request: FfiWithdrawalWitnessRequest,
) -> Result<WithdrawalWitnessRequest, FfiError> {
    Ok(WithdrawalWitnessRequest {
        commitment: from_ffi_commitment(request.commitment)?,
        withdrawal: from_ffi_withdrawal(request.withdrawal)?,
        scope: parse_field(&request.scope)?,
        withdrawal_amount: parse_field(&request.withdrawal_amount)?,
        state_witness: from_ffi_circuit_merkle_witness(request.state_witness)?,
        asp_witness: from_ffi_circuit_merkle_witness(request.asp_witness)?,
        new_nullifier: parse_field(&request.new_nullifier)?,
        new_secret: parse_field(&request.new_secret)?,
    })
}

fn from_ffi_pool_events(events: Vec<FfiPoolEvent>) -> Result<Vec<PoolEvent>, FfiError> {
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

fn from_ffi_artifact_bytes(
    artifacts: Vec<FfiArtifactBytes>,
) -> Result<Vec<privacy_pools_sdk::artifacts::ArtifactBytes>, FfiError> {
    artifacts
        .into_iter()
        .map(|artifact| {
            Ok(privacy_pools_sdk::artifacts::ArtifactBytes {
                kind: parse_artifact_kind(&artifact.kind)?,
                bytes: artifact.bytes,
            })
        })
        .collect()
}

fn prove_withdrawal_background(
    entry: Arc<Mutex<BackgroundJobEntry>>,
    profile: BackendProfile,
    manifest: ArtifactManifest,
    artifacts_root: PathBuf,
    request: WithdrawalWitnessRequest,
) -> Result<BackgroundJobResult, FfiError> {
    set_job_stage(&entry, "preloading_artifacts");
    ensure_job_not_cancelled(&entry)?;
    let session = sdk()
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "proving");
    ensure_job_not_cancelled(&entry)?;
    let result = sdk()
        .prove_withdrawal_with_session(profile, &session, &request)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    ensure_job_not_cancelled(&entry)?;
    Ok(BackgroundJobResult::Proving(Box::new(
        to_ffi_proving_result(result),
    )))
}

fn prepare_withdrawal_execution_background(
    entry: Arc<Mutex<BackgroundJobEntry>>,
    profile: BackendProfile,
    manifest: ArtifactManifest,
    artifacts_root: PathBuf,
    request: WithdrawalWitnessRequest,
    config: PrepareWithdrawalJobConfig,
) -> Result<BackgroundJobResult, FfiError> {
    set_job_stage(&entry, "preloading_artifacts");
    ensure_job_not_cancelled(&entry)?;
    let session = sdk()
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "proving");
    ensure_job_not_cancelled(&entry)?;
    let proving = sdk()
        .prove_withdrawal_with_session(profile, &session, &request)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "validating");
    ensure_job_not_cancelled(&entry)?;
    sdk()
        .validate_withdrawal_proof_against_request(&request, &proving.proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "verifying");
    ensure_job_not_cancelled(&entry)?;
    if !sdk()
        .verify_withdrawal_proof_with_session(profile, &session, &proving.proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?
    {
        return Err(FfiError::OperationFailed(
            privacy_pools_sdk::SdkError::ProofRejected.to_string(),
        ));
    }

    set_job_stage(&entry, "planning");
    ensure_job_not_cancelled(&entry)?;
    let transaction = sdk()
        .plan_withdrawal_transaction(
            config.chain_id,
            config.pool_address,
            &request.withdrawal,
            &proving.proof,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "preflight");
    ensure_job_not_cancelled(&entry)?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&config.rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let runtime = build_runtime()?;
    let preflight = runtime
        .block_on(privacy_pools_sdk::chain::preflight_withdrawal(
            &client,
            &transaction,
            config.pool_address,
            request.state_witness.root,
            request.asp_witness.root,
            &config.policy,
        ))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    ensure_job_not_cancelled(&entry)?;
    Ok(BackgroundJobResult::PreparedExecution(Box::new(
        to_ffi_prepared_execution(PreparedTransactionExecution {
            proving,
            transaction,
            preflight,
        }),
    )))
}

fn prepare_relay_execution_background(
    entry: Arc<Mutex<BackgroundJobEntry>>,
    profile: BackendProfile,
    manifest: ArtifactManifest,
    artifacts_root: PathBuf,
    request: WithdrawalWitnessRequest,
    config: PrepareRelayJobConfig,
) -> Result<BackgroundJobResult, FfiError> {
    set_job_stage(&entry, "preloading_artifacts");
    ensure_job_not_cancelled(&entry)?;
    let session = sdk()
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "proving");
    ensure_job_not_cancelled(&entry)?;
    let proving = sdk()
        .prove_withdrawal_with_session(profile, &session, &request)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "validating");
    ensure_job_not_cancelled(&entry)?;
    sdk()
        .validate_withdrawal_proof_against_request(&request, &proving.proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "verifying");
    ensure_job_not_cancelled(&entry)?;
    if !sdk()
        .verify_withdrawal_proof_with_session(profile, &session, &proving.proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?
    {
        return Err(FfiError::OperationFailed(
            privacy_pools_sdk::SdkError::ProofRejected.to_string(),
        ));
    }

    set_job_stage(&entry, "planning");
    ensure_job_not_cancelled(&entry)?;
    let transaction = sdk()
        .plan_relay_transaction(
            config.chain_id,
            config.entrypoint_address,
            &request.withdrawal,
            &proving.proof,
            request.scope,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    set_job_stage(&entry, "preflight");
    ensure_job_not_cancelled(&entry)?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&config.rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let runtime = build_runtime()?;
    let preflight = runtime
        .block_on(privacy_pools_sdk::chain::preflight_relay(
            &client,
            &transaction,
            config.entrypoint_address,
            config.pool_address,
            request.state_witness.root,
            request.asp_witness.root,
            &config.policy,
        ))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    ensure_job_not_cancelled(&entry)?;
    Ok(BackgroundJobResult::PreparedExecution(Box::new(
        to_ffi_prepared_execution(PreparedTransactionExecution {
            proving,
            transaction,
            preflight,
        }),
    )))
}

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn get_version() -> String {
    PrivacyPoolsSdk::version().to_owned()
}

#[uniffi::export]
pub fn get_stable_backend_name() -> Result<String, FfiError> {
    sdk()
        .stable_backend_name()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn fast_backend_supported_on_target() -> bool {
    sdk().fast_backend_supported_on_target()
}

#[uniffi::export]
pub fn derive_master_keys(mnemonic: String) -> Result<FfiMasterKeys, FfiError> {
    let keys = sdk()
        .generate_master_keys(&mnemonic)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FfiMasterKeys {
        master_nullifier: keys.master_nullifier.to_string(),
        master_secret: keys.master_secret.to_string(),
    })
}

#[uniffi::export]
pub fn derive_deposit_secrets(
    master_nullifier: String,
    master_secret: String,
    scope: String,
    index: String,
) -> Result<FfiSecrets, FfiError> {
    let keys = to_master_keys(&master_nullifier, &master_secret)?;
    let secrets = sdk()
        .generate_deposit_secrets(&keys, parse_field(&scope)?, parse_field(&index)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_secrets(secrets))
}

#[uniffi::export]
pub fn calculate_withdrawal_context(
    withdrawal: FfiWithdrawal,
    scope: String,
) -> Result<String, FfiError> {
    sdk()
        .calculate_context(&from_ffi_withdrawal(withdrawal)?, parse_field(&scope)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn derive_withdrawal_secrets(
    master_nullifier: String,
    master_secret: String,
    label: String,
    index: String,
) -> Result<FfiSecrets, FfiError> {
    let keys = to_master_keys(&master_nullifier, &master_secret)?;
    let secrets = sdk()
        .generate_withdrawal_secrets(&keys, parse_field(&label)?, parse_field(&index)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_secrets(secrets))
}

#[uniffi::export]
pub fn get_commitment(
    value: String,
    label: String,
    nullifier: String,
    secret: String,
) -> Result<FfiCommitment, FfiError> {
    let commitment = sdk()
        .get_commitment(
            parse_field(&value)?,
            parse_field(&label)?,
            parse_field(&nullifier)?,
            parse_field(&secret)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_commitment(commitment))
}

#[uniffi::export]
pub fn generate_merkle_proof(
    leaves: Vec<String>,
    leaf: String,
) -> Result<FfiMerkleProof, FfiError> {
    let leaves = leaves
        .iter()
        .map(|value| parse_field(value))
        .collect::<Result<Vec<_>, _>>()?;
    let proof = sdk()
        .generate_merkle_proof(&leaves, parse_field(&leaf)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    to_ffi_merkle_proof(proof)
}

#[uniffi::export]
pub fn build_circuit_merkle_witness(
    proof: FfiMerkleProof,
    depth: u64,
) -> Result<FfiCircuitMerkleWitness, FfiError> {
    let proof = from_ffi_merkle_proof(proof)?;
    let witness = sdk()
        .to_circuit_witness(
            &proof,
            usize::try_from(depth).map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    to_ffi_circuit_merkle_witness(witness)
}

#[uniffi::export]
pub fn build_withdrawal_circuit_input(
    request: FfiWithdrawalWitnessRequest,
) -> Result<FfiWithdrawalCircuitInput, FfiError> {
    let input = sdk()
        .build_withdrawal_circuit_input(&from_ffi_withdrawal_witness_request(request)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    to_ffi_withdrawal_circuit_input(input)
}

#[uniffi::export]
pub fn prepare_withdrawal_circuit_session(
    manifest_json: String,
    artifacts_root: String,
) -> Result<FfiWithdrawalCircuitSessionHandle, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let session = sdk()
        .prepare_withdrawal_circuit_session(&manifest, PathBuf::from(artifacts_root))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_withdrawal_session(session)
}

#[uniffi::export]
pub fn prepare_withdrawal_circuit_session_from_bytes(
    manifest_json: String,
    artifacts: Vec<FfiArtifactBytes>,
) -> Result<FfiWithdrawalCircuitSessionHandle, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let bundle = sdk()
        .verify_artifact_bundle_bytes(&manifest, "withdraw", from_ffi_artifact_bytes(artifacts)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let session = sdk()
        .prepare_withdrawal_circuit_session_from_bundle(bundle)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_withdrawal_session(session)
}

#[uniffi::export]
pub fn remove_withdrawal_circuit_session(handle: String) -> Result<bool, FfiError> {
    remove_withdrawal_session(&handle)
}

#[uniffi::export]
pub fn start_prove_withdrawal_job_with_session(
    backend_profile: String,
    session_handle: String,
    request: FfiWithdrawalWitnessRequest,
) -> Result<FfiAsyncJobHandle, FfiError> {
    let profile = parse_backend_profile(&backend_profile)?;
    let session = registered_withdrawal_session(&session_handle)?;
    let request = from_ffi_withdrawal_witness_request(request)?;

    spawn_background_job(BackgroundJobKind::ProveWithdrawal, move |entry| {
        set_job_stage(&entry, "proving");
        ensure_job_not_cancelled(&entry)?;
        let result = sdk()
            .prove_withdrawal_with_session(profile, &session, &request)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
        ensure_job_not_cancelled(&entry)?;
        Ok(BackgroundJobResult::Proving(Box::new(
            to_ffi_proving_result(result),
        )))
    })
}

#[uniffi::export]
pub fn start_prove_withdrawal_job(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
) -> Result<FfiAsyncJobHandle, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let profile = parse_backend_profile(&backend_profile)?;
    let request = from_ffi_withdrawal_witness_request(request)?;
    let artifacts_root = PathBuf::from(artifacts_root);

    spawn_background_job(BackgroundJobKind::ProveWithdrawal, move |entry| {
        prove_withdrawal_background(entry, profile, manifest, artifacts_root, request)
    })
}

#[uniffi::export]
pub fn prove_withdrawal(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
) -> Result<FfiProvingResult, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let result = sdk()
        .prove_withdrawal(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_withdrawal_witness_request(request)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_proving_result(result))
}

#[uniffi::export]
pub fn prove_withdrawal_with_session(
    backend_profile: String,
    session_handle: String,
    request: FfiWithdrawalWitnessRequest,
) -> Result<FfiProvingResult, FfiError> {
    let session = registered_withdrawal_session(&session_handle)?;
    let result = sdk()
        .prove_withdrawal_with_session(
            parse_backend_profile(&backend_profile)?,
            &session,
            &from_ffi_withdrawal_witness_request(request)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_proving_result(result))
}

#[uniffi::export]
pub fn poll_job_status(job_id: String) -> Result<FfiAsyncJobStatus, FfiError> {
    poll_job(&job_id)
}

#[uniffi::export]
pub fn get_prove_withdrawal_job_result(
    job_id: String,
) -> Result<Option<FfiProvingResult>, FfiError> {
    proving_job_result(&job_id)
}

#[uniffi::export]
pub fn cancel_job(job_id: String) -> Result<bool, FfiError> {
    let entry = lookup_job(&job_id)?;
    Ok(cancel_job_entry(&entry))
}

#[uniffi::export]
pub fn remove_job(job_id: String) -> Result<bool, FfiError> {
    remove_job_entry(&job_id)
}

#[uniffi::export]
pub fn verify_withdrawal_proof(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    proof: FfiProofBundle,
) -> Result<bool, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;

    sdk()
        .verify_withdrawal_proof(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn verify_withdrawal_proof_with_session(
    backend_profile: String,
    session_handle: String,
    proof: FfiProofBundle,
) -> Result<bool, FfiError> {
    let session = registered_withdrawal_session(&session_handle)?;

    sdk()
        .verify_withdrawal_proof_with_session(
            parse_backend_profile(&backend_profile)?,
            &session,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn start_prepare_withdrawal_execution_job(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
    chain_id: u64,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
) -> Result<FfiAsyncJobHandle, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let profile = parse_backend_profile(&backend_profile)?;
    let request = from_ffi_withdrawal_witness_request(request)?;
    let pool_address = parse_address(&pool_address)?;
    let policy = from_ffi_execution_policy(policy)?;
    let artifacts_root = PathBuf::from(artifacts_root);
    let config = PrepareWithdrawalJobConfig {
        chain_id,
        pool_address,
        rpc_url,
        policy,
    };

    spawn_background_job(
        BackgroundJobKind::PrepareWithdrawalExecution,
        move |entry| {
            prepare_withdrawal_execution_background(
                entry,
                profile,
                manifest,
                artifacts_root,
                request,
                config,
            )
        },
    )
}

#[uniffi::export]
pub fn get_prepare_withdrawal_execution_job_result(
    job_id: String,
) -> Result<Option<FfiPreparedTransactionExecution>, FfiError> {
    prepared_execution_job_result(&job_id, BackgroundJobKind::PrepareWithdrawalExecution)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn prepare_withdrawal_execution(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
    chain_id: u64,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
) -> Result<FfiPreparedTransactionExecution, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_prepared_execution(block_on_sdk(
        sdk().prepare_withdrawal_execution_with_client(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_withdrawal_witness_request(request)?,
            &privacy_pools_sdk::core::WithdrawalExecutionConfig {
                chain_id,
                pool_address: parse_address(&pool_address)?,
                policy: from_ffi_execution_policy(policy)?,
            },
            &client,
        ),
    )?))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn start_prepare_relay_execution_job(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
    chain_id: u64,
    entrypoint_address: String,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
) -> Result<FfiAsyncJobHandle, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let profile = parse_backend_profile(&backend_profile)?;
    let request = from_ffi_withdrawal_witness_request(request)?;
    let entrypoint_address = parse_address(&entrypoint_address)?;
    let pool_address = parse_address(&pool_address)?;
    let policy = from_ffi_execution_policy(policy)?;
    let artifacts_root = PathBuf::from(artifacts_root);
    let config = PrepareRelayJobConfig {
        chain_id,
        entrypoint_address,
        pool_address,
        rpc_url,
        policy,
    };

    spawn_background_job(BackgroundJobKind::PrepareRelayExecution, move |entry| {
        prepare_relay_execution_background(
            entry,
            profile,
            manifest,
            artifacts_root,
            request,
            config,
        )
    })
}

#[uniffi::export]
pub fn get_prepare_relay_execution_job_result(
    job_id: String,
) -> Result<Option<FfiPreparedTransactionExecution>, FfiError> {
    prepared_execution_job_result(&job_id, BackgroundJobKind::PrepareRelayExecution)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn prepare_relay_execution(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiWithdrawalWitnessRequest,
    chain_id: u64,
    entrypoint_address: String,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
) -> Result<FfiPreparedTransactionExecution, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_prepared_execution(block_on_sdk(
        sdk().prepare_relay_execution_with_client(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_withdrawal_witness_request(request)?,
            &privacy_pools_sdk::core::RelayExecutionConfig {
                chain_id,
                entrypoint_address: parse_address(&entrypoint_address)?,
                pool_address: parse_address(&pool_address)?,
                policy: from_ffi_execution_policy(policy)?,
            },
            &client,
        ),
    )?))
}

#[uniffi::export]
pub fn register_local_mnemonic_signer(
    handle: String,
    mnemonic: String,
    index: u32,
) -> Result<FfiSignerHandle, FfiError> {
    let signer = LocalMnemonicSigner::from_phrase_nth(&mnemonic, index)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    register_signer(handle, RegisteredSigner::LocalMnemonic(signer))
}

#[uniffi::export]
pub fn register_host_provided_signer(
    handle: String,
    address: String,
) -> Result<FfiSignerHandle, FfiError> {
    let signer = ExternalSigner::host_provided(parse_address(&address)?);
    register_signer(handle, RegisteredSigner::External(signer))
}

#[uniffi::export]
pub fn register_mobile_secure_storage_signer(
    handle: String,
    address: String,
) -> Result<FfiSignerHandle, FfiError> {
    let signer = ExternalSigner::mobile_secure_storage(parse_address(&address)?);
    register_signer(handle, RegisteredSigner::External(signer))
}

#[uniffi::export]
pub fn unregister_signer(handle: String) -> Result<bool, FfiError> {
    remove_signer(&handle)
}

#[uniffi::export]
pub fn finalize_prepared_transaction(
    rpc_url: String,
    prepared: FfiPreparedTransactionExecution,
) -> Result<FfiFinalizedTransactionExecution, FfiError> {
    Ok(to_ffi_finalized_execution(block_on_sdk(
        sdk().finalize_prepared_transaction(&rpc_url, from_ffi_prepared_execution(prepared)?),
    )?))
}

#[uniffi::export]
pub fn finalize_prepared_transaction_for_signer(
    rpc_url: String,
    signer_handle: String,
    prepared: FfiPreparedTransactionExecution,
) -> Result<FfiFinalizedTransactionExecution, FfiError> {
    finalize_for_signer_handle(&rpc_url, &signer_handle, prepared)
}

#[uniffi::export]
pub fn submit_prepared_transaction(
    rpc_url: String,
    signer_handle: String,
    prepared: FfiPreparedTransactionExecution,
) -> Result<FfiSubmittedTransactionExecution, FfiError> {
    let signer = registered_signer(&signer_handle)?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let finalized = block_on_sdk(sdk().finalize_prepared_transaction_with_client(
        from_ffi_prepared_execution(prepared)?,
        &client,
    ))?;

    if finalized.request.from != signer.address() {
        return Err(FfiError::OperationFailed(format!(
            "finalized transaction signer mismatch for handle {signer_handle}: expected {}, got {}",
            signer.address(),
            finalized.request.from
        )));
    }

    let signed_transaction = signer.sign_transaction_request(&signer_handle, &finalized.request)?;

    Ok(to_ffi_submitted_execution(block_on_sdk(
        sdk().submit_finalized_transaction_with_client(finalized, &signed_transaction, &client),
    )?))
}

#[uniffi::export]
pub fn submit_signed_transaction(
    rpc_url: String,
    finalized: FfiFinalizedTransactionExecution,
    signed_transaction: String,
) -> Result<FfiSubmittedTransactionExecution, FfiError> {
    let encoded_tx = hex::decode(signed_transaction.trim_start_matches("0x"))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_submitted_execution(block_on_sdk(
        sdk().submit_finalized_transaction(
            &rpc_url,
            from_ffi_finalized_execution(finalized)?,
            &encoded_tx,
        ),
    )?))
}

#[uniffi::export]
pub fn plan_withdrawal_transaction(
    chain_id: u64,
    pool_address: String,
    withdrawal: FfiWithdrawal,
    proof: FfiProofBundle,
) -> Result<FfiTransactionPlan, FfiError> {
    let plan = sdk()
        .plan_withdrawal_transaction(
            chain_id,
            parse_address(&pool_address)?,
            &from_ffi_withdrawal(withdrawal)?,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn plan_relay_transaction(
    chain_id: u64,
    entrypoint_address: String,
    withdrawal: FfiWithdrawal,
    proof: FfiProofBundle,
    scope: String,
) -> Result<FfiTransactionPlan, FfiError> {
    let plan = sdk()
        .plan_relay_transaction(
            chain_id,
            parse_address(&entrypoint_address)?,
            &from_ffi_withdrawal(withdrawal)?,
            &from_ffi_proof_bundle(proof)?,
            parse_field(&scope)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn is_current_state_root(
    expected_root: String,
    current_root: String,
) -> Result<bool, FfiError> {
    Ok(sdk().is_current_state_root(parse_field(&expected_root)?, parse_field(&current_root)?))
}

#[uniffi::export]
pub fn plan_pool_state_root_read(pool_address: String) -> Result<FfiRootRead, FfiError> {
    let pool_address = parse_address(&pool_address)?;
    Ok(to_ffi_root_read(
        sdk().plan_pool_state_root_read(pool_address),
    ))
}

#[uniffi::export]
pub fn plan_asp_root_read(
    entrypoint_address: String,
    pool_address: String,
) -> Result<FfiRootRead, FfiError> {
    let entrypoint_address = parse_address(&entrypoint_address)?;
    let pool_address = parse_address(&pool_address)?;

    Ok(to_ffi_root_read(
        sdk().plan_asp_root_read(entrypoint_address, pool_address),
    ))
}

#[uniffi::export]
pub fn format_groth16_proof_bundle(
    proof: FfiProofBundle,
) -> Result<FfiFormattedGroth16Proof, FfiError> {
    let formatted = sdk()
        .format_groth16_proof(&from_ffi_proof_bundle(proof)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_formatted_groth16_proof(formatted))
}

#[uniffi::export]
pub fn verify_artifact_bytes(
    manifest_json: String,
    circuit: String,
    kind: String,
    bytes: Vec<u8>,
) -> Result<FfiArtifactVerification, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let kind = parse_artifact_kind(&kind)?;
    let version = manifest.version.clone();
    let descriptor = manifest
        .descriptor(&circuit, kind)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    privacy_pools_sdk::artifacts::verify_artifact_bytes(descriptor, &bytes)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FfiArtifactVerification {
        version,
        circuit,
        kind: artifact_kind_label(kind),
        filename: descriptor.filename.clone(),
    })
}

#[uniffi::export]
pub fn get_artifact_statuses(
    manifest_json: String,
    artifacts_root: String,
    circuit: String,
) -> Result<Vec<FfiArtifactStatus>, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let version = manifest.version.clone();
    let statuses = sdk().artifact_statuses(&manifest, PathBuf::from(artifacts_root), &circuit);

    Ok(statuses
        .into_iter()
        .map(|status| to_ffi_artifact_status(&version, status))
        .collect())
}

#[uniffi::export]
pub fn resolve_verified_artifact_bundle(
    manifest_json: String,
    artifacts_root: String,
    circuit: String,
) -> Result<FfiResolvedArtifactBundle, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let bundle = sdk()
        .resolve_verified_artifact_bundle(&manifest, PathBuf::from(artifacts_root), &circuit)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_resolved_artifact_bundle(bundle))
}

#[uniffi::export]
pub fn checkpoint_recovery(
    events: Vec<FfiPoolEvent>,
    policy: FfiRecoveryPolicy,
) -> Result<FfiRecoveryCheckpoint, FfiError> {
    let checkpoint = sdk()
        .checkpoint_recovery(
            &from_ffi_pool_events(events)?,
            from_ffi_recovery_policy(policy)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    to_ffi_recovery_checkpoint(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;
    use serde_json::Value;
    use std::time::Duration;

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .expect("valid ffi fixture")
    }

    fn valid_relay_data_bytes() -> Vec<u8> {
        bytes!(
            "0000000000000000000000002222222222222222222222222222222222222222\
             0000000000000000000000003333333333333333333333333333333333333333\
             0000000000000000000000000000000000000000000000000000000000000019"
        )
        .to_vec()
    }

    #[test]
    fn ffi_exports_match_crypto_and_merkle_vectors() {
        let fixture = vector();
        let mnemonic = fixture["mnemonic"].as_str().unwrap().to_owned();
        let keys = derive_master_keys(mnemonic).unwrap();

        let deposit = derive_deposit_secrets(
            keys.master_nullifier.clone(),
            keys.master_secret.clone(),
            fixture["scope"].as_str().unwrap().to_owned(),
            "0".to_owned(),
        )
        .unwrap();
        assert_eq!(
            deposit.nullifier,
            fixture["depositSecrets"]["nullifier"].as_str().unwrap()
        );
        assert_eq!(
            deposit.secret,
            fixture["depositSecrets"]["secret"].as_str().unwrap()
        );

        let withdrawal = derive_withdrawal_secrets(
            keys.master_nullifier.clone(),
            keys.master_secret.clone(),
            fixture["label"].as_str().unwrap().to_owned(),
            "1".to_owned(),
        )
        .unwrap();
        assert_eq!(
            withdrawal.nullifier,
            fixture["withdrawalSecrets"]["nullifier"].as_str().unwrap()
        );
        assert_eq!(
            withdrawal.secret,
            fixture["withdrawalSecrets"]["secret"].as_str().unwrap()
        );

        let commitment = get_commitment(
            "1000".to_owned(),
            fixture["label"].as_str().unwrap().to_owned(),
            deposit.nullifier.clone(),
            deposit.secret.clone(),
        )
        .unwrap();
        assert_eq!(
            commitment.hash,
            fixture["commitment"]["hash"].as_str().unwrap()
        );
        assert_eq!(
            commitment.nullifier_hash,
            fixture["commitment"]["nullifierHash"].as_str().unwrap()
        );

        let proof = generate_merkle_proof(
            vec![
                "11".to_owned(),
                "22".to_owned(),
                "33".to_owned(),
                "44".to_owned(),
                "55".to_owned(),
            ],
            "44".to_owned(),
        )
        .unwrap();
        assert_eq!(proof.root, fixture["merkleProof"]["root"].as_str().unwrap());
        assert_eq!(proof.leaf, "44");
        assert_eq!(
            proof.index,
            fixture["merkleProof"]["index"].as_u64().unwrap()
        );

        let witness = build_circuit_merkle_witness(
            proof,
            privacy_pools_sdk::tree::DEFAULT_CIRCUIT_DEPTH as u64,
        )
        .unwrap();
        assert_eq!(
            witness.depth,
            privacy_pools_sdk::tree::DEFAULT_CIRCUIT_DEPTH as u64
        );
        assert_eq!(
            witness.siblings.len(),
            privacy_pools_sdk::tree::DEFAULT_CIRCUIT_DEPTH
        );

        let context = calculate_withdrawal_context(
            FfiWithdrawal {
                processooor: "0x1111111111111111111111111111111111111111".to_owned(),
                data: vec![0x12, 0x34],
            },
            fixture["scope"].as_str().unwrap().to_owned(),
        )
        .unwrap();
        assert_eq!(context, fixture["context"].as_str().unwrap());
    }

    #[test]
    fn ffi_builds_typed_withdrawal_circuit_inputs() {
        let crypto_fixture = vector();
        let withdrawal_fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();
        let keys =
            derive_master_keys(crypto_fixture["mnemonic"].as_str().unwrap().to_owned()).unwrap();
        let deposit = derive_deposit_secrets(
            keys.master_nullifier.clone(),
            keys.master_secret.clone(),
            crypto_fixture["scope"].as_str().unwrap().to_owned(),
            "0".to_owned(),
        )
        .unwrap();
        let commitment = get_commitment(
            withdrawal_fixture["existingValue"]
                .as_str()
                .unwrap()
                .to_owned(),
            withdrawal_fixture["label"].as_str().unwrap().to_owned(),
            deposit.nullifier,
            deposit.secret,
        )
        .unwrap();

        let request = FfiWithdrawalWitnessRequest {
            commitment,
            withdrawal: FfiWithdrawal {
                processooor: "0x1111111111111111111111111111111111111111".to_owned(),
                data: vec![0x12, 0x34],
            },
            scope: crypto_fixture["scope"].as_str().unwrap().to_owned(),
            withdrawal_amount: withdrawal_fixture["withdrawalAmount"]
                .as_str()
                .unwrap()
                .to_owned(),
            state_witness: FfiCircuitMerkleWitness {
                root: withdrawal_fixture["stateWitness"]["root"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                leaf: withdrawal_fixture["stateWitness"]["leaf"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                index: withdrawal_fixture["stateWitness"]["index"]
                    .as_u64()
                    .unwrap(),
                siblings: withdrawal_fixture["stateWitness"]["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect(),
                depth: withdrawal_fixture["stateWitness"]["depth"]
                    .as_u64()
                    .unwrap(),
            },
            asp_witness: FfiCircuitMerkleWitness {
                root: withdrawal_fixture["aspWitness"]["root"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                leaf: withdrawal_fixture["aspWitness"]["leaf"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                index: withdrawal_fixture["aspWitness"]["index"].as_u64().unwrap(),
                siblings: withdrawal_fixture["aspWitness"]["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect(),
                depth: withdrawal_fixture["aspWitness"]["depth"].as_u64().unwrap(),
            },
            new_nullifier: withdrawal_fixture["newNullifier"]
                .as_str()
                .unwrap()
                .to_owned(),
            new_secret: withdrawal_fixture["newSecret"].as_str().unwrap().to_owned(),
        };

        let input = build_withdrawal_circuit_input(request.clone()).unwrap();

        assert_eq!(
            input.context,
            withdrawal_fixture["expected"]["context"].as_str().unwrap()
        );
        assert_eq!(
            input.state_siblings,
            withdrawal_fixture["expected"]["normalizedInputs"]["stateSiblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(input.state_tree_depth, 0);
        assert_eq!(input.asp_tree_depth, 0);

        let missing_manifest = serde_json::to_string(&ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![
                privacy_pools_sdk::artifacts::ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "sample-artifact.bin".to_owned(),
                    sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                        .to_owned(),
                },
                privacy_pools_sdk::artifacts::ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Zkey,
                    filename: "missing-artifact.zkey".to_owned(),
                    sha256: "00".repeat(32),
                },
            ],
        })
        .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");

        assert!(matches!(
            prove_withdrawal(
                "stable".to_owned(),
                missing_manifest,
                root.to_string_lossy().into_owned(),
                request,
            ),
            Err(FfiError::OperationFailed(_))
        ));
    }

    #[test]
    fn ffi_exports_root_reads_and_recovery_checkpoints() {
        let pool_address = "0x0987654321098765432109876543210987654321".to_owned();
        let entrypoint_address = "0x1234567890123456789012345678901234567890".to_owned();

        let state_read = plan_pool_state_root_read(pool_address.clone()).unwrap();
        assert_eq!(state_read.kind, "pool_state");
        assert_eq!(state_read.contract_address, pool_address);

        let asp_read =
            plan_asp_root_read(entrypoint_address.clone(), pool_address.clone()).unwrap();
        assert_eq!(asp_read.kind, "asp");
        assert_eq!(asp_read.contract_address, entrypoint_address);
        assert_eq!(asp_read.pool_address, pool_address);
        assert_ne!(state_read.call_data, asp_read.call_data);

        let checkpoint = checkpoint_recovery(
            vec![
                FfiPoolEvent {
                    block_number: 12,
                    transaction_index: 0,
                    log_index: 0,
                    pool_address: "0x1111111111111111111111111111111111111111".to_owned(),
                    commitment_hash: "11".to_owned(),
                },
                FfiPoolEvent {
                    block_number: 18,
                    transaction_index: 1,
                    log_index: 3,
                    pool_address: "0x1111111111111111111111111111111111111111".to_owned(),
                    commitment_hash: "22".to_owned(),
                },
            ],
            FfiRecoveryPolicy {
                compatibility_mode: "strict".to_owned(),
                fail_closed: true,
            },
        )
        .unwrap();

        assert_eq!(checkpoint.latest_block, 18);
        assert_eq!(checkpoint.commitments_seen, 2);
        assert!(is_current_state_root("12".to_owned(), "12".to_owned()).unwrap());
        assert!(!is_current_state_root("12".to_owned(), "18".to_owned()).unwrap());
    }

    #[test]
    fn ffi_rejects_unordered_recovery_streams() {
        assert!(matches!(
            checkpoint_recovery(
                vec![
                    FfiPoolEvent {
                        block_number: 18,
                        transaction_index: 1,
                        log_index: 3,
                        pool_address: "0x1111111111111111111111111111111111111111".to_owned(),
                        commitment_hash: "22".to_owned(),
                    },
                    FfiPoolEvent {
                        block_number: 12,
                        transaction_index: 0,
                        log_index: 0,
                        pool_address: "0x1111111111111111111111111111111111111111".to_owned(),
                        commitment_hash: "11".to_owned(),
                    },
                ],
                FfiRecoveryPolicy {
                    compatibility_mode: "strict".to_owned(),
                    fail_closed: true,
                },
            ),
            Err(FfiError::OperationFailed(message))
                if message.contains("canonically ordered")
        ));
    }

    #[test]
    fn ffi_plans_offline_transactions() {
        let proof = FfiProofBundle {
            proof: FfiSnarkJsProof {
                pi_a: vec!["123".to_owned(), "123".to_owned()],
                pi_b: vec![
                    vec!["69".to_owned(), "123".to_owned()],
                    vec!["12".to_owned(), "123".to_owned()],
                ],
                pi_c: vec!["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let relay_entrypoint = "0x1234567890123456789012345678901234567890".to_owned();
        let withdrawal = FfiWithdrawal {
            processooor: "0x1111111111111111111111111111111111111111".to_owned(),
            data: vec![0x12, 0x34],
        };
        let relay_withdrawal = FfiWithdrawal {
            processooor: relay_entrypoint.clone(),
            data: valid_relay_data_bytes(),
        };

        let withdraw = plan_withdrawal_transaction(
            1,
            "0x0987654321098765432109876543210987654321".to_owned(),
            withdrawal.clone(),
            proof.clone(),
        )
        .unwrap();
        let relay = plan_relay_transaction(
            1,
            relay_entrypoint,
            relay_withdrawal,
            proof,
            "123".to_owned(),
        )
        .unwrap();

        assert_eq!(withdraw.kind, "withdraw");
        assert_eq!(relay.kind, "relay");
        assert_eq!(withdraw.chain_id, 1);
        assert_eq!(relay.chain_id, 1);
        assert!(withdraw.calldata.starts_with("0x"));
        assert!(relay.calldata.starts_with("0x"));
    }

    #[test]
    fn ffi_exports_artifact_statuses() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest = serde_json::to_string(&ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![
                privacy_pools_sdk::artifacts::ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "sample-artifact.bin".to_owned(),
                    sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                        .to_owned(),
                },
                privacy_pools_sdk::artifacts::ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Zkey,
                    filename: "missing-artifact.zkey".to_owned(),
                    sha256: "00".repeat(32),
                },
            ],
        })
        .unwrap();

        let statuses = get_artifact_statuses(
            manifest,
            root.to_string_lossy().into_owned(),
            "withdraw".to_owned(),
        )
        .unwrap();

        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].kind, "wasm");
        assert!(statuses[0].exists);
        assert!(statuses[0].verified);
        assert_eq!(statuses[1].kind, "zkey");
        assert!(!statuses[1].exists);
        assert!(!statuses[1].verified);
    }

    #[test]
    fn ffi_resolves_verified_artifact_bundles() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest = serde_json::to_string(&ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![privacy_pools_sdk::artifacts::ArtifactDescriptor {
                circuit: "withdraw".to_owned(),
                kind: ArtifactKind::Wasm,
                filename: "sample-artifact.bin".to_owned(),
                sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                    .to_owned(),
            }],
        })
        .unwrap();

        let bundle = resolve_verified_artifact_bundle(
            manifest,
            root.to_string_lossy().into_owned(),
            "withdraw".to_owned(),
        )
        .unwrap();

        assert_eq!(bundle.version, "0.1.0-alpha.1");
        assert_eq!(bundle.circuit, "withdraw");
        assert_eq!(bundle.artifacts.len(), 1);
        assert_eq!(bundle.artifacts[0].kind, "wasm");
        assert!(bundle.artifacts[0].path.ends_with("sample-artifact.bin"));
    }

    #[test]
    fn ffi_exposes_withdrawal_session_entrypoints_fail_closed() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest =
            include_str!("../../../fixtures/artifacts/sample-proving-manifest.json").to_owned();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let from_paths = prepare_withdrawal_circuit_session(
            manifest.clone(),
            root.to_string_lossy().into_owned(),
        )
        .unwrap();
        assert_eq!(from_paths.circuit, "withdraw");
        assert_eq!(from_paths.artifact_version, "0.1.0-alpha.1");
        assert!(remove_withdrawal_circuit_session(from_paths.handle).unwrap());

        let from_bytes = prepare_withdrawal_circuit_session_from_bytes(
            manifest,
            vec![
                FfiArtifactBytes {
                    kind: "wasm".to_owned(),
                    bytes: bytes.clone(),
                },
                FfiArtifactBytes {
                    kind: "zkey".to_owned(),
                    bytes: bytes.clone(),
                },
                FfiArtifactBytes {
                    kind: "vkey".to_owned(),
                    bytes,
                },
            ],
        )
        .unwrap();
        assert_eq!(from_bytes.circuit, "withdraw");
        assert_eq!(from_bytes.artifact_version, "0.1.0-alpha.1");
        assert!(remove_withdrawal_circuit_session(from_bytes.handle).unwrap());
        assert!(!remove_withdrawal_circuit_session("missing".to_owned()).unwrap());
    }

    #[test]
    fn ffi_fails_closed_on_artifact_hash_mismatch() {
        let manifest = serde_json::to_string(&ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![privacy_pools_sdk::artifacts::ArtifactDescriptor {
                circuit: "withdraw".to_owned(),
                kind: ArtifactKind::Wasm,
                filename: "sample-artifact.bin".to_owned(),
                sha256: "00".repeat(32),
            }],
        })
        .unwrap();

        assert!(matches!(
            verify_artifact_bytes(
                manifest,
                "withdraw".to_owned(),
                "wasm".to_owned(),
                include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec(),
            ),
            Err(FfiError::OperationFailed(message)) if message.contains("sha256 mismatch")
        ));
    }

    #[test]
    fn ffi_formats_groth16_proofs() {
        let formatted = format_groth16_proof_bundle(FfiProofBundle {
            proof: FfiSnarkJsProof {
                pi_a: vec!["123".to_owned(), "123".to_owned()],
                pi_b: vec![
                    vec!["69".to_owned(), "123".to_owned()],
                    vec!["12".to_owned(), "123".to_owned()],
                ],
                pi_c: vec!["12".to_owned(), "828".to_owned()],
                protocol: "milady".to_owned(),
                curve: "nsa-definitely-non-backdoored-curve-69".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 6],
        })
        .unwrap();

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/proof-formatting.json"
        ))
        .unwrap();

        assert_eq!(
            formatted.p_a[0],
            fixture["expected"]["pA"][0].as_str().unwrap()
        );
        assert_eq!(
            formatted.p_b[0][0],
            fixture["expected"]["pB"][0][0].as_str().unwrap()
        );
        assert_eq!(
            formatted.p_c[1],
            fixture["expected"]["pC"][1].as_str().unwrap()
        );
        assert_eq!(
            formatted.pub_signals[0],
            fixture["expected"]["pubSignals"][0].as_str().unwrap()
        );
    }

    #[test]
    fn ffi_rejects_malformed_proof_shapes() {
        assert!(matches!(
            format_groth16_proof_bundle(FfiProofBundle {
                proof: FfiSnarkJsProof {
                    pi_a: vec!["123".to_owned(), "123".to_owned()],
                    pi_b: vec![vec!["69".to_owned()], vec!["12".to_owned(), "123".to_owned()]],
                    pi_c: vec!["12".to_owned(), "828".to_owned()],
                    protocol: "groth16".to_owned(),
                    curve: "bn128".to_owned(),
                },
                public_signals: vec!["911".to_owned(); 8],
            }),
            Err(FfiError::InvalidProofShape(message)) if message.contains("pi_b")
        ));

        assert!(matches!(
            plan_withdrawal_transaction(
                1,
                "0x0987654321098765432109876543210987654321".to_owned(),
                FfiWithdrawal {
                    processooor: "0x1111111111111111111111111111111111111111".to_owned(),
                    data: vec![0x12, 0x34],
                },
                FfiProofBundle {
                    proof: FfiSnarkJsProof {
                        pi_a: vec!["123".to_owned(), "123".to_owned()],
                        pi_b: vec![
                            vec!["69".to_owned(), "123".to_owned()],
                            vec!["12".to_owned(), "123".to_owned()],
                        ],
                        pi_c: vec!["12".to_owned(), "828".to_owned()],
                        protocol: "groth16".to_owned(),
                        curve: "bn128".to_owned(),
                    },
                    public_signals: vec!["911".to_owned(); 7],
                },
            ),
            Err(FfiError::OperationFailed(message))
                if message.contains("exactly 8 public signals")
        ));
    }

    #[test]
    fn ffi_registers_external_signer_handles() {
        let host = register_host_provided_signer(
            "host-wallet".to_owned(),
            "0x1111111111111111111111111111111111111111".to_owned(),
        )
        .unwrap();
        assert_eq!(host.kind, "host_provided");
        assert_eq!(host.address, "0x1111111111111111111111111111111111111111");

        let mobile = register_mobile_secure_storage_signer(
            "mobile-wallet".to_owned(),
            "0x2222222222222222222222222222222222222222".to_owned(),
        )
        .unwrap();
        assert_eq!(mobile.kind, "mobile_secure_storage");
        assert_eq!(mobile.address, "0x2222222222222222222222222222222222222222");

        let request = FinalizedTransactionRequest {
            kind: privacy_pools_sdk::core::TransactionKind::Withdraw,
            chain_id: 1,
            from: parse_address(&host.address).unwrap(),
            to: parse_address("0x3333333333333333333333333333333333333333").unwrap(),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: Default::default(),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };

        let registered = registered_signer("host-wallet").unwrap();
        assert!(matches!(
            registered.sign_transaction_request("host-wallet", &request),
            Err(FfiError::SignerRequiresExternalSigning(handle)) if handle == "host-wallet"
        ));

        assert!(unregister_signer("host-wallet".to_owned()).unwrap());
        assert!(unregister_signer("mobile-wallet".to_owned()).unwrap());
    }

    fn dummy_proving_result() -> FfiProvingResult {
        FfiProvingResult {
            backend: "arkworks".to_owned(),
            proof: FfiProofBundle {
                proof: FfiSnarkJsProof {
                    pi_a: vec!["1".to_owned(), "2".to_owned()],
                    pi_b: vec![
                        vec!["3".to_owned(), "4".to_owned()],
                        vec!["5".to_owned(), "6".to_owned()],
                    ],
                    pi_c: vec!["7".to_owned(), "8".to_owned()],
                    protocol: "groth16".to_owned(),
                    curve: "bn128".to_owned(),
                },
                public_signals: vec!["9".to_owned(); 8],
            },
        }
    }

    #[test]
    fn ffi_background_jobs_report_status_results_and_cancellation() {
        let proving_handle =
            spawn_background_job(BackgroundJobKind::ProveWithdrawal, move |entry| {
                set_job_stage(&entry, "proving");
                std::thread::sleep(Duration::from_millis(25));
                ensure_job_not_cancelled(&entry)?;
                Ok(BackgroundJobResult::Proving(Box::new(
                    dummy_proving_result(),
                )))
            })
            .unwrap();

        let mut proving_status = poll_job_status(proving_handle.job_id.clone()).unwrap();
        for _ in 0..20 {
            if proving_status.state == "completed" {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            proving_status = poll_job_status(proving_handle.job_id.clone()).unwrap();
        }
        assert_eq!(proving_status.kind, "prove_withdrawal");
        assert_eq!(proving_status.state, "completed");
        assert!(
            get_prove_withdrawal_job_result(proving_handle.job_id.clone())
                .unwrap()
                .is_some()
        );
        assert!(remove_job(proving_handle.job_id).unwrap());

        let cancelled_handle = spawn_background_job(
            BackgroundJobKind::PrepareWithdrawalExecution,
            move |entry| {
                set_job_stage(&entry, "preparing_request");
                std::thread::sleep(Duration::from_millis(40));
                ensure_job_not_cancelled(&entry)?;
                Ok(BackgroundJobResult::PreparedExecution(Box::new(
                    FfiPreparedTransactionExecution {
                        proving: dummy_proving_result(),
                        transaction: FfiTransactionPlan {
                            kind: "withdraw".to_owned(),
                            chain_id: 1,
                            target: "0x1111111111111111111111111111111111111111".to_owned(),
                            calldata: "0x".to_owned(),
                            value: "0".to_owned(),
                            proof: FfiFormattedGroth16Proof {
                                p_a: vec!["1".to_owned(), "2".to_owned()],
                                p_b: vec![
                                    vec!["3".to_owned(), "4".to_owned()],
                                    vec!["5".to_owned(), "6".to_owned()],
                                ],
                                p_c: vec!["7".to_owned(), "8".to_owned()],
                                pub_signals: vec!["9".to_owned(); 8],
                            },
                        },
                        preflight: FfiExecutionPreflightReport {
                            kind: "withdraw".to_owned(),
                            caller: "0x1111111111111111111111111111111111111111".to_owned(),
                            target: "0x1111111111111111111111111111111111111111".to_owned(),
                            expected_chain_id: 1,
                            actual_chain_id: 1,
                            chain_id_matches: true,
                            simulated: true,
                            estimated_gas: 42_000,
                            code_hash_checks: vec![],
                            root_checks: vec![],
                        },
                    },
                )))
            },
        )
        .unwrap();

        assert!(cancel_job(cancelled_handle.job_id.clone()).unwrap());
        let mut cancelled_status = poll_job_status(cancelled_handle.job_id.clone()).unwrap();
        for _ in 0..20 {
            if cancelled_status.state == "cancelled" {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            cancelled_status = poll_job_status(cancelled_handle.job_id.clone()).unwrap();
        }
        assert_eq!(cancelled_status.kind, "prepare_withdrawal_execution");
        assert_eq!(cancelled_status.state, "cancelled");
        assert!(cancelled_status.cancel_requested);
        assert!(
            get_prepare_withdrawal_execution_job_result(cancelled_handle.job_id.clone())
                .unwrap()
                .is_none()
        );
        assert!(remove_job(cancelled_handle.job_id).unwrap());
    }
}
