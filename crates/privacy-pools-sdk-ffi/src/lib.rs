use alloy_primitives::{Address, B256, U256};
#[cfg(feature = "local-mnemonic")]
use privacy_pools_sdk::signer::LocalMnemonicSigner;
use privacy_pools_sdk::{
    FinalizedPreflightedTransaction, FinalizedTransactionExecution, PreflightedTransaction,
    PreparedTransactionExecution, PrivacyPoolsSdk, SubmittedPreflightedTransaction,
    SubmittedTransactionExecution, VerifiedCommitmentProof, VerifiedRagequitProof,
    VerifiedWithdrawalProof,
    artifacts::{
        ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle,
        SignedManifestArtifactBytes,
    },
    core::{
        CircuitMerkleWitness, CodeHashCheck, CommitmentCircuitInput, CommitmentWitnessRequest,
        ExecutionPolicy, ExecutionPolicyMode, ExecutionPreflightReport,
        FinalizedTransactionRequest, FormattedGroth16Proof, MasterKeys, MerkleProof, ProofBundle,
        RagequitExecutionConfig, RelayExecutionConfig, RootCheck, RootReadKind, SnarkJsProof,
        TransactionPlan, TransactionReceiptSummary, Withdrawal, WithdrawalCircuitInput,
        WithdrawalExecutionConfig, WithdrawalWitnessRequest,
        wire::{
            WireCircuitMerkleWitness, WireCommitment, WireCommitmentCircuitInput,
            WireCommitmentWitnessRequest, WireWithdrawal, WireWithdrawalCircuitInput,
            WireWithdrawalWitnessRequest,
        },
    },
    prover::{BackendProfile, ProverBackend, ProvingResult},
    recovery::{CompatibilityMode, PoolEvent, RecoveryPolicy},
    signer::{ExternalSigner, SignerAdapter, SignerKind},
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
    #[error("invalid execution policy mode: {0}")]
    InvalidExecutionPolicyMode(String),
    #[error("withdrawal circuit session handle not found: {0}")]
    SessionNotFound(String),
    #[error("signer handle not found: {0}")]
    SignerNotFound(String),
    #[error("secret handle not found: {0}")]
    SecretHandleNotFound(String),
    #[error("verified proof handle not found: {0}")]
    VerifiedProofHandleNotFound(String),
    #[error("execution handle not found: {0}")]
    ExecutionHandleNotFound(String),
    #[error("job handle not found: {0}")]
    JobNotFound(String),
    #[error("signer handle requires external signing: {0}")]
    SignerRequiresExternalSigning(String),
    #[error("artifact manifest parse failed: {0}")]
    InvalidManifest(String),
    #[error("sdk operation failed: {0}")]
    OperationFailed(String),
}

#[cfg(not(feature = "dangerous-exports"))]
fn dangerous_exports_disabled<T>() -> Result<T, FfiError> {
    Err(FfiError::OperationFailed(
        "dangerous export helpers are disabled in this build; rebuild with feature `dangerous-exports` to use the debug surface".to_owned(),
    ))
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
    pub mode: Option<String>,
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
    pub mode: Option<String>,
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
pub struct FfiPreflightedTransaction {
    pub transaction: FfiTransactionPlan,
    pub preflight: FfiExecutionPreflightReport,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFinalizedPreflightedTransaction {
    pub preflighted: FfiPreflightedTransaction,
    pub request: FfiFinalizedTransactionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSubmittedPreflightedTransaction {
    pub preflighted: FfiPreflightedTransaction,
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
pub struct FfiSignedManifestArtifactBytes {
    pub filename: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVerifiedSignedManifest {
    pub version: String,
    pub artifact_count: u64,
    pub ceremony: Option<String>,
    pub build: Option<String>,
    pub repository: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWithdrawalCircuitSessionHandle {
    pub handle: String,
    pub circuit: String,
    pub artifact_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCommitmentCircuitSessionHandle {
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
pub struct FfiCommitmentCircuitInput {
    pub value: String,
    pub label: String,
    pub nullifier: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCommitmentWitnessRequest {
    pub commitment: FfiCommitment,
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
    #[cfg(feature = "local-mnemonic")]
    LocalMnemonic(LocalMnemonicSigner),
    External(ExternalSigner),
}

#[derive(Debug, Clone)]
enum SecretHandleEntry {
    MasterKeys(MasterKeys),
    Secrets {
        nullifier: privacy_pools_sdk::core::Nullifier,
        secret: privacy_pools_sdk::core::Secret,
    },
    CommitmentRequest(CommitmentWitnessRequest),
    WithdrawalRequest(Box<WithdrawalWitnessRequest>),
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
            #[cfg(feature = "local-mnemonic")]
            Self::LocalMnemonic(signer) => signer.address(),
            Self::External(signer) => signer.address(),
        }
    }

    fn kind(&self) -> SignerKind {
        match self {
            #[cfg(feature = "local-mnemonic")]
            Self::LocalMnemonic(signer) => signer.kind(),
            Self::External(signer) => signer.kind(),
        }
    }

    fn sign_transaction_request(
        &self,
        handle: &str,
        request: &FinalizedTransactionRequest,
    ) -> Result<alloy_primitives::Bytes, FfiError> {
        #[cfg(not(feature = "local-mnemonic"))]
        let _ = request;
        match self {
            #[cfg(feature = "local-mnemonic")]
            Self::LocalMnemonic(signer) => signer
                .sign_transaction_request(request)
                .map_err(|error| FfiError::OperationFailed(error.to_string())),
            Self::External(_) => Err(FfiError::SignerRequiresExternalSigning(handle.to_owned())),
        }
    }
}

static SIGNER_REGISTRY: LazyLock<RwLock<HashMap<String, RegisteredSigner>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static SECRET_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, SecretHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static VERIFIED_PROOF_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, VerifiedProofHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static EXECUTION_HANDLE_REGISTRY: LazyLock<RwLock<HashMap<String, ExecutionHandleEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static JOB_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static JOB_REGISTRY: LazyLock<RwLock<HashMap<String, Arc<Mutex<BackgroundJobEntry>>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static SESSION_COUNTER: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));
static WITHDRAWAL_SESSION_REGISTRY: LazyLock<
    RwLock<HashMap<String, privacy_pools_sdk::WithdrawalCircuitSession>>,
> = LazyLock::new(|| RwLock::new(HashMap::new()));
static COMMITMENT_SESSION_REGISTRY: LazyLock<
    RwLock<HashMap<String, privacy_pools_sdk::CommitmentCircuitSession>>,
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

fn parse_execution_policy_mode(value: &str) -> Result<ExecutionPolicyMode, FfiError> {
    match value {
        "strict" => Ok(ExecutionPolicyMode::Strict),
        "insecure_dev" => Ok(ExecutionPolicyMode::InsecureDev),
        _ => Err(FfiError::InvalidExecutionPolicyMode(value.to_owned())),
    }
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
        _ => Err(FfiError::OperationFailed(format!(
            "invalid backend profile: {value}"
        ))),
    }
}

fn to_master_keys(master_nullifier: &str, master_secret: &str) -> Result<MasterKeys, FfiError> {
    Ok(MasterKeys {
        master_nullifier: parse_field(master_nullifier)?.into(),
        master_secret: parse_field(master_secret)?.into(),
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
        privacy_pools_sdk::core::TransactionKind::Ragequit => "ragequit".to_owned(),
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

fn register_secret_handle(entry: SecretHandleEntry) -> Result<String, FfiError> {
    let handle = uuid::Uuid::new_v4().to_string();
    let mut registry = SECRET_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn registered_secret_handle(handle: &str) -> Result<SecretHandleEntry, FfiError> {
    let registry = SECRET_HANDLE_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::SecretHandleNotFound(handle.to_owned()))
}

fn remove_secret_handle_entry(handle: &str) -> Result<bool, FfiError> {
    let mut registry = SECRET_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(handle).is_some())
}

fn clear_secret_handle_registry() -> Result<bool, FfiError> {
    let mut registry = SECRET_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let removed = !registry.is_empty();
    registry.clear();
    Ok(removed)
}

fn register_verified_proof_handle(entry: VerifiedProofHandleEntry) -> Result<String, FfiError> {
    let handle = uuid::Uuid::new_v4().to_string();
    let mut registry = VERIFIED_PROOF_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn registered_verified_proof_handle(handle: &str) -> Result<VerifiedProofHandleEntry, FfiError> {
    let registry = VERIFIED_PROOF_HANDLE_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::VerifiedProofHandleNotFound(handle.to_owned()))
}

fn remove_verified_proof_handle_entry(handle: &str) -> Result<bool, FfiError> {
    let mut registry = VERIFIED_PROOF_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(handle).is_some())
}

fn clear_verified_proof_handle_registry() -> Result<bool, FfiError> {
    let mut registry = VERIFIED_PROOF_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let removed = !registry.is_empty();
    registry.clear();
    Ok(removed)
}

fn register_execution_handle(entry: ExecutionHandleEntry) -> Result<String, FfiError> {
    let handle = uuid::Uuid::new_v4().to_string();
    let mut registry = EXECUTION_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle.clone(), entry);
    Ok(handle)
}

fn registered_execution_handle(handle: &str) -> Result<ExecutionHandleEntry, FfiError> {
    let registry = EXECUTION_HANDLE_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::ExecutionHandleNotFound(handle.to_owned()))
}

fn remove_execution_handle_entry(handle: &str) -> Result<bool, FfiError> {
    let mut registry = EXECUTION_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(registry.remove(handle).is_some())
}

fn clear_execution_handle_registry() -> Result<bool, FfiError> {
    let mut registry = EXECUTION_HANDLE_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let removed = !registry.is_empty();
    registry.clear();
    Ok(removed)
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

fn register_commitment_session(
    session: privacy_pools_sdk::CommitmentCircuitSession,
) -> Result<FfiCommitmentCircuitSessionHandle, FfiError> {
    let handle = format!(
        "commitment-session-{}",
        SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let ffi = FfiCommitmentCircuitSessionHandle {
        handle: handle.clone(),
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
    };
    let mut registry = COMMITMENT_SESSION_REGISTRY
        .write()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry.insert(handle, session);
    Ok(ffi)
}

fn registered_commitment_session(
    handle: &str,
) -> Result<privacy_pools_sdk::CommitmentCircuitSession, FfiError> {
    let registry = COMMITMENT_SESSION_REGISTRY
        .read()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    registry
        .get(handle)
        .cloned()
        .ok_or_else(|| FfiError::SessionNotFound(handle.to_owned()))
}

fn remove_commitment_session(handle: &str) -> Result<bool, FfiError> {
    let mut registry = COMMITMENT_SESSION_REGISTRY
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
        nullifier: nullifier.to_decimal_string(),
        secret: secret.to_decimal_string(),
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
    let wire = WireCommitment::from(&commitment);
    FfiCommitment {
        hash: wire.hash,
        nullifier_hash: wire.nullifier_hash,
        precommitment_hash: wire.precommitment_hash,
        value: wire.value,
        label: wire.label,
        nullifier: wire.nullifier,
        secret: wire.secret,
    }
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
    let mode = policy
        .mode
        .as_deref()
        .map(parse_execution_policy_mode)
        .transpose()?
        .unwrap_or_default();

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
        mode,
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
        mode: Some(match report.mode {
            ExecutionPolicyMode::Strict => "strict".to_owned(),
            ExecutionPolicyMode::InsecureDev => "insecure_dev".to_owned(),
        }),
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

fn to_ffi_preflighted_transaction(
    preflighted: &PreflightedTransaction,
) -> FfiPreflightedTransaction {
    FfiPreflightedTransaction {
        transaction: to_ffi_transaction_plan(preflighted.plan().clone()),
        preflight: to_ffi_execution_preflight(preflighted.preflight().clone()),
    }
}

fn to_ffi_finalized_preflighted_transaction(
    finalized: &FinalizedPreflightedTransaction,
) -> FfiFinalizedPreflightedTransaction {
    FfiFinalizedPreflightedTransaction {
        preflighted: to_ffi_preflighted_transaction(finalized.transaction()),
        request: to_ffi_finalized_request(finalized.request().clone()),
    }
}

fn to_ffi_submitted_preflighted_transaction(
    submitted: &SubmittedPreflightedTransaction,
) -> FfiSubmittedPreflightedTransaction {
    FfiSubmittedPreflightedTransaction {
        preflighted: to_ffi_preflighted_transaction(submitted.transaction()),
        receipt: to_ffi_receipt_summary(submitted.receipt().clone()),
    }
}

fn from_ffi_withdrawal(withdrawal: FfiWithdrawal) -> Result<Withdrawal, FfiError> {
    Ok(Withdrawal {
        processor: parse_address(&withdrawal.processooor)?,
        data: withdrawal.data.into(),
    })
}

fn ffi_withdrawal_to_wire(withdrawal: FfiWithdrawal) -> WireWithdrawal {
    WireWithdrawal {
        processooor: withdrawal.processooor,
        data: format!("0x{}", hex::encode(withdrawal.data)),
    }
}

fn ffi_commitment_to_wire(commitment: FfiCommitment) -> WireCommitment {
    WireCommitment {
        hash: commitment.hash,
        nullifier_hash: commitment.nullifier_hash,
        precommitment_hash: commitment.precommitment_hash,
        value: commitment.value,
        label: commitment.label,
        nullifier: commitment.nullifier,
        secret: commitment.secret,
    }
}

fn ffi_circuit_merkle_witness_to_wire(
    witness: FfiCircuitMerkleWitness,
) -> Result<WireCircuitMerkleWitness, FfiError> {
    Ok(WireCircuitMerkleWitness {
        root: witness.root,
        leaf: witness.leaf,
        index: usize::try_from(witness.index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        siblings: witness.siblings,
        depth: usize::try_from(witness.depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
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
        "ragequit" => privacy_pools_sdk::core::TransactionKind::Ragequit,
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
        "ragequit" => privacy_pools_sdk::core::TransactionKind::Ragequit,
        _ => {
            return Err(FfiError::OperationFailed(format!(
                "invalid transaction kind: {}",
                report.kind
            )));
        }
    };

    let mode = match report.mode.as_deref().unwrap_or("strict") {
        "strict" => ExecutionPolicyMode::Strict,
        "insecure_dev" => ExecutionPolicyMode::InsecureDev,
        other => {
            return Err(FfiError::InvalidExecutionPolicyMode(other.to_owned()));
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
        mode,
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
        "ragequit" => privacy_pools_sdk::core::TransactionKind::Ragequit,
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
    let wire = WireWithdrawalCircuitInput::from(&input);
    Ok(FfiWithdrawalCircuitInput {
        withdrawn_value: wire.withdrawn_value,
        state_root: wire.state_root,
        state_tree_depth: u64::try_from(wire.state_tree_depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        asp_root: wire.asp_root,
        asp_tree_depth: u64::try_from(wire.asp_tree_depth)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        context: wire.context,
        label: wire.label,
        existing_value: wire.existing_value,
        existing_nullifier: wire.existing_nullifier,
        existing_secret: wire.existing_secret,
        new_nullifier: wire.new_nullifier,
        new_secret: wire.new_secret,
        state_siblings: wire.state_siblings,
        state_index: u64::try_from(wire.state_index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
        asp_siblings: wire.asp_siblings,
        asp_index: u64::try_from(wire.asp_index)
            .map_err(|error| FfiError::OperationFailed(error.to_string()))?,
    })
}

fn to_ffi_commitment_circuit_input(input: &CommitmentCircuitInput) -> FfiCommitmentCircuitInput {
    let wire = WireCommitmentCircuitInput::from(input);
    FfiCommitmentCircuitInput {
        value: wire.value,
        label: wire.label,
        nullifier: wire.nullifier,
        secret: wire.secret,
    }
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

fn to_ffi_verified_signed_manifest(
    payload: &privacy_pools_sdk::artifacts::SignedArtifactManifestPayload,
    artifact_count: usize,
) -> FfiVerifiedSignedManifest {
    FfiVerifiedSignedManifest {
        version: payload.manifest.version.clone(),
        artifact_count: artifact_count as u64,
        ceremony: payload.metadata.ceremony.clone(),
        build: payload.metadata.build.clone(),
        repository: payload.metadata.repository.clone(),
        commit: payload.metadata.commit.clone(),
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
    WithdrawalWitnessRequest::try_from(WireWithdrawalWitnessRequest {
        commitment: ffi_commitment_to_wire(request.commitment),
        withdrawal: ffi_withdrawal_to_wire(request.withdrawal),
        scope: request.scope,
        withdrawal_amount: request.withdrawal_amount,
        state_witness: ffi_circuit_merkle_witness_to_wire(request.state_witness)?,
        asp_witness: ffi_circuit_merkle_witness_to_wire(request.asp_witness)?,
        new_nullifier: request.new_nullifier,
        new_secret: request.new_secret,
    })
    .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

fn from_ffi_commitment_witness_request(
    request: FfiCommitmentWitnessRequest,
) -> Result<CommitmentWitnessRequest, FfiError> {
    CommitmentWitnessRequest::try_from(WireCommitmentWitnessRequest {
        commitment: ffi_commitment_to_wire(request.commitment),
    })
    .map_err(|error| FfiError::OperationFailed(error.to_string()))
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

fn from_ffi_signed_manifest_artifact_bytes(
    artifacts: Vec<FfiSignedManifestArtifactBytes>,
) -> Vec<SignedManifestArtifactBytes> {
    artifacts
        .into_iter()
        .map(|artifact| SignedManifestArtifactBytes {
            filename: artifact.filename,
            bytes: artifact.bytes,
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
pub fn derive_master_keys(mnemonic: String) -> Result<FfiMasterKeys, FfiError> {
    let keys = sdk()
        .generate_master_keys(&mnemonic)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FfiMasterKeys {
        master_nullifier: keys.master_nullifier.to_decimal_string(),
        master_secret: keys.master_secret.to_decimal_string(),
    })
}

#[uniffi::export]
pub fn derive_master_keys_handle(mnemonic: String) -> Result<String, FfiError> {
    let keys = sdk()
        .generate_master_keys(&mnemonic)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    register_secret_handle(SecretHandleEntry::MasterKeys(keys))
}

#[uniffi::export]
pub fn dangerously_export_master_keys(handle: String) -> Result<FfiMasterKeys, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_secret_handle(&handle)? {
        SecretHandleEntry::MasterKeys(keys) => Ok(FfiMasterKeys {
            master_nullifier: keys.master_nullifier.to_decimal_string(),
            master_secret: keys.master_secret.to_decimal_string(),
        }),
        _ => Err(FfiError::OperationFailed(
            "secret handle does not contain master keys".to_owned(),
        )),
    }
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
pub fn generate_deposit_secrets_handle(
    master_keys_handle: String,
    scope: String,
    index: String,
) -> Result<String, FfiError> {
    let master_keys = match registered_secret_handle(&master_keys_handle)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain master keys".to_owned(),
            ));
        }
    };
    let secrets = sdk()
        .generate_deposit_secrets(&master_keys, parse_field(&scope)?, parse_field(&index)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    register_secret_handle(SecretHandleEntry::Secrets {
        nullifier: secrets.0,
        secret: secrets.1,
    })
}

#[uniffi::export]
pub fn calculate_withdrawal_context(
    withdrawal: FfiWithdrawal,
    scope: String,
) -> Result<String, FfiError> {
    sdk()
        .calculate_withdrawal_context(&from_ffi_withdrawal(withdrawal)?, parse_field(&scope)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn generate_withdrawal_secrets_handle(
    master_keys_handle: String,
    label: String,
    index: String,
) -> Result<String, FfiError> {
    let master_keys = match registered_secret_handle(&master_keys_handle)? {
        SecretHandleEntry::MasterKeys(keys) => keys,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain master keys".to_owned(),
            ));
        }
    };
    let secrets = sdk()
        .generate_withdrawal_secrets(&master_keys, parse_field(&label)?, parse_field(&index)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    register_secret_handle(SecretHandleEntry::Secrets {
        nullifier: secrets.0,
        secret: secrets.1,
    })
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
        .build_commitment(
            parse_field(&value)?,
            parse_field(&label)?,
            parse_field(&nullifier)?,
            parse_field(&secret)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_commitment(commitment))
}

#[uniffi::export]
pub fn get_commitment_from_handles(
    value: String,
    label: String,
    secrets_handle: String,
) -> Result<String, FfiError> {
    let (nullifier, secret) = match registered_secret_handle(&secrets_handle)? {
        SecretHandleEntry::Secrets { nullifier, secret } => (nullifier, secret),
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain secret pair material".to_owned(),
            ));
        }
    };
    let commitment = sdk()
        .build_commitment(
            parse_field(&value)?,
            parse_field(&label)?,
            nullifier.dangerously_expose_field(),
            secret.dangerously_expose_field(),
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    register_secret_handle(SecretHandleEntry::CommitmentRequest(
        CommitmentWitnessRequest { commitment },
    ))
}

#[uniffi::export]
pub fn dangerously_export_commitment_preimage(handle: String) -> Result<FfiCommitment, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_secret_handle(&handle)? {
        SecretHandleEntry::CommitmentRequest(request) => Ok(to_ffi_commitment(request.commitment)),
        _ => Err(FfiError::OperationFailed(
            "secret handle does not contain a commitment witness request".to_owned(),
        )),
    }
}

#[uniffi::export]
pub fn dangerously_export_secret(handle: String) -> Result<FfiSecrets, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_secret_handle(&handle)? {
        SecretHandleEntry::Secrets { nullifier, secret } => Ok(to_ffi_secrets((nullifier, secret))),
        _ => Err(FfiError::OperationFailed(
            "secret handle does not contain secret pair material".to_owned(),
        )),
    }
}

#[uniffi::export]
pub fn build_withdrawal_witness_request_handle(
    request: FfiWithdrawalWitnessRequest,
) -> Result<String, FfiError> {
    register_secret_handle(SecretHandleEntry::WithdrawalRequest(Box::new(
        from_ffi_withdrawal_witness_request(request)?,
    )))
}

#[uniffi::export]
pub fn remove_secret_handle(handle: String) -> Result<bool, FfiError> {
    remove_secret_handle_entry(&handle)
}

#[uniffi::export]
pub fn clear_secret_handles() -> Result<bool, FfiError> {
    clear_secret_handle_registry()
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
pub fn build_commitment_circuit_input(
    request: FfiCommitmentWitnessRequest,
) -> Result<FfiCommitmentCircuitInput, FfiError> {
    let input = sdk()
        .build_commitment_circuit_input(&from_ffi_commitment_witness_request(request)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_commitment_circuit_input(&input))
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
pub fn prepare_commitment_circuit_session(
    manifest_json: String,
    artifacts_root: String,
) -> Result<FfiCommitmentCircuitSessionHandle, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let session = sdk()
        .prepare_commitment_circuit_session(&manifest, PathBuf::from(artifacts_root))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_commitment_session(session)
}

#[uniffi::export]
pub fn prepare_commitment_circuit_session_from_bytes(
    manifest_json: String,
    artifacts: Vec<FfiArtifactBytes>,
) -> Result<FfiCommitmentCircuitSessionHandle, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let bundle = sdk()
        .verify_artifact_bundle_bytes(&manifest, "commitment", from_ffi_artifact_bytes(artifacts)?)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let session = sdk()
        .prepare_commitment_circuit_session_from_bundle(bundle)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_commitment_session(session)
}

#[uniffi::export]
pub fn remove_commitment_circuit_session(handle: String) -> Result<bool, FfiError> {
    remove_commitment_session(&handle)
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
pub fn prove_withdrawal_with_handles(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> Result<FfiProvingResult, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a withdrawal witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let result = sdk()
        .prove_withdrawal(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
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
pub fn prove_commitment(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request: FfiCommitmentWitnessRequest,
) -> Result<FfiProvingResult, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;
    let result = sdk()
        .prove_commitment(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_commitment_witness_request(request)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_proving_result(result))
}

#[uniffi::export]
pub fn prove_commitment_with_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> Result<FfiProvingResult, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a commitment witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let result = sdk()
        .prove_commitment(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_proving_result(result))
}

#[uniffi::export]
pub fn prove_commitment_with_session(
    backend_profile: String,
    session_handle: String,
    request: FfiCommitmentWitnessRequest,
) -> Result<FfiProvingResult, FfiError> {
    let session = registered_commitment_session(&session_handle)?;
    let result = sdk()
        .prove_commitment_with_session(
            parse_backend_profile(&backend_profile)?,
            &session,
            &from_ffi_commitment_witness_request(request)?,
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
pub fn verify_commitment_proof(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    proof: FfiProofBundle,
) -> Result<bool, FfiError> {
    let manifest = parse_manifest(&manifest_json)?;

    sdk()
        .verify_commitment_proof(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn verify_commitment_proof_with_session(
    backend_profile: String,
    session_handle: String,
    proof: FfiProofBundle,
) -> Result<bool, FfiError> {
    let session = registered_commitment_session(&session_handle)?;

    sdk()
        .verify_commitment_proof_with_session(
            parse_backend_profile(&backend_profile)?,
            &session,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn prove_and_verify_commitment_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> Result<String, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a commitment witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let verified = sdk()
        .prove_and_verify_commitment(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_verified_proof_handle(VerifiedProofHandleEntry::Commitment(verified))
}

#[uniffi::export]
pub fn prove_and_verify_withdrawal_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
) -> Result<String, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a withdrawal witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let verified = sdk()
        .prove_and_verify_withdrawal(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_verified_proof_handle(VerifiedProofHandleEntry::Withdrawal(verified))
}

#[uniffi::export]
pub fn verify_commitment_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof: FfiProofBundle,
) -> Result<String, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a commitment witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let verified = sdk()
        .verify_commitment_proof_for_request(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_verified_proof_handle(VerifiedProofHandleEntry::Commitment(verified))
}

#[uniffi::export]
pub fn verify_ragequit_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof: FfiProofBundle,
) -> Result<String, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::CommitmentRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a commitment witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let verified = sdk()
        .verify_ragequit_proof_for_request(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_verified_proof_handle(VerifiedProofHandleEntry::Ragequit(verified))
}

#[uniffi::export]
pub fn verify_withdrawal_proof_for_request_handle(
    backend_profile: String,
    manifest_json: String,
    artifacts_root: String,
    request_handle: String,
    proof: FfiProofBundle,
) -> Result<String, FfiError> {
    let request = match registered_secret_handle(&request_handle)? {
        SecretHandleEntry::WithdrawalRequest(request) => request,
        _ => {
            return Err(FfiError::OperationFailed(
                "secret handle does not contain a withdrawal witness request".to_owned(),
            ));
        }
    };
    let manifest = parse_manifest(&manifest_json)?;
    let verified = sdk()
        .verify_withdrawal_proof_for_request(
            parse_backend_profile(&backend_profile)?,
            &manifest,
            PathBuf::from(artifacts_root),
            &request,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    register_verified_proof_handle(VerifiedProofHandleEntry::Withdrawal(verified))
}

#[uniffi::export]
pub fn remove_verified_proof_handle(handle: String) -> Result<bool, FfiError> {
    remove_verified_proof_handle_entry(&handle)
}

#[uniffi::export]
pub fn clear_verified_proof_handles() -> Result<bool, FfiError> {
    clear_verified_proof_handle_registry()
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

#[cfg(feature = "local-mnemonic")]
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
pub fn plan_ragequit_transaction(
    chain_id: u64,
    pool_address: String,
    proof: FfiProofBundle,
) -> Result<FfiTransactionPlan, FfiError> {
    let plan = sdk()
        .plan_ragequit_transaction(
            chain_id,
            parse_address(&pool_address)?,
            &from_ffi_proof_bundle(proof)?,
        )
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn plan_verified_withdrawal_transaction_with_handle(
    chain_id: u64,
    pool_address: String,
    proof_handle: String,
) -> Result<FfiTransactionPlan, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a withdrawal proof".to_owned(),
            ));
        }
    };
    let plan = sdk()
        .plan_verified_withdrawal_transaction(chain_id, parse_address(&pool_address)?, &proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn plan_verified_relay_transaction_with_handle(
    chain_id: u64,
    entrypoint_address: String,
    proof_handle: String,
) -> Result<FfiTransactionPlan, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a withdrawal proof".to_owned(),
            ));
        }
    };
    let plan = sdk()
        .plan_verified_relay_transaction(chain_id, parse_address(&entrypoint_address)?, &proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn plan_verified_ragequit_transaction_with_handle(
    chain_id: u64,
    pool_address: String,
    proof_handle: String,
) -> Result<FfiTransactionPlan, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a ragequit proof".to_owned(),
            ));
        }
    };
    let plan = sdk()
        .plan_verified_ragequit_transaction(chain_id, parse_address(&pool_address)?, &proof)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(to_ffi_transaction_plan(plan))
}

#[uniffi::export]
pub fn preflight_verified_withdrawal_transaction_with_handle(
    chain_id: u64,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
    proof_handle: String,
) -> Result<String, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a withdrawal proof".to_owned(),
            ));
        }
    };
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let preflighted = block_on_sdk(sdk().preflight_verified_withdrawal_transaction_with_client(
        &WithdrawalExecutionConfig {
            chain_id,
            pool_address: parse_address(&pool_address)?,
            policy: from_ffi_execution_policy(policy)?,
        },
        &proof,
        &client,
    ))?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted))
}

#[uniffi::export]
pub fn preflight_verified_relay_transaction_with_handle(
    chain_id: u64,
    entrypoint_address: String,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
    proof_handle: String,
) -> Result<String, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Withdrawal(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a withdrawal proof".to_owned(),
            ));
        }
    };
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let preflighted = block_on_sdk(sdk().preflight_verified_relay_transaction_with_client(
        &RelayExecutionConfig {
            chain_id,
            entrypoint_address: parse_address(&entrypoint_address)?,
            pool_address: parse_address(&pool_address)?,
            policy: from_ffi_execution_policy(policy)?,
        },
        &proof,
        &client,
    ))?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted))
}

#[uniffi::export]
pub fn preflight_verified_ragequit_transaction_with_handle(
    chain_id: u64,
    pool_address: String,
    rpc_url: String,
    policy: FfiExecutionPolicy,
    proof_handle: String,
) -> Result<String, FfiError> {
    let proof = match registered_verified_proof_handle(&proof_handle)? {
        VerifiedProofHandleEntry::Ragequit(proof) => proof,
        _ => {
            return Err(FfiError::OperationFailed(
                "verified proof handle does not contain a ragequit proof".to_owned(),
            ));
        }
    };
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let preflighted = block_on_sdk(sdk().preflight_verified_ragequit_transaction_with_client(
        &RagequitExecutionConfig {
            chain_id,
            pool_address: parse_address(&pool_address)?,
            policy: from_ffi_execution_policy(policy)?,
        },
        &proof,
        &client,
    ))?;
    register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted))
}

#[uniffi::export]
pub fn finalize_preflighted_transaction_handle(
    rpc_url: String,
    preflighted_handle: String,
) -> Result<String, FfiError> {
    let preflighted = match registered_execution_handle(&preflighted_handle)? {
        ExecutionHandleEntry::Preflighted(preflighted) => preflighted,
        _ => {
            return Err(FfiError::OperationFailed(
                "execution handle does not contain a preflighted transaction".to_owned(),
            ));
        }
    };
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let finalized =
        block_on_sdk(sdk().finalize_preflighted_transaction_with_client(preflighted, &client))?;
    register_execution_handle(ExecutionHandleEntry::Finalized(finalized))
}

#[uniffi::export]
pub fn submit_preflighted_transaction_handle(
    rpc_url: String,
    signer_handle: String,
    preflighted_handle: String,
) -> Result<String, FfiError> {
    let preflighted = match registered_execution_handle(&preflighted_handle)? {
        ExecutionHandleEntry::Preflighted(preflighted) => preflighted,
        _ => {
            return Err(FfiError::OperationFailed(
                "execution handle does not contain a preflighted transaction".to_owned(),
            ));
        }
    };
    let signer = registered_signer(&signer_handle)?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let finalized =
        block_on_sdk(sdk().finalize_preflighted_transaction_with_client(preflighted, &client))?;
    if finalized.request().from != signer.address() {
        return Err(FfiError::OperationFailed(format!(
            "finalized transaction signer mismatch for handle {signer_handle}: expected {}, got {}",
            signer.address(),
            finalized.request().from
        )));
    }
    let signed_transaction =
        signer.sign_transaction_request(&signer_handle, finalized.request())?;
    let submitted = block_on_sdk(sdk().submit_finalized_preflighted_transaction_with_client(
        finalized,
        &signed_transaction,
        &client,
    ))?;
    register_execution_handle(ExecutionHandleEntry::Submitted(submitted))
}

#[uniffi::export]
pub fn submit_finalized_preflighted_transaction_handle(
    rpc_url: String,
    finalized_handle: String,
    signed_transaction: String,
) -> Result<String, FfiError> {
    let finalized = match registered_execution_handle(&finalized_handle)? {
        ExecutionHandleEntry::Finalized(finalized) => finalized,
        _ => {
            return Err(FfiError::OperationFailed(
                "execution handle does not contain a finalized preflighted transaction".to_owned(),
            ));
        }
    };
    let encoded_tx = hex::decode(signed_transaction.trim_start_matches("0x"))
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let client = privacy_pools_sdk::chain::HttpExecutionClient::new(&rpc_url)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    let submitted = block_on_sdk(sdk().submit_finalized_preflighted_transaction_with_client(
        finalized,
        &encoded_tx,
        &client,
    ))?;
    register_execution_handle(ExecutionHandleEntry::Submitted(submitted))
}

#[uniffi::export]
pub fn dangerously_export_preflighted_transaction(
    handle: String,
) -> Result<FfiPreflightedTransaction, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_execution_handle(&handle)? {
        ExecutionHandleEntry::Preflighted(preflighted) => {
            Ok(to_ffi_preflighted_transaction(&preflighted))
        }
        _ => Err(FfiError::OperationFailed(
            "execution handle does not contain a preflighted transaction".to_owned(),
        )),
    }
}

#[uniffi::export]
pub fn dangerously_export_finalized_preflighted_transaction(
    handle: String,
) -> Result<FfiFinalizedPreflightedTransaction, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_execution_handle(&handle)? {
        ExecutionHandleEntry::Finalized(finalized) => {
            Ok(to_ffi_finalized_preflighted_transaction(&finalized))
        }
        _ => Err(FfiError::OperationFailed(
            "execution handle does not contain a finalized preflighted transaction".to_owned(),
        )),
    }
}

#[uniffi::export]
pub fn dangerously_export_submitted_preflighted_transaction(
    handle: String,
) -> Result<FfiSubmittedPreflightedTransaction, FfiError> {
    #[cfg(not(feature = "dangerous-exports"))]
    {
        let _ = handle;
        return dangerous_exports_disabled();
    }

    #[cfg(feature = "dangerous-exports")]
    match registered_execution_handle(&handle)? {
        ExecutionHandleEntry::Submitted(submitted) => {
            Ok(to_ffi_submitted_preflighted_transaction(&submitted))
        }
        _ => Err(FfiError::OperationFailed(
            "execution handle does not contain a submitted preflighted transaction".to_owned(),
        )),
    }
}

#[uniffi::export]
pub fn remove_execution_handle(handle: String) -> Result<bool, FfiError> {
    remove_execution_handle_entry(&handle)
}

#[uniffi::export]
pub fn clear_execution_handles() -> Result<bool, FfiError> {
    clear_execution_handle_registry()
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
pub fn verify_signed_manifest(
    payload_json: String,
    signature_hex: String,
    public_key_hex: String,
) -> Result<FfiVerifiedSignedManifest, FfiError> {
    let payload = privacy_pools_sdk::artifacts::verify_signed_manifest_bytes(
        payload_json.as_bytes(),
        &signature_hex,
        &public_key_hex,
    )
    .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(to_ffi_verified_signed_manifest(&payload, 0))
}

#[uniffi::export]
pub fn verify_signed_manifest_artifacts(
    payload_json: String,
    signature_hex: String,
    public_key_hex: String,
    artifacts: Vec<FfiSignedManifestArtifactBytes>,
) -> Result<FfiVerifiedSignedManifest, FfiError> {
    let verified = privacy_pools_sdk::artifacts::verify_signed_manifest_artifact_bytes(
        payload_json.as_bytes(),
        &signature_hex,
        &public_key_hex,
        from_ffi_signed_manifest_artifact_bytes(artifacts),
    )
    .map_err(|error| FfiError::OperationFailed(error.to_string()))?;
    Ok(to_ffi_verified_signed_manifest(
        verified.payload(),
        verified.artifact_count(),
    ))
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
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
    use alloy_eips::Encodable2718;
    use alloy_network::TxSignerSync;
    use alloy_primitives::{bytes, keccak256};
    use alloy_signer_local::MnemonicBuilder;
    use async_trait::async_trait;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    fn handle_registry_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static HANDLE_REGISTRY_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        HANDLE_REGISTRY_TEST_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("handle registry test mutex")
    }

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .expect("valid ffi fixture")
    }

    fn assert_dangerous_exports_disabled<T>(result: Result<T, FfiError>) {
        match result {
            Ok(_) => panic!("expected dangerous export helper to be disabled"),
            Err(FfiError::OperationFailed(message)) => {
                assert!(message.contains("dangerous export helpers are disabled"));
            }
            Err(other) => panic!("expected disabled-operation error, found {other:?}"),
        }
    }

    const EXECUTION_TEST_MNEMONIC: &str =
        "test test test test test test test test test test test junk";

    fn valid_relay_data_bytes() -> Vec<u8> {
        bytes!(
            "0000000000000000000000002222222222222222222222222222222222222222\
             0000000000000000000000003333333333333333333333333333333333333333\
             0000000000000000000000000000000000000000000000000000000000000019"
        )
        .to_vec()
    }

    fn withdrawal_vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .expect("valid withdrawal fixture")
    }

    fn ffi_withdrawal_request() -> FfiWithdrawalWitnessRequest {
        let crypto_fixture = vector();
        let withdrawal_fixture = withdrawal_vector();
        let keys =
            derive_master_keys(crypto_fixture["mnemonic"].as_str().unwrap().to_owned()).unwrap();
        let deposit = derive_deposit_secrets(
            keys.master_nullifier,
            keys.master_secret,
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

        FfiWithdrawalWitnessRequest {
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
        }
    }

    fn signed_manifest_fixture() -> (String, String, String, String, Vec<u8>) {
        let artifact_bytes = b"signed manifest ffi fixture".to_vec();
        let payload = privacy_pools_sdk::artifacts::SignedArtifactManifestPayload {
            manifest: privacy_pools_sdk::artifacts::ArtifactManifest {
                version: "signed-ffi-test".to_owned(),
                artifacts: vec![privacy_pools_sdk::artifacts::ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: privacy_pools_sdk::artifacts::ArtifactKind::Wasm,
                    filename: "signed.wasm".to_owned(),
                    sha256: hex::encode(Sha256::digest(&artifact_bytes)),
                }],
            },
            metadata: privacy_pools_sdk::artifacts::ArtifactManifestMetadata {
                ceremony: Some("ffi ceremony".to_owned()),
                build: Some("ffi-test".to_owned()),
                repository: Some("0xbow/privacy-pools-sdk-rs".to_owned()),
                commit: Some("abc123".to_owned()),
            },
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[17_u8; 32]);
        let signature_hex = hex::encode(signing_key.sign(payload_json.as_bytes()).to_bytes());
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let wrong_public_key_hex = hex::encode(wrong_key.verifying_key().to_bytes());

        (
            payload_json,
            signature_hex,
            public_key_hex,
            wrong_public_key_hex,
            artifact_bytes,
        )
    }

    fn ffi_commitment_request() -> FfiCommitmentWitnessRequest {
        FfiCommitmentWitnessRequest {
            commitment: ffi_withdrawal_request().commitment,
        }
    }

    #[derive(Clone)]
    struct MockChainClient {
        caller: Address,
        pool: Address,
        entrypoint: Address,
        pool_code_hash: B256,
        entrypoint_code_hash: B256,
        state_root: U256,
        asp_root: U256,
    }

    #[async_trait]
    impl privacy_pools_sdk::chain::ExecutionClient for MockChainClient {
        async fn chain_id(&self) -> Result<u64, privacy_pools_sdk::chain::ChainError> {
            Ok(1)
        }

        async fn code_hash(
            &self,
            address: Address,
        ) -> Result<B256, privacy_pools_sdk::chain::ChainError> {
            if address == self.pool {
                Ok(self.pool_code_hash)
            } else if address == self.entrypoint {
                Ok(self.entrypoint_code_hash)
            } else {
                Ok(B256::ZERO)
            }
        }

        async fn read_root(
            &self,
            read: &privacy_pools_sdk::core::RootRead,
        ) -> Result<U256, privacy_pools_sdk::chain::ChainError> {
            match read.kind {
                RootReadKind::Asp => Ok(self.asp_root),
                RootReadKind::PoolState => {
                    let state_root_read = privacy_pools_sdk::chain::state_root_read(self.pool);
                    if read.call_data == state_root_read.call_data {
                        Ok(self.state_root)
                    } else {
                        let mut word = [0_u8; 32];
                        word[12..].copy_from_slice(self.entrypoint.as_slice());
                        Ok(U256::from_be_bytes(word))
                    }
                }
            }
        }

        async fn simulate_transaction(
            &self,
            _caller: Address,
            _plan: &TransactionPlan,
        ) -> Result<u64, privacy_pools_sdk::chain::ChainError> {
            Ok(210_000)
        }
    }

    #[async_trait]
    impl privacy_pools_sdk::chain::SubmissionClient for MockChainClient {
        fn caller(&self) -> Address {
            self.caller
        }

        async fn submit_transaction(
            &self,
            _plan: &TransactionPlan,
        ) -> Result<TransactionReceiptSummary, privacy_pools_sdk::chain::ChainError> {
            Ok(dummy_receipt_summary())
        }
    }

    #[async_trait]
    impl privacy_pools_sdk::chain::FinalizationClient for MockChainClient {
        async fn next_nonce(
            &self,
            _caller: Address,
        ) -> Result<u64, privacy_pools_sdk::chain::ChainError> {
            Ok(7)
        }

        async fn fee_parameters(
            &self,
        ) -> Result<privacy_pools_sdk::chain::FeeParameters, privacy_pools_sdk::chain::ChainError>
        {
            Ok(privacy_pools_sdk::chain::FeeParameters {
                gas_price: Some(1_500_000_000),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
            })
        }

        async fn submit_raw_transaction(
            &self,
            _encoded_tx: &[u8],
        ) -> Result<TransactionReceiptSummary, privacy_pools_sdk::chain::ChainError> {
            Ok(dummy_receipt_summary())
        }
    }

    struct ExecutionRpcFixtureServer {
        url: String,
        shutdown: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        raw_transactions: Arc<Mutex<Vec<String>>>,
    }

    impl ExecutionRpcFixtureServer {
        fn start(state_root: U256, asp_root: U256) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture rpc server");
            listener
                .set_nonblocking(true)
                .expect("configure fixture rpc server");
            let address = listener.local_addr().expect("fixture rpc local addr");
            let shutdown = Arc::new(AtomicBool::new(false));
            let raw_transactions = Arc::new(Mutex::new(Vec::new()));
            let worker_shutdown = Arc::clone(&shutdown);
            let worker_raw_transactions = Arc::clone(&raw_transactions);

            let worker = thread::spawn(move || {
                let pool = Address::from_slice(&[0x22; 20]);
                let entrypoint = Address::from_slice(&[0x11; 20]);
                while !worker_shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => handle_rpc_connection(
                            &mut stream,
                            pool,
                            entrypoint,
                            state_root,
                            asp_root,
                            &worker_raw_transactions,
                        ),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                url: format!("http://127.0.0.1:{}", address.port()),
                shutdown,
                worker: Some(worker),
                raw_transactions,
            }
        }

        fn raw_transactions(&self) -> Vec<String> {
            self.raw_transactions.lock().expect("raw tx lock").clone()
        }
    }

    impl Drop for ExecutionRpcFixtureServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn handle_rpc_connection(
        stream: &mut TcpStream,
        pool: Address,
        entrypoint: Address,
        state_root: U256,
        asp_root: U256,
        raw_transactions: &Arc<Mutex<Vec<String>>>,
    ) {
        if let Ok(body) = read_http_body(stream) {
            if body.is_empty() {
                return;
            }
            let request_json: Value = serde_json::from_slice(&body).expect("valid rpc json");
            let response = match &request_json {
                Value::Array(requests) => Value::Array(
                    requests
                        .iter()
                        .map(|request| {
                            handle_rpc_payload(
                                request,
                                pool,
                                entrypoint,
                                state_root,
                                asp_root,
                                raw_transactions,
                            )
                        })
                        .collect(),
                ),
                _ => handle_rpc_payload(
                    &request_json,
                    pool,
                    entrypoint,
                    state_root,
                    asp_root,
                    raw_transactions,
                ),
            };
            let encoded = serde_json::to_vec(&response).expect("encode rpc response");
            let response_head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                encoded.len()
            );
            stream
                .write_all(response_head.as_bytes())
                .expect("write rpc response head");
            stream.write_all(&encoded).expect("write rpc response body");
        }
    }

    fn read_http_body(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        let headers_end = loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(Vec::new());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };

        let headers = String::from_utf8_lossy(&buffer[..headers_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        while buffer.len() < headers_end + content_length {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        Ok(buffer[headers_end..headers_end + content_length].to_vec())
    }

    fn handle_rpc_payload(
        request: &Value,
        pool: Address,
        entrypoint: Address,
        state_root: U256,
        asp_root: U256,
        raw_transactions: &Arc<Mutex<Vec<String>>>,
    ) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        match method {
            "eth_chainId" => rpc_ok(id, json!(hex_quantity_u64(1))),
            "eth_getCode" => {
                let address = params.first().and_then(Value::as_str).unwrap_or_default();
                let bytecode = if address.eq_ignore_ascii_case(&format!("{pool:#x}")) {
                    "0x60006000556001600055"
                } else if address.eq_ignore_ascii_case(&format!("{entrypoint:#x}")) {
                    "0x60016000556002600055"
                } else {
                    "0x"
                };
                rpc_ok(id, json!(bytecode))
            }
            "eth_call" => rpc_ok(
                id,
                json!(handle_eth_call(
                    &params, pool, entrypoint, state_root, asp_root
                )),
            ),
            "eth_estimateGas" => rpc_ok(id, json!(hex_quantity_u64(210_000))),
            "eth_getTransactionCount" => rpc_ok(id, json!(hex_quantity_u64(7))),
            "eth_feeHistory" | "eth_maxPriorityFeePerGas" => rpc_error(
                id,
                -32000,
                &format!("{method} unsupported in ffi execution test fixture"),
            ),
            "eth_gasPrice" => rpc_ok(id, json!(hex_quantity_u64(1_500_000_000))),
            "eth_sendRawTransaction" => {
                let signed_transaction = params
                    .first()
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                raw_transactions
                    .lock()
                    .expect("raw tx lock")
                    .push(signed_transaction);
                rpc_ok(id, json!(format!("0x{}", "ab".repeat(32))))
            }
            "eth_getTransactionReceipt" => rpc_ok(
                id,
                json!({
                    "transactionHash": format!("0x{}", "ab".repeat(32)),
                    "transactionIndex": hex_quantity_u64(0),
                    "blockHash": format!("0x{}", "cd".repeat(32)),
                    "blockNumber": hex_quantity_u64(128),
                    "from": format!("{:#x}", Address::from_slice(&[0x55; 20])),
                    "to": format!("{pool:#x}"),
                    "cumulativeGasUsed": hex_quantity_u64(123_456),
                    "gasUsed": hex_quantity_u64(123_456),
                    "contractAddress": Value::Null,
                    "logs": Vec::<Value>::new(),
                    "logsBloom": format!("0x{}", "0".repeat(512)),
                    "status": "0x1",
                    "effectiveGasPrice": hex_quantity_u64(1_500_000_000),
                    "type": "0x0",
                }),
            ),
            "eth_blockNumber" => rpc_ok(id, json!(hex_quantity_u64(128))),
            "eth_getBlockByNumber" => rpc_ok(
                id,
                json!({
                    "hash": format!("0x{}", "cd".repeat(32)),
                    "number": hex_quantity_u64(128),
                    "baseFeePerGas": hex_quantity_u64(1),
                    "timestamp": hex_quantity_u64(1),
                    "transactions": [format!("0x{}", "ab".repeat(32))],
                }),
            ),
            "eth_getTransactionByHash" => rpc_ok(
                id,
                json!({
                    "hash": format!("0x{}", "ab".repeat(32)),
                    "nonce": hex_quantity_u64(7),
                    "blockHash": format!("0x{}", "cd".repeat(32)),
                    "blockNumber": hex_quantity_u64(128),
                    "transactionIndex": hex_quantity_u64(0),
                    "from": format!("{:#x}", Address::from_slice(&[0x55; 20])),
                    "to": format!("{pool:#x}"),
                    "value": "0x0",
                    "gas": hex_quantity_u64(210_000),
                    "gasPrice": hex_quantity_u64(1_500_000_000),
                    "input": "0x",
                    "chainId": hex_quantity_u64(1),
                    "type": "0x0",
                    "v": "0x1b",
                    "r": format!("0x{}", "11".repeat(32)),
                    "s": format!("0x{}", "22".repeat(32)),
                }),
            ),
            _ => rpc_error(id, -32601, &format!("unsupported rpc method {method}")),
        }
    }

    fn handle_eth_call(
        params: &[Value],
        pool: Address,
        entrypoint: Address,
        state_root: U256,
        asp_root: U256,
    ) -> String {
        let call = params
            .first()
            .and_then(Value::as_object)
            .expect("rpc call object");
        let to = call
            .get("to")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let data = call
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();

        let state_call = format!(
            "0x{}",
            hex::encode(privacy_pools_sdk::chain::state_root_read(pool).call_data)
        );
        let asp_call = format!(
            "0x{}",
            hex::encode(privacy_pools_sdk::chain::asp_root_read(entrypoint, pool).call_data)
        );

        if to == format!("{pool:#x}") && data == state_call {
            hex_word_u256(state_root)
        } else if to == format!("{entrypoint:#x}") && data == asp_call {
            hex_word_u256(asp_root)
        } else if to == format!("{pool:#x}") {
            let mut word = [0_u8; 32];
            word[12..].copy_from_slice(entrypoint.as_slice());
            hex_word_u256(U256::from_be_bytes(word))
        } else {
            hex_word_u256(U256::ZERO)
        }
    }

    fn rpc_ok(id: Value, result: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "result": result })
    }

    fn rpc_error(id: Value, code: i64, message: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
    }

    fn hex_quantity_u64(value: u64) -> String {
        format!("0x{:x}", value)
    }

    fn hex_word_u256(value: U256) -> String {
        format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
    }

    fn compatibility_shapes() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/compatibility-shapes/sdk-json-shapes.json"
        ))
        .expect("valid compatibility shape fixture")
    }

    fn assert_ffi_shape(name: &str, value: Value) {
        let shapes = compatibility_shapes();
        let runtime_shapes = resolve_shape_ref(&shapes, &shapes["ffi"]);
        assert_eq!(
            shape_of_json(&value),
            resolve_shape_ref(&shapes, &runtime_shapes[name]),
            "ffi.{name}"
        );
    }

    fn resolve_shape_ref(root: &Value, value: &Value) -> Value {
        match value {
            Value::String(reference) if reference.starts_with("$ref:") => {
                resolve_shape_ref(root, &lookup_shape_ref(root, &reference[5..]))
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|entry| resolve_shape_ref(root, entry))
                    .collect(),
            ),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, entry)| (key.clone(), resolve_shape_ref(root, entry)))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn lookup_shape_ref(root: &Value, path: &str) -> Value {
        path.split('.')
            .fold(root, |cursor, segment| &cursor[segment])
            .clone()
    }

    fn shape_of_json(value: &Value) -> Value {
        match value {
            Value::Array(values) => {
                if let Some(first) = values.first() {
                    Value::Array(vec![shape_of_json(first)])
                } else {
                    Value::Array(vec![])
                }
            }
            Value::Object(map) => {
                let mut entries = map
                    .iter()
                    .map(|(key, entry)| (key.clone(), shape_of_json(entry)))
                    .collect::<Vec<_>>();
                entries.sort_by(|left, right| left.0.cmp(&right.0));
                Value::Object(entries.into_iter().collect())
            }
            Value::Null => Value::String("null".to_owned()),
            Value::Bool(_) => Value::String("boolean".to_owned()),
            Value::Number(_) => Value::String("number".to_owned()),
            Value::String(_) => Value::String("string".to_owned()),
        }
    }

    fn assert_uuid_v4(handle: &str) {
        let parsed = uuid::Uuid::parse_str(handle).expect("valid UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    fn dummy_receipt_summary() -> TransactionReceiptSummary {
        TransactionReceiptSummary {
            transaction_hash: B256::repeat_byte(0xab),
            block_hash: Some(B256::repeat_byte(0xcd)),
            block_number: Some(128),
            transaction_index: Some(0),
            success: true,
            gas_used: 123_456,
            effective_gas_price: "1500000000".to_owned(),
            from: Address::from_slice(&[0x55; 20]),
            to: Some(Address::from_slice(&[0x22; 20])),
        }
    }

    fn json_master_keys(keys: &FfiMasterKeys) -> Value {
        json!({
            "master_nullifier": keys.master_nullifier,
            "master_secret": keys.master_secret,
        })
    }

    fn json_commitment(commitment: &FfiCommitment) -> Value {
        json!({
            "hash": commitment.hash,
            "label": commitment.label,
            "nullifier": commitment.nullifier,
            "nullifier_hash": commitment.nullifier_hash,
            "precommitment_hash": commitment.precommitment_hash,
            "secret": commitment.secret,
            "value": commitment.value,
        })
    }

    fn json_circuit_witness(witness: &FfiCircuitMerkleWitness) -> Value {
        json!({
            "root": witness.root,
            "leaf": witness.leaf,
            "index": witness.index,
            "siblings": witness.siblings,
            "depth": witness.depth,
        })
    }

    fn json_withdrawal(withdrawal: &FfiWithdrawal) -> Value {
        json!({
            "processooor": withdrawal.processooor,
            "data": withdrawal.data,
        })
    }

    fn json_withdrawal_request(request: &FfiWithdrawalWitnessRequest) -> Value {
        json!({
            "commitment": json_commitment(&request.commitment),
            "withdrawal": json_withdrawal(&request.withdrawal),
            "scope": request.scope,
            "withdrawal_amount": request.withdrawal_amount,
            "state_witness": json_circuit_witness(&request.state_witness),
            "asp_witness": json_circuit_witness(&request.asp_witness),
            "new_nullifier": request.new_nullifier,
            "new_secret": request.new_secret,
        })
    }

    fn json_commitment_request(request: &FfiCommitmentWitnessRequest) -> Value {
        json!({
            "commitment": json_commitment(&request.commitment),
        })
    }

    fn json_proof_bundle(proof: &FfiProofBundle) -> Value {
        json!({
            "proof": {
                "pi_a": proof.proof.pi_a,
                "pi_b": proof.proof.pi_b,
                "pi_c": proof.proof.pi_c,
                "protocol": proof.proof.protocol,
                "curve": proof.proof.curve,
            },
            "public_signals": proof.public_signals,
        })
    }

    fn json_transaction_plan(plan: &FfiTransactionPlan) -> Value {
        json!({
            "kind": plan.kind,
            "chain_id": plan.chain_id,
            "target": plan.target,
            "calldata": plan.calldata,
            "value": plan.value,
            "proof": {
                "p_a": plan.proof.p_a,
                "p_b": plan.proof.p_b,
                "p_c": plan.proof.p_c,
                "pub_signals": plan.proof.pub_signals,
            },
        })
    }

    fn json_preflight_report(report: &FfiExecutionPreflightReport) -> Value {
        json!({
            "kind": report.kind,
            "caller": report.caller,
            "target": report.target,
            "expected_chain_id": report.expected_chain_id,
            "actual_chain_id": report.actual_chain_id,
            "chain_id_matches": report.chain_id_matches,
            "simulated": report.simulated,
            "estimated_gas": report.estimated_gas,
            "mode": report.mode,
            "code_hash_checks": report.code_hash_checks.iter().map(|check| {
                json!({
                    "address": check.address,
                    "expected_code_hash": check.expected_code_hash,
                    "actual_code_hash": check.actual_code_hash,
                    "matches_expected": check.matches_expected,
                })
            }).collect::<Vec<_>>(),
            "root_checks": report.root_checks.iter().map(|check| {
                json!({
                    "kind": check.kind,
                    "contract_address": check.contract_address,
                    "pool_address": check.pool_address,
                    "expected_root": check.expected_root,
                    "actual_root": check.actual_root,
                    "matches": check.matches,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn json_finalized_request(request: &FfiFinalizedTransactionRequest) -> Value {
        json!({
            "kind": request.kind,
            "chain_id": request.chain_id,
            "from": request.from,
            "to": request.to,
            "nonce": request.nonce,
            "gas_limit": request.gas_limit,
            "value": request.value,
            "data": request.data,
            "gas_price": request.gas_price,
            "max_fee_per_gas": request.max_fee_per_gas,
            "max_priority_fee_per_gas": request.max_priority_fee_per_gas,
        })
    }

    fn json_receipt_summary(receipt: &FfiTransactionReceiptSummary) -> Value {
        json!({
            "transaction_hash": receipt.transaction_hash,
            "block_hash": receipt.block_hash,
            "block_number": receipt.block_number,
            "transaction_index": receipt.transaction_index,
            "success": receipt.success,
            "gas_used": receipt.gas_used,
            "effective_gas_price": receipt.effective_gas_price,
            "from": receipt.from,
            "to": receipt.to,
        })
    }

    fn json_preflighted_transaction(transaction: &FfiPreflightedTransaction) -> Value {
        json!({
            "transaction": json_transaction_plan(&transaction.transaction),
            "preflight": json_preflight_report(&transaction.preflight),
        })
    }

    fn json_finalized_preflighted_transaction(
        transaction: &FfiFinalizedPreflightedTransaction,
    ) -> Value {
        json!({
            "preflighted": json_preflighted_transaction(&transaction.preflighted),
            "request": json_finalized_request(&transaction.request),
        })
    }

    fn json_submitted_preflighted_transaction(
        transaction: &FfiSubmittedPreflightedTransaction,
    ) -> Value {
        json!({
            "preflighted": json_preflighted_transaction(&transaction.preflighted),
            "receipt": json_receipt_summary(&transaction.receipt),
        })
    }

    fn json_prepared_transaction_execution(execution: &FfiPreparedTransactionExecution) -> Value {
        json!({
            "proving": {
                "backend": execution.proving.backend,
                "proof": json_proof_bundle(&execution.proving.proof),
            },
            "transaction": json_transaction_plan(&execution.transaction),
            "preflight": json_preflight_report(&execution.preflight),
        })
    }

    fn json_finalized_transaction_execution(execution: &FfiFinalizedTransactionExecution) -> Value {
        json!({
            "prepared": json_prepared_transaction_execution(&execution.prepared),
            "request": json_finalized_request(&execution.request),
        })
    }

    fn json_submitted_transaction_execution(execution: &FfiSubmittedTransactionExecution) -> Value {
        json!({
            "prepared": json_prepared_transaction_execution(&execution.prepared),
            "receipt": json_receipt_summary(&execution.receipt),
        })
    }

    fn json_verified_signed_manifest(verified: &FfiVerifiedSignedManifest) -> Value {
        json!({
            "version": verified.version,
            "artifact_count": verified.artifact_count,
            "ceremony": verified.ceremony,
            "build": verified.build,
            "repository": verified.repository,
            "commit": verified.commit,
        })
    }

    fn sign_finalized_request_hex(request: FfiFinalizedTransactionRequest) -> String {
        let request = from_ffi_finalized_request(request).expect("valid finalized request");
        let signer = MnemonicBuilder::from_phrase_nth(EXECUTION_TEST_MNEMONIC, 0);
        assert_eq!(request.from, signer.address());

        let envelope = if let Some(gas_price) = request.gas_price {
            let mut tx = TxLegacy {
                chain_id: Some(request.chain_id),
                nonce: request.nonce,
                gas_price,
                gas_limit: request.gas_limit,
                to: request.to.into(),
                value: request.value,
                input: request.data.clone(),
            };
            let signature = signer
                .sign_transaction_sync(&mut tx)
                .expect("sign legacy request");
            TxEnvelope::from(tx.into_signed(signature))
        } else {
            let mut tx = TxEip1559 {
                chain_id: request.chain_id,
                nonce: request.nonce,
                gas_limit: request.gas_limit,
                max_fee_per_gas: request.max_fee_per_gas.expect("dynamic max fee per gas"),
                max_priority_fee_per_gas: request
                    .max_priority_fee_per_gas
                    .expect("dynamic max priority fee per gas"),
                to: request.to.into(),
                value: request.value,
                access_list: Default::default(),
                input: request.data.clone(),
            };
            let signature = signer
                .sign_transaction_sync(&mut tx)
                .expect("sign dynamic request");
            TxEnvelope::from(tx.into_signed(signature))
        };

        format!("0x{}", hex::encode(envelope.encoded_2718()))
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
            commitment.precommitment_hash,
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
    fn ffi_exports_match_frozen_binding_shapes() {
        let _guard = handle_registry_test_guard();
        let crypto_fixture = vector();
        let withdrawal_request = ffi_withdrawal_request();
        let commitment_request = ffi_commitment_request();

        let master_keys_handle =
            derive_master_keys_handle(crypto_fixture["mnemonic"].as_str().unwrap().to_owned())
                .unwrap();
        let exported_master_keys = dangerously_export_master_keys(master_keys_handle.clone());
        let deposit_handle = generate_deposit_secrets_handle(
            master_keys_handle.clone(),
            crypto_fixture["scope"].as_str().unwrap().to_owned(),
            "0".to_owned(),
        )
        .unwrap();
        let withdrawal_handle = generate_withdrawal_secrets_handle(
            master_keys_handle,
            crypto_fixture["label"].as_str().unwrap().to_owned(),
            "1".to_owned(),
        )
        .unwrap();
        let commitment_handle = get_commitment_from_handles(
            withdrawal_request.commitment.value.clone(),
            withdrawal_request.commitment.label.clone(),
            deposit_handle.clone(),
        )
        .unwrap();
        let exported_commitment = dangerously_export_commitment_preimage(commitment_handle.clone());

        assert_uuid_v4(&deposit_handle);
        assert_uuid_v4(&withdrawal_handle);
        assert_uuid_v4(&commitment_handle);
        if cfg!(feature = "dangerous-exports") {
            assert_ffi_shape(
                "masterKeys",
                json_master_keys(&exported_master_keys.unwrap()),
            );
            assert_ffi_shape("commitment", json_commitment(&exported_commitment.unwrap()));
        } else {
            assert_dangerous_exports_disabled(exported_master_keys);
            assert_dangerous_exports_disabled(exported_commitment);
        }
        assert_ffi_shape(
            "withdrawalWitnessRequest",
            json_withdrawal_request(&withdrawal_request),
        );
        assert_ffi_shape(
            "commitmentWitnessRequest",
            json_commitment_request(&commitment_request),
        );

        let withdrawal_input = build_withdrawal_circuit_input(withdrawal_request.clone()).unwrap();
        let commitment_input = build_commitment_circuit_input(commitment_request.clone()).unwrap();
        assert_ffi_shape(
            "withdrawalCircuitInput",
            json!({
                "existing_nullifier": withdrawal_input.existing_nullifier,
                "existing_secret": withdrawal_input.existing_secret,
                "existing_value": withdrawal_input.existing_value,
                "label": withdrawal_input.label,
                "new_nullifier": withdrawal_input.new_nullifier,
                "new_secret": withdrawal_input.new_secret,
                "withdrawn_value": withdrawal_input.withdrawn_value,
                "state_root": withdrawal_input.state_root,
                "state_siblings": withdrawal_input.state_siblings,
                "state_index": withdrawal_input.state_index,
                "state_tree_depth": withdrawal_input.state_tree_depth,
                "asp_root": withdrawal_input.asp_root,
                "asp_siblings": withdrawal_input.asp_siblings,
                "asp_index": withdrawal_input.asp_index,
                "asp_tree_depth": withdrawal_input.asp_tree_depth,
                "context": withdrawal_input.context,
            }),
        );
        assert_ffi_shape(
            "commitmentCircuitInput",
            json!({
                "value": commitment_input.value,
                "label": commitment_input.label,
                "nullifier": commitment_input.nullifier,
                "secret": commitment_input.secret,
            }),
        );

        let proving = dummy_proving_result();
        assert_ffi_shape("proofBundle", json_proof_bundle(&proving.proof));
        let transaction_plan = plan_withdrawal_transaction(
            1,
            "0x2222222222222222222222222222222222222222".to_owned(),
            withdrawal_request.withdrawal.clone(),
            proving.proof.clone(),
        )
        .unwrap();
        assert_ffi_shape("transactionPlan", json_transaction_plan(&transaction_plan));

        let artifacts_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/withdrawal-proving-manifest.json"
        ))
        .unwrap();
        let request = from_ffi_withdrawal_witness_request(withdrawal_request).unwrap();
        let verified = sdk()
            .prove_and_verify_withdrawal(
                BackendProfile::Stable,
                &manifest,
                &artifacts_root,
                &request,
            )
            .unwrap();
        let caller = Address::from_slice(&[0x55; 20]);
        let pool = Address::from_slice(&[0x22; 20]);
        let entrypoint = Address::from_slice(&[0x11; 20]);
        let client = MockChainClient {
            caller,
            pool,
            entrypoint,
            pool_code_hash: B256::repeat_byte(0x33),
            entrypoint_code_hash: B256::repeat_byte(0x44),
            state_root: request.state_witness.root,
            asp_root: request.asp_witness.root,
        };
        let preflighted =
            block_on_sdk(sdk().preflight_verified_withdrawal_transaction_with_client(
                &WithdrawalExecutionConfig {
                    chain_id: 1,
                    pool_address: pool,
                    policy: ExecutionPolicy::strict(
                        1,
                        caller,
                        client.pool_code_hash,
                        client.entrypoint_code_hash,
                    ),
                },
                &verified,
                &client,
            ))
            .unwrap();
        let finalized = block_on_sdk(
            sdk().finalize_preflighted_transaction_with_client(preflighted.clone(), &client),
        )
        .unwrap();
        let submitted = block_on_sdk(
            sdk().submit_preflighted_transaction_with_client(preflighted.clone(), &client),
        )
        .unwrap();

        let preflighted_handle =
            register_execution_handle(ExecutionHandleEntry::Preflighted(preflighted.clone()))
                .unwrap();
        let finalized_handle =
            register_execution_handle(ExecutionHandleEntry::Finalized(finalized.clone())).unwrap();
        let submitted_handle =
            register_execution_handle(ExecutionHandleEntry::Submitted(submitted.clone())).unwrap();
        assert_uuid_v4(&preflighted_handle);
        assert_uuid_v4(&finalized_handle);
        assert_uuid_v4(&submitted_handle);
        assert_ffi_shape(
            "executionHandles",
            json!({
                "preflighted": preflighted_handle,
                "finalized": finalized_handle,
                "submitted": submitted_handle,
            }),
        );

        let exported_preflighted_result =
            dangerously_export_preflighted_transaction(preflighted_handle.clone());
        let exported_finalized_result =
            dangerously_export_finalized_preflighted_transaction(finalized_handle.clone());
        let exported_submitted_result =
            dangerously_export_submitted_preflighted_transaction(submitted_handle.clone());
        let (exported_preflighted, exported_finalized, exported_submitted) =
            if cfg!(feature = "dangerous-exports") {
                (
                    exported_preflighted_result.unwrap(),
                    exported_finalized_result.unwrap(),
                    exported_submitted_result.unwrap(),
                )
            } else {
                assert_dangerous_exports_disabled(exported_preflighted_result);
                assert_dangerous_exports_disabled(exported_finalized_result);
                assert_dangerous_exports_disabled(exported_submitted_result);
                (
                    to_ffi_preflighted_transaction(&preflighted),
                    to_ffi_finalized_preflighted_transaction(&finalized),
                    to_ffi_submitted_preflighted_transaction(&submitted),
                )
            };
        assert_ffi_shape(
            "preflightedTransaction",
            json_preflighted_transaction(&exported_preflighted),
        );
        assert_ffi_shape(
            "finalizedPreflightedTransaction",
            json_finalized_preflighted_transaction(&exported_finalized),
        );
        assert_ffi_shape(
            "submittedPreflightedTransaction",
            json_submitted_preflighted_transaction(&exported_submitted),
        );
        assert_ffi_shape(
            "transactionReceiptSummary",
            json_receipt_summary(&exported_submitted.receipt),
        );

        let prepared_execution = FfiPreparedTransactionExecution {
            proving: dummy_proving_result(),
            transaction: exported_preflighted.transaction.clone(),
            preflight: exported_preflighted.preflight.clone(),
        };
        assert_ffi_shape(
            "preparedTransactionExecution",
            json_prepared_transaction_execution(&prepared_execution),
        );
        assert_ffi_shape(
            "finalizedTransactionExecution",
            json_finalized_transaction_execution(&FfiFinalizedTransactionExecution {
                prepared: prepared_execution.clone(),
                request: exported_finalized.request.clone(),
            }),
        );
        assert_ffi_shape(
            "submittedTransactionExecution",
            json_submitted_transaction_execution(&FfiSubmittedTransactionExecution {
                prepared: prepared_execution,
                receipt: exported_submitted.receipt.clone(),
            }),
        );

        let (payload_json, signature_hex, public_key_hex, _, artifact_bytes) =
            signed_manifest_fixture();
        let verified_manifest = verify_signed_manifest(
            payload_json.clone(),
            signature_hex.clone(),
            public_key_hex.clone(),
        )
        .unwrap();
        assert_ffi_shape(
            "verifiedSignedManifest",
            json_verified_signed_manifest(&verified_manifest),
        );
        let verified_manifest_artifacts = verify_signed_manifest_artifacts(
            payload_json,
            signature_hex,
            public_key_hex,
            vec![FfiSignedManifestArtifactBytes {
                filename: "signed.wasm".to_owned(),
                bytes: artifact_bytes,
            }],
        )
        .unwrap();
        assert_ffi_shape(
            "verifiedSignedManifest",
            json_verified_signed_manifest(&verified_manifest_artifacts),
        );

        assert!(remove_execution_handle(finalized_handle).unwrap());
        assert!(clear_execution_handles().unwrap());
        assert!(clear_secret_handles().unwrap());
    }

    #[test]
    fn ffi_public_handle_apis_match_frozen_shapes() {
        let _guard = handle_registry_test_guard();
        let crypto_fixture = vector();
        let withdrawal_request = ffi_withdrawal_request();
        let artifacts_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let artifacts_root_string = artifacts_root.to_string_lossy().to_string();
        let withdrawal_manifest =
            include_str!("../../../fixtures/artifacts/withdrawal-proving-manifest.json").to_owned();
        let commitment_manifest =
            include_str!("../../../fixtures/artifacts/commitment-proving-manifest.json").to_owned();

        let master_keys_handle =
            derive_master_keys_handle(crypto_fixture["mnemonic"].as_str().unwrap().to_owned())
                .unwrap();
        let deposit_handle = generate_deposit_secrets_handle(
            master_keys_handle.clone(),
            crypto_fixture["scope"].as_str().unwrap().to_owned(),
            "0".to_owned(),
        )
        .unwrap();
        let commitment_handle = get_commitment_from_handles(
            withdrawal_request.commitment.value.clone(),
            withdrawal_request.commitment.label.clone(),
            deposit_handle,
        )
        .unwrap();
        let withdrawal_request_handle =
            build_withdrawal_witness_request_handle(withdrawal_request.clone()).unwrap();

        let verified_withdrawal_handle = prove_and_verify_withdrawal_handle(
            "stable".to_owned(),
            withdrawal_manifest.clone(),
            artifacts_root_string.clone(),
            withdrawal_request_handle.clone(),
        )
        .unwrap();
        let commitment_proof = prove_commitment_with_handle(
            "stable".to_owned(),
            commitment_manifest.clone(),
            artifacts_root_string.clone(),
            commitment_handle.clone(),
        )
        .unwrap();
        let verified_ragequit_handle = verify_ragequit_proof_for_request_handle(
            "stable".to_owned(),
            commitment_manifest,
            artifacts_root_string.clone(),
            commitment_handle.clone(),
            commitment_proof.proof.clone(),
        )
        .unwrap();

        assert_uuid_v4(&verified_withdrawal_handle);
        assert_uuid_v4(&verified_ragequit_handle);

        let rpc_server = ExecutionRpcFixtureServer::start(
            parse_field(&withdrawal_request.state_witness.root).unwrap(),
            parse_field(&withdrawal_request.asp_witness.root).unwrap(),
        );
        let expected_pool_code_hash = format!(
            "{:#x}",
            B256::from(keccak256(bytes!("60006000556001600055")))
        );
        let expected_entrypoint_code_hash = format!(
            "{:#x}",
            B256::from(keccak256(bytes!("60016000556002600055")))
        );
        let strict_policy = FfiExecutionPolicy {
            expected_chain_id: 1,
            caller: format!(
                "{:#x}",
                MnemonicBuilder::from_phrase_nth(EXECUTION_TEST_MNEMONIC, 0).address()
            ),
            expected_pool_code_hash: Some(expected_pool_code_hash),
            expected_entrypoint_code_hash: Some(expected_entrypoint_code_hash),
            mode: Some("strict".to_owned()),
        };

        let preflighted_handle = preflight_verified_withdrawal_transaction_with_handle(
            1,
            "0x2222222222222222222222222222222222222222".to_owned(),
            rpc_server.url.clone(),
            strict_policy.clone(),
            verified_withdrawal_handle.clone(),
        )
        .unwrap();
        assert_uuid_v4(&preflighted_handle);
        let preflighted = dangerously_export_preflighted_transaction(preflighted_handle.clone());
        if cfg!(feature = "dangerous-exports") {
            assert_ffi_shape(
                "preflightedTransaction",
                json_preflighted_transaction(&preflighted.unwrap()),
            );
        } else {
            assert_dangerous_exports_disabled(preflighted);
        }

        let finalized_handle = finalize_preflighted_transaction_handle(
            rpc_server.url.clone(),
            preflighted_handle.clone(),
        )
        .unwrap();
        assert_uuid_v4(&finalized_handle);
        let finalized =
            dangerously_export_finalized_preflighted_transaction(finalized_handle.clone());
        let submitted_handle = if cfg!(feature = "dangerous-exports") {
            let finalized = finalized.unwrap();
            assert_ffi_shape(
                "finalizedPreflightedTransaction",
                json_finalized_preflighted_transaction(&finalized),
            );
            let signed_transaction = sign_finalized_request_hex(finalized.request.clone());

            let submitted_handle = submit_finalized_preflighted_transaction_handle(
                rpc_server.url.clone(),
                finalized_handle.clone(),
                signed_transaction.clone(),
            )
            .unwrap();
            assert_uuid_v4(&submitted_handle);
            assert_ffi_shape(
                "executionHandles",
                json!({
                    "preflighted": preflighted_handle.clone(),
                    "finalized": finalized_handle.clone(),
                    "submitted": submitted_handle.clone(),
                }),
            );

            let submitted =
                dangerously_export_submitted_preflighted_transaction(submitted_handle.clone())
                    .unwrap();
            assert_ffi_shape(
                "submittedPreflightedTransaction",
                json_submitted_preflighted_transaction(&submitted),
            );
            assert_ffi_shape(
                "transactionReceiptSummary",
                json_receipt_summary(&submitted.receipt),
            );
            assert_eq!(rpc_server.raw_transactions(), vec![signed_transaction]);
            Some(submitted_handle)
        } else {
            assert_dangerous_exports_disabled(finalized);
            None
        };

        let ragequit_plan = plan_verified_ragequit_transaction_with_handle(
            1,
            "0x2222222222222222222222222222222222222222".to_owned(),
            verified_ragequit_handle,
        )
        .unwrap();
        assert_ffi_shape("transactionPlan", json_transaction_plan(&ragequit_plan));

        assert!(remove_verified_proof_handle(verified_withdrawal_handle).unwrap());
        if let Some(submitted_handle) = submitted_handle {
            assert!(remove_execution_handle(submitted_handle).unwrap());
        }
        assert!(clear_execution_handles().unwrap());
        assert!(clear_verified_proof_handles().unwrap());
        assert!(clear_secret_handles().unwrap());
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
        let commitment_input = build_commitment_circuit_input(FfiCommitmentWitnessRequest {
            commitment: request.commitment.clone(),
        })
        .unwrap();

        assert_eq!(
            input.context,
            withdrawal_fixture["expected"]["context"].as_str().unwrap()
        );
        assert_eq!(
            commitment_input.value,
            withdrawal_fixture["existingValue"].as_str().unwrap()
        );
        assert_eq!(
            commitment_input.label,
            withdrawal_fixture["label"].as_str().unwrap()
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
        let ragequit_proof = FfiProofBundle {
            proof: proof.proof.clone(),
            public_signals: vec!["911".to_owned(); 4],
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
        let ragequit = plan_ragequit_transaction(
            1,
            "0x0987654321098765432109876543210987654321".to_owned(),
            ragequit_proof,
        )
        .unwrap();

        assert_eq!(withdraw.kind, "withdraw");
        assert_eq!(relay.kind, "relay");
        assert_eq!(ragequit.kind, "ragequit");
        assert_eq!(withdraw.chain_id, 1);
        assert_eq!(relay.chain_id, 1);
        assert_eq!(ragequit.chain_id, 1);
        assert!(withdraw.calldata.starts_with("0x"));
        assert!(relay.calldata.starts_with("0x"));
        assert!(ragequit.calldata.starts_with("0x"));
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
    fn ffi_rejects_invalid_withdrawal_session_artifacts() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest =
            include_str!("../../../fixtures/artifacts/sample-proving-manifest.json").to_owned();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let path_error = prepare_withdrawal_circuit_session(
            manifest.clone(),
            root.to_string_lossy().into_owned(),
        )
        .unwrap_err();
        assert!(path_error.to_string().contains("invalid zkey bundle"));

        let bytes_error = prepare_withdrawal_circuit_session_from_bytes(
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
        .unwrap_err();
        assert!(bytes_error.to_string().contains("invalid zkey bundle"));
        assert!(!remove_withdrawal_circuit_session("missing".to_owned()).unwrap());
    }

    #[test]
    fn ffi_proves_and_verifies_withdrawal_with_v1_artifacts() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest =
            include_str!("../../../fixtures/artifacts/withdrawal-proving-manifest.json").to_owned();
        let session =
            prepare_withdrawal_circuit_session(manifest, root.to_string_lossy().into_owned())
                .unwrap();
        assert_eq!(session.circuit, "withdraw");
        assert_eq!(session.artifact_version, "v1.2.0");

        let proving = prove_withdrawal_with_session(
            "stable".to_owned(),
            session.handle.clone(),
            ffi_withdrawal_request(),
        )
        .unwrap();
        assert_eq!(proving.backend, "arkworks");
        assert_eq!(proving.proof.public_signals.len(), 8);
        assert!(
            verify_withdrawal_proof_with_session(
                "stable".to_owned(),
                session.handle.clone(),
                proving.proof.clone(),
            )
            .unwrap()
        );

        let mut tampered = proving.proof;
        tampered.public_signals[0] = "9".to_owned();
        assert!(
            !verify_withdrawal_proof_with_session(
                "stable".to_owned(),
                session.handle.clone(),
                tampered,
            )
            .unwrap()
        );
        assert!(remove_withdrawal_circuit_session(session.handle).unwrap());
    }

    #[test]
    fn ffi_proves_and_verifies_commitment_with_v1_artifacts() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let manifest =
            include_str!("../../../fixtures/artifacts/commitment-proving-manifest.json").to_owned();
        let session =
            prepare_commitment_circuit_session(manifest, root.to_string_lossy().into_owned())
                .unwrap();
        assert_eq!(session.circuit, "commitment");
        assert_eq!(session.artifact_version, "v1.2.0");

        let proving = prove_commitment_with_session(
            "stable".to_owned(),
            session.handle.clone(),
            ffi_commitment_request(),
        )
        .unwrap();
        assert_eq!(proving.backend, "arkworks");
        assert_eq!(proving.proof.public_signals.len(), 4);
        assert!(
            verify_commitment_proof_with_session(
                "stable".to_owned(),
                session.handle.clone(),
                proving.proof,
            )
            .unwrap()
        );
        assert!(remove_commitment_circuit_session(session.handle).unwrap());
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
                            mode: Some("strict".to_owned()),
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

    #[test]
    fn ffi_verifies_signed_manifests_and_artifacts() {
        let (payload_json, signature_hex, public_key_hex, wrong_public_key_hex, artifact_bytes) =
            signed_manifest_fixture();

        let verified = verify_signed_manifest(
            payload_json.clone(),
            signature_hex.clone(),
            public_key_hex.clone(),
        )
        .unwrap();
        assert_eq!(verified.version, "signed-ffi-test");
        assert_eq!(verified.artifact_count, 0);
        assert_eq!(verified.build.as_deref(), Some("ffi-test"));

        let verified_artifacts = verify_signed_manifest_artifacts(
            payload_json.clone(),
            signature_hex.clone(),
            public_key_hex.clone(),
            vec![FfiSignedManifestArtifactBytes {
                filename: "signed.wasm".to_owned(),
                bytes: artifact_bytes.clone(),
            }],
        )
        .unwrap();
        assert_eq!(verified_artifacts.artifact_count, 1);
        assert_eq!(verified_artifacts.ceremony.as_deref(), Some("ffi ceremony"));

        let modified_payload = format!("{payload_json} ");
        assert!(matches!(
            verify_signed_manifest(
                modified_payload,
                signature_hex.clone(),
                public_key_hex.clone()
            ),
            Err(FfiError::OperationFailed(message)) if message.contains("signature")
        ));

        assert!(matches!(
            verify_signed_manifest(
                payload_json.clone(),
                signature_hex.clone(),
                wrong_public_key_hex,
            ),
            Err(FfiError::OperationFailed(message)) if message.contains("signature")
        ));

        assert!(matches!(
            verify_signed_manifest_artifacts(
                payload_json.clone(),
                signature_hex.clone(),
                public_key_hex.clone(),
                vec![],
            ),
            Err(FfiError::OperationFailed(message))
                if message.contains("artifact file does not exist")
                    || message.contains("missing")
        ));

        assert!(matches!(
            verify_signed_manifest_artifacts(
                payload_json.clone(),
                signature_hex.clone(),
                public_key_hex.clone(),
                vec![FfiSignedManifestArtifactBytes {
                    filename: "signed.wasm".to_owned(),
                    bytes: b"tampered".to_vec(),
                }],
            ),
            Err(FfiError::OperationFailed(message))
                if message.contains("sha256") || message.contains("hash")
        ));

        assert!(matches!(
            verify_signed_manifest_artifacts(
                payload_json,
                signature_hex,
                public_key_hex,
                vec![
                    FfiSignedManifestArtifactBytes {
                        filename: "signed.wasm".to_owned(),
                        bytes: artifact_bytes,
                    },
                    FfiSignedManifestArtifactBytes {
                        filename: "unexpected.wasm".to_owned(),
                        bytes: b"unexpected".to_vec(),
                    },
                ],
            ),
            Err(FfiError::OperationFailed(message)) if message.contains("unexpected")
        ));
    }
}
