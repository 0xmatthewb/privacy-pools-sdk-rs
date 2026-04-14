use alloy_primitives::{Address, U256};
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{ArtifactKind, ArtifactManifest, ArtifactStatus, ResolvedArtifactBundle},
    core::{
        CircuitMerkleWitness, Commitment, FormattedGroth16Proof, MasterKeys, MerkleProof,
        ProofBundle, RootReadKind, SnarkJsProof, Withdrawal, WithdrawalCircuitInput,
        WithdrawalWitnessRequest,
    },
    recovery::{CompatibilityMode, PoolEvent, RecoveryPolicy},
};
use std::{path::PathBuf, str::FromStr};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid field element: {0}")]
    InvalidField(String),
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(String),
    #[error("invalid artifact kind: {0}")]
    InvalidArtifactKind(String),
    #[error("invalid compatibility mode: {0}")]
    InvalidCompatibilityMode(String),
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
pub struct FfiFormattedGroth16Proof {
    pub p_a: Vec<String>,
    pub p_b: Vec<Vec<String>>,
    pub p_c: Vec<String>,
    pub pub_signals: Vec<String>,
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

fn sdk() -> PrivacyPoolsSdk {
    PrivacyPoolsSdk::default()
}

fn parse_address(value: &str) -> Result<Address, FfiError> {
    Address::from_str(value).map_err(|_| FfiError::InvalidAddress(value.to_owned()))
}

fn parse_field(value: &str) -> Result<U256, FfiError> {
    U256::from_str(value).map_err(|_| FfiError::InvalidField(value.to_owned()))
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
    use serde_json::Value;

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .expect("valid ffi fixture")
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

        let input = build_withdrawal_circuit_input(FfiWithdrawalWitnessRequest {
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
        })
        .unwrap();

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
        assert_eq!(input.state_tree_depth, 32);
        assert_eq!(input.asp_tree_depth, 32);
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
}
