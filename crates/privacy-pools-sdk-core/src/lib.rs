use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

pub type FieldElement = U256;
pub type Nullifier = U256;
pub type Secret = U256;
pub type Scope = U256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterKeys {
    pub master_nullifier: Secret,
    pub master_secret: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Precommitment {
    pub hash: FieldElement,
    pub nullifier: Nullifier,
    pub secret: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentPreimage {
    pub value: FieldElement,
    pub label: FieldElement,
    pub precommitment: Precommitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub hash: FieldElement,
    pub nullifier_hash: FieldElement,
    pub preimage: CommitmentPreimage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub processooor: Address,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkJsProof {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub protocol: String,
    pub curve: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundle {
    pub proof: SnarkJsProof,
    pub public_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub root: FieldElement,
    pub leaf: FieldElement,
    pub index: usize,
    pub siblings: Vec<FieldElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitMerkleWitness {
    pub root: FieldElement,
    pub leaf: FieldElement,
    pub index: usize,
    pub siblings: Vec<FieldElement>,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalWitnessRequest {
    pub commitment: Commitment,
    pub withdrawal: Withdrawal,
    pub scope: Scope,
    pub withdrawal_amount: FieldElement,
    pub state_witness: CircuitMerkleWitness,
    pub asp_witness: CircuitMerkleWitness,
    pub new_nullifier: Secret,
    pub new_secret: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalCircuitInput {
    #[serde(rename = "withdrawnValue")]
    pub withdrawn_value: FieldElement,
    #[serde(rename = "stateRoot")]
    pub state_root: FieldElement,
    #[serde(rename = "stateTreeDepth")]
    pub state_tree_depth: usize,
    #[serde(rename = "ASPRoot")]
    pub asp_root: FieldElement,
    #[serde(rename = "ASPTreeDepth")]
    pub asp_tree_depth: usize,
    pub context: FieldElement,
    pub label: FieldElement,
    #[serde(rename = "existingValue")]
    pub existing_value: FieldElement,
    #[serde(rename = "existingNullifier")]
    pub existing_nullifier: Secret,
    #[serde(rename = "existingSecret")]
    pub existing_secret: Secret,
    #[serde(rename = "newNullifier")]
    pub new_nullifier: Secret,
    #[serde(rename = "newSecret")]
    pub new_secret: Secret,
    #[serde(rename = "stateSiblings")]
    pub state_siblings: Vec<FieldElement>,
    #[serde(rename = "stateIndex")]
    pub state_index: usize,
    #[serde(rename = "ASPSiblings")]
    pub asp_siblings: Vec<FieldElement>,
    #[serde(rename = "ASPIndex")]
    pub asp_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormattedGroth16Proof {
    pub p_a: [String; 2],
    pub p_b: [[String; 2]; 2],
    pub p_c: [String; 2],
    pub pub_signals: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionKind {
    Withdraw,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionPlan {
    pub kind: TransactionKind,
    pub chain_id: u64,
    pub target: Address,
    pub calldata: Bytes,
    pub value: U256,
    pub proof: FormattedGroth16Proof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedTransactionRequest {
    pub kind: TransactionKind,
    pub chain_id: u64,
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub value: U256,
    pub data: Bytes,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVersion {
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootReadKind {
    PoolState,
    Asp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRead {
    pub kind: RootReadKind,
    pub contract_address: Address,
    pub pool_address: Address,
    pub call_data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub expected_chain_id: u64,
    pub caller: Address,
    pub expected_pool_code_hash: Option<B256>,
    pub expected_entrypoint_code_hash: Option<B256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeHashCheck {
    pub address: Address,
    pub expected_code_hash: Option<B256>,
    pub actual_code_hash: B256,
    pub matches_expected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCheck {
    pub kind: RootReadKind,
    pub contract_address: Address,
    pub pool_address: Address,
    pub expected_root: U256,
    pub actual_root: U256,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPreflightReport {
    pub kind: TransactionKind,
    pub caller: Address,
    pub target: Address,
    pub expected_chain_id: u64,
    pub actual_chain_id: u64,
    pub chain_id_matches: bool,
    pub simulated: bool,
    pub estimated_gas: u64,
    pub code_hash_checks: Vec<CodeHashCheck>,
    pub root_checks: Vec<RootCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceiptSummary {
    pub transaction_hash: B256,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub success: bool,
    pub gas_used: u64,
    pub effective_gas_price: String,
    pub from: Address,
    pub to: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalExecutionConfig {
    pub chain_id: u64,
    pub pool_address: Address,
    pub policy: ExecutionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayExecutionConfig {
    pub chain_id: u64,
    pub entrypoint_address: Address,
    pub pool_address: Address,
    pub policy: ExecutionPolicy,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("failed to parse decimal field element: {0}")]
    InvalidDecimalField(String),
    #[error("field element cannot be zero: {0}")]
    ZeroValue(&'static str),
    #[error(
        "invalid merkle witness shape for `{name}`: expected {expected} siblings, got {actual}"
    )]
    InvalidWitnessShape {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
}

pub fn parse_decimal_field(value: &str) -> Result<FieldElement, CoreError> {
    U256::from_str(value).map_err(|_| CoreError::InvalidDecimalField(value.to_owned()))
}

pub fn field_to_decimal(value: FieldElement) -> String {
    value.to_string()
}

pub fn field_to_hex_32(value: FieldElement) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}
