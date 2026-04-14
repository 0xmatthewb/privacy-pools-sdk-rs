use alloy_primitives::{Address, Bytes, U256};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionPlan {
    pub chain_id: u64,
    pub target: Address,
    pub calldata: Bytes,
    pub value: U256,
    pub proof: FormattedGroth16Proof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVersion {
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
