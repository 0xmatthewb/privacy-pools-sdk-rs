//! Core protocol types shared by the Privacy Pools Rust SDK crates.
//!
//! The published Rust crate is named `privacy-pools-sdk`, while this repository
//! is named `privacy-pools-sdk-rs` to distinguish the Rust implementation from
//! other language packages. Protocol wire formats are preserved here even when
//! Rust-facing names are cleaned up.

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use zeroize::Zeroize;

/// A field element represented as a 256-bit integer.
pub type FieldElement = U256;
/// A protocol nullifier.
pub type Nullifier = U256;
/// A Privacy Pools scope.
pub type Scope = U256;

/// A redacted field element used for secret protocol material.
///
/// `Secret` deliberately does not expose its inner value through `Debug`.
/// Use [`Secret::expose_secret`] or [`Secret::to_decimal_string`] only at
/// explicit serialization, hashing, or signing boundaries.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(U256);

impl Secret {
    /// Wraps a field element as secret material.
    pub const fn new(value: U256) -> Self {
        Self(value)
    }

    /// Explicitly exposes the raw field element.
    pub const fn expose_secret(&self) -> U256 {
        self.0
    }

    /// Returns true when the secret field element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Serializes the secret as a decimal string for circuit and FFI payloads.
    pub fn to_decimal_string(&self) -> String {
        self.0.to_string()
    }

    /// Serializes the secret as a fixed-width 32-byte hex string.
    pub fn to_hex_32(&self) -> String {
        field_to_hex_32(self.0)
    }
}

impl From<U256> for Secret {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl From<Secret> for U256 {
    fn from(value: Secret) -> Self {
        value.0
    }
}

impl PartialEq<U256> for Secret {
    fn eq(&self, other: &U256) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Secret> for U256 {
    fn eq(&self, other: &Secret) -> bool {
        *self == other.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0 = U256::ZERO;
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Root Privacy Pools key material derived from a mnemonic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterKeys {
    /// Secret seed used to derive nullifiers.
    pub master_nullifier: Secret,
    /// Secret seed used to derive commitment secrets.
    pub master_secret: Secret,
}

/// The nullifier and secret preimage used to build a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Precommitment {
    /// Poseidon hash of the nullifier and secret.
    pub hash: FieldElement,
    /// Nullifier secret for this commitment.
    pub nullifier: Nullifier,
    /// Commitment blinding secret.
    pub secret: Secret,
}

/// Full preimage for a Privacy Pools commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentPreimage {
    /// Deposited value.
    pub value: FieldElement,
    /// Association-set label.
    pub label: FieldElement,
    /// Commitment precommitment material.
    pub precommitment: Precommitment,
}

/// A Privacy Pools commitment plus the preimage needed by client-side proving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Commitment hash inserted into the pool tree.
    pub hash: FieldElement,
    /// Hash of the commitment nullifier.
    pub nullifier_hash: FieldElement,
    /// Client-side preimage for witness construction.
    pub preimage: CommitmentPreimage,
}

/// Withdrawal target data.
///
/// The Rust-facing field and constructor use `processor`. Serde keeps the
/// protocol wire spelling `processooor` for compatibility with existing
/// contracts, fixtures, and JS/mobile payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    #[serde(rename = "processooor", alias = "processor")]
    pub processor: Address,
    pub data: Bytes,
}

impl Withdrawal {
    /// Creates a withdrawal using the preferred Rust-facing `processor` name.
    pub fn new(processor: Address, data: Bytes) -> Self {
        Self { processor, data }
    }

    /// Returns the processor address.
    pub const fn processor(&self) -> Address {
        self.processor
    }

    /// Compatibility accessor for the protocol wire spelling.
    pub const fn processooor(&self) -> Address {
        self.processor
    }
}

/// Browser-compatible Groth16 proof shape emitted by snarkjs-compatible tools.
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
pub struct CommitmentWitnessRequest {
    pub commitment: Commitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentCircuitInput {
    pub value: FieldElement,
    pub label: FieldElement,
    pub nullifier: Secret,
    pub secret: Secret,
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
    Ragequit,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};

    #[test]
    fn secret_debug_is_redacted_and_explicitly_exported() {
        let secret = Secret::new(U256::from(42_u64));

        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(secret.expose_secret(), U256::from(42_u64));
        assert_eq!(secret.to_decimal_string(), "42");
    }

    #[test]
    fn secret_zeroize_clears_observable_value() {
        let mut secret = Secret::new(U256::from(42_u64));
        secret.zeroize();

        assert_eq!(secret.expose_secret(), U256::ZERO);
    }

    #[test]
    fn withdrawal_prefers_processor_but_preserves_wire_name() {
        let processor = address!("1111111111111111111111111111111111111111");
        let withdrawal = Withdrawal::new(processor, bytes!("1234"));

        assert_eq!(withdrawal.processor(), processor);
        assert_eq!(withdrawal.processooor(), processor);

        let json = serde_json::to_value(&withdrawal).expect("withdrawal serializes");
        assert_eq!(json["processooor"], processor.to_string());
        assert!(json.get("processor").is_none());

        let decoded: Withdrawal = serde_json::from_value(serde_json::json!({
            "processor": processor,
            "data": "0x1234"
        }))
        .expect("processor alias decodes");
        assert_eq!(decoded, withdrawal);
    }
}
