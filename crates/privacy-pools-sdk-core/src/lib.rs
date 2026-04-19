//! Core protocol types shared by the Privacy Pools Rust SDK crates.
//!
//! The published Rust crate is named `privacy-pools-sdk`, while this repository
//! is named `privacy-pools-sdk-rs` to distinguish the Rust implementation from
//! other language packages. Protocol wire formats are preserved here even when
//! Rust-facing names are cleaned up.

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolValue, sol};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub mod limits;
pub mod parsers;
pub mod wire;

sol! {
    struct RelayDataAbi {
        address recipient;
        address feeRecipient;
        uint256 relayFeeBPS;
    }
}

/// A field element represented as a 256-bit integer.
pub type FieldElement = U256;
/// A Privacy Pools scope.
pub type Scope = U256;

/// A redacted protocol nullifier.
///
/// Nullifiers are spend-enabling protocol material until they are hashed for
/// public signals. `Nullifier` deliberately does not expose its inner value
/// through `Debug`. Use [`Nullifier::dangerously_expose_field`],
/// [`Nullifier::to_decimal_string`], or [`Nullifier::to_hex_32`] only at
/// explicit hashing, circuit, or serialization boundaries.
#[derive(Clone, Default)]
pub struct Nullifier(Zeroizing<[u8; 32]>);

impl Nullifier {
    /// Wraps a field element as nullifier material.
    pub fn new(value: U256) -> Self {
        Self(Zeroizing::new(field_to_be_bytes(value)))
    }

    /// Explicitly exposes the raw field element.
    ///
    /// The deliberately noisy name marks this as a declassification boundary:
    /// callers should only use it for hashing, proving, verification, or
    /// compatibility wire exports.
    pub fn dangerously_expose_field(&self) -> U256 {
        field_from_be_bytes(*self.0)
    }

    /// Returns true when the nullifier field element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Serializes the nullifier as a decimal string for circuit and FFI payloads.
    pub fn to_decimal_string(&self) -> String {
        self.dangerously_expose_field().to_string()
    }

    /// Serializes the nullifier as a fixed-width 32-byte hex string.
    pub fn to_hex_32(&self) -> String {
        field_to_hex_32(self.dangerously_expose_field())
    }
}

impl From<U256> for Nullifier {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl From<&Nullifier> for Nullifier {
    fn from(value: &Nullifier) -> Self {
        value.clone()
    }
}

impl PartialEq for Nullifier {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for Nullifier {}

impl fmt::Debug for Nullifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nullifier([redacted])")
    }
}

impl Zeroize for Nullifier {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A redacted field element used for secret protocol material.
///
/// `Secret` deliberately does not expose its inner value through `Debug`.
/// Use [`Secret::dangerously_expose_field`] or [`Secret::to_decimal_string`]
/// only at explicit serialization, hashing, or signing boundaries.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    /// Wraps a field element as secret material.
    pub fn new(value: U256) -> Self {
        Self(Zeroizing::new(field_to_be_bytes(value)))
    }

    /// Explicitly exposes the raw field element.
    ///
    /// The deliberately noisy name marks this as a declassification boundary:
    /// callers should only use it for hashing, proving, verification, or
    /// compatibility wire exports.
    pub fn dangerously_expose_field(&self) -> U256 {
        field_from_be_bytes(*self.0)
    }

    /// Returns true when the secret field element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Serializes the secret as a decimal string for circuit and FFI payloads.
    pub fn to_decimal_string(&self) -> String {
        self.dangerously_expose_field().to_string()
    }

    /// Serializes the secret as a fixed-width 32-byte hex string.
    pub fn to_hex_32(&self) -> String {
        field_to_hex_32(self.dangerously_expose_field())
    }
}

impl From<U256> for Secret {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl From<&Secret> for Secret {
    fn from(value: &Secret) -> Self {
        value.clone()
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Root Privacy Pools key material derived from a mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKeys {
    /// Secret seed used to derive nullifiers.
    pub master_nullifier: Secret,
    /// Secret seed used to derive commitment secrets.
    pub master_secret: Secret,
}

/// The nullifier and secret preimage used to build a commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precommitment {
    /// Poseidon hash of the nullifier and secret.
    pub hash: FieldElement,
    /// Nullifier secret for this commitment.
    pub nullifier: Nullifier,
    /// Commitment blinding secret.
    pub secret: Secret,
}

/// Full preimage for a Privacy Pools commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentPreimage {
    /// Deposited value.
    pub value: FieldElement,
    /// Association-set label.
    pub label: FieldElement,
    /// Commitment precommitment material.
    pub precommitment: Precommitment,
}

/// A Privacy Pools commitment plus the preimage needed by client-side proving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// Commitment hash inserted into the pool tree.
    pub hash: FieldElement,
    /// Poseidon hash of the commitment nullifier and secret.
    pub precommitment_hash: FieldElement,
    /// Client-side preimage for witness construction.
    pub preimage: CommitmentPreimage,
}

/// ABI payload used by relayed withdrawals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayData {
    /// Final recipient of withdrawn funds.
    pub recipient: Address,
    /// Address receiving relay fees.
    #[serde(rename = "feeRecipient", alias = "fee_recipient")]
    pub fee_recipient: Address,
    /// Relay fee in basis points.
    #[serde(rename = "relayFeeBPS", alias = "relay_fee_bps")]
    pub relay_fee_bps: U256,
}

impl RelayData {
    /// Creates a relay payload.
    pub const fn new(recipient: Address, fee_recipient: Address, relay_fee_bps: U256) -> Self {
        Self {
            recipient,
            fee_recipient,
            relay_fee_bps,
        }
    }

    /// ABI-encodes the relay payload for [`Withdrawal::relayed`].
    pub fn encode(&self) -> Bytes {
        Bytes::from(
            RelayDataAbi {
                recipient: self.recipient,
                feeRecipient: self.fee_recipient,
                relayFeeBPS: self.relay_fee_bps,
            }
            .abi_encode(),
        )
    }
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

    /// Creates a direct pool withdrawal.
    ///
    /// In the direct path, the final recipient is also the withdrawal
    /// processor and the withdrawal data is empty.
    pub fn direct(recipient: Address) -> Self {
        Self::new(recipient, Bytes::new())
    }

    /// Creates a withdrawal processed through the entrypoint relay path.
    pub fn relayed(entrypoint: Address, relay_data: &RelayData) -> Self {
        Self::new(entrypoint, relay_data.encode())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalWitnessRequest {
    pub commitment: Commitment,
    pub withdrawal: Withdrawal,
    pub scope: Scope,
    pub withdrawal_amount: FieldElement,
    pub state_witness: CircuitMerkleWitness,
    pub asp_witness: CircuitMerkleWitness,
    pub new_nullifier: Nullifier,
    pub new_secret: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentWitnessRequest {
    pub commitment: Commitment,
}

/// Request for proving the public ragequit path.
///
/// The deployed artifact is the `commitment` circuit, because the proof exposes
/// commitment hash, nullifier hash, value, and label. The action-facing alias
/// helps Rust application code describe the protocol operation it is preparing.
pub type RagequitWitnessRequest = CommitmentWitnessRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentCircuitInput {
    pub value: FieldElement,
    pub label: FieldElement,
    pub nullifier: Nullifier,
    pub secret: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalCircuitInput {
    pub withdrawn_value: FieldElement,
    pub state_root: FieldElement,
    pub state_tree_depth: usize,
    pub asp_root: FieldElement,
    pub asp_tree_depth: usize,
    pub context: FieldElement,
    pub label: FieldElement,
    pub existing_value: FieldElement,
    pub existing_nullifier: Nullifier,
    pub existing_secret: Secret,
    pub new_nullifier: Nullifier,
    pub new_secret: Secret,
    pub state_siblings: Vec<FieldElement>,
    pub state_index: usize,
    pub asp_siblings: Vec<FieldElement>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReadConsistency {
    #[default]
    Latest,
    Finalized,
}

impl ReadConsistency {
    pub const fn is_latest(&self) -> bool {
        matches!(self, Self::Latest)
    }
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
    #[serde(default, skip_serializing_if = "ReadConsistency::is_latest")]
    pub consistency: ReadConsistency,
    pub call_data: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicyMode {
    #[default]
    Strict,
    InsecureDev,
}

impl ExecutionPolicyMode {
    pub const fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub expected_chain_id: u64,
    pub caller: Address,
    pub expected_pool_code_hash: Option<B256>,
    pub expected_entrypoint_code_hash: Option<B256>,
    #[serde(default, skip_serializing_if = "ReadConsistency::is_latest")]
    pub read_consistency: ReadConsistency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_quote_wei: Option<u128>,
    #[serde(default, skip_serializing_if = "ExecutionPolicyMode::is_strict")]
    pub mode: ExecutionPolicyMode,
}

impl ExecutionPolicy {
    pub const fn strict(
        expected_chain_id: u64,
        caller: Address,
        pool_code_hash: B256,
        entrypoint_code_hash: B256,
    ) -> Self {
        Self {
            expected_chain_id,
            caller,
            expected_pool_code_hash: Some(pool_code_hash),
            expected_entrypoint_code_hash: Some(entrypoint_code_hash),
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: ExecutionPolicyMode::Strict,
        }
    }

    pub const fn insecure_dev(expected_chain_id: u64, caller: Address) -> Self {
        Self {
            expected_chain_id,
            caller,
            expected_pool_code_hash: None,
            expected_entrypoint_code_hash: None,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: ExecutionPolicyMode::InsecureDev,
        }
    }

    pub const fn is_insecure_dev(&self) -> bool {
        matches!(self.mode, ExecutionPolicyMode::InsecureDev)
    }
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
    #[serde(default, skip_serializing_if = "ReadConsistency::is_latest")]
    pub read_consistency: ReadConsistency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_quote_wei: Option<u128>,
    #[serde(default)]
    pub mode: ExecutionPolicyMode,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RagequitExecutionConfig {
    pub chain_id: u64,
    pub pool_address: Address,
    pub policy: ExecutionPolicy,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("failed to parse decimal field element: {0}")]
    InvalidDecimalField(String),
    #[error("failed to parse address: {0}")]
    InvalidAddress(String),
    #[error("failed to parse hex bytes: {0}")]
    InvalidHexBytes(String),
    #[error("invalid execution policy mode: {0}")]
    InvalidExecutionPolicyMode(String),
    #[error("invalid read consistency: {0}")]
    InvalidReadConsistency(String),
    #[error("commitment nullifier hash compatibility field must match precommitment hash")]
    MismatchedCommitmentCompatibilityHash,
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

pub fn field_to_be_bytes(value: FieldElement) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

pub fn field_from_be_bytes(bytes: [u8; 32]) -> FieldElement {
    U256::from_be_slice(&bytes)
}

pub fn field_to_hex_32(value: FieldElement) -> String {
    format!("0x{}", hex::encode(field_to_be_bytes(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};

    #[test]
    fn secret_debug_is_redacted_and_explicitly_exported() {
        let secret = Secret::new(U256::from(42_u64));

        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(secret.dangerously_expose_field(), U256::from(42_u64));
        assert_eq!(secret.to_decimal_string(), "42");
    }

    #[test]
    fn secret_zeroize_clears_observable_value() {
        let mut secret = Secret::new(U256::from(42_u64));
        secret.zeroize();

        assert_eq!(secret.dangerously_expose_field(), U256::ZERO);
    }

    #[test]
    fn nullifier_debug_is_redacted_and_explicitly_exported() {
        let nullifier = Nullifier::new(U256::from(42_u64));

        assert_eq!(format!("{nullifier:?}"), "Nullifier([redacted])");
        assert_eq!(nullifier.dangerously_expose_field(), U256::from(42_u64));
        assert_eq!(nullifier.to_decimal_string(), "42");
    }

    #[test]
    fn nullifier_zeroize_clears_observable_value() {
        let mut nullifier = Nullifier::new(U256::from(42_u64));
        nullifier.zeroize();

        assert_eq!(nullifier.dangerously_expose_field(), U256::ZERO);
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

    #[test]
    fn withdrawal_constructors_model_direct_and_relay_paths() {
        let recipient = address!("2222222222222222222222222222222222222222");
        let entrypoint = address!("3333333333333333333333333333333333333333");
        let fee_recipient = address!("4444444444444444444444444444444444444444");

        let direct = Withdrawal::direct(recipient);
        assert_eq!(direct.processor(), recipient);
        assert!(direct.data.is_empty());

        let relay_data = RelayData::new(recipient, fee_recipient, U256::from(25_u64));
        let relayed = Withdrawal::relayed(entrypoint, &relay_data);
        let decoded = RelayDataAbi::abi_decode(relayed.data.as_ref()).expect("relay data decodes");

        assert_eq!(relayed.processor(), entrypoint);
        assert_eq!(decoded.recipient, recipient);
        assert_eq!(decoded.feeRecipient, fee_recipient);
        assert_eq!(decoded.relayFeeBPS, U256::from(25_u64));
    }

    #[test]
    fn commitment_wire_exports_v1_compatibility_hashes() {
        let commitment = Commitment {
            hash: U256::from(1_u64),
            precommitment_hash: U256::from(2_u64),
            preimage: CommitmentPreimage {
                value: U256::from(3_u64),
                label: U256::from(4_u64),
                precommitment: Precommitment {
                    hash: U256::from(2_u64),
                    nullifier: U256::from(5_u64).into(),
                    secret: U256::from(6_u64).into(),
                },
            },
        };

        let wire = wire::WireCommitment::from(&commitment);
        let json = serde_json::to_value(&wire).expect("wire commitment serializes");
        assert_eq!(json["precommitmentHash"], "2");
        assert_eq!(json["nullifierHash"], "2");

        let decoded: Commitment = serde_json::from_value::<wire::WireCommitment>(json)
            .expect("wire commitment decodes")
            .try_into()
            .expect("wire commitment converts");
        assert_eq!(decoded, commitment);

        let legacy_json = serde_json::json!({
            "hash": "1",
            "nullifier_hash": "2",
            "value": "3",
            "label": "4",
            "nullifier": "5",
            "secret": "6"
        });
        let decoded: Commitment = serde_json::from_value::<wire::WireCommitment>(legacy_json)
            .expect("legacy wire commitment decodes")
            .try_into()
            .expect("legacy wire commitment converts");
        assert_eq!(decoded, commitment);
    }

    #[test]
    fn execution_preflight_report_defaults_missing_mode_to_strict() {
        let report: ExecutionPreflightReport = serde_json::from_value(serde_json::json!({
            "kind": "withdraw",
            "caller": "0x1111111111111111111111111111111111111111",
            "target": "0x2222222222222222222222222222222222222222",
            "expected_chain_id": 1,
            "actual_chain_id": 1,
            "chain_id_matches": true,
            "simulated": true,
            "estimated_gas": 1234,
            "code_hash_checks": [],
            "root_checks": []
        }))
        .expect("legacy report decodes");

        assert_eq!(report.mode, ExecutionPolicyMode::Strict);
        assert_eq!(report.read_consistency, ReadConsistency::Latest);
        assert_eq!(report.max_fee_quote_wei, None);
    }

    #[test]
    fn field_bytes_roundtrip_big_endian_boundaries() {
        let values = [
            U256::ZERO,
            U256::from(1_u64),
            U256::from_be_slice(&[0, 0, 0, 7]),
            U256::MAX,
            U256::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            )
            .expect("bn254 scalar field modulus parses"),
        ];

        for value in values {
            let bytes = field_to_be_bytes(value);
            assert_eq!(field_from_be_bytes(bytes), value);
            assert_eq!(Secret::new(value).dangerously_expose_field(), value);
            assert_eq!(Nullifier::new(value).dangerously_expose_field(), value);
        }
    }
}
