use alloy_consensus::{
    Transaction as ConsensusTransaction, TxEnvelope, transaction::SignerRecoverable,
};
use alloy_eips::{BlockId, Decodable2718};
use alloy_network::{Ethereum, ReceiptResponse};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_sol_types::{SolCall, SolValue, sol};
use async_trait::async_trait;
use privacy_pools_sdk_core::{
    CodeHashCheck, ExecutionPolicy, ExecutionPreflightReport, FinalizedTransactionRequest,
    FormattedGroth16Proof, ProofBundle, ReadConsistency, RootCheck, RootRead, RootReadKind,
    TransactionKind, TransactionPlan, TransactionReceiptSummary, Withdrawal, field_to_hex_32,
    parse_decimal_field,
};
#[cfg(feature = "local-signer-client")]
use privacy_pools_sdk_signer::{LocalMnemonicSigner, SignerAdapter};
use serde_json::Value;
use std::sync::LazyLock;
use thiserror::Error;
use url::Url;

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
        function ENTRYPOINT() external view returns (address);
        function currentRoot() external view returns (uint256);
        function currentRootIndex() external view returns (uint32);
        function roots(uint256 index) external view returns (uint256);
        function withdraw(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof) external;
        function ragequit(RagequitProofAbi _proof) external;
    }

    interface IEntrypoint {
        function latestRoot() external view returns (uint256);
        function relay(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof, uint256 scope) external;
    }
}

const ROOT_HISTORY_SIZE: u32 = 64;
pub const WITHDRAW_PUBLIC_SIGNAL_COUNT: usize = 8;
pub const RAGEQUIT_PUBLIC_SIGNAL_COUNT: usize = 4;

static WITHDRAW_VKEY_PUBLIC_SIGNAL_COUNT: LazyLock<usize> = LazyLock::new(|| {
    parse_vkey_public_signal_count(include_str!(
        "../../../fixtures/artifacts/withdraw.vkey.json"
    ))
    .expect("withdraw verification key should declare nPublic")
});

#[derive(Debug, Error)]
pub enum ChainError {
    #[error(transparent)]
    Core(#[from] privacy_pools_sdk_core::CoreError),
    #[error("withdraw proof must contain exactly 8 public signals, got {0}")]
    InvalidWithdrawPublicSignals(usize),
    #[error("ragequit proof must contain exactly 4 public signals, got {0}")]
    InvalidRagequitPublicSignals(usize),
    #[error(
        "{circuit} verification key expects {actual} public signals but formatter expects {expected}"
    )]
    PublicSignalCountDrift {
        circuit: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("withdraw proof public signal mismatch for {field}: expected {expected}, got {actual}")]
    WithdrawProofSignalMismatch {
        field: &'static str,
        expected: U256,
        actual: U256,
    },
    #[error("proof field `{field}` is not canonical: {value} >= {modulus}")]
    NonCanonicalProofField {
        field: String,
        value: U256,
        modulus: U256,
    },
    #[error("relay transactions require a non-zero withdrawn value")]
    RelayRequiresNonZeroWithdrawValue,
    #[error("relay withdrawal processooor mismatch: expected {expected}, got {actual}")]
    RelayProcessooorMismatch { expected: Address, actual: Address },
    #[error("relay withdrawal data is invalid: {0}")]
    InvalidRelayData(String),
    #[error("{field} must be non-zero")]
    ZeroAddress { field: &'static str },
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(String),
    #[error("invalid root response length: expected at least 32 bytes, got {0}")]
    InvalidRootResponse(usize),
    #[error("invalid address response word: {0}")]
    InvalidAddressResponse(U256),
    #[error("planned transaction kind mismatch: expected {expected:?}, got {actual:?}")]
    UnexpectedTransactionKind {
        expected: TransactionKind,
        actual: TransactionKind,
    },
    #[error("planned transaction target mismatch: expected {expected}, got {actual}")]
    UnexpectedTransactionTarget { expected: Address, actual: Address },
    #[error("planned transaction chain id mismatch: expected {expected}, got {actual}")]
    PlannedChainIdMismatch { expected: u64, actual: u64 },
    #[error("live chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
    #[error("contract code hash mismatch at {address}: expected {expected}, got {actual}")]
    CodeHashMismatch {
        address: Address,
        expected: B256,
        actual: B256,
    },
    #[error("missing required code hash expectation for contract at {address}")]
    MissingCodeHashExpectation { address: Address },
    #[error("state root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: U256, actual: U256 },
    #[error("asp root mismatch: expected {expected}, got {actual}")]
    AspRootMismatch { expected: U256, actual: U256 },
    #[error("pool entrypoint mismatch for {pool}: expected {expected}, got {actual}")]
    EntrypointMismatch {
        pool: Address,
        expected: Address,
        actual: Address,
    },
    #[error("submission signer mismatch: expected caller {expected}, got {actual}")]
    SignerAddressMismatch { expected: Address, actual: Address },
    #[error("transaction submission failed: {0}")]
    Submission(String),
    #[error("waiting for receipt failed for {transaction_hash}: {message}")]
    PendingTransaction {
        transaction_hash: B256,
        message: String,
    },
    #[error("failed to decode signed transaction: {0}")]
    InvalidSignedTransaction(String),
    #[error("signed transaction signer mismatch: expected {expected}, got {actual}")]
    SignedTransactionSignerMismatch { expected: Address, actual: Address },
    #[error("signed transaction field mismatch for {field}: expected {expected}, got {actual}")]
    SignedTransactionFieldMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("quoted fee `{field}` exceeds configured cap: quoted {quoted}, cap {cap}")]
    FeeQuoteExceedsCap {
        field: &'static str,
        quoted: u128,
        cap: u128,
    },
    #[error("rpc request failed: {0}")]
    Transport(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeParameters {
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
}

#[async_trait]
pub trait ExecutionClient: Send + Sync {
    async fn chain_id(&self) -> Result<u64, ChainError>;
    async fn code_hash(
        &self,
        address: Address,
        consistency: ReadConsistency,
    ) -> Result<B256, ChainError>;
    async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError>;
    async fn simulate_transaction(
        &self,
        caller: Address,
        plan: &TransactionPlan,
    ) -> Result<u64, ChainError>;
}

#[async_trait]
pub trait SubmissionClient: ExecutionClient {
    fn caller(&self) -> Address;
    async fn submit_transaction(
        &self,
        plan: &TransactionPlan,
    ) -> Result<TransactionReceiptSummary, ChainError>;
}

#[async_trait]
pub trait FinalizationClient: ExecutionClient {
    async fn next_nonce(&self, caller: Address) -> Result<u64, ChainError>;
    async fn fee_parameters(&self) -> Result<FeeParameters, ChainError>;
    async fn submit_raw_transaction(
        &self,
        encoded_tx: &[u8],
    ) -> Result<TransactionReceiptSummary, ChainError>;
}

pub struct HttpExecutionClient {
    provider: DynProvider<Ethereum>,
}

#[cfg(feature = "local-signer-client")]
pub struct LocalSignerExecutionClient {
    provider: DynProvider<Ethereum>,
    caller: Address,
}

impl HttpExecutionClient {
    pub fn new(rpc_url: &str) -> Result<Self, ChainError> {
        let url = Url::parse(rpc_url).map_err(|_| ChainError::InvalidRpcUrl(rpc_url.to_owned()))?;
        Ok(Self {
            provider: ProviderBuilder::new().connect_http(url).erased(),
        })
    }
}

#[cfg(feature = "local-signer-client")]
impl LocalSignerExecutionClient {
    pub fn new(rpc_url: &str, signer: &LocalMnemonicSigner) -> Result<Self, ChainError> {
        let url = Url::parse(rpc_url).map_err(|_| ChainError::InvalidRpcUrl(rpc_url.to_owned()))?;
        let caller = signer.address();

        Ok(Self {
            provider: ProviderBuilder::new()
                .wallet(signer.clone_private_key_signer_for_local_client())
                .connect_http(url)
                .erased(),
            caller,
        })
    }
}

#[async_trait]
impl ExecutionClient for HttpExecutionClient {
    async fn chain_id(&self) -> Result<u64, ChainError> {
        self.provider
            .get_chain_id()
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }

    async fn code_hash(
        &self,
        address: Address,
        consistency: ReadConsistency,
    ) -> Result<B256, ChainError> {
        let code = self
            .provider
            .get_code_at(address)
            .block_id(block_id_for_consistency(consistency))
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        Ok(keccak256(code))
    }

    async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError> {
        let output = self
            .provider
            .call(root_read_request(read))
            .block(block_id_for_consistency(read.consistency))
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        decode_root_response(&output)
    }

    async fn simulate_transaction(
        &self,
        caller: Address,
        plan: &TransactionPlan,
    ) -> Result<u64, ChainError> {
        let request = transaction_request(plan, caller);
        self.provider
            .call(request.clone())
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        self.provider
            .estimate_gas(request)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }
}

#[async_trait]
impl FinalizationClient for HttpExecutionClient {
    async fn next_nonce(&self, caller: Address) -> Result<u64, ChainError> {
        self.provider
            .get_transaction_count(caller)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }

    async fn fee_parameters(&self) -> Result<FeeParameters, ChainError> {
        match self.provider.estimate_eip1559_fees().await {
            Ok(fees) => Ok(FeeParameters {
                gas_price: None,
                max_fee_per_gas: Some(fees.max_fee_per_gas),
                max_priority_fee_per_gas: Some(fees.max_priority_fee_per_gas),
            }),
            Err(_) => self
                .provider
                .get_gas_price()
                .await
                .map(|gas_price| FeeParameters {
                    gas_price: Some(gas_price),
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                })
                .map_err(|error| ChainError::Transport(error.to_string())),
        }
    }

    async fn submit_raw_transaction(
        &self,
        encoded_tx: &[u8],
    ) -> Result<TransactionReceiptSummary, ChainError> {
        let pending = self
            .provider
            .send_raw_transaction(encoded_tx)
            .await
            .map_err(|error| ChainError::Submission(error.to_string()))?;
        let transaction_hash = *pending.tx_hash();
        let receipt =
            pending
                .get_receipt()
                .await
                .map_err(|error| ChainError::PendingTransaction {
                    transaction_hash,
                    message: error.to_string(),
                })?;

        Ok(receipt_summary(receipt))
    }
}

#[async_trait]
#[cfg(feature = "local-signer-client")]
impl ExecutionClient for LocalSignerExecutionClient {
    async fn chain_id(&self) -> Result<u64, ChainError> {
        self.provider
            .get_chain_id()
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }

    async fn code_hash(
        &self,
        address: Address,
        consistency: ReadConsistency,
    ) -> Result<B256, ChainError> {
        let code = self
            .provider
            .get_code_at(address)
            .block_id(block_id_for_consistency(consistency))
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        Ok(keccak256(code))
    }

    async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError> {
        let output = self
            .provider
            .call(root_read_request(read))
            .block(block_id_for_consistency(read.consistency))
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        decode_root_response(&output)
    }

    async fn simulate_transaction(
        &self,
        caller: Address,
        plan: &TransactionPlan,
    ) -> Result<u64, ChainError> {
        let request = transaction_request(plan, caller);
        self.provider
            .call(request.clone())
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        self.provider
            .estimate_gas(request)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }
}

#[async_trait]
#[cfg(feature = "local-signer-client")]
impl FinalizationClient for LocalSignerExecutionClient {
    async fn next_nonce(&self, caller: Address) -> Result<u64, ChainError> {
        self.provider
            .get_transaction_count(caller)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }

    async fn fee_parameters(&self) -> Result<FeeParameters, ChainError> {
        match self.provider.estimate_eip1559_fees().await {
            Ok(fees) => Ok(FeeParameters {
                gas_price: None,
                max_fee_per_gas: Some(fees.max_fee_per_gas),
                max_priority_fee_per_gas: Some(fees.max_priority_fee_per_gas),
            }),
            Err(_) => self
                .provider
                .get_gas_price()
                .await
                .map(|gas_price| FeeParameters {
                    gas_price: Some(gas_price),
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                })
                .map_err(|error| ChainError::Transport(error.to_string())),
        }
    }

    async fn submit_raw_transaction(
        &self,
        encoded_tx: &[u8],
    ) -> Result<TransactionReceiptSummary, ChainError> {
        let pending = self
            .provider
            .send_raw_transaction(encoded_tx)
            .await
            .map_err(|error| ChainError::Submission(error.to_string()))?;
        let transaction_hash = *pending.tx_hash();
        let receipt =
            pending
                .get_receipt()
                .await
                .map_err(|error| ChainError::PendingTransaction {
                    transaction_hash,
                    message: error.to_string(),
                })?;

        Ok(receipt_summary(receipt))
    }
}

#[async_trait]
#[cfg(feature = "local-signer-client")]
impl SubmissionClient for LocalSignerExecutionClient {
    fn caller(&self) -> Address {
        self.caller
    }

    async fn submit_transaction(
        &self,
        plan: &TransactionPlan,
    ) -> Result<TransactionReceiptSummary, ChainError> {
        let request = transaction_request(plan, self.caller);
        let pending = self
            .provider
            .send_transaction(request)
            .await
            .map_err(|error| ChainError::Submission(error.to_string()))?;
        let transaction_hash = *pending.tx_hash();
        let receipt =
            pending
                .get_receipt()
                .await
                .map_err(|error| ChainError::PendingTransaction {
                    transaction_hash,
                    message: error.to_string(),
                })?;

        Ok(receipt_summary(receipt))
    }
}

pub fn format_groth16_proof(proof: &ProofBundle) -> Result<FormattedGroth16Proof, ChainError> {
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
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn withdraw_public_signals(proof: &ProofBundle) -> Result<[U256; 8], ChainError> {
    ensure_public_signal_count(
        "withdraw",
        *WITHDRAW_VKEY_PUBLIC_SIGNAL_COUNT,
        WITHDRAW_PUBLIC_SIGNAL_COUNT,
    )?;
    let public_signals = proof
        .public_signals
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_public_signal(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    public_signals
        .try_into()
        .map_err(|signals: Vec<U256>| ChainError::InvalidWithdrawPublicSignals(signals.len()))
}

pub fn ragequit_public_signals(proof: &ProofBundle) -> Result<[U256; 4], ChainError> {
    let public_signals = proof
        .public_signals
        .iter()
        .enumerate()
        .map(|(index, value)| parse_bn254_public_signal(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    public_signals
        .try_into()
        .map_err(|signals: Vec<U256>| ChainError::InvalidRagequitPublicSignals(signals.len()))
}

fn parse_bn254_proof_coordinate(value: &str, field: &str) -> Result<U256, ChainError> {
    let parsed = parse_decimal_field(value)?;
    ensure_canonical_proof_field(field.to_owned(), parsed, bn254_base_field_modulus())?;
    Ok(parsed)
}

fn parse_bn254_public_signal(value: &str, index: usize) -> Result<U256, ChainError> {
    let parsed = parse_decimal_field(value)?;
    ensure_canonical_proof_field(
        format!("publicSignals[{index}]"),
        parsed,
        bn254_scalar_field_modulus(),
    )?;
    Ok(parsed)
}

fn ensure_canonical_proof_field(
    field: String,
    value: U256,
    modulus: U256,
) -> Result<(), ChainError> {
    if value >= modulus {
        return Err(ChainError::NonCanonicalProofField {
            field,
            value,
            modulus,
        });
    }
    Ok(())
}

fn bn254_base_field_modulus() -> U256 {
    parse_decimal_field(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .expect("valid BN254 base field modulus")
}

fn bn254_scalar_field_modulus() -> U256 {
    parse_decimal_field(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("valid BN254 scalar field modulus")
}

pub fn state_root_read(pool_address: Address, consistency: ReadConsistency) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        consistency,
        call_data: Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode()),
    }
}

pub fn asp_root_read(
    entrypoint_address: Address,
    pool_address: Address,
    consistency: ReadConsistency,
) -> RootRead {
    RootRead {
        kind: RootReadKind::Asp,
        contract_address: entrypoint_address,
        pool_address,
        consistency,
        call_data: Bytes::from(IEntrypoint::latestRootCall {}.abi_encode()),
    }
}

fn pool_entrypoint_read(pool_address: Address, consistency: ReadConsistency) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        consistency,
        call_data: Bytes::from(IPrivacyPool::ENTRYPOINTCall {}.abi_encode()),
    }
}

pub fn is_current_state_root(expected_root: U256, current_root: U256) -> bool {
    expected_root == current_root
}

pub fn plan_withdrawal_transaction(
    chain_id: u64,
    pool_address: Address,
    withdrawal: &Withdrawal,
    proof: &ProofBundle,
) -> Result<TransactionPlan, ChainError> {
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

pub fn plan_relay_transaction(
    chain_id: u64,
    entrypoint_address: Address,
    withdrawal: &Withdrawal,
    proof: &ProofBundle,
    scope: U256,
) -> Result<TransactionPlan, ChainError> {
    ensure_non_zero_address(entrypoint_address, "entrypoint address")?;

    if withdrawal.processor != entrypoint_address {
        return Err(ChainError::RelayProcessooorMismatch {
            expected: entrypoint_address,
            actual: withdrawal.processor,
        });
    }

    parse_relay_data(&withdrawal.data)?;

    // Relay enforces a non-zero withdrawn value at the contract boundary,
    // while direct withdraw and ragequit flows intentionally allow zero values.
    let public_signals = withdraw_public_signals(proof)?;
    if public_signals[2].is_zero() {
        return Err(ChainError::RelayRequiresNonZeroWithdrawValue);
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

pub fn plan_ragequit_transaction(
    chain_id: u64,
    pool_address: Address,
    proof: &ProofBundle,
) -> Result<TransactionPlan, ChainError> {
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

fn parse_relay_data(data: &Bytes) -> Result<RelayDataAbi, ChainError> {
    let relay_data = RelayDataAbi::abi_decode(data.as_ref())
        .map_err(|error| ChainError::InvalidRelayData(error.to_string()))?;

    if relay_data.recipient.is_zero() {
        return Err(ChainError::InvalidRelayData(
            "recipient must be non-zero".to_owned(),
        ));
    }

    if relay_data.feeRecipient.is_zero() {
        return Err(ChainError::InvalidRelayData(
            "fee recipient must be non-zero".to_owned(),
        ));
    }

    Ok(relay_data)
}

#[doc(hidden)]
pub fn decode_relay_data(data: &Bytes) -> Result<(), ChainError> {
    parse_relay_data(data).map(|_| ())
}

fn ensure_public_signal_count(
    circuit: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ChainError> {
    if actual != expected {
        return Err(ChainError::PublicSignalCountDrift {
            circuit,
            expected,
            actual,
        });
    }
    Ok(())
}

fn parse_vkey_public_signal_count(vkey_json: &str) -> Result<usize, ChainError> {
    let json: Value = serde_json::from_str(vkey_json)
        .map_err(|error| ChainError::InvalidRelayData(error.to_string()))?;
    let count = json.get("nPublic").and_then(Value::as_u64).ok_or_else(|| {
        ChainError::InvalidRelayData("verification key missing nPublic".to_owned())
    })?;
    usize::try_from(count).map_err(|_| {
        ChainError::InvalidRelayData("verification key nPublic exceeds usize".to_owned())
    })
}

pub async fn preflight_withdrawal<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    pool_address: Address,
    expected_state_root: U256,
    expected_asp_root: U256,
    policy: &ExecutionPolicy,
) -> Result<ExecutionPreflightReport, ChainError> {
    ensure_non_zero_address(pool_address, "pool address")?;
    let entrypoint_address =
        read_pool_entrypoint_address(client, pool_address, policy.read_consistency).await?;

    preflight_transaction(
        client,
        plan,
        TransactionKind::Withdraw,
        pool_address,
        policy,
        vec![
            (
                state_root_read(pool_address, policy.read_consistency),
                expected_state_root,
                ChainError::StateRootMismatch {
                    expected: expected_state_root,
                    actual: expected_state_root,
                },
            ),
            (
                asp_root_read(entrypoint_address, pool_address, policy.read_consistency),
                expected_asp_root,
                ChainError::AspRootMismatch {
                    expected: expected_asp_root,
                    actual: expected_asp_root,
                },
            ),
        ],
        vec![
            (pool_address, policy.expected_pool_code_hash),
            (entrypoint_address, policy.expected_entrypoint_code_hash),
        ],
    )
    .await
}

pub async fn preflight_relay<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    entrypoint_address: Address,
    pool_address: Address,
    expected_state_root: U256,
    expected_asp_root: U256,
    policy: &ExecutionPolicy,
) -> Result<ExecutionPreflightReport, ChainError> {
    ensure_non_zero_address(entrypoint_address, "entrypoint address")?;
    ensure_non_zero_address(pool_address, "pool address")?;
    verify_pool_entrypoint_address(
        client,
        pool_address,
        entrypoint_address,
        policy.read_consistency,
    )
    .await?;
    preflight_transaction(
        client,
        plan,
        TransactionKind::Relay,
        entrypoint_address,
        policy,
        vec![
            (
                state_root_read(pool_address, policy.read_consistency),
                expected_state_root,
                ChainError::StateRootMismatch {
                    expected: expected_state_root,
                    actual: expected_state_root,
                },
            ),
            (
                asp_root_read(entrypoint_address, pool_address, policy.read_consistency),
                expected_asp_root,
                ChainError::AspRootMismatch {
                    expected: expected_asp_root,
                    actual: expected_asp_root,
                },
            ),
        ],
        vec![
            (pool_address, policy.expected_pool_code_hash),
            (entrypoint_address, policy.expected_entrypoint_code_hash),
        ],
    )
    .await
}

pub async fn preflight_ragequit<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    pool_address: Address,
    policy: &ExecutionPolicy,
) -> Result<ExecutionPreflightReport, ChainError> {
    ensure_non_zero_address(pool_address, "pool address")?;

    preflight_transaction(
        client,
        plan,
        TransactionKind::Ragequit,
        pool_address,
        policy,
        vec![],
        vec![(pool_address, policy.expected_pool_code_hash)],
    )
    .await
}

pub async fn reconfirm_preflight<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    report: &ExecutionPreflightReport,
) -> Result<ExecutionPreflightReport, ChainError> {
    validate_plan(plan, report.kind, report.target, report.expected_chain_id)?;

    let actual_chain_id = client.chain_id().await?;
    if actual_chain_id != report.expected_chain_id {
        return Err(ChainError::ChainIdMismatch {
            expected: report.expected_chain_id,
            actual: actual_chain_id,
        });
    }

    let mut code_hash_checks = Vec::with_capacity(report.code_hash_checks.len());
    for check in &report.code_hash_checks {
        if report.mode.is_strict() && check.expected_code_hash.is_none() {
            return Err(ChainError::MissingCodeHashExpectation {
                address: check.address,
            });
        }
        let actual_code_hash = client
            .code_hash(check.address, report.read_consistency)
            .await?;
        let matches_expected = if let Some(expected_code_hash) = check.expected_code_hash {
            if expected_code_hash != actual_code_hash {
                return Err(ChainError::CodeHashMismatch {
                    address: check.address,
                    expected: expected_code_hash,
                    actual: actual_code_hash,
                });
            }
            Some(true)
        } else {
            None
        };

        code_hash_checks.push(CodeHashCheck {
            address: check.address,
            expected_code_hash: check.expected_code_hash,
            actual_code_hash,
            matches_expected,
        });
    }

    if report.kind == TransactionKind::Relay {
        let pool_address = report
            .root_checks
            .iter()
            .find(|check| check.kind == RootReadKind::PoolState)
            .map(|check| check.pool_address)
            .ok_or_else(|| {
                ChainError::Transport(
                    "relay preflight report is missing a pool state root check".to_owned(),
                )
            })?;
        verify_pool_entrypoint_address(
            client,
            pool_address,
            report.target,
            report.read_consistency,
        )
        .await?;
    }

    let mut root_checks = Vec::with_capacity(report.root_checks.len());
    for check in &report.root_checks {
        match check.kind {
            RootReadKind::PoolState => {
                let actual_root = verify_known_pool_root(
                    client,
                    check.pool_address,
                    check.expected_root,
                    report.read_consistency,
                )
                .await?;
                root_checks.push(RootCheck {
                    kind: check.kind,
                    contract_address: check.contract_address,
                    pool_address: check.pool_address,
                    expected_root: check.expected_root,
                    actual_root,
                    matches: true,
                });
            }
            RootReadKind::Asp => {
                let read = RootRead {
                    kind: check.kind,
                    contract_address: check.contract_address,
                    pool_address: check.pool_address,
                    consistency: report.read_consistency,
                    call_data: root_call_data(
                        check.kind,
                        check.contract_address,
                        check.pool_address,
                    ),
                };
                let actual_root = client.read_root(&read).await?;
                if actual_root != check.expected_root {
                    return Err(ChainError::AspRootMismatch {
                        expected: check.expected_root,
                        actual: actual_root,
                    });
                }

                root_checks.push(RootCheck {
                    kind: check.kind,
                    contract_address: check.contract_address,
                    pool_address: check.pool_address,
                    expected_root: check.expected_root,
                    actual_root,
                    matches: true,
                });
            }
        }
    }

    let estimated_gas = client.simulate_transaction(report.caller, plan).await?;

    Ok(ExecutionPreflightReport {
        kind: plan.kind,
        caller: report.caller,
        target: plan.target,
        expected_chain_id: report.expected_chain_id,
        actual_chain_id,
        chain_id_matches: true,
        simulated: true,
        estimated_gas,
        read_consistency: report.read_consistency,
        max_fee_quote_wei: report.max_fee_quote_wei,
        mode: report.mode,
        code_hash_checks,
        root_checks,
    })
}

pub async fn finalize_transaction<C: FinalizationClient>(
    client: &C,
    plan: &TransactionPlan,
    report: &ExecutionPreflightReport,
) -> Result<(ExecutionPreflightReport, FinalizedTransactionRequest), ChainError> {
    let refreshed_preflight = reconfirm_preflight(client, plan, report).await?;
    let fees = client.fee_parameters().await?;
    let nonce = client.next_nonce(refreshed_preflight.caller).await?;
    enforce_fee_cap(refreshed_preflight.max_fee_quote_wei, &fees)?;

    Ok((
        refreshed_preflight.clone(),
        FinalizedTransactionRequest {
            kind: plan.kind,
            chain_id: plan.chain_id,
            from: refreshed_preflight.caller,
            to: plan.target,
            nonce,
            gas_limit: refreshed_preflight.estimated_gas,
            value: plan.value,
            data: plan.calldata.clone(),
            gas_price: fees.gas_price,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        },
    ))
}

pub async fn submit_signed_transaction<C: FinalizationClient>(
    client: &C,
    request: &FinalizedTransactionRequest,
    encoded_tx: &[u8],
) -> Result<TransactionReceiptSummary, ChainError> {
    validate_signed_transaction_request(encoded_tx, request)?;
    client.submit_raw_transaction(encoded_tx).await
}

pub fn validate_signed_transaction_request(
    encoded_tx: &[u8],
    request: &FinalizedTransactionRequest,
) -> Result<(), ChainError> {
    validate_signed_transaction(encoded_tx, request)
}

async fn preflight_transaction<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    expected_kind: TransactionKind,
    expected_target: Address,
    policy: &ExecutionPolicy,
    root_reads: Vec<(RootRead, U256, ChainError)>,
    code_expectations: Vec<(Address, Option<B256>)>,
) -> Result<ExecutionPreflightReport, ChainError> {
    validate_plan(
        plan,
        expected_kind,
        expected_target,
        policy.expected_chain_id,
    )?;
    ensure_non_zero_address(policy.caller, "execution policy caller")?;

    let actual_chain_id = client.chain_id().await?;
    if actual_chain_id != policy.expected_chain_id {
        return Err(ChainError::ChainIdMismatch {
            expected: policy.expected_chain_id,
            actual: actual_chain_id,
        });
    }

    let mut code_hash_checks = Vec::with_capacity(code_expectations.len());
    for (address, expected_code_hash) in code_expectations {
        if expected_code_hash.is_none() && !policy.is_insecure_dev() {
            return Err(ChainError::MissingCodeHashExpectation { address });
        }

        let actual_code_hash = client.code_hash(address, policy.read_consistency).await?;
        let matches_expected = if let Some(expected_code_hash) = expected_code_hash {
            if expected_code_hash != actual_code_hash {
                return Err(ChainError::CodeHashMismatch {
                    address,
                    expected: expected_code_hash,
                    actual: actual_code_hash,
                });
            }
            Some(true)
        } else {
            None
        };

        code_hash_checks.push(CodeHashCheck {
            address,
            expected_code_hash,
            actual_code_hash,
            matches_expected,
        });
    }

    let mut root_checks = Vec::with_capacity(root_reads.len());
    for (read, expected_root, mismatch_error) in root_reads {
        match read.kind {
            RootReadKind::PoolState => {
                let actual_root = verify_known_pool_root(
                    client,
                    read.pool_address,
                    expected_root,
                    read.consistency,
                )
                .await?;
                root_checks.push(RootCheck {
                    kind: read.kind,
                    contract_address: read.contract_address,
                    pool_address: read.pool_address,
                    expected_root,
                    actual_root,
                    matches: true,
                });
            }
            RootReadKind::Asp => {
                let actual_root = client.read_root(&read).await?;
                if actual_root != expected_root {
                    return Err(match mismatch_error {
                        ChainError::AspRootMismatch { .. } => ChainError::AspRootMismatch {
                            expected: expected_root,
                            actual: actual_root,
                        },
                        other => other,
                    });
                }

                root_checks.push(RootCheck {
                    kind: read.kind,
                    contract_address: read.contract_address,
                    pool_address: read.pool_address,
                    expected_root,
                    actual_root,
                    matches: true,
                });
            }
        }
    }

    let estimated_gas = client.simulate_transaction(policy.caller, plan).await?;

    Ok(ExecutionPreflightReport {
        kind: plan.kind,
        caller: policy.caller,
        target: plan.target,
        expected_chain_id: policy.expected_chain_id,
        actual_chain_id,
        chain_id_matches: true,
        simulated: true,
        estimated_gas,
        read_consistency: policy.read_consistency,
        max_fee_quote_wei: policy.max_fee_quote_wei,
        mode: policy.mode,
        code_hash_checks,
        root_checks,
    })
}

fn validate_plan(
    plan: &TransactionPlan,
    expected_kind: TransactionKind,
    expected_target: Address,
    expected_chain_id: u64,
) -> Result<(), ChainError> {
    if plan.kind != expected_kind {
        return Err(ChainError::UnexpectedTransactionKind {
            expected: expected_kind,
            actual: plan.kind,
        });
    }
    if plan.target != expected_target {
        return Err(ChainError::UnexpectedTransactionTarget {
            expected: expected_target,
            actual: plan.target,
        });
    }
    if plan.chain_id != expected_chain_id {
        return Err(ChainError::PlannedChainIdMismatch {
            expected: expected_chain_id,
            actual: plan.chain_id,
        });
    }
    Ok(())
}

fn root_read_request(read: &RootRead) -> TransactionRequest {
    TransactionRequest::default()
        .to(read.contract_address)
        .input(TransactionInput::both(read.call_data.clone()))
}

fn root_call_data(kind: RootReadKind, _contract_address: Address, pool_address: Address) -> Bytes {
    match kind {
        RootReadKind::PoolState => Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode()),
        RootReadKind::Asp => {
            let _ = pool_address;
            Bytes::from(IEntrypoint::latestRootCall {}.abi_encode())
        }
    }
}

fn current_root_index_read(pool_address: Address, consistency: ReadConsistency) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        consistency,
        call_data: Bytes::from(IPrivacyPool::currentRootIndexCall {}.abi_encode()),
    }
}

fn historical_state_root_read(
    pool_address: Address,
    index: u32,
    consistency: ReadConsistency,
) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        consistency,
        call_data: Bytes::from(
            IPrivacyPool::rootsCall {
                index: U256::from(index),
            }
            .abi_encode(),
        ),
    }
}

async fn read_pool_entrypoint_address<C: ExecutionClient>(
    client: &C,
    pool_address: Address,
    consistency: ReadConsistency,
) -> Result<Address, ChainError> {
    let encoded = client
        .read_root(&pool_entrypoint_read(pool_address, consistency))
        .await?;
    let address = decode_address_word(encoded)?;
    ensure_non_zero_address(address, "pool entrypoint address")?;
    Ok(address)
}

async fn verify_pool_entrypoint_address<C: ExecutionClient>(
    client: &C,
    pool_address: Address,
    expected_entrypoint: Address,
    consistency: ReadConsistency,
) -> Result<(), ChainError> {
    let actual_entrypoint = read_pool_entrypoint_address(client, pool_address, consistency).await?;
    if actual_entrypoint != expected_entrypoint {
        return Err(ChainError::EntrypointMismatch {
            pool: pool_address,
            expected: expected_entrypoint,
            actual: actual_entrypoint,
        });
    }

    Ok(())
}

fn decode_address_word(value: U256) -> Result<Address, ChainError> {
    let bytes = value.to_be_bytes::<32>();
    if bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidAddressResponse(value));
    }

    Ok(Address::from_slice(&bytes[12..]))
}

fn ensure_non_zero_address(address: Address, field: &'static str) -> Result<(), ChainError> {
    if address.is_zero() {
        return Err(ChainError::ZeroAddress { field });
    }
    Ok(())
}

async fn verify_known_pool_root<C: ExecutionClient>(
    client: &C,
    pool_address: Address,
    expected_root: U256,
    consistency: ReadConsistency,
) -> Result<U256, ChainError> {
    let current_root = client
        .read_root(&state_root_read(pool_address, consistency))
        .await?;
    if current_root == expected_root {
        return Ok(actual_known_root(expected_root));
    }

    if expected_root.is_zero() {
        return Err(ChainError::StateRootMismatch {
            expected: expected_root,
            actual: current_root,
        });
    }

    let current_index = decode_root_index(
        client
            .read_root(&current_root_index_read(pool_address, consistency))
            .await?,
    )?;
    let mut index = current_index;

    for _ in 0..ROOT_HISTORY_SIZE {
        let historical_root = client
            .read_root(&historical_state_root_read(
                pool_address,
                index,
                consistency,
            ))
            .await?;
        if historical_root == expected_root {
            return Ok(actual_known_root(expected_root));
        }
        index = (index + ROOT_HISTORY_SIZE - 1) % ROOT_HISTORY_SIZE;
    }

    Err(ChainError::StateRootMismatch {
        expected: expected_root,
        actual: current_root,
    })
}

fn block_id_for_consistency(consistency: ReadConsistency) -> BlockId {
    match consistency {
        ReadConsistency::Latest => BlockId::latest(),
        ReadConsistency::Finalized => BlockId::finalized(),
    }
}

fn enforce_fee_cap(
    max_fee_quote_wei: Option<u128>,
    fees: &FeeParameters,
) -> Result<(), ChainError> {
    let Some(cap) = max_fee_quote_wei else {
        return Ok(());
    };

    if let Some(gas_price) = fees.gas_price
        && gas_price > cap
    {
        return Err(ChainError::FeeQuoteExceedsCap {
            field: "gas_price",
            quoted: gas_price,
            cap,
        });
    }
    if let Some(max_fee_per_gas) = fees.max_fee_per_gas
        && max_fee_per_gas > cap
    {
        return Err(ChainError::FeeQuoteExceedsCap {
            field: "max_fee_per_gas",
            quoted: max_fee_per_gas,
            cap,
        });
    }
    if let Some(max_priority_fee_per_gas) = fees.max_priority_fee_per_gas
        && max_priority_fee_per_gas > cap
    {
        return Err(ChainError::FeeQuoteExceedsCap {
            field: "max_priority_fee_per_gas",
            quoted: max_priority_fee_per_gas,
            cap,
        });
    }

    Ok(())
}

fn actual_known_root(root: U256) -> U256 {
    root
}

fn decode_root_index(value: U256) -> Result<u32, ChainError> {
    u32::try_from(value).map_err(|_| ChainError::InvalidRootResponse(32))
}

fn transaction_request(plan: &TransactionPlan, caller: Address) -> TransactionRequest {
    let mut request = TransactionRequest::default()
        .from(caller)
        .to(plan.target)
        .value(plan.value)
        .input(TransactionInput::both(plan.calldata.clone()));
    request.chain_id = Some(plan.chain_id);
    request
}

fn validate_signed_transaction(
    encoded_tx: &[u8],
    request: &FinalizedTransactionRequest,
) -> Result<(), ChainError> {
    let mut slice = encoded_tx;
    let transaction = TxEnvelope::decode_2718(&mut slice)
        .map_err(|error| ChainError::InvalidSignedTransaction(error.to_string()))?;
    if !slice.is_empty() {
        return Err(ChainError::InvalidSignedTransaction(
            "signed transaction contains trailing bytes".to_owned(),
        ));
    }

    let signer = transaction
        .recover_signer()
        .map_err(|error| ChainError::InvalidSignedTransaction(error.to_string()))?;
    if signer != request.from {
        return Err(ChainError::SignedTransactionSignerMismatch {
            expected: request.from,
            actual: signer,
        });
    }

    match transaction.chain_id() {
        Some(actual) if actual == request.chain_id => {}
        Some(actual) => {
            return Err(ChainError::SignedTransactionFieldMismatch {
                field: "chain_id",
                expected: request.chain_id.to_string(),
                actual: actual.to_string(),
            });
        }
        None => {
            return Err(ChainError::SignedTransactionFieldMismatch {
                field: "chain_id",
                expected: request.chain_id.to_string(),
                actual: "none".to_owned(),
            });
        }
    }

    let actual_to = transaction
        .to()
        .ok_or_else(|| ChainError::SignedTransactionFieldMismatch {
            field: "to",
            expected: request.to.to_string(),
            actual: "create".to_owned(),
        })?;
    compare_signed_field("to", request.to, actual_to)?;
    compare_signed_field("nonce", request.nonce, transaction.nonce())?;
    compare_signed_field("gas_limit", request.gas_limit, transaction.gas_limit())?;
    compare_signed_field("value", request.value, transaction.value())?;

    if transaction.input() != &request.data {
        return Err(ChainError::SignedTransactionFieldMismatch {
            field: "data",
            expected: format!("0x{}", hex::encode(&request.data)),
            actual: format!("0x{}", hex::encode(transaction.input())),
        });
    }

    match request.gas_price {
        Some(gas_price) => {
            if transaction.is_dynamic_fee() {
                return Err(ChainError::SignedTransactionFieldMismatch {
                    field: "fee_model",
                    expected: "legacy".to_owned(),
                    actual: "dynamic".to_owned(),
                });
            }
            compare_signed_field("gas_price", gas_price, transaction.max_fee_per_gas())?;
        }
        None => {
            if !transaction.is_dynamic_fee() {
                return Err(ChainError::SignedTransactionFieldMismatch {
                    field: "fee_model",
                    expected: "dynamic".to_owned(),
                    actual: "legacy".to_owned(),
                });
            }
            compare_signed_field(
                "max_fee_per_gas",
                request.max_fee_per_gas.unwrap_or_default(),
                transaction.max_fee_per_gas(),
            )?;
            compare_signed_field(
                "max_priority_fee_per_gas",
                request.max_priority_fee_per_gas.unwrap_or_default(),
                transaction.max_priority_fee_per_gas().unwrap_or_default(),
            )?;
        }
    }

    Ok(())
}

fn compare_signed_field<T>(field: &'static str, expected: T, actual: T) -> Result<(), ChainError>
where
    T: PartialEq + ToString,
{
    if expected != actual {
        return Err(ChainError::SignedTransactionFieldMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }

    Ok(())
}

fn decode_root_response(output: &Bytes) -> Result<U256, ChainError> {
    if output.len() < 32 {
        return Err(ChainError::InvalidRootResponse(output.len()));
    }
    Ok(U256::from_be_slice(&output[output.len() - 32..]))
}

fn receipt_summary<R: ReceiptResponse>(receipt: R) -> TransactionReceiptSummary {
    TransactionReceiptSummary {
        transaction_hash: receipt.transaction_hash(),
        block_hash: receipt.block_hash(),
        block_number: receipt.block_number(),
        transaction_index: receipt.transaction_index(),
        success: receipt.status(),
        gas_used: receipt.gas_used(),
        effective_gas_price: receipt.effective_gas_price().to_string(),
        from: receipt.from(),
        to: receipt.to(),
    }
}

fn withdrawal_abi(withdrawal: &Withdrawal) -> WithdrawalAbi {
    WithdrawalAbi {
        processooor: withdrawal.processor,
        data: withdrawal.data.clone(),
    }
}

fn withdraw_proof_abi(proof: &ProofBundle) -> Result<WithdrawProofAbi, ChainError> {
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

fn ragequit_proof_abi(proof: &ProofBundle) -> Result<RagequitProofAbi, ChainError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, bytes};
    use privacy_pools_sdk_core::ExecutionPolicyMode;
    #[cfg(feature = "local-signer-client")]
    use privacy_pools_sdk_signer::{LocalMnemonicSigner, SignerAdapter};
    use serde_json::Value;

    #[derive(Debug, Clone)]
    struct MockExecutionClient {
        chain_id: u64,
        code_hashes: std::collections::HashMap<Address, B256>,
        roots: std::collections::HashMap<(Address, Bytes), U256>,
        estimated_gas: u64,
    }

    fn valid_relay_data_bytes() -> Bytes {
        Bytes::from(
            RelayDataAbi {
                recipient: address!("2222222222222222222222222222222222222222"),
                feeRecipient: address!("3333333333333333333333333333333333333333"),
                relayFeeBPS: U256::from(25_u64),
            }
            .abi_encode(),
        )
    }

    fn state_root_read(pool_address: Address) -> RootRead {
        super::state_root_read(pool_address, ReadConsistency::Latest)
    }

    fn asp_root_read(entrypoint_address: Address, pool_address: Address) -> RootRead {
        super::asp_root_read(entrypoint_address, pool_address, ReadConsistency::Latest)
    }

    fn pool_entrypoint_read(pool_address: Address) -> RootRead {
        super::pool_entrypoint_read(pool_address, ReadConsistency::Latest)
    }

    fn current_root_index_read(pool_address: Address) -> RootRead {
        super::current_root_index_read(pool_address, ReadConsistency::Latest)
    }

    fn historical_state_root_read(pool_address: Address, index: u32) -> RootRead {
        super::historical_state_root_read(pool_address, index, ReadConsistency::Latest)
    }

    #[async_trait]
    impl ExecutionClient for MockExecutionClient {
        async fn chain_id(&self) -> Result<u64, ChainError> {
            Ok(self.chain_id)
        }

        async fn code_hash(
            &self,
            address: Address,
            _consistency: ReadConsistency,
        ) -> Result<B256, ChainError> {
            self.code_hashes
                .get(&address)
                .copied()
                .ok_or_else(|| ChainError::Transport(format!("missing code hash for {address}")))
        }

        async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError> {
            self.roots
                .get(&(read.contract_address, read.call_data.clone()))
                .copied()
                .ok_or_else(|| {
                    ChainError::Transport(format!(
                        "missing root for {:?} at {}",
                        read.kind, read.contract_address
                    ))
                })
        }

        async fn simulate_transaction(
            &self,
            _caller: Address,
            _plan: &TransactionPlan,
        ) -> Result<u64, ChainError> {
            Ok(self.estimated_gas)
        }
    }

    #[test]
    fn state_root_read_calls_current_root_on_pool() {
        let pool = address!("0987654321098765432109876543210987654321");
        let read = state_root_read(pool);
        let asp_read = asp_root_read(address!("1234567890123456789012345678901234567890"), pool);

        assert_eq!(read.pool_address, pool);
        assert_eq!(read.contract_address, pool);
        assert_eq!(read.kind, RootReadKind::PoolState);
        assert_eq!(
            read.call_data,
            Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode())
        );
        assert_eq!(
            asp_read.contract_address,
            address!("1234567890123456789012345678901234567890")
        );
        assert_eq!(asp_read.pool_address, pool);
        assert_eq!(asp_read.kind, RootReadKind::Asp);
        assert_eq!(
            asp_read.call_data,
            Bytes::from(IEntrypoint::latestRootCall {}.abi_encode())
        );
        assert_ne!(read.call_data, asp_read.call_data);
    }

    #[test]
    fn formats_groth16_proofs_like_the_ts_sdk() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/proof-formatting.json"
        ))
        .unwrap();

        let input = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "milady".to_owned(),
                curve: "nsa-definitely-non-backdoored-curve-69".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 6],
        };

        let formatted = format_groth16_proof(&input).unwrap();
        assert_eq!(
            formatted.p_a,
            [
                fixture["expected"]["pA"][0].as_str().unwrap().to_owned(),
                fixture["expected"]["pA"][1].as_str().unwrap().to_owned()
            ]
        );
        assert_eq!(
            formatted.p_b,
            [
                [
                    fixture["expected"]["pB"][0][0].as_str().unwrap().to_owned(),
                    fixture["expected"]["pB"][0][1].as_str().unwrap().to_owned()
                ],
                [
                    fixture["expected"]["pB"][1][0].as_str().unwrap().to_owned(),
                    fixture["expected"]["pB"][1][1].as_str().unwrap().to_owned()
                ]
            ]
        );
        assert_eq!(
            formatted.p_c,
            [
                fixture["expected"]["pC"][0].as_str().unwrap().to_owned(),
                fixture["expected"]["pC"][1].as_str().unwrap().to_owned()
            ]
        );
        assert_eq!(
            formatted.pub_signals,
            fixture["expected"]["pubSignals"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_noncanonical_proof_fields_before_calldata_planning() {
        let mut proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };

        proof.public_signals[0] = bn254_scalar_field_modulus().to_string();
        let error = format_groth16_proof(&proof).expect_err("public signal must be canonical");
        assert!(matches!(
            error,
            ChainError::NonCanonicalProofField { field, .. } if field == "publicSignals[0]"
        ));

        proof.public_signals[0] = "911".to_owned();
        proof.proof.pi_a[0] = bn254_base_field_modulus().to_string();
        let error = plan_withdrawal_transaction(
            1,
            address!("0987654321098765432109876543210987654321"),
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .expect_err("proof coordinate must be canonical");
        assert!(matches!(
            error,
            ChainError::NonCanonicalProofField { field, .. } if field == "piA[0]"
        ));
    }

    #[test]
    fn rejects_withdrawal_proof_when_planning_ragequit_transaction() {
        let withdrawal_proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };

        assert!(matches!(
            plan_ragequit_transaction(
                1,
                address!("0987654321098765432109876543210987654321"),
                &withdrawal_proof,
            ),
            Err(ChainError::InvalidRagequitPublicSignals(8))
        ));
    }

    #[test]
    fn plans_withdraw_and_relay_transactions() {
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let ragequit_proof = ProofBundle {
            proof: proof.proof.clone(),
            public_signals: vec!["911".to_owned(); 4],
        };
        let withdrawal = Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        };
        let relay_withdrawal = Withdrawal {
            processor: entrypoint,
            data: valid_relay_data_bytes(),
        };

        let withdraw = plan_withdrawal_transaction(
            1,
            address!("0987654321098765432109876543210987654321"),
            &withdrawal,
            &proof,
        )
        .unwrap();
        let relay = plan_relay_transaction(
            1,
            entrypoint,
            &relay_withdrawal,
            &proof,
            U256::from(123_u64),
        )
        .unwrap();
        let ragequit = plan_ragequit_transaction(
            1,
            address!("0987654321098765432109876543210987654321"),
            &ragequit_proof,
        )
        .unwrap();

        assert_eq!(withdraw.kind, TransactionKind::Withdraw);
        assert_eq!(
            &withdraw.calldata[..4],
            IPrivacyPool::withdrawCall::SELECTOR.as_slice()
        );
        assert_eq!(relay.kind, TransactionKind::Relay);
        assert_eq!(
            &relay.calldata[..4],
            IEntrypoint::relayCall::SELECTOR.as_slice()
        );
        assert_eq!(ragequit.kind, TransactionKind::Ragequit);
        assert_eq!(
            &ragequit.calldata[..4],
            IPrivacyPool::ragequitCall::SELECTOR.as_slice()
        );
        assert_eq!(withdraw.value, U256::ZERO);
        assert_eq!(relay.value, U256::ZERO);
        assert_eq!(ragequit.value, U256::ZERO);
        assert_eq!(withdraw.proof.pub_signals.len(), 8);
        assert_eq!(ragequit.proof.pub_signals.len(), 4);
    }

    #[test]
    fn rejects_invalid_withdraw_public_signal_lengths() {
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["9".to_owned(); 6],
        };

        assert!(matches!(
            plan_withdrawal_transaction(
                1,
                address!("0987654321098765432109876543210987654321"),
                &Withdrawal {
                    processor: address!("1111111111111111111111111111111111111111"),
                    data: bytes!("1234"),
                },
                &proof,
            ),
            Err(ChainError::InvalidWithdrawPublicSignals(6))
        ));
    }

    #[test]
    fn rejects_invalid_ragequit_public_signal_lengths() {
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["9".to_owned(); 8],
        };

        assert!(matches!(
            plan_ragequit_transaction(
                1,
                address!("0987654321098765432109876543210987654321"),
                &proof,
            ),
            Err(ChainError::InvalidRagequitPublicSignals(8))
        ));
    }

    #[test]
    fn rejects_zero_address_withdrawals() {
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["9".to_owned(); 8],
        };

        assert!(matches!(
            plan_withdrawal_transaction(
                1,
                Address::ZERO,
                &Withdrawal {
                    processor: address!("1111111111111111111111111111111111111111"),
                    data: bytes!("1234"),
                },
                &proof,
            ),
            Err(ChainError::ZeroAddress {
                field: "pool address"
            })
        ));

        assert!(matches!(
            plan_withdrawal_transaction(
                1,
                address!("0987654321098765432109876543210987654321"),
                &Withdrawal {
                    processor: Address::ZERO,
                    data: bytes!("1234"),
                },
                &proof,
            ),
            Err(ChainError::ZeroAddress {
                field: "withdrawal processor"
            })
        ));
    }

    #[test]
    fn rejects_zero_value_relay_transactions() {
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "10".to_owned(),
                "11".to_owned(),
                "0".to_owned(),
                "12".to_owned(),
                "32".to_owned(),
                "13".to_owned(),
                "32".to_owned(),
                "14".to_owned(),
            ],
        };

        assert!(matches!(
            plan_relay_transaction(
                1,
                entrypoint,
                &Withdrawal {
                    processor: entrypoint,
                    data: valid_relay_data_bytes(),
                },
                &proof,
                U256::from(123_u64),
            ),
            Err(ChainError::RelayRequiresNonZeroWithdrawValue)
        ));
    }

    #[test]
    fn rejects_relay_transactions_with_wrong_processooor() {
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "10".to_owned(),
                "11".to_owned(),
                "1".to_owned(),
                "12".to_owned(),
                "32".to_owned(),
                "13".to_owned(),
                "32".to_owned(),
                "14".to_owned(),
            ],
        };

        assert!(matches!(
            plan_relay_transaction(
                1,
                entrypoint,
                &Withdrawal {
                    processor: address!("1111111111111111111111111111111111111111"),
                    data: bytes!("1234"),
                },
                &proof,
                U256::from(123_u64),
            ),
            Err(ChainError::RelayProcessooorMismatch { expected, actual })
                if expected == entrypoint
                    && actual == address!("1111111111111111111111111111111111111111")
        ));
    }

    #[test]
    fn rejects_zero_address_relay_targets() {
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "10".to_owned(),
                "11".to_owned(),
                "1".to_owned(),
                "12".to_owned(),
                "32".to_owned(),
                "13".to_owned(),
                "32".to_owned(),
                "14".to_owned(),
            ],
        };

        assert!(matches!(
            plan_relay_transaction(
                1,
                Address::ZERO,
                &Withdrawal {
                    processor: Address::ZERO,
                    data: valid_relay_data_bytes(),
                },
                &proof,
                U256::from(123_u64),
            ),
            Err(ChainError::ZeroAddress {
                field: "entrypoint address"
            })
        ));
    }

    #[test]
    fn rejects_relay_transactions_with_malformed_relay_data() {
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["1".to_owned(), "2".to_owned()],
                pi_b: [
                    ["3".to_owned(), "4".to_owned()],
                    ["5".to_owned(), "6".to_owned()],
                ],
                pi_c: ["7".to_owned(), "8".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "10".to_owned(),
                "11".to_owned(),
                "1".to_owned(),
                "12".to_owned(),
                "32".to_owned(),
                "13".to_owned(),
                "32".to_owned(),
                "14".to_owned(),
            ],
        };

        assert!(matches!(
            plan_relay_transaction(
                1,
                entrypoint,
                &Withdrawal {
                    processor: entrypoint,
                    data: bytes!("1234"),
                },
                &proof,
                U256::from(123_u64),
            ),
            Err(ChainError::InvalidRelayData(_))
        ));
    }

    #[tokio::test]
    async fn preflights_withdrawals_against_live_roots_and_code_hashes() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        let report = preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &policy)
            .await
            .unwrap();

        assert_eq!(report.kind, TransactionKind::Withdraw);
        assert!(report.chain_id_matches);
        assert!(report.simulated);
        assert_eq!(report.estimated_gas, 420_000);
        assert_eq!(report.code_hash_checks.len(), 2);
        assert_eq!(report.root_checks.len(), 2);
        assert!(report.root_checks[0].matches);
        assert!(report.root_checks[1].matches);
    }

    #[tokio::test]
    async fn strict_policy_rejects_missing_code_hash_expectations() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let strict_policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: None,
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &strict_policy).await,
            Err(ChainError::MissingCodeHashExpectation { address }) if address == entrypoint
        ));

        let dev_policy =
            ExecutionPolicy::insecure_dev(1, address!("9999999999999999999999999999999999999999"));
        let report = preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &dev_policy)
            .await
            .unwrap();

        assert_eq!(report.code_hash_checks.len(), 2);
        assert!(
            report
                .code_hash_checks
                .iter()
                .all(|check| check.matches_expected.is_none())
        );
    }

    #[tokio::test]
    async fn rejects_wrong_chain_id_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 2,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &policy).await,
            Err(ChainError::ChainIdMismatch { expected, actual })
                if expected == 1 && actual == 2
        ));
    }

    #[tokio::test]
    async fn rejects_pool_code_hash_mismatch_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "1111111111111111111111111111111111111111111111111111111111111111"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &policy).await,
            Err(ChainError::CodeHashMismatch { address, expected, actual })
                if address == pool
                    && expected
                        == b256!("1111111111111111111111111111111111111111111111111111111111111111")
                    && actual
                        == b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        ));
    }

    #[tokio::test]
    async fn accepts_known_historical_state_roots_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), U256::from(555_u64)),
                (
                    (pool, current_root_index_read(pool).call_data),
                    U256::from(3_u64),
                ),
                (
                    (pool, historical_state_root_read(pool, 3).call_data),
                    U256::from(555_u64),
                ),
                (
                    (pool, historical_state_root_read(pool, 2).call_data),
                    U256::from(444_u64),
                ),
                (
                    (pool, historical_state_root_read(pool, 1).call_data),
                    U256::from(123_u64),
                ),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    U256::from(111_u64),
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        let report =
            preflight_withdrawal(&client, &plan, pool, U256::from(123_u64), asp_root, &policy)
                .await
                .unwrap();

        assert!(report.root_checks[0].matches);
        assert_eq!(report.root_checks[0].expected_root, U256::from(123_u64));
        assert_eq!(report.root_checks[0].actual_root, U256::from(123_u64));
        assert!(report.root_checks[1].matches);
    }

    #[tokio::test]
    async fn rejects_unknown_state_roots_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let mut roots = std::collections::HashMap::from([
            (
                (pool, pool_entrypoint_read(pool).call_data),
                U256::from_be_slice(entrypoint.as_slice()),
            ),
            ((pool, state_root_read(pool).call_data), U256::from(555_u64)),
            (
                (pool, current_root_index_read(pool).call_data),
                U256::from(1_u64),
            ),
            (
                (entrypoint, asp_root_read(entrypoint, pool).call_data),
                U256::from(999_u64),
            ),
        ]);
        for index in 0..ROOT_HISTORY_SIZE {
            roots.insert(
                (pool, historical_state_root_read(pool, index).call_data),
                U256::from(400_u64 + index as u64),
            );
        }
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots,
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(
                &client,
                &plan,
                pool,
                U256::from(123_u64),
                U256::from(999_u64),
                &policy
            )
            .await,
            Err(ChainError::StateRootMismatch { expected, actual })
                if expected == U256::from(123_u64) && actual == U256::from(555_u64)
        ));
    }

    #[tokio::test]
    async fn rejects_stale_asp_roots_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    U256::from(888_u64),
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(
                &client,
                &plan,
                pool,
                state_root,
                U256::from(999_u64),
                &policy
            )
            .await,
            Err(ChainError::AspRootMismatch { expected, actual })
                if expected == U256::from(999_u64) && actual == U256::from(888_u64)
        ));
    }

    #[tokio::test]
    async fn rejects_zero_pool_entrypoint_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let state_root = U256::from(123_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([(
                pool,
                b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )]),
            roots: std::collections::HashMap::from([(
                (pool, pool_entrypoint_read(pool).call_data),
                U256::ZERO,
            )]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: None,
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(
                &client,
                &plan,
                pool,
                state_root,
                U256::from(999_u64),
                &policy
            )
            .await,
            Err(ChainError::ZeroAddress {
                field: "pool entrypoint address"
            })
        ));
    }

    #[tokio::test]
    async fn rejects_malformed_pool_entrypoint_words_during_withdrawal_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let state_root = U256::from(123_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec!["911".to_owned(); 8],
        };
        let plan = plan_withdrawal_transaction(
            1,
            pool,
            &Withdrawal {
                processor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            &proof,
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([(
                pool,
                b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )]),
            roots: std::collections::HashMap::from([(
                (pool, pool_entrypoint_read(pool).call_data),
                U256::MAX,
            )]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: None,
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_withdrawal(
                &client,
                &plan,
                pool,
                state_root,
                U256::from(999_u64),
                &policy
            )
            .await,
            Err(ChainError::InvalidAddressResponse(value)) if value == U256::MAX
        ));
    }

    #[tokio::test]
    async fn rejects_stale_asp_roots_during_relay_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "100".to_owned(),
                "200".to_owned(),
                "250".to_owned(),
                state_root.to_string(),
                "32".to_owned(),
                "999".to_owned(),
                "32".to_owned(),
                "300".to_owned(),
            ],
        };
        let plan = plan_relay_transaction(
            1,
            entrypoint,
            &Withdrawal {
                processor: entrypoint,
                data: valid_relay_data_bytes(),
            },
            &proof,
            U256::from(123_u64),
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    U256::from(888_u64),
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_relay(
                &client,
                &plan,
                entrypoint,
                pool,
                state_root,
                U256::from(999_u64),
                &policy
            )
            .await,
            Err(ChainError::AspRootMismatch { expected, actual })
                if expected == U256::from(999_u64) && actual == U256::from(888_u64)
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_entrypoint_mapping_during_relay_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let actual_entrypoint = address!("2222222222222222222222222222222222222222");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "100".to_owned(),
                "200".to_owned(),
                "250".to_owned(),
                state_root.to_string(),
                "32".to_owned(),
                asp_root.to_string(),
                "32".to_owned(),
                "300".to_owned(),
            ],
        };
        let plan = plan_relay_transaction(
            1,
            entrypoint,
            &Withdrawal {
                processor: entrypoint,
                data: valid_relay_data_bytes(),
            },
            &proof,
            U256::from(123_u64),
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([(
                (pool, pool_entrypoint_read(pool).call_data),
                U256::from_be_slice(actual_entrypoint.as_slice()),
            )]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_relay(
                &client, &plan, entrypoint, pool, state_root, asp_root, &policy
            )
            .await,
            Err(ChainError::EntrypointMismatch {
                pool: mismatch_pool,
                expected,
                actual
            }) if mismatch_pool == pool && expected == entrypoint && actual == actual_entrypoint
        ));
    }

    #[tokio::test]
    async fn rejects_zero_policy_caller_during_relay_preflight() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(888_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "100".to_owned(),
                "101".to_owned(),
                "1".to_owned(),
                "102".to_owned(),
                "32".to_owned(),
                "103".to_owned(),
                "32".to_owned(),
                "104".to_owned(),
            ],
        };
        let plan = plan_relay_transaction(
            1,
            entrypoint,
            &Withdrawal {
                processor: entrypoint,
                data: valid_relay_data_bytes(),
            },
            &proof,
            U256::from(77_u64),
        )
        .unwrap();
        let client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::new(),
            roots: std::collections::HashMap::from([(
                (pool, pool_entrypoint_read(pool).call_data),
                U256::from_be_slice(entrypoint.as_slice()),
            )]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: Address::ZERO,
            expected_pool_code_hash: None,
            expected_entrypoint_code_hash: None,
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };

        assert!(matches!(
            preflight_relay(
                &client, &plan, entrypoint, pool, state_root, asp_root, &policy
            )
            .await,
            Err(ChainError::ZeroAddress {
                field: "execution policy caller"
            })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_entrypoint_mapping_during_reconfirm() {
        let pool = address!("0987654321098765432109876543210987654321");
        let entrypoint = address!("1234567890123456789012345678901234567890");
        let actual_entrypoint = address!("2222222222222222222222222222222222222222");
        let state_root = U256::from(123_u64);
        let asp_root = U256::from(999_u64);
        let proof = ProofBundle {
            proof: privacy_pools_sdk_core::SnarkJsProof {
                pi_a: ["123".to_owned(), "123".to_owned()],
                pi_b: [
                    ["69".to_owned(), "123".to_owned()],
                    ["12".to_owned(), "123".to_owned()],
                ],
                pi_c: ["12".to_owned(), "828".to_owned()],
                protocol: "groth16".to_owned(),
                curve: "bn128".to_owned(),
            },
            public_signals: vec![
                "100".to_owned(),
                "200".to_owned(),
                "250".to_owned(),
                state_root.to_string(),
                "32".to_owned(),
                asp_root.to_string(),
                "32".to_owned(),
                "300".to_owned(),
            ],
        };
        let plan = plan_relay_transaction(
            1,
            entrypoint,
            &Withdrawal {
                processor: entrypoint,
                data: valid_relay_data_bytes(),
            },
            &proof,
            U256::from(123_u64),
        )
        .unwrap();
        let valid_client = MockExecutionClient {
            chain_id: 1,
            code_hashes: std::collections::HashMap::from([
                (
                    pool,
                    b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    entrypoint,
                    b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };
        let policy = ExecutionPolicy {
            expected_chain_id: 1,
            caller: address!("9999999999999999999999999999999999999999"),
            expected_pool_code_hash: Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            expected_entrypoint_code_hash: Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
            mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
        };
        let report = preflight_relay(
            &valid_client,
            &plan,
            entrypoint,
            pool,
            state_root,
            asp_root,
            &policy,
        )
        .await
        .unwrap();

        let mismatch_client = MockExecutionClient {
            chain_id: 1,
            code_hashes: valid_client.code_hashes.clone(),
            roots: std::collections::HashMap::from([
                (
                    (pool, pool_entrypoint_read(pool).call_data),
                    U256::from_be_slice(actual_entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                (
                    (pool, historical_state_root_read(pool, 0).call_data),
                    state_root,
                ),
                (
                    (entrypoint, asp_root_read(entrypoint, pool).call_data),
                    asp_root,
                ),
            ]),
            estimated_gas: 420_000,
        };

        assert!(matches!(
            reconfirm_preflight(&mismatch_client, &plan, &report).await,
            Err(ChainError::EntrypointMismatch {
                pool: mismatch_pool,
                expected,
                actual
            }) if mismatch_pool == pool && expected == entrypoint && actual == actual_entrypoint
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_trailing_bytes() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let mut signed = signer.sign_transaction_request(&request).unwrap().to_vec();
        signed.extend_from_slice(&[0xaa, 0xbb]);

        assert!(matches!(
            validate_signed_transaction(&signed, &request),
            Err(ChainError::InvalidSignedTransaction(message))
                if message.contains("trailing bytes")
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_fee_model() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let dynamic_request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: None,
            max_fee_per_gas: Some(10),
            max_priority_fee_per_gas: Some(2),
        };
        let signed = signer.sign_transaction_request(&dynamic_request).unwrap();
        let legacy_request = FinalizedTransactionRequest {
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            ..dynamic_request
        };

        assert!(matches!(
            validate_signed_transaction(&signed, &legacy_request),
            Err(ChainError::SignedTransactionFieldMismatch { field, expected, actual })
                if field == "fee_model" && expected == "legacy" && actual == "dynamic"
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_chain_id() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let signed = signer.sign_transaction_request(&request).unwrap();
        let wrong_chain = FinalizedTransactionRequest {
            chain_id: 10,
            ..request
        };

        assert!(matches!(
            validate_signed_transaction(&signed, &wrong_chain),
            Err(ChainError::SignedTransactionFieldMismatch { field, expected, actual })
                if field == "chain_id" && expected == "10" && actual == "1"
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_signer() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let wrong_signer = LocalMnemonicSigner::from_phrase_nth(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let signed = wrong_signer.sign_transaction_request(&request).unwrap();

        assert!(matches!(
            validate_signed_transaction(&signed, &request),
            Err(ChainError::SignedTransactionSignerMismatch { expected, actual })
                if expected == signer.address() && actual == wrong_signer.address()
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_target() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let signed = signer.sign_transaction_request(&request).unwrap();
        let wrong_target = FinalizedTransactionRequest {
            to: address!("3333333333333333333333333333333333333333"),
            ..request
        };

        assert!(matches!(
            validate_signed_transaction(&signed, &wrong_target),
            Err(ChainError::SignedTransactionFieldMismatch { field, expected, actual })
                if field == "to"
                    && expected == "0x3333333333333333333333333333333333333333"
                    && actual == "0x2222222222222222222222222222222222222222"
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_nonce() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let signed = signer.sign_transaction_request(&request).unwrap();
        let wrong_nonce = FinalizedTransactionRequest {
            nonce: 8,
            ..request
        };

        assert!(matches!(
            validate_signed_transaction(&signed, &wrong_nonce),
            Err(ChainError::SignedTransactionFieldMismatch { field, expected, actual })
                if field == "nonce" && expected == "8" && actual == "7"
        ));
    }

    #[cfg(feature = "local-signer-client")]
    #[test]
    fn rejects_signed_transactions_with_wrong_gas_limit() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let request = FinalizedTransactionRequest {
            kind: TransactionKind::Withdraw,
            chain_id: 1,
            from: signer.address(),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };
        let signed = signer.sign_transaction_request(&request).unwrap();
        let wrong_gas_limit = FinalizedTransactionRequest {
            gas_limit: 25_000,
            ..request
        };

        assert!(matches!(
            validate_signed_transaction(&signed, &wrong_gas_limit),
            Err(ChainError::SignedTransactionFieldMismatch { field, expected, actual })
                if field == "gas_limit" && expected == "25000" && actual == "21000"
        ));
    }
}
