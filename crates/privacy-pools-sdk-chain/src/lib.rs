use alloy_consensus::{
    Transaction as ConsensusTransaction, TxEnvelope, transaction::SignerRecoverable,
};
use alloy_eips::Decodable2718;
use alloy_network::{Ethereum, ReceiptResponse};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_sol_types::{SolCall, SolValue, sol};
use async_trait::async_trait;
use privacy_pools_sdk_core::{
    CodeHashCheck, ExecutionPolicy, ExecutionPreflightReport, FinalizedTransactionRequest,
    FormattedGroth16Proof, ProofBundle, RootCheck, RootRead, RootReadKind, TransactionKind,
    TransactionPlan, TransactionReceiptSummary, Withdrawal, field_to_hex_32, parse_decimal_field,
};
use privacy_pools_sdk_signer::{LocalMnemonicSigner, SignerAdapter};
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

    interface IPrivacyPool {
        function ENTRYPOINT() external view returns (address);
        function currentRoot() external view returns (uint256);
        function currentRootIndex() external view returns (uint32);
        function roots(uint256 index) external view returns (uint256);
        function withdraw(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof) external;
    }

    interface IEntrypoint {
        function latestRoot() external view returns (uint256);
        function relay(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof, uint256 scope) external;
    }
}

const ROOT_HISTORY_SIZE: u32 = 64;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error(transparent)]
    Core(#[from] privacy_pools_sdk_core::CoreError),
    #[error("withdraw proof must contain exactly 8 public signals, got {0}")]
    InvalidWithdrawPublicSignals(usize),
    #[error("withdraw proof public signal mismatch for {field}: expected {expected}, got {actual}")]
    WithdrawProofSignalMismatch {
        field: &'static str,
        expected: U256,
        actual: U256,
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
    #[error("state root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: U256, actual: U256 },
    #[error("asp root mismatch: expected {expected}, got {actual}")]
    AspRootMismatch { expected: U256, actual: U256 },
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
    async fn code_hash(&self, address: Address) -> Result<B256, ChainError>;
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

impl LocalSignerExecutionClient {
    pub fn new(rpc_url: &str, signer: &LocalMnemonicSigner) -> Result<Self, ChainError> {
        let url = Url::parse(rpc_url).map_err(|_| ChainError::InvalidRpcUrl(rpc_url.to_owned()))?;
        let caller = signer.address();

        Ok(Self {
            provider: ProviderBuilder::new()
                .wallet(signer.private_key_signer())
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

    async fn code_hash(&self, address: Address) -> Result<B256, ChainError> {
        let code = self
            .provider
            .get_code_at(address)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        Ok(keccak256(code))
    }

    async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError> {
        let output = self
            .provider
            .call(root_read_request(read))
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
impl ExecutionClient for LocalSignerExecutionClient {
    async fn chain_id(&self) -> Result<u64, ChainError> {
        self.provider
            .get_chain_id()
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))
    }

    async fn code_hash(&self, address: Address) -> Result<B256, ChainError> {
        let code = self
            .provider
            .get_code_at(address)
            .await
            .map_err(|error| ChainError::Transport(error.to_string()))?;
        Ok(keccak256(code))
    }

    async fn read_root(&self, read: &RootRead) -> Result<U256, ChainError> {
        let output = self
            .provider
            .call(root_read_request(read))
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
            field_to_hex_32(parse_decimal_field(&proof.proof.pi_a[0])?),
            field_to_hex_32(parse_decimal_field(&proof.proof.pi_a[1])?),
        ],
        p_b: [
            [
                field_to_hex_32(parse_decimal_field(&proof.proof.pi_b[0][1])?),
                field_to_hex_32(parse_decimal_field(&proof.proof.pi_b[0][0])?),
            ],
            [
                field_to_hex_32(parse_decimal_field(&proof.proof.pi_b[1][1])?),
                field_to_hex_32(parse_decimal_field(&proof.proof.pi_b[1][0])?),
            ],
        ],
        p_c: [
            field_to_hex_32(parse_decimal_field(&proof.proof.pi_c[0])?),
            field_to_hex_32(parse_decimal_field(&proof.proof.pi_c[1])?),
        ],
        pub_signals: proof
            .public_signals
            .iter()
            .map(|value| parse_decimal_field(value).map(field_to_hex_32))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn withdraw_public_signals(proof: &ProofBundle) -> Result<[U256; 8], ChainError> {
    let public_signals = proof
        .public_signals
        .iter()
        .map(|value| parse_decimal_field(value))
        .collect::<Result<Vec<_>, _>>()?;
    public_signals
        .try_into()
        .map_err(|signals: Vec<U256>| ChainError::InvalidWithdrawPublicSignals(signals.len()))
}

pub fn state_root_read(pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        call_data: Bytes::from(IPrivacyPool::currentRootCall {}.abi_encode()),
    }
}

pub fn asp_root_read(entrypoint_address: Address, pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::Asp,
        contract_address: entrypoint_address,
        pool_address,
        call_data: Bytes::from(IEntrypoint::latestRootCall {}.abi_encode()),
    }
}

fn pool_entrypoint_read(pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
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
    if pool_address.is_zero() {
        return Err(ChainError::ZeroAddress {
            field: "pool address",
        });
    }

    if withdrawal.processooor.is_zero() {
        return Err(ChainError::ZeroAddress {
            field: "withdrawal processooor",
        });
    }

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
    if entrypoint_address.is_zero() {
        return Err(ChainError::ZeroAddress {
            field: "entrypoint address",
        });
    }

    if withdrawal.processooor != entrypoint_address {
        return Err(ChainError::RelayProcessooorMismatch {
            expected: entrypoint_address,
            actual: withdrawal.processooor,
        });
    }

    parse_relay_data(&withdrawal.data)?;

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

pub async fn preflight_withdrawal<C: ExecutionClient>(
    client: &C,
    plan: &TransactionPlan,
    pool_address: Address,
    expected_state_root: U256,
    expected_asp_root: U256,
    policy: &ExecutionPolicy,
) -> Result<ExecutionPreflightReport, ChainError> {
    let entrypoint_address = read_pool_entrypoint_address(client, pool_address).await?;

    preflight_transaction(
        client,
        plan,
        TransactionKind::Withdraw,
        pool_address,
        policy,
        vec![
            (
                state_root_read(pool_address),
                expected_state_root,
                ChainError::StateRootMismatch {
                    expected: expected_state_root,
                    actual: expected_state_root,
                },
            ),
            (
                asp_root_read(entrypoint_address, pool_address),
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
    preflight_transaction(
        client,
        plan,
        TransactionKind::Relay,
        entrypoint_address,
        policy,
        vec![
            (
                state_root_read(pool_address),
                expected_state_root,
                ChainError::StateRootMismatch {
                    expected: expected_state_root,
                    actual: expected_state_root,
                },
            ),
            (
                asp_root_read(entrypoint_address, pool_address),
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
        let actual_code_hash = client.code_hash(check.address).await?;
        let matches_expected = check
            .expected_code_hash
            .map(|expected| expected == actual_code_hash);

        if let Some(false) = matches_expected {
            return Err(ChainError::CodeHashMismatch {
                address: check.address,
                expected: check.expected_code_hash.expect("checked some above"),
                actual: actual_code_hash,
            });
        }

        code_hash_checks.push(CodeHashCheck {
            address: check.address,
            expected_code_hash: check.expected_code_hash,
            actual_code_hash,
            matches_expected,
        });
    }

    let mut root_checks = Vec::with_capacity(report.root_checks.len());
    for check in &report.root_checks {
        match check.kind {
            RootReadKind::PoolState => {
                let actual_root =
                    verify_known_pool_root(client, check.pool_address, check.expected_root).await?;
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
    validate_signed_transaction(encoded_tx, request)?;
    client.submit_raw_transaction(encoded_tx).await
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

    let actual_chain_id = client.chain_id().await?;
    if actual_chain_id != policy.expected_chain_id {
        return Err(ChainError::ChainIdMismatch {
            expected: policy.expected_chain_id,
            actual: actual_chain_id,
        });
    }

    let mut code_hash_checks = Vec::with_capacity(code_expectations.len());
    for (address, expected_code_hash) in code_expectations {
        let actual_code_hash = client.code_hash(address).await?;
        let matches_expected = expected_code_hash.map(|expected| expected == actual_code_hash);

        if let Some(false) = matches_expected {
            return Err(ChainError::CodeHashMismatch {
                address,
                expected: expected_code_hash.expect("checked some above"),
                actual: actual_code_hash,
            });
        }

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
                let actual_root =
                    verify_known_pool_root(client, read.pool_address, expected_root).await?;
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

fn current_root_index_read(pool_address: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
        call_data: Bytes::from(IPrivacyPool::currentRootIndexCall {}.abi_encode()),
    }
}

fn historical_state_root_read(pool_address: Address, index: u32) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool_address,
        pool_address,
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
) -> Result<Address, ChainError> {
    let encoded = client
        .read_root(&pool_entrypoint_read(pool_address))
        .await?;
    decode_address_word(encoded)
}

fn decode_address_word(value: U256) -> Result<Address, ChainError> {
    let bytes = value.to_be_bytes::<32>();
    if bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidAddressResponse(value));
    }

    Ok(Address::from_slice(&bytes[12..]))
}

async fn verify_known_pool_root<C: ExecutionClient>(
    client: &C,
    pool_address: Address,
    expected_root: U256,
) -> Result<U256, ChainError> {
    let current_root = client.read_root(&state_root_read(pool_address)).await?;
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
            .read_root(&current_root_index_read(pool_address))
            .await?,
    )?;
    let mut index = current_index;

    for _ in 0..ROOT_HISTORY_SIZE {
        let historical_root = client
            .read_root(&historical_state_root_read(pool_address, index))
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
        processooor: withdrawal.processooor,
        data: withdrawal.data.clone(),
    }
}

fn withdraw_proof_abi(proof: &ProofBundle) -> Result<WithdrawProofAbi, ChainError> {
    let public_signals = withdraw_public_signals(proof)?;

    Ok(WithdrawProofAbi {
        pA: [
            parse_decimal_field(&proof.proof.pi_a[0])?,
            parse_decimal_field(&proof.proof.pi_a[1])?,
        ],
        pB: [
            [
                parse_decimal_field(&proof.proof.pi_b[0][1])?,
                parse_decimal_field(&proof.proof.pi_b[0][0])?,
            ],
            [
                parse_decimal_field(&proof.proof.pi_b[1][1])?,
                parse_decimal_field(&proof.proof.pi_b[1][0])?,
            ],
        ],
        pC: [
            parse_decimal_field(&proof.proof.pi_c[0])?,
            parse_decimal_field(&proof.proof.pi_c[1])?,
        ],
        pubSignals: public_signals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, bytes};
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

    #[async_trait]
    impl ExecutionClient for MockExecutionClient {
        async fn chain_id(&self) -> Result<u64, ChainError> {
            Ok(self.chain_id)
        }

        async fn code_hash(&self, address: Address) -> Result<B256, ChainError> {
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
    fn uses_current_root_for_pool_state_reads() {
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
        let withdrawal = Withdrawal {
            processooor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        };
        let relay_withdrawal = Withdrawal {
            processooor: entrypoint,
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
        assert_eq!(withdraw.value, U256::ZERO);
        assert_eq!(relay.value, U256::ZERO);
        assert_eq!(withdraw.proof.pub_signals.len(), 8);
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
                    processooor: address!("1111111111111111111111111111111111111111"),
                    data: bytes!("1234"),
                },
                &proof,
            ),
            Err(ChainError::InvalidWithdrawPublicSignals(6))
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
                    processooor: address!("1111111111111111111111111111111111111111"),
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
                    processooor: Address::ZERO,
                    data: bytes!("1234"),
                },
                &proof,
            ),
            Err(ChainError::ZeroAddress {
                field: "withdrawal processooor"
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
                    processooor: entrypoint,
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
                    processooor: address!("1111111111111111111111111111111111111111"),
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
                    processooor: Address::ZERO,
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
                    processooor: entrypoint,
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
                processooor: address!("1111111111111111111111111111111111111111"),
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
                processooor: address!("1111111111111111111111111111111111111111"),
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
                processooor: address!("1111111111111111111111111111111111111111"),
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
                processooor: address!("1111111111111111111111111111111111111111"),
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
                processooor: address!("1111111111111111111111111111111111111111"),
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
                processooor: entrypoint,
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
