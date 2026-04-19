use alloy_primitives::{Address, B256, Bytes, U256, address};
use alloy_sol_types::{SolCall, sol};
use async_trait::async_trait;
use privacy_pools_sdk_chain::{
    ChainError, ExecutionClient, FeeParameters, FinalizationClient, finalize_transaction,
    preflight_withdrawal, state_root_read as chain_state_root_read,
};
use privacy_pools_sdk_core::{
    ExecutionPolicy, ExecutionPolicyMode, FormattedGroth16Proof, ReadConsistency, RootRead,
    RootReadKind, TransactionKind, TransactionPlan, TransactionReceiptSummary,
};
#[cfg(feature = "local-signer-client")]
use privacy_pools_sdk_signer::{LocalMnemonicSigner, SignerAdapter};
use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf, str::FromStr};

sol! {
    interface IPrivacyPoolSpec {
        function ENTRYPOINT() external view returns (address);
        function currentRootIndex() external view returns (uint32);
        function roots(uint256 index) external view returns (uint256);
    }
}

const ROOT_HISTORY_SIZE: u32 = 64;

fn state_root_read(pool: Address) -> RootRead {
    chain_state_root_read(pool, ReadConsistency::Latest)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionPolicyFixture {
    chain_id: u64,
    caller: String,
    pool_address: String,
    entrypoint_address: String,
    pool_code_hash: String,
    entrypoint_code_hash: String,
    state_root: String,
    asp_root: String,
    estimated_gas: u64,
    nonce: u64,
    proof: FormattedGroth16Proof,
    withdrawal: WithdrawalFixture,
}

#[derive(Debug, Deserialize)]
struct WithdrawalFixture {
    #[allow(dead_code)]
    processooor: String,
    data: String,
}

#[derive(Debug, Clone)]
struct MockClient {
    chain_id: u64,
    code_hashes: HashMap<Address, B256>,
    roots: HashMap<(Address, Bytes), U256>,
    estimated_gas: u64,
    nonce: u64,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn entrypoint_read(pool: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool,
        pool_address: pool,
        call_data: Bytes::from(IPrivacyPoolSpec::ENTRYPOINTCall {}.abi_encode()),
        consistency: ReadConsistency::Latest,
    }
}

fn current_root_index_read(pool: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool,
        pool_address: pool,
        call_data: Bytes::from(IPrivacyPoolSpec::currentRootIndexCall {}.abi_encode()),
        consistency: ReadConsistency::Latest,
    }
}

fn historical_state_root_read(pool: Address, index: u32) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool,
        pool_address: pool,
        call_data: Bytes::from(
            IPrivacyPoolSpec::rootsCall {
                index: U256::from(index),
            }
            .abi_encode(),
        ),
        consistency: ReadConsistency::Latest,
    }
}

fn read_fixture() -> ExecutionPolicyFixture {
    serde_json::from_slice(
        &fs::read(workspace_path("fixtures/spec/execution-policy.json")).unwrap(),
    )
    .unwrap()
}

fn fixture_plan(fixture: &ExecutionPolicyFixture) -> TransactionPlan {
    TransactionPlan {
        kind: TransactionKind::Withdraw,
        chain_id: fixture.chain_id,
        target: Address::from_str(&fixture.pool_address).unwrap(),
        calldata: Bytes::from_str(&fixture.withdrawal.data).unwrap(),
        value: U256::ZERO,
        proof: fixture.proof.clone(),
    }
}

fn strict_policy(fixture: &ExecutionPolicyFixture) -> ExecutionPolicy {
    ExecutionPolicy {
        expected_chain_id: fixture.chain_id,
        caller: Address::from_str(&fixture.caller).unwrap(),
        expected_pool_code_hash: Some(B256::from_str(&fixture.pool_code_hash).unwrap()),
        expected_entrypoint_code_hash: Some(B256::from_str(&fixture.entrypoint_code_hash).unwrap()),
        mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None
    }
}

fn happy_client(fixture: &ExecutionPolicyFixture) -> MockClient {
    let pool = Address::from_str(&fixture.pool_address).unwrap();
    let entrypoint = Address::from_str(&fixture.entrypoint_address).unwrap();
    let state_root = U256::from_str(&fixture.state_root).unwrap();
    let asp_root = U256::from_str(&fixture.asp_root).unwrap();
    MockClient {
        chain_id: fixture.chain_id,
        code_hashes: HashMap::from([
            (pool, B256::from_str(&fixture.pool_code_hash).unwrap()),
            (
                entrypoint,
                B256::from_str(&fixture.entrypoint_code_hash).unwrap(),
            ),
        ]),
        roots: HashMap::from([
            (
                (pool, entrypoint_read(pool).call_data),
                U256::from_be_slice(entrypoint.as_slice()),
            ),
            ((pool, state_root_read(pool).call_data), state_root),
            (
                (
                    entrypoint,
                    privacy_pools_sdk_chain::asp_root_read(
                        entrypoint,
                        pool,
                        ReadConsistency::Latest,
                    )
                    .call_data,
                ),
                asp_root,
            ),
        ]),
        estimated_gas: fixture.estimated_gas,
        nonce: fixture.nonce,
    }
}

#[async_trait]
impl ExecutionClient for MockClient {
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
                ChainError::Transport(format!("missing read for {}", read.contract_address))
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

#[async_trait]
impl FinalizationClient for MockClient {
    async fn next_nonce(&self, _caller: Address) -> Result<u64, ChainError> {
        Ok(self.nonce)
    }

    async fn fee_parameters(&self) -> Result<FeeParameters, ChainError> {
        Ok(FeeParameters {
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        })
    }

    async fn submit_raw_transaction(
        &self,
        _encoded_tx: &[u8],
    ) -> Result<TransactionReceiptSummary, ChainError> {
        Ok(TransactionReceiptSummary {
            transaction_hash: Default::default(),
            block_hash: None,
            block_number: Some(1),
            transaction_index: Some(0),
            success: true,
            gas_used: self.estimated_gas,
            effective_gas_price: "1".to_owned(),
            from: address!("1111111111111111111111111111111111111111"),
            to: Some(address!("2222222222222222222222222222222222222222")),
        })
    }
}

#[tokio::test]
async fn strict_execution_policy_fixture_happy_path_preflights_and_finalizes() {
    let fixture = read_fixture();
    let client = happy_client(&fixture);
    let policy = strict_policy(&fixture);
    let pool = Address::from_str(&fixture.pool_address).unwrap();
    let report = preflight_withdrawal(
        &client,
        &fixture_plan(&fixture),
        pool,
        U256::from_str(&fixture.state_root).unwrap(),
        U256::from_str(&fixture.asp_root).unwrap(),
        &policy,
    )
    .await
    .expect("preflight succeeds");
    let (_, finalized) = finalize_transaction(&client, &fixture_plan(&fixture), &report)
        .await
        .expect("finalize succeeds");

    assert_eq!(report.expected_chain_id, fixture.chain_id);
    assert_eq!(report.estimated_gas, fixture.estimated_gas);
    assert_eq!(finalized.nonce, fixture.nonce);
}

#[tokio::test]
async fn strict_execution_policy_fixture_rejects_wrong_chain_root_and_code_hash() {
    let fixture = read_fixture();
    let policy = strict_policy(&fixture);
    let pool = Address::from_str(&fixture.pool_address).unwrap();
    let state_root = U256::from_str(&fixture.state_root).unwrap();
    let asp_root = U256::from_str(&fixture.asp_root).unwrap();

    let mut wrong_chain = happy_client(&fixture);
    wrong_chain.chain_id += 1;
    assert!(matches!(
        preflight_withdrawal(
            &wrong_chain,
            &fixture_plan(&fixture),
            pool,
            state_root,
            asp_root,
            &policy,
        )
        .await,
        Err(ChainError::ChainIdMismatch { .. })
    ));

    let mut wrong_root = happy_client(&fixture);
    wrong_root
        .roots
        .insert((pool, state_root_read(pool).call_data), U256::from(999_u64));
    wrong_root
        .roots
        .insert((pool, current_root_index_read(pool).call_data), U256::ZERO);
    for index in 0..ROOT_HISTORY_SIZE {
        wrong_root.roots.insert(
            (pool, historical_state_root_read(pool, index).call_data),
            U256::from(888_u64 + u64::from(index)),
        );
    }
    assert!(matches!(
        preflight_withdrawal(
            &wrong_root,
            &fixture_plan(&fixture),
            pool,
            state_root,
            asp_root,
            &policy,
        )
        .await,
        Err(ChainError::StateRootMismatch { .. })
    ));

    let mut wrong_hash = happy_client(&fixture);
    wrong_hash.code_hashes.insert(pool, B256::repeat_byte(0x55));
    assert!(matches!(
        preflight_withdrawal(
            &wrong_hash,
            &fixture_plan(&fixture),
            pool,
            state_root,
            asp_root,
            &policy,
        )
        .await,
        Err(ChainError::CodeHashMismatch { .. })
    ));
}

#[cfg(feature = "local-signer-client")]
#[tokio::test]
async fn strict_execution_policy_fixture_rejects_wrong_signer_submission() {
    use alloy_primitives::bytes;
    use privacy_pools_sdk_chain::submit_signed_transaction;
    use privacy_pools_sdk_core::FinalizedTransactionRequest;

    let fixture = read_fixture();
    let right_signer = LocalMnemonicSigner::from_phrase_nth(
        "test test test test test test test test test test test junk",
        0,
    )
    .unwrap();
    let wrong_signer = LocalMnemonicSigner::from_phrase_nth(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        0,
    )
    .unwrap();
    let client = happy_client(&fixture);
    let request = FinalizedTransactionRequest {
        kind: TransactionKind::Withdraw,
        chain_id: fixture.chain_id,
        from: right_signer.address(),
        to: Address::from_str(&fixture.pool_address).unwrap(),
        nonce: fixture.nonce,
        gas_limit: fixture.estimated_gas,
        value: U256::ZERO,
        data: bytes!("1234"),
        gas_price: Some(1),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    let signed = wrong_signer.sign_transaction_request(&request).unwrap();

    assert!(matches!(
        submit_signed_transaction(&client, &request, &signed).await,
        Err(ChainError::SignedTransactionSignerMismatch { expected, actual })
            if expected == right_signer.address() && actual == wrong_signer.address()
    ));
}
