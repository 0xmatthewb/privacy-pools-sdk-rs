use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use async_trait::async_trait;
use privacy_pools_sdk_chain::{
    ChainError, ExecutionClient, asp_root_read as chain_asp_root_read, preflight_withdrawal,
    state_root_read as chain_state_root_read,
};
use privacy_pools_sdk_core::{
    ExecutionPolicy, ExecutionPolicyMode, FormattedGroth16Proof, ReadConsistency, RootRead,
    RootReadKind, TransactionKind, TransactionPlan,
};
use proptest::prelude::*;
use std::collections::HashMap;
use tokio::runtime::Builder;

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

fn asp_root_read(entrypoint: Address, pool: Address) -> RootRead {
    chain_asp_root_read(entrypoint, pool, ReadConsistency::Latest)
}

#[derive(Debug, Clone)]
struct MockClient {
    chain_id: u64,
    code_hashes: HashMap<Address, B256>,
    roots: HashMap<(Address, Bytes), U256>,
    estimated_gas: u64,
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
                ChainError::Transport(format!("missing root for {}", read.contract_address))
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

fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

fn arb_b256() -> impl Strategy<Value = B256> {
    any::<[u8; 32]>().prop_map(B256::from)
}

fn plan(chain_id: u64, target: Address) -> TransactionPlan {
    TransactionPlan {
        kind: TransactionKind::Withdraw,
        chain_id,
        target,
        calldata: Bytes::from_static(b"\x12\x34"),
        value: U256::ZERO,
        proof: FormattedGroth16Proof {
            p_a: ["0x01".to_owned(), "0x02".to_owned()],
            p_b: [
                ["0x03".to_owned(), "0x04".to_owned()],
                ["0x05".to_owned(), "0x06".to_owned()],
            ],
            p_c: ["0x07".to_owned(), "0x08".to_owned()],
            pub_signals: vec!["0x09".to_owned(); 8],
        },
    }
}

fn strict_policy(
    expected_chain_id: u64,
    caller: Address,
    expected_pool_code_hash: B256,
    expected_entrypoint_code_hash: B256,
) -> ExecutionPolicy {
    ExecutionPolicy {
        expected_chain_id,
        caller,
        expected_pool_code_hash: Some(expected_pool_code_hash),
        expected_entrypoint_code_hash: Some(expected_entrypoint_code_hash),
        mode: ExecutionPolicyMode::Strict,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None
    }
}

fn run_preflight(
    client: &MockClient,
    plan: &TransactionPlan,
    pool: Address,
    state_root: U256,
    asp_root: U256,
    policy: &ExecutionPolicy,
) -> Result<(), ChainError> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            preflight_withdrawal(client, plan, pool, state_root, asp_root, policy)
                .await
                .map(|_| ())
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn strict_preflight_rejects_chain_id_mismatches(
        expected_chain_id in 1_u64..u64::MAX,
        actual_chain_id in 1_u64..u64::MAX,
        caller in arb_address(),
        pool in arb_address(),
        entrypoint in arb_address(),
        pool_hash in arb_b256(),
        entrypoint_hash in arb_b256(),
        state_root in any::<[u8; 32]>(),
        asp_root in any::<[u8; 32]>(),
    ) {
        prop_assume!(expected_chain_id != actual_chain_id);
        let state_root = U256::from_be_slice(&state_root);
        let asp_root = U256::from_be_slice(&asp_root);
        let client = MockClient {
            chain_id: actual_chain_id,
            code_hashes: HashMap::from([(pool, pool_hash), (entrypoint, entrypoint_hash)]),
            roots: HashMap::from([
                (
                    (pool, entrypoint_read(pool).call_data),
                    U256::from_be_slice(entrypoint.as_slice()),
                ),
                ((pool, state_root_read(pool).call_data), state_root),
                ((entrypoint, asp_root_read(entrypoint, pool).call_data), asp_root),
            ]),
            estimated_gas: 21_000,
        };
        let policy = strict_policy(expected_chain_id, caller, pool_hash, entrypoint_hash);
        let result = run_preflight(
            &client,
            &plan(expected_chain_id, pool),
            pool,
            state_root,
            asp_root,
            &policy,
        );

        let error = result.expect_err("chain id mismatch should fail");
        match error {
            ChainError::ChainIdMismatch { expected, actual } => {
                prop_assert_eq!(expected, expected_chain_id);
                prop_assert_eq!(actual, actual_chain_id);
            }
            other => prop_assert!(false, "unexpected error: {:?}", other),
        }
    }

    #[test]
    fn strict_preflight_rejects_root_and_code_hash_mismatches(
        chain_id in 1_u64..u64::MAX,
        caller in arb_address(),
        pool in arb_address(),
        entrypoint in arb_address(),
        expected_pool_hash in arb_b256(),
        actual_pool_hash in arb_b256(),
        entrypoint_hash in arb_b256(),
        expected_state_root in any::<[u8; 32]>(),
        actual_state_root in any::<[u8; 32]>(),
        asp_root in any::<[u8; 32]>(),
    ) {
        let expected_state_root = U256::from_be_slice(&expected_state_root);
        let actual_state_root = U256::from_be_slice(&actual_state_root);
        let asp_root = U256::from_be_slice(&asp_root);
        let policy = strict_policy(chain_id, caller, expected_pool_hash, entrypoint_hash);

        if expected_pool_hash == actual_pool_hash {
            prop_assume!(expected_state_root != actual_state_root);
            let client = MockClient {
                chain_id,
                code_hashes: HashMap::from([(pool, expected_pool_hash), (entrypoint, entrypoint_hash)]),
                roots: HashMap::from([
                    (
                        (pool, entrypoint_read(pool).call_data),
                        U256::from_be_slice(entrypoint.as_slice()),
                    ),
                    ((pool, state_root_read(pool).call_data), actual_state_root),
                    ((pool, current_root_index_read(pool).call_data), U256::ZERO),
                    ((entrypoint, asp_root_read(entrypoint, pool).call_data), asp_root),
                ])
                .into_iter()
                .chain((0..ROOT_HISTORY_SIZE).map(|index| {
                    (
                        (pool, historical_state_root_read(pool, index).call_data),
                        actual_state_root + U256::from(index + 1),
                    )
                }))
                .collect(),
                estimated_gas: 21_000,
            };
            let result = run_preflight(
                &client,
                &plan(chain_id, pool),
                pool,
                expected_state_root,
                asp_root,
                &policy,
            );
            let error = result.expect_err("state root mismatch should fail");
            match error {
                ChainError::StateRootMismatch { expected, actual } => {
                    prop_assert_eq!(expected, expected_state_root);
                    prop_assert_eq!(actual, actual_state_root);
                }
                other => prop_assert!(false, "unexpected error: {:?}", other),
            }
        } else {
            let client = MockClient {
                chain_id,
                code_hashes: HashMap::from([(pool, actual_pool_hash), (entrypoint, entrypoint_hash)]),
                roots: HashMap::from([
                    (
                        (pool, entrypoint_read(pool).call_data),
                        U256::from_be_slice(entrypoint.as_slice()),
                    ),
                    ((pool, state_root_read(pool).call_data), expected_state_root),
                    ((entrypoint, asp_root_read(entrypoint, pool).call_data), asp_root),
                ]),
                estimated_gas: 21_000,
            };
            let result = run_preflight(
                &client,
                &plan(chain_id, pool),
                pool,
                expected_state_root,
                asp_root,
                &policy,
            );
            let error = result.expect_err("code hash mismatch should fail");
            match error {
                ChainError::CodeHashMismatch {
                    address,
                    expected,
                    actual,
                } => {
                    prop_assert_eq!(address, pool);
                    prop_assert_eq!(expected, expected_pool_hash);
                    prop_assert_eq!(actual, actual_pool_hash);
                }
                other => prop_assert!(false, "unexpected error: {:?}", other),
            }
        }
    }
}
