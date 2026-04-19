#![no_main]

use alloy_primitives::{Address, B256, Bytes, U256, address};
use alloy_sol_types::{SolCall, sol};
use async_trait::async_trait;
use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_chain::{
    ChainError, ExecutionClient, asp_root_read, preflight_withdrawal, state_root_read,
};
use privacy_pools_sdk_core::{
    ExecutionPolicy, ExecutionPolicyMode, FormattedGroth16Proof, ReadConsistency, RootRead,
    RootReadKind, TransactionKind, TransactionPlan,
};
use std::collections::HashMap;
use tokio::runtime::Builder;

sol! {
    interface IPrivacyPoolFuzzSpec {
        function ENTRYPOINT() external view returns (address);
        function currentRootIndex() external view returns (uint32);
        function roots(uint256 index) external view returns (uint256);
    }
}

const ROOT_HISTORY_SIZE: u32 = 64;

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
        call_data: Bytes::from(IPrivacyPoolFuzzSpec::ENTRYPOINTCall {}.abi_encode()),
        consistency: ReadConsistency::Latest,
    }
}

fn current_root_index_read(pool: Address) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool,
        pool_address: pool,
        call_data: Bytes::from(IPrivacyPoolFuzzSpec::currentRootIndexCall {}.abi_encode()),
        consistency: ReadConsistency::Latest,
    }
}

fn historical_state_root_read(pool: Address, index: u32) -> RootRead {
    RootRead {
        kind: RootReadKind::PoolState,
        contract_address: pool,
        pool_address: pool,
        call_data: Bytes::from(
            IPrivacyPoolFuzzSpec::rootsCall {
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
            .ok_or_else(|| ChainError::Transport(format!("missing root for {}", read.contract_address)))
    }

    async fn simulate_transaction(
        &self,
        _caller: Address,
        _plan: &TransactionPlan,
    ) -> Result<u64, ChainError> {
        Ok(self.estimated_gas)
    }
}

fn plan(chain_id: u64, pool: Address) -> TransactionPlan {
    TransactionPlan {
        kind: TransactionKind::Withdraw,
        chain_id,
        target: pool,
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

fuzz_target!(|data: &[u8]| {
    let pool = address!("2222222222222222222222222222222222222222");
    let entrypoint = address!("1111111111111111111111111111111111111111");
    let caller = address!("3333333333333333333333333333333333333333");
    let expected_chain_id = u64::from(data.first().copied().unwrap_or(1)).max(1);
    let state_root = U256::from_be_slice(&kept_32(data, 1));
    let asp_root = U256::from_be_slice(&kept_32(data, 33));
    let pool_hash = B256::from(kept_32(data, 65));
    let entrypoint_hash = B256::from(kept_32(data, 97));
    let actual_chain_id = if data.get(129).copied().unwrap_or(0) & 0x1 == 0 {
        expected_chain_id
    } else {
        expected_chain_id.saturating_add(1)
    };
    let actual_pool_hash = if data.get(130).copied().unwrap_or(0) & 0x1 == 0 {
        pool_hash
    } else {
        B256::from(kept_32(data, 131))
    };
    let actual_state_root = if data.get(163).copied().unwrap_or(0) & 0x1 == 0 {
        state_root
    } else {
        U256::from_be_slice(&kept_32(data, 164))
    };

    let mut roots = HashMap::from([
        (
            (pool, entrypoint_read(pool).call_data),
            U256::from_be_slice(entrypoint.as_slice()),
        ),
        (
            (pool, state_root_read(pool, ReadConsistency::Latest).call_data),
            actual_state_root,
        ),
        ((pool, current_root_index_read(pool).call_data), U256::ZERO),
        (
            (
                entrypoint,
                asp_root_read(entrypoint, pool, ReadConsistency::Latest).call_data,
            ),
            asp_root,
        ),
    ]);
    if actual_state_root != state_root {
        for index in 0..ROOT_HISTORY_SIZE {
            roots.insert(
                (pool, historical_state_root_read(pool, index).call_data),
                actual_state_root + U256::from(index + 1),
            );
        }
    }

    let client = MockClient {
        chain_id: actual_chain_id,
        code_hashes: HashMap::from([(pool, actual_pool_hash), (entrypoint, entrypoint_hash)]),
        roots,
        estimated_gas: 21_000,
    };
    let policy = ExecutionPolicy {
        expected_chain_id,
        caller,
        expected_pool_code_hash: Some(pool_hash),
        expected_entrypoint_code_hash: Some(entrypoint_hash),
        mode: ExecutionPolicyMode::Strict,
        read_consistency: ReadConsistency::Latest,
        max_fee_quote_wei: None,
    };
    let plan = plan(expected_chain_id, pool);

    let _ = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime builds")
        .block_on(async {
            preflight_withdrawal(&client, &plan, pool, state_root, asp_root, &policy).await
        });
});

fn kept_32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, byte) in data.iter().skip(offset).take(32).enumerate() {
        out[index] = *byte;
    }
    out
}
