use alloy_primitives::{Address, B256, U256, address, bytes};
use privacy_pools_sdk_core::{
    CodeHashCheck, ExecutionPolicy, ExecutionPolicyMode, ExecutionPreflightReport, ReadConsistency,
    RelayData, RootCheck, RootRead, RootReadKind, TransactionKind, Withdrawal,
    WithdrawalExecutionConfig,
};
use proptest::prelude::*;

fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

fn arb_b256() -> impl Strategy<Value = B256> {
    any::<[u8; 32]>().prop_map(B256::from)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn execution_policy_json_roundtrips_with_strict_mode_omitted(
        expected_chain_id in 1_u64..u64::MAX,
        caller in arb_address(),
        expected_pool_code_hash in prop::option::of(arb_b256()),
        expected_entrypoint_code_hash in prop::option::of(arb_b256()),
        insecure_dev in any::<bool>(),
    ) {
        let policy = ExecutionPolicy {
            expected_chain_id,
            caller,
            expected_pool_code_hash,
            expected_entrypoint_code_hash,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: if insecure_dev {
                ExecutionPolicyMode::InsecureDev
            } else {
                ExecutionPolicyMode::Strict
            },
        };

        let json = serde_json::to_value(&policy).expect("policy serializes");
        let decoded: ExecutionPolicy = serde_json::from_value(json.clone()).expect("policy deserializes");

        prop_assert_eq!(decoded, policy);
        if insecure_dev {
            prop_assert_eq!(&json["mode"], &serde_json::json!("insecure_dev"));
        } else {
            prop_assert!(json.get("mode").is_none());
        }
    }

    #[test]
    fn execution_configs_and_reports_roundtrip_through_wire_shapes(
        chain_id in 1_u64..u64::MAX,
        caller in arb_address(),
        pool in arb_address(),
        entrypoint in arb_address(),
        expected_root in any::<[u8; 32]>(),
        actual_root in any::<[u8; 32]>(),
        code_hash in arb_b256(),
    ) {
        let policy = ExecutionPolicy {
            expected_chain_id: chain_id,
            caller,
            expected_pool_code_hash: Some(code_hash),
            expected_entrypoint_code_hash: Some(code_hash),
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: ExecutionPolicyMode::Strict,
        };
        let config = WithdrawalExecutionConfig {
            chain_id,
            pool_address: pool,
            policy: policy.clone(),
        };
        let report = ExecutionPreflightReport {
            kind: TransactionKind::Withdraw,
            caller,
            target: pool,
            expected_chain_id: chain_id,
            actual_chain_id: chain_id,
            chain_id_matches: true,
            simulated: true,
            estimated_gas: 21_000,
            read_consistency: ReadConsistency::Latest,
            max_fee_quote_wei: None,
            mode: ExecutionPolicyMode::Strict,
            code_hash_checks: vec![CodeHashCheck {
                address: pool,
                expected_code_hash: Some(code_hash),
                actual_code_hash: code_hash,
                matches_expected: Some(true),
            }],
            root_checks: vec![RootCheck {
                kind: RootReadKind::PoolState,
                contract_address: pool,
                pool_address: pool,
                expected_root: U256::from_be_slice(&expected_root),
                actual_root: U256::from_be_slice(&actual_root),
                matches: expected_root == actual_root,
            }],
        };
        let root_read = RootRead {
            kind: RootReadKind::Asp,
            contract_address: entrypoint,
            pool_address: pool,
            consistency: ReadConsistency::Latest,
            call_data: bytes!("1234"),
        };

        prop_assert_eq!(
            serde_json::from_value::<WithdrawalExecutionConfig>(
                serde_json::to_value(&config).expect("config serializes")
            )
            .expect("config deserializes"),
            config
        );
        prop_assert_eq!(
            serde_json::from_value::<ExecutionPreflightReport>(
                serde_json::to_value(&report).expect("report serializes")
            )
            .expect("report deserializes"),
            report
        );
        prop_assert_eq!(
            serde_json::from_value::<RootRead>(
                serde_json::to_value(&root_read).expect("root read serializes")
            )
            .expect("root read deserializes"),
            root_read
        );
    }
}

#[test]
fn withdrawal_alias_and_relay_encoding_remain_compatible() {
    let recipient = address!("1111111111111111111111111111111111111111");
    let fee_recipient = address!("2222222222222222222222222222222222222222");
    let entrypoint = address!("3333333333333333333333333333333333333333");
    let withdrawal = Withdrawal::relayed(
        entrypoint,
        &RelayData::new(recipient, fee_recipient, U256::from(25_u64)),
    );

    let json = serde_json::to_value(&withdrawal).expect("withdrawal serializes");
    assert_eq!(json["processooor"], entrypoint.to_string());
    assert!(json.get("processor").is_none());
}
