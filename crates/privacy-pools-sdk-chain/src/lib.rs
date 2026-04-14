use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use privacy_pools_sdk_core::{
    FormattedGroth16Proof, ProofBundle, RootRead, RootReadKind, TransactionKind, TransactionPlan,
    Withdrawal, field_to_hex_32, parse_decimal_field,
};
use thiserror::Error;

sol! {
    struct WithdrawalAbi {
        address processooor;
        bytes data;
    }

    struct WithdrawProofAbi {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[8] pubSignals;
    }

    interface IPrivacyPool {
        function currentRoot() external view returns (uint256);
        function withdraw(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof) external;
    }

    interface IEntrypoint {
        function latestRoot(address pool) external view returns (uint256);
        function relay(WithdrawalAbi _withdrawal, WithdrawProofAbi _proof, uint256 scope) external;
    }
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error(transparent)]
    Core(#[from] privacy_pools_sdk_core::CoreError),
    #[error("withdraw proof must contain exactly 8 public signals, got {0}")]
    InvalidWithdrawPublicSignals(usize),
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
        call_data: Bytes::from(IEntrypoint::latestRootCall { pool: pool_address }.abi_encode()),
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

fn withdrawal_abi(withdrawal: &Withdrawal) -> WithdrawalAbi {
    WithdrawalAbi {
        processooor: withdrawal.processooor,
        data: withdrawal.data.clone(),
    }
}

fn withdraw_proof_abi(proof: &ProofBundle) -> Result<WithdrawProofAbi, ChainError> {
    let public_signals = proof
        .public_signals
        .iter()
        .map(|value| parse_decimal_field(value))
        .collect::<Result<Vec<_>, _>>()?;
    let public_signals: [U256; 8] = public_signals
        .try_into()
        .map_err(|signals: Vec<U256>| ChainError::InvalidWithdrawPublicSignals(signals.len()))?;

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
    use alloy_primitives::{address, bytes};
    use serde_json::Value;

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
        assert_eq!(formatted.pub_signals.len(), 6);
        assert_eq!(
            formatted.pub_signals[0],
            fixture["expected"]["pubSignals"][0].as_str().unwrap()
        );
    }

    #[test]
    fn plans_withdraw_and_relay_transactions() {
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

        let withdraw = plan_withdrawal_transaction(
            1,
            address!("0987654321098765432109876543210987654321"),
            &withdrawal,
            &proof,
        )
        .unwrap();
        let relay = plan_relay_transaction(
            1,
            address!("1234567890123456789012345678901234567890"),
            &withdrawal,
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
}
