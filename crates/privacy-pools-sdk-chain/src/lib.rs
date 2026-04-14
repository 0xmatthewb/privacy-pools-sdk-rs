use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use privacy_pools_sdk_core::{
    FormattedGroth16Proof, ProofBundle, RootRead, RootReadKind, field_to_hex_32,
    parse_decimal_field,
};
use thiserror::Error;

sol! {
    interface IPrivacyPool {
        function currentRoot() external view returns (uint256);
    }

    interface IEntrypoint {
        function latestRoot(address pool) external view returns (uint256);
    }
}

#[derive(Debug, Error)]
pub enum ChainError {
    #[error(transparent)]
    Core(#[from] privacy_pools_sdk_core::CoreError),
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
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
}
