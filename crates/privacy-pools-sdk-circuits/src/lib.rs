use privacy_pools_sdk_core::{
    CircuitMerkleWitness, Commitment, FieldElement, WithdrawalCircuitInput,
    WithdrawalWitnessRequest,
};
use privacy_pools_sdk_crypto as crypto;
use privacy_pools_sdk_tree as tree;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error(transparent)]
    Core(#[from] privacy_pools_sdk_core::CoreError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Tree(#[from] tree::TreeError),
    #[error(
        "withdrawal amount {withdrawal_amount} exceeds existing commitment value {existing_value}"
    )]
    WithdrawalAmountExceedsExistingValue {
        existing_value: FieldElement,
        withdrawal_amount: FieldElement,
    },
    #[error("state witness leaf mismatch: expected commitment hash {expected}, got {actual}")]
    StateWitnessLeafMismatch {
        expected: FieldElement,
        actual: FieldElement,
    },
    #[error("asp witness leaf mismatch: expected label {expected}, got {actual}")]
    AspWitnessLeafMismatch {
        expected: FieldElement,
        actual: FieldElement,
    },
    #[error("commitment field mismatch for {field}: expected {expected}, got {actual}")]
    CommitmentFieldMismatch {
        field: &'static str,
        expected: FieldElement,
        actual: FieldElement,
    },
    #[error("merkle witness depth for `{name}` exceeds protocol maximum {max_depth}: got {depth}")]
    WitnessDepthExceedsProtocolMaximum {
        name: &'static str,
        depth: usize,
        max_depth: usize,
    },
    #[error("merkle witness padding for `{name}` must be zero beyond depth {depth}")]
    WitnessPaddingNotZero { name: &'static str, depth: usize },
    #[error("merkle witness root mismatch for `{name}`: expected {expected}, got {actual}")]
    WitnessRootMismatch {
        name: &'static str,
        expected: FieldElement,
        actual: FieldElement,
    },
}

pub fn build_withdrawal_circuit_input(
    request: &WithdrawalWitnessRequest,
) -> Result<WithdrawalCircuitInput, CircuitError> {
    validate_withdrawal_request(request)?;

    Ok(WithdrawalCircuitInput {
        withdrawn_value: request.withdrawal_amount,
        state_root: request.state_witness.root,
        state_tree_depth: request.state_witness.depth,
        asp_root: request.asp_witness.root,
        asp_tree_depth: request.asp_witness.depth,
        context: crypto::calculate_context_field(&request.withdrawal, request.scope)?,
        label: request.commitment.preimage.label,
        existing_value: request.commitment.preimage.value,
        existing_nullifier: request.commitment.preimage.precommitment.nullifier,
        existing_secret: request.commitment.preimage.precommitment.secret,
        new_nullifier: request.new_nullifier,
        new_secret: request.new_secret,
        state_siblings: request.state_witness.siblings.clone(),
        state_index: request.state_witness.index,
        asp_siblings: request.asp_witness.siblings.clone(),
        asp_index: request.asp_witness.index,
    })
}

pub fn validate_withdrawal_request(request: &WithdrawalWitnessRequest) -> Result<(), CircuitError> {
    validate_witness_shape("state", &request.state_witness)?;
    validate_witness_shape("asp", &request.asp_witness)?;

    let computed_commitment = recompute_commitment(&request.commitment)?;
    for (field, expected, actual) in [
        (
            "precommitmentHash",
            request.commitment.preimage.precommitment.hash,
            computed_commitment.preimage.precommitment.hash,
        ),
        (
            "commitmentHash",
            request.commitment.hash,
            computed_commitment.hash,
        ),
        (
            "nullifierHash",
            request.commitment.nullifier_hash,
            computed_commitment.nullifier_hash,
        ),
    ] {
        if expected != actual {
            return Err(CircuitError::CommitmentFieldMismatch {
                field,
                expected,
                actual,
            });
        }
    }

    if request.withdrawal_amount > request.commitment.preimage.value {
        return Err(CircuitError::WithdrawalAmountExceedsExistingValue {
            existing_value: request.commitment.preimage.value,
            withdrawal_amount: request.withdrawal_amount,
        });
    }

    if request.state_witness.leaf != request.commitment.hash {
        return Err(CircuitError::StateWitnessLeafMismatch {
            expected: request.commitment.hash,
            actual: request.state_witness.leaf,
        });
    }

    if request.asp_witness.leaf != request.commitment.preimage.label {
        return Err(CircuitError::AspWitnessLeafMismatch {
            expected: request.commitment.preimage.label,
            actual: request.asp_witness.leaf,
        });
    }

    Ok(())
}

fn validate_witness_shape(
    name: &'static str,
    witness: &CircuitMerkleWitness,
) -> Result<(), CircuitError> {
    if witness.depth > tree::DEFAULT_CIRCUIT_DEPTH {
        return Err(CircuitError::WitnessDepthExceedsProtocolMaximum {
            name,
            depth: witness.depth,
            max_depth: tree::DEFAULT_CIRCUIT_DEPTH,
        });
    }

    if witness.siblings.len() != tree::DEFAULT_CIRCUIT_DEPTH {
        return Err(privacy_pools_sdk_core::CoreError::InvalidWitnessShape {
            name,
            expected: tree::DEFAULT_CIRCUIT_DEPTH,
            actual: witness.siblings.len(),
        }
        .into());
    }

    if witness
        .siblings
        .iter()
        .skip(witness.depth)
        .any(|sibling| !sibling.is_zero())
    {
        return Err(CircuitError::WitnessPaddingNotZero {
            name,
            depth: witness.depth,
        });
    }

    let computed_root = tree::compute_circuit_root(witness)?;
    if computed_root != witness.root {
        return Err(CircuitError::WitnessRootMismatch {
            name,
            expected: witness.root,
            actual: computed_root,
        });
    }

    Ok(())
}

fn recompute_commitment(commitment: &Commitment) -> Result<Commitment, CircuitError> {
    Ok(crypto::get_commitment(
        commitment.preimage.value,
        commitment.preimage.label,
        commitment.preimage.precommitment.nullifier,
        commitment.preimage.precommitment.secret,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256};

    #[test]
    fn builds_withdrawal_inputs_for_valid_requests() {
        let request = valid_request();
        let input = build_withdrawal_circuit_input(&request).expect("request should be valid");
        assert_eq!(input.withdrawn_value, U256::from(400_u64));
        assert_eq!(input.state_root, request.state_witness.root);
        assert_eq!(input.asp_root, request.asp_witness.root);
        assert_eq!(input.label, request.commitment.preimage.label);
    }

    #[test]
    fn rejects_commitment_mismatches() {
        let mut request = valid_request();
        request.commitment.preimage.precommitment.hash = U256::from(999_u64);
        let error = build_withdrawal_circuit_input(&request).expect_err("request should fail");
        assert!(matches!(
            error,
            CircuitError::CommitmentFieldMismatch { field, .. } if field == "precommitmentHash"
        ));
    }

    fn valid_request() -> WithdrawalWitnessRequest {
        let commitment = crypto::get_commitment(
            U256::from(1_000_u64),
            U256::from(456_u64),
            U256::from(66_u64),
            U256::from(77_u64),
        )
        .expect("commitment should build");

        WithdrawalWitnessRequest {
            state_witness: CircuitMerkleWitness {
                root: commitment.hash,
                leaf: commitment.hash,
                index: 0,
                siblings: vec![U256::ZERO; 32],
                depth: 0,
            },
            asp_witness: CircuitMerkleWitness {
                root: commitment.preimage.label,
                leaf: commitment.preimage.label,
                index: 0,
                siblings: vec![U256::ZERO; 32],
                depth: 0,
            },
            commitment,
            withdrawal: privacy_pools_sdk_core::Withdrawal {
                processooor: Address::repeat_byte(0x11),
                data: Bytes::from_static(&[0x12, 0x34]),
            },
            scope: U256::from(789_u64),
            withdrawal_amount: U256::from(400_u64),
            new_nullifier: U256::from(222_u64),
            new_secret: U256::from(333_u64),
        }
    }
}
