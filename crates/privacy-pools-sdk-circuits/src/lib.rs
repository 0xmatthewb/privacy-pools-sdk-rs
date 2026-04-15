use privacy_pools_sdk_core::{
    CircuitMerkleWitness, Commitment, CommitmentCircuitInput, CommitmentWitnessRequest,
    FieldElement, WithdrawalCircuitInput, WithdrawalWitnessRequest,
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
    #[error("withdrawal field `{field}` exceeds the circuit uint128 range: {value} > {max}")]
    ValueExceedsCircuitU128 {
        field: &'static str,
        value: FieldElement,
        max: FieldElement,
    },
    #[error(
        "withdrawal field `{field}` is outside the contract deposit range: {value} >= {max_exclusive}"
    )]
    ValueExceedsContractDepositRange {
        field: &'static str,
        value: FieldElement,
        max_exclusive: FieldElement,
    },
    #[error("new commitment field `{field}` cannot be zero")]
    NewCommitmentFieldZero { field: &'static str },
    #[error("new nullifier must not match the existing nullifier")]
    NewNullifierMatchesExisting,
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
    #[error("merkle witness root mismatch for `{name}`: expected {expected}, got {actual}")]
    WitnessRootMismatch {
        name: &'static str,
        expected: FieldElement,
        actual: FieldElement,
    },
}

pub fn build_commitment_circuit_input(
    request: &CommitmentWitnessRequest,
) -> Result<CommitmentCircuitInput, CircuitError> {
    validate_commitment_request(request)?;

    Ok(CommitmentCircuitInput {
        value: request.commitment.preimage.value,
        label: request.commitment.preimage.label,
        nullifier: request.commitment.preimage.precommitment.nullifier.into(),
        secret: request.commitment.preimage.precommitment.secret.clone(),
    })
}

pub fn validate_commitment_request(request: &CommitmentWitnessRequest) -> Result<(), CircuitError> {
    validate_commitment(&request.commitment, "value")
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
        context: crypto::calculate_withdrawal_context_field(&request.withdrawal, request.scope)?,
        label: request.commitment.preimage.label,
        existing_value: request.commitment.preimage.value,
        existing_nullifier: request.commitment.preimage.precommitment.nullifier.into(),
        existing_secret: request.commitment.preimage.precommitment.secret.clone(),
        new_nullifier: request.new_nullifier.clone(),
        new_secret: request.new_secret.clone(),
        state_siblings: request.state_witness.siblings.clone(),
        state_index: request.state_witness.index,
        asp_siblings: request.asp_witness.siblings.clone(),
        asp_index: request.asp_witness.index,
    })
}

pub fn validate_withdrawal_request(request: &WithdrawalWitnessRequest) -> Result<(), CircuitError> {
    validate_witness_shape("state", &request.state_witness)?;
    validate_witness_shape("asp", &request.asp_witness)?;

    validate_commitment(&request.commitment, "existingValue")?;

    if request.withdrawal_amount > request.commitment.preimage.value {
        return Err(CircuitError::WithdrawalAmountExceedsExistingValue {
            existing_value: request.commitment.preimage.value,
            withdrawal_amount: request.withdrawal_amount,
        });
    }

    validate_contract_deposit_value("existingValue", request.commitment.preimage.value)?;
    validate_circuit_u128("withdrawnValue", request.withdrawal_amount)?;
    validate_new_commitment_secret("newNullifier", &request.new_nullifier)?;
    validate_new_commitment_secret("newSecret", &request.new_secret)?;

    if request.new_nullifier == request.commitment.preimage.precommitment.nullifier {
        return Err(CircuitError::NewNullifierMatchesExisting);
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

fn validate_commitment(
    commitment: &Commitment,
    value_field: &'static str,
) -> Result<(), CircuitError> {
    validate_contract_deposit_value(value_field, commitment.preimage.value)?;

    let computed_commitment = recompute_commitment(commitment)?;
    for (field, expected, actual) in [
        (
            "precommitmentHash",
            commitment.preimage.precommitment.hash,
            computed_commitment.preimage.precommitment.hash,
        ),
        ("commitmentHash", commitment.hash, computed_commitment.hash),
        (
            "commitmentPrecommitmentHash",
            commitment.precommitment_hash,
            computed_commitment.precommitment_hash,
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

fn validate_circuit_u128(field: &'static str, value: FieldElement) -> Result<(), CircuitError> {
    let max = FieldElement::from(u128::MAX);
    if value > max {
        return Err(CircuitError::ValueExceedsCircuitU128 { field, value, max });
    }
    Ok(())
}

fn validate_contract_deposit_value(
    field: &'static str,
    value: FieldElement,
) -> Result<(), CircuitError> {
    let max_exclusive = FieldElement::from(u128::MAX);
    if value >= max_exclusive {
        return Err(CircuitError::ValueExceedsContractDepositRange {
            field,
            value,
            max_exclusive,
        });
    }
    Ok(())
}

fn validate_new_commitment_secret(
    field: &'static str,
    value: &privacy_pools_sdk_core::Secret,
) -> Result<(), CircuitError> {
    if value.is_zero() {
        return Err(CircuitError::NewCommitmentFieldZero { field });
    }
    Ok(())
}

fn recompute_commitment(commitment: &Commitment) -> Result<Commitment, CircuitError> {
    Ok(crypto::get_commitment(
        commitment.preimage.value,
        commitment.preimage.label,
        commitment.preimage.precommitment.nullifier,
        commitment.preimage.precommitment.secret.clone(),
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
    fn builds_commitment_inputs_for_valid_requests() {
        let request = CommitmentWitnessRequest {
            commitment: valid_request().commitment,
        };

        let input = build_commitment_circuit_input(&request).expect("request should be valid");

        assert_eq!(input.value, request.commitment.preimage.value);
        assert_eq!(input.label, request.commitment.preimage.label);
        assert_eq!(
            input.nullifier,
            request.commitment.preimage.precommitment.nullifier
        );
        assert_eq!(
            input.secret,
            request.commitment.preimage.precommitment.secret
        );
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

    #[test]
    fn rejects_commitment_inputs_outside_contract_deposit_range() {
        let mut request = CommitmentWitnessRequest {
            commitment: valid_request().commitment,
        };
        request.commitment = crypto::get_commitment(
            U256::from(u128::MAX),
            request.commitment.preimage.label,
            request.commitment.preimage.precommitment.nullifier,
            request.commitment.preimage.precommitment.secret,
        )
        .expect("commitment should build");

        let error = build_commitment_circuit_input(&request).expect_err("request should fail");

        assert!(matches!(
            error,
            CircuitError::ValueExceedsContractDepositRange { field, .. } if field == "value"
        ));
    }

    #[test]
    fn accepts_circuit_zero_sentinel_merkle_semantics() {
        let mut request = valid_request();
        request.state_witness.siblings[0] = U256::from(999_u64);
        request.state_witness.depth = 0;
        request.state_witness.root =
            tree::compute_circuit_root(&request.state_witness).expect("root should compute");

        let input = build_withdrawal_circuit_input(&request).expect("request should be valid");

        assert_eq!(input.state_root, request.state_witness.root);
        assert_eq!(input.state_tree_depth, 0);
    }

    #[test]
    fn rejects_new_commitment_zero_secrets() {
        let mut request = valid_request();
        request.new_nullifier = U256::ZERO.into();

        let error = build_withdrawal_circuit_input(&request).expect_err("request should fail");
        assert!(matches!(
            error,
            CircuitError::NewCommitmentFieldZero { field } if field == "newNullifier"
        ));

        let mut request = valid_request();
        request.new_secret = U256::ZERO.into();

        let error = build_withdrawal_circuit_input(&request).expect_err("request should fail");
        assert!(matches!(
            error,
            CircuitError::NewCommitmentFieldZero { field } if field == "newSecret"
        ));
    }

    #[test]
    fn rejects_reused_nullifiers_before_proving() {
        let mut request = valid_request();
        request.new_nullifier = request.commitment.preimage.precommitment.nullifier.into();

        let error = build_withdrawal_circuit_input(&request).expect_err("request should fail");
        assert!(matches!(error, CircuitError::NewNullifierMatchesExisting));
    }

    #[test]
    fn rejects_existing_values_outside_contract_deposit_range() {
        let mut request = valid_request();
        request.withdrawal_amount = U256::from(1_u64);
        request.commitment = crypto::get_commitment(
            U256::from(u128::MAX),
            request.commitment.preimage.label,
            request.commitment.preimage.precommitment.nullifier,
            request.commitment.preimage.precommitment.secret,
        )
        .expect("commitment should build");
        request.state_witness.leaf = request.commitment.hash;
        request.state_witness.root = request.commitment.hash;

        let error = build_withdrawal_circuit_input(&request).expect_err("request should fail");
        assert!(matches!(
            error,
            CircuitError::ValueExceedsContractDepositRange { field, .. } if field == "existingValue"
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
                processor: Address::repeat_byte(0x11),
                data: Bytes::from_static(&[0x12, 0x34]),
            },
            scope: U256::from(789_u64),
            withdrawal_amount: U256::from(400_u64),
            new_nullifier: U256::from(222_u64).into(),
            new_secret: U256::from(333_u64).into(),
        }
    }
}
