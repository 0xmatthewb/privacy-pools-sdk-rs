use alloy_primitives::U256;
use lean_imt::lean_imt::{LeanIMT, LeanIMTError, MerkleProof as LeanMerkleProof};
use privacy_pools_sdk_core::{CircuitMerkleWitness, FieldElement, MerkleProof};
use privacy_pools_sdk_crypto::poseidon_hash;
use thiserror::Error;

pub const DEFAULT_CIRCUIT_DEPTH: usize = 32;

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("leaf not found in the leaves array")]
    LeafNotFound,
    #[error("circuit depth {depth} is smaller than proof depth {proof_depth}")]
    InvalidCircuitDepth { depth: usize, proof_depth: usize },
    #[error("circuit depth {depth} exceeds protocol maximum {max_depth}")]
    DepthExceedsProtocolMaximum { depth: usize, max_depth: usize },
    #[error(transparent)]
    LeanImt(#[from] LeanIMTError),
    #[error(transparent)]
    Crypto(#[from] privacy_pools_sdk_crypto::CryptoError),
}

pub fn generate_merkle_proof(
    leaves: &[FieldElement],
    leaf: FieldElement,
) -> Result<MerkleProof, TreeError> {
    let leaf_bytes = leaves
        .iter()
        .copied()
        .map(field_to_bytes)
        .collect::<Vec<_>>();
    let tree = LeanIMT::<32>::new(&leaf_bytes, lean_poseidon_hash)?;
    let leaf_index = tree
        .index_of(&field_to_bytes(leaf))
        .ok_or(TreeError::LeafNotFound)?;
    let proof = tree.generate_proof(leaf_index)?;
    Ok(from_lean_proof(proof))
}

pub fn verify_merkle_proof(proof: &MerkleProof) -> Result<bool, TreeError> {
    let lean = LeanMerkleProof {
        root: field_to_bytes(proof.root),
        leaf: field_to_bytes(proof.leaf),
        index: proof.index,
        siblings: proof.siblings.iter().copied().map(field_to_bytes).collect(),
    };
    Ok(LeanIMT::<32>::verify_proof(&lean, lean_poseidon_hash))
}

pub fn to_circuit_witness(
    proof: &MerkleProof,
    depth: usize,
) -> Result<CircuitMerkleWitness, TreeError> {
    if depth > DEFAULT_CIRCUIT_DEPTH {
        return Err(TreeError::DepthExceedsProtocolMaximum {
            depth,
            max_depth: DEFAULT_CIRCUIT_DEPTH,
        });
    }

    if proof.siblings.len() > depth {
        return Err(TreeError::InvalidCircuitDepth {
            depth,
            proof_depth: proof.siblings.len(),
        });
    }

    let mut siblings = proof.siblings.clone();
    siblings.resize(depth, U256::ZERO);

    Ok(CircuitMerkleWitness {
        root: proof.root,
        leaf: proof.leaf,
        index: proof.index,
        siblings,
        depth,
    })
}

fn from_lean_proof(proof: LeanMerkleProof<32>) -> MerkleProof {
    MerkleProof {
        root: bytes_to_field(proof.root),
        leaf: bytes_to_field(proof.leaf),
        index: proof.index,
        siblings: proof.siblings.into_iter().map(bytes_to_field).collect(),
    }
}

fn lean_poseidon_hash(input: &[u8]) -> [u8; 32] {
    let left = U256::from_be_slice(&input[..32]);
    let right = U256::from_be_slice(&input[32..64]);
    field_to_bytes(poseidon_hash(&[left, right]).expect("poseidon pair hash should succeed"))
}

fn bytes_to_field(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

fn field_to_bytes(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::str::FromStr;

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .expect("valid tree fixture")
    }

    #[test]
    fn matches_current_sdk_merkle_proof_shape() {
        let proof = generate_merkle_proof(
            &[
                U256::from(11),
                U256::from(22),
                U256::from(33),
                U256::from(44),
                U256::from(55),
            ],
            U256::from(44),
        )
        .unwrap();

        let fixture = vector();
        assert_eq!(
            proof.root,
            U256::from_str(fixture["merkleProof"]["root"].as_str().unwrap()).unwrap()
        );
        assert_eq!(proof.leaf, U256::from(44));
        assert_eq!(
            proof.index,
            fixture["merkleProof"]["index"].as_u64().unwrap() as usize
        );
        assert_eq!(proof.siblings[0], U256::from(33));

        let witness = to_circuit_witness(&proof, DEFAULT_CIRCUIT_DEPTH).unwrap();
        assert_eq!(witness.siblings.len(), DEFAULT_CIRCUIT_DEPTH);
        assert_eq!(witness.siblings[3], U256::ZERO);
        assert!(verify_merkle_proof(&proof).unwrap());
    }

    #[test]
    fn duplicate_leaves_use_first_match() {
        let proof = generate_merkle_proof(
            &[
                U256::from(11),
                U256::from(22),
                U256::from(22),
                U256::from(44),
            ],
            U256::from(22),
        )
        .unwrap();

        assert_eq!(proof.index, 1);
        assert!(verify_merkle_proof(&proof).unwrap());
    }

    #[test]
    fn missing_leaves_fail_closed() {
        assert!(matches!(
            generate_merkle_proof(&[U256::from(11), U256::from(22)], U256::from(33)),
            Err(TreeError::LeafNotFound)
        ));
    }

    #[test]
    fn empty_trees_fail_closed() {
        assert!(matches!(
            generate_merkle_proof(&[], U256::from(33)),
            Err(TreeError::LeafNotFound)
        ));
    }

    #[test]
    fn singleton_trees_generate_empty_sibling_paths() {
        let proof = generate_merkle_proof(&[U256::from(44)], U256::from(44)).unwrap();

        assert_eq!(proof.root, U256::from(44));
        assert_eq!(proof.leaf, U256::from(44));
        assert_eq!(proof.index, 0);
        assert!(proof.siblings.is_empty());
        assert!(verify_merkle_proof(&proof).unwrap());

        let witness = to_circuit_witness(&proof, DEFAULT_CIRCUIT_DEPTH).unwrap();
        assert_eq!(witness.siblings.len(), DEFAULT_CIRCUIT_DEPTH);
        assert!(
            witness
                .siblings
                .iter()
                .all(|sibling| *sibling == U256::ZERO)
        );
    }

    #[test]
    fn rejects_witness_depths_above_protocol_maximum() {
        let proof = generate_merkle_proof(
            &[
                U256::from(11),
                U256::from(22),
                U256::from(33),
                U256::from(44),
            ],
            U256::from(44),
        )
        .unwrap();

        assert!(matches!(
            to_circuit_witness(&proof, DEFAULT_CIRCUIT_DEPTH + 1),
            Err(TreeError::DepthExceedsProtocolMaximum {
                depth,
                max_depth
            }) if depth == DEFAULT_CIRCUIT_DEPTH + 1 && max_depth == DEFAULT_CIRCUIT_DEPTH
        ));
    }
}
