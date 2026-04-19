//! Fail-closed Merkle helpers for Privacy Pools circuit witnesses.
//!
//! All public entrypoints validate canonical BN254 field elements before they
//! enter the tree. Verification returns `false` instead of panicking on
//! malformed proofs, and generation rejects non-canonical leaves up front.
//!
//! Reorg handling is intentionally stateless: callers should rebuild proofs and
//! witnesses from the canonical post-reorg leaf sequence rather than trying to
//! mutate a cached tree in place. A typical recovery flow is "rewind local
//! events to the reorg boundary, replay the canonical leaf stream, then call
//! [`generate_merkle_proof`] and [`to_circuit_witness`] again".

use alloy_primitives::U256;
use lean_imt::lean_imt::{LeanIMT, LeanIMTError, MerkleProof as LeanMerkleProof};
use privacy_pools_sdk_core::{
    CircuitMerkleWitness, FieldElement, MerkleProof, parse_decimal_field,
};
use privacy_pools_sdk_crypto::poseidon_hash;
use std::{cell::RefCell, sync::LazyLock};
use thiserror::Error;

pub const DEFAULT_CIRCUIT_DEPTH: usize = 32;
static SNARK_SCALAR_FIELD_MODULUS: LazyLock<FieldElement> = LazyLock::new(|| {
    // This literal is fixed by the protocol. If parsing ever regresses, return
    // zero so all field checks fail closed instead of silently accepting values.
    parse_decimal_field(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap_or(U256::ZERO)
});
thread_local! {
    static LEAN_HASH_ERROR: RefCell<Option<TreeError>> = const { RefCell::new(None) };
}

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("leaf not found in the leaves array")]
    LeafNotFound,
    #[error("invalid lean hash input length: expected 64 bytes, got {actual}")]
    InvalidLeanHashInput { actual: usize },
    #[error("invalid circuit witness shape: expected {expected} siblings, got {actual}")]
    InvalidCircuitWitnessShape { expected: usize, actual: usize },
    #[error("circuit witness index {index} exceeds circuit index bit width {depth}")]
    InvalidCircuitWitnessIndex { index: usize, depth: usize },
    #[error("circuit depth {depth} is smaller than proof depth {proof_depth}")]
    InvalidCircuitDepth { depth: usize, proof_depth: usize },
    #[error("circuit depth {depth} exceeds protocol maximum {max_depth}")]
    DepthExceedsProtocolMaximum { depth: usize, max_depth: usize },
    #[error("non-canonical field element for {field}: {value} >= {modulus}")]
    NonCanonicalField {
        field: &'static str,
        value: FieldElement,
        modulus: FieldElement,
    },
    #[error(transparent)]
    LeanImt(#[from] LeanIMTError),
    #[error(transparent)]
    Crypto(#[from] privacy_pools_sdk_crypto::CryptoError),
}

pub fn generate_merkle_proof(
    leaves: &[FieldElement],
    leaf: FieldElement,
) -> Result<MerkleProof, TreeError> {
    for value in leaves {
        ensure_canonical_field(*value, "leaf")?;
    }
    ensure_canonical_field(leaf, "leaf")?;
    let leaf_bytes = leaves
        .iter()
        .copied()
        .map(field_to_bytes)
        .collect::<Vec<_>>();
    let tree = with_lean_hash_error(|| LeanIMT::<32>::new(&leaf_bytes, lean_poseidon_hash))??;
    let leaf_index = tree
        .index_of(&field_to_bytes(leaf))
        .ok_or(TreeError::LeafNotFound)?;
    let proof = from_lean_proof(tree.generate_proof(leaf_index)?);
    validate_merkle_proof_fields(&proof)?;
    Ok(proof)
}

pub fn verify_merkle_proof(proof: &MerkleProof) -> bool {
    if validate_merkle_proof_fields(proof).is_err() {
        return false;
    }
    let lean = LeanMerkleProof {
        root: field_to_bytes(proof.root),
        leaf: field_to_bytes(proof.leaf),
        index: proof.index,
        siblings: proof.siblings.iter().copied().map(field_to_bytes).collect(),
    };
    with_lean_hash_error(|| LeanIMT::<32>::verify_proof(&lean, lean_poseidon_hash))
        .unwrap_or(false)
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
    siblings.resize(DEFAULT_CIRCUIT_DEPTH, U256::ZERO);

    Ok(CircuitMerkleWitness {
        root: proof.root,
        leaf: proof.leaf,
        index: proof.index,
        siblings,
        depth,
    })
}

pub fn compute_circuit_root(witness: &CircuitMerkleWitness) -> Result<FieldElement, TreeError> {
    if witness.depth > DEFAULT_CIRCUIT_DEPTH {
        return Err(TreeError::DepthExceedsProtocolMaximum {
            depth: witness.depth,
            max_depth: DEFAULT_CIRCUIT_DEPTH,
        });
    }

    if witness.siblings.len() != DEFAULT_CIRCUIT_DEPTH {
        return Err(TreeError::InvalidCircuitWitnessShape {
            expected: DEFAULT_CIRCUIT_DEPTH,
            actual: witness.siblings.len(),
        });
    }

    let mut node = witness.leaf;
    if DEFAULT_CIRCUIT_DEPTH < usize::BITS as usize && (witness.index >> DEFAULT_CIRCUIT_DEPTH) != 0
    {
        return Err(TreeError::InvalidCircuitWitnessIndex {
            index: witness.index,
            depth: DEFAULT_CIRCUIT_DEPTH,
        });
    }

    for (level, sibling) in witness.siblings.iter().copied().enumerate() {
        if sibling.is_zero() {
            continue;
        }

        let is_right = ((witness.index >> level) & 1) == 1;
        node = if is_right {
            poseidon_hash(&[sibling, node])?
        } else {
            poseidon_hash(&[node, sibling])?
        };
    }

    Ok(node)
}

pub fn verify_circuit_witness(witness: &CircuitMerkleWitness) -> Result<bool, TreeError> {
    Ok(compute_circuit_root(witness)? == witness.root)
}

fn from_lean_proof(proof: LeanMerkleProof<32>) -> MerkleProof {
    MerkleProof {
        root: bytes_to_field(proof.root),
        leaf: bytes_to_field(proof.leaf),
        index: proof.index,
        siblings: proof.siblings.into_iter().map(bytes_to_field).collect(),
    }
}

fn with_lean_hash_error<T>(operation: impl FnOnce() -> T) -> Result<T, TreeError> {
    LEAN_HASH_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
    let value = operation();
    let error = LEAN_HASH_ERROR.with(|slot| slot.borrow_mut().take());
    match error {
        Some(error) => Err(error),
        None => Ok(value),
    }
}

fn try_lean_poseidon_hash(input: &[u8]) -> Result<[u8; 32], TreeError> {
    if input.len() != 64 {
        return Err(TreeError::InvalidLeanHashInput {
            actual: input.len(),
        });
    }

    let left = U256::from_be_slice(&input[..32]);
    let right = U256::from_be_slice(&input[32..64]);
    ensure_canonical_field(left, "left")?;
    ensure_canonical_field(right, "right")?;
    Ok(field_to_bytes(poseidon_hash(&[left, right])?))
}

fn lean_poseidon_hash(input: &[u8]) -> [u8; 32] {
    match try_lean_poseidon_hash(input) {
        Ok(value) => value,
        Err(error) => {
            LEAN_HASH_ERROR.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(error);
                }
            });
            [0_u8; 32]
        }
    }
}

fn bytes_to_field(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

fn field_to_bytes(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn validate_merkle_proof_fields(proof: &MerkleProof) -> Result<(), TreeError> {
    ensure_canonical_field(proof.root, "root")?;
    ensure_canonical_field(proof.leaf, "leaf")?;
    for sibling in &proof.siblings {
        ensure_canonical_field(*sibling, "sibling")?;
    }
    Ok(())
}

fn ensure_canonical_field(value: FieldElement, field: &'static str) -> Result<(), TreeError> {
    let modulus = snark_scalar_field_modulus();
    if value >= modulus {
        return Err(TreeError::NonCanonicalField {
            field,
            value,
            modulus,
        });
    }
    Ok(())
}

fn snark_scalar_field_modulus() -> FieldElement {
    *SNARK_SCALAR_FIELD_MODULUS
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{collection::vec, prelude::*};
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
        assert_eq!(compute_circuit_root(&witness).unwrap(), proof.root);
        assert!(verify_circuit_witness(&witness).unwrap());
        assert!(verify_merkle_proof(&proof));
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
        assert!(verify_merkle_proof(&proof));
    }

    #[test]
    fn rejects_non_canonical_leaves_without_panicking() {
        let modulus = snark_scalar_field_modulus();
        assert!(matches!(
            generate_merkle_proof(&[modulus], modulus),
            Err(TreeError::NonCanonicalField { field, .. }) if field == "leaf"
        ));
    }

    #[test]
    fn non_canonical_proofs_fail_closed() {
        let modulus = snark_scalar_field_modulus();
        let proof = MerkleProof {
            root: U256::from(1_u64),
            leaf: modulus,
            index: 0,
            siblings: vec![],
        };

        assert!(!verify_merkle_proof(&proof));
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
        assert!(verify_merkle_proof(&proof));

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
    fn pads_shallow_witnesses_to_protocol_depth() {
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

        let shallow_depth = proof.siblings.len();
        let witness = to_circuit_witness(&proof, shallow_depth).unwrap();

        assert_eq!(witness.depth, shallow_depth);
        assert_eq!(witness.siblings.len(), DEFAULT_CIRCUIT_DEPTH);
        assert_eq!(&witness.siblings[..proof.siblings.len()], &proof.siblings);
        assert!(
            witness.siblings[proof.siblings.len()..]
                .iter()
                .all(|sibling| *sibling == U256::ZERO)
        );
        assert_eq!(compute_circuit_root(&witness).unwrap(), proof.root);
        assert!(verify_circuit_witness(&witness).unwrap());
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

    #[test]
    fn rejects_invalid_circuit_witness_shapes() {
        let witness = CircuitMerkleWitness {
            root: U256::from(44_u64),
            leaf: U256::from(44_u64),
            index: 0,
            siblings: vec![U256::ZERO; 3],
            depth: 3,
        };

        assert!(matches!(
            compute_circuit_root(&witness),
            Err(TreeError::InvalidCircuitWitnessShape { expected, actual })
                if expected == DEFAULT_CIRCUIT_DEPTH && actual == 3
        ));
    }

    #[test]
    fn detects_mismatched_circuit_witness_roots() {
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
        let mut witness = to_circuit_witness(&proof, proof.siblings.len()).unwrap();

        witness.root += U256::from(1_u64);

        assert!(!verify_circuit_witness(&witness).unwrap());
    }

    #[test]
    fn zero_siblings_match_circuit_empty_node_semantics() {
        let witness = CircuitMerkleWitness {
            root: U256::from(44_u64),
            leaf: U256::from(44_u64),
            index: 0,
            siblings: {
                let mut siblings = vec![U256::ZERO; DEFAULT_CIRCUIT_DEPTH];
                siblings[0] = U256::ZERO;
                siblings
            },
            depth: 1,
        };

        assert_eq!(compute_circuit_root(&witness).unwrap(), U256::from(44_u64));
        assert!(verify_circuit_witness(&witness).unwrap());
    }

    #[test]
    fn rejects_indices_outside_circuit_depth() {
        let witness = CircuitMerkleWitness {
            root: U256::from(44_u64),
            leaf: U256::from(44_u64),
            index: 1usize << DEFAULT_CIRCUIT_DEPTH,
            siblings: vec![U256::ZERO; DEFAULT_CIRCUIT_DEPTH],
            depth: 1,
        };

        assert!(matches!(
            compute_circuit_root(&witness),
            Err(TreeError::InvalidCircuitWitnessIndex { index, depth })
                if index == 1usize << DEFAULT_CIRCUIT_DEPTH
                    && depth == DEFAULT_CIRCUIT_DEPTH
        ));
    }

    fn reference_circuit_root(leaf: U256, index: usize, siblings: &[U256]) -> U256 {
        let mut node = leaf;
        for (level, sibling) in siblings.iter().copied().enumerate() {
            if sibling.is_zero() {
                continue;
            }

            let is_right = ((index >> level) & 1) == 1;
            node = if is_right {
                poseidon_hash(&[sibling, node]).expect("poseidon pair hash should succeed")
            } else {
                poseidon_hash(&[node, sibling]).expect("poseidon pair hash should succeed")
            };
        }
        node
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            .. ProptestConfig::default()
        })]

        #[test]
        fn generated_proofs_match_reference_root(
            seeds in vec(1_u64..10_000, 1..10),
            requested_index in 0_usize..10,
        ) {
            let leaves = seeds
                .iter()
                .copied()
                .map(|seed| U256::from(seed.saturating_add(1)))
                .collect::<Vec<_>>();
            let unique = leaves.iter().copied().collect::<std::collections::BTreeSet<_>>();
            prop_assume!(unique.len() == leaves.len());
            prop_assume!(requested_index < leaves.len());

            let leaf = leaves[requested_index];
            let proof = generate_merkle_proof(&leaves, leaf).expect("proof generates");

            prop_assert_eq!(proof.leaf, leaf);
            prop_assert!(proof.index < leaves.len());
            prop_assert!(verify_merkle_proof(&proof));
            prop_assert_eq!(
                reference_circuit_root(proof.leaf, proof.index, &proof.siblings),
                proof.root
            );

            let witness = to_circuit_witness(&proof, proof.siblings.len()).expect("witness builds");
            prop_assert_eq!(witness.depth, proof.siblings.len());
            prop_assert_eq!(witness.siblings.len(), DEFAULT_CIRCUIT_DEPTH);
            prop_assert_eq!(
                compute_circuit_root(&witness).expect("circuit root computes"),
                proof.root
            );
            prop_assert!(verify_circuit_witness(&witness).expect("circuit witness verifies"));
        }
    }
}
