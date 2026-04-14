pub use privacy_pools_sdk_artifacts as artifacts;
pub use privacy_pools_sdk_chain as chain;
pub use privacy_pools_sdk_core as core;
pub use privacy_pools_sdk_crypto as crypto;
pub use privacy_pools_sdk_prover as prover;
pub use privacy_pools_sdk_recovery as recovery;
pub use privacy_pools_sdk_signer as signer;
pub use privacy_pools_sdk_tree as tree;

use alloy_primitives::{Address, U256};
use privacy_pools_sdk_prover::{BackendPolicy, BackendProfile, NativeProofEngine, ProverError};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error(transparent)]
    Core(#[from] core::CoreError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Artifact(#[from] artifacts::ArtifactError),
    #[error(transparent)]
    Prover(#[from] prover::ProverError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrivacyPoolsSdk {
    backend_policy: BackendPolicy,
}

impl PrivacyPoolsSdk {
    pub fn new(backend_policy: BackendPolicy) -> Self {
        Self { backend_policy }
    }

    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn proving_engine(
        &self,
        profile: BackendProfile,
    ) -> Result<NativeProofEngine, ProverError> {
        NativeProofEngine::from_policy(profile, self.backend_policy)
    }

    pub fn stable_backend_name(&self) -> Result<String, ProverError> {
        use privacy_pools_sdk_prover::ProofEngine;

        Ok(format!(
            "{:?}",
            self.proving_engine(BackendProfile::Stable)?.backend()
        ))
    }

    pub fn fast_backend_supported_on_target(&self) -> bool {
        privacy_pools_sdk_prover::rapidsnark_supported_target()
    }

    pub fn generate_master_keys(
        &self,
        mnemonic: &str,
    ) -> Result<core::MasterKeys, crypto::CryptoError> {
        crypto::generate_master_keys(mnemonic)
    }

    pub fn generate_deposit_secrets(
        &self,
        keys: &core::MasterKeys,
        scope: U256,
        index: U256,
    ) -> Result<(core::Nullifier, core::Secret), crypto::CryptoError> {
        crypto::generate_deposit_secrets(keys, scope, index)
    }

    pub fn generate_withdrawal_secrets(
        &self,
        keys: &core::MasterKeys,
        label: U256,
        index: U256,
    ) -> Result<(core::Nullifier, core::Secret), crypto::CryptoError> {
        crypto::generate_withdrawal_secrets(keys, label, index)
    }

    pub fn get_commitment(
        &self,
        value: U256,
        label: U256,
        nullifier: core::Nullifier,
        secret: core::Secret,
    ) -> Result<core::Commitment, crypto::CryptoError> {
        crypto::get_commitment(value, label, nullifier, secret)
    }

    pub fn calculate_context(
        &self,
        withdrawal: &core::Withdrawal,
        scope: U256,
    ) -> Result<String, crypto::CryptoError> {
        crypto::calculate_context(withdrawal, scope)
    }

    pub fn generate_merkle_proof(
        &self,
        leaves: &[core::FieldElement],
        leaf: core::FieldElement,
    ) -> Result<core::MerkleProof, tree::TreeError> {
        tree::generate_merkle_proof(leaves, leaf)
    }

    pub fn to_circuit_witness(
        &self,
        proof: &core::MerkleProof,
        depth: usize,
    ) -> Result<core::CircuitMerkleWitness, tree::TreeError> {
        tree::to_circuit_witness(proof, depth)
    }

    pub fn plan_pool_state_root_read(&self, pool_address: Address) -> core::RootRead {
        chain::state_root_read(pool_address)
    }

    pub fn artifact_statuses(
        &self,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        circuit: &str,
    ) -> Vec<artifacts::ArtifactStatus> {
        artifacts::artifact_statuses(manifest, root, circuit)
    }

    pub fn resolve_verified_artifact_bundle(
        &self,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        circuit: &str,
    ) -> Result<artifacts::ResolvedArtifactBundle, artifacts::ArtifactError> {
        manifest.resolve_verified_bundle(root, circuit)
    }

    pub fn plan_asp_root_read(
        &self,
        entrypoint_address: Address,
        pool_address: Address,
    ) -> core::RootRead {
        chain::asp_root_read(entrypoint_address, pool_address)
    }

    pub fn is_current_state_root(&self, expected_root: U256, current_root: U256) -> bool {
        chain::is_current_state_root(expected_root, current_root)
    }

    pub fn format_groth16_proof(
        &self,
        proof: &core::ProofBundle,
    ) -> Result<core::FormattedGroth16Proof, chain::ChainError> {
        chain::format_groth16_proof(proof)
    }

    pub fn build_withdrawal_circuit_input(
        &self,
        request: &core::WithdrawalWitnessRequest,
    ) -> Result<core::WithdrawalCircuitInput, SdkError> {
        validate_witness_shape("state", &request.state_witness)?;
        validate_witness_shape("asp", &request.asp_witness)?;

        Ok(core::WithdrawalCircuitInput {
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

    pub fn serialize_withdrawal_circuit_input(
        &self,
        input: &core::WithdrawalCircuitInput,
    ) -> Result<String, SdkError> {
        prover::serialize_withdrawal_circuit_input(input).map_err(Into::into)
    }

    pub fn prepare_withdrawal_proving_request(
        &self,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        request: &core::WithdrawalWitnessRequest,
    ) -> Result<prover::ProvingRequest, SdkError> {
        let input = self.build_withdrawal_circuit_input(request)?;
        let input_json = self.serialize_withdrawal_circuit_input(&input)?;
        let bundle = self.resolve_verified_artifact_bundle(manifest, root, "withdraw")?;
        let artifact_version = bundle.version.clone();
        let zkey_path = bundle.artifact(artifacts::ArtifactKind::Zkey)?.path.clone();

        Ok(prover::ProvingRequest {
            circuit: "withdraw".to_owned(),
            input_json,
            artifact_version,
            zkey_path,
        })
    }

    pub fn prove_withdrawal_with_witness(
        &self,
        profile: BackendProfile,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        request: &core::WithdrawalWitnessRequest,
        witness_fn: prover::WitnessFn,
    ) -> Result<prover::ProvingResult, SdkError> {
        let proving_request = self.prepare_withdrawal_proving_request(manifest, root, request)?;
        self.proving_engine(profile)?
            .prove_with_witness(&proving_request, witness_fn)
            .map_err(Into::into)
    }

    pub fn checkpoint_recovery(
        &self,
        events: &[recovery::PoolEvent],
        policy: recovery::RecoveryPolicy,
    ) -> Result<recovery::RecoveryCheckpoint, recovery::RecoveryError> {
        recovery::checkpoint(events, policy)
    }
}

fn validate_witness_shape(
    name: &'static str,
    witness: &core::CircuitMerkleWitness,
) -> Result<(), core::CoreError> {
    if witness.siblings.len() != witness.depth {
        return Err(core::CoreError::InvalidWitnessShape {
            name,
            expected: witness.depth,
            actual: witness.siblings.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};
    use serde_json::Value;
    use std::str::FromStr;

    #[test]
    fn exposes_expected_default_backend() {
        let sdk = PrivacyPoolsSdk::default();
        assert_eq!(sdk.stable_backend_name().unwrap(), "Arkworks");
    }

    #[test]
    fn public_api_matches_reference_master_keys() {
        let sdk = PrivacyPoolsSdk::default();
        let keys = sdk
            .generate_master_keys("test test test test test test test test test test test junk")
            .unwrap();

        assert_eq!(
            keys.master_nullifier,
            U256::from_str(
                "20068762160393292801596226195912281868434195939362930533775271887246872084568"
            )
            .unwrap()
        );
        assert_eq!(
            keys.master_secret,
            U256::from_str(
                "4263194520628581151689140073493505946870598678660509318310629023735624352890"
            )
            .unwrap()
        );
    }

    #[test]
    fn builds_typed_withdrawal_inputs_from_reference_vectors() {
        let sdk = PrivacyPoolsSdk::default();
        let crypto_fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .unwrap();
        let withdrawal_fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();
        let keys = sdk
            .generate_master_keys(crypto_fixture["mnemonic"].as_str().unwrap())
            .unwrap();
        let (deposit_nullifier, deposit_secret) = sdk
            .generate_deposit_secrets(
                &keys,
                U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
                U256::ZERO,
            )
            .unwrap();
        let commitment = sdk
            .get_commitment(
                U256::from_str(withdrawal_fixture["existingValue"].as_str().unwrap()).unwrap(),
                U256::from_str(withdrawal_fixture["label"].as_str().unwrap()).unwrap(),
                deposit_nullifier,
                deposit_secret,
            )
            .unwrap();
        let state_witness = core::CircuitMerkleWitness {
            root: U256::from_str(withdrawal_fixture["stateWitness"]["root"].as_str().unwrap())
                .unwrap(),
            leaf: U256::from_str(withdrawal_fixture["stateWitness"]["leaf"].as_str().unwrap())
                .unwrap(),
            index: withdrawal_fixture["stateWitness"]["index"]
                .as_u64()
                .unwrap() as usize,
            siblings: withdrawal_fixture["stateWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value: &Value| U256::from_str(value.as_str().unwrap()).unwrap())
                .collect(),
            depth: withdrawal_fixture["stateWitness"]["depth"]
                .as_u64()
                .unwrap() as usize,
        };
        let asp_witness = core::CircuitMerkleWitness {
            root: U256::from_str(withdrawal_fixture["aspWitness"]["root"].as_str().unwrap())
                .unwrap(),
            leaf: U256::from_str(withdrawal_fixture["aspWitness"]["leaf"].as_str().unwrap())
                .unwrap(),
            index: withdrawal_fixture["aspWitness"]["index"].as_u64().unwrap() as usize,
            siblings: withdrawal_fixture["aspWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value: &Value| U256::from_str(value.as_str().unwrap()).unwrap())
                .collect(),
            depth: withdrawal_fixture["aspWitness"]["depth"].as_u64().unwrap() as usize,
        };
        let request = core::WithdrawalWitnessRequest {
            commitment,
            withdrawal: core::Withdrawal {
                processooor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            scope: U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
            withdrawal_amount: U256::from_str(
                withdrawal_fixture["withdrawalAmount"].as_str().unwrap(),
            )
            .unwrap(),
            state_witness,
            asp_witness,
            new_nullifier: U256::from_str(withdrawal_fixture["newNullifier"].as_str().unwrap())
                .unwrap(),
            new_secret: U256::from_str(withdrawal_fixture["newSecret"].as_str().unwrap()).unwrap(),
        };

        let input = sdk.build_withdrawal_circuit_input(&request).unwrap();
        assert_eq!(
            input.context,
            U256::from_str(withdrawal_fixture["expected"]["context"].as_str().unwrap()).unwrap()
        );

        let normalized: Value =
            serde_json::from_str(&sdk.serialize_withdrawal_circuit_input(&input).unwrap()).unwrap();
        assert_eq!(
            normalized,
            withdrawal_fixture["expected"]["normalizedInputs"]
        );
    }

    #[test]
    fn prepares_withdrawal_proving_requests_from_verified_zkeys() {
        let sdk = PrivacyPoolsSdk::default();
        let crypto_fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/crypto-compatibility.json"
        ))
        .unwrap();
        let withdrawal_fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();
        let manifest: artifacts::ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-proving-manifest.json"
        ))
        .unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let keys = sdk
            .generate_master_keys(crypto_fixture["mnemonic"].as_str().unwrap())
            .unwrap();
        let (deposit_nullifier, deposit_secret) = sdk
            .generate_deposit_secrets(
                &keys,
                U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
                U256::ZERO,
            )
            .unwrap();
        let request = core::WithdrawalWitnessRequest {
            commitment: sdk
                .get_commitment(
                    U256::from_str(withdrawal_fixture["existingValue"].as_str().unwrap()).unwrap(),
                    U256::from_str(withdrawal_fixture["label"].as_str().unwrap()).unwrap(),
                    deposit_nullifier,
                    deposit_secret,
                )
                .unwrap(),
            withdrawal: core::Withdrawal {
                processooor: address!("1111111111111111111111111111111111111111"),
                data: bytes!("1234"),
            },
            scope: U256::from_str(crypto_fixture["scope"].as_str().unwrap()).unwrap(),
            withdrawal_amount: U256::from_str(
                withdrawal_fixture["withdrawalAmount"].as_str().unwrap(),
            )
            .unwrap(),
            state_witness: core::CircuitMerkleWitness {
                root: U256::from_str(withdrawal_fixture["stateWitness"]["root"].as_str().unwrap())
                    .unwrap(),
                leaf: U256::from_str(withdrawal_fixture["stateWitness"]["leaf"].as_str().unwrap())
                    .unwrap(),
                index: withdrawal_fixture["stateWitness"]["index"]
                    .as_u64()
                    .unwrap() as usize,
                siblings: withdrawal_fixture["stateWitness"]["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value: &Value| U256::from_str(value.as_str().unwrap()).unwrap())
                    .collect(),
                depth: withdrawal_fixture["stateWitness"]["depth"]
                    .as_u64()
                    .unwrap() as usize,
            },
            asp_witness: core::CircuitMerkleWitness {
                root: U256::from_str(withdrawal_fixture["aspWitness"]["root"].as_str().unwrap())
                    .unwrap(),
                leaf: U256::from_str(withdrawal_fixture["aspWitness"]["leaf"].as_str().unwrap())
                    .unwrap(),
                index: withdrawal_fixture["aspWitness"]["index"].as_u64().unwrap() as usize,
                siblings: withdrawal_fixture["aspWitness"]["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value: &Value| U256::from_str(value.as_str().unwrap()).unwrap())
                    .collect(),
                depth: withdrawal_fixture["aspWitness"]["depth"].as_u64().unwrap() as usize,
            },
            new_nullifier: U256::from_str(withdrawal_fixture["newNullifier"].as_str().unwrap())
                .unwrap(),
            new_secret: U256::from_str(withdrawal_fixture["newSecret"].as_str().unwrap()).unwrap(),
        };

        let proving_request = sdk
            .prepare_withdrawal_proving_request(&manifest, root, &request)
            .unwrap();

        assert_eq!(proving_request.circuit, "withdraw");
        assert_eq!(proving_request.artifact_version, "0.1.0-alpha.1");
        assert!(proving_request.zkey_path.ends_with("sample-artifact.bin"));
    }
}
