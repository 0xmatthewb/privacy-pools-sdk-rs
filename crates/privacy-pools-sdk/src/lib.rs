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

    pub fn checkpoint_recovery(
        &self,
        events: &[recovery::PoolEvent],
        policy: recovery::RecoveryPolicy,
    ) -> Result<recovery::RecoveryCheckpoint, recovery::RecoveryError> {
        recovery::checkpoint(events, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
