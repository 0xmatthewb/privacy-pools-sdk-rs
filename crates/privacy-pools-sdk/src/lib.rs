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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransactionExecution {
    pub proving: prover::ProvingResult,
    pub transaction: core::TransactionPlan,
    pub preflight: core::ExecutionPreflightReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedTransactionExecution {
    pub prepared: PreparedTransactionExecution,
    pub receipt: core::TransactionReceiptSummary,
}

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
    #[error(transparent)]
    Chain(#[from] chain::ChainError),
    #[error(transparent)]
    Signer(#[from] signer::SignerError),
    #[error("local proof verification failed")]
    ProofRejected,
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

    pub fn plan_withdrawal_transaction(
        &self,
        chain_id: u64,
        pool_address: Address,
        withdrawal: &core::Withdrawal,
        proof: &core::ProofBundle,
    ) -> Result<core::TransactionPlan, chain::ChainError> {
        chain::plan_withdrawal_transaction(chain_id, pool_address, withdrawal, proof)
    }

    pub fn plan_relay_transaction(
        &self,
        chain_id: u64,
        entrypoint_address: Address,
        withdrawal: &core::Withdrawal,
        proof: &core::ProofBundle,
        scope: U256,
    ) -> Result<core::TransactionPlan, chain::ChainError> {
        chain::plan_relay_transaction(chain_id, entrypoint_address, withdrawal, proof, scope)
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

    pub fn prove_withdrawal(
        &self,
        profile: BackendProfile,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        request: &core::WithdrawalWitnessRequest,
    ) -> Result<prover::ProvingResult, SdkError> {
        let proving_request = self.prepare_withdrawal_proving_request(manifest, root, request)?;
        self.proving_engine(profile)?
            .prove_with_compiled_witness(&proving_request)
            .map_err(Into::into)
    }

    pub fn verify_withdrawal_proof(
        &self,
        profile: BackendProfile,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        proof: &core::ProofBundle,
    ) -> Result<bool, SdkError> {
        let bundle = self.resolve_verified_artifact_bundle(manifest, root, "withdraw")?;
        let zkey_path = bundle.artifact(artifacts::ArtifactKind::Zkey)?.path.clone();

        self.proving_engine(profile)?
            .verify(proof, zkey_path)
            .map_err(Into::into)
    }

    pub async fn prepare_withdrawal_execution_with_client<C: chain::ExecutionClient>(
        &self,
        profile: BackendProfile,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        request: &core::WithdrawalWitnessRequest,
        config: &core::WithdrawalExecutionConfig,
        client: &C,
    ) -> Result<PreparedTransactionExecution, SdkError> {
        let proving = self.prove_withdrawal(profile, manifest, root.as_ref(), request)?;
        if !self.verify_withdrawal_proof(profile, manifest, root.as_ref(), &proving.proof)? {
            return Err(SdkError::ProofRejected);
        }

        let transaction = self.plan_withdrawal_transaction(
            config.chain_id,
            config.pool_address,
            &request.withdrawal,
            &proving.proof,
        )?;
        let preflight = chain::preflight_withdrawal(
            client,
            &transaction,
            config.pool_address,
            request.state_witness.root,
            &config.policy,
        )
        .await?;

        Ok(PreparedTransactionExecution {
            proving,
            transaction,
            preflight,
        })
    }

    pub async fn prepare_relay_execution_with_client<C: chain::ExecutionClient>(
        &self,
        profile: BackendProfile,
        manifest: &artifacts::ArtifactManifest,
        root: impl AsRef<Path>,
        request: &core::WithdrawalWitnessRequest,
        config: &core::RelayExecutionConfig,
        client: &C,
    ) -> Result<PreparedTransactionExecution, SdkError> {
        let proving = self.prove_withdrawal(profile, manifest, root.as_ref(), request)?;
        if !self.verify_withdrawal_proof(profile, manifest, root.as_ref(), &proving.proof)? {
            return Err(SdkError::ProofRejected);
        }

        let transaction = self.plan_relay_transaction(
            config.chain_id,
            config.entrypoint_address,
            &request.withdrawal,
            &proving.proof,
            request.scope,
        )?;
        let preflight = chain::preflight_relay(
            client,
            &transaction,
            config.entrypoint_address,
            config.pool_address,
            request.state_witness.root,
            request.asp_witness.root,
            &config.policy,
        )
        .await?;

        Ok(PreparedTransactionExecution {
            proving,
            transaction,
            preflight,
        })
    }

    pub async fn submit_prepared_transaction_with_client<C: chain::SubmissionClient>(
        &self,
        prepared: PreparedTransactionExecution,
        client: &C,
    ) -> Result<SubmittedTransactionExecution, SdkError> {
        if client.caller() != prepared.preflight.caller {
            return Err(chain::ChainError::SignerAddressMismatch {
                expected: prepared.preflight.caller,
                actual: client.caller(),
            }
            .into());
        }

        let refreshed_preflight =
            chain::reconfirm_preflight(client, &prepared.transaction, &prepared.preflight).await?;
        let receipt = client.submit_transaction(&prepared.transaction).await?;

        Ok(SubmittedTransactionExecution {
            prepared: PreparedTransactionExecution {
                preflight: refreshed_preflight,
                ..prepared
            },
            receipt,
        })
    }

    pub async fn submit_prepared_transaction_with_local_mnemonic(
        &self,
        rpc_url: &str,
        mnemonic: &str,
        index: u32,
        prepared: PreparedTransactionExecution,
    ) -> Result<SubmittedTransactionExecution, SdkError> {
        let signer = signer::LocalMnemonicSigner::from_phrase_nth(mnemonic, index)?;
        let client = chain::LocalSignerExecutionClient::new(rpc_url, &signer)?;

        self.submit_prepared_transaction_with_client(prepared, &client)
            .await
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
    use alloy_primitives::{address, b256, bytes};
    use async_trait::async_trait;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[derive(Debug, Clone)]
    struct MockSubmissionClient {
        caller: Address,
        chain_id: u64,
        code_hashes: HashMap<Address, alloy_primitives::B256>,
        roots: HashMap<(core::RootReadKind, Address), U256>,
        estimated_gas: u64,
        receipt: core::TransactionReceiptSummary,
    }

    #[async_trait]
    impl chain::ExecutionClient for MockSubmissionClient {
        async fn chain_id(&self) -> Result<u64, chain::ChainError> {
            Ok(self.chain_id)
        }

        async fn code_hash(
            &self,
            address: Address,
        ) -> Result<alloy_primitives::B256, chain::ChainError> {
            self.code_hashes.get(&address).copied().ok_or_else(|| {
                chain::ChainError::Transport(format!("missing code hash for {address}"))
            })
        }

        async fn read_root(&self, read: &core::RootRead) -> Result<U256, chain::ChainError> {
            self.roots
                .get(&(read.kind, read.contract_address))
                .copied()
                .ok_or_else(|| {
                    chain::ChainError::Transport(format!(
                        "missing root for {}",
                        read.contract_address
                    ))
                })
        }

        async fn simulate_transaction(
            &self,
            _caller: Address,
            _plan: &core::TransactionPlan,
        ) -> Result<u64, chain::ChainError> {
            Ok(self.estimated_gas)
        }
    }

    #[async_trait]
    impl chain::SubmissionClient for MockSubmissionClient {
        fn caller(&self) -> Address {
            self.caller
        }

        async fn submit_transaction(
            &self,
            _plan: &core::TransactionPlan,
        ) -> Result<core::TransactionReceiptSummary, chain::ChainError> {
            Ok(self.receipt.clone())
        }
    }

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

    #[test]
    fn plans_offline_withdrawal_and_relay_transactions() {
        let sdk = PrivacyPoolsSdk::default();
        let proof = core::ProofBundle {
            proof: core::SnarkJsProof {
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
        let withdrawal = core::Withdrawal {
            processooor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        };

        let withdraw = sdk
            .plan_withdrawal_transaction(
                1,
                address!("0987654321098765432109876543210987654321"),
                &withdrawal,
                &proof,
            )
            .unwrap();
        let relay = sdk
            .plan_relay_transaction(
                1,
                address!("1234567890123456789012345678901234567890"),
                &withdrawal,
                &proof,
                U256::from(123_u64),
            )
            .unwrap();

        assert_eq!(withdraw.kind, core::TransactionKind::Withdraw);
        assert_eq!(relay.kind, core::TransactionKind::Relay);
        assert_eq!(withdraw.chain_id, 1);
        assert_eq!(relay.chain_id, 1);
    }

    #[tokio::test]
    async fn submits_prepared_transactions_after_reconfirming_preflight() {
        let sdk = PrivacyPoolsSdk::default();
        let caller = address!("1111111111111111111111111111111111111111");
        let target = address!("2222222222222222222222222222222222222222");
        let root = U256::from(42_u64);
        let code_hash = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let prepared = PreparedTransactionExecution {
            proving: prover::ProvingResult {
                backend: prover::ProverBackend::Arkworks,
                proof: core::ProofBundle {
                    proof: core::SnarkJsProof {
                        pi_a: ["1".to_owned(), "2".to_owned()],
                        pi_b: [
                            ["3".to_owned(), "4".to_owned()],
                            ["5".to_owned(), "6".to_owned()],
                        ],
                        pi_c: ["7".to_owned(), "8".to_owned()],
                        protocol: "groth16".to_owned(),
                        curve: "bn128".to_owned(),
                    },
                    public_signals: vec!["9".to_owned(); 8],
                },
            },
            transaction: core::TransactionPlan {
                kind: core::TransactionKind::Withdraw,
                chain_id: 11155111,
                target,
                calldata: bytes!("1234"),
                value: U256::ZERO,
                proof: core::FormattedGroth16Proof {
                    p_a: ["0x01".to_owned(), "0x02".to_owned()],
                    p_b: [
                        ["0x03".to_owned(), "0x04".to_owned()],
                        ["0x05".to_owned(), "0x06".to_owned()],
                    ],
                    p_c: ["0x07".to_owned(), "0x08".to_owned()],
                    pub_signals: vec!["0x09".to_owned(); 8],
                },
            },
            preflight: core::ExecutionPreflightReport {
                kind: core::TransactionKind::Withdraw,
                caller,
                target,
                expected_chain_id: 11155111,
                actual_chain_id: 11155111,
                chain_id_matches: true,
                simulated: true,
                estimated_gas: 21_000,
                code_hash_checks: vec![core::CodeHashCheck {
                    address: target,
                    expected_code_hash: Some(code_hash),
                    actual_code_hash: code_hash,
                    matches_expected: Some(true),
                }],
                root_checks: vec![core::RootCheck {
                    kind: core::RootReadKind::PoolState,
                    contract_address: target,
                    pool_address: target,
                    expected_root: root,
                    actual_root: root,
                    matches: true,
                }],
            },
        };
        let client = MockSubmissionClient {
            caller,
            chain_id: 11155111,
            code_hashes: HashMap::from([(target, code_hash)]),
            roots: HashMap::from([((core::RootReadKind::PoolState, target), root)]),
            estimated_gas: 84_000,
            receipt: core::TransactionReceiptSummary {
                transaction_hash: b256!(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                block_hash: Some(b256!(
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                )),
                block_number: Some(123),
                transaction_index: Some(0),
                success: true,
                gas_used: 64_000,
                effective_gas_price: "123456789".to_owned(),
                from: caller,
                to: Some(target),
            },
        };

        let submitted = sdk
            .submit_prepared_transaction_with_client(prepared, &client)
            .await
            .unwrap();

        assert_eq!(submitted.prepared.preflight.estimated_gas, 84_000);
        assert!(submitted.receipt.success);
        assert_eq!(submitted.receipt.from, caller);
    }
}
