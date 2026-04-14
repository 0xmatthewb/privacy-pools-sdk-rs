use circom_prover::{
    CircomProver,
    prover::{
        CircomProof, ProofLib, PublicInputs,
        circom::{G1, G2, Proof},
    },
};
use num_bigint::BigUint;
use privacy_pools_sdk_core::{ProofBundle, SnarkJsProof, WithdrawalCircuitInput};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{path::PathBuf, str::FromStr};
use thiserror::Error;

pub use circom_prover::witness::WitnessFn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendProfile {
    Stable,
    Fast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProverBackend {
    Arkworks,
    Rapidsnark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvingRequest {
    pub circuit: String,
    pub input_json: String,
    pub artifact_version: String,
    pub zkey_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvingResult {
    pub backend: ProverBackend,
    pub proof: ProofBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackendPolicy {
    pub allow_fast_backend: bool,
}

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("fast prover backend is not enabled")]
    FastBackendDisabled,
    #[error("fast prover backend is not compiled into this build")]
    FastBackendNotCompiled,
    #[error("rapidsnark is not supported on this target")]
    UnsupportedFastTarget,
    #[error("proof generation requires an explicit witness function")]
    WitnessFunctionRequired,
    #[error("proving key does not exist: {0}")]
    MissingZkey(PathBuf),
    #[error("failed to parse decimal field: {0}")]
    InvalidField(String),
    #[error("failed to serialize circuit input: {0}")]
    InputSerialization(String),
    #[error("circom prover failed: {0}")]
    Circom(String),
}

pub trait ProofEngine {
    fn backend(&self) -> ProverBackend;
    fn prove(&self, request: &ProvingRequest) -> Result<ProvingResult, ProverError>;
}

pub struct NativeProofEngine {
    backend: ProverBackend,
}

impl NativeProofEngine {
    pub fn from_policy(
        profile: BackendProfile,
        policy: BackendPolicy,
    ) -> Result<Self, ProverError> {
        let backend = match profile {
            BackendProfile::Stable => ProverBackend::Arkworks,
            BackendProfile::Fast => {
                if !policy.allow_fast_backend {
                    return Err(ProverError::FastBackendDisabled);
                }
                if !cfg!(feature = "rapidsnark") {
                    return Err(ProverError::FastBackendNotCompiled);
                }
                if !rapidsnark_supported_target() {
                    return Err(ProverError::UnsupportedFastTarget);
                }
                ProverBackend::Rapidsnark
            }
        };

        Ok(Self { backend })
    }

    pub fn prove_with_witness(
        &self,
        request: &ProvingRequest,
        witness_fn: WitnessFn,
    ) -> Result<ProvingResult, ProverError> {
        if !request.zkey_path.exists() {
            return Err(ProverError::MissingZkey(request.zkey_path.clone()));
        }

        let proof = CircomProver::prove(
            self.proof_lib()?,
            witness_fn,
            request.input_json.clone(),
            request.zkey_path.to_string_lossy().into_owned(),
        )
        .map_err(|error| ProverError::Circom(error.to_string()))?;

        Ok(ProvingResult {
            backend: self.backend,
            proof: circom_proof_to_bundle(proof),
        })
    }

    pub fn verify(&self, proof: &ProofBundle, zkey_path: PathBuf) -> Result<bool, ProverError> {
        if !zkey_path.exists() {
            return Err(ProverError::MissingZkey(zkey_path));
        }

        let circom_proof = bundle_to_circom_proof(proof)?;
        CircomProver::verify(
            self.proof_lib()?,
            circom_proof,
            zkey_path.to_string_lossy().into_owned(),
        )
        .map_err(|error| ProverError::Circom(error.to_string()))
    }

    fn proof_lib(&self) -> Result<ProofLib, ProverError> {
        match self.backend {
            ProverBackend::Arkworks => Ok(ProofLib::Arkworks),
            ProverBackend::Rapidsnark => {
                if cfg!(feature = "rapidsnark") {
                    Ok(ProofLib::Rapidsnark)
                } else {
                    Err(ProverError::FastBackendNotCompiled)
                }
            }
        }
    }
}

pub fn serialize_withdrawal_circuit_input(
    input: &WithdrawalCircuitInput,
) -> Result<String, ProverError> {
    let mut json = Map::new();

    insert_field(
        &mut json,
        "withdrawnValue",
        input.withdrawn_value.to_string(),
    );
    insert_field(&mut json, "stateRoot", input.state_root.to_string());
    insert_field(
        &mut json,
        "stateTreeDepth",
        input.state_tree_depth.to_string(),
    );
    insert_field(&mut json, "ASPRoot", input.asp_root.to_string());
    insert_field(&mut json, "ASPTreeDepth", input.asp_tree_depth.to_string());
    insert_field(&mut json, "context", input.context.to_string());
    insert_field(&mut json, "label", input.label.to_string());
    insert_field(&mut json, "existingValue", input.existing_value.to_string());
    insert_field(
        &mut json,
        "existingNullifier",
        input.existing_nullifier.to_string(),
    );
    insert_field(
        &mut json,
        "existingSecret",
        input.existing_secret.to_string(),
    );
    insert_field(&mut json, "newNullifier", input.new_nullifier.to_string());
    insert_field(&mut json, "newSecret", input.new_secret.to_string());
    insert_fields(
        &mut json,
        "stateSiblings",
        input.state_siblings.iter().map(ToString::to_string),
    );
    insert_field(&mut json, "stateIndex", input.state_index.to_string());
    insert_fields(
        &mut json,
        "ASPSiblings",
        input.asp_siblings.iter().map(ToString::to_string),
    );
    insert_field(&mut json, "ASPIndex", input.asp_index.to_string());

    serde_json::to_string(&Value::Object(json))
        .map_err(|error| ProverError::InputSerialization(error.to_string()))
}

fn insert_field(json: &mut Map<String, Value>, key: &str, value: String) {
    json.insert(key.to_owned(), Value::Array(vec![Value::String(value)]));
}

fn insert_fields<I>(json: &mut Map<String, Value>, key: &str, values: I)
where
    I: IntoIterator<Item = String>,
{
    json.insert(
        key.to_owned(),
        Value::Array(values.into_iter().map(Value::String).collect()),
    );
}

impl ProofEngine for NativeProofEngine {
    fn backend(&self) -> ProverBackend {
        self.backend
    }

    fn prove(&self, _request: &ProvingRequest) -> Result<ProvingResult, ProverError> {
        Err(ProverError::WitnessFunctionRequired)
    }
}

fn circom_proof_to_bundle(proof: CircomProof) -> ProofBundle {
    ProofBundle {
        proof: SnarkJsProof {
            pi_a: [proof.proof.a.x.to_string(), proof.proof.a.y.to_string()],
            pi_b: [
                [
                    proof.proof.b.x[0].to_string(),
                    proof.proof.b.x[1].to_string(),
                ],
                [
                    proof.proof.b.y[0].to_string(),
                    proof.proof.b.y[1].to_string(),
                ],
            ],
            pi_c: [proof.proof.c.x.to_string(), proof.proof.c.y.to_string()],
            protocol: proof.proof.protocol,
            curve: proof.proof.curve,
        },
        public_signals: proof
            .pub_inputs
            .0
            .into_iter()
            .map(|value| value.to_string())
            .collect(),
    }
}

fn bundle_to_circom_proof(bundle: &ProofBundle) -> Result<CircomProof, ProverError> {
    Ok(CircomProof {
        proof: Proof {
            a: G1 {
                x: parse_biguint(&bundle.proof.pi_a[0])?,
                y: parse_biguint(&bundle.proof.pi_a[1])?,
                z: BigUint::from(1u8),
            },
            b: G2 {
                x: [
                    parse_biguint(&bundle.proof.pi_b[0][0])?,
                    parse_biguint(&bundle.proof.pi_b[0][1])?,
                ],
                y: [
                    parse_biguint(&bundle.proof.pi_b[1][0])?,
                    parse_biguint(&bundle.proof.pi_b[1][1])?,
                ],
                z: [BigUint::from(1u8), BigUint::from(0u8)],
            },
            c: G1 {
                x: parse_biguint(&bundle.proof.pi_c[0])?,
                y: parse_biguint(&bundle.proof.pi_c[1])?,
                z: BigUint::from(1u8),
            },
            protocol: bundle.proof.protocol.clone(),
            curve: bundle.proof.curve.clone(),
        },
        pub_inputs: PublicInputs(
            bundle
                .public_signals
                .iter()
                .map(|value| parse_biguint(value))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn parse_biguint(value: &str) -> Result<BigUint, ProverError> {
    BigUint::from_str(value).map_err(|_| ProverError::InvalidField(value.to_owned()))
}

pub fn rapidsnark_supported_target() -> bool {
    matches!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("ios", "aarch64")
            | ("android", "aarch64")
            | ("android", "x86_64")
            | ("macos", "aarch64")
            | ("macos", "x86_64")
            | ("linux", "aarch64")
            | ("linux", "x86_64")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use privacy_pools_sdk_core::parse_decimal_field;
    use serde_json::Value;

    #[test]
    fn stable_backend_is_arkworks() {
        let engine =
            NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy::default())
                .unwrap();
        assert_eq!(engine.backend(), ProverBackend::Arkworks);
    }

    #[test]
    fn generic_prove_requires_witness_function() {
        let engine =
            NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy::default())
                .unwrap();
        let request = ProvingRequest {
            circuit: "withdraw".to_owned(),
            input_json: "{}".to_owned(),
            artifact_version: "0.1.0-alpha.1".to_owned(),
            zkey_path: PathBuf::from("/tmp/withdraw.zkey"),
        };

        assert!(matches!(
            engine.prove(&request),
            Err(ProverError::WitnessFunctionRequired)
        ));
    }

    #[test]
    fn serializes_withdrawal_input_for_default_witness_backends() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();

        let input = WithdrawalCircuitInput {
            withdrawn_value: parse_decimal_field(fixture["withdrawalAmount"].as_str().unwrap())
                .unwrap(),
            state_root: parse_decimal_field(fixture["stateWitness"]["root"].as_str().unwrap())
                .unwrap(),
            state_tree_depth: fixture["stateWitness"]["depth"].as_u64().unwrap() as usize,
            asp_root: parse_decimal_field(fixture["aspWitness"]["root"].as_str().unwrap()).unwrap(),
            asp_tree_depth: fixture["aspWitness"]["depth"].as_u64().unwrap() as usize,
            context: parse_decimal_field(fixture["expected"]["context"].as_str().unwrap()).unwrap(),
            label: parse_decimal_field(fixture["label"].as_str().unwrap()).unwrap(),
            existing_value: parse_decimal_field(fixture["existingValue"].as_str().unwrap())
                .unwrap(),
            existing_nullifier: parse_decimal_field(fixture["existingNullifier"].as_str().unwrap())
                .unwrap(),
            existing_secret: parse_decimal_field(fixture["existingSecret"].as_str().unwrap())
                .unwrap(),
            new_nullifier: parse_decimal_field(fixture["newNullifier"].as_str().unwrap()).unwrap(),
            new_secret: parse_decimal_field(fixture["newSecret"].as_str().unwrap()).unwrap(),
            state_siblings: fixture["stateWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| parse_decimal_field(value.as_str().unwrap()).unwrap())
                .collect(),
            state_index: fixture["stateWitness"]["index"].as_u64().unwrap() as usize,
            asp_siblings: fixture["aspWitness"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| parse_decimal_field(value.as_str().unwrap()).unwrap())
                .collect(),
            asp_index: fixture["aspWitness"]["index"].as_u64().unwrap() as usize,
        };

        let normalized: Value =
            serde_json::from_str(&serialize_withdrawal_circuit_input(&input).unwrap()).unwrap();
        assert_eq!(normalized, fixture["expected"]["normalizedInputs"]);
    }
}
