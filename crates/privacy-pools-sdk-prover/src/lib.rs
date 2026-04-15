use ark_bls12_381::{Bls12_381, Fr as Bls12_381Fr};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::ConstraintMatrices;
use ark_std::UniformRand;
use ark_std::rand::thread_rng;
use circom_prover::{
    CircomProver,
    prover::{
        CircomProof, ProofLib, PublicInputs,
        ark_circom::{CircomReduction, read_zkey},
        circom::{G1, G2, Proof},
    },
    witness::generate_witness,
};
use num_bigint::BigUint;
use privacy_pools_sdk_artifacts::{self as artifacts, ArtifactKind, VerifiedArtifactBundle};
use privacy_pools_sdk_core::{ProofBundle, SnarkJsProof, WithdrawalCircuitInput};
use privacy_pools_sdk_verifier::{PreparedVerifier, VerifierError};
use rust_witness::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    io::{Cursor, Write},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, OnceLock},
    thread::JoinHandle,
};
use tempfile::NamedTempFile;
use thiserror::Error;

pub use circom_prover::witness::WitnessFn;

rust_witness::witness!(withdraw);

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
    #[error(transparent)]
    Artifact(#[from] artifacts::ArtifactError),
    #[error("fast prover backend is not enabled")]
    FastBackendDisabled,
    #[error("fast prover backend is not compiled into this build")]
    FastBackendNotCompiled,
    #[error("rapidsnark is not supported on this target")]
    UnsupportedFastTarget,
    #[error("proof generation requires an explicit witness function")]
    WitnessFunctionRequired,
    #[error("no compiled witness adapter is available for circuit `{0}`")]
    MissingCompiledWitness(String),
    #[error("proving key does not exist: {0}")]
    MissingZkey(PathBuf),
    #[error("failed to parse decimal field: {0}")]
    InvalidField(String),
    #[error("failed to serialize circuit input: {0}")]
    InputSerialization(String),
    #[error("invalid zkey bundle: {0}")]
    InvalidZkey(String),
    #[error("circom prover failed: {0}")]
    Circom(String),
    #[error(transparent)]
    Verification(#[from] VerifierError),
}

pub trait ProofEngine {
    fn backend(&self) -> ProverBackend;
    fn prove(&self, request: &ProvingRequest) -> Result<ProvingResult, ProverError>;
}

pub struct NativeProofEngine {
    backend: ProverBackend,
}

#[derive(Clone)]
pub struct PreparedCircuitArtifacts {
    inner: Arc<PreparedCircuitArtifactsInner>,
}

struct PreparedCircuitArtifactsInner {
    circuit: String,
    artifact_version: String,
    zkey_bytes: Arc<[u8]>,
    vkey_bytes: Option<Arc<[u8]>>,
    arkworks_circuit: OnceLock<Arc<PreparedArkworksCircuit>>,
    verifier: OnceLock<Option<PreparedVerifier>>,
}

enum PreparedArkworksCircuit {
    Bn254 {
        proving_key: Arc<ProvingKey<Bn254>>,
        matrices: Arc<ConstraintMatrices<Bn254Fr>>,
        verifier: Box<PreparedVerifyingKey<Bn254>>,
    },
    Bls12_381 {
        proving_key: Arc<ProvingKey<Bls12_381>>,
        matrices: Arc<ConstraintMatrices<Bls12_381Fr>>,
        verifier: Box<PreparedVerifyingKey<Bls12_381>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZkeyCurve {
    Bn254,
    Bls12_381,
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

    pub fn prove_with_prepared_artifacts(
        &self,
        artifacts: &PreparedCircuitArtifacts,
        input_json: &str,
        witness_fn: WitnessFn,
    ) -> Result<ProvingResult, ProverError> {
        artifacts.prove_with_witness(self, input_json, witness_fn)
    }

    pub fn prove_with_compiled_witness(
        &self,
        request: &ProvingRequest,
    ) -> Result<ProvingResult, ProverError> {
        self.prove_with_witness(request, compiled_witness_fn(&request.circuit)?)
    }

    pub fn prove_with_compiled_witness_and_artifacts(
        &self,
        artifacts: &PreparedCircuitArtifacts,
        input_json: &str,
    ) -> Result<ProvingResult, ProverError> {
        artifacts.prove_with_compiled_witness(self, input_json)
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

    pub fn verify_with_prepared_artifacts(
        &self,
        artifacts: &PreparedCircuitArtifacts,
        proof: &ProofBundle,
    ) -> Result<bool, ProverError> {
        artifacts.verify(self, proof)
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

impl PreparedCircuitArtifacts {
    pub fn from_verified_bundle(bundle: &VerifiedArtifactBundle) -> Result<Self, ProverError> {
        let zkey_bytes = bundle.artifact(ArtifactKind::Zkey)?.bytes.clone();
        let vkey_bytes = bundle
            .artifact(ArtifactKind::Vkey)
            .ok()
            .map(|artifact| Arc::<[u8]>::from(artifact.bytes.clone()));

        Ok(Self {
            inner: Arc::new(PreparedCircuitArtifactsInner {
                circuit: bundle.circuit.clone(),
                artifact_version: bundle.version.clone(),
                zkey_bytes: Arc::<[u8]>::from(zkey_bytes),
                vkey_bytes,
                arkworks_circuit: OnceLock::new(),
                verifier: OnceLock::new(),
            }),
        })
    }

    pub fn circuit(&self) -> &str {
        &self.inner.circuit
    }

    pub fn artifact_version(&self) -> &str {
        &self.inner.artifact_version
    }

    pub fn prove_with_witness(
        &self,
        engine: &NativeProofEngine,
        input_json: &str,
        witness_fn: WitnessFn,
    ) -> Result<ProvingResult, ProverError> {
        let proof = match engine.backend {
            ProverBackend::Arkworks => {
                let witness_thread = generate_witness(witness_fn, input_json.to_owned());
                self.prepare_arkworks_circuit()?.prove(witness_thread)?
            }
            ProverBackend::Rapidsnark => {
                let zkey_file = self.materialize_zkey_file()?;
                CircomProver::prove(
                    engine.proof_lib()?,
                    witness_fn,
                    input_json.to_owned(),
                    zkey_file.path().to_string_lossy().into_owned(),
                )
                .map_err(|error| ProverError::Circom(error.to_string()))?
            }
        };

        Ok(ProvingResult {
            backend: engine.backend,
            proof: circom_proof_to_bundle(proof),
        })
    }

    pub fn prove_with_compiled_witness(
        &self,
        engine: &NativeProofEngine,
        input_json: &str,
    ) -> Result<ProvingResult, ProverError> {
        self.prove_with_witness(engine, input_json, compiled_witness_fn(self.circuit())?)
    }

    pub fn verify(
        &self,
        engine: &NativeProofEngine,
        proof: &ProofBundle,
    ) -> Result<bool, ProverError> {
        let circom_proof = bundle_to_circom_proof(proof)?;

        if let Some(verifier) = self.prepare_verifier()? {
            return verify_prepared_verifier_circom(verifier, &circom_proof);
        }

        match engine.backend {
            ProverBackend::Arkworks => self.prepare_arkworks_circuit()?.verify(&circom_proof),
            ProverBackend::Rapidsnark => {
                let zkey_file = self.materialize_zkey_file()?;
                CircomProver::verify(
                    engine.proof_lib()?,
                    circom_proof,
                    zkey_file.path().to_string_lossy().into_owned(),
                )
                .map_err(|error| ProverError::Circom(error.to_string()))
            }
        }
    }

    fn materialize_zkey_file(&self) -> Result<NamedTempFile, ProverError> {
        let mut file =
            NamedTempFile::new().map_err(|error| ProverError::Circom(error.to_string()))?;
        file.write_all(&self.inner.zkey_bytes)
            .map_err(|error| ProverError::Circom(error.to_string()))?;
        Ok(file)
    }

    fn prepare_arkworks_circuit(&self) -> Result<&PreparedArkworksCircuit, ProverError> {
        if let Some(prepared) = self.inner.arkworks_circuit.get() {
            return Ok(prepared.as_ref());
        }

        let prepared = Arc::new(parse_arkworks_circuit(&self.inner.zkey_bytes)?);
        let _ = self.inner.arkworks_circuit.set(prepared);
        Ok(self
            .inner
            .arkworks_circuit
            .get()
            .expect("prepared circuit was just initialized")
            .as_ref())
    }

    fn prepare_verifier(&self) -> Result<Option<&PreparedVerifier>, ProverError> {
        if let Some(prepared) = self.inner.verifier.get() {
            return Ok(prepared.as_ref());
        }

        let prepared = self
            .inner
            .vkey_bytes
            .as_deref()
            .and_then(|bytes| PreparedVerifier::from_vkey_bytes(bytes).ok());
        let _ = self.inner.verifier.set(prepared);
        Ok(self
            .inner
            .verifier
            .get()
            .expect("prepared verifier was just initialized")
            .as_ref())
    }
}

impl PreparedArkworksCircuit {
    fn prove(&self, witness_thread: JoinHandle<Vec<BigUint>>) -> Result<CircomProof, ProverError> {
        match self {
            Self::Bn254 {
                proving_key,
                matrices,
                ..
            } => prove_with_prepared_key_bn254(proving_key, matrices, witness_thread),
            Self::Bls12_381 {
                proving_key,
                matrices,
                ..
            } => prove_with_prepared_key_bls12_381(proving_key, matrices, witness_thread),
        }
    }

    fn verify(&self, proof: &CircomProof) -> Result<bool, ProverError> {
        match self {
            Self::Bn254 { verifier, .. } => verify_with_prepared_bn254_verifier(verifier, proof),
            Self::Bls12_381 { verifier, .. } => {
                verify_with_prepared_bls12_381_verifier(verifier, proof)
            }
        }
    }
}

pub fn generate_withdrawal_witness(
    input: &WithdrawalCircuitInput,
) -> Result<Vec<String>, ProverError> {
    generate_withdrawal_witness_from_json(&serialize_withdrawal_circuit_input(input)?)
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

fn verify_prepared_verifier_circom(
    verifier: &PreparedVerifier,
    proof: &CircomProof,
) -> Result<bool, ProverError> {
    let bundle = circom_proof_to_bundle(proof.clone());
    verifier.verify(&bundle).map_err(Into::into)
}

impl ProofEngine for NativeProofEngine {
    fn backend(&self) -> ProverBackend {
        self.backend
    }

    fn prove(&self, _request: &ProvingRequest) -> Result<ProvingResult, ProverError> {
        Err(ProverError::WitnessFunctionRequired)
    }
}

fn compiled_witness_fn(circuit: &str) -> Result<WitnessFn, ProverError> {
    match circuit {
        "withdraw" => Ok(WitnessFn::RustWitness(withdraw_witness)),
        _ => Err(ProverError::MissingCompiledWitness(circuit.to_owned())),
    }
}

fn generate_withdrawal_witness_from_json(input_json: &str) -> Result<Vec<String>, ProverError> {
    let witness_map = circom_prover::witness::json_to_hashmap(input_json)
        .map_err(|error| ProverError::InputSerialization(error.to_string()))?;
    let normalized_inputs = witness_map
        .into_iter()
        .map(|(name, values)| Ok((name, parse_bigints(values)?)))
        .collect::<Result<HashMap<_, _>, ProverError>>()?;

    Ok(withdraw_witness(normalized_inputs)
        .into_iter()
        .map(|value| value.to_string())
        .collect())
}

fn parse_bigints(values: Vec<String>) -> Result<Vec<BigInt>, ProverError> {
    values
        .into_iter()
        .map(|value| BigInt::from_str(&value).map_err(|_| ProverError::InvalidField(value)))
        .collect()
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

fn parse_arkworks_circuit(zkey_bytes: &[u8]) -> Result<PreparedArkworksCircuit, ProverError> {
    match detect_zkey_curve(zkey_bytes)? {
        ZkeyCurve::Bn254 => {
            let mut reader = Cursor::new(zkey_bytes);
            let (proving_key, matrices) = read_zkey::<_, Bn254>(&mut reader)
                .map_err(|error| ProverError::InvalidZkey(error.to_string()))?;

            Ok(PreparedArkworksCircuit::Bn254 {
                verifier: Box::new(prepare_verifying_key(&proving_key.vk)),
                proving_key: Arc::new(proving_key),
                matrices: Arc::new(matrices),
            })
        }
        ZkeyCurve::Bls12_381 => {
            let mut reader = Cursor::new(zkey_bytes);
            let (proving_key, matrices) = read_zkey::<_, Bls12_381>(&mut reader)
                .map_err(|error| ProverError::InvalidZkey(error.to_string()))?;

            Ok(PreparedArkworksCircuit::Bls12_381 {
                verifier: Box::new(prepare_verifying_key(&proving_key.vk)),
                proving_key: Arc::new(proving_key),
                matrices: Arc::new(matrices),
            })
        }
    }
}

fn detect_zkey_curve(zkey_bytes: &[u8]) -> Result<ZkeyCurve, ProverError> {
    let header = read_zkey_header(zkey_bytes)?;
    if header.r == BigUint::from(<Bn254 as Pairing>::ScalarField::MODULUS) {
        Ok(ZkeyCurve::Bn254)
    } else if header.r == BigUint::from(<Bls12_381 as Pairing>::ScalarField::MODULUS) {
        Ok(ZkeyCurve::Bls12_381)
    } else {
        Err(ProverError::InvalidZkey(
            "unknown curve detected in zkey".to_owned(),
        ))
    }
}

fn read_zkey_header(zkey_bytes: &[u8]) -> Result<ZkeyHeader, ProverError> {
    let mut reader = ByteReader::new(zkey_bytes);
    let _magic = reader.read_u32()?;
    let _version = reader.read_u32()?;
    let num_sections = reader.read_u32()?;
    let mut r = None;

    for index in 0..num_sections {
        let section_id = reader.read_u32()?;
        let section_length = reader.read_u64()? as usize;
        if index > 1 {
            break;
        }
        if section_id == 1 {
            let key_type = reader.read_u32()?;
            if key_type != 1 {
                return Err(ProverError::InvalidZkey(
                    "non-groth16 zkey detected".to_owned(),
                ));
            }
            if section_length > 4 {
                reader.skip(section_length - 4)?;
            }
            continue;
        }
        if section_id == 2 {
            let q_bytes = reader.read_u32()? as usize;
            let _q = reader.read_biguint(q_bytes)?;
            let r_bytes = reader.read_u32()? as usize;
            r = Some(reader.read_biguint(r_bytes)?);
            break;
        }
        reader.skip(section_length)?;
    }

    r.map(|r| ZkeyHeader { r })
        .ok_or_else(|| ProverError::InvalidZkey("missing Groth16 header".to_owned()))
}

fn prove_with_prepared_key_bn254(
    proving_key: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Bn254Fr>,
    witness_thread: JoinHandle<Vec<BigUint>>,
) -> Result<CircomProof, ProverError> {
    let witness = witness_thread
        .join()
        .map_err(|_| ProverError::Circom("witness thread panicked".to_owned()))?;
    let witness_fr = witness
        .iter()
        .map(|value| Bn254Fr::from(value.clone()))
        .collect::<Vec<_>>();
    let public_inputs = witness_fr.as_slice()[1..matrices.num_instance_variables]
        .iter()
        .map(|scalar| BigUint::from_bytes_le(scalar.into_bigint().to_bytes_le().as_ref()))
        .collect::<Vec<_>>();
    let mut rng = thread_rng();
    let r = Bn254Fr::rand(&mut rng);
    let s = Bn254Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        proving_key,
        r,
        s,
        matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        witness_fr.as_slice(),
    )
    .map_err(|error| ProverError::Circom(error.to_string()))?;

    Ok(CircomProof {
        proof: proof.into(),
        pub_inputs: PublicInputs(public_inputs),
    })
}

fn prove_with_prepared_key_bls12_381(
    proving_key: &ProvingKey<Bls12_381>,
    matrices: &ConstraintMatrices<Bls12_381Fr>,
    witness_thread: JoinHandle<Vec<BigUint>>,
) -> Result<CircomProof, ProverError> {
    let witness = witness_thread
        .join()
        .map_err(|_| ProverError::Circom("witness thread panicked".to_owned()))?;
    let witness_fr = witness
        .iter()
        .map(|value| Bls12_381Fr::from(value.clone()))
        .collect::<Vec<_>>();
    let public_inputs = witness_fr.as_slice()[1..matrices.num_instance_variables]
        .iter()
        .map(|scalar| BigUint::from_bytes_le(scalar.into_bigint().to_bytes_le().as_ref()))
        .collect::<Vec<_>>();
    let mut rng = thread_rng();
    let r = Bls12_381Fr::rand(&mut rng);
    let s = Bls12_381Fr::rand(&mut rng);
    let proof = Groth16::<Bls12_381, CircomReduction>::create_proof_with_reduction_and_matrices(
        proving_key,
        r,
        s,
        matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        witness_fr.as_slice(),
    )
    .map_err(|error| ProverError::Circom(error.to_string()))?;

    Ok(CircomProof {
        proof: proof.into(),
        pub_inputs: PublicInputs(public_inputs),
    })
}

fn verify_with_prepared_bn254_verifier(
    verifier: &PreparedVerifyingKey<Bn254>,
    proof: &CircomProof,
) -> Result<bool, ProverError> {
    let public_inputs = proof
        .pub_inputs
        .0
        .iter()
        .map(|value| Bn254Fr::from(value.clone()))
        .collect::<Vec<_>>();
    Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        verifier,
        &public_inputs,
        &proof.proof.clone().into(),
    )
    .map_err(|error| ProverError::Circom(error.to_string()))
}

fn verify_with_prepared_bls12_381_verifier(
    verifier: &PreparedVerifyingKey<Bls12_381>,
    proof: &CircomProof,
) -> Result<bool, ProverError> {
    let public_inputs = proof
        .pub_inputs
        .0
        .iter()
        .map(|value| Bls12_381Fr::from(value.clone()))
        .collect::<Vec<_>>();
    Groth16::<Bls12_381, CircomReduction>::verify_with_processed_vk(
        verifier,
        &public_inputs,
        &proof.proof.clone().into(),
    )
    .map_err(|error| ProverError::Circom(error.to_string()))
}

struct ZkeyHeader {
    r: BigUint,
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, ProverError> {
        let end = self.offset + 4;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ProverError::InvalidZkey("unexpected end of zkey header".to_owned()))?;
        self.offset = end;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("length already checked"),
        ))
    }

    fn read_u64(&mut self) -> Result<u64, ProverError> {
        let end = self.offset + 8;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ProverError::InvalidZkey("unexpected end of zkey header".to_owned()))?;
        self.offset = end;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("length already checked"),
        ))
    }

    fn read_biguint(&mut self, length: usize) -> Result<BigUint, ProverError> {
        let end = self.offset + length;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ProverError::InvalidZkey("unexpected end of zkey header".to_owned()))?;
        self.offset = end;
        Ok(BigUint::from_bytes_le(bytes))
    }

    fn skip(&mut self, length: usize) -> Result<(), ProverError> {
        let end = self.offset + length;
        if self.bytes.get(self.offset..end).is_none() {
            return Err(ProverError::InvalidZkey(
                "unexpected end of zkey header".to_owned(),
            ));
        }
        self.offset = end;
        Ok(())
    }
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

    #[test]
    fn compiled_withdraw_witness_generates_values_from_reference_input() {
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

        let witness = generate_withdrawal_witness(&input).unwrap();
        assert!(!witness.is_empty());
        assert_eq!(witness[0], "1");
    }

    #[test]
    fn compiled_withdraw_proof_path_uses_internal_witness_adapter() {
        let engine =
            NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy::default())
                .unwrap();
        let request = ProvingRequest {
            circuit: "withdraw".to_owned(),
            input_json: "{\"foo\":[\"1\"]}".to_owned(),
            artifact_version: "0.1.0-alpha.1".to_owned(),
            zkey_path: PathBuf::from("/tmp/withdraw.zkey"),
        };

        assert!(matches!(
            engine.prove_with_compiled_witness(&request),
            Err(ProverError::MissingZkey(_))
        ));
    }
}
