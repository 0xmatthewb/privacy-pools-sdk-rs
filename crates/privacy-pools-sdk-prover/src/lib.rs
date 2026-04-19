use ark_bls12_381::{Bls12_381, Fr as Bls12_381Fr};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_std::UniformRand;
use ark_std::rand::rngs::OsRng;
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
use circom_prover::prover::ProofLib;
use circom_prover::prover::{
    CircomProof, PublicInputs,
    ark_circom::{CircomReduction, read_zkey},
    circom::{G1, G2, Proof},
};
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
use circom_prover::{CircomProver, witness::generate_witness};
use num_bigint::BigUint;
use privacy_pools_sdk_artifacts::{self as artifacts, ArtifactKind, VerifiedArtifactBundle};
use privacy_pools_sdk_core::{
    CommitmentCircuitInput, ProofBundle, SnarkJsProof, WithdrawalCircuitInput,
};
use privacy_pools_sdk_verifier::{ParsedVerificationKey, PreparedVerifier, VerifierError};
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
use rust_witness::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
use std::collections::HashMap;
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
use std::thread::JoinHandle;
use std::{
    io::Cursor,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, OnceLock},
};
use thiserror::Error;

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
pub use circom_prover::witness::WitnessFn;

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
rust_witness::witness!(commitment);
#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
rust_witness::witness!(withdraw);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendProfile {
    Stable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProverBackend {
    Arkworks,
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
pub struct BackendPolicy;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error(transparent)]
    Artifact(#[from] artifacts::ArtifactError),
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
    #[error("invalid witness length: expected at least {expected}, got {actual}")]
    InvalidWitnessLength { expected: usize, actual: usize },
    #[error("manifest vkey does not match zkey for circuit `{0}`")]
    VerificationKeyMismatch(String),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessFormat {
    pub field_modulus: BigUint,
    pub witness_count: usize,
}

struct PreparedCircuitArtifactsInner {
    circuit: String,
    artifact_version: String,
    zkey_bytes: Arc<[u8]>,
    arkworks_circuit: OnceLock<Arc<PreparedArkworksCircuit>>,
    verifier: OnceLock<Option<PreparedVerifier>>,
}

enum PreparedArkworksCircuit {
    Bn254 {
        proving_key: Arc<ProvingKey<Bn254>>,
        matrices: Arc<ConstraintMatrices<Bn254Fr>>,
        verifier: PreparedVerifier,
    },
    Bls12_381 {
        proving_key: Arc<ProvingKey<Bls12_381>>,
        matrices: Arc<ConstraintMatrices<Bls12_381Fr>>,
        verifier: PreparedVerifier,
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
        _policy: BackendPolicy,
    ) -> Result<Self, ProverError> {
        let backend = match profile {
            BackendProfile::Stable => ProverBackend::Arkworks,
        };

        Ok(Self { backend })
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
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

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    pub fn prove_with_prepared_artifacts(
        &self,
        artifacts: &PreparedCircuitArtifacts,
        input_json: &str,
        witness_fn: WitnessFn,
    ) -> Result<ProvingResult, ProverError> {
        artifacts.prove_with_witness(self, input_json, witness_fn)
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    pub fn prove_with_compiled_witness(
        &self,
        request: &ProvingRequest,
    ) -> Result<ProvingResult, ProverError> {
        self.prove_with_witness(request, compiled_witness_fn(&request.circuit)?)
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    pub fn prove_with_compiled_witness_and_artifacts(
        &self,
        artifacts: &PreparedCircuitArtifacts,
        input_json: &str,
    ) -> Result<ProvingResult, ProverError> {
        artifacts.prove_with_compiled_witness(self, input_json)
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
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

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    fn proof_lib(&self) -> Result<ProofLib, ProverError> {
        match self.backend {
            ProverBackend::Arkworks => Ok(ProofLib::Arkworks),
        }
    }
}

impl PreparedCircuitArtifacts {
    pub fn from_verified_bundle(bundle: &VerifiedArtifactBundle) -> Result<Self, ProverError> {
        let zkey_bytes = bundle.artifact(ArtifactKind::Zkey)?.bytes().to_vec();
        let prepared_circuit = Arc::new(parse_arkworks_circuit(&zkey_bytes)?);
        let verifier = bundle
            .artifact(ArtifactKind::Vkey)
            .ok()
            .map(|artifact| {
                prepare_manifest_bound_verifier(
                    bundle.circuit(),
                    &prepared_circuit,
                    artifact.bytes(),
                )
            })
            .transpose()?;
        let arkworks_circuit = OnceLock::new();
        let _ = arkworks_circuit.set(Arc::clone(&prepared_circuit));
        let cached_verifier = OnceLock::new();
        let _ = cached_verifier.set(verifier);

        Ok(Self {
            inner: Arc::new(PreparedCircuitArtifactsInner {
                circuit: bundle.circuit().to_owned(),
                artifact_version: bundle.version().to_owned(),
                zkey_bytes: Arc::<[u8]>::from(zkey_bytes),
                arkworks_circuit,
                verifier: cached_verifier,
            }),
        })
    }

    pub fn circuit(&self) -> &str {
        &self.inner.circuit
    }

    pub fn artifact_version(&self) -> &str {
        &self.inner.artifact_version
    }

    pub fn witness_format(&self) -> Result<WitnessFormat, ProverError> {
        Ok(self.prepare_arkworks_circuit()?.witness_format())
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    pub fn prove_with_witness(
        &self,
        engine: &NativeProofEngine,
        input_json: &str,
        witness_fn: WitnessFn,
    ) -> Result<ProvingResult, ProverError> {
        let witness_thread = generate_witness(witness_fn, input_json.to_owned());
        let proof = self.prepare_arkworks_circuit()?.prove(witness_thread)?;

        Ok(ProvingResult {
            backend: engine.backend,
            proof: circom_proof_to_bundle(proof),
        })
    }

    pub fn prove_with_witness_values(
        &self,
        witness: Vec<BigUint>,
    ) -> Result<ProvingResult, ProverError> {
        let proof = self
            .prepare_arkworks_circuit()?
            .prove_with_witness_values(witness)?;

        Ok(ProvingResult {
            backend: ProverBackend::Arkworks,
            proof: circom_proof_to_bundle(proof),
        })
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    pub fn prove_with_compiled_witness(
        &self,
        engine: &NativeProofEngine,
        input_json: &str,
    ) -> Result<ProvingResult, ProverError> {
        self.prove_with_witness(engine, input_json, compiled_witness_fn(self.circuit())?)
    }

    pub fn verify(
        &self,
        _engine: &NativeProofEngine,
        proof: &ProofBundle,
    ) -> Result<bool, ProverError> {
        let circom_proof = bundle_to_circom_proof(proof)?;

        if let Some(verifier) = self.prepare_verifier()? {
            return verify_prepared_verifier_circom(verifier, &circom_proof);
        }

        self.prepare_arkworks_circuit()?.verify(&circom_proof)
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
        Ok(self
            .inner
            .verifier
            .get()
            .expect("prepared verifier cache is initialized with the session")
            .as_ref())
    }
}

impl PreparedArkworksCircuit {
    fn parsed_verification_key(&self) -> ParsedVerificationKey {
        match self {
            Self::Bn254 { proving_key, .. } => {
                ParsedVerificationKey::from_bn254_verifying_key(proving_key.vk.clone())
            }
            Self::Bls12_381 { proving_key, .. } => {
                ParsedVerificationKey::from_bls12_381_verifying_key(proving_key.vk.clone())
            }
        }
    }

    #[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
    fn prove(&self, witness_thread: JoinHandle<Vec<BigUint>>) -> Result<CircomProof, ProverError> {
        let witness = witness_thread
            .join()
            .map_err(|_| ProverError::Circom("witness thread panicked".to_owned()))?;
        self.prove_with_witness_values(witness)
    }

    fn prove_with_witness_values(&self, witness: Vec<BigUint>) -> Result<CircomProof, ProverError> {
        match self {
            Self::Bn254 {
                proving_key,
                matrices,
                ..
            } => prove_with_prepared_key_bn254(proving_key, matrices, witness),
            Self::Bls12_381 {
                proving_key,
                matrices,
                ..
            } => prove_with_prepared_key_bls12_381(proving_key, matrices, witness),
        }
    }

    fn verify(&self, proof: &CircomProof) -> Result<bool, ProverError> {
        match self {
            Self::Bn254 { verifier, .. } | Self::Bls12_381 { verifier, .. } => {
                verify_prepared_verifier_circom(verifier, proof)
            }
        }
    }

    fn witness_format(&self) -> WitnessFormat {
        match self {
            Self::Bn254 { matrices, .. } => WitnessFormat {
                field_modulus: BigUint::from_bytes_le(Bn254Fr::MODULUS.to_bytes_le().as_ref()),
                witness_count: expected_witness_count(
                    matrices.num_instance_variables,
                    matrices.num_witness_variables,
                ),
            },
            Self::Bls12_381 { matrices, .. } => WitnessFormat {
                field_modulus: BigUint::from_bytes_le(Bls12_381Fr::MODULUS.to_bytes_le().as_ref()),
                witness_count: expected_witness_count(
                    matrices.num_instance_variables,
                    matrices.num_witness_variables,
                ),
            },
        }
    }
}

fn expected_witness_count(instance_variables: usize, witness_variables: usize) -> usize {
    instance_variables
        .checked_add(witness_variables)
        .and_then(|count| count.checked_sub(1))
        .unwrap_or(instance_variables)
}

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
pub fn generate_commitment_witness(
    input: &CommitmentCircuitInput,
) -> Result<Vec<String>, ProverError> {
    generate_commitment_witness_from_json(&serialize_commitment_circuit_input(input)?)
}

pub fn serialize_commitment_circuit_input(
    input: &CommitmentCircuitInput,
) -> Result<String, ProverError> {
    let mut json = Map::new();

    insert_field(&mut json, "value", input.value.to_string());
    insert_field(&mut json, "label", input.label.to_string());
    insert_field(&mut json, "nullifier", input.nullifier.to_decimal_string());
    insert_field(&mut json, "secret", input.secret.to_decimal_string());

    serde_json::to_string(&Value::Object(json))
        .map_err(|error| ProverError::InputSerialization(error.to_string()))
}

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
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
        input.existing_nullifier.to_decimal_string(),
    );
    insert_field(
        &mut json,
        "existingSecret",
        input.existing_secret.to_decimal_string(),
    );
    insert_field(
        &mut json,
        "newNullifier",
        input.new_nullifier.to_decimal_string(),
    );
    insert_field(&mut json, "newSecret", input.new_secret.to_decimal_string());
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

pub fn parse_witness_values(values: &[String]) -> Result<Vec<BigUint>, ProverError> {
    values.iter().map(|value| parse_biguint(value)).collect()
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

fn prepare_manifest_bound_verifier(
    circuit: &str,
    zkey_circuit: &PreparedArkworksCircuit,
    vkey_bytes: &[u8],
) -> Result<PreparedVerifier, ProverError> {
    let parsed_vkey = ParsedVerificationKey::from_vkey_bytes(vkey_bytes)?;
    let zkey_vkey = zkey_circuit.parsed_verification_key();
    if !parsed_vkey.matches(&zkey_vkey) {
        return Err(ProverError::VerificationKeyMismatch(circuit.to_owned()));
    }

    Ok(parsed_vkey.prepare())
}

impl ProofEngine for NativeProofEngine {
    fn backend(&self) -> ProverBackend {
        self.backend
    }

    fn prove(&self, _request: &ProvingRequest) -> Result<ProvingResult, ProverError> {
        Err(ProverError::WitnessFunctionRequired)
    }
}

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
fn compiled_witness_fn(circuit: &str) -> Result<WitnessFn, ProverError> {
    match circuit {
        "commitment" => Ok(WitnessFn::RustWitness(commitment_witness)),
        "withdraw" => Ok(WitnessFn::RustWitness(withdraw_witness)),
        _ => Err(ProverError::MissingCompiledWitness(circuit.to_owned())),
    }
}

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
fn generate_commitment_witness_from_json(input_json: &str) -> Result<Vec<String>, ProverError> {
    let witness_map = circom_prover::witness::json_to_hashmap(input_json)
        .map_err(|error| ProverError::InputSerialization(error.to_string()))?;
    let normalized_inputs = witness_map
        .into_iter()
        .map(|(name, values)| Ok((name, parse_bigints(values)?)))
        .collect::<Result<HashMap<_, _>, ProverError>>()?;

    Ok(commitment_witness(normalized_inputs)
        .into_iter()
        .map(|value| value.to_string())
        .collect())
}

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
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

#[cfg(all(feature = "native-witness", not(target_arch = "wasm32")))]
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
                verifier: ParsedVerificationKey::from_bn254_verifying_key(proving_key.vk.clone())
                    .prepare(),
                proving_key: Arc::new(proving_key),
                matrices: Arc::new(matrices),
            })
        }
        ZkeyCurve::Bls12_381 => {
            let mut reader = Cursor::new(zkey_bytes);
            let (proving_key, matrices) = read_zkey::<_, Bls12_381>(&mut reader)
                .map_err(|error| ProverError::InvalidZkey(error.to_string()))?;

            Ok(PreparedArkworksCircuit::Bls12_381 {
                verifier: ParsedVerificationKey::from_bls12_381_verifying_key(
                    proving_key.vk.clone(),
                )
                .prepare(),
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
    witness: Vec<BigUint>,
) -> Result<CircomProof, ProverError> {
    validate_witness_length(witness.len(), matrices.num_instance_variables)?;
    let witness_fr = witness
        .iter()
        .map(|value| Bn254Fr::from(value.clone()))
        .collect::<Vec<_>>();
    let public_inputs = witness_fr.as_slice()[1..matrices.num_instance_variables]
        .iter()
        .map(|scalar| BigUint::from_bytes_le(scalar.into_bigint().to_bytes_le().as_ref()))
        .collect::<Vec<_>>();
    let mut rng = OsRng;
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
    witness: Vec<BigUint>,
) -> Result<CircomProof, ProverError> {
    validate_witness_length(witness.len(), matrices.num_instance_variables)?;
    let witness_fr = witness
        .iter()
        .map(|value| Bls12_381Fr::from(value.clone()))
        .collect::<Vec<_>>();
    let public_inputs = witness_fr.as_slice()[1..matrices.num_instance_variables]
        .iter()
        .map(|scalar| BigUint::from_bytes_le(scalar.into_bigint().to_bytes_le().as_ref()))
        .collect::<Vec<_>>();
    let mut rng = OsRng;
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

fn validate_witness_length(actual: usize, expected: usize) -> Result<(), ProverError> {
    if actual < expected {
        return Err(ProverError::InvalidWitnessLength { expected, actual });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use privacy_pools_sdk_artifacts::{
        ArtifactBytes, ArtifactDescriptor, ArtifactKind, ArtifactManifest,
    };
    use privacy_pools_sdk_core::{CommitmentCircuitInput, parse_decimal_field};
    use serde_json::Value;
    use std::fs;

    fn withdrawal_fixture_input() -> WithdrawalCircuitInput {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();

        WithdrawalCircuitInput {
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
                .unwrap()
                .into(),
            existing_secret: parse_decimal_field(fixture["existingSecret"].as_str().unwrap())
                .unwrap()
                .into(),
            new_nullifier: parse_decimal_field(fixture["newNullifier"].as_str().unwrap())
                .unwrap()
                .into(),
            new_secret: parse_decimal_field(fixture["newSecret"].as_str().unwrap())
                .unwrap()
                .into(),
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
        }
    }

    fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> u32 {
        let end = *cursor + 4;
        let value = u32::from_le_bytes(bytes[*cursor..end].try_into().unwrap());
        *cursor = end;
        value
    }

    fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> u64 {
        let end = *cursor + 8;
        let value = u64::from_le_bytes(bytes[*cursor..end].try_into().unwrap());
        *cursor = end;
        value
    }

    fn read_wtns_values(path: &PathBuf) -> Vec<String> {
        let bytes = fs::read(path).unwrap();
        let mut cursor = 0usize;

        assert_eq!(&bytes[..4], b"wtns");
        cursor += 4;
        assert_eq!(read_u32_le(&bytes, &mut cursor), 2);

        let section_count = read_u32_le(&bytes, &mut cursor);
        let mut field_bytes = None;
        let mut witness_count = None;
        let mut witness_values = None;

        for _ in 0..section_count {
            let section_id = read_u32_le(&bytes, &mut cursor);
            let section_len = read_u64_le(&bytes, &mut cursor) as usize;
            let section_start = cursor;
            let section_end = section_start + section_len;

            match section_id {
                1 => {
                    let n8 = read_u32_le(&bytes, &mut cursor) as usize;
                    cursor += n8;
                    let n_witness = read_u32_le(&bytes, &mut cursor) as usize;
                    field_bytes = Some(n8);
                    witness_count = Some(n_witness);
                }
                2 => {
                    let n8 = field_bytes.expect("wtns header precedes witness section");
                    let n_witness =
                        witness_count.expect("wtns header declares witness count first");
                    let mut values = Vec::with_capacity(n_witness);
                    for _ in 0..n_witness {
                        let end = cursor + n8;
                        values.push(BigUint::from_bytes_le(&bytes[cursor..end]).to_string());
                        cursor = end;
                    }
                    witness_values = Some(values);
                }
                _ => {
                    cursor = section_end;
                }
            }

            assert_eq!(cursor, section_end);
        }

        witness_values.expect("wtns witness section present")
    }

    #[test]
    fn stable_backend_is_arkworks() {
        let engine = NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy).unwrap();
        assert_eq!(engine.backend(), ProverBackend::Arkworks);
    }

    #[test]
    fn generic_prove_requires_witness_function() {
        let engine = NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy).unwrap();
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
        let input = withdrawal_fixture_input();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/vectors/withdrawal-circuit-input.json"
        ))
        .unwrap();

        let serialized = serialize_withdrawal_circuit_input(&input).unwrap();
        let normalized: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(normalized, fixture["expected"]["normalizedInputs"]);
        assert_eq!(
            serialized,
            serde_json::to_string(&fixture["expected"]["normalizedInputs"]).unwrap()
        );
    }

    #[test]
    fn serializes_commitment_input_for_default_witness_backends() {
        let input = CommitmentCircuitInput {
            value: parse_decimal_field("1000").unwrap(),
            label: parse_decimal_field("456").unwrap(),
            nullifier: parse_decimal_field(
                "9878240014447325541744515257207865961484965884202615717842202674496027003398",
            )
            .unwrap()
            .into(),
            secret: parse_decimal_field(
                "13069389595930744619595476459130906967784496307970072089240474669876753189225",
            )
            .unwrap()
            .into(),
        };

        let normalized: Value =
            serde_json::from_str(&serialize_commitment_circuit_input(&input).unwrap()).unwrap();

        assert_eq!(normalized["value"], serde_json::json!(["1000"]));
        assert_eq!(normalized["label"], serde_json::json!(["456"]));
        assert_eq!(
            normalized["nullifier"],
            serde_json::json!([
                "9878240014447325541744515257207865961484965884202615717842202674496027003398"
            ])
        );
        assert_eq!(
            normalized["secret"],
            serde_json::json!([
                "13069389595930744619595476459130906967784496307970072089240474669876753189225"
            ])
        );
    }

    #[test]
    fn compiled_commitment_witness_generates_values_from_reference_input() {
        let input = CommitmentCircuitInput {
            value: parse_decimal_field("1000").unwrap(),
            label: parse_decimal_field("456").unwrap(),
            nullifier: parse_decimal_field(
                "9878240014447325541744515257207865961484965884202615717842202674496027003398",
            )
            .unwrap()
            .into(),
            secret: parse_decimal_field(
                "13069389595930744619595476459130906967784496307970072089240474669876753189225",
            )
            .unwrap()
            .into(),
        };

        let witness = generate_commitment_witness(&input).unwrap();

        assert!(!witness.is_empty());
        assert_eq!(witness[0], "1");
        assert_eq!(
            witness[1],
            "18437108638057730733389558898787811857923614754235980305933849061572031046967"
        );
        assert_eq!(witness[3], "1000");
        assert_eq!(witness[4], "456");
    }

    #[test]
    fn compiled_withdraw_witness_generates_values_from_reference_input() {
        let input = withdrawal_fixture_input();
        let witness = generate_withdrawal_witness(&input).unwrap();
        assert!(!witness.is_empty());
        assert_eq!(witness[0], "1");
    }

    #[test]
    fn compiled_withdraw_witness_matches_snarkjs_wtns_golden() {
        let witness = generate_withdrawal_witness(&withdrawal_fixture_input()).unwrap();
        let golden_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vectors/withdrawal-witness-golden.wtns");
        let golden = read_wtns_values(&golden_path);

        assert_eq!(witness, golden);
    }

    #[test]
    fn compiled_commitment_proof_path_uses_internal_witness_adapter() {
        let engine = NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy).unwrap();
        let request = ProvingRequest {
            circuit: "commitment".to_owned(),
            input_json: "{\"foo\":[\"1\"]}".to_owned(),
            artifact_version: "0.1.0-alpha.1".to_owned(),
            zkey_path: PathBuf::from("/tmp/commitment.zkey"),
        };

        assert!(matches!(
            engine.prove_with_compiled_witness(&request),
            Err(ProverError::MissingZkey(_))
        ));
    }

    #[test]
    fn compiled_withdraw_proof_path_uses_internal_witness_adapter() {
        let engine = NativeProofEngine::from_policy(BackendProfile::Stable, BackendPolicy).unwrap();
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

    #[test]
    fn session_preload_rejects_invalid_zkey_bytes() {
        let manifest = ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![ArtifactDescriptor {
                circuit: "withdraw".to_owned(),
                kind: ArtifactKind::Zkey,
                filename: "sample-artifact.bin".to_owned(),
                sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                    .to_owned(),
            }],
        };
        let bundle = manifest
            .verify_bundle_bytes(
                "withdraw",
                [ArtifactBytes {
                    kind: ArtifactKind::Zkey,
                    bytes: include_bytes!("../../../fixtures/artifacts/sample-artifact.bin")
                        .to_vec(),
                }],
            )
            .unwrap();

        let error = match PreparedCircuitArtifacts::from_verified_bundle(&bundle) {
            Ok(_) => panic!("invalid zkey bytes must not create a cached session"),
            Err(error) => error,
        };

        assert!(matches!(error, ProverError::InvalidZkey(_)));
    }

    #[test]
    fn portable_prover_rejects_wrong_witness_length() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/commitment-proving-manifest.json"
        ))
        .unwrap();
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let bundle = manifest.load_verified_bundle(root, "commitment").unwrap();
        let artifacts = PreparedCircuitArtifacts::from_verified_bundle(&bundle).unwrap();

        let error = artifacts
            .prove_with_witness_values(vec![BigUint::from(1_u8)])
            .unwrap_err();

        assert!(matches!(
            error,
            ProverError::InvalidWitnessLength { actual: 1, .. }
        ));
    }
}
