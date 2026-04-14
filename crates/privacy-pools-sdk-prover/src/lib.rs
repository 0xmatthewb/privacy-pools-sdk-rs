use circom_prover::{
    CircomProver,
    prover::{
        CircomProof, ProofLib, PublicInputs,
        circom::{G1, G2, Proof},
    },
    witness::WitnessFn,
};
use num_bigint::BigUint;
use privacy_pools_sdk_core::{ProofBundle, SnarkJsProof};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr};
use thiserror::Error;

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
}
