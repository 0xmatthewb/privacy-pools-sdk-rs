use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    Wasm,
    Zkey,
    Vkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    pub circuit: String,
    pub kind: ArtifactKind,
    pub filename: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub version: String,
    pub artifacts: Vec<ArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifestMetadata {
    pub ceremony: Option<String>,
    pub build: Option<String>,
    pub repository: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedArtifactManifestPayload {
    pub manifest: ArtifactManifest,
    pub metadata: ArtifactManifestMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedArtifactManifest {
    pub payload: SignedArtifactManifestPayload,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifestArtifactBytes {
    pub filename: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignedArtifactManifest {
    payload: SignedArtifactManifestPayload,
    artifact_count: usize,
}

impl VerifiedSignedArtifactManifest {
    pub fn payload(&self) -> &SignedArtifactManifestPayload {
        &self.payload
    }

    pub fn artifact_count(&self) -> usize {
        self.artifact_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArtifact {
    pub descriptor: ArtifactDescriptor,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArtifactBundle {
    pub version: String,
    pub circuit: String,
    pub artifacts: Vec<ResolvedArtifact>,
}

impl ResolvedArtifactBundle {
    pub fn artifact(&self, kind: ArtifactKind) -> Result<&ResolvedArtifact, ArtifactError> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.descriptor.kind == kind)
            .ok_or_else(|| ArtifactError::MissingArtifact {
                circuit: self.circuit.clone(),
                kind,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBytes {
    pub kind: ArtifactKind,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    descriptor: ArtifactDescriptor,
    bytes: Vec<u8>,
}

impl VerifiedArtifact {
    pub fn descriptor(&self) -> &ArtifactDescriptor {
        &self.descriptor
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifactBundle {
    version: String,
    circuit: String,
    artifacts: Vec<VerifiedArtifact>,
}

impl VerifiedArtifactBundle {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn circuit(&self) -> &str {
        &self.circuit
    }

    pub fn artifacts(&self) -> &[VerifiedArtifact] {
        &self.artifacts
    }

    pub fn artifact(&self, kind: ArtifactKind) -> Result<&VerifiedArtifact, ArtifactError> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.descriptor.kind == kind)
            .ok_or_else(|| ArtifactError::MissingArtifact {
                circuit: self.circuit.clone(),
                kind,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStatus {
    pub descriptor: ArtifactDescriptor,
    pub path: PathBuf,
    pub exists: bool,
    pub verified: bool,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("no artifacts declared for circuit `{0}`")]
    MissingCircuit(String),
    #[error("missing artifact `{kind:?}` for circuit `{circuit}`")]
    MissingArtifact { circuit: String, kind: ArtifactKind },
    #[error("duplicate artifact descriptor for `{kind:?}` in circuit `{circuit}`")]
    DuplicateArtifactDescriptor { circuit: String, kind: ArtifactKind },
    #[error("duplicate artifact bytes supplied for `{kind:?}` in circuit `{circuit}`")]
    DuplicateArtifactBytes { circuit: String, kind: ArtifactKind },
    #[error("artifact file does not exist: {0}")]
    MissingArtifactFile(PathBuf),
    #[error("unexpected artifact bytes supplied for `{kind:?}` in circuit `{circuit}`")]
    UnexpectedArtifactBytes { circuit: String, kind: ArtifactKind },
    #[error("sha256 mismatch for `{filename}`: expected {expected}, got {actual}")]
    HashMismatch {
        filename: String,
        expected: String,
        actual: String,
    },
    #[error("invalid signed artifact manifest: {0}")]
    InvalidSignedManifest(String),
    #[error("artifact manifest signature verification failed")]
    InvalidManifestSignature,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl ArtifactManifest {
    pub fn descriptor(
        &self,
        circuit: &str,
        kind: ArtifactKind,
    ) -> Result<&ArtifactDescriptor, ArtifactError> {
        let mut matches = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.circuit == circuit && artifact.kind == kind);
        let descriptor = matches
            .next()
            .ok_or_else(|| ArtifactError::MissingArtifact {
                circuit: circuit.to_owned(),
                kind,
            })?;
        if matches.next().is_some() {
            return Err(ArtifactError::DuplicateArtifactDescriptor {
                circuit: circuit.to_owned(),
                kind,
            });
        }

        Ok(descriptor)
    }

    pub fn resolve_path(&self, root: impl AsRef<Path>, descriptor: &ArtifactDescriptor) -> PathBuf {
        root.as_ref().join(&descriptor.filename)
    }

    pub fn descriptors_for_circuit(&self, circuit: &str) -> Vec<&ArtifactDescriptor> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.circuit == circuit)
            .collect()
    }

    pub fn resolve_required(
        &self,
        root: impl AsRef<Path>,
        circuit: &str,
        kind: ArtifactKind,
    ) -> Result<ResolvedArtifact, ArtifactError> {
        let descriptor = self.descriptor(circuit, kind)?.clone();
        let path = self.resolve_path(root, &descriptor);

        if !path.exists() {
            return Err(ArtifactError::MissingArtifactFile(path));
        }

        Ok(ResolvedArtifact { descriptor, path })
    }

    pub fn resolve_verified_bundle(
        &self,
        root: impl AsRef<Path>,
        circuit: &str,
    ) -> Result<ResolvedArtifactBundle, ArtifactError> {
        let descriptors = self.validated_descriptors_for_circuit(circuit)?;

        let artifacts = descriptors
            .into_iter()
            .map(|descriptor| {
                let resolved = self.resolve_required(root.as_ref(), circuit, descriptor.kind)?;
                verify_artifact_file(&resolved)?;
                Ok(resolved)
            })
            .collect::<Result<Vec<_>, ArtifactError>>()?;

        Ok(ResolvedArtifactBundle {
            version: self.version.clone(),
            circuit: circuit.to_owned(),
            artifacts,
        })
    }

    pub fn load_verified_bundle(
        &self,
        root: impl AsRef<Path>,
        circuit: &str,
    ) -> Result<VerifiedArtifactBundle, ArtifactError> {
        let descriptors = self.validated_descriptors_for_circuit(circuit)?;

        let artifacts = descriptors
            .into_iter()
            .map(|descriptor| {
                let resolved = self.resolve_required(root.as_ref(), circuit, descriptor.kind)?;
                let bytes = fs::read(&resolved.path)?;
                verify_artifact_bytes(&resolved.descriptor, &bytes)?;

                Ok(VerifiedArtifact {
                    descriptor: resolved.descriptor,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, ArtifactError>>()?;

        Ok(VerifiedArtifactBundle {
            version: self.version.clone(),
            circuit: circuit.to_owned(),
            artifacts,
        })
    }

    pub fn verify_bundle_bytes(
        &self,
        circuit: &str,
        artifacts: impl IntoIterator<Item = ArtifactBytes>,
    ) -> Result<VerifiedArtifactBundle, ArtifactError> {
        let descriptors = self.validated_descriptors_for_circuit(circuit)?;

        let mut supplied = HashMap::new();
        for artifact in artifacts {
            if supplied.insert(artifact.kind, artifact.bytes).is_some() {
                return Err(ArtifactError::DuplicateArtifactBytes {
                    circuit: circuit.to_owned(),
                    kind: artifact.kind,
                });
            }
        }

        let mut verified = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            let bytes = supplied.remove(&descriptor.kind).ok_or_else(|| {
                ArtifactError::MissingArtifact {
                    circuit: circuit.to_owned(),
                    kind: descriptor.kind,
                }
            })?;
            verify_artifact_bytes(descriptor, &bytes)?;
            verified.push(VerifiedArtifact {
                descriptor: descriptor.clone(),
                bytes,
            });
        }

        if let Some(kind) = supplied.into_keys().next() {
            return Err(ArtifactError::UnexpectedArtifactBytes {
                circuit: circuit.to_owned(),
                kind,
            });
        }

        Ok(VerifiedArtifactBundle {
            version: self.version.clone(),
            circuit: circuit.to_owned(),
            artifacts: verified,
        })
    }

    fn validated_descriptors_for_circuit(
        &self,
        circuit: &str,
    ) -> Result<Vec<&ArtifactDescriptor>, ArtifactError> {
        let descriptors = self.descriptors_for_circuit(circuit);
        if descriptors.is_empty() {
            return Err(ArtifactError::MissingCircuit(circuit.to_owned()));
        }

        let mut seen = HashMap::<ArtifactKind, ()>::new();
        for descriptor in &descriptors {
            if seen.insert(descriptor.kind, ()).is_some() {
                return Err(ArtifactError::DuplicateArtifactDescriptor {
                    circuit: circuit.to_owned(),
                    kind: descriptor.kind,
                });
            }
        }

        Ok(descriptors)
    }
}

pub fn verify_artifact_bytes(
    descriptor: &ArtifactDescriptor,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != descriptor.sha256 {
        return Err(ArtifactError::HashMismatch {
            filename: descriptor.filename.clone(),
            expected: descriptor.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_artifact_file(resolved: &ResolvedArtifact) -> Result<(), ArtifactError> {
    let bytes = fs::read(&resolved.path)?;
    verify_artifact_bytes(&resolved.descriptor, &bytes)
}

pub fn verify_signed_manifest_bytes(
    payload_json: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<SignedArtifactManifestPayload, ArtifactError> {
    let signature_bytes = decode_fixed_hex::<64>(signature_hex)?;
    let public_key_bytes = decode_fixed_hex::<32>(public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| ArtifactError::InvalidSignedManifest(error.to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(payload_json, &signature)
        .map_err(|_| ArtifactError::InvalidManifestSignature)?;

    serde_json::from_slice(payload_json)
        .map_err(|error| ArtifactError::InvalidSignedManifest(error.to_string()))
}

pub fn verify_signed_manifest_artifact_bytes(
    payload_json: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    artifacts: impl IntoIterator<Item = SignedManifestArtifactBytes>,
) -> Result<VerifiedSignedArtifactManifest, ArtifactError> {
    let payload = verify_signed_manifest_bytes(payload_json, signature_hex, public_key_hex)?;
    let mut supplied = HashMap::new();
    for artifact in artifacts {
        if supplied.insert(artifact.filename, artifact.bytes).is_some() {
            return Err(ArtifactError::InvalidSignedManifest(
                "duplicate artifact filename supplied".to_owned(),
            ));
        }
    }

    for descriptor in &payload.manifest.artifacts {
        let bytes = supplied.remove(&descriptor.filename).ok_or_else(|| {
            ArtifactError::MissingArtifactFile(PathBuf::from(&descriptor.filename))
        })?;
        verify_artifact_bytes(descriptor, &bytes)?;
    }

    if let Some(filename) = supplied.into_keys().next() {
        return Err(ArtifactError::InvalidSignedManifest(format!(
            "unexpected artifact bytes supplied for {filename}"
        )));
    }

    let artifact_count = payload.manifest.artifacts.len();
    Ok(VerifiedSignedArtifactManifest {
        payload,
        artifact_count,
    })
}

pub fn verify_signed_manifest_artifact_files(
    payload_json: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
    root: impl AsRef<Path>,
) -> Result<VerifiedSignedArtifactManifest, ArtifactError> {
    let payload = verify_signed_manifest_bytes(payload_json, signature_hex, public_key_hex)?;

    for descriptor in &payload.manifest.artifacts {
        let path = payload.manifest.resolve_path(root.as_ref(), descriptor);
        if !path.exists() {
            return Err(ArtifactError::MissingArtifactFile(path));
        }
        let bytes = fs::read(&path)?;
        verify_artifact_bytes(descriptor, &bytes)?;
    }

    let artifact_count = payload.manifest.artifacts.len();
    Ok(VerifiedSignedArtifactManifest {
        payload,
        artifact_count,
    })
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ArtifactError> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| ArtifactError::InvalidSignedManifest(error.to_string()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ArtifactError::InvalidSignedManifest(format!("expected {N} bytes, got {}", bytes.len()))
    })
}

pub fn artifact_status(root: impl AsRef<Path>, descriptor: &ArtifactDescriptor) -> ArtifactStatus {
    let path = root.as_ref().join(&descriptor.filename);
    let exists = path.exists();
    let verified = if exists {
        fs::read(&path)
            .ok()
            .map(|bytes| verify_artifact_bytes(descriptor, &bytes).is_ok())
            .unwrap_or(false)
    } else {
        false
    };

    ArtifactStatus {
        descriptor: descriptor.clone(),
        path,
        exists,
        verified,
    }
}

pub fn artifact_statuses(
    manifest: &ArtifactManifest,
    root: impl AsRef<Path>,
    circuit: &str,
) -> Vec<ArtifactStatus> {
    manifest
        .descriptors_for_circuit(circuit)
        .into_iter()
        .map(|descriptor| artifact_status(root.as_ref(), descriptor))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use std::path::PathBuf;

    #[test]
    fn verifies_manifest_and_bytes() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-manifest.json"
        ))
        .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let resolved = manifest
            .resolve_required(root, "withdraw", ArtifactKind::Wasm)
            .unwrap();

        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin");
        verify_artifact_bytes(&resolved.descriptor, bytes).unwrap();
        verify_artifact_file(&resolved).unwrap();
        assert!(resolved.path.ends_with("sample-artifact.bin"));
    }

    #[test]
    fn verifies_signed_manifest_payload_bytes() {
        let payload = SignedArtifactManifestPayload {
            manifest: ArtifactManifest {
                version: "1.2.0".to_owned(),
                artifacts: vec![ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "withdraw.wasm".to_owned(),
                    sha256: hex::encode(Sha256::digest(b"artifact bytes")),
                }],
            },
            metadata: ArtifactManifestMetadata {
                ceremony: Some("test ceremony".to_owned()),
                build: Some("ci release".to_owned()),
                repository: Some("0xbow/privacy-pools-sdk-rs".to_owned()),
                commit: Some("abc123".to_owned()),
            },
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let signature = signing_key.sign(&payload_json);
        let signature_hex = hex::encode(signature.to_bytes());
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let verified =
            verify_signed_manifest_bytes(&payload_json, &signature_hex, &public_key_hex).unwrap();
        assert_eq!(verified, payload);

        let verified_artifacts = verify_signed_manifest_artifact_bytes(
            &payload_json,
            &signature_hex,
            &public_key_hex,
            [SignedManifestArtifactBytes {
                filename: "withdraw.wasm".to_owned(),
                bytes: b"artifact bytes".to_vec(),
            }],
        )
        .unwrap();
        assert_eq!(verified_artifacts.payload(), &payload);
        assert_eq!(verified_artifacts.artifact_count(), 1);

        let artifact_root = tempfile::tempdir().unwrap();
        fs::write(
            artifact_root.path().join("withdraw.wasm"),
            b"artifact bytes",
        )
        .unwrap();
        let verified_files = verify_signed_manifest_artifact_files(
            &payload_json,
            &signature_hex,
            &public_key_hex,
            artifact_root.path(),
        )
        .unwrap();
        assert_eq!(verified_files.payload(), &payload);
        assert_eq!(verified_files.artifact_count(), 1);

        assert!(matches!(
            verify_signed_manifest_artifact_bytes(
                &payload_json,
                &signature_hex,
                &public_key_hex,
                [SignedManifestArtifactBytes {
                    filename: "withdraw.wasm".to_owned(),
                    bytes: b"modified artifact bytes".to_vec(),
                }],
            ),
            Err(ArtifactError::HashMismatch { .. })
        ));

        let mut modified_payload = payload_json.clone();
        modified_payload.push(b' ');
        assert!(matches!(
            verify_signed_manifest_bytes(&modified_payload, &signature_hex, &public_key_hex),
            Err(ArtifactError::InvalidManifestSignature)
        ));

        let wrong_key = SigningKey::from_bytes(&[8_u8; 32]);
        assert!(matches!(
            verify_signed_manifest_bytes(
                &payload_json,
                &signature_hex,
                &hex::encode(wrong_key.verifying_key().to_bytes())
            ),
            Err(ArtifactError::InvalidManifestSignature)
        ));

        let mut wrong_signature = signature.to_bytes();
        wrong_signature[0] ^= 1;
        assert!(matches!(
            verify_signed_manifest_bytes(
                &payload_json,
                &hex::encode(wrong_signature),
                &public_key_hex
            ),
            Err(ArtifactError::InvalidManifestSignature)
        ));
    }

    #[test]
    fn reports_artifact_status_for_existing_and_missing_files() {
        let manifest = ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![
                ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "sample-artifact.bin".to_owned(),
                    sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                        .to_owned(),
                },
                ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Zkey,
                    filename: "missing-artifact.zkey".to_owned(),
                    sha256: "00".repeat(32),
                },
            ],
        };

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let statuses = artifact_statuses(&manifest, root, "withdraw");

        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].exists);
        assert!(statuses[0].verified);
        assert!(!statuses[1].exists);
        assert!(!statuses[1].verified);
    }

    #[test]
    fn resolves_verified_bundle_for_declared_circuit() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-manifest.json"
        ))
        .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let bundle = manifest.resolve_verified_bundle(root, "withdraw").unwrap();

        assert_eq!(bundle.version, "0.1.0-alpha.1");
        assert_eq!(bundle.circuit, "withdraw");
        assert_eq!(bundle.artifacts.len(), 1);
        assert_eq!(bundle.artifacts[0].descriptor.kind, ArtifactKind::Wasm);
        assert!(bundle.artifacts[0].path.ends_with("sample-artifact.bin"));
    }

    #[test]
    fn loads_verified_bundle_bytes_for_declared_circuit() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-proving-manifest.json"
        ))
        .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let bundle = manifest.load_verified_bundle(root, "withdraw").unwrap();

        assert_eq!(bundle.version(), "0.1.0-alpha.1");
        assert_eq!(bundle.circuit(), "withdraw");
        assert_eq!(bundle.artifacts().len(), 3);
        assert_eq!(
            bundle.artifact(ArtifactKind::Zkey).unwrap().bytes(),
            include_bytes!("../../../fixtures/artifacts/sample-artifact.bin")
        );
    }

    #[test]
    fn verifies_bundle_from_supplied_bytes() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-proving-manifest.json"
        ))
        .unwrap();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let bundle = manifest
            .verify_bundle_bytes(
                "withdraw",
                [
                    ArtifactBytes {
                        kind: ArtifactKind::Wasm,
                        bytes: bytes.clone(),
                    },
                    ArtifactBytes {
                        kind: ArtifactKind::Zkey,
                        bytes: bytes.clone(),
                    },
                    ArtifactBytes {
                        kind: ArtifactKind::Vkey,
                        bytes,
                    },
                ],
            )
            .unwrap();

        assert_eq!(bundle.artifacts().len(), 3);
        assert_eq!(
            bundle
                .artifact(ArtifactKind::Vkey)
                .unwrap()
                .descriptor()
                .filename,
            "sample-artifact.bin"
        );
    }

    #[test]
    fn rejects_duplicate_bundle_bytes() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-proving-manifest.json"
        ))
        .unwrap();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let error = manifest
            .verify_bundle_bytes(
                "withdraw",
                [
                    ArtifactBytes {
                        kind: ArtifactKind::Wasm,
                        bytes: bytes.clone(),
                    },
                    ArtifactBytes {
                        kind: ArtifactKind::Wasm,
                        bytes,
                    },
                ],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ArtifactError::DuplicateArtifactBytes {
                circuit,
                kind: ArtifactKind::Wasm,
            } if circuit == "withdraw"
        ));
    }

    #[test]
    fn rejects_incomplete_bundle_bytes() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-proving-manifest.json"
        ))
        .unwrap();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let error = manifest
            .verify_bundle_bytes(
                "withdraw",
                [
                    ArtifactBytes {
                        kind: ArtifactKind::Wasm,
                        bytes: bytes.clone(),
                    },
                    ArtifactBytes {
                        kind: ArtifactKind::Zkey,
                        bytes,
                    },
                ],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ArtifactError::MissingArtifact {
                circuit,
                kind: ArtifactKind::Vkey,
            } if circuit == "withdraw"
        ));
    }

    #[test]
    fn rejects_unexpected_bundle_bytes() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-manifest.json"
        ))
        .unwrap();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let error = manifest
            .verify_bundle_bytes(
                "withdraw",
                [
                    ArtifactBytes {
                        kind: ArtifactKind::Wasm,
                        bytes: bytes.clone(),
                    },
                    ArtifactBytes {
                        kind: ArtifactKind::Zkey,
                        bytes,
                    },
                ],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ArtifactError::UnexpectedArtifactBytes {
                circuit,
                kind: ArtifactKind::Zkey,
            } if circuit == "withdraw"
        ));
    }

    #[test]
    fn rejects_unknown_bundle_circuit() {
        let manifest: ArtifactManifest = serde_json::from_str(include_str!(
            "../../../fixtures/artifacts/sample-manifest.json"
        ))
        .unwrap();
        let bytes = include_bytes!("../../../fixtures/artifacts/sample-artifact.bin").to_vec();

        let error = manifest
            .verify_bundle_bytes(
                "relay",
                [ArtifactBytes {
                    kind: ArtifactKind::Wasm,
                    bytes,
                }],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ArtifactError::MissingCircuit(circuit) if circuit == "relay"
        ));
    }

    #[test]
    fn verified_bundle_fails_closed_on_hash_mismatch() {
        let manifest = ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![ArtifactDescriptor {
                circuit: "withdraw".to_owned(),
                kind: ArtifactKind::Wasm,
                filename: "sample-artifact.bin".to_owned(),
                sha256: "00".repeat(32),
            }],
        };
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
        let error = manifest
            .resolve_verified_bundle(root, "withdraw")
            .unwrap_err();

        assert!(matches!(error, ArtifactError::HashMismatch { .. }));
    }

    #[test]
    fn rejects_duplicate_artifact_descriptors() {
        let manifest = ArtifactManifest {
            version: "0.1.0-alpha.1".to_owned(),
            artifacts: vec![
                ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "sample-artifact.bin".to_owned(),
                    sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                        .to_owned(),
                },
                ArtifactDescriptor {
                    circuit: "withdraw".to_owned(),
                    kind: ArtifactKind::Wasm,
                    filename: "sample-artifact-copy.bin".to_owned(),
                    sha256: "cd36a390ad623cecbf1bb61d5e3b4e256a8a9c9cd7f7650dd140a95c9e0395b5"
                        .to_owned(),
                },
            ],
        };
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");

        let error = manifest
            .resolve_verified_bundle(root, "withdraw")
            .unwrap_err();

        assert!(matches!(
            error,
            ArtifactError::DuplicateArtifactDescriptor {
                circuit,
                kind: ArtifactKind::Wasm,
            } if circuit == "withdraw"
        ));
    }

    proptest! {
        #[test]
        fn artifact_hash_validation_accepts_only_matching_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let descriptor = ArtifactDescriptor {
                circuit: "withdraw".to_owned(),
                kind: ArtifactKind::Wasm,
                filename: "withdraw.wasm".to_owned(),
                sha256: hex::encode(Sha256::digest(&bytes)),
            };

            prop_assert!(verify_artifact_bytes(&descriptor, &bytes).is_ok());

            let mut modified = bytes.clone();
            modified.push(1);
            let hash_mismatch = matches!(
                verify_artifact_bytes(&descriptor, &modified),
                Err(ArtifactError::HashMismatch { .. })
            );
            prop_assert!(hash_mismatch);
        }

        #[test]
        fn signed_manifest_artifact_validation_rejects_unexpected_artifacts(
            required in prop::collection::vec(any::<u8>(), 0..128),
            unexpected in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            let payload = SignedArtifactManifestPayload {
                manifest: ArtifactManifest {
                    version: "property".to_owned(),
                    artifacts: vec![ArtifactDescriptor {
                        circuit: "withdraw".to_owned(),
                        kind: ArtifactKind::Wasm,
                        filename: "withdraw.wasm".to_owned(),
                        sha256: hex::encode(Sha256::digest(&required)),
                    }],
                },
                metadata: ArtifactManifestMetadata {
                    ceremony: None,
                    build: None,
                    repository: None,
                    commit: None,
                },
            };
            let payload_json = serde_json::to_vec(&payload).expect("payload serializes");
            let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
            let signature = signing_key.sign(&payload_json);
            let signature_hex = hex::encode(signature.to_bytes());
            let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

            let error = verify_signed_manifest_artifact_bytes(
                &payload_json,
                &signature_hex,
                &public_key_hex,
                [
                    SignedManifestArtifactBytes {
                        filename: "withdraw.wasm".to_owned(),
                        bytes: required,
                    },
                    SignedManifestArtifactBytes {
                        filename: "unexpected.wasm".to_owned(),
                        bytes: unexpected,
                    },
                ],
            )
            .expect_err("unexpected artifacts are rejected");

            prop_assert!(matches!(error, ArtifactError::InvalidSignedManifest(_)));
        }
    }
}
