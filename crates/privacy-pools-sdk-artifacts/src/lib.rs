use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub descriptor: ArtifactDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifactBundle {
    pub version: String,
    pub circuit: String,
    pub artifacts: Vec<VerifiedArtifact>,
}

impl VerifiedArtifactBundle {
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
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl ArtifactManifest {
    pub fn descriptor(
        &self,
        circuit: &str,
        kind: ArtifactKind,
    ) -> Result<&ArtifactDescriptor, ArtifactError> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.circuit == circuit && artifact.kind == kind)
            .ok_or_else(|| ArtifactError::MissingArtifact {
                circuit: circuit.to_owned(),
                kind,
            })
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
        let descriptors = self.descriptors_for_circuit(circuit);
        if descriptors.is_empty() {
            return Err(ArtifactError::MissingCircuit(circuit.to_owned()));
        }

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
        let descriptors = self.descriptors_for_circuit(circuit);
        if descriptors.is_empty() {
            return Err(ArtifactError::MissingCircuit(circuit.to_owned()));
        }

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
        let descriptors = self.descriptors_for_circuit(circuit);
        if descriptors.is_empty() {
            return Err(ArtifactError::MissingCircuit(circuit.to_owned()));
        }

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

        assert_eq!(bundle.version, "0.1.0-alpha.1");
        assert_eq!(bundle.circuit, "withdraw");
        assert_eq!(bundle.artifacts.len(), 3);
        assert_eq!(
            bundle.artifact(ArtifactKind::Zkey).unwrap().bytes,
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

        assert_eq!(bundle.artifacts.len(), 3);
        assert_eq!(
            bundle
                .artifact(ArtifactKind::Vkey)
                .unwrap()
                .descriptor
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
}
