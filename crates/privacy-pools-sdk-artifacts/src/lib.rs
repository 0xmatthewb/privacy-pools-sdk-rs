use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("missing artifact `{kind:?}` for circuit `{circuit}`")]
    MissingArtifact { circuit: String, kind: ArtifactKind },
    #[error("artifact file does not exist: {0}")]
    MissingArtifactFile(PathBuf),
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
}
