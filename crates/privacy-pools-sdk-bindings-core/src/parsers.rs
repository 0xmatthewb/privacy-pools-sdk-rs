use privacy_pools_sdk_artifacts::ArtifactKind;
use privacy_pools_sdk_prover::BackendProfile;
use privacy_pools_sdk_recovery::CompatibilityMode;

use crate::BindingCoreError;

pub fn parse_artifact_kind(value: &str) -> Result<ArtifactKind, BindingCoreError> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => Err(BindingCoreError::InvalidRelayData(format!(
            "invalid artifact kind: {value}"
        ))),
    }
}

pub fn parse_compatibility_mode(value: &str) -> Result<CompatibilityMode, BindingCoreError> {
    match value {
        "strict" => Ok(CompatibilityMode::Strict),
        "legacy" => Ok(CompatibilityMode::Legacy),
        _ => Err(BindingCoreError::InvalidRelayData(format!(
            "invalid compatibility mode: {value}"
        ))),
    }
}

pub fn parse_backend_profile(value: &str) -> Result<BackendProfile, BindingCoreError> {
    match value {
        "stable" => Ok(BackendProfile::Stable),
        _ => Err(BindingCoreError::InvalidRelayData(format!(
            "invalid backend profile: {value}"
        ))),
    }
}
