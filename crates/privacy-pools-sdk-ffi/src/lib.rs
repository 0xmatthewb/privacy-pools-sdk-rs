use alloy_primitives::Address;
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{ArtifactKind, ArtifactManifest},
    core::RootReadKind,
};
use std::str::FromStr;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid artifact kind: {0}")]
    InvalidArtifactKind(String),
    #[error("artifact manifest parse failed: {0}")]
    InvalidManifest(String),
    #[error("sdk operation failed: {0}")]
    OperationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMasterKeys {
    pub master_nullifier: String,
    pub master_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRootRead {
    pub kind: String,
    pub contract_address: String,
    pub pool_address: String,
    pub call_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiArtifactVerification {
    pub version: String,
    pub circuit: String,
    pub kind: String,
    pub filename: String,
}

fn sdk() -> PrivacyPoolsSdk {
    PrivacyPoolsSdk::default()
}

fn parse_address(value: &str) -> Result<Address, FfiError> {
    Address::from_str(value).map_err(|_| FfiError::InvalidAddress(value.to_owned()))
}

fn parse_artifact_kind(value: &str) -> Result<ArtifactKind, FfiError> {
    match value {
        "wasm" => Ok(ArtifactKind::Wasm),
        "zkey" => Ok(ArtifactKind::Zkey),
        "vkey" => Ok(ArtifactKind::Vkey),
        _ => Err(FfiError::InvalidArtifactKind(value.to_owned())),
    }
}

fn root_read_kind_label(kind: RootReadKind) -> String {
    match kind {
        RootReadKind::PoolState => "pool_state".to_owned(),
        RootReadKind::Asp => "asp".to_owned(),
    }
}

fn to_ffi_root_read(read: privacy_pools_sdk::core::RootRead) -> FfiRootRead {
    FfiRootRead {
        kind: root_read_kind_label(read.kind),
        contract_address: read.contract_address.to_string(),
        pool_address: read.pool_address.to_string(),
        call_data: format!("0x{}", hex::encode(read.call_data)),
    }
}

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn get_version() -> String {
    PrivacyPoolsSdk::version().to_owned()
}

#[uniffi::export]
pub fn get_stable_backend_name() -> Result<String, FfiError> {
    sdk()
        .stable_backend_name()
        .map_err(|error| FfiError::OperationFailed(error.to_string()))
}

#[uniffi::export]
pub fn fast_backend_supported_on_target() -> bool {
    sdk().fast_backend_supported_on_target()
}

#[uniffi::export]
pub fn derive_master_keys(mnemonic: String) -> Result<FfiMasterKeys, FfiError> {
    let keys = sdk()
        .generate_master_keys(&mnemonic)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FfiMasterKeys {
        master_nullifier: keys.master_nullifier.to_string(),
        master_secret: keys.master_secret.to_string(),
    })
}

#[uniffi::export]
pub fn plan_pool_state_root_read(pool_address: String) -> Result<FfiRootRead, FfiError> {
    let pool_address = parse_address(&pool_address)?;
    Ok(to_ffi_root_read(
        sdk().plan_pool_state_root_read(pool_address),
    ))
}

#[uniffi::export]
pub fn plan_asp_root_read(
    entrypoint_address: String,
    pool_address: String,
) -> Result<FfiRootRead, FfiError> {
    let entrypoint_address = parse_address(&entrypoint_address)?;
    let pool_address = parse_address(&pool_address)?;

    Ok(to_ffi_root_read(
        sdk().plan_asp_root_read(entrypoint_address, pool_address),
    ))
}

#[uniffi::export]
pub fn verify_artifact_bytes(
    manifest_json: String,
    circuit: String,
    kind: String,
    bytes: Vec<u8>,
) -> Result<FfiArtifactVerification, FfiError> {
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| FfiError::InvalidManifest(error.to_string()))?;
    let kind = parse_artifact_kind(&kind)?;
    let version = manifest.version.clone();
    let descriptor = manifest
        .descriptor(&circuit, kind)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    privacy_pools_sdk::artifacts::verify_artifact_bytes(descriptor, &bytes)
        .map_err(|error| FfiError::OperationFailed(error.to_string()))?;

    Ok(FfiArtifactVerification {
        version,
        circuit,
        kind: match kind {
            ArtifactKind::Wasm => "wasm".to_owned(),
            ArtifactKind::Zkey => "zkey".to_owned(),
            ArtifactKind::Vkey => "vkey".to_owned(),
        },
        filename: descriptor.filename.clone(),
    })
}
