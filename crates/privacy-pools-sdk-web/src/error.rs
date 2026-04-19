use privacy_pools_sdk_bindings_core::BindingCoreError;
use serde::Serialize;
use wasm_bindgen::prelude::JsValue;

#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "kebab-case")]
pub enum WebError {
    ChainIdMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidSignedTransaction {
        message: String,
    },
    SignerRequiresExternalSigning,
    UnmatchedRagequit {
        scope: String,
        label: String,
    },
    RegistryFull {
        registry: String,
        capacity: usize,
    },
    HandleAlreadyRegistered {
        handle: String,
    },
    PayloadTooLarge {
        field: String,
        limit: u64,
        actual: u64,
    },
    InvalidMnemonic {
        message: String,
    },
    InvalidRelayData {
        message: String,
    },
    OperationFailed {
        message: String,
    },
}

impl From<WebError> for JsValue {
    fn from(error: WebError) -> Self {
        serde_wasm_bindgen::to_value(&error).unwrap_or_else(|serialization_error| {
            JsValue::from_str(&format!(
                "failed to serialize web error: {serialization_error}: {error:?}"
            ))
        })
    }
}

impl From<BindingCoreError> for WebError {
    fn from(error: BindingCoreError) -> Self {
        match error {
            BindingCoreError::ChainIdMismatch { expected, actual } => {
                Self::ChainIdMismatch { expected, actual }
            }
            BindingCoreError::InvalidSignedTransaction(message) => {
                Self::InvalidSignedTransaction { message }
            }
            BindingCoreError::SignerRequiresExternalSigning => Self::SignerRequiresExternalSigning,
            BindingCoreError::UnmatchedRagequit { scope, label } => {
                Self::UnmatchedRagequit { scope, label }
            }
            BindingCoreError::RegistryFull { registry, capacity } => Self::RegistryFull {
                registry: registry.to_owned(),
                capacity,
            },
            BindingCoreError::HandleAlreadyRegistered(handle) => {
                Self::HandleAlreadyRegistered { handle }
            }
            BindingCoreError::PayloadTooLarge {
                field,
                limit,
                actual,
            } => Self::PayloadTooLarge {
                field: field.to_owned(),
                limit: limit as u64,
                actual: actual as u64,
            },
            BindingCoreError::InvalidMnemonic(message) => Self::InvalidMnemonic { message },
            BindingCoreError::InvalidRelayData(message) => Self::InvalidRelayData { message },
        }
    }
}

impl From<anyhow::Error> for WebError {
    fn from(error: anyhow::Error) -> Self {
        Self::OperationFailed {
            message: error.to_string(),
        }
    }
}
