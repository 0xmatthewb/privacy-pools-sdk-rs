use thiserror::Error;

#[derive(Error, Debug)]
pub enum BindingCoreError {
    #[error("chain id mismatch: expected {expected}, actual {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
    #[error("invalid signed transaction: {0}")]
    InvalidSignedTransaction(String),
    #[error("signer requires external signing capability")]
    SignerRequiresExternalSigning,
    #[error("unmatched ragequit: scope={scope} label={label}")]
    UnmatchedRagequit { scope: String, label: String },
    #[error("registry {registry} is full (capacity {capacity})")]
    RegistryFull {
        registry: &'static str,
        capacity: usize,
    },
    #[error("handle already registered: {0}")]
    HandleAlreadyRegistered(String),
    #[error("payload too large: {field} exceeded {limit} bytes (actual {actual})")]
    PayloadTooLarge {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("invalid relay data: {0}")]
    InvalidRelayData(String),
}
