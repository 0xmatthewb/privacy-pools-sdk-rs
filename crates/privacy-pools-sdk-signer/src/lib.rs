use alloy_primitives::{Address, B256};
use alloy_signer_local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    LocalDev,
    HostProvided,
    MobileSecureStorage,
}

pub trait SignerAdapter {
    fn address(&self) -> Address;
    fn kind(&self) -> SignerKind;
}

#[derive(Debug, Clone)]
pub struct LocalMnemonicSigner {
    signer: PrivateKeySigner,
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error(transparent)]
    Local(#[from] LocalSignerError),
}

impl LocalMnemonicSigner {
    pub fn from_phrase_nth(phrase: &str, index: u32) -> Result<Self, SignerError> {
        Ok(Self {
            signer: MnemonicBuilder::from_phrase_nth(phrase, index),
        })
    }

    pub fn private_key_bytes(&self) -> B256 {
        self.signer.to_bytes()
    }
}

impl SignerAdapter for LocalMnemonicSigner {
    fn address(&self) -> Address {
        self.signer.address()
    }

    fn kind(&self) -> SignerKind {
        SignerKind::LocalDev
    }
}
