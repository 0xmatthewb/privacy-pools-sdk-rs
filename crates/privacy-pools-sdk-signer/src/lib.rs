use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, B256, Bytes};
use alloy_signer_local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner};
use privacy_pools_sdk_core::FinalizedTransactionRequest;
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
pub struct ExternalSigner {
    address: Address,
    kind: SignerKind,
}

#[derive(Debug, Clone)]
pub struct LocalMnemonicSigner {
    signer: PrivateKeySigner,
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error(transparent)]
    Local(#[from] LocalSignerError),
    #[error("invalid finalized transaction fee model")]
    InvalidFeeModel,
    #[error("failed to sign transaction: {0}")]
    Transaction(String),
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

    pub fn private_key_signer(&self) -> PrivateKeySigner {
        self.signer.clone()
    }

    pub fn sign_transaction_request(
        &self,
        request: &FinalizedTransactionRequest,
    ) -> Result<Bytes, SignerError> {
        let envelope = if let Some(gas_price) = request.gas_price {
            let mut tx = TxLegacy {
                chain_id: Some(request.chain_id),
                nonce: request.nonce,
                gas_price,
                gas_limit: request.gas_limit,
                to: request.to.into(),
                value: request.value,
                input: request.data.clone(),
            };
            let signature = self
                .signer
                .sign_transaction_sync(&mut tx)
                .map_err(|error| SignerError::Transaction(error.to_string()))?;
            TxEnvelope::from(tx.into_signed(signature))
        } else {
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                match (request.max_fee_per_gas, request.max_priority_fee_per_gas) {
                    (Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => {
                        (max_fee_per_gas, max_priority_fee_per_gas)
                    }
                    _ => return Err(SignerError::InvalidFeeModel),
                };
            let mut tx = TxEip1559 {
                chain_id: request.chain_id,
                nonce: request.nonce,
                gas_limit: request.gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to: request.to.into(),
                value: request.value,
                access_list: Default::default(),
                input: request.data.clone(),
            };
            let signature = self
                .signer
                .sign_transaction_sync(&mut tx)
                .map_err(|error| SignerError::Transaction(error.to_string()))?;
            TxEnvelope::from(tx.into_signed(signature))
        };

        Ok(envelope.encoded_2718().into())
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

impl ExternalSigner {
    pub fn host_provided(address: Address) -> Self {
        Self {
            address,
            kind: SignerKind::HostProvided,
        }
    }

    pub fn mobile_secure_storage(address: Address) -> Self {
        Self {
            address,
            kind: SignerKind::MobileSecureStorage,
        }
    }
}

impl SignerAdapter for ExternalSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn kind(&self) -> SignerKind {
        self.kind
    }
}
