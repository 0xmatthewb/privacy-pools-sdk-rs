#[cfg(feature = "local-mnemonic")]
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
#[cfg(feature = "local-mnemonic")]
use alloy_eips::Encodable2718;
#[cfg(feature = "local-mnemonic")]
use alloy_network::TxSignerSync;
use alloy_primitives::Address;
#[cfg(feature = "dangerous-key-export")]
use alloy_primitives::B256;
#[cfg(feature = "local-mnemonic")]
use alloy_primitives::Bytes;
#[cfg(feature = "local-mnemonic")]
use alloy_signer_local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner};
#[cfg(feature = "local-mnemonic")]
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

#[cfg(feature = "local-mnemonic")]
#[derive(Clone)]
pub struct LocalMnemonicSigner {
    signer: PrivateKeySigner,
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error(transparent)]
    #[cfg(feature = "local-mnemonic")]
    Local(#[from] LocalSignerError),
    #[error("transaction chain id must be non-zero")]
    InvalidChainId,
    #[error("provider chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
    #[error("invalid finalized transaction fee model")]
    InvalidFeeModel,
    #[error("failed to sign transaction: {0}")]
    Transaction(String),
}

#[cfg(feature = "local-mnemonic")]
impl LocalMnemonicSigner {
    pub fn from_phrase_nth(phrase: &str, index: u32) -> Result<Self, SignerError> {
        Ok(Self {
            signer: MnemonicBuilder::try_from_phrase_nth(phrase, index)?,
        })
    }

    #[cfg(feature = "dangerous-key-export")]
    pub fn dangerously_export_private_key_bytes(&self) -> B256 {
        self.signer.to_bytes()
    }

    #[cfg(feature = "dangerous-key-export")]
    pub fn dangerously_clone_private_key_signer(&self) -> PrivateKeySigner {
        self.signer.clone()
    }

    #[cfg(feature = "local-signer-client")]
    #[doc(hidden)]
    pub fn clone_private_key_signer_for_local_client(&self) -> PrivateKeySigner {
        self.signer.clone()
    }

    pub fn sign_transaction_request(
        &self,
        request: &FinalizedTransactionRequest,
    ) -> Result<Bytes, SignerError> {
        if request.chain_id == 0 {
            return Err(SignerError::InvalidChainId);
        }
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

#[cfg(feature = "local-mnemonic")]
impl std::fmt::Debug for LocalMnemonicSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalMnemonicSigner")
            .field("address", &self.address())
            .field("private_key", &"[redacted]")
            .finish()
    }
}

#[cfg(feature = "local-mnemonic")]
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

#[cfg(all(test, feature = "local-mnemonic"))]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address, bytes};

    fn sample_request(chain_id: u64) -> FinalizedTransactionRequest {
        FinalizedTransactionRequest {
            kind: privacy_pools_sdk_core::TransactionKind::Withdraw,
            chain_id,
            from: address!("1111111111111111111111111111111111111111"),
            to: address!("2222222222222222222222222222222222222222"),
            nonce: 7,
            gas_limit: 21_000,
            value: U256::ZERO,
            data: bytes!("1234"),
            gas_price: Some(1),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        }
    }

    #[test]
    fn malformed_mnemonic_returns_error() {
        let error = LocalMnemonicSigner::from_phrase_nth("not a bip39 mnemonic", 0).unwrap_err();
        assert!(matches!(error, SignerError::Local(_)));
    }

    #[test]
    fn transaction_chain_id_zero_is_rejected() {
        let signer = LocalMnemonicSigner::from_phrase_nth(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();

        let error = signer
            .sign_transaction_request(&sample_request(0))
            .expect_err("chain_id = 0 must fail closed");
        assert!(matches!(error, SignerError::InvalidChainId));
    }
}
