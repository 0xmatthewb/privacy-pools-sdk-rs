use alloy_primitives::Address;
use privacy_pools_sdk_core::FieldElement;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatibilityMode {
    Strict,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub compatibility_mode: CompatibilityMode,
    pub fail_closed: bool,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            compatibility_mode: CompatibilityMode::Strict,
            fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolEvent {
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
    pub pool_address: Address,
    pub commitment_hash: FieldElement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCheckpoint {
    pub latest_block: u64,
    pub commitments_seen: usize,
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("ambiguous recovery state detected")]
    AmbiguousState,
    #[error("event stream is empty")]
    EmptyEventStream,
}

pub fn checkpoint(
    events: &[PoolEvent],
    policy: RecoveryPolicy,
) -> Result<RecoveryCheckpoint, RecoveryError> {
    if events.is_empty() && policy.fail_closed {
        return Err(RecoveryError::EmptyEventStream);
    }

    let latest_block = events
        .iter()
        .map(|event| event.block_number)
        .max()
        .unwrap_or_default();
    Ok(RecoveryCheckpoint {
        latest_block,
        commitments_seen: events.len(),
    })
}
