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
    #[error("event stream is not canonically ordered")]
    UnorderedEventStream,
}

pub fn checkpoint(
    events: &[PoolEvent],
    policy: RecoveryPolicy,
) -> Result<RecoveryCheckpoint, RecoveryError> {
    if events.is_empty() && policy.fail_closed {
        return Err(RecoveryError::EmptyEventStream);
    }

    if policy.fail_closed {
        validate_event_stream(events)?;
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

fn validate_event_stream(events: &[PoolEvent]) -> Result<(), RecoveryError> {
    for window in events.windows(2) {
        let previous = &window[0];
        let current = &window[1];
        let previous_cursor = (
            previous.block_number,
            previous.transaction_index,
            previous.log_index,
        );
        let current_cursor = (
            current.block_number,
            current.transaction_index,
            current.log_index,
        );

        if current_cursor < previous_cursor {
            return Err(RecoveryError::UnorderedEventStream);
        }

        if current_cursor == previous_cursor {
            return Err(RecoveryError::AmbiguousState);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address};

    fn event(block_number: u64, transaction_index: u64, log_index: u64) -> PoolEvent {
        PoolEvent {
            block_number,
            transaction_index,
            log_index,
            pool_address: address!("1111111111111111111111111111111111111111"),
            commitment_hash: U256::from(block_number + transaction_index + log_index),
        }
    }

    #[test]
    fn checkpoints_sorted_event_streams() {
        let checkpoint = checkpoint(
            &[event(10, 0, 1), event(12, 0, 0), event(12, 1, 0)],
            RecoveryPolicy::default(),
        )
        .unwrap();

        assert_eq!(checkpoint.latest_block, 12);
        assert_eq!(checkpoint.commitments_seen, 3);
    }

    #[test]
    fn rejects_unsorted_event_streams_when_fail_closed() {
        assert!(matches!(
            checkpoint(
                &[event(12, 0, 0), event(10, 0, 1)],
                RecoveryPolicy::default()
            ),
            Err(RecoveryError::UnorderedEventStream)
        ));
    }

    #[test]
    fn rejects_duplicate_event_cursors_when_fail_closed() {
        assert!(matches!(
            checkpoint(
                &[event(12, 0, 0), event(12, 0, 0)],
                RecoveryPolicy::default()
            ),
            Err(RecoveryError::AmbiguousState)
        ));
    }
}
