use alloy_primitives::{Address, B256, U256};
use privacy_pools_sdk_core::{FieldElement, MasterKeys, Nullifier, Scope, Secret};
use privacy_pools_sdk_crypto::{
    CryptoError, build_commitment, generate_deposit_secrets, generate_legacy_master_keys,
    generate_master_keys, generate_withdrawal_secrets, hash_nullifier, hash_precommitment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CONSECUTIVE_DEPOSIT_MISSES: u64 = 10;

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

impl RecoveryPolicy {
    pub fn strict() -> Self {
        Self {
            compatibility_mode: CompatibilityMode::Strict,
            fail_closed: true,
        }
    }

    pub fn ts_compatible() -> Self {
        Self {
            compatibility_mode: CompatibilityMode::Legacy,
            fail_closed: true,
        }
    }
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self::ts_compatible()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    pub commitment_hash: FieldElement,
    pub label: FieldElement,
    pub value: FieldElement,
    pub precommitment_hash: FieldElement,
    pub block_number: u64,
    pub transaction_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalEvent {
    pub withdrawn_value: FieldElement,
    pub spent_nullifier_hash: FieldElement,
    pub new_commitment_hash: FieldElement,
    pub block_number: u64,
    pub transaction_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RagequitEvent {
    pub commitment_hash: FieldElement,
    pub label: FieldElement,
    pub value: FieldElement,
    pub block_number: u64,
    pub transaction_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolRecoveryInput {
    pub scope: Scope,
    pub deposit_events: Vec<DepositEvent>,
    pub withdrawal_events: Vec<WithdrawalEvent>,
    pub ragequit_events: Vec<RagequitEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKeyset {
    pub safe: MasterKeys,
    pub legacy: Option<MasterKeys>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCommitment {
    pub hash: FieldElement,
    pub value: FieldElement,
    pub label: FieldElement,
    pub nullifier: Nullifier,
    pub secret: Secret,
    pub block_number: u64,
    pub transaction_hash: B256,
    pub is_migration: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPoolAccount {
    pub label: FieldElement,
    pub deposit: RecoveredCommitment,
    pub children: Vec<RecoveredCommitment>,
    pub ragequit: Option<RagequitEvent>,
    pub is_migrated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredScope {
    pub scope: Scope,
    pub accounts: Vec<RecoveredPoolAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredAccountState {
    pub safe_master_keys: MasterKeys,
    pub legacy_master_keys: Option<MasterKeys>,
    pub safe_scopes: Vec<RecoveredScope>,
    pub legacy_scopes: Vec<RecoveredScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendableScope {
    pub scope: Scope,
    pub commitments: Vec<RecoveredCommitment>,
}

impl RecoveredPoolAccount {
    pub fn current_commitment(&self) -> &RecoveredCommitment {
        self.children.last().unwrap_or(&self.deposit)
    }

    pub fn is_spendable(&self) -> bool {
        !self.is_migrated && self.ragequit.is_none() && !self.current_commitment().value.is_zero()
    }
}

impl RecoveredScope {
    pub fn spendable_commitments(&self) -> Vec<RecoveredCommitment> {
        self.accounts
            .iter()
            .filter(|account| account.is_spendable())
            .map(|account| account.current_commitment().clone())
            .collect()
    }
}

impl RecoveredAccountState {
    pub fn safe_spendable_commitments(&self) -> Vec<SpendableScope> {
        scopes_to_spendable_commitments(&self.safe_scopes)
    }

    pub fn legacy_spendable_commitments(&self) -> Vec<SpendableScope> {
        scopes_to_spendable_commitments(&self.legacy_scopes)
    }
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("ambiguous recovery state detected")]
    AmbiguousState,
    #[error("event stream is empty")]
    EmptyEventStream,
    #[error("event stream is not canonically ordered")]
    UnorderedEventStream,
    #[error("duplicate pool scope in recovery input: {scope}")]
    DuplicateScope { scope: Scope },
    #[error(
        "duplicate withdrawal event for scope {scope} and spent nullifier {spent_nullifier_hash}"
    )]
    DuplicateWithdrawalEvent {
        scope: Scope,
        spent_nullifier_hash: FieldElement,
    },
    #[error("duplicate ragequit event for scope {scope} and label {label}")]
    DuplicateRagequitEvent { scope: Scope, label: FieldElement },
    #[error("deposit commitment mismatch for scope {scope}: expected {expected}, got {actual}")]
    DepositCommitmentMismatch {
        scope: String,
        expected: String,
        actual: String,
    },
    #[error(
        "withdrawal amount {withdrawn_value} exceeds current commitment value {current_value} for spent nullifier {spent_nullifier_hash} in scope {scope}"
    )]
    WithdrawalAmountExceedsCommitment {
        scope: String,
        spent_nullifier_hash: String,
        withdrawn_value: String,
        current_value: String,
    },
    #[error("recovery keyset is missing legacy keys for legacy compatibility mode")]
    MissingLegacyKeys,
    #[error("failed to locate parent commitment {parent_hash} in scope {scope}")]
    MissingParentCommitment {
        scope: Scope,
        parent_hash: FieldElement,
    },
    #[error(transparent)]
    Crypto(#[from] CryptoError),
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

pub fn derive_recovery_keyset(
    mnemonic: &str,
    policy: RecoveryPolicy,
) -> Result<RecoveryKeyset, RecoveryError> {
    let safe = generate_master_keys(mnemonic)?;
    let legacy = match policy.compatibility_mode {
        CompatibilityMode::Strict => None,
        CompatibilityMode::Legacy => Some(generate_legacy_master_keys(mnemonic)?),
    };

    Ok(RecoveryKeyset { safe, legacy })
}

pub fn recover_account_state(
    mnemonic: &str,
    pools: &[PoolRecoveryInput],
    policy: RecoveryPolicy,
) -> Result<RecoveredAccountState, RecoveryError> {
    let keyset = derive_recovery_keyset(mnemonic, policy.clone())?;
    recover_account_state_with_keyset(&keyset, pools, policy)
}

pub fn recover_account_state_with_keyset(
    keyset: &RecoveryKeyset,
    pools: &[PoolRecoveryInput],
    policy: RecoveryPolicy,
) -> Result<RecoveredAccountState, RecoveryError> {
    validate_pool_inputs(pools)?;

    let mut safe_book = RecoveryBook::default();
    let mut legacy_book = RecoveryBook::default();

    for pool in pools {
        let deposits = normalize_deposit_events(&pool.deposit_events)?;
        let withdrawals = normalize_withdrawal_events(&pool.withdrawal_events)?;
        let ragequits = normalize_ragequit_events(&pool.ragequit_events)?;

        if policy.compatibility_mode == CompatibilityMode::Legacy
            && let Some(legacy_keys) = keyset.legacy.as_ref()
        {
            process_deposit_events(&mut legacy_book, legacy_keys, pool.scope, &deposits, 0)?;
            process_withdrawal_events(&mut legacy_book, legacy_keys, pool.scope, &withdrawals)?;
            discover_migrated_commitments(
                &mut safe_book,
                &keyset.safe,
                pool.scope,
                legacy_book.accounts(pool.scope).unwrap_or(&[]),
                &withdrawals,
            )?;

            let safe_start_index = safe_book
                .accounts(pool.scope)
                .map(|accounts| accounts.len())
                .unwrap_or(0);
            process_deposit_events(
                &mut safe_book,
                &keyset.safe,
                pool.scope,
                &deposits,
                safe_start_index as u64,
            )?;
            process_withdrawal_events(&mut safe_book, &keyset.safe, pool.scope, &withdrawals)?;

            process_ragequit_events(&mut legacy_book, pool.scope, &ragequits)?;
            process_ragequit_events(&mut safe_book, pool.scope, &ragequits)?;
        } else {
            process_deposit_events(&mut safe_book, &keyset.safe, pool.scope, &deposits, 0)?;
            process_withdrawal_events(&mut safe_book, &keyset.safe, pool.scope, &withdrawals)?;
            process_ragequit_events(&mut safe_book, pool.scope, &ragequits)?;
        }
    }

    Ok(RecoveredAccountState {
        safe_master_keys: keyset.safe.clone(),
        legacy_master_keys: keyset.legacy.clone(),
        safe_scopes: safe_book.into_scopes(),
        legacy_scopes: legacy_book.into_scopes(),
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

fn scopes_to_spendable_commitments(scopes: &[RecoveredScope]) -> Vec<SpendableScope> {
    scopes
        .iter()
        .filter_map(|scope| {
            let commitments = scope.spendable_commitments();
            (!commitments.is_empty()).then_some(SpendableScope {
                scope: scope.scope,
                commitments,
            })
        })
        .collect()
}

fn validate_pool_inputs(pools: &[PoolRecoveryInput]) -> Result<(), RecoveryError> {
    let mut scopes = Vec::with_capacity(pools.len());
    for pool in pools {
        if scopes.contains(&pool.scope) {
            return Err(RecoveryError::DuplicateScope { scope: pool.scope });
        }
        scopes.push(pool.scope);
    }
    Ok(())
}

fn normalize_deposit_events(events: &[DepositEvent]) -> Result<Vec<DepositEvent>, RecoveryError> {
    let mut normalized: Vec<DepositEvent> = Vec::new();
    for event in events {
        if let Some(existing) = normalized
            .iter_mut()
            .find(|candidate| candidate.precommitment_hash == event.precommitment_hash)
        {
            // Match the shipped TS SDK's deposit canonicalization:
            // keep the earliest block for a precommitment and otherwise retain
            // the first event we saw for that block.
            if existing == event {
                continue;
            }

            if event.block_number < existing.block_number {
                *existing = event.clone();
            }

            continue;
        }

        normalized.push(event.clone());
    }

    Ok(normalized)
}

fn normalize_withdrawal_events(
    events: &[WithdrawalEvent],
) -> Result<Vec<WithdrawalEvent>, RecoveryError> {
    let mut normalized: Vec<WithdrawalEvent> = Vec::new();
    for event in events {
        if let Some(existing) = normalized
            .iter_mut()
            .find(|candidate| candidate.spent_nullifier_hash == event.spent_nullifier_hash)
        {
            *existing = event.clone();
            continue;
        }

        normalized.push(event.clone());
    }

    Ok(normalized)
}

fn normalize_ragequit_events(
    events: &[RagequitEvent],
) -> Result<Vec<RagequitEvent>, RecoveryError> {
    let mut normalized: Vec<RagequitEvent> = Vec::new();
    for event in events {
        if let Some(existing) = normalized
            .iter_mut()
            .find(|candidate| candidate.label == event.label)
        {
            *existing = event.clone();
            continue;
        }

        normalized.push(event.clone());
    }

    Ok(normalized)
}

fn process_deposit_events(
    book: &mut RecoveryBook,
    keys: &MasterKeys,
    scope: Scope,
    deposit_events: &[DepositEvent],
    start_index: u64,
) -> Result<(), RecoveryError> {
    let mut index = start_index;
    let mut consecutive_misses = 0_u64;

    while consecutive_misses < MAX_CONSECUTIVE_DEPOSIT_MISSES {
        let (nullifier, secret) = generate_deposit_secrets(keys, scope, U256::from(index))?;
        let precommitment_hash = hash_precommitment(&nullifier, secret.clone())?;

        if let Some(event) = deposit_events
            .iter()
            .find(|candidate| candidate.precommitment_hash == precommitment_hash)
        {
            consecutive_misses = 0;
            book.add_pool_account(
                scope,
                AccountInsertion {
                    value: event.value,
                    nullifier,
                    secret,
                    label: event.label,
                    block_number: event.block_number,
                    transaction_hash: event.transaction_hash,
                    is_migrated: false,
                    expected_hash: Some(event.commitment_hash),
                },
            )?;
        } else {
            consecutive_misses += 1;
        }

        index += 1;
    }

    Ok(())
}

fn process_withdrawal_events(
    book: &mut RecoveryBook,
    keys: &MasterKeys,
    scope: Scope,
    withdrawal_events: &[WithdrawalEvent],
) -> Result<(), RecoveryError> {
    let account_count = book
        .accounts(scope)
        .map(|accounts| accounts.len())
        .unwrap_or(0);
    for account_index in 0..account_count {
        let mut current_commitment = book.current_commitment(scope, account_index)?;
        let label = book.accounts(scope).expect("count checked above")[account_index].label;
        let mut child_index = book.accounts(scope).expect("count checked above")[account_index]
            .children
            .len() as u64;

        loop {
            let spent_nullifier_hash = hash_nullifier(&current_commitment.nullifier)?;
            let Some(withdrawal) = withdrawal_events
                .iter()
                .find(|candidate| candidate.spent_nullifier_hash == spent_nullifier_hash)
            else {
                break;
            };

            if withdrawal.withdrawn_value > current_commitment.value {
                return Err(RecoveryError::WithdrawalAmountExceedsCommitment {
                    scope: scope.to_string(),
                    spent_nullifier_hash: spent_nullifier_hash.to_string(),
                    withdrawn_value: withdrawal.withdrawn_value.to_string(),
                    current_value: current_commitment.value.to_string(),
                });
            }

            let remaining_value = current_commitment.value - withdrawal.withdrawn_value;
            let (nullifier, secret) =
                generate_withdrawal_secrets(keys, label, U256::from(child_index))?;
            let computed_commitment =
                build_commitment(remaining_value, label, &nullifier, secret.clone())?;
            let is_migration = computed_commitment.hash != withdrawal.new_commitment_hash;

            let next_commitment = book.add_child_commitment(
                scope,
                ChildInsertion {
                    parent_hash: current_commitment.hash,
                    value: remaining_value,
                    label,
                    nullifier,
                    secret,
                    block_number: withdrawal.block_number,
                    transaction_hash: withdrawal.transaction_hash,
                    is_migration,
                },
            )?;
            current_commitment = next_commitment;
            child_index += 1;
        }
    }

    Ok(())
}

fn discover_migrated_commitments(
    safe_book: &mut RecoveryBook,
    safe_keys: &MasterKeys,
    scope: Scope,
    legacy_accounts: &[RecoveredPoolAccount],
    withdrawal_events: &[WithdrawalEvent],
) -> Result<(), RecoveryError> {
    for legacy_account in legacy_accounts {
        if !legacy_account.is_migrated {
            continue;
        }

        let Some(migration_child) = legacy_account
            .children
            .iter()
            .find(|commitment| commitment.is_migration)
        else {
            continue;
        };

        let (nullifier, secret) =
            generate_withdrawal_secrets(safe_keys, legacy_account.label, U256::ZERO)?;
        let safe_commitment = build_commitment(
            migration_child.value,
            legacy_account.label,
            &nullifier,
            secret.clone(),
        )?;
        let Some(withdrawal_event) = withdrawal_events
            .iter()
            .find(|event| event.new_commitment_hash == safe_commitment.hash)
        else {
            continue;
        };

        let new_account = safe_book.add_pool_account(
            scope,
            AccountInsertion {
                value: migration_child.value,
                nullifier: nullifier.clone(),
                secret: secret.clone(),
                label: legacy_account.label,
                block_number: withdrawal_event.block_number,
                transaction_hash: withdrawal_event.transaction_hash,
                is_migrated: false,
                expected_hash: Some(withdrawal_event.new_commitment_hash),
            },
        )?;
        let _ = safe_book.add_child_commitment(
            scope,
            ChildInsertion {
                parent_hash: new_account.deposit.hash,
                value: migration_child.value,
                label: legacy_account.label,
                nullifier,
                secret,
                block_number: withdrawal_event.block_number,
                transaction_hash: withdrawal_event.transaction_hash,
                is_migration: false,
            },
        )?;
    }

    Ok(())
}

fn process_ragequit_events(
    book: &mut RecoveryBook,
    scope: Scope,
    ragequit_events: &[RagequitEvent],
) -> Result<(), RecoveryError> {
    for event in ragequit_events {
        let _ = book.attach_ragequit(scope, event.label, event.clone());
    }
    Ok(())
}

#[derive(Debug, Default, Clone)]
struct RecoveryBook {
    scopes: Vec<RecoveredScope>,
}

#[derive(Debug, Clone)]
struct AccountInsertion {
    value: FieldElement,
    nullifier: Nullifier,
    secret: Secret,
    label: FieldElement,
    block_number: u64,
    transaction_hash: B256,
    is_migrated: bool,
    expected_hash: Option<FieldElement>,
}

#[derive(Debug, Clone)]
struct ChildInsertion {
    parent_hash: FieldElement,
    value: FieldElement,
    label: FieldElement,
    nullifier: Nullifier,
    secret: Secret,
    block_number: u64,
    transaction_hash: B256,
    is_migration: bool,
}

impl RecoveryBook {
    fn accounts(&self, scope: Scope) -> Option<&[RecoveredPoolAccount]> {
        self.scopes
            .iter()
            .find(|entry| entry.scope == scope)
            .map(|entry| entry.accounts.as_slice())
    }

    fn accounts_mut(&mut self, scope: Scope) -> &mut Vec<RecoveredPoolAccount> {
        if let Some(index) = self.scopes.iter().position(|entry| entry.scope == scope) {
            return &mut self.scopes[index].accounts;
        }

        self.scopes.push(RecoveredScope {
            scope,
            accounts: Vec::new(),
        });
        &mut self.scopes.last_mut().expect("just pushed").accounts
    }

    fn add_pool_account(
        &mut self,
        scope: Scope,
        insertion: AccountInsertion,
    ) -> Result<RecoveredPoolAccount, RecoveryError> {
        let commitment = build_commitment(
            insertion.value,
            insertion.label,
            insertion.nullifier.clone(),
            insertion.secret.clone(),
        )?;
        if let Some(expected_hash) = insertion.expected_hash
            && commitment.hash != expected_hash
        {
            return Err(RecoveryError::DepositCommitmentMismatch {
                scope: scope.to_string(),
                expected: expected_hash.to_string(),
                actual: commitment.hash.to_string(),
            });
        }

        let account = RecoveredPoolAccount {
            label: insertion.label,
            deposit: RecoveredCommitment {
                hash: commitment.hash,
                value: insertion.value,
                label: insertion.label,
                nullifier: insertion.nullifier,
                secret: insertion.secret,
                block_number: insertion.block_number,
                transaction_hash: insertion.transaction_hash,
                is_migration: false,
            },
            children: Vec::new(),
            ragequit: None,
            is_migrated: insertion.is_migrated,
        };

        self.accounts_mut(scope).push(account.clone());
        Ok(account)
    }

    fn add_child_commitment(
        &mut self,
        scope: Scope,
        insertion: ChildInsertion,
    ) -> Result<RecoveredCommitment, RecoveryError> {
        let commitment = build_commitment(
            insertion.value,
            insertion.label,
            insertion.nullifier.clone(),
            insertion.secret.clone(),
        )?;
        let account = self
            .accounts_mut(scope)
            .iter_mut()
            .find(|account| {
                account.deposit.hash == insertion.parent_hash
                    || account
                        .children
                        .iter()
                        .any(|child| child.hash == insertion.parent_hash)
            })
            .ok_or(RecoveryError::MissingParentCommitment {
                scope,
                parent_hash: insertion.parent_hash,
            })?;

        let child = RecoveredCommitment {
            hash: commitment.hash,
            value: insertion.value,
            label: insertion.label,
            nullifier: insertion.nullifier,
            secret: insertion.secret,
            block_number: insertion.block_number,
            transaction_hash: insertion.transaction_hash,
            is_migration: insertion.is_migration,
        };
        if insertion.is_migration {
            account.is_migrated = true;
        }
        account.children.push(child.clone());
        Ok(child)
    }

    fn current_commitment(
        &self,
        scope: Scope,
        account_index: usize,
    ) -> Result<RecoveredCommitment, RecoveryError> {
        let account = self
            .accounts(scope)
            .and_then(|accounts| accounts.get(account_index))
            .ok_or(RecoveryError::MissingParentCommitment {
                scope,
                parent_hash: U256::ZERO,
            })?;
        Ok(account
            .children
            .last()
            .cloned()
            .unwrap_or_else(|| account.deposit.clone()))
    }

    fn attach_ragequit(
        &mut self,
        scope: Scope,
        label: FieldElement,
        ragequit: RagequitEvent,
    ) -> bool {
        let Some(account) = self
            .accounts_mut(scope)
            .iter_mut()
            .find(|account| account.label == label)
        else {
            return false;
        };
        account.ragequit = Some(ragequit);
        true
    }

    fn into_scopes(mut self) -> Vec<RecoveredScope> {
        self.scopes
            .sort_by(|left, right| left.scope.cmp(&right.scope));
        self.scopes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use std::str::FromStr;

    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    fn tx_hash(seed: u64) -> B256 {
        B256::from(U256::from(seed))
    }

    fn deposit_event(
        commitment_hash: FieldElement,
        label: FieldElement,
        value: FieldElement,
        precommitment_hash: FieldElement,
        block_number: u64,
        seed: u64,
    ) -> DepositEvent {
        DepositEvent {
            commitment_hash,
            label,
            value,
            precommitment_hash,
            block_number,
            transaction_hash: tx_hash(seed),
        }
    }

    fn withdrawal_event(
        withdrawn_value: FieldElement,
        spent_nullifier_hash: FieldElement,
        new_commitment_hash: FieldElement,
        block_number: u64,
        seed: u64,
    ) -> WithdrawalEvent {
        WithdrawalEvent {
            withdrawn_value,
            spent_nullifier_hash,
            new_commitment_hash,
            block_number,
            transaction_hash: tx_hash(seed),
        }
    }

    fn recovery_input(
        scope: Scope,
        deposit_events: Vec<DepositEvent>,
        withdrawal_events: Vec<WithdrawalEvent>,
    ) -> PoolRecoveryInput {
        PoolRecoveryInput {
            scope,
            deposit_events,
            withdrawal_events,
            ragequit_events: Vec::new(),
        }
    }

    fn derived_keyset(mnemonic: &str, include_legacy: bool) -> RecoveryKeyset {
        RecoveryKeyset {
            safe: generate_master_keys(mnemonic).unwrap(),
            legacy: include_legacy.then(|| generate_legacy_master_keys(mnemonic).unwrap()),
        }
    }

    #[test]
    fn checkpoints_sorted_event_streams() {
        let checkpoint = checkpoint(
            &[
                PoolEvent {
                    block_number: 10,
                    transaction_index: 0,
                    log_index: 1,
                    pool_address: address!("1111111111111111111111111111111111111111"),
                    commitment_hash: U256::from(11_u64),
                },
                PoolEvent {
                    block_number: 12,
                    transaction_index: 0,
                    log_index: 0,
                    pool_address: address!("1111111111111111111111111111111111111111"),
                    commitment_hash: U256::from(12_u64),
                },
            ],
            RecoveryPolicy::default(),
        )
        .unwrap();

        assert_eq!(checkpoint.latest_block, 12);
        assert_eq!(checkpoint.commitments_seen, 2);
    }

    #[test]
    fn rejects_unsorted_event_streams_when_fail_closed() {
        assert!(matches!(
            checkpoint(
                &[
                    PoolEvent {
                        block_number: 12,
                        transaction_index: 0,
                        log_index: 0,
                        pool_address: address!("1111111111111111111111111111111111111111"),
                        commitment_hash: U256::from(12_u64),
                    },
                    PoolEvent {
                        block_number: 10,
                        transaction_index: 0,
                        log_index: 1,
                        pool_address: address!("1111111111111111111111111111111111111111"),
                        commitment_hash: U256::from(11_u64),
                    },
                ],
                RecoveryPolicy::default()
            ),
            Err(RecoveryError::UnorderedEventStream)
        ));
    }

    #[test]
    fn rejects_duplicate_event_cursors_when_fail_closed() {
        assert!(matches!(
            checkpoint(
                &[
                    PoolEvent {
                        block_number: 12,
                        transaction_index: 0,
                        log_index: 0,
                        pool_address: address!("1111111111111111111111111111111111111111"),
                        commitment_hash: U256::from(12_u64),
                    },
                    PoolEvent {
                        block_number: 12,
                        transaction_index: 0,
                        log_index: 0,
                        pool_address: address!("1111111111111111111111111111111111111111"),
                        commitment_hash: U256::from(12_u64),
                    },
                ],
                RecoveryPolicy::default()
            ),
            Err(RecoveryError::AmbiguousState)
        ));
    }

    #[test]
    fn reconstructs_safe_deposit_and_withdrawal_chain() {
        let keyset = derived_keyset(TEST_MNEMONIC, false);
        let scope = U256::from(123_u64);
        let label = U256::from(777_u64);
        let deposit_value = U256::from(1_000_u64);

        let (deposit_nullifier, deposit_secret) =
            generate_deposit_secrets(&keyset.safe, scope, U256::ZERO).unwrap();
        let deposit =
            build_commitment(deposit_value, label, &deposit_nullifier, deposit_secret).unwrap();

        let (withdraw_nullifier, withdraw_secret) =
            generate_withdrawal_secrets(&keyset.safe, label, U256::ZERO).unwrap();
        let remaining_value = U256::from(600_u64);
        let withdrawal_child =
            build_commitment(remaining_value, label, withdraw_nullifier, withdraw_secret).unwrap();

        let recovered = recover_account_state_with_keyset(
            &keyset,
            &[recovery_input(
                scope,
                vec![deposit_event(
                    deposit.hash,
                    label,
                    deposit_value,
                    deposit.preimage.precommitment.hash,
                    10,
                    1,
                )],
                vec![withdrawal_event(
                    U256::from(400_u64),
                    hash_nullifier(&deposit_nullifier).unwrap(),
                    withdrawal_child.hash,
                    20,
                    2,
                )],
            )],
            RecoveryPolicy::default(),
        )
        .unwrap();

        assert!(recovered.legacy_scopes.is_empty());
        assert_eq!(recovered.safe_scopes.len(), 1);
        assert_eq!(recovered.safe_scopes[0].scope, scope);
        assert_eq!(recovered.safe_scopes[0].accounts.len(), 1);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].deposit.hash,
            deposit.hash
        );
        assert_eq!(recovered.safe_scopes[0].accounts[0].children.len(), 1);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].children[0].hash,
            withdrawal_child.hash
        );
        assert_eq!(recovered.safe_spendable_commitments().len(), 1);
        assert_eq!(
            recovered.safe_spendable_commitments()[0].commitments[0].hash,
            withdrawal_child.hash
        );
    }

    #[test]
    fn discovers_zero_value_migrations_from_legacy_replay() {
        let safe_keys = generate_master_keys(TEST_MNEMONIC).unwrap();
        let legacy_keys = generate_legacy_master_keys(TEST_MNEMONIC).unwrap();
        let keyset = RecoveryKeyset {
            safe: safe_keys.clone(),
            legacy: Some(legacy_keys.clone()),
        };
        let scope = U256::from(123_u64);
        let label = U256::from(888_u64);
        let deposit_value = U256::from(1_000_u64);

        let (legacy_nullifier, legacy_secret) =
            generate_deposit_secrets(&legacy_keys, scope, U256::ZERO).unwrap();
        let legacy_deposit =
            build_commitment(deposit_value, label, &legacy_nullifier, legacy_secret).unwrap();

        let (safe_nullifier, safe_secret) =
            generate_withdrawal_secrets(&safe_keys, label, U256::ZERO).unwrap();
        let migrated_commitment =
            build_commitment(deposit_value, label, safe_nullifier, safe_secret).unwrap();

        let recovered = recover_account_state_with_keyset(
            &keyset,
            &[recovery_input(
                scope,
                vec![deposit_event(
                    legacy_deposit.hash,
                    label,
                    deposit_value,
                    legacy_deposit.preimage.precommitment.hash,
                    10,
                    1,
                )],
                vec![withdrawal_event(
                    U256::ZERO,
                    hash_nullifier(&legacy_nullifier).unwrap(),
                    migrated_commitment.hash,
                    20,
                    2,
                )],
            )],
            RecoveryPolicy {
                compatibility_mode: CompatibilityMode::Legacy,
                fail_closed: true,
            },
        )
        .unwrap();

        assert_eq!(recovered.legacy_scopes.len(), 1);
        assert_eq!(recovered.safe_scopes.len(), 1);
        assert!(recovered.legacy_scopes[0].accounts[0].is_migrated);
        assert!(recovered.legacy_scopes[0].accounts[0].children[0].is_migration);
        assert_ne!(
            recovered.legacy_scopes[0].accounts[0].children[0].hash,
            migrated_commitment.hash
        );
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].deposit.hash,
            migrated_commitment.hash
        );
        assert_eq!(recovered.safe_scopes[0].accounts[0].children.len(), 1);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].children[0].hash,
            migrated_commitment.hash
        );
    }

    #[test]
    fn default_policy_reconstructs_migrated_funds_from_mnemonic() {
        let scope = U256::from(123_u64);
        let label = U256::from(888_u64);
        let deposit_value = U256::from(1_000_u64);
        let legacy_keys = generate_legacy_master_keys(TEST_MNEMONIC).unwrap();
        let safe_keys = generate_master_keys(TEST_MNEMONIC).unwrap();

        let (legacy_nullifier, legacy_secret) =
            generate_deposit_secrets(&legacy_keys, scope, U256::ZERO).unwrap();
        let legacy_deposit =
            build_commitment(deposit_value, label, &legacy_nullifier, legacy_secret).unwrap();

        let (safe_nullifier, safe_secret) =
            generate_withdrawal_secrets(&safe_keys, label, U256::ZERO).unwrap();
        let migrated_commitment =
            build_commitment(deposit_value, label, safe_nullifier, safe_secret).unwrap();

        let recovered = recover_account_state(
            TEST_MNEMONIC,
            &[recovery_input(
                scope,
                vec![deposit_event(
                    legacy_deposit.hash,
                    label,
                    deposit_value,
                    legacy_deposit.preimage.precommitment.hash,
                    10,
                    1,
                )],
                vec![withdrawal_event(
                    U256::ZERO,
                    hash_nullifier(&legacy_nullifier).unwrap(),
                    migrated_commitment.hash,
                    20,
                    2,
                )],
            )],
            RecoveryPolicy::default(),
        )
        .unwrap();

        assert_eq!(recovered.safe_scopes.len(), 1);
        assert_eq!(recovered.legacy_scopes.len(), 1);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].deposit.hash,
            migrated_commitment.hash
        );
        assert!(recovered.legacy_scopes[0].accounts[0].is_migrated);
    }

    #[test]
    fn starts_safe_deposit_scan_after_migrated_slots() {
        let safe_keys = generate_master_keys(TEST_MNEMONIC).unwrap();
        let legacy_keys = generate_legacy_master_keys(TEST_MNEMONIC).unwrap();
        let keyset = RecoveryKeyset {
            safe: safe_keys.clone(),
            legacy: Some(legacy_keys.clone()),
        };
        let scope = U256::from(321_u64);
        let label = U256::from(999_u64);
        let deposit_value = U256::from(1_000_u64);

        let (legacy_nullifier, legacy_secret) =
            generate_deposit_secrets(&legacy_keys, scope, U256::ZERO).unwrap();
        let legacy_deposit =
            build_commitment(deposit_value, label, &legacy_nullifier, legacy_secret).unwrap();

        let (safe_withdraw_nullifier, safe_withdraw_secret) =
            generate_withdrawal_secrets(&safe_keys, label, U256::ZERO).unwrap();
        let migrated_commitment = build_commitment(
            deposit_value,
            label,
            safe_withdraw_nullifier,
            safe_withdraw_secret,
        )
        .unwrap();

        let safe_label = U256::from(1_111_u64);
        let safe_value = U256::from(250_u64);
        let (safe_deposit_nullifier, safe_deposit_secret) =
            generate_deposit_secrets(&safe_keys, scope, U256::from(1_u64)).unwrap();
        let safe_deposit = build_commitment(
            safe_value,
            safe_label,
            safe_deposit_nullifier,
            safe_deposit_secret,
        )
        .unwrap();

        let recovered = recover_account_state_with_keyset(
            &keyset,
            &[recovery_input(
                scope,
                vec![
                    deposit_event(
                        legacy_deposit.hash,
                        label,
                        deposit_value,
                        legacy_deposit.preimage.precommitment.hash,
                        10,
                        1,
                    ),
                    deposit_event(
                        safe_deposit.hash,
                        safe_label,
                        safe_value,
                        safe_deposit.preimage.precommitment.hash,
                        30,
                        3,
                    ),
                ],
                vec![withdrawal_event(
                    U256::ZERO,
                    hash_nullifier(&legacy_nullifier).unwrap(),
                    migrated_commitment.hash,
                    20,
                    2,
                )],
            )],
            RecoveryPolicy {
                compatibility_mode: CompatibilityMode::Legacy,
                fail_closed: true,
            },
        )
        .unwrap();

        assert_eq!(recovered.safe_scopes[0].accounts.len(), 2);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].deposit.hash,
            migrated_commitment.hash
        );
        assert_eq!(
            recovered.safe_scopes[0].accounts[1].deposit.hash,
            safe_deposit.hash
        );
    }

    #[test]
    fn mirrors_ts_spendable_commitment_filtering() {
        let keyset = derived_keyset(TEST_MNEMONIC, true);
        let scope = U256::from(456_u64);
        let migrated_label = U256::from(100_u64);
        let active_label = U256::from(200_u64);
        let ragequit_label = U256::from(300_u64);

        let (legacy_nullifier, legacy_secret) =
            generate_deposit_secrets(keyset.legacy.as_ref().unwrap(), scope, U256::ZERO).unwrap();
        let migrated_legacy_deposit = build_commitment(
            U256::from(900_u64),
            migrated_label,
            &legacy_nullifier,
            legacy_secret,
        )
        .unwrap();
        let (safe_migration_nullifier, safe_migration_secret) =
            generate_withdrawal_secrets(&keyset.safe, migrated_label, U256::ZERO).unwrap();
        let migrated_safe_commitment = build_commitment(
            U256::from(900_u64),
            migrated_label,
            safe_migration_nullifier,
            safe_migration_secret,
        )
        .unwrap();

        let (active_nullifier, active_secret) =
            generate_deposit_secrets(&keyset.safe, scope, U256::from(1_u64)).unwrap();
        let active_deposit = build_commitment(
            U256::from(500_u64),
            active_label,
            active_nullifier,
            active_secret,
        )
        .unwrap();

        let (ragequit_nullifier, ragequit_secret) =
            generate_deposit_secrets(&keyset.safe, scope, U256::from(2_u64)).unwrap();
        let ragequit_deposit = build_commitment(
            U256::from(250_u64),
            ragequit_label,
            ragequit_nullifier,
            ragequit_secret,
        )
        .unwrap();

        let recovered = recover_account_state_with_keyset(
            &keyset,
            &[PoolRecoveryInput {
                scope,
                deposit_events: vec![
                    deposit_event(
                        migrated_legacy_deposit.hash,
                        migrated_label,
                        U256::from(900_u64),
                        migrated_legacy_deposit.preimage.precommitment.hash,
                        10,
                        1,
                    ),
                    deposit_event(
                        active_deposit.hash,
                        active_label,
                        U256::from(500_u64),
                        active_deposit.preimage.precommitment.hash,
                        30,
                        3,
                    ),
                    deposit_event(
                        ragequit_deposit.hash,
                        ragequit_label,
                        U256::from(250_u64),
                        ragequit_deposit.preimage.precommitment.hash,
                        40,
                        4,
                    ),
                ],
                withdrawal_events: vec![withdrawal_event(
                    U256::ZERO,
                    hash_nullifier(&legacy_nullifier).unwrap(),
                    migrated_safe_commitment.hash,
                    20,
                    2,
                )],
                ragequit_events: vec![RagequitEvent {
                    commitment_hash: ragequit_deposit.hash,
                    label: ragequit_label,
                    value: U256::from(250_u64),
                    block_number: 50,
                    transaction_hash: tx_hash(5),
                }],
            }],
            RecoveryPolicy {
                compatibility_mode: CompatibilityMode::Legacy,
                fail_closed: true,
            },
        )
        .unwrap();

        let safe_spendable = recovered.safe_spendable_commitments();
        assert_eq!(safe_spendable.len(), 1);
        assert_eq!(safe_spendable[0].scope, scope);
        assert_eq!(safe_spendable[0].commitments.len(), 2);
        assert_eq!(
            safe_spendable[0].commitments[0].hash,
            migrated_safe_commitment.hash
        );
        assert_eq!(safe_spendable[0].commitments[1].hash, active_deposit.hash);
        assert!(recovered.legacy_spendable_commitments().is_empty());
    }

    #[test]
    fn keeps_earliest_deposit_for_duplicate_precommitments() {
        let keyset = derived_keyset(TEST_MNEMONIC, false);
        let scope = U256::from(654_u64);
        let label = U256::from(321_u64);
        let value = U256::from(111_u64);
        let (nullifier, secret) =
            generate_deposit_secrets(&keyset.safe, scope, U256::ZERO).unwrap();
        let deposit = build_commitment(value, label, nullifier, secret).unwrap();

        let earlier = deposit_event(
            deposit.hash,
            label,
            value,
            deposit.preimage.precommitment.hash,
            10,
            1,
        );
        let later = deposit_event(
            deposit.hash,
            label,
            value,
            deposit.preimage.precommitment.hash,
            20,
            2,
        );

        let recovered = recover_account_state_with_keyset(
            &keyset,
            &[recovery_input(
                scope,
                vec![later.clone(), earlier.clone()],
                Vec::new(),
            )],
            RecoveryPolicy::default(),
        )
        .unwrap();

        assert_eq!(recovered.safe_scopes[0].accounts.len(), 1);
        assert_eq!(
            recovered.safe_scopes[0].accounts[0].deposit.block_number,
            earlier.block_number
        );
        assert_eq!(
            recovered.safe_scopes[0].accounts[0]
                .deposit
                .transaction_hash,
            earlier.transaction_hash
        );
    }

    #[test]
    fn rejects_duplicate_scope_inputs() {
        let keyset = derived_keyset(TEST_MNEMONIC, false);
        let scope = U256::from(123_u64);
        let input = recovery_input(scope, Vec::new(), Vec::new());

        assert!(matches!(
            recover_account_state_with_keyset(
                &keyset,
                &[input.clone(), input],
                RecoveryPolicy::default()
            ),
            Err(RecoveryError::DuplicateScope { scope: duplicate_scope })
                if duplicate_scope == scope
        ));
    }

    #[test]
    fn canonicalizes_duplicate_withdrawal_events_with_last_write_wins() {
        let keyset = derived_keyset(TEST_MNEMONIC, false);
        let scope = U256::from(123_u64);
        let label = U256::from(555_u64);
        let value = U256::from(500_u64);
        let (nullifier, secret) =
            generate_deposit_secrets(&keyset.safe, scope, U256::ZERO).unwrap();
        let deposit = build_commitment(value, label, nullifier, secret).unwrap();
        let spent = U256::from(77_u64);
        let earlier = withdrawal_event(U256::from(1_u64), spent, U256::from(2_u64), 1, 1);
        let later = withdrawal_event(U256::from(2_u64), spent, U256::from(3_u64), 2, 2);
        let input = PoolRecoveryInput {
            scope,
            deposit_events: vec![deposit_event(
                deposit.hash,
                label,
                value,
                deposit.preimage.precommitment.hash,
                0,
                0,
            )],
            withdrawal_events: vec![earlier.clone(), later.clone()],
            ragequit_events: Vec::new(),
        };

        let normalized = normalize_withdrawal_events(&input.withdrawal_events).unwrap();
        assert_eq!(normalized, vec![later]);
    }

    #[test]
    fn canonicalizes_duplicate_ragequit_events_with_last_write_wins() {
        let label = U256::from(77_u64);
        let earlier = RagequitEvent {
            commitment_hash: U256::from(1_u64),
            label,
            value: U256::from(2_u64),
            block_number: 1,
            transaction_hash: tx_hash(1),
        };
        let later = RagequitEvent {
            commitment_hash: U256::from(3_u64),
            label,
            value: U256::from(4_u64),
            block_number: 2,
            transaction_hash: tx_hash(2),
        };

        let normalized = normalize_ragequit_events(&[earlier, later.clone()]).unwrap();
        assert_eq!(normalized, vec![later]);
    }

    #[test]
    fn derive_recovery_keyset_supports_legacy_mode() {
        let keyset = derive_recovery_keyset(
            TEST_MNEMONIC,
            RecoveryPolicy {
                compatibility_mode: CompatibilityMode::Legacy,
                fail_closed: true,
            },
        )
        .unwrap();

        let legacy = keyset.legacy.unwrap();
        assert_ne!(keyset.safe.master_nullifier, legacy.master_nullifier);
        assert_ne!(keyset.safe.master_secret, legacy.master_secret);
        assert_eq!(
            legacy.master_nullifier.dangerously_expose_field(),
            U256::from_str(
                "16629217087516280053769625512741000936965671973118241282486996830438009025879"
            )
            .unwrap()
        );
        assert_eq!(
            legacy.master_secret.dangerously_expose_field(),
            U256::from_str(
                "9843793310547505184827673578253843418217689387365691544946232242162772441433"
            )
            .unwrap()
        );
    }
}
