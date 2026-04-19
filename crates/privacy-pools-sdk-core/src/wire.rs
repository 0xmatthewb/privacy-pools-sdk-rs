use crate::{
    CircuitMerkleWitness, Commitment, CommitmentCircuitInput, CommitmentPreimage,
    CommitmentWitnessRequest, CoreError, FieldElement, MasterKeys, Nullifier, Precommitment,
    Secret, Withdrawal, WithdrawalCircuitInput, WithdrawalWitnessRequest, field_to_decimal,
    parse_decimal_field,
};
use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireMasterKeys {
    #[serde(alias = "master_nullifier")]
    pub master_nullifier: String,
    #[serde(alias = "master_secret")]
    pub master_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireCommitment {
    pub hash: String,
    #[serde(default, alias = "nullifier_hash")]
    pub nullifier_hash: String,
    #[serde(default, alias = "precommitment_hash")]
    pub precommitment_hash: String,
    pub value: String,
    pub label: String,
    pub nullifier: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireWithdrawal {
    pub processooor: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireCircuitMerkleWitness {
    pub root: String,
    pub leaf: String,
    pub index: usize,
    pub siblings: Vec<String>,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireCommitmentWitnessRequest {
    pub commitment: WireCommitment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireWithdrawalWitnessRequest {
    pub commitment: WireCommitment,
    pub withdrawal: WireWithdrawal,
    pub scope: String,
    pub withdrawal_amount: String,
    pub state_witness: WireCircuitMerkleWitness,
    pub asp_witness: WireCircuitMerkleWitness,
    pub new_nullifier: String,
    pub new_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCommitmentCircuitInput {
    pub value: String,
    pub label: String,
    pub nullifier: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireWithdrawalCircuitInput {
    #[serde(rename = "withdrawnValue", alias = "withdrawn_value")]
    pub withdrawn_value: String,
    #[serde(rename = "stateRoot", alias = "state_root")]
    pub state_root: String,
    #[serde(rename = "stateTreeDepth", alias = "state_tree_depth")]
    pub state_tree_depth: usize,
    #[serde(rename = "aspRoot", alias = "ASPRoot", alias = "asp_root")]
    pub asp_root: String,
    #[serde(
        rename = "aspTreeDepth",
        alias = "ASPTreeDepth",
        alias = "asp_tree_depth"
    )]
    pub asp_tree_depth: usize,
    pub context: String,
    pub label: String,
    #[serde(rename = "existingValue", alias = "existing_value")]
    pub existing_value: String,
    #[serde(rename = "existingNullifier", alias = "existing_nullifier")]
    pub existing_nullifier: String,
    #[serde(rename = "existingSecret", alias = "existing_secret")]
    pub existing_secret: String,
    #[serde(rename = "newNullifier", alias = "new_nullifier")]
    pub new_nullifier: String,
    #[serde(rename = "newSecret", alias = "new_secret")]
    pub new_secret: String,
    #[serde(rename = "stateSiblings", alias = "state_siblings")]
    pub state_siblings: Vec<String>,
    #[serde(rename = "stateIndex", alias = "state_index")]
    pub state_index: usize,
    #[serde(rename = "ASPSiblings", alias = "aspSiblings", alias = "asp_siblings")]
    pub asp_siblings: Vec<String>,
    #[serde(rename = "ASPIndex", alias = "aspIndex", alias = "asp_index")]
    pub asp_index: usize,
}

impl TryFrom<WireMasterKeys> for MasterKeys {
    type Error = CoreError;

    fn try_from(value: WireMasterKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            master_nullifier: parse_secret(&value.master_nullifier)?,
            master_secret: parse_secret(&value.master_secret)?,
        })
    }
}

impl From<&MasterKeys> for WireMasterKeys {
    fn from(value: &MasterKeys) -> Self {
        Self {
            master_nullifier: value.master_nullifier.to_decimal_string(),
            master_secret: value.master_secret.to_decimal_string(),
        }
    }
}

impl TryFrom<WireCommitment> for Commitment {
    type Error = CoreError;

    fn try_from(value: WireCommitment) -> Result<Self, Self::Error> {
        let precommitment_hash_label = if value.precommitment_hash.is_empty() {
            &value.nullifier_hash
        } else {
            &value.precommitment_hash
        };
        let compatibility_hash_label = if value.nullifier_hash.is_empty() {
            precommitment_hash_label
        } else {
            &value.nullifier_hash
        };

        let precommitment_hash = parse_decimal_field(precommitment_hash_label)?;
        let compatibility_hash = parse_decimal_field(compatibility_hash_label)?;
        if compatibility_hash != precommitment_hash {
            return Err(CoreError::MismatchedCommitmentCompatibilityHash);
        }

        Ok(Self {
            hash: parse_decimal_field(&value.hash)?,
            precommitment_hash,
            preimage: CommitmentPreimage {
                value: parse_decimal_field(&value.value)?,
                label: parse_decimal_field(&value.label)?,
                precommitment: Precommitment {
                    hash: precommitment_hash,
                    nullifier: parse_nullifier(&value.nullifier)?,
                    secret: parse_secret(&value.secret)?,
                },
            },
        })
    }
}

impl From<&Commitment> for WireCommitment {
    fn from(value: &Commitment) -> Self {
        Self {
            hash: field_to_decimal(value.hash),
            nullifier_hash: field_to_decimal(value.precommitment_hash),
            precommitment_hash: field_to_decimal(value.precommitment_hash),
            value: field_to_decimal(value.preimage.value),
            label: field_to_decimal(value.preimage.label),
            nullifier: value.preimage.precommitment.nullifier.to_decimal_string(),
            secret: value.preimage.precommitment.secret.to_decimal_string(),
        }
    }
}

impl TryFrom<WireWithdrawal> for Withdrawal {
    type Error = CoreError;

    fn try_from(value: WireWithdrawal) -> Result<Self, Self::Error> {
        let data = hex::decode(value.data.trim_start_matches("0x"))
            .map_err(|_| CoreError::InvalidHexBytes(value.data))?;
        Ok(Self {
            processor: parse_address(&value.processooor)?,
            data: Bytes::from(data),
        })
    }
}

impl From<&Withdrawal> for WireWithdrawal {
    fn from(value: &Withdrawal) -> Self {
        Self {
            processooor: value.processor.to_string(),
            data: format!("0x{}", hex::encode(&value.data)),
        }
    }
}

impl TryFrom<WireCircuitMerkleWitness> for CircuitMerkleWitness {
    type Error = CoreError;

    fn try_from(value: WireCircuitMerkleWitness) -> Result<Self, Self::Error> {
        Ok(Self {
            root: parse_decimal_field(&value.root)?,
            leaf: parse_decimal_field(&value.leaf)?,
            index: value.index,
            siblings: parse_fields(value.siblings)?,
            depth: value.depth,
        })
    }
}

impl From<&CircuitMerkleWitness> for WireCircuitMerkleWitness {
    fn from(value: &CircuitMerkleWitness) -> Self {
        Self {
            root: field_to_decimal(value.root),
            leaf: field_to_decimal(value.leaf),
            index: value.index,
            siblings: value
                .siblings
                .iter()
                .copied()
                .map(field_to_decimal)
                .collect(),
            depth: value.depth,
        }
    }
}

impl TryFrom<WireCommitmentWitnessRequest> for CommitmentWitnessRequest {
    type Error = CoreError;

    fn try_from(value: WireCommitmentWitnessRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: value.commitment.try_into()?,
        })
    }
}

impl From<&CommitmentWitnessRequest> for WireCommitmentWitnessRequest {
    fn from(value: &CommitmentWitnessRequest) -> Self {
        Self {
            commitment: WireCommitment::from(&value.commitment),
        }
    }
}

impl TryFrom<WireWithdrawalWitnessRequest> for WithdrawalWitnessRequest {
    type Error = CoreError;

    fn try_from(value: WireWithdrawalWitnessRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: value.commitment.try_into()?,
            withdrawal: value.withdrawal.try_into()?,
            scope: parse_decimal_field(&value.scope)?,
            withdrawal_amount: parse_decimal_field(&value.withdrawal_amount)?,
            state_witness: value.state_witness.try_into()?,
            asp_witness: value.asp_witness.try_into()?,
            new_nullifier: parse_nullifier(&value.new_nullifier)?,
            new_secret: parse_secret(&value.new_secret)?,
        })
    }
}

impl From<&WithdrawalWitnessRequest> for WireWithdrawalWitnessRequest {
    fn from(value: &WithdrawalWitnessRequest) -> Self {
        Self {
            commitment: WireCommitment::from(&value.commitment),
            withdrawal: WireWithdrawal::from(&value.withdrawal),
            scope: field_to_decimal(value.scope),
            withdrawal_amount: field_to_decimal(value.withdrawal_amount),
            state_witness: WireCircuitMerkleWitness::from(&value.state_witness),
            asp_witness: WireCircuitMerkleWitness::from(&value.asp_witness),
            new_nullifier: value.new_nullifier.to_decimal_string(),
            new_secret: value.new_secret.to_decimal_string(),
        }
    }
}

impl TryFrom<WireCommitmentCircuitInput> for CommitmentCircuitInput {
    type Error = CoreError;

    fn try_from(value: WireCommitmentCircuitInput) -> Result<Self, Self::Error> {
        Ok(Self {
            value: parse_decimal_field(&value.value)?,
            label: parse_decimal_field(&value.label)?,
            nullifier: parse_nullifier(&value.nullifier)?,
            secret: parse_secret(&value.secret)?,
        })
    }
}

impl From<&CommitmentCircuitInput> for WireCommitmentCircuitInput {
    fn from(value: &CommitmentCircuitInput) -> Self {
        Self {
            value: field_to_decimal(value.value),
            label: field_to_decimal(value.label),
            nullifier: value.nullifier.to_decimal_string(),
            secret: value.secret.to_decimal_string(),
        }
    }
}

impl TryFrom<WireWithdrawalCircuitInput> for WithdrawalCircuitInput {
    type Error = CoreError;

    fn try_from(value: WireWithdrawalCircuitInput) -> Result<Self, Self::Error> {
        Ok(Self {
            withdrawn_value: parse_decimal_field(&value.withdrawn_value)?,
            state_root: parse_decimal_field(&value.state_root)?,
            state_tree_depth: value.state_tree_depth,
            asp_root: parse_decimal_field(&value.asp_root)?,
            asp_tree_depth: value.asp_tree_depth,
            context: parse_decimal_field(&value.context)?,
            label: parse_decimal_field(&value.label)?,
            existing_value: parse_decimal_field(&value.existing_value)?,
            existing_nullifier: parse_nullifier(&value.existing_nullifier)?,
            existing_secret: parse_secret(&value.existing_secret)?,
            new_nullifier: parse_nullifier(&value.new_nullifier)?,
            new_secret: parse_secret(&value.new_secret)?,
            state_siblings: parse_fields(value.state_siblings)?,
            state_index: value.state_index,
            asp_siblings: parse_fields(value.asp_siblings)?,
            asp_index: value.asp_index,
        })
    }
}

impl From<&WithdrawalCircuitInput> for WireWithdrawalCircuitInput {
    fn from(value: &WithdrawalCircuitInput) -> Self {
        Self {
            withdrawn_value: field_to_decimal(value.withdrawn_value),
            state_root: field_to_decimal(value.state_root),
            state_tree_depth: value.state_tree_depth,
            asp_root: field_to_decimal(value.asp_root),
            asp_tree_depth: value.asp_tree_depth,
            context: field_to_decimal(value.context),
            label: field_to_decimal(value.label),
            existing_value: field_to_decimal(value.existing_value),
            existing_nullifier: value.existing_nullifier.to_decimal_string(),
            existing_secret: value.existing_secret.to_decimal_string(),
            new_nullifier: value.new_nullifier.to_decimal_string(),
            new_secret: value.new_secret.to_decimal_string(),
            state_siblings: value
                .state_siblings
                .iter()
                .copied()
                .map(field_to_decimal)
                .collect(),
            state_index: value.state_index,
            asp_siblings: value
                .asp_siblings
                .iter()
                .copied()
                .map(field_to_decimal)
                .collect(),
            asp_index: value.asp_index,
        }
    }
}

fn parse_address(value: &str) -> Result<Address, CoreError> {
    Address::from_str(value).map_err(|_| CoreError::InvalidAddress(value.to_owned()))
}

fn parse_secret(value: &str) -> Result<Secret, CoreError> {
    parse_decimal_field(value).map(Secret::new)
}

fn parse_nullifier(value: &str) -> Result<Nullifier, CoreError> {
    parse_decimal_field(value).map(Nullifier::new)
}

fn parse_fields(values: Vec<String>) -> Result<Vec<FieldElement>, CoreError> {
    values
        .iter()
        .map(|value| parse_decimal_field(value))
        .collect()
}
