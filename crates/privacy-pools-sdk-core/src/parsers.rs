use crate::{CoreError, ExecutionPolicyMode, ReadConsistency};

pub fn parse_execution_policy_mode(value: &str) -> Result<ExecutionPolicyMode, CoreError> {
    match value {
        "strict" => Ok(ExecutionPolicyMode::Strict),
        "insecure_dev" => Ok(ExecutionPolicyMode::InsecureDev),
        _ => Err(CoreError::InvalidExecutionPolicyMode(value.to_owned())),
    }
}

pub fn parse_read_consistency(value: &str) -> Result<ReadConsistency, CoreError> {
    match value {
        "latest" => Ok(ReadConsistency::Latest),
        "finalized" => Ok(ReadConsistency::Finalized),
        _ => Err(CoreError::InvalidReadConsistency(value.to_owned())),
    }
}
