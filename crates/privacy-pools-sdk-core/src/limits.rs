use serde::de::DeserializeOwned;

pub const MAX_CONTROL_JSON_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_WITNESS_JSON_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RECOVERY_JSON_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARTIFACT_JSON_INPUT_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_SIGNED_MANIFEST_PAYLOAD_BYTES: usize = 128 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_TOTAL_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_SECRET_HANDLES: usize = 512;
pub const MAX_VERIFIED_PROOF_HANDLES: usize = 256;
pub const MAX_EXECUTION_HANDLES: usize = 256;
pub const MAX_CIRCUIT_SESSIONS_PER_TYPE: usize = 64;

pub fn parse_json_with_limit<T, E, F>(
    json: &str,
    limit: usize,
    field: &'static str,
    to_err: F,
) -> Result<T, E>
where
    T: DeserializeOwned,
    F: FnOnce(LimitError) -> E,
{
    if json.len() > limit {
        return Err(to_err(LimitError::PayloadTooLarge {
            field,
            limit,
            actual: json.len(),
        }));
    }

    serde_json::from_str(json).map_err(|error| to_err(LimitError::Parse(error.to_string())))
}

#[derive(Debug)]
pub enum LimitError {
    PayloadTooLarge {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    Parse(String),
}
