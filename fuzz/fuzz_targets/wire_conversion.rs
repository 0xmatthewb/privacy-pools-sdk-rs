#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_core::{
    Commitment, CommitmentCircuitInput, MasterKeys, WithdrawalCircuitInput,
    WithdrawalWitnessRequest,
    wire::{
        WireCommitment, WireCommitmentCircuitInput, WireMasterKeys, WireWithdrawalCircuitInput,
        WireWithdrawalWitnessRequest,
    },
};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<WireMasterKeys>(data) {
        let _ = MasterKeys::try_from(value);
    }

    if let Ok(value) = serde_json::from_slice::<WireCommitment>(data) {
        let _ = Commitment::try_from(value);
    }

    if let Ok(value) = serde_json::from_slice::<WireCommitmentCircuitInput>(data) {
        let _ = CommitmentCircuitInput::try_from(value);
    }

    if let Ok(value) = serde_json::from_slice::<WireWithdrawalWitnessRequest>(data) {
        let _ = WithdrawalWitnessRequest::try_from(value);
    }

    if let Ok(value) = serde_json::from_slice::<WireWithdrawalCircuitInput>(data) {
        let _ = WithdrawalCircuitInput::try_from(value);
    }
});
