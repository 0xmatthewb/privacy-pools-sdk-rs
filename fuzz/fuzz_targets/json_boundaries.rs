#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_artifacts::ArtifactManifest;
use privacy_pools_sdk_core::{
    ProofBundle,
    wire::{
        WireCommitment, WireCommitmentCircuitInput, WireMasterKeys, WireWithdrawalCircuitInput,
        WireWithdrawalWitnessRequest,
    },
};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<serde_json::Value>(data);
    let _ = serde_json::from_slice::<WireMasterKeys>(data);
    let _ = serde_json::from_slice::<WireCommitment>(data);
    let _ = serde_json::from_slice::<WireCommitmentCircuitInput>(data);
    let _ = serde_json::from_slice::<WireWithdrawalWitnessRequest>(data);
    let _ = serde_json::from_slice::<WireWithdrawalCircuitInput>(data);
    let _ = serde_json::from_slice::<ProofBundle>(data);
    let _ = serde_json::from_slice::<ArtifactManifest>(data);
});
