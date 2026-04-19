#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_artifacts::{
    ArtifactManifest, SignedArtifactManifest, SignedArtifactManifestPayload,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = serde_json::from_slice::<ArtifactManifest>(data) {
        let _ = serde_json::to_vec(&manifest).expect("artifact manifest should serialize");
    }

    if let Ok(payload) = serde_json::from_slice::<SignedArtifactManifestPayload>(data) {
        let _ = serde_json::to_vec(&payload).expect("signed manifest payload should serialize");
    }

    if let Ok(signed) = serde_json::from_slice::<SignedArtifactManifest>(data) {
        let _ = serde_json::to_vec(&signed).expect("signed manifest should serialize");
    }
});
