#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_artifacts::{
    ArtifactManifest, SignedArtifactManifest, SignedArtifactManifestPayload,
    SignedManifestArtifactBytes, verify_signed_manifest_artifact_bytes,
};

const SIGNED_MANIFEST_PAYLOAD: &[u8] =
    include_bytes!("../../fixtures/artifacts/signed-manifest/payload.json");
const SIGNED_MANIFEST_SIGNATURE: &str =
    include_str!("../../fixtures/artifacts/signed-manifest/signature");
const SIGNED_MANIFEST_PUBLIC_KEY: &str =
    include_str!("../../fixtures/artifacts/signed-manifest/public-key.hex");
const SIGNED_MANIFEST_WASM: &[u8] =
    include_bytes!("../../fixtures/artifacts/signed-manifest/artifacts/withdraw-fixture.wasm");

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

    let mut payload = SIGNED_MANIFEST_PAYLOAD.to_vec();
    for (index, byte) in data.iter().take(payload.len().min(256)).enumerate() {
        payload[index] ^= *byte;
    }
    let mutated = !data.is_empty();
    let result = verify_signed_manifest_artifact_bytes(
        &payload,
        SIGNED_MANIFEST_SIGNATURE.trim(),
        SIGNED_MANIFEST_PUBLIC_KEY.trim(),
        [SignedManifestArtifactBytes {
            filename: "withdraw-fixture.wasm".to_owned(),
            bytes: SIGNED_MANIFEST_WASM.to_vec(),
        }],
    );
    if mutated {
        assert!(
            result.is_err(),
            "tampered signed manifest should be rejected"
        );
    } else {
        assert!(result.is_ok(), "untampered signed manifest should verify");
    }
});
