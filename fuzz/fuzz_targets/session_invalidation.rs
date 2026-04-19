#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk::{
    PrivacyPoolsSdk, SessionCache, SessionCacheKey,
    artifacts::{ArtifactBytes, ArtifactKind, ArtifactManifest},
    prover::BackendProfile,
};

const COMMITMENT_MANIFEST_JSON: &str =
    include_str!("../../fixtures/artifacts/commitment-proving-manifest.json");
const COMMITMENT_WASM: &[u8] = include_bytes!("../../fixtures/circuits/commitment/commitment.wasm");
const COMMITMENT_ZKEY: &[u8] = include_bytes!("../../fixtures/artifacts/commitment.zkey");
const COMMITMENT_VKEY: &[u8] = include_bytes!("../../fixtures/artifacts/commitment.vkey.json");

fn commitment_artifacts() -> [ArtifactBytes; 3] {
    [
        ArtifactBytes {
            kind: ArtifactKind::Wasm,
            bytes: COMMITMENT_WASM.to_vec(),
        },
        ArtifactBytes {
            kind: ArtifactKind::Zkey,
            bytes: COMMITMENT_ZKEY.to_vec(),
        },
        ArtifactBytes {
            kind: ArtifactKind::Vkey,
            bytes: COMMITMENT_VKEY.to_vec(),
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let sdk = PrivacyPoolsSdk::default();
    let base_manifest: ArtifactManifest =
        serde_json::from_str(COMMITMENT_MANIFEST_JSON).expect("commitment manifest parses");
    let capacity = usize::from(data.first().copied().unwrap_or(0) % 4);
    let mut cache = SessionCache::new(capacity);
    let mut retained = Vec::new();

    for (index, byte) in data.iter().skip(1).take(8).enumerate() {
        let mut manifest = base_manifest.clone();
        manifest.version = format!("{}-{}", manifest.version, byte);
        let Ok(bundle) =
            sdk.verify_artifact_bundle_bytes(&manifest, "commitment", commitment_artifacts())
        else {
            continue;
        };
        let key = SessionCacheKey::from_verified_bundle(BackendProfile::Stable, &bundle);
        let Ok(session) = sdk.prepare_commitment_circuit_session_from_bundle(bundle) else {
            continue;
        };
        cache.insert_commitment(key.clone(), session);
        if index % 2 == 0 {
            let _ = cache.commitment(&key);
        }
        if index % 3 == 0 {
            let _ = cache.remove(&key);
        } else {
            retained.push(key);
        }
    }

    for key in retained {
        let _ = cache.commitment(&key);
        let _ = cache.remove(&key);
    }
});
