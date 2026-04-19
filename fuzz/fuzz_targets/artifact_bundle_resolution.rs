#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{ArtifactBytes, ArtifactKind, ArtifactManifest},
};

const WITHDRAW_MANIFEST_JSON: &str =
    include_str!("../../fixtures/artifacts/withdrawal-proving-manifest.json");
const WITHDRAW_WASM: &[u8] = include_bytes!("../../fixtures/circuits/withdraw/withdraw.wasm");
const WITHDRAW_ZKEY: &[u8] = include_bytes!("../../fixtures/artifacts/withdraw.zkey");
const WITHDRAW_VKEY: &[u8] = include_bytes!("../../fixtures/artifacts/withdraw.vkey.json");

fn mutated_fixture_bytes(seed: &[u8], fixture: &[u8]) -> Vec<u8> {
    if fixture.is_empty() {
        return seed.to_vec();
    }

    let mut bytes = fixture.to_vec();
    for (index, byte) in seed.iter().take(256).enumerate() {
        let slot = (index.wrapping_mul(131)) % bytes.len();
        bytes[slot] ^= *byte;
    }
    bytes
}

fuzz_target!(|data: &[u8]| {
    let sdk = PrivacyPoolsSdk::default();
    let manifest: ArtifactManifest =
        serde_json::from_str(WITHDRAW_MANIFEST_JSON).expect("withdraw manifest parses");
    let split = data.len() / 3;
    let (wasm_seed, rest) = data.split_at(split);
    let (zkey_seed, vkey_seed) = rest.split_at(rest.len() / 2);

    let artifacts = [
        ArtifactBytes {
            kind: ArtifactKind::Wasm,
            bytes: mutated_fixture_bytes(wasm_seed, WITHDRAW_WASM),
        },
        ArtifactBytes {
            kind: ArtifactKind::Zkey,
            bytes: mutated_fixture_bytes(zkey_seed, WITHDRAW_ZKEY),
        },
        ArtifactBytes {
            kind: ArtifactKind::Vkey,
            bytes: mutated_fixture_bytes(vkey_seed, WITHDRAW_VKEY),
        },
    ];

    let _ = sdk.verify_artifact_bundle_bytes(&manifest, "withdraw", artifacts);
});
