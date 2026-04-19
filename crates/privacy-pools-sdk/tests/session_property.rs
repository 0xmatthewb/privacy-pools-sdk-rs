use privacy_pools_sdk::{
    PrivacyPoolsSdk, SessionCache, SessionCacheKey,
    artifacts::{ArtifactBytes, ArtifactManifest},
    prover::BackendProfile,
};
use proptest::prelude::*;
use std::{fs, path::PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn rotated_bundle(
    sdk: &PrivacyPoolsSdk,
    version: &str,
) -> privacy_pools_sdk::artifacts::VerifiedArtifactBundle {
    let manifest: ArtifactManifest = serde_json::from_slice(
        &fs::read(workspace_path(
            "fixtures/artifacts/commitment-proving-manifest.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let bytes = manifest
        .artifacts
        .iter()
        .map(|descriptor| ArtifactBytes {
            kind: descriptor.kind,
            bytes: fs::read(workspace_path(&format!(
                "fixtures/artifacts/{}",
                descriptor.filename
            )))
            .unwrap(),
        })
        .collect::<Vec<_>>();
    let rotated_manifest = ArtifactManifest {
        version: version.to_owned(),
        artifacts: manifest.artifacts,
    };

    sdk.verify_artifact_bundle_bytes(&rotated_manifest, "commitment", bytes)
        .expect("rotated bundle verifies")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        .. ProptestConfig::default()
    })]

    #[test]
    fn session_cache_invalidates_rotated_keys_and_respects_capacity(
        capacity in 1_usize..4,
        salts in proptest::collection::vec(1_u8..=250, 1..6),
    ) {
        let sdk = PrivacyPoolsSdk::default();
        let mut cache = SessionCache::new(capacity);
        let mut inserted = Vec::new();

        for (index, salt) in salts.iter().copied().enumerate() {
            let bundle = rotated_bundle(&sdk, &format!("property-{index}-{salt}"));
            let key = SessionCacheKey::from_verified_bundle(BackendProfile::Stable, &bundle);
            let session = sdk
                .prepare_commitment_circuit_session_from_bundle(bundle)
                .expect("commitment session prepares");
            cache.insert_commitment(key.clone(), session.clone());
            inserted.push(key);
        }

        let retained = capacity.min(inserted.len());
        prop_assert_eq!(cache.len(), retained);
        prop_assert!(cache.commitment(inserted.last().unwrap()).is_some());

        for key in inserted.iter().take(inserted.len().saturating_sub(retained)) {
            prop_assert!(cache.commitment(key).is_none());
        }

        let latest = inserted.last().unwrap().clone();
        prop_assert!(cache.remove(&latest));
        prop_assert!(cache.commitment(&latest).is_none());
    }
}
