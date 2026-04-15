use privacy_pools_sdk::{
    PrivacyPoolsClient, PrivacyPoolsClientConfig, PrivacyPoolsSdk, artifacts,
    prover::BackendProfile,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: artifacts::ArtifactManifest = serde_json::from_str(include_str!(
        "../../../fixtures/artifacts/sample-proving-manifest.json"
    ))?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artifacts");
    let config = PrivacyPoolsClientConfig::new(manifest, root).with_profile(BackendProfile::Stable);

    let client = PrivacyPoolsClient::http("http://127.0.0.1:8545", config)?;

    println!("sdk version: {}", PrivacyPoolsSdk::version());
    println!("client backend profile: {:?}", client.config().profile);

    Ok(())
}
