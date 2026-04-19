use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{
        ArtifactError, ArtifactKind, ArtifactManifest, SignedManifestArtifactBytes,
        verify_signed_manifest_artifact_bytes, verify_signed_manifest_artifact_files,
    },
    chain, core,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolVectorsFixture {
    proof_formatting_path: String,
    signed_manifest: SignedManifestFixture,
    artifact_bundles: Vec<ArtifactBundleFixture>,
    error_semantics: Vec<ErrorSemanticFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedManifestFixture {
    payload_path: String,
    signature_path: String,
    public_key_path: String,
    artifacts_root: String,
    expected_version: String,
    expected_artifact_count: usize,
    expected_filenames: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactBundleFixture {
    name: String,
    manifest_path: String,
    artifacts_root: String,
    circuit: String,
    expected_version: String,
    expected_artifacts: Vec<ExpectedArtifactFixture>,
}

#[derive(Debug, Deserialize)]
struct ExpectedArtifactFixture {
    kind: String,
    filename: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorSemanticFixture {
    name: String,
    expected_substring: String,
}

#[derive(Debug, Deserialize)]
struct ProofFormattingFixture {
    input: ProofFormattingInput,
    expected: ExpectedFormattedProof,
}

#[derive(Debug, Deserialize)]
struct ProofFormattingInput {
    proof: core::SnarkJsProof,
    #[serde(rename = "publicSignals")]
    public_signals: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFormattedProof {
    #[serde(rename = "pA")]
    p_a: [String; 2],
    #[serde(rename = "pB")]
    p_b: [[String; 2]; 2],
    #[serde(rename = "pC")]
    p_c: [String; 2],
    #[serde(rename = "pubSignals")]
    pub_signals: Vec<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_path(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

fn read_json<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let path = workspace_path(relative);
    let bytes = fs::read(path).expect("fixture exists");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

fn read_text(relative: &str) -> String {
    fs::read_to_string(workspace_path(relative)).expect("fixture exists")
}

fn artifact_kind(kind: &str) -> ArtifactKind {
    match kind {
        "wasm" => ArtifactKind::Wasm,
        "zkey" => ArtifactKind::Zkey,
        "vkey" => ArtifactKind::Vkey,
        other => panic!("unsupported artifact kind fixture: {other}"),
    }
}

#[test]
fn protocol_vectors_cover_proof_formatting_and_public_signals() {
    let vectors: ProtocolVectorsFixture = read_json("fixtures/spec/protocol-vectors.json");
    let formatting: ProofFormattingFixture = read_json(vectors.proof_formatting_path.as_str());
    let bundle = core::ProofBundle {
        proof: formatting.input.proof,
        public_signals: formatting.input.public_signals,
    };

    let formatted = chain::format_groth16_proof(&bundle).expect("proof formats");

    assert_eq!(
        formatted,
        core::FormattedGroth16Proof {
            p_a: formatting.expected.p_a,
            p_b: formatting.expected.p_b,
            p_c: formatting.expected.p_c,
            pub_signals: formatting.expected.pub_signals,
        }
    );
}

#[test]
fn protocol_vectors_cover_signed_manifest_and_artifact_bundle_binding() {
    let vectors: ProtocolVectorsFixture = read_json("fixtures/spec/protocol-vectors.json");
    let payload = fs::read(workspace_path(&vectors.signed_manifest.payload_path)).unwrap();
    let signature = read_text(&vectors.signed_manifest.signature_path);
    let public_key = read_text(&vectors.signed_manifest.public_key_path);
    let artifacts_root = workspace_path(&vectors.signed_manifest.artifacts_root);

    let verified = verify_signed_manifest_artifact_files(
        &payload,
        signature.trim(),
        public_key.trim(),
        &artifacts_root,
    )
    .expect("signed manifest artifacts verify");

    assert_eq!(
        verified.payload().manifest.version,
        vectors.signed_manifest.expected_version
    );
    assert_eq!(
        verified.artifact_count(),
        vectors.signed_manifest.expected_artifact_count
    );
    assert_eq!(
        verified
            .payload()
            .manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.filename.clone())
            .collect::<Vec<_>>(),
        vectors.signed_manifest.expected_filenames
    );
}

#[test]
fn protocol_vectors_cover_expected_artifact_versions_hashes_and_kinds() {
    let vectors: ProtocolVectorsFixture = read_json("fixtures/spec/protocol-vectors.json");
    let sdk = PrivacyPoolsSdk::default();

    for fixture in vectors.artifact_bundles {
        let manifest: ArtifactManifest = read_json(&fixture.manifest_path);
        let bundle = sdk
            .load_verified_artifact_bundle(
                &manifest,
                workspace_path(&fixture.artifacts_root),
                &fixture.circuit,
            )
            .unwrap_or_else(|error| panic!("bundle {} should load: {error}", fixture.name));

        assert_eq!(bundle.version(), fixture.expected_version);
        assert_eq!(bundle.circuit(), fixture.circuit);
        assert_eq!(bundle.artifacts().len(), fixture.expected_artifacts.len());

        for expected in &fixture.expected_artifacts {
            let actual = bundle
                .artifact(artifact_kind(&expected.kind))
                .unwrap_or_else(|error| {
                    panic!("missing {} in {}: {error}", expected.kind, fixture.name)
                });
            assert_eq!(actual.descriptor().filename, expected.filename);
            assert_eq!(actual.descriptor().sha256, expected.sha256);
            assert_eq!(hex::encode(Sha256::digest(actual.bytes())), expected.sha256);
        }
    }
}

#[test]
fn protocol_vectors_capture_normalized_error_semantics() {
    let vectors: ProtocolVectorsFixture = read_json("fixtures/spec/protocol-vectors.json");
    let payload = fs::read(workspace_path(
        "fixtures/artifacts/signed-manifest/payload.json",
    ))
    .unwrap();
    let signature = read_text("fixtures/artifacts/signed-manifest/signature");
    let public_key = read_text("fixtures/artifacts/signed-manifest/public-key.hex");
    let manifest: ArtifactManifest = read_json("fixtures/artifacts/sample-proving-manifest.json");
    let sample_bytes = fs::read(workspace_path("fixtures/artifacts/sample-artifact.bin")).unwrap();

    for case in vectors.error_semantics {
        let error = match case.name.as_str() {
            "hash-mismatch" => {
                let mut descriptor = manifest
                    .descriptor("withdraw", ArtifactKind::Wasm)
                    .expect("descriptor exists")
                    .clone();
                descriptor.sha256 = "00".repeat(32);
                privacy_pools_sdk::artifacts::verify_artifact_bytes(&descriptor, &sample_bytes)
                    .expect_err("hash mismatch should fail")
            }
            "unexpected-signed-artifact" => verify_signed_manifest_artifact_bytes(
                &payload,
                signature.trim(),
                public_key.trim(),
                [
                    SignedManifestArtifactBytes {
                        filename: "withdraw-fixture.wasm".to_owned(),
                        bytes: fs::read(workspace_path(
                            "fixtures/artifacts/signed-manifest/artifacts/withdraw-fixture.wasm",
                        ))
                        .expect("signed artifact exists"),
                    },
                    SignedManifestArtifactBytes {
                        filename: "unexpected.wasm".to_owned(),
                        bytes: sample_bytes.clone(),
                    },
                ],
            )
            .expect_err("unexpected signed-manifest artifact should fail"),
            other => panic!("unsupported error semantic fixture: {other}"),
        };

        let normalized = match &error {
            ArtifactError::HashMismatch { .. } | ArtifactError::InvalidSignedManifest(_) => {
                error.to_string()
            }
            other => panic!("unexpected error shape for {}: {other}", case.name),
        };
        assert!(
            normalized.contains(&case.expected_substring),
            "expected `{}` to contain `{}`",
            normalized,
            case.expected_substring,
        );
    }
}
