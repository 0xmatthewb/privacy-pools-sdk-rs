use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

fn evidence_path() -> Utf8PathBuf {
    Utf8PathBuf::from("mobile-smoke.json")
}

fn mobile_smoke_fixture(commit: &str) -> Value {
    mobile_smoke_fixture_with_identity(
        commit,
        "github-workflow",
        "mobile-smoke",
        "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
    )
}

fn mobile_smoke_fixture_with_identity(
    commit: &str,
    source: &str,
    workflow: &str,
    run_url: &str,
) -> Value {
    json!({
        "commit": commit,
        "source": source,
        "workflow": workflow,
        "run_url": run_url,
        "ios": "passed",
        "android": "passed",
        "surfaces": {
            "iosNative": "passed",
            "iosReactNative": "passed",
            "androidNative": "passed",
            "androidReactNative": "passed",
        }
    })
}

#[test]
fn preserved_file_contents_restore_original_on_success() {
    let temp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(temp.path().join("build-flags.ts")).unwrap();
    fs::write(&path, "original").unwrap();

    with_preserved_file_contents(&path, || {
        fs::write(&path, "modified").unwrap();
        Ok::<(), anyhow::Error>(())
    })
    .unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "original");
}

#[test]
fn preserved_file_contents_restore_original_on_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(temp.path().join("build-flags.ts")).unwrap();
    fs::write(&path, "original").unwrap();

    let error = with_preserved_file_contents(&path, || {
        fs::write(&path, "modified").unwrap();
        Err::<(), anyhow::Error>(anyhow::anyhow!("expected failure"))
    })
    .unwrap_err()
    .to_string();

    assert!(error.contains("expected failure"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "original");
}

#[test]
fn mobile_smoke_local_options_reject_partial_evidence_runs() {
    let workspace_root = workspace_root().unwrap();
    let options = MobileSmokeLocalOptions::parse(
        vec![
            "--platform".to_owned(),
            "ios".to_owned(),
            "--evidence-out-dir".to_owned(),
            "target/mobile-evidence".to_owned(),
        ],
        &workspace_root,
    )
    .unwrap();

    let error = options.validate().unwrap_err().to_string();

    assert!(error.contains("--evidence-out-dir"));
    assert!(error.contains("--platform all --surface all"));
}

#[test]
fn mobile_smoke_local_options_allow_full_suite_evidence_runs() {
    let workspace_root = workspace_root().unwrap();
    let options = MobileSmokeLocalOptions::parse(
        vec![
            "--platform".to_owned(),
            "all".to_owned(),
            "--surface".to_owned(),
            "all".to_owned(),
            "--evidence-out-dir".to_owned(),
            "target/mobile-evidence".to_owned(),
        ],
        &workspace_root,
    )
    .unwrap();

    options.validate().unwrap();
    assert!(options.is_full_suite());
}

fn benchmark_fixture_metadata(file: &str) -> (&'static str, &'static str, &'static str) {
    match file {
        "rust-desktop-stable.json"
        | "node-desktop-stable.json"
        | "browser-desktop-stable.json"
        | "browser-desktop-threaded.json" => ("desktop", "reference-desktop", "desktop-reference"),
        "react-native-ios-stable.json" => ("ios", "reference-ios-device", "ios-reference"),
        "react-native-android-stable.json" => {
            ("android", "reference-android-device", "android-reference")
        }
        other => panic!("unexpected benchmark fixture file: {other}"),
    }
}

fn benchmark_report(commit: &str, file: &str) -> Value {
    let (device_label, device_model, device_class) = benchmark_fixture_metadata(file);
    json!({
        "generated_at_unix_seconds": 1,
        "git_commit": commit,
        "sdk_version": "0.1.0-alpha.0",
        "backend_name": "stable",
        "device_label": device_label,
        "device_model": device_model,
        "device_class": device_class,
        "cpu_model": "fixture-cpu",
        "os_name": "fixture-os",
        "os_version": "fixture-version",
        "rustc_version_verbose": "rustc 1.99.0",
        "cargo_version": "cargo 1.99.0",
        "benchmark_scenario_id": "withdraw-stable",
        "artifact_version": "fixture-artifacts",
        "zkey_sha256": "fixture-zkey",
        "manifest_sha256": "fixture-manifest",
        "artifact_bundle_sha256": "fixture-bundle",
        "manifest_path": "fixtures/artifacts/sample-proving-manifest.json",
        "artifacts_root": "fixtures/artifacts",
        "backend_profile": "Stable",
        "artifact_resolution_ms": 0.0,
        "bundle_verification_ms": 0.0,
        "session_preload_ms": 0.0,
        "first_input_preparation_ms": 0.0,
        "first_witness_generation_ms": 0.0,
        "first_proof_generation_ms": 0.0,
        "first_verification_ms": 0.0,
        "first_prove_and_verify_ms": 0.0,
        "iterations": 1,
        "warmup": 0,
        "input_preparation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
        "witness_generation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
        "proof_generation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
        "verification": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
        "prove_and_verify": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
        "samples": [{}]
    })
}

fn mobile_parity_fixture(commit: &str) -> Value {
    mobile_parity_fixture_with_identity(
        commit,
        "github-workflow",
        "mobile-smoke",
        "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
    )
}

fn mobile_parity_fixture_with_identity(
    commit: &str,
    source: &str,
    workflow: &str,
    run_url: &str,
) -> Value {
    json!({
        "commit": commit,
        "source": source,
        "workflow": workflow,
        "run_url": run_url,
        "totalChecks": 32,
        "passed": 32,
        "failed": 0,
        "ios": mobile_platform_rollup("ios"),
        "android": mobile_platform_rollup("android"),
    })
}

fn mobile_platform_rollup(platform: &str) -> Value {
    json!({
        "totalChecks": 16,
        "passed": 16,
        "failed": 0,
        "native": mobile_surface_report(platform, "native", "native"),
        "reactNative": mobile_surface_report(platform, "react-native-app", "react-native"),
    })
}

fn mobile_surface_report(platform: &str, runtime: &str, surface: &str) -> Value {
    json!({
        "generatedAt": "2026-01-01T00:00:00.000Z",
        "runtime": runtime,
        "platform": platform,
        "surface": surface,
        "smoke": {
            "backend": "arkworks",
            "commitmentVerified": true,
            "withdrawalVerified": true,
            "executionSubmitted": true,
            "signedManifestVerified": true,
            "wrongSignedManifestPublicKeyRejected": true,
            "tamperedSignedManifestArtifactsRejected": true,
            "tamperedProofRejected": true,
            "handleKindMismatchRejected": true,
            "staleVerifiedProofHandleRejected": true,
            "staleCommitmentSessionRejected": true,
            "staleWithdrawalSessionRejected": true,
            "wrongRootRejected": true,
            "wrongChainIdRejected": true,
            "wrongCodeHashRejected": true,
            "wrongSignerRejected": true,
        },
        "parity": {
            "totalChecks": 8,
            "passed": 8,
            "failed": 0,
            "failedChecks": [],
        },
        "benchmark": {
            "artifactResolutionMs": 1.0,
            "bundleVerificationMs": 1.0,
            "sessionPreloadMs": 1.0,
            "firstInputPreparationMs": 1.0,
            "firstWitnessGenerationMs": 1.0,
            "firstProofGenerationMs": 1.0,
            "firstVerificationMs": 1.0,
            "firstProveAndVerifyMs": 1.0,
            "iterations": 1,
            "warmup": 0,
            "peakResidentMemoryBytes": Value::Null,
            "samples": [
                {
                    "inputPreparationMs": 1.0,
                    "witnessGenerationMs": 1.0,
                    "proofGenerationMs": 1.0,
                    "verificationMs": 1.0,
                    "proveAndVerifyMs": 1.0
                }
            ]
        }
    })
}

fn browser_metric() -> Value {
    json!({
        "iterations": 1,
        "total": { "averageMs": 1.0, "minMs": 1.0, "maxMs": 1.0 },
        "slices": {
            "preloadMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "witnessParseMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "witnessTransferMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "witnessMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "proveMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "verifyMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
            "totalMs": { "averageMs": 1.0, "minMs": 1.0, "maxMs": 1.0 }
        }
    })
}

fn browser_comparison_report() -> Value {
    json!({
        "generatedAt": "2026-01-01T00:00:00.000Z",
        "browserPerformance": {
            "commitment": {
                "directCold": browser_metric(),
                "directWarm": browser_metric(),
                "workerCold": browser_metric(),
                "workerWarm": browser_metric()
            },
            "withdrawal": {
                "directCold": browser_metric(),
                "directWarm": browser_metric(),
                "workerCold": browser_metric(),
                "workerWarm": browser_metric()
            }
        }
    })
}

fn write_json(path: &Utf8PathBuf, value: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn write_signed_manifest_fixture(dir: &Utf8PathBuf) -> String {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let artifact_bytes = b"signed manifest fixture artifact";
    let artifact_sha256 = hex::encode(Sha256::digest(artifact_bytes));
    let payload = json!({
        "manifest": {
            "version": "signed-fixture",
            "artifacts": [
                {
                    "circuit": "withdraw",
                    "kind": "wasm",
                    "filename": "withdraw-fixture.wasm",
                    "sha256": artifact_sha256
                }
            ]
        },
        "metadata": {
            "ceremony": "fixture ceremony",
            "build": "fixture build",
            "repository": "https://github.com/0xbow/privacy-pools-sdk-rs",
            "commit": "abcdef0"
        }
    });
    let payload_json = serde_json::to_vec_pretty(&payload).unwrap();
    let signature = signing_key.sign(&payload_json);
    let artifact_root = dir.join("signed-artifact-manifest-artifacts");
    fs::create_dir_all(&artifact_root).unwrap();
    fs::write(
        dir.join("signed-artifact-manifest.payload.json"),
        &payload_json,
    )
    .unwrap();
    fs::write(
        dir.join("signed-artifact-manifest.signature"),
        hex::encode(signature.to_bytes()),
    )
    .unwrap();
    fs::write(artifact_root.join("withdraw-fixture.wasm"), artifact_bytes).unwrap();

    hex::encode(signing_key.verifying_key().to_bytes())
}

fn write_external_signed_manifest_fixture(dir: &Utf8PathBuf) -> String {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let fixture_dir = dir.join("signed-manifest");
    let artifact_root = fixture_dir.join("artifacts");
    let artifact_bytes = b"signed manifest fixture artifact";
    let artifact_sha256 = hex::encode(Sha256::digest(artifact_bytes));
    let payload = json!({
        "manifest": {
            "version": "signed-fixture",
            "artifacts": [
                {
                    "circuit": "withdraw",
                    "kind": "wasm",
                    "filename": "withdraw-fixture.wasm",
                    "sha256": artifact_sha256
                }
            ]
        },
        "metadata": {
            "ceremony": "fixture ceremony",
            "build": "fixture build",
            "repository": "https://github.com/0xbow/privacy-pools-sdk-rs",
            "commit": "abcdef0"
        }
    });
    let payload_json = serde_json::to_vec_pretty(&payload).unwrap();
    let signature = signing_key.sign(&payload_json);
    fs::create_dir_all(&artifact_root).unwrap();
    fs::write(fixture_dir.join("payload.json"), &payload_json).unwrap();
    fs::write(
        fixture_dir.join("signature"),
        hex::encode(signature.to_bytes()),
    )
    .unwrap();
    fs::write(artifact_root.join("withdraw-fixture.wasm"), artifact_bytes).unwrap();
    hex::encode(signing_key.verifying_key().to_bytes())
}

fn write_sdk_web_package_fixture(
    root: &Utf8PathBuf,
    package_dir: &Utf8PathBuf,
) -> (Utf8PathBuf, Utf8PathBuf) {
    let sdk_dir = package_dir.join("sdk");
    fs::create_dir_all(&sdk_dir).unwrap();

    let browser_wasm_bytes = b"browser wasm fixture";
    let external_wasm_path = sdk_dir.join("privacy_pools_sdk_web_bg.wasm");
    fs::write(&external_wasm_path, browser_wasm_bytes).unwrap();

    let package_fixture_root = root.join("sdk-package-fixture");
    let generated_root = package_fixture_root.join("package/src/browser/generated");
    fs::create_dir_all(&generated_root).unwrap();
    fs::create_dir_all(package_fixture_root.join("package")).unwrap();
    fs::write(
        generated_root.join("privacy_pools_sdk_web_bg.wasm"),
        browser_wasm_bytes,
    )
    .unwrap();
    fs::write(
        package_fixture_root.join("package/package.json"),
        r#"{"name":"@0xmatthewb/privacy-pools-sdk","version":"0.1.0-alpha.1"}"#,
    )
    .unwrap();

    let tarball_path = sdk_dir.join("privacy-pools-sdk-alpha.tgz");
    let status = Command::new("tar")
        .args([
            "-C",
            package_fixture_root.as_str(),
            "-czf",
            tarball_path.as_str(),
            "package",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    (tarball_path, external_wasm_path)
}

fn write_react_native_package_fixture(package_dir: &Utf8PathBuf) -> Utf8PathBuf {
    let react_native_dir = package_dir.join("react-native");
    fs::create_dir_all(&react_native_dir).unwrap();
    let package_path = react_native_dir.join("privacy-pools-sdk-react-native-alpha.tgz");
    fs::write(&package_path, b"react native package fixture").unwrap();
    package_path
}

fn attestation_verification_fixture(subject_path: &str, sha256: &str, repo: &str) -> Value {
    json!({
        "verified": true,
        "verifiedAt": "2026-04-17T00:00:00Z",
        "repo": repo,
        "signerWorkflow": format!("{repo}/.github/workflows/release.yml"),
        "subjectPath": subject_path,
        "subjectSha256": sha256,
        "attestedSubjectName": Utf8PathBuf::from(subject_path).file_name().unwrap_or(subject_path),
        "attestedSubjectBasename": Utf8PathBuf::from(subject_path).file_name().unwrap_or(subject_path),
        "predicateType": "https://slsa.dev/provenance/v1",
        "verificationCount": 1
    })
}

fn attestation_record_fixture(
    attestation_root: &Utf8PathBuf,
    subject_path: &str,
    sha256: &str,
    attestation_url: &str,
    workflow_run_url: &str,
    repo: &str,
) -> Value {
    let verification_relative = format!(
        "attestation-verification/{}.verified.json",
        subject_path.replace('/', "__")
    );
    write_json(
        &attestation_root.join(&verification_relative),
        &attestation_verification_fixture(subject_path, sha256, repo),
    );
    json!({
        "subjectPath": subject_path,
        "sha256": sha256,
        "attestationUrl": attestation_url,
        "workflowRunUrl": workflow_run_url,
        "verificationPath": verification_relative,
    })
}

fn read_attestation_records(path: &Utf8PathBuf) -> Vec<AttestationRecord> {
    serde_json::from_value(read_required_json(path).unwrap()).unwrap()
}

fn overwrite_attestation_verification(
    attestation_root: &Utf8PathBuf,
    record: &AttestationRecord,
    value: &Value,
) {
    write_json(&attestation_root.join(&record.verification_path), value);
}

fn write_external_evidence_fixture(dir: &Utf8PathBuf, commit: &str) -> String {
    write_json(
        &dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(commit),
    );
    write_json(
        &dir.join("mobile-parity.json"),
        &mobile_parity_fixture(commit),
    );
    let public_key = write_external_signed_manifest_fixture(dir);

    let sbom_dir = dir.join("sbom");
    fs::create_dir_all(&sbom_dir).unwrap();
    write_json(
        &sbom_dir.join("rust.cdx.json"),
        &json!({ "bomFormat": "CycloneDX" }),
    );
    write_json(
        &sbom_dir.join("sdk.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );
    write_json(
        &sbom_dir.join("react-native.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );

    let benchmark_dir = dir.join("benchmarks");
    fs::create_dir_all(&benchmark_dir).unwrap();
    for file in [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "browser-desktop-threaded.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ] {
        write_json(&benchmark_dir.join(file), &benchmark_report(commit, file));
    }

    let package_dir = dir.join("packages");
    fs::create_dir_all(&package_dir).unwrap();
    let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(dir, &package_dir);
    let react_native_package_path = write_react_native_package_fixture(&package_dir);
    let circuits_dir = package_dir.join("circuits");
    fs::create_dir_all(&circuits_dir).unwrap();
    let circuit_archive = circuits_dir.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
    let circuit_fixture_root = dir.join("circuit-fixture");
    let archive_artifacts_root = circuit_fixture_root.join("artifacts");
    fs::create_dir_all(&archive_artifacts_root).unwrap();
    fs::create_dir_all(archive_artifacts_root.join("signed-manifest")).unwrap();
    stage_directory(
        &dir.join("signed-manifest"),
        &archive_artifacts_root.join("signed-manifest"),
    )
    .unwrap();
    fs::write(
        archive_artifacts_root.join("withdraw-fixture.wasm"),
        b"signed manifest fixture artifact",
    )
    .unwrap();
    let status = Command::new("tar")
        .args([
            "-C",
            circuit_fixture_root.as_str(),
            "-czf",
            circuit_archive.as_str(),
            "artifacts",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let sdk_sha256 = sha256_hex(&fs::read(&sdk_package_path).unwrap());
    let sdk_wasm_sha256 = sha256_hex(&fs::read(&sdk_wasm_path).unwrap());
    let react_native_sha256 = sha256_hex(&fs::read(&react_native_package_path).unwrap());
    let circuit_sha256 = sha256_hex(&fs::read(&circuit_archive).unwrap());
    let repo = current_github_repository_slug(&workspace_root().unwrap()).unwrap();

    write_json(
        &dir.join("attestations.json"),
        &json!([
            attestation_record_fixture(
                dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sdk_sha256,
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sdk_wasm_sha256,
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &react_native_sha256,
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &circuit_sha256,
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    public_key
}

fn write_release_assembly_inputs(
    root: &Utf8PathBuf,
    commit: &str,
) -> (
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
) {
    write_release_assembly_inputs_with_mobile_fixtures(
        root,
        &mobile_smoke_fixture(commit),
        &mobile_parity_fixture(commit),
    )
}

fn write_release_assembly_inputs_with_mobile_fixtures(
    root: &Utf8PathBuf,
    mobile_smoke: &Value,
    mobile_parity: &Value,
) -> (
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
    Utf8PathBuf,
) {
    let workspace_root = workspace_root().unwrap();
    let mobile_dir = root.join("mobile");
    fs::create_dir_all(&mobile_dir).unwrap();
    let commit = mobile_smoke["commit"].as_str().unwrap();
    write_json(&mobile_dir.join("mobile-smoke.json"), mobile_smoke);
    write_json(&mobile_dir.join("mobile-parity.json"), mobile_parity);

    let reference_dir = root.join("reference");
    let benchmark_dir = reference_dir.join("benchmarks");
    fs::create_dir_all(&benchmark_dir).unwrap();
    for file in [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "browser-desktop-threaded.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ] {
        write_json(&benchmark_dir.join(file), &benchmark_report(commit, file));
    }

    let sbom_dir = root.join("sbom-inputs");
    let sbom_root = sbom_dir.join("sbom");
    fs::create_dir_all(&sbom_root).unwrap();
    write_json(
        &sbom_root.join("rust.cdx.json"),
        &json!({ "bomFormat": "CycloneDX" }),
    );
    write_json(
        &sbom_root.join("sdk.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );
    write_json(
        &sbom_root.join("react-native.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );

    let packages_dir = root.join("package-inputs");
    let package_root = packages_dir.join("packages");
    fs::create_dir_all(&package_root).unwrap();
    let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(root, &package_root);
    let react_native_package_path = write_react_native_package_fixture(&package_root);
    let circuits_root = package_root.join("circuits");
    fs::create_dir_all(&circuits_root).unwrap();
    let circuit_archive = circuits_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
    let status = Command::new("tar")
        .args([
            "-C",
            workspace_root.join("fixtures").as_str(),
            "-czf",
            circuit_archive.as_str(),
            "artifacts",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let sdk_sha256 = sha256_hex(&fs::read(&sdk_package_path).unwrap());
    let sdk_wasm_sha256 = sha256_hex(&fs::read(&sdk_wasm_path).unwrap());
    let react_native_sha256 = sha256_hex(&fs::read(&react_native_package_path).unwrap());
    let circuit_sha256 = sha256_hex(&fs::read(&circuit_archive).unwrap());
    let repo = current_github_repository_slug(&workspace_root).unwrap();

    let attestation_dir = root.join("attestation-inputs");
    fs::create_dir_all(&attestation_dir).unwrap();
    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sdk_sha256,
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sdk_wasm_sha256,
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &react_native_sha256,
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &circuit_sha256,
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    (
        mobile_dir,
        reference_dir,
        sbom_dir,
        packages_dir,
        attestation_dir,
    )
}

fn selected_assurance_specs(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
) -> Vec<AssuranceCheckSpec> {
    assurance_selected_specs(workspace_root, options).unwrap()
}

fn write_assurance_merge_fixture(
    dir: &Utf8PathBuf,
    commit: &str,
    check_ids: &[&str],
) -> Utf8PathBuf {
    fs::create_dir_all(dir).unwrap();
    let log_root = dir.join("logs");
    let checks_root = dir.join("checks");
    fs::create_dir_all(&log_root).unwrap();
    fs::create_dir_all(&checks_root).unwrap();

    let checks = check_ids
        .iter()
        .map(|id| {
            let log_path = log_root.join(format!("{id}.log"));
            let report_path = checks_root.join(format!("{id}.json"));
            fs::write(&log_path, format!("{id} ok\n")).unwrap();
            json!({
                "id": id,
                "label": id,
                "runtime": ["rust"],
                "allowedProfiles": ["pr"],
                "dependsOn": [],
                "blockedBy": [],
                "scenarioTags": [],
                "riskClass": "correctness",
                "mode": "normative",
                "normative": true,
                "status": "passed",
                "durationMs": 1,
                "rationale": "fixture",
                "inputs": [],
                "command": "fixture",
                "logPath": log_path.as_str(),
                "reportPath": report_path.as_str(),
                "error": Value::Null,
                "expectedOutputs": [],
                "thresholds": Value::Null,
            })
        })
        .collect::<Vec<_>>();

    write_json(
        &dir.join("environment.json"),
        &json!({
            "gitCommit": commit,
            "profile": "pr",
            "runtime": "rust",
            "status": "passed",
        }),
    );
    write_json(
        &dir.join("assurance-index.json"),
        &json!({
            "gitCommit": commit,
            "checks": checks,
        }),
    );
    dir.clone()
}

fn write_assurance_merge_fixture_with_original_root(
    dir: &Utf8PathBuf,
    original_root: &Utf8PathBuf,
    commit: &str,
    check_ids: &[&str],
) -> Utf8PathBuf {
    fs::create_dir_all(dir).unwrap();
    let log_root = dir.join("logs");
    let checks_root = dir.join("checks");
    fs::create_dir_all(&log_root).unwrap();
    fs::create_dir_all(&checks_root).unwrap();

    let checks = check_ids
            .iter()
            .map(|id| {
                let staged_log_path = log_root.join(format!("{id}.log"));
                fs::write(&staged_log_path, format!("{id} ok\n")).unwrap();
                json!({
                    "id": id,
                    "label": id,
                    "runtime": ["rust"],
                    "allowedProfiles": ["pr"],
                    "dependsOn": [],
                    "blockedBy": [],
                    "scenarioTags": [],
                    "riskClass": "correctness",
                    "mode": "normative",
                    "normative": true,
                    "status": "passed",
                    "durationMs": 1,
                    "rationale": "fixture",
                    "inputs": [],
                    "command": "fixture",
                    "logPath": original_root.join("logs").join(format!("{id}.log")).as_str(),
                    "reportPath": original_root
                        .join("checks")
                        .join(format!("{id}.json"))
                        .as_str(),
                    "error": Value::Null,
                    "expectedOutputs": [original_root.join("outputs").join(format!("{id}.txt")).as_str()],
                    "thresholds": Value::Null,
                })
            })
            .collect::<Vec<_>>();

    write_json(
        &dir.join("environment.json"),
        &json!({
            "gitCommit": commit,
            "profile": "pr",
            "runtime": "rust",
            "status": "passed",
        }),
    );
    write_json(
        &dir.join("assurance-index.json"),
        &json!({
            "gitCommit": commit,
            "checks": checks,
            "reports": {
                "environment": original_root.join("environment.json").as_str(),
            },
        }),
    );
    dir.clone()
}

#[test]
fn log_tail_for_error_limits_output_to_requested_lines() {
    let log = "one\ntwo\nthree\nfour";
    let tail = log_tail_for_error(log, 2);

    assert!(tail.contains("three\nfour"));
    assert!(!tail.contains("one"));
    assert!(!tail.contains("two"));
}

#[test]
fn examples_validation_rejects_missing_required_examples() {
    let examples = vec![
        "basic".to_owned(),
        "npm_migration".to_owned(),
        "client_builder".to_owned(),
    ];

    let error = validate_required_examples(&examples)
        .unwrap_err()
        .to_string();

    assert!(error.contains("withdrawal_paths"));
}

#[test]
fn feature_check_invokes_targeted_feature_combinations() {
    let commands = feature_check_commands();

    assert!(commands.iter().any(|command| {
        command.args.contains(&"hack")
            && command.args.contains(&"--each-feature")
            && command.args.contains(&"privacy-pools-sdk-prover")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"--no-default-features")
            && command.args.contains(&"privacy-pools-sdk-prover")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"--all-features")
            && command.args.contains(&"privacy-pools-sdk-prover")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"privacy-pools-sdk-web")
            && command.args.contains(&"wasm32-unknown-unknown")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"privacy-pools-sdk-signer")
            && command.args.contains(&"local-mnemonic")
            && !command.args.contains(&"dangerous-key-export")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"privacy-pools-sdk-signer")
            && command.args.contains(&"dangerous-key-export")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"privacy-pools-sdk-chain")
            && command.args.contains(&"local-signer-client")
    }));
    assert!(commands.iter().any(|command| {
        command.args.contains(&"privacy-pools-sdk-ffi")
            && command.args.contains(&"--no-default-features")
    }));
}

#[test]
fn assurance_runtime_filter_keeps_shared_checks_on_rust_only() {
    assert!(runtime_selected(
        AssuranceRuntime::Rust,
        &[AssuranceRuntime::Shared]
    ));
    assert!(!runtime_selected(
        AssuranceRuntime::Browser,
        &[AssuranceRuntime::Shared]
    ));
    assert!(runtime_selected(
        AssuranceRuntime::Browser,
        &[AssuranceRuntime::Browser]
    ));
    assert!(runtime_selected(
        AssuranceRuntime::All,
        &[AssuranceRuntime::ReactNative]
    ));
}

#[test]
fn audit_pack_alias_maps_to_release_audit_mode() {
    let options = AssuranceOptions::from_audit_pack(AuditPackOptions {
        out_dir: Utf8PathBuf::from("dist/audit-pack"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: Utf8PathBuf::from("/tmp/v1-package"),
        v1_source_path: Utf8PathBuf::from("/tmp/v1-source"),
        external_evidence_dir: Some(Utf8PathBuf::from("/tmp/external-evidence")),
        fuzz_runs: 12,
        skip_fuzz: true,
    });

    assert_eq!(options.profile, AssuranceProfile::Release);
    assert_eq!(options.runtime, AssuranceRuntime::All);
    assert_eq!(options.report_mode, AssuranceReportMode::Audit);
    assert_eq!(
        options.external_evidence_dir,
        Some(Utf8PathBuf::from("/tmp/external-evidence"))
    );
    assert_eq!(options.fuzz_runs, 12);
    assert!(options.skip_fuzz);
}

#[test]
fn assurance_parse_preserves_explicit_out_dir_after_profile_flag() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions::parse(
        vec![
            "--out-dir".to_owned(),
            "/tmp/custom-assurance".to_owned(),
            "--profile".to_owned(),
            "release".to_owned(),
        ],
        &workspace_root,
    )
    .unwrap();

    assert_eq!(options.profile, AssuranceProfile::Release);
    assert_eq!(options.out_dir, Utf8PathBuf::from("/tmp/custom-assurance"));
}

#[test]
fn assurance_parse_supports_only_checks_flag() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions::parse(
        vec![
            "--only-checks".to_owned(),
            "rust-fmt,rust-clippy".to_owned(),
        ],
        &workspace_root,
    )
    .unwrap();

    assert_eq!(
        options.only_checks,
        Some(vec!["rust-fmt".to_owned(), "rust-clippy".to_owned()])
    );
}

#[test]
fn assurance_selected_specs_rejects_unknown_requested_check() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::Rust,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: Some(vec!["definitely-missing-check".to_owned()]),
    };

    let error = assurance_selected_specs(&workspace_root, &options)
        .unwrap_err()
        .to_string();

    assert!(error.contains("unknown assurance check id"));
}

#[test]
fn assurance_selected_specs_include_transitive_dependencies() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::ReactNative,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: Some(vec!["bindings-drift-check".to_owned()]),
    };

    let selected_specs = selected_assurance_specs(&workspace_root, &options);
    let ids = selected_specs
        .iter()
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        ids,
        BTreeSet::from(["bindings-generate", "bindings-drift-check"])
    );
}

#[test]
fn rust_pr_profile_uses_policy_checks_without_vet_or_advisories() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::Rust,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };

    let selected_specs = selected_assurance_specs(&workspace_root, &options);
    let ids = selected_specs
        .iter()
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();

    assert!(ids.contains("cargo-deny-policy"));
    assert!(!ids.contains("cargo-deny-advisories"));
    assert!(!ids.contains("cargo-vet"));
}

#[test]
fn fuzz_checks_are_nightly_only() {
    let workspace_root = workspace_root().unwrap();
    let nightly = AssuranceOptions {
        profile: AssuranceProfile::Nightly,
        runtime: AssuranceRuntime::Rust,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: false,
        only_checks: None,
    };
    let release = AssuranceOptions {
        profile: AssuranceProfile::Release,
        external_evidence_dir: Some(workspace_root.join("target/test-release-evidence")),
        ..nightly.clone()
    };

    let nightly_specs = selected_assurance_specs(&workspace_root, &nightly);
    let nightly_ids = nightly_specs
        .iter()
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();
    let release_specs = selected_assurance_specs(&workspace_root, &release);
    let release_ids = release_specs
        .iter()
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();

    assert!(nightly_ids.iter().any(|id| id.starts_with("fuzz-")));
    assert!(!release_ids.iter().any(|id| id.starts_with("fuzz-")));
}

#[test]
fn advisory_metadata_rejects_expired_review_dates() {
    let contents = r#"
[metadata.RUSTSEC-2099-0001]
owner = "sdk-core"
review_date = "2000-01-01"
exit_condition = "upgrade the dependency"
reachability = "transitive"
"#;

    let error = validate_advisory_metadata_sections(contents, &[String::from("RUSTSEC-2099-0001")])
        .unwrap_err()
        .to_string();

    assert!(error.contains("expired review_date"), "{error}");
}

#[test]
fn advisory_metadata_rejects_invalid_review_dates() {
    let contents = r#"
[metadata.RUSTSEC-2099-0002]
owner = "sdk-core"
review_date = "2026-02-30"
exit_condition = "upgrade the dependency"
reachability = "transitive"
"#;

    let error = validate_advisory_metadata_sections(contents, &[String::from("RUSTSEC-2099-0002")])
        .unwrap_err()
        .to_string();

    assert!(error.contains("invalid review_date"), "{error}");
}

#[test]
fn package_check_uses_workspace_dry_run() {
    let args = package_check_args(&[
        "privacy-pools-sdk".to_owned(),
        "privacy-pools-sdk-core".to_owned(),
    ]);

    assert!(args.contains(&"package".to_owned()));
    assert!(args.contains(&"--allow-dirty".to_owned()));
    assert!(args.contains(&"--no-verify".to_owned()));
    assert!(args.contains(&"--locked".to_owned()));
    assert!(args.contains(&"-p".to_owned()));
    assert!(args.contains(&"privacy-pools-sdk".to_owned()));
    assert!(args.contains(&"privacy-pools-sdk-core".to_owned()));
}

#[test]
fn mobile_smoke_evidence_accepts_passed_same_commit_statuses() {
    let commit = "abcdef0";
    let evidence = mobile_smoke_fixture(commit);

    validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit).unwrap();
}

#[test]
fn mobile_smoke_evidence_accepts_local_xtask_identity() {
    let commit = "abcdef0";
    let evidence = mobile_smoke_fixture_with_identity(
        commit,
        "local-xtask",
        "mobile-smoke-local",
        "local://mobile-smoke-local",
    );

    validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit).unwrap();
}

#[test]
fn mobile_smoke_evidence_rejects_commit_mismatch() {
    let evidence = mobile_smoke_fixture("abcdef0");

    let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), "1234567")
        .unwrap_err()
        .to_string();

    assert!(error.contains("commit mismatch"));
}

#[test]
fn mobile_smoke_evidence_rejects_failed_platform_status() {
    let commit = "abcdef0";
    let mut evidence = mobile_smoke_fixture(commit);
    evidence["android"] = json!("failed");

    let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
        .unwrap_err()
        .to_string();

    assert!(error.contains("android status"));
}

#[test]
fn mobile_smoke_evidence_rejects_missing_fields() {
    let commit = "abcdef0";
    let evidence = json!({
        "commit": commit,
        "source": "github-workflow",
        "workflow": "mobile-smoke",
        "ios": "passed",
        "android": "passed",
        "surfaces": {
            "iosNative": "passed",
            "iosReactNative": "passed",
            "androidNative": "passed",
            "androidReactNative": "passed",
        }
    });

    let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
        .unwrap_err()
        .to_string();

    assert!(error.contains("run_url"));
}

#[test]
fn mobile_smoke_evidence_rejects_malformed_source_workflow_pair() {
    let commit = "abcdef0";
    let evidence = mobile_smoke_fixture_with_identity(
        commit,
        "local-xtask",
        "mobile-smoke",
        "local://mobile-smoke-local",
    );

    let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
        .unwrap_err()
        .to_string();

    assert!(error.contains("workflow mismatch for local mobile evidence"));
}

#[test]
fn mobile_parity_evidence_accepts_valid_fixture() {
    let commit = "abcdef0";
    let evidence = mobile_parity_fixture(commit);

    let summary =
        validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit).unwrap();

    assert_eq!(summary["passed"], 32);
    assert_eq!(summary["failed"], 0);
}

#[test]
fn mobile_parity_evidence_accepts_local_xtask_identity() {
    let commit = "abcdef0";
    let evidence = mobile_parity_fixture_with_identity(
        commit,
        "local-xtask",
        "mobile-smoke-local",
        "local://mobile-smoke-local",
    );

    let summary =
        validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit).unwrap();

    assert_eq!(summary["passed"], 32);
    assert_eq!(summary["failed"], 0);
}

#[test]
fn mobile_parity_evidence_rejects_commit_mismatch() {
    let evidence = mobile_parity_fixture("abcdef0");

    let error = validate_mobile_parity_evidence_value(&evidence, &evidence_path(), "1234567")
        .unwrap_err()
        .to_string();

    assert!(error.contains("commit mismatch"));
}

#[test]
fn mobile_parity_evidence_rejects_missing_samples() {
    let commit = "abcdef0";
    let mut evidence = mobile_parity_fixture(commit);
    evidence["ios"]["native"]["benchmark"]["samples"] = json!([]);

    let error = validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit)
        .unwrap_err()
        .to_string();

    assert!(error.contains("benchmark.samples"));
}

#[test]
fn browser_comparison_report_requires_all_timing_slices() {
    let temp = tempfile::tempdir().unwrap();
    let path = Utf8PathBuf::from_path_buf(temp.path().join("v1-npm-comparison.json")).unwrap();
    let mut report = browser_comparison_report();
    report["browserPerformance"]["withdrawal"]["directCold"]["slices"]
        .as_object_mut()
        .unwrap()
        .remove("witnessTransferMs");
    write_json(&path, &report);

    let error = validate_browser_comparison_report(&path)
        .unwrap_err()
        .to_string();

    assert!(error.contains("witnessTransferMs"));
}

#[test]
fn signed_manifest_evidence_accepts_valid_fixture() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let public_key = write_signed_manifest_fixture(&dir);

    let verified = validate_signed_manifest_evidence(&dir, Some(&public_key))
        .unwrap()
        .unwrap();

    assert_eq!(verified, ("signed-fixture".to_owned(), 1));
}

#[test]
fn signed_manifest_evidence_rejects_missing_public_key() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    write_signed_manifest_fixture(&dir);

    let error = validate_signed_manifest_evidence(&dir, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed-manifest-public-key"));
}

#[test]
fn signed_manifest_evidence_rejects_wrong_public_key() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    write_signed_manifest_fixture(&dir);
    let wrong_key = hex::encode(
        SigningKey::from_bytes(&[9_u8; 32])
            .verifying_key()
            .to_bytes(),
    );

    let error = validate_signed_manifest_evidence(&dir, Some(&wrong_key))
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed artifact manifest validation failed"));
}

#[test]
fn signed_manifest_evidence_rejects_bad_signature() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let public_key = write_signed_manifest_fixture(&dir);
    fs::write(
        dir.join("signed-artifact-manifest.signature"),
        "00".repeat(64),
    )
    .unwrap();

    let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed artifact manifest validation failed"));
}

#[test]
fn signed_manifest_evidence_rejects_modified_payload() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let public_key = write_signed_manifest_fixture(&dir);
    let mut payload =
        fs::read_to_string(dir.join("signed-artifact-manifest.payload.json")).unwrap();
    payload.push('\n');
    fs::write(dir.join("signed-artifact-manifest.payload.json"), payload).unwrap();

    let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed artifact manifest validation failed"));
}

#[test]
fn signed_manifest_evidence_rejects_missing_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let public_key = write_signed_manifest_fixture(&dir);
    fs::remove_file(
        dir.join("signed-artifact-manifest-artifacts")
            .join("withdraw-fixture.wasm"),
    )
    .unwrap();

    let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed artifact manifest validation failed"));
}

#[test]
fn signed_manifest_evidence_rejects_hash_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let public_key = write_signed_manifest_fixture(&dir);
    fs::write(
        dir.join("signed-artifact-manifest-artifacts")
            .join("withdraw-fixture.wasm"),
        b"tampered",
    )
    .unwrap();

    let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
        .unwrap_err()
        .to_string();

    assert!(error.contains("signed artifact manifest validation failed"));
}

#[test]
fn evidence_check_accepts_complete_same_commit_alpha_fixture() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = "abcdef0";
    let public_key = write_external_evidence_fixture(&dir, commit);

    evidence_check(vec![
        "--channel".to_owned(),
        "alpha".to_owned(),
        "--dir".to_owned(),
        dir.to_string(),
        "--signed-manifest-public-key".to_owned(),
        public_key,
    ])
    .unwrap();
}

#[test]
fn scenario_coverage_requires_mobile_evidence_for_react_native_nightly() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Nightly,
        runtime: AssuranceRuntime::ReactNative,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };
    let selected_specs = selected_assurance_specs(&workspace_root, &options);

    let error = validate_scenario_coverage(&workspace_root, &options, &selected_specs)
        .unwrap_err()
        .to_string();

    assert!(error.contains("wrong-root-rejection"));
}

#[test]
fn scenario_coverage_accepts_react_native_nightly_with_external_evidence() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let evidence_dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &evidence_dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &evidence_dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );
    let options = AssuranceOptions {
        profile: AssuranceProfile::Nightly,
        runtime: AssuranceRuntime::ReactNative,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: Some(evidence_dir),
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };
    let selected_specs = selected_assurance_specs(&workspace_root, &options);

    validate_scenario_coverage(&workspace_root, &options, &selected_specs).unwrap();
}

#[test]
fn nightly_assessment_defaults_mobile_and_reference_to_not_run_and_missing() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Nightly,
        runtime: AssuranceRuntime::All,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };

    let assessment = assurance_assessment(&options, &[], None);

    assert_eq!(assessment["mobileAppEvidence"], "not-run");
    assert_eq!(assessment["referencePerformance"], "missing");
}

#[test]
fn scenario_coverage_rejects_proxy_only_checks() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::Node,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };
    let mut selected_specs = selected_assurance_specs(&workspace_root, &options);

    for spec in &mut selected_specs {
        match spec.id.as_str() {
            "sdk-node-smoke" => {
                spec.scenario_tags
                    .push("manifest-artifact-tamper-rejection".to_owned());
            }
            "sdk-node-fail-closed-checks" => {
                spec.scenario_tags
                    .retain(|tag| tag != "manifest-artifact-tamper-rejection");
            }
            _ => {}
        }
    }

    let error = validate_scenario_coverage(&workspace_root, &options, &selected_specs)
        .unwrap_err()
        .to_string();

    assert!(error.contains("relies only on proxy checks"));
    assert!(error.contains("sdk-node-smoke"));
}

#[test]
fn pr_browser_profile_skips_v1_npm_smoke_compare() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::Browser,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };

    let selected_specs = selected_assurance_specs(&workspace_root, &options);

    assert!(
        !selected_specs
            .iter()
            .any(|spec| spec.id == "compare-v1-npm-smoke"),
        "pr browser profile should not include compare-v1-npm-smoke"
    );
    for required in [
        "sdk-browser-build",
        "sdk-browser-smoke",
        "sdk-browser-generated-drift-check",
        "sdk-browser-fail-closed-checks",
        "sdk-browser-worker-suite",
    ] {
        assert!(
            selected_specs.iter().any(|spec| spec.id == required),
            "pr browser profile should include {required}"
        );
    }
    for excluded in [
        "sdk-browser-core",
        "sdk-browser-direct-execution",
        "browser-threaded-build",
        "browser-threaded-drift-check",
    ] {
        assert!(
            !selected_specs.iter().any(|spec| spec.id == excluded),
            "pr browser profile should exclude {excluded}"
        );
    }
}

#[test]
fn nightly_external_evidence_reports_missing_reference_benchmarks() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );

    let evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Nightly,
        BenchmarkBackendProfile::Stable,
        &commit,
        None,
    )
    .unwrap();

    assert_eq!(evidence["referencePerformance"]["status"], "missing");
}

#[test]
fn nightly_external_evidence_reports_stale_reference_benchmarks() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );
    let benchmark_dir = dir.join("benchmarks");
    fs::create_dir_all(&benchmark_dir).unwrap();
    for file in [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "browser-desktop-threaded.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ] {
        write_json(
            &benchmark_dir.join(file),
            &benchmark_report("1234567", file),
        );
    }

    let evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Nightly,
        BenchmarkBackendProfile::Stable,
        &commit,
        None,
    )
    .unwrap();

    assert_eq!(evidence["referencePerformance"]["status"], "stale");
    assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 6);
}

#[test]
fn nightly_external_evidence_reports_missing_for_incomplete_reference_benchmarks() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );
    let benchmark_dir = dir.join("benchmarks");
    fs::create_dir_all(&benchmark_dir).unwrap();
    write_json(
        &benchmark_dir.join("rust-desktop-stable.json"),
        &benchmark_report(&commit, "rust-desktop-stable.json"),
    );

    let evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Nightly,
        BenchmarkBackendProfile::Stable,
        &commit,
        None,
    )
    .unwrap();

    assert_eq!(evidence["referencePerformance"]["status"], "missing");
    assert!(
        evidence["referencePerformance"]["error"]
            .as_str()
            .is_some_and(|value| value.contains("incomplete"))
    );
}

#[test]
fn nightly_external_evidence_reports_fresh_reference_benchmarks() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );
    let benchmark_dir = dir.join("benchmarks");
    fs::create_dir_all(&benchmark_dir).unwrap();
    for file in [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "browser-desktop-threaded.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ] {
        write_json(&benchmark_dir.join(file), &benchmark_report(&commit, file));
    }

    let evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Nightly,
        BenchmarkBackendProfile::Stable,
        &commit,
        None,
    )
    .unwrap();

    assert_eq!(evidence["referencePerformance"]["status"], "fresh");
    assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 6);
}

#[test]
fn release_external_evidence_assembly_allows_missing_reference_benchmarks() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let mobile_dir = root.join("mobile");
    fs::create_dir_all(&mobile_dir).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    write_json(
        &mobile_dir.join("mobile-smoke.json"),
        &mobile_smoke_fixture(&commit),
    );
    write_json(
        &mobile_dir.join("mobile-parity.json"),
        &mobile_parity_fixture(&commit),
    );
    let sbom_dir = root.join("sbom-inputs");
    let sbom_root = sbom_dir.join("sbom");
    fs::create_dir_all(&sbom_root).unwrap();
    write_json(
        &sbom_root.join("rust.cdx.json"),
        &json!({ "bomFormat": "CycloneDX" }),
    );
    write_json(
        &sbom_root.join("sdk.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );
    write_json(
        &sbom_root.join("react-native.spdx.json"),
        &json!({ "spdxVersion": "SPDX-2.3" }),
    );
    let packages_dir = root.join("package-inputs");
    let package_root = packages_dir.join("packages");
    fs::create_dir_all(&package_root).unwrap();
    let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(&root, &package_root);
    let react_native_package_path = write_react_native_package_fixture(&package_root);
    let circuits_root = package_root.join("circuits");
    fs::create_dir_all(&circuits_root).unwrap();
    let circuit_archive = circuits_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
    let status = Command::new("tar")
        .args([
            "-C",
            workspace_root.join("fixtures").as_str(),
            "-czf",
            circuit_archive.as_str(),
            "artifacts",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let attestation_dir = root.join("attestation-inputs");
    fs::create_dir_all(&attestation_dir).unwrap();
    let repo = current_github_repository_slug(&workspace_root).unwrap();
    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sha256_hex(&fs::read(&sdk_package_path).unwrap()),
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sha256_hex(&fs::read(&sdk_wasm_path).unwrap()),
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &sha256_hex(&fs::read(&react_native_package_path).unwrap()),
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &sha256_hex(&fs::read(&circuit_archive).unwrap()),
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );
    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: None,
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };

    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    assert_eq!(manifest["referencePerformance"]["status"], "missing");
}

#[test]
fn release_external_evidence_assembly_requires_remaining_inputs() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);

    let cases = [
        (
            "--mobile-evidence-dir",
            ExternalEvidenceAssembleOptions {
                mode: ExternalEvidenceMode::Release,
                out_dir: root.join("assembled-missing-mobile"),
                mobile_evidence_dir: None,
                reference_benchmarks_dir: Some(reference_dir.clone()),
                sbom_dir: Some(sbom_dir.clone()),
                packages_dir: Some(packages_dir.clone()),
                attestation_metadata_dir: Some(attestation_dir.clone()),
            },
        ),
        (
            "--sbom-dir",
            ExternalEvidenceAssembleOptions {
                mode: ExternalEvidenceMode::Release,
                out_dir: root.join("assembled-missing-sbom"),
                mobile_evidence_dir: Some(mobile_dir.clone()),
                reference_benchmarks_dir: Some(reference_dir.clone()),
                sbom_dir: None,
                packages_dir: Some(packages_dir.clone()),
                attestation_metadata_dir: Some(attestation_dir.clone()),
            },
        ),
        (
            "--packages-dir",
            ExternalEvidenceAssembleOptions {
                mode: ExternalEvidenceMode::Release,
                out_dir: root.join("assembled-missing-packages"),
                mobile_evidence_dir: Some(mobile_dir.clone()),
                reference_benchmarks_dir: Some(reference_dir.clone()),
                sbom_dir: Some(sbom_dir.clone()),
                packages_dir: None,
                attestation_metadata_dir: Some(attestation_dir.clone()),
            },
        ),
        (
            "--attestation-metadata-dir",
            ExternalEvidenceAssembleOptions {
                mode: ExternalEvidenceMode::Release,
                out_dir: root.join("assembled-missing-attestations"),
                mobile_evidence_dir: Some(mobile_dir.clone()),
                reference_benchmarks_dir: Some(reference_dir.clone()),
                sbom_dir: Some(sbom_dir.clone()),
                packages_dir: Some(packages_dir.clone()),
                attestation_metadata_dir: None,
            },
        ),
    ];

    for (expected_flag, options) in cases {
        let error = assemble_external_evidence_dir(&workspace_root, &options, &commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains(expected_flag), "{error}");
    }
}

#[test]
fn release_external_evidence_assembly_accepts_complete_inputs() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);
    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };

    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    assert_eq!(manifest["mobileEvidence"]["status"], "pass");
    assert_eq!(manifest["referencePerformance"]["status"], "fresh");

    let public_key = read_required_text_file(
        &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
    )
    .unwrap();
    let evidence = validate_external_evidence_dir(
        &workspace_root,
        &options.out_dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap();

    assert_eq!(evidence["attestationCount"], 4);
    assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 6);
    assert_eq!(
        evidence["signedManifestPackageBinding"]["subjectPath"],
        "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
    );
    assert_eq!(
        evidence["sdkWebPackageBinding"]["packageSubjectPath"],
        "packages/sdk/privacy-pools-sdk-alpha.tgz"
    );
    assert_eq!(
        evidence["sdkWebPackageBinding"]["wasmSubjectPath"],
        "packages/sdk/privacy_pools_sdk_web_bg.wasm"
    );
}

#[test]
fn release_external_evidence_assembly_accepts_local_mobile_evidence() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let local_mobile_smoke = mobile_smoke_fixture_with_identity(
        &commit,
        "local-xtask",
        "mobile-smoke-local",
        "local://mobile-smoke-local",
    );
    let local_mobile_parity = mobile_parity_fixture_with_identity(
        &commit,
        "local-xtask",
        "mobile-smoke-local",
        "local://mobile-smoke-local",
    );
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs_with_mobile_fixtures(
            &root,
            &local_mobile_smoke,
            &local_mobile_parity,
        );
    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled-local"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };

    let public_key = read_required_text_file(
        &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
    )
    .unwrap();
    assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    validate_external_evidence_dir(
        &workspace_root,
        &options.out_dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap();
}

#[test]
fn release_external_evidence_assembly_rejects_browser_wasm_attestation_mismatch() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);
    let repo = current_github_repository_slug(&workspace_root).unwrap();
    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &"00".repeat(32),
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &sha256_hex(
                    &fs::read(
                        packages_dir
                            .join("packages/react-native/privacy-pools-sdk-react-native-alpha.tgz")
                    )
                    .unwrap()
                ),
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &sha256_hex(
                    &fs::read(packages_dir.join(
                        "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
                    ))
                    .unwrap()
                ),
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled-digest-mismatch"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };

    let error = assemble_external_evidence_dir(&workspace_root, &options, &commit)
        .unwrap_err()
        .to_string();

    assert!(error.contains("attestation sha256 mismatch"), "{error}");
}

#[test]
fn release_external_evidence_rejects_browser_package_wasm_mismatch() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);
    let wasm_path = packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm");
    fs::write(&wasm_path, b"tampered browser wasm").unwrap();
    let repo = current_github_repository_slug(&workspace_root).unwrap();

    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sha256_hex(&fs::read(&wasm_path).unwrap()),
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &sha256_hex(
                    &fs::read(
                        packages_dir
                            .join("packages/react-native/privacy-pools-sdk-react-native-alpha.tgz")
                    )
                    .unwrap()
                ),
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &sha256_hex(
                    &fs::read(packages_dir.join(
                        "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
                    ))
                    .unwrap()
                ),
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled-browser-wasm-mismatch"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };
    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    let public_key = read_required_text_file(
        &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
    )
    .unwrap();

    let error = validate_external_evidence_dir(
        &workspace_root,
        &options.out_dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert_eq!(manifest["referencePerformance"]["status"], "fresh");
    assert!(error.contains("packaged browser WASM mismatch"), "{error}");
}

#[test]
fn evidence_check_accepts_malformed_optional_reference_benchmarks() {
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = "abcdef0";
    let public_key = write_external_evidence_fixture(&dir, commit);
    fs::write(dir.join("benchmarks/rust-desktop-stable.json"), "{").unwrap();

    evidence_check(vec![
        "--channel".to_owned(),
        "alpha".to_owned(),
        "--dir".to_owned(),
        dir.to_string(),
        "--signed-manifest-public-key".to_owned(),
        public_key,
    ])
    .unwrap();
}

#[test]
fn blocked_dependencies_report_failed_prerequisites() {
    let mut statuses = BTreeMap::new();
    statuses.insert("sdk-browser-build".to_owned(), "failed".to_owned());
    statuses.insert(
        "external-evidence-validation".to_owned(),
        "passed".to_owned(),
    );
    let spec = assurance_check_with_dependencies(
        assurance_check_spec(
            "sdk-browser-smoke",
            "npm run test:browser:smoke",
            vec![AssuranceRuntime::Browser],
            "correctness",
            AssuranceCheckMode::Normative,
            "npm",
            vec!["run".to_owned(), "test:browser:smoke".to_owned()],
            Utf8PathBuf::from("packages/sdk"),
            vec![],
            "sdk-browser-smoke.log",
            vec![],
            None,
        ),
        vec![
            "sdk-browser-build".to_owned(),
            "external-evidence-validation".to_owned(),
        ],
    );

    assert_eq!(
        blocked_dependencies(&spec, &statuses),
        vec!["sdk-browser-build".to_owned()]
    );
}

#[test]
fn browser_goldens_depend_on_browser_build() {
    let workspace_root = workspace_root().unwrap();
    let options = AssuranceOptions {
        profile: AssuranceProfile::Pr,
        runtime: AssuranceRuntime::Browser,
        report_mode: AssuranceReportMode::Standard,
        out_dir: workspace_root.join("target/test-assurance"),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: "fixture".to_owned(),
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 8,
        skip_fuzz: true,
        only_checks: None,
    };

    let selected_specs = selected_assurance_specs(&workspace_root, &options);
    let spec = selected_specs
        .iter()
        .find(|spec| spec.id == "compare-rust-goldens-browser")
        .unwrap();
    assert_eq!(spec.depends_on, vec!["sdk-browser-build".to_owned()]);

    let mut statuses = BTreeMap::new();
    statuses.insert("sdk-browser-build".to_owned(), "failed".to_owned());
    assert_eq!(
        blocked_dependencies(spec, &statuses),
        vec!["sdk-browser-build".to_owned()]
    );
}

#[test]
fn browser_smoke_is_not_treated_as_proxy_coverage() {
    assert!(!is_proxy_scenario_check_id("sdk-browser-smoke"));
}

#[test]
fn assurance_merge_rejects_duplicate_check_ids() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let input_a =
        write_assurance_merge_fixture(&root.join("assurance-pr-rust-core"), &commit, &["rust-fmt"]);
    let input_b = write_assurance_merge_fixture(
        &root.join("assurance-pr-rust-generated"),
        &commit,
        &["rust-fmt"],
    );

    let error = merge_assurance_outputs(
        &workspace_root,
        &AssuranceMergeOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            out_dir: root.join("merged"),
            inputs: vec![input_a, input_b],
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("duplicate check id `rust-fmt`"));
}

#[test]
fn assurance_merge_reports_missing_subgroup_artifacts() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let missing = root.join("assurance-pr-rust-core");

    let error = merge_assurance_outputs(
        &workspace_root,
        &AssuranceMergeOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            out_dir: root.join("merged"),
            inputs: vec![missing.clone()],
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("missing subgroup assurance artifact"));
    assert!(error.contains(missing.as_str()));
}

#[test]
fn assurance_merge_uses_staged_logs_for_downloaded_artifacts() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let original_root = Utf8PathBuf::from("/tmp/original-assurance-pr-rust-core");
    let input = write_assurance_merge_fixture_with_original_root(
        &root.join("assurance-pr-rust-core"),
        &original_root,
        &commit,
        &["rust-fmt"],
    );
    let merged_out = root.join("merged");

    let error = merge_assurance_outputs(
        &workspace_root,
        &AssuranceMergeOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            out_dir: merged_out.clone(),
            inputs: vec![input],
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("missing required checks"));
    let merged_log = fs::read_to_string(merged_out.join("logs/rust-core-rust-fmt.log")).unwrap();
    assert!(merged_log.contains("rust-fmt ok"));
    let merged_check = read_required_json(&merged_out.join("checks/rust-fmt.json")).unwrap();
    assert_eq!(
        merged_check["expectedOutputs"][0].as_str().unwrap(),
        merged_out
            .join("groups/rust-core/outputs/rust-fmt.txt")
            .as_str()
    );
}

#[test]
fn assurance_merge_writes_failure_bundle_for_malformed_subgroup_index() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let input = root.join("assurance-pr-rust-core");
    fs::create_dir_all(&input).unwrap();
    write_json(
        &input.join("environment.json"),
        &json!({
            "gitCommit": commit,
            "profile": "pr",
            "runtime": "rust",
            "status": "passed",
        }),
    );
    fs::write(input.join("assurance-index.json"), "{").unwrap();
    let merged_out = root.join("merged");

    let error = merge_assurance_outputs(
        &workspace_root,
        &AssuranceMergeOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            out_dir: merged_out.clone(),
            inputs: vec![input],
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("failed to load subgroup index"));
    assert!(merged_out.join("assurance-index.json").exists());
    assert!(merged_out.join("findings.md").exists());
    let merged_index = read_required_json(&merged_out.join("assurance-index.json")).unwrap();
    assert!(
        merged_index["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "invalid-rust-core-index")
    );
}

#[test]
fn release_external_evidence_rejects_missing_attestation_verification_file() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let public_key = write_external_evidence_fixture(&dir, &commit);
    let records = read_attestation_records(&dir.join("attestations.json"));
    let verification_path = dir.join(&records[0].verification_path);
    fs::remove_file(&verification_path).unwrap();

    let error = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("attestation verificationPath does not exist"));
}

#[test]
fn release_external_evidence_rejects_malformed_attestation_verification_file() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let public_key = write_external_evidence_fixture(&dir, &commit);
    let records = read_attestation_records(&dir.join("attestations.json"));
    fs::write(dir.join(&records[0].verification_path), "{").unwrap();

    let error = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("failed to parse") && error.contains("attestation-verification"),
        "{error}"
    );
}

#[test]
fn release_external_evidence_rejects_attestation_verification_digest_mismatch() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let public_key = write_external_evidence_fixture(&dir, &commit);
    let records = read_attestation_records(&dir.join("attestations.json"));
    let record = &records[0];
    let repo = current_github_repository_slug(&workspace_root).unwrap();
    let mut verification =
        attestation_verification_fixture(&record.subject_path, &record.sha256, &repo);
    verification["subjectSha256"] = json!("00".repeat(32));
    overwrite_attestation_verification(&dir, record, &verification);

    let error = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("attestation verification sha256 mismatch"));
}

#[test]
fn release_external_evidence_rejects_attestation_verification_repo_mismatch() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let public_key = write_external_evidence_fixture(&dir, &commit);
    let records = read_attestation_records(&dir.join("attestations.json"));
    let record = &records[0];
    let verification =
        attestation_verification_fixture(&record.subject_path, &record.sha256, "wrong/repo");
    overwrite_attestation_verification(&dir, record, &verification);

    let error = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("attestation verification repo mismatch"));
}

#[test]
fn release_external_evidence_rejects_attestation_verification_workflow_mismatch() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let public_key = write_external_evidence_fixture(&dir, &commit);
    let records = read_attestation_records(&dir.join("attestations.json"));
    let record = &records[0];
    let repo = current_github_repository_slug(&workspace_root).unwrap();
    let mut verification =
        attestation_verification_fixture(&record.subject_path, &record.sha256, &repo);
    verification["signerWorkflow"] = json!("wrong/repo/.github/workflows/other.yml");
    overwrite_attestation_verification(&dir, record, &verification);

    let error = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("attestation signer workflow mismatch"));
}

#[test]
fn release_external_evidence_rejects_duplicate_circuit_attestation_subjects() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);
    let packages_root = packages_dir.join("packages/circuits");
    let source_archive = packages_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
    let duplicate_archive = packages_root.join("privacy-pools-sdk-circuit-artifacts-beta.tar.gz");
    fs::copy(&source_archive, &duplicate_archive).unwrap();
    let repo = current_github_repository_slug(&workspace_root).unwrap();

    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &sha256_hex(
                    &fs::read(
                        packages_dir
                            .join("packages/react-native/privacy-pools-sdk-react-native-alpha.tgz")
                    )
                    .unwrap()
                ),
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &sha256_hex(&fs::read(&source_archive).unwrap()),
                "https://example.invalid/attestations/circuits-alpha",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-beta.tar.gz",
                &sha256_hex(&fs::read(&duplicate_archive).unwrap()),
                "https://example.invalid/attestations/circuits-beta",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled-duplicate-circuits"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };
    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    let public_key = read_required_text_file(
        &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
    )
    .unwrap();

    let error = validate_external_evidence_dir(
        &workspace_root,
        &options.out_dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(manifest["referencePerformance"]["status"].is_string());
    assert!(error.contains("exactly one"), "{error}");
}

#[test]
fn release_external_evidence_rejects_tampered_top_level_circuit_artifacts() {
    let workspace_root = workspace_root().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
    let commit = current_git_commit(&workspace_root).unwrap();
    let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
        write_release_assembly_inputs(&root, &commit);
    let circuit_archive =
        packages_dir.join("packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
    let unpacked = root.join("tampered-circuit");
    fs::create_dir_all(&unpacked).unwrap();
    let status = Command::new("tar")
        .args(["-xzf", circuit_archive.as_str(), "-C", unpacked.as_str()])
        .status()
        .unwrap();
    assert!(status.success());
    fs::write(
        unpacked.join("artifacts/withdraw-fixture.wasm"),
        b"tampered packaged circuit artifact",
    )
    .unwrap();
    let status = Command::new("tar")
        .args([
            "-C",
            unpacked.as_str(),
            "-czf",
            circuit_archive.as_str(),
            "artifacts",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let repo = current_github_repository_slug(&workspace_root).unwrap();
    write_json(
        &attestation_dir.join("records.json"),
        &json!([
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy-pools-sdk-alpha.tgz",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                &sha256_hex(
                    &fs::read(packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm"))
                        .unwrap()
                ),
                "https://example.invalid/attestations/sdk-wasm",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                &sha256_hex(
                    &fs::read(
                        packages_dir
                            .join("packages/react-native/privacy-pools-sdk-react-native-alpha.tgz")
                    )
                    .unwrap()
                ),
                "https://example.invalid/attestations/react-native",
                "https://example.invalid/workflows/release",
                &repo
            ),
            attestation_record_fixture(
                &attestation_dir,
                "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                &sha256_hex(&fs::read(&circuit_archive).unwrap()),
                "https://example.invalid/attestations/circuits",
                "https://example.invalid/workflows/release",
                &repo
            )
        ]),
    );

    let options = ExternalEvidenceAssembleOptions {
        mode: ExternalEvidenceMode::Release,
        out_dir: root.join("assembled-tampered-circuit"),
        mobile_evidence_dir: Some(mobile_dir),
        reference_benchmarks_dir: Some(reference_dir),
        sbom_dir: Some(sbom_dir),
        packages_dir: Some(packages_dir),
        attestation_metadata_dir: Some(attestation_dir),
    };
    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
    let public_key = read_required_text_file(
        &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
    )
    .unwrap();

    let error = validate_external_evidence_dir(
        &workspace_root,
        &options.out_dir,
        AssuranceProfile::Release,
        BenchmarkBackendProfile::Stable,
        &commit,
        Some(&public_key),
    )
    .unwrap_err()
    .to_string();

    assert!(manifest["referencePerformance"]["status"].is_string());
    assert!(
        error.contains("does not match embedded signed manifest"),
        "{error}"
    );
}
