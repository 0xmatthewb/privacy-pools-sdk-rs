fn trusted_artifact_environment(workspace_root: &Utf8PathBuf) -> Result<Value> {
    Ok(json!({
        "snapshotPath": workspace_root.join("fixtures/artifacts/fingerprints.lock.json").as_str(),
        "fingerprints": artifact_fingerprint_snapshot(workspace_root)?,
    }))
}

fn artifact_fingerprint_snapshot(workspace_root: &Utf8PathBuf) -> Result<Value> {
    let artifacts_root = workspace_root.join("fixtures/artifacts");
    Ok(json!({
        "artifactsRoot": "fixtures/artifacts",
        "manifests": {
            "commitment": manifest_fingerprint(
                &artifacts_root,
                &artifacts_root.join("commitment-proving-manifest.json"),
            )?,
            "withdrawal": manifest_fingerprint(
                &artifacts_root,
                &artifacts_root.join("withdrawal-proving-manifest.json"),
            )?,
        },
    }))
}

fn manifest_fingerprint(
    artifacts_root: &Utf8PathBuf,
    manifest_path: &Utf8PathBuf,
) -> Result<Value> {
    let manifest_bytes =
        fs::read(manifest_path).with_context(|| format!("failed to read {}", manifest_path))?;
    let manifest_json: Value = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("failed to parse {}", manifest_path))?;
    let artifacts = manifest_json
        .get("artifacts")
        .and_then(Value::as_array)
        .with_context(|| format!("{} missing `artifacts` array", manifest_path))?;

    let mut bundle_entries = Vec::new();
    let mut artifact_records = Vec::new();
    let mut vkey_sha256 = None::<String>;

    for artifact in artifacts {
        let filename = artifact
            .get("filename")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing filename", manifest_path))?;
        let kind = artifact
            .get("kind")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing kind", manifest_path))?;
        let circuit = artifact
            .get("circuit")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing circuit", manifest_path))?;
        let path = artifacts_root.join(filename);
        let sha256 = if path.exists() {
            sha256_hex(&fs::read(&path).with_context(|| format!("failed to read {}", path))?)
        } else {
            artifact
                .get("sha256")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .with_context(|| format!("{} missing sha256 for {}", manifest_path, filename))?
        };
        if kind == "vkey" {
            vkey_sha256 = Some(sha256.clone());
        }
        bundle_entries.push(format!("{circuit}:{kind}:{filename}:{sha256}"));
        artifact_records.push(json!({
            "circuit": circuit,
            "kind": kind,
            "filename": filename,
            "sha256": sha256,
        }));
    }
    bundle_entries.sort_unstable();
    artifact_records
        .sort_by(|left, right| left["filename"].as_str().cmp(&right["filename"].as_str()));

    Ok(json!({
        "manifestSha256": sha256_hex(&manifest_bytes),
        "artifactBundleSha256": sha256_hex(bundle_entries.join("\n").as_bytes()),
        "vkeyFingerprint": vkey_sha256,
        "artifacts": artifact_records,
    }))
}

fn validate_external_evidence(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    commit: &str,
) -> Result<Option<Value>> {
    let Some(dir) = options.external_evidence_dir.as_ref() else {
        return Ok(None);
    };
    validate_external_evidence_dir(
        workspace_root,
        dir,
        options.profile,
        options.backend,
        commit,
        None,
    )
    .map(Some)
}

fn validate_mobile_evidence_subset(
    dir: &Utf8PathBuf,
    expected_commit: &str,
    required: bool,
) -> Result<Value> {
    let mobile_smoke_path = dir.join("mobile-smoke.json");
    let mobile_parity_path = dir.join("mobile-parity.json");
    let mobile_smoke_exists = mobile_smoke_path.exists();
    let mobile_parity_exists = mobile_parity_path.exists();

    ensure!(
        mobile_smoke_exists == mobile_parity_exists,
        "external mobile evidence in {} must contain both mobile-smoke.json and mobile-parity.json",
        dir
    );

    if !mobile_smoke_exists {
        ensure!(
            !required,
            "external evidence directory is missing mobile app evidence in {}",
            dir
        );
        return Ok(json!({
            "status": AssessmentStatus::NotRun.as_str(),
            "mobileSmokePath": Value::Null,
            "mobileParityPath": Value::Null,
            "mobileParity": Value::Null,
        }));
    }

    validate_mobile_smoke_evidence(&mobile_smoke_path, expected_commit)?;
    let mobile_parity = validate_mobile_parity_evidence(&mobile_parity_path, expected_commit)?;

    Ok(json!({
        "status": AssessmentStatus::Pass.as_str(),
        "mobileSmokePath": mobile_smoke_path.as_str(),
        "mobileParityPath": mobile_parity_path.as_str(),
        "mobileParity": mobile_parity,
    }))
}

fn mobile_evidence_files_present(dir: &Utf8PathBuf) -> bool {
    dir.join("mobile-smoke.json").exists() && dir.join("mobile-parity.json").exists()
}

fn reference_device_registry(workspace_root: &Utf8PathBuf) -> Result<ReferenceDeviceRegistry> {
    let registry_path = workspace_root.join("security/reference-devices.json");
    serde_json::from_value(read_required_json(&registry_path)?)
        .with_context(|| format!("failed to parse {}", registry_path))
}

fn validate_reference_benchmark_evidence(
    workspace_root: &Utf8PathBuf,
    benchmark_dir: &Utf8PathBuf,
    _profile: AssuranceProfile,
    backend: BenchmarkBackendProfile,
    commit: &str,
) -> Result<Value> {
    let required_benchmark_files = [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ];
    let optional_benchmark_files = ["browser-desktop-threaded.json"];
    let existing_count = required_benchmark_files
        .iter()
        .filter(|file| benchmark_dir.join(file).exists())
        .count();

    if existing_count == 0 {
        return Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
        }));
    }

    if existing_count != required_benchmark_files.len() {
        return Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
            "error": format!(
                "reference benchmark evidence in {} is incomplete: expected {} reports but found {}",
                benchmark_dir,
                required_benchmark_files.len(),
                existing_count
            ),
        }));
    }

    let validate_complete = || -> Result<Value> {
        let registry = reference_device_registry(workspace_root)?;
        let expected_backend_profile = backend.report_label();
        let mut benchmark_summaries = Vec::new();
        let mut reference_device_ids = BTreeSet::new();
        let mut artifact_version = None::<String>;
        let mut zkey_sha256 = None::<String>;
        let mut manifest_sha256 = None::<String>;
        let mut artifact_bundle_sha256 = None::<String>;
        let mut reference_status = ReferencePerformanceStatus::Fresh;

        for benchmark_file in required_benchmark_files.into_iter().chain(
            optional_benchmark_files
                .into_iter()
                .filter(|file| benchmark_dir.join(file).exists()),
        ) {
            let path = benchmark_dir.join(benchmark_file);
            let expected_device_label = if benchmark_file.contains("-ios-") {
                "ios"
            } else if benchmark_file.contains("-android-") {
                "android"
            } else {
                "desktop"
            };
            let metadata = validate_benchmark_report_with_commit_policy(
                &path,
                commit,
                expected_device_label,
                expected_backend_profile,
                backend.as_str(),
                true,
            )
            .with_context(|| format!("invalid benchmark report for {}", benchmark_file))?;

            if metadata.git_commit != commit {
                reference_status = ReferencePerformanceStatus::Stale;
            }

            match &artifact_version {
                Some(expected) => ensure!(
                    metadata.artifact_version == *expected,
                    "{} artifact_version mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.artifact_version
                ),
                None => artifact_version = Some(metadata.artifact_version.clone()),
            }
            match &zkey_sha256 {
                Some(expected) => ensure!(
                    metadata.zkey_sha256 == *expected,
                    "{} zkey_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.zkey_sha256
                ),
                None => zkey_sha256 = Some(metadata.zkey_sha256.clone()),
            }
            match &manifest_sha256 {
                Some(expected) => ensure!(
                    metadata.manifest_sha256 == *expected,
                    "{} manifest_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.manifest_sha256
                ),
                None => manifest_sha256 = Some(metadata.manifest_sha256.clone()),
            }
            match &artifact_bundle_sha256 {
                Some(expected) => ensure!(
                    metadata.artifact_bundle_sha256 == *expected,
                    "{} artifact_bundle_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.artifact_bundle_sha256
                ),
                None => artifact_bundle_sha256 = Some(metadata.artifact_bundle_sha256.clone()),
            }

            let device = registry
                .devices
                .iter()
                .find(|device| {
                    device.label == metadata.device_label
                        && device.model == metadata.device_model
                        && device.device_class == metadata.device_class
                        && device.evidence.iter().any(|entry| entry == benchmark_file)
                })
                .with_context(|| {
                    format!(
                        "{} does not match any entry in {}",
                        path,
                        workspace_root.join("security/reference-devices.json")
                    )
                })?;
            reference_device_ids.insert(device.id.clone());
            benchmark_summaries.push(json!({
                "path": path.as_str(),
                "deviceId": device.id,
                "deviceLabel": metadata.device_label,
                "deviceModel": metadata.device_model,
                "deviceClass": metadata.device_class,
                "benchmarkScenarioId": metadata.benchmark_scenario_id,
                "artifactVersion": metadata.artifact_version,
                "manifestSha256": metadata.manifest_sha256,
                "artifactBundleSha256": metadata.artifact_bundle_sha256,
                "gitCommit": metadata.git_commit,
            }));
        }

        Ok(json!({
            "status": reference_status.as_str(),
            "path": benchmark_dir.as_str(),
            "referenceDeviceIds": reference_device_ids.into_iter().collect::<Vec<_>>(),
            "artifactVersion": artifact_version,
            "zkeySha256": zkey_sha256,
            "manifestSha256": manifest_sha256,
            "artifactBundleSha256": artifact_bundle_sha256,
            "benchmarks": benchmark_summaries,
        }))
    };

    match validate_complete() {
        Ok(value) => Ok(value),
        Err(error) => Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
            "error": error.to_string(),
        })),
    }
}

fn validate_sbom_evidence(sbom_dir: &Utf8PathBuf, required: bool) -> Result<Vec<Utf8PathBuf>> {
    let candidate_dir = if sbom_dir.join("sbom").is_dir() {
        sbom_dir.join("sbom")
    } else {
        sbom_dir.clone()
    };
    let mut rust_paths = Vec::new();
    let rust_bundle_dir = candidate_dir.join("rust");
    if rust_bundle_dir.is_dir() {
        let mut entries = fs::read_dir(&rust_bundle_dir)
            .with_context(|| format!("failed to read {}", rust_bundle_dir))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to enumerate {}", rust_bundle_dir))?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = Utf8PathBuf::from_path_buf(entry.path())
                .map_err(|path| anyhow!("non-utf8 Rust SBOM evidence path: {}", path.display()))?;
            if path
                .file_name()
                .is_some_and(|name| name.ends_with(".cdx.json"))
            {
                rust_paths.push(path);
            }
        }
    }
    if rust_paths.is_empty() {
        let legacy_rust_path = candidate_dir.join("rust.cdx.json");
        if legacy_rust_path.exists() {
            rust_paths.push(legacy_rust_path);
        }
    }

    let supplementary_paths = vec![
        candidate_dir.join("sdk.spdx.json"),
        candidate_dir.join("react-native.spdx.json"),
    ];

    if rust_paths.is_empty() && supplementary_paths.iter().all(|path| !path.exists()) {
        ensure!(
            !required,
            "SBOM evidence directory does not contain rust.cdx.json, rust/*.cdx.json, sdk.spdx.json, and react-native.spdx.json: {}",
            candidate_dir
        );
        return Ok(Vec::new());
    }

    ensure!(
        !rust_paths.is_empty(),
        "SBOM evidence directory does not contain rust.cdx.json or rust/*.cdx.json: {}",
        candidate_dir
    );

    let mut sbom_paths = rust_paths;
    sbom_paths.extend(supplementary_paths);

    for path in &sbom_paths {
        let _ = read_required_json(path)?;
    }

    Ok(sbom_paths)
}

fn validate_attestation_verification_record(
    record: &AttestationRecord,
    verification: &AttestationVerificationRecord,
    expected_repo: &str,
    expected_signer_workflow: &str,
) -> Result<()> {
    ensure!(
        verification.verified,
        "attestation verification result must set verified=true for {}",
        record.subject_path
    );
    ensure!(
        !verification.verified_at.trim().is_empty(),
        "attestation verification result must include verifiedAt for {}",
        record.subject_path
    );
    ensure!(
        verification.repo == expected_repo,
        "attestation verification repo mismatch for {}: expected {} but found {}",
        record.subject_path,
        expected_repo,
        verification.repo
    );
    ensure!(
        verification.signer_workflow == expected_signer_workflow,
        "attestation signer workflow mismatch for {}: expected {} but found {}",
        record.subject_path,
        expected_signer_workflow,
        verification.signer_workflow
    );
    ensure!(
        verification.subject_path == record.subject_path,
        "attestation verification subjectPath mismatch for {}: expected {} but found {}",
        record.subject_path,
        record.subject_path,
        verification.subject_path
    );
    ensure!(
        verification.subject_sha256 == record.sha256,
        "attestation verification sha256 mismatch for {}: expected {} but found {}",
        record.subject_path,
        record.sha256,
        verification.subject_sha256
    );
    ensure!(
        verification
            .predicate_type
            .as_deref()
            .is_some_and(|value| value == "https://slsa.dev/provenance/v1"),
        "attestation verification predicate type mismatch for {}",
        record.subject_path
    );
    ensure!(
        verification.verification_count > 0,
        "attestation verification result must include at least one verified attestation for {}",
        record.subject_path
    );
    let subject_path = Utf8PathBuf::from(record.subject_path.as_str());
    let expected_basename = subject_path
        .file_name()
        .unwrap_or(record.subject_path.as_str());
    ensure!(
        verification
            .attested_subject_basename
            .as_deref()
            .is_some_and(|value| value == expected_basename),
        "attestation verification subject name mismatch for {}",
        record.subject_path
    );

    Ok(())
}

fn validate_attestation_records_for_packages(
    workspace_root: &Utf8PathBuf,
    dir: &Utf8PathBuf,
    packages_root: &Utf8PathBuf,
    attestations: &[AttestationRecord],
) -> Result<()> {
    ensure!(
        packages_root.exists() && packages_root.is_dir(),
        "external package evidence directory does not exist: {}",
        packages_root
    );
    ensure!(
        !attestations.is_empty(),
        "{} must contain at least one attestation record",
        dir.join("attestations.json")
    );
    let expected_repo = current_github_repository_slug(workspace_root)?;
    let expected_signer_workflow = format!("{expected_repo}/.github/workflows/release.yml");

    for record in attestations {
        ensure!(
            !record.subject_path.trim().is_empty(),
            "attestation subjectPath must not be empty"
        );
        ensure!(
            !record.sha256.trim().is_empty(),
            "attestation sha256 must not be empty"
        );
        ensure!(
            !record.attestation_url.trim().is_empty(),
            "attestation attestationUrl must not be empty"
        );
        ensure!(
            !record.workflow_run_url.trim().is_empty(),
            "attestation workflowRunUrl must not be empty"
        );
        ensure!(
            !record.verification_path.trim().is_empty(),
            "attestation verificationPath must not be empty"
        );

        let subject_path = Utf8PathBuf::from(record.subject_path.as_str());
        let resolved_subject = if subject_path.is_absolute() {
            subject_path
        } else {
            dir.join(subject_path)
        };
        ensure!(
            resolved_subject.exists(),
            "attestation subjectPath does not exist: {}",
            resolved_subject
        );
        let actual_sha256 =
            sha256_hex(&fs::read(&resolved_subject).with_context(|| {
                format!("failed to read attestation subject {}", resolved_subject)
            })?);
        ensure!(
            record.sha256 == actual_sha256,
            "attestation sha256 mismatch for {}: expected {} but found {}",
            resolved_subject,
            record.sha256,
            actual_sha256
        );

        let verification_path = Utf8PathBuf::from(record.verification_path.as_str());
        let resolved_verification = if verification_path.is_absolute() {
            verification_path
        } else {
            dir.join(verification_path)
        };
        ensure!(
            resolved_verification.exists(),
            "attestation verificationPath does not exist: {}",
            resolved_verification
        );
        let verification: AttestationVerificationRecord = serde_json::from_value(
            read_required_json(&resolved_verification)?,
        )
        .with_context(|| {
            format!(
                "failed to parse attestation verification {}",
                resolved_verification
            )
        })?;
        validate_attestation_verification_record(
            record,
            &verification,
            &expected_repo,
            &expected_signer_workflow,
        )?;
    }

    let mut package_files = Vec::new();
    collect_files_recursive(packages_root, &mut package_files)?;
    package_files.sort();
    let attested_subjects = attestations
        .iter()
        .map(|record| record.subject_path.clone())
        .collect::<BTreeSet<_>>();
    for file in package_files {
        let relative = file
            .strip_prefix(dir.as_path())
            .unwrap_or(file.as_path())
            .as_str()
            .trim_start_matches('/')
            .to_owned();
        ensure!(
            attested_subjects.contains(&relative),
            "missing attestation metadata for packaged subject {}",
            relative
        );
    }

    Ok(())
}

fn validate_external_evidence_dir(
    workspace_root: &Utf8PathBuf,
    dir: &Utf8PathBuf,
    profile: AssuranceProfile,
    backend: BenchmarkBackendProfile,
    commit: &str,
    signed_manifest_public_key_override: Option<&str>,
) -> Result<Value> {
    ensure!(
        dir.exists() && dir.is_dir(),
        "external evidence directory does not exist: {}",
        dir
    );

    let mobile_evidence =
        validate_mobile_evidence_subset(dir, commit, matches!(profile, AssuranceProfile::Release))?;
    let reference_benchmarks = validate_reference_benchmark_evidence(
        workspace_root,
        &dir.join("benchmarks"),
        profile,
        backend,
        commit,
    )?;
    let digest_sha256 = sha256_hex(directory_digest_bytes(dir)?.as_slice());

    if matches!(profile, AssuranceProfile::Nightly) {
        return Ok(json!({
            "path": dir.as_str(),
            "digestSha256": digest_sha256,
            "mobileSmokePath": mobile_evidence["mobileSmokePath"],
            "mobileParityPath": mobile_evidence["mobileParityPath"],
            "mobileParity": mobile_evidence["mobileParity"],
            "mobileEvidence": mobile_evidence,
            "referencePerformance": reference_benchmarks,
            "referenceDeviceIds": reference_benchmarks["referenceDeviceIds"],
            "benchmarks": reference_benchmarks["benchmarks"],
        }));
    }

    let signed_manifest_dir = dir.join("signed-manifest");
    let signed_manifest_public_key = signed_manifest_public_key_override
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .context(
            "external signed manifest evidence requires PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY or --signed-manifest-public-key",
        )?;
    let signed_manifest =
        validate_signed_manifest_directory(&signed_manifest_dir, &signed_manifest_public_key)?;
    let sbom_paths = validate_sbom_evidence(&dir.join("sbom"), true)?;

    let packages_root = dir.join("packages");
    let attestations_path = dir.join("attestations.json");
    let attestations: Vec<AttestationRecord> =
        serde_json::from_value(read_required_json(&attestations_path)?)
            .with_context(|| format!("failed to parse {}", attestations_path))?;
    validate_attestation_records_for_packages(workspace_root, dir, &packages_root, &attestations)?;
    let signed_manifest_package_binding = validate_signed_manifest_package_binding(
        dir,
        &packages_root,
        &attestations,
        &signed_manifest,
    )?;
    let sdk_web_package_binding = validate_sdk_web_package_binding(dir, &attestations)?;

    Ok(json!({
        "path": dir.as_str(),
        "digestSha256": digest_sha256,
        "referenceDeviceIds": reference_benchmarks["referenceDeviceIds"],
        "mobileSmokePath": mobile_evidence["mobileSmokePath"],
        "mobileParityPath": mobile_evidence["mobileParityPath"],
        "mobileParity": mobile_evidence["mobileParity"],
        "mobileEvidence": mobile_evidence,
        "signedManifest": signed_manifest,
        "signedManifestPackageBinding": signed_manifest_package_binding,
        "sdkWebPackageBinding": sdk_web_package_binding,
        "referencePerformance": reference_benchmarks,
        "benchmarks": reference_benchmarks["benchmarks"],
        "sboms": sbom_paths.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
        "attestationsPath": attestations_path.as_str(),
        "attestationCount": attestations.len(),
    }))
}

fn resolve_evidence_source_dir(source: &Utf8PathBuf, nested: &str) -> Utf8PathBuf {
    let nested_path = source.join(nested);
    if nested_path.is_dir() {
        nested_path
    } else {
        source.clone()
    }
}

fn copy_file_if_present(source: &Utf8PathBuf, destination: &Utf8PathBuf) -> Result<bool> {
    if !source.exists() {
        return Ok(false);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
    }
    fs::copy(source, destination)
        .with_context(|| format!("failed to copy {} to {}", source, destination))?;
    Ok(true)
}

fn collect_attestation_metadata_records(dir: &Utf8PathBuf) -> Result<Vec<AttestationRecord>> {
    let root = resolve_evidence_source_dir(dir, "attestation-metadata");
    ensure!(
        root.exists() && root.is_dir(),
        "attestation metadata directory does not exist: {}",
        root
    );

    let mut files = Vec::new();
    collect_files_recursive(&root, &mut files)?;
    files.sort();

    let mut records = Vec::new();
    let mut seen_subjects = BTreeSet::new();
    for path in files {
        if path
            .components()
            .any(|component| component.as_str() == "attestation-verification")
        {
            continue;
        }
        if path.extension() != Some("json") {
            continue;
        }
        let parsed: Vec<AttestationRecord> = serde_json::from_value(read_required_json(&path)?)
            .with_context(|| format!("failed to parse {}", path))?;
        for record in parsed {
            ensure!(
                seen_subjects.insert(record.subject_path.clone()),
                "duplicate attestation metadata for {}",
                record.subject_path
            );
            records.push(record);
        }
    }

    ensure!(
        !records.is_empty(),
        "attestation metadata directory must contain at least one JSON record set: {}",
        root
    );
    records.sort_by(|left, right| left.subject_path.cmp(&right.subject_path));
    Ok(records)
}

fn write_external_evidence_manifest(path: &Utf8PathBuf, value: &Value) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value)
            .context("failed to serialize external evidence manifest")?,
    )
    .with_context(|| format!("failed to write {}", path))
}

fn assemble_external_evidence_dir(
    workspace_root: &Utf8PathBuf,
    options: &ExternalEvidenceAssembleOptions,
    commit: &str,
) -> Result<Value> {
    reset_directory(&options.out_dir)?;
    let signed_manifest_source = workspace_root.join("fixtures/artifacts/signed-manifest");
    stage_directory(
        &signed_manifest_source,
        &options.out_dir.join("signed-manifest"),
    )?;

    let mut mobile_source = None::<String>;
    if let Some(dir) = options.mobile_evidence_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let copied_smoke = copy_file_if_present(
            &source.join("mobile-smoke.json"),
            &options.out_dir.join("mobile-smoke.json"),
        )?;
        let copied_parity = copy_file_if_present(
            &source.join("mobile-parity.json"),
            &options.out_dir.join("mobile-parity.json"),
        )?;
        ensure!(
            copied_smoke == copied_parity,
            "mobile evidence source {} must contain both mobile-smoke.json and mobile-parity.json",
            source
        );
        if copied_smoke {
            mobile_source = Some(source.to_string());
        }
    }

    let mut reference_source = None::<String>;
    if let Some(dir) = options.reference_benchmarks_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let benchmark_source = resolve_evidence_source_dir(&source, "benchmarks");
        if benchmark_source.exists() {
            stage_directory(&benchmark_source, &options.out_dir.join("benchmarks"))?;
            reference_source = Some(benchmark_source.to_string());
        }
    }

    let mut sbom_source = None::<String>;
    if let Some(dir) = options.sbom_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let resolved = resolve_evidence_source_dir(&source, "sbom");
        if resolved.exists() {
            stage_directory(&resolved, &options.out_dir.join("sbom"))?;
            sbom_source = Some(resolved.to_string());
        }
    }

    let mut packages_source = None::<String>;
    if let Some(dir) = options.packages_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let resolved = resolve_evidence_source_dir(&source, "packages");
        if resolved.exists() {
            stage_directory(&resolved, &options.out_dir.join("packages"))?;
            packages_source = Some(resolved.to_string());
        }
    }

    let mut attestation_source = None::<String>;
    if let Some(dir) = options.attestation_metadata_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let records = collect_attestation_metadata_records(&source)?;
        let verification_source = resolve_evidence_source_dir(&source, "attestation-verification");
        if verification_source.exists() {
            stage_directory(
                &verification_source,
                &options.out_dir.join("attestation-verification"),
            )?;
        }
        write_external_evidence_manifest(
            &options.out_dir.join("attestations.json"),
            &serde_json::to_value(&records).context("failed to encode attestation metadata")?,
        )?;
        attestation_source = Some(source.to_string());
    }

    match options.mode {
        ExternalEvidenceMode::Nightly => {
            let _ = validate_mobile_evidence_subset(&options.out_dir, commit, false)?;
            let _ = validate_reference_benchmark_evidence(
                workspace_root,
                &options.out_dir.join("benchmarks"),
                AssuranceProfile::Nightly,
                BenchmarkBackendProfile::Stable,
                commit,
            )?;
        }
        ExternalEvidenceMode::Release => {
            ensure!(
                mobile_source.is_some(),
                "release external evidence assembly requires --mobile-evidence-dir"
            );
            ensure!(
                sbom_source.is_some(),
                "release external evidence assembly requires --sbom-dir"
            );
            ensure!(
                packages_source.is_some(),
                "release external evidence assembly requires --packages-dir"
            );
            ensure!(
                attestation_source.is_some(),
                "release external evidence assembly requires --attestation-metadata-dir"
            );

            let _ = validate_mobile_evidence_subset(&options.out_dir, commit, true)?;
            let _ = validate_reference_benchmark_evidence(
                workspace_root,
                &options.out_dir.join("benchmarks"),
                AssuranceProfile::Release,
                BenchmarkBackendProfile::Stable,
                commit,
            )?;
            let _ = validate_sbom_evidence(&options.out_dir.join("sbom"), true)?;
            let attestations: Vec<AttestationRecord> = serde_json::from_value(read_required_json(
                &options.out_dir.join("attestations.json"),
            )?)
            .with_context(|| {
                format!(
                    "failed to parse {}",
                    options.out_dir.join("attestations.json")
                )
            })?;
            validate_attestation_records_for_packages(
                workspace_root,
                &options.out_dir,
                &options.out_dir.join("packages"),
                &attestations,
            )?;
        }
    }

    let mobile_evidence = validate_mobile_evidence_subset(
        &options.out_dir,
        commit,
        matches!(options.mode, ExternalEvidenceMode::Release),
    )?;
    let reference_performance = validate_reference_benchmark_evidence(
        workspace_root,
        &options.out_dir.join("benchmarks"),
        if matches!(options.mode, ExternalEvidenceMode::Release) {
            AssuranceProfile::Release
        } else {
            AssuranceProfile::Nightly
        },
        BenchmarkBackendProfile::Stable,
        commit,
    )?;
    let assembly_manifest = json!({
        "generatedAtUnixSeconds": current_unix_seconds()?,
        "mode": options.mode.as_str(),
        "gitCommit": commit,
        "outDir": options.out_dir.as_str(),
        "sources": {
            "mobileEvidenceDir": mobile_source,
            "referenceBenchmarksDir": reference_source,
            "sbomDir": sbom_source,
            "packagesDir": packages_source,
            "attestationMetadataDir": attestation_source,
            "signedManifestDir": signed_manifest_source.as_str(),
        },
        "mobileEvidence": {
            "status": mobile_evidence["status"],
            "mobileSmokePath": mobile_evidence["mobileSmokePath"],
            "mobileParityPath": mobile_evidence["mobileParityPath"],
        },
        "referencePerformance": {
            "status": reference_performance["status"],
            "benchmarkCount": reference_performance["benchmarks"]
                .as_array()
                .map_or(0, Vec::len),
            "referenceDeviceIds": reference_performance["referenceDeviceIds"],
        },
    });
    write_external_evidence_manifest(
        &options.out_dir.join("assembly-manifest.json"),
        &assembly_manifest,
    )?;

    Ok(assembly_manifest)
}

fn validate_signed_manifest_directory(dir: &Utf8PathBuf, public_key_hex: &str) -> Result<Value> {
    let payload_path = dir.join("payload.json");
    let signature_path = dir.join("signature");
    let artifacts_root = dir.join("artifacts");
    ensure!(
        artifacts_root.exists() && artifacts_root.is_dir(),
        "signed manifest artifact directory does not exist: {}",
        artifacts_root
    );
    let payload_json =
        fs::read(&payload_path).with_context(|| format!("failed to read {}", payload_path))?;
    let signature = read_required_text_file(&signature_path)?;
    let verified = verify_signed_manifest_artifact_files(
        &payload_json,
        signature.trim(),
        public_key_hex.trim(),
        artifacts_root.as_std_path(),
    )
    .with_context(|| format!("signed manifest validation failed for {}", dir))?;
    let artifacts_digest_sha256 = sha256_hex(directory_digest_bytes(&artifacts_root)?.as_slice());

    Ok(json!({
        "path": dir.as_str(),
        "version": verified.payload().manifest.version,
        "artifactCount": verified.artifact_count(),
        "payloadSha256": sha256_hex(&payload_json),
        "signatureSha256": sha256_hex(signature.trim().as_bytes()),
        "artifactsDigestSha256": artifacts_digest_sha256,
    }))
}

fn archive_signed_manifest_package_summary(
    archive_path: &Utf8PathBuf,
    current_dir: &Utf8PathBuf,
) -> Result<Value> {
    let payload_path = "artifacts/signed-manifest/payload.json";
    let signature_path = "artifacts/signed-manifest/signature";

    let payload = command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), payload_path],
        current_dir,
        &format!("failed to read {payload_path} from {}", archive_path),
    )?;
    let signature = command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), signature_path],
        current_dir,
        &format!("failed to read {signature_path} from {}", archive_path),
    )?;
    let payload_json: Value = serde_json::from_slice(&payload)
        .with_context(|| format!("failed to parse {payload_path} from {}", archive_path))?;
    let manifest = payload_json
        .get("manifest")
        .and_then(Value::as_object)
        .with_context(|| format!("{payload_path} from {} is missing manifest", archive_path))?;
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .with_context(|| {
            format!(
                "{payload_path} from {} is missing manifest.version",
                archive_path
            )
        })?;
    let artifact_entries = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .with_context(|| {
            format!(
                "{payload_path} from {} is missing manifest.artifacts",
                archive_path
            )
        })?;
    ensure!(
        !artifact_entries.is_empty(),
        "{} does not contain any signed manifest artifact entries",
        archive_path,
    );

    let mut digest = Sha256::new();
    for entry in artifact_entries {
        let relative = entry
            .get("filename")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "{payload_path} from {} has an artifact without filename",
                    archive_path
                )
            })?;
        let expected_sha256 = entry
            .get("sha256")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "{payload_path} from {} has an artifact without sha256",
                    archive_path
                )
            })?;
        let archive_entry = format!("artifacts/{relative}");
        let bytes = command_output_bytes(
            "tar",
            &["-xOf", archive_path.as_str(), &archive_entry],
            current_dir,
            &format!("failed to read {archive_entry} from {}", archive_path),
        )?;
        ensure!(
            sha256_hex(&bytes) == expected_sha256,
            "packaged circuit artifact {} in {} does not match embedded signed manifest",
            archive_entry,
            archive_path
        );
        digest.update(relative.as_bytes());
        digest.update(b"\n");
        digest.update(&bytes);
        digest.update(b"\n");
    }

    Ok(json!({
        "version": version,
        "artifactCount": artifact_entries.len(),
        "payloadSha256": sha256_hex(&payload),
        "signatureSha256": sha256_hex(signature.trim_ascii()),
        "artifactsDigestSha256": sha256_hex(&digest.finalize()),
    }))
}

fn archive_entry_bytes(
    archive_path: &Utf8PathBuf,
    archive_entry: &str,
    current_dir: &Utf8PathBuf,
) -> Result<Vec<u8>> {
    command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), archive_entry],
        current_dir,
        &format!("failed to read {archive_entry} from {}", archive_path),
    )
}

fn validate_signed_manifest_package_binding(
    dir: &Utf8PathBuf,
    packages_root: &Utf8PathBuf,
    attestations: &[AttestationRecord],
    signed_manifest: &Value,
) -> Result<Value> {
    let package_records = attestations
        .iter()
        .filter(|record| record.subject_path.starts_with("packages/circuits/"))
        .collect::<Vec<_>>();
    ensure!(
        !package_records.is_empty(),
        "missing attestation metadata for packaged circuit artifacts under {}",
        packages_root
    );
    ensure!(
        package_records.len() == 1,
        "expected exactly one packaged circuit-artifact attestation subject under {} but found {}",
        packages_root,
        package_records.len()
    );
    let package_record = package_records[0];
    let archive_path = dir.join(&package_record.subject_path);
    ensure!(
        archive_path.exists(),
        "packaged circuit-artifact subject does not exist: {}",
        archive_path
    );

    let archive_summary = archive_signed_manifest_package_summary(&archive_path, dir)?;
    for field in ["payloadSha256", "signatureSha256", "artifactsDigestSha256"] {
        ensure!(
            archive_summary[field] == signed_manifest[field],
            "packaged circuit-artifact signed-manifest {} mismatch for {}",
            field,
            archive_path
        );
    }

    Ok(json!({
        "subjectPath": package_record.subject_path,
        "archivePath": archive_path.as_str(),
        "version": archive_summary["version"],
        "artifactCount": archive_summary["artifactCount"],
        "payloadSha256": archive_summary["payloadSha256"],
        "signatureSha256": archive_summary["signatureSha256"],
        "artifactsDigestSha256": archive_summary["artifactsDigestSha256"],
    }))
}

fn validate_sdk_web_package_binding(
    dir: &Utf8PathBuf,
    attestations: &[AttestationRecord],
) -> Result<Value> {
    let package_records = attestations
        .iter()
        .filter(|record| {
            (record.subject_path.starts_with("packages/sdk/")
                && Path::new(&record.subject_path)
                    .extension()
                    .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("tgz")))
                || record.subject_path == "packages/sdk.tgz"
        })
        .collect::<Vec<_>>();
    ensure!(
        package_records.len() == 1,
        "expected exactly one packaged browser npm tarball attestation subject but found {}",
        package_records.len()
    );
    let package_record = package_records[0];
    let package_path = dir.join(&package_record.subject_path);
    ensure!(
        package_path.exists(),
        "packaged browser npm tarball subject does not exist: {}",
        package_path
    );

    let wasm_records = attestations
        .iter()
        .filter(|record| {
            record
                .subject_path
                .ends_with("/privacy_pools_sdk_web_bg.wasm")
                || record.subject_path == "packages/privacy_pools_sdk_web_bg.wasm"
        })
        .collect::<Vec<_>>();
    ensure!(
        wasm_records.len() == 1,
        "expected exactly one packaged browser wasm attestation subject but found {}",
        wasm_records.len()
    );
    let wasm_record = wasm_records[0];
    let wasm_path = dir.join(&wasm_record.subject_path);
    ensure!(
        wasm_path.exists(),
        "packaged browser wasm subject does not exist: {}",
        wasm_path
    );

    let packaged_wasm = archive_entry_bytes(
        &package_path,
        "package/src/browser/generated/privacy_pools_sdk_web_bg.wasm",
        dir,
    )?;
    let exported_wasm =
        fs::read(&wasm_path).with_context(|| format!("failed to read {}", wasm_path))?;
    let packaged_wasm_sha256 = sha256_hex(&packaged_wasm);
    let exported_wasm_sha256 = sha256_hex(&exported_wasm);
    ensure!(
        packaged_wasm == exported_wasm,
        "packaged browser WASM mismatch: {} embeds {} but {} has {}",
        package_path,
        packaged_wasm_sha256,
        wasm_path,
        exported_wasm_sha256
    );

    Ok(json!({
        "packageSubjectPath": package_record.subject_path,
        "packagePath": package_path.as_str(),
        "wasmSubjectPath": wasm_record.subject_path,
        "wasmPath": wasm_path.as_str(),
        "browserWasmSha256": exported_wasm_sha256,
    }))
}

fn directory_digest_bytes(dir: &Utf8PathBuf) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files)?;
    files.sort();

    let mut digest = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(dir.as_path())
            .unwrap_or(path.as_path())
            .as_str()
            .trim_start_matches('/');
        digest.update(relative.as_bytes());
        digest.update(b"\n");
        digest.update(&fs::read(&path).with_context(|| format!("failed to read {}", path))?);
        digest.update(b"\n");
    }
    Ok(digest.finalize().to_vec())
}

fn collect_files_recursive(root: &Utf8PathBuf, output: &mut Vec<Utf8PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root))?;
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("path is not valid UTF-8: {:?}", raw))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path))?
            .is_dir()
        {
            collect_files_recursive(&path, output)?;
        } else {
            output.push(path);
        }
    }
    Ok(())
}

fn workspace_unsafe_matches(workspace_root: &Utf8PathBuf) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let root = workspace_root.join("crates");
    if root.exists() {
        collect_files_recursive(&root, &mut files)?;
    }
    files.sort();

    let mut matches = Vec::new();
    for path in files {
        let display_path = path.strip_prefix(workspace_root).unwrap_or(path.as_path());
        if path.extension() == Some("rs") {
            let contents =
                fs::read_to_string(&path).with_context(|| format!("failed to read {}", path))?;
            for (index, line) in contents.lines().enumerate() {
                if line.contains("unsafe") {
                    matches.push(format!("{}:{}:{}", display_path, index + 1, line.trim()));
                }
            }
        }
        if path.file_name() == Some("Cargo.toml") {
            let contents =
                fs::read_to_string(&path).with_context(|| format!("failed to read {}", path))?;
            for (index, line) in contents.lines().enumerate() {
                if line.contains("unsafe_code = \"allow\"") {
                    matches.push(format!("{}:{}:{}", display_path, index + 1, line.trim()));
                }
            }
        }
    }
    Ok(matches)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn format_command(program: &str, args: &[String]) -> String {
    let mut command = program.to_owned();
    for arg in args {
        command.push(' ');
        command.push_str(arg);
    }
    command
}

fn shell_escape_path(path: &Utf8PathBuf) -> String {
    format!("'{}'", path.as_str().replace('\'', "'\"'\"'"))
}

fn resolve_path_for_child(workspace_root: &Utf8PathBuf, path: &Utf8PathBuf) -> Utf8PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        workspace_root.join(path)
    }
}

#[cfg(test)]
fn validate_signed_manifest_evidence(
    dir: &Utf8PathBuf,
    public_key_hex: Option<&str>,
) -> Result<Option<(String, usize)>> {
    let payload_path = dir.join("signed-artifact-manifest.payload.json");
    if !payload_path.exists() {
        return Ok(None);
    }

    let public_key_hex = public_key_hex.context(
        "signed-artifact-manifest.payload.json is present; pass --signed-manifest-public-key or set PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY",
    )?;
    let signature = read_required_text_file(&dir.join("signed-artifact-manifest.signature"))?;
    let artifact_root = signed_manifest_artifact_root(dir);
    ensure!(
        artifact_root.exists() && artifact_root.is_dir(),
        "signed artifact manifest artifact root does not exist: {}",
        artifact_root
    );
    let payload_json =
        fs::read(&payload_path).with_context(|| format!("failed to read {payload_path}"))?;
    let verified = verify_signed_manifest_artifact_files(
        &payload_json,
        signature.trim(),
        public_key_hex.trim(),
        artifact_root.as_std_path(),
    )
    .with_context(|| {
        format!(
            "signed artifact manifest validation failed for {}",
            payload_path
        )
    })?;

    Ok(Some((
        verified.payload().manifest.version.clone(),
        verified.artifact_count(),
    )))
}

#[cfg(test)]
fn signed_manifest_artifact_root(dir: &Utf8PathBuf) -> Utf8PathBuf {
    for candidate in [
        dir.join("signed-artifact-manifest-artifacts"),
        dir.join("artifacts"),
    ] {
        if candidate.is_dir() {
            return candidate;
        }
    }
    dir.clone()
}

fn validate_browser_comparison_report(path: &Utf8PathBuf) -> Result<()> {
    let json = read_required_json(path)?;
    let browser = json
        .get("browserPerformance")
        .with_context(|| format!("{path} missing `browserPerformance`"))?;
    for circuit in ["commitment", "withdrawal"] {
        let report = browser
            .get(circuit)
            .with_context(|| format!("{path} missing `browserPerformance.{circuit}`"))?;

        for suite in ["directCold", "directWarm", "workerCold", "workerWarm"] {
            let metric = report
                .get(suite)
                .with_context(|| format!("{path} missing browser {circuit} suite `{suite}`"))?;
            ensure_json_u64(metric, "iterations", path)?;
            validate_metric_summary(
                metric
                    .get("total")
                    .with_context(|| format!("{path} missing `{circuit}.{suite}.total`"))?,
                &format!("{circuit}.{suite}.total"),
                path,
            )?;
            let slices = metric
                .get("slices")
                .with_context(|| format!("{path} missing `{circuit}.{suite}.slices`"))?;
            for slice in [
                "preloadMs",
                "witnessParseMs",
                "witnessTransferMs",
                "witnessMs",
                "proveMs",
                "verifyMs",
                "totalMs",
            ] {
                validate_metric_summary(
                    slices.get(slice).with_context(|| {
                        format!("{path} missing `{circuit}.{suite}.slices.{slice}`")
                    })?,
                    &format!("{circuit}.{suite}.slices.{slice}"),
                    path,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_rust_comparison_report(path: &Utf8PathBuf) -> Result<Value> {
    let json = read_required_json(path)?;
    ensure_json_string(&json, "gitCommit", path)?;
    ensure_json_string(&json, "sdkVersion", path)?;
    let baseline = json
        .get("baseline")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `baseline` object"))?;
    ensure!(
        baseline
            .get("packagePath")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "{path} missing `baseline.packagePath`"
    );
    ensure!(
        baseline
            .get("sourcePath")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "{path} missing `baseline.sourcePath`"
    );

    let safety = json
        .get("safety")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `safety` object"))?;
    let failed = safety
        .get("failed")
        .and_then(Value::as_u64)
        .with_context(|| format!("{path} missing `safety.failed`"))?;
    ensure!(
        failed == 0,
        "{path} recorded {failed} Rust-v1 safety failures"
    );
    let checks = safety
        .get("checks")
        .and_then(Value::as_array)
        .with_context(|| format!("{path} missing `safety.checks`"))?;
    ensure!(
        !checks.is_empty(),
        "{path} safety checks array must not be empty"
    );

    let performance = json
        .get("performance")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `performance` object"))?;
    let regressions = performance
        .get("regressions")
        .and_then(Value::as_array)
        .with_context(|| format!("{path} missing `performance.regressions`"))?;
    ensure!(
        regressions.is_empty(),
        "{path} recorded {} unexplained performance regressions",
        regressions.len()
    );

    Ok(json)
}

fn validate_metric_summary(metric: &Value, label: &str, path: &Utf8PathBuf) -> Result<()> {
    for field in ["averageMs", "minMs", "maxMs"] {
        let value = metric
            .get(field)
            .and_then(Value::as_f64)
            .with_context(|| format!("{path} missing numeric `{label}.{field}`"))?;
        ensure!(
            value.is_finite() && value >= 0.0,
            "{} has invalid `{label}.{field}`: {value}",
            path
        );
    }
    Ok(())
}

fn cdylib_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libprivacy_pools_sdk_ffi.dylib"
    } else if cfg!(target_os = "windows") {
        "privacy_pools_sdk_ffi.dll"
    } else {
        "libprivacy_pools_sdk_ffi.so"
    }
}
