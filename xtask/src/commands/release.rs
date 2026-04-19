fn release_check(args: Vec<String>) -> Result<()> {
    let options = ReleaseCheckOptions::parse(args)?;
    let workspace_root = workspace_root()?;

    let rust_manifests = [
        "crates/privacy-pools-sdk/Cargo.toml",
        "crates/privacy-pools-sdk-ffi/Cargo.toml",
        "crates/privacy-pools-sdk-core/Cargo.toml",
        "crates/privacy-pools-sdk-crypto/Cargo.toml",
        "crates/privacy-pools-sdk-tree/Cargo.toml",
        "crates/privacy-pools-sdk-artifacts/Cargo.toml",
        "crates/privacy-pools-sdk-prover/Cargo.toml",
        "crates/privacy-pools-sdk-chain/Cargo.toml",
        "crates/privacy-pools-sdk-recovery/Cargo.toml",
        "crates/privacy-pools-sdk-signer/Cargo.toml",
        "crates/privacy-pools-sdk-cli/Cargo.toml",
    ];

    let rust_versions = rust_manifests
        .iter()
        .map(|path| {
            let absolute = workspace_root.join(path);
            read_keyed_string(&absolute, "version = ")
                .map(|version| (path.to_string(), version))
                .with_context(|| format!("failed to read Rust crate version from {}", absolute))
        })
        .collect::<Result<Vec<_>>>()?;
    let rust_version = ensure_same_versions("Rust crate versions", &rust_versions)?;

    let react_native_package_version =
        read_package_json_version(&workspace_root.join("packages/react-native/package.json"))?;
    let sdk_package_version =
        read_package_json_version(&workspace_root.join("packages/sdk/package.json"))?;
    let react_native_podspec_version = read_keyed_string(
        &workspace_root.join("packages/react-native/PrivacyPoolsSdk.podspec"),
        "s.version = ",
    )?;
    let ios_podspec_version = read_keyed_string(
        &workspace_root.join("bindings/ios/PrivacyPoolsSdk.podspec"),
        "s.version = ",
    )?;

    ensure!(
        react_native_package_version == react_native_podspec_version,
        "React Native package version {} does not match package podspec version {}",
        react_native_package_version,
        react_native_podspec_version
    );
    ensure!(
        react_native_package_version == ios_podspec_version,
        "React Native package version {} does not match iOS podspec version {}",
        react_native_package_version,
        ios_podspec_version
    );

    let rust_base = base_version(&rust_version);
    ensure!(
        base_version(&sdk_package_version) == rust_base,
        "SDK package version base {} does not match Rust crate version base {}",
        base_version(&sdk_package_version),
        rust_base
    );

    let mobile_base = base_version(&react_native_package_version);
    ensure!(
        rust_base == mobile_base,
        "Rust crate version base {} does not match mobile package version base {}",
        rust_base,
        mobile_base
    );

    options
        .channel
        .validate_mobile_version(&react_native_package_version)?;
    options
        .channel
        .validate_mobile_version(&sdk_package_version)?;

    println!("release-check ok");
    println!("channel: {}", options.channel.as_str());
    println!("rust crate version: {}", rust_version);
    println!(
        "react-native package version: {}",
        react_native_package_version
    );
    println!("sdk package version: {}", sdk_package_version);
    println!(
        "react-native podspec version: {}",
        react_native_podspec_version
    );
    println!("ios podspec version: {}", ios_podspec_version);

    Ok(())
}

fn evidence_check(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = EvidenceCheckOptions::parse(args)?;

    ensure!(
        options.dir.exists(),
        "evidence directory does not exist: {}",
        options.dir
    );
    ensure!(
        options.dir.is_dir(),
        "evidence path is not a directory: {}",
        options.dir
    );

    let mobile_smoke_path = options.dir.join("mobile-smoke.json");
    let mobile_smoke = read_required_json(&mobile_smoke_path)?;
    let commit = ensure_json_string(&mobile_smoke, "commit", &mobile_smoke_path)?.to_owned();
    ensure!(
        is_hex_commit(&commit),
        "mobile-smoke.json commit must contain a short or full hex git commit, found `{commit}`"
    );
    let external_evidence = validate_external_evidence_dir(
        &workspace_root,
        &options.dir,
        AssuranceProfile::Release,
        options.backend,
        &commit,
        options.signed_manifest_public_key.as_deref(),
    )?;

    println!("evidence-check ok");
    println!("mode: compatibility alias");
    println!("channel: {}", options.channel.as_str());
    println!("backend: {}", options.backend.as_str());
    println!("commit: {commit}");
    println!("evidence directory: {}", options.dir);
    println!(
        "digest: {}",
        external_evidence["digestSha256"]
            .as_str()
            .unwrap_or("unknown")
    );
    Ok(())
}

fn mobile_evidence_check(args: Vec<String>) -> Result<()> {
    let options = MobileEvidenceCheckOptions::parse(args)?;
    ensure!(
        options.dir.exists() && options.dir.is_dir(),
        "mobile evidence directory does not exist: {}",
        options.dir
    );

    let mobile_smoke_path = options.dir.join("mobile-smoke.json");
    let mobile_smoke = read_required_json(&mobile_smoke_path)?;
    let commit = ensure_json_string(&mobile_smoke, "commit", &mobile_smoke_path)?.to_owned();
    ensure!(
        is_hex_commit(&commit),
        "mobile-smoke.json commit must contain a short or full hex git commit, found `{commit}`"
    );
    let mobile_parity_path = options.dir.join("mobile-parity.json");
    validate_mobile_smoke_evidence_value(&mobile_smoke, &mobile_smoke_path, &commit)?;
    let parity = validate_mobile_parity_evidence(&mobile_parity_path, &commit)?;

    println!("mobile-evidence-check ok");
    println!("commit: {commit}");
    println!("mobile evidence directory: {}", options.dir);
    println!(
        "parity checks: {}/{}",
        parity["passed"].as_u64().unwrap_or(0),
        parity["totalChecks"].as_u64().unwrap_or(0)
    );
    Ok(())
}

struct ReleaseAcceptanceEvaluation {
    benchmark_count: usize,
    attestation_count: u64,
}

fn evaluate_release_acceptance_from_external_evidence(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    selected_specs: &[AssuranceCheckSpec],
    external_evidence: &Value,
) -> Result<ReleaseAcceptanceEvaluation> {
    validate_scenario_coverage(workspace_root, options, selected_specs)?;

    let benchmark_count = external_evidence
        .get("benchmarks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let attestation_count = external_evidence
        .get("attestationCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    ensure!(
        attestation_count > 0,
        "release acceptance evidence must include attestation metadata"
    );
    let sdk_web_package_binding = external_evidence
        .get("sdkWebPackageBinding")
        .context("release acceptance evidence must include sdkWebPackageBinding")?;
    ensure!(
        sdk_web_package_binding
            .get("browserWasmSha256")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "release acceptance sdkWebPackageBinding is missing browserWasmSha256"
    );

    Ok(ReleaseAcceptanceEvaluation {
        benchmark_count,
        attestation_count,
    })
}

fn release_acceptance_check(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let mut dir = None::<Utf8PathBuf>;
    let mut backend = BenchmarkBackendProfile::Stable;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dir" => {
                dir = Some(Utf8PathBuf::from(
                    iter.next().context("--dir requires a value")?,
                ));
            }
            "--backend" => {
                backend = BenchmarkBackendProfile::parse(
                    &iter.next().context("--backend requires a value")?,
                )?;
            }
            other => bail!("unknown release-acceptance-check flag: {other}"),
        }
    }

    let dir = dir.context("release-acceptance-check requires --dir <path>")?;
    let commit = current_git_commit(&workspace_root)?;
    let external_evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        backend,
        &commit,
        None,
    )?;
    let options = AssuranceOptions {
        profile: AssuranceProfile::Release,
        runtime: AssuranceRuntime::All,
        report_mode: AssuranceReportMode::Audit,
        out_dir: workspace_root.join("target/release-acceptance"),
        backend,
        device_label: "desktop".to_owned(),
        device_model: detect_device_model(&workspace_root)?,
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: Some(dir.clone()),
        fuzz_runs: 1,
        skip_fuzz: true,
        only_checks: None,
    };
    let selected_specs = assurance_selected_specs(&workspace_root, &options)?;
    let evaluation = evaluate_release_acceptance_from_external_evidence(
        &workspace_root,
        &options,
        &selected_specs,
        &external_evidence,
    )?;

    println!("release-acceptance-check ok");
    println!("commit: {commit}");
    println!("backend: {}", backend.as_str());
    println!("evidence directory: {}", dir);
    println!("reference benchmarks: {}", evaluation.benchmark_count);
    println!("attestations: {}", evaluation.attestation_count);
    Ok(())
}

