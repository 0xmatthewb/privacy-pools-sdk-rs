struct ValidatedBenchmarkMetadata {
    git_commit: String,
    device_label: String,
    device_model: String,
    device_class: String,
    benchmark_scenario_id: String,
    artifact_version: String,
    zkey_sha256: String,
    manifest_sha256: String,
    artifact_bundle_sha256: String,
}

fn collect_advisory_ids(audit_json: &Value, category: &str) -> Vec<String> {
    audit_json
        .get("warnings")
        .and_then(|warnings| warnings.get(category))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("advisory")
                .and_then(|advisory| advisory.get("id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvisoryPolicy {
    cargo_audit_ignore: Vec<String>,
    cargo_deny_ignore: Vec<String>,
    dependency_check_warnings: Vec<String>,
}

impl AdvisoryPolicy {
    fn all_ids(&self) -> Vec<String> {
        let mut ids = self.cargo_audit_ignore.clone();
        ids.extend(self.cargo_deny_ignore.iter().cloned());
        ids.extend(self.dependency_check_warnings.iter().cloned());
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

fn read_advisory_policy(workspace_root: &Utf8PathBuf) -> Result<AdvisoryPolicy> {
    let contents = read_required_text_file(&workspace_root.join("security/advisories.toml"))?;
    let cargo_audit_ignore = collect_section_rustsec_ids(&contents, "cargo_audit");
    let cargo_deny_ignore = collect_section_rustsec_ids(&contents, "cargo_deny");
    let dependency_check_warnings = collect_section_rustsec_ids(&contents, "dependency_check");

    ensure!(
        !cargo_audit_ignore.is_empty(),
        "security/advisories.toml cargo_audit.ignore must not be empty"
    );
    ensure!(
        !cargo_deny_ignore.is_empty(),
        "security/advisories.toml cargo_deny.ignore must not be empty"
    );
    ensure!(
        !dependency_check_warnings.is_empty(),
        "security/advisories.toml dependency_check.warnings must not be empty"
    );
    validate_advisory_metadata_sections(&contents, &{
        let mut ids = cargo_audit_ignore.clone();
        ids.extend(cargo_deny_ignore.iter().cloned());
        ids.extend(dependency_check_warnings.iter().cloned());
        ids.sort_unstable();
        ids.dedup();
        ids
    })?;

    Ok(AdvisoryPolicy {
        cargo_audit_ignore,
        cargo_deny_ignore,
        dependency_check_warnings,
    })
}

fn validate_advisory_metadata_sections(contents: &str, advisory_ids: &[String]) -> Result<()> {
    let today = current_calendar_date()?;

    for advisory_id in advisory_ids {
        let section_marker = format!("[metadata.{advisory_id}]");
        ensure!(
            contents.contains(&section_marker),
            "security/advisories.toml is missing metadata for {advisory_id}"
        );

        let section = advisory_metadata_section(contents, &section_marker)
            .with_context(|| format!("failed to read metadata section for {advisory_id}"))?;
        for required_key in ["owner", "review_date", "exit_condition", "reachability"] {
            ensure!(
                section
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{required_key} ="))),
                "security/advisories.toml metadata for {advisory_id} must define `{required_key}`"
            );
        }

        let review_date = advisory_metadata_value(section, "review_date")
            .with_context(|| format!("missing review_date for {advisory_id}"))?;
        let review_date_value = parse_calendar_date(&review_date)
            .with_context(|| format!("invalid review_date for {advisory_id}: {review_date}"))?;
        ensure!(
            review_date_value >= today,
            "security/advisories.toml metadata for {advisory_id} has expired review_date {review_date} (today is {})",
            format_calendar_date(today)
        );
    }

    Ok(())
}

fn advisory_metadata_section<'a>(contents: &'a str, section_marker: &str) -> Option<&'a str> {
    let start = contents.find(section_marker)?;
    let remainder = &contents[start + section_marker.len()..];
    let end = remainder
        .find("\n[")
        .map(|offset| start + section_marker.len() + offset)
        .unwrap_or(contents.len());
    Some(&contents[start..end])
}

fn advisory_metadata_value(section: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} =");
    section
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(&prefix))
        .map(str::trim)
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.strip_suffix('"'))
        .map(ToOwned::to_owned)
}

fn current_calendar_date() -> Result<(u32, u32, u32)> {
    let output = Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .context("failed to execute `date` to determine the current review date")?;
    ensure!(output.status.success(), "`date` exited unsuccessfully");

    let today = String::from_utf8(output.stdout).context("`date` output was not valid UTF-8")?;
    parse_calendar_date(today.trim())
}

fn parse_calendar_date(value: &str) -> Result<(u32, u32, u32)> {
    ensure!(
        value.len() == 10
            && value.as_bytes().get(4) == Some(&b'-')
            && value.as_bytes().get(7) == Some(&b'-'),
        "expected YYYY-MM-DD"
    );

    let year = value[0..4]
        .parse::<u32>()
        .with_context(|| format!("invalid year component in {value}"))?;
    let month = value[5..7]
        .parse::<u32>()
        .with_context(|| format!("invalid month component in {value}"))?;
    let day = value[8..10]
        .parse::<u32>()
        .with_context(|| format!("invalid day component in {value}"))?;

    ensure!((1..=12).contains(&month), "month must be between 01 and 12");
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => unreachable!("validated month range"),
    };
    ensure!(
        (1..=max_day).contains(&day),
        "day must be between 01 and {max_day:02}"
    );

    Ok((year, month, day))
}

const fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn format_calendar_date((year, month, day): (u32, u32, u32)) -> String {
    format!("{year:04}-{month:02}-{day:02}")
}

fn read_deny_advisory_ids(workspace_root: &Utf8PathBuf) -> Result<Vec<String>> {
    let contents = read_required_text_file(&workspace_root.join("deny.toml"))?;
    let mut ids = Vec::new();
    let mut in_advisories = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_advisories = trimmed == "[advisories]";
            continue;
        }
        if !in_advisories || !trimmed.starts_with('"') {
            continue;
        }
        if let Some(id) = extract_rustsec_id(trimmed) {
            ids.push(id);
        }
    }

    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn collect_section_rustsec_ids(contents: &str, section: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut in_section = false;
    let section_marker = format!("[{section}]");

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == section_marker;
            continue;
        }
        if !in_section {
            continue;
        }
        ids.extend(extract_rustsec_ids(trimmed));
    }

    ids.sort_unstable();
    ids.dedup();
    ids
}

fn extract_rustsec_ids(line: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut search_start = 0;

    while let Some(offset) = line[search_start..].find("RUSTSEC-") {
        let start = search_start + offset;
        let mut end = start + "RUSTSEC-".len();
        while end < line.len() {
            let byte = line.as_bytes()[end];
            if byte.is_ascii_digit() || byte == b'-' {
                end += 1;
            } else {
                break;
            }
        }
        ids.push(line[start..end].to_owned());
        search_start = end;
    }

    ids
}

fn extract_rustsec_id(line: &str) -> Option<String> {
    extract_rustsec_ids(line).into_iter().next()
}

fn collect_rustsec_ids(contents: &str) -> Vec<String> {
    let mut ids = Vec::new();

    for line in contents.lines() {
        ids.extend(extract_rustsec_ids(line));
    }

    ids.sort_unstable();
    ids.dedup();
    ids
}

fn audit_command_args(ignore_ids: &[String]) -> Vec<String> {
    let mut args = vec!["audit".to_owned(), "--json".to_owned()];
    for ignore_id in ignore_ids {
        args.push("--ignore".to_owned());
        args.push(ignore_id.clone());
    }
    args
}

fn validate_benchmark_report(
    path: &Utf8PathBuf,
    expected_commit: &str,
    expected_device_label: &str,
    expected_backend_profile: &str,
    expected_backend_name: &str,
) -> Result<ValidatedBenchmarkMetadata> {
    validate_benchmark_report_with_commit_policy(
        path,
        expected_commit,
        expected_device_label,
        expected_backend_profile,
        expected_backend_name,
        false,
    )
}

fn validate_benchmark_report_with_commit_policy(
    path: &Utf8PathBuf,
    expected_commit: &str,
    expected_device_label: &str,
    expected_backend_profile: &str,
    expected_backend_name: &str,
    allow_stale_commit: bool,
) -> Result<ValidatedBenchmarkMetadata> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let json: Value =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;

    ensure_json_u64(&json, "generated_at_unix_seconds", path)?;
    let git_commit = ensure_json_string(&json, "git_commit", path)?;
    if !allow_stale_commit {
        ensure!(
            git_commit == expected_commit,
            "{} git_commit mismatch: expected {} but found {}",
            path,
            expected_commit,
            git_commit
        );
    }
    ensure_json_string(&json, "sdk_version", path)?;
    let backend_name = ensure_json_string(&json, "backend_name", path)?;
    ensure!(
        backend_name == expected_backend_name,
        "{} backend_name mismatch: expected {} but found {}",
        path,
        expected_backend_name,
        backend_name
    );
    let device_label = ensure_json_string(&json, "device_label", path)?;
    ensure!(
        device_label == expected_device_label,
        "{} device_label mismatch: expected {} but found {}",
        path,
        expected_device_label,
        device_label
    );
    ensure_json_string(&json, "device_model", path)?;
    ensure_json_string(&json, "device_class", path)?;
    ensure_json_string(&json, "cpu_model", path)?;
    ensure_json_string(&json, "os_name", path)?;
    ensure_json_string(&json, "os_version", path)?;
    ensure_json_string(&json, "rustc_version_verbose", path)?;
    ensure_json_string(&json, "cargo_version", path)?;
    ensure_json_string(&json, "benchmark_scenario_id", path)?;
    let artifact_version = ensure_json_string(&json, "artifact_version", path)?;
    let zkey_sha256 = ensure_json_string(&json, "zkey_sha256", path)?;
    let manifest_sha256 = ensure_json_string(&json, "manifest_sha256", path)?;
    let artifact_bundle_sha256 = ensure_json_string(&json, "artifact_bundle_sha256", path)?;
    ensure_json_string(&json, "manifest_path", path)?;
    ensure_json_string(&json, "artifacts_root", path)?;

    let backend_profile = ensure_json_string(&json, "backend_profile", path)?;
    ensure!(
        backend_profile == expected_backend_profile,
        "{} backend_profile mismatch: expected {} but found {}",
        path,
        expected_backend_profile,
        backend_profile
    );

    for field in [
        "artifact_resolution_ms",
        "bundle_verification_ms",
        "session_preload_ms",
        "first_input_preparation_ms",
        "first_witness_generation_ms",
        "first_proof_generation_ms",
        "first_verification_ms",
        "first_prove_and_verify_ms",
    ] {
        ensure_json_number(&json, field, path)?;
    }

    let iterations = ensure_json_u64(&json, "iterations", path)? as usize;
    ensure_json_u64(&json, "warmup", path)?;

    for field in [
        "input_preparation",
        "witness_generation",
        "proof_generation",
        "verification",
        "prove_and_verify",
    ] {
        let summary = json
            .get(field)
            .and_then(Value::as_object)
            .with_context(|| format!("{} missing object field `{field}`", path))?;
        for summary_field in ["average_ms", "min_ms", "max_ms"] {
            ensure!(
                summary
                    .get(summary_field)
                    .and_then(Value::as_f64)
                    .is_some_and(|value| value >= 0.0),
                "{} missing non-negative numeric field `{}.{}`",
                path,
                field,
                summary_field
            );
        }
    }

    let samples = json
        .get("samples")
        .and_then(Value::as_array)
        .with_context(|| format!("{} missing array field `samples`", path))?;
    ensure!(
        !samples.is_empty(),
        "{} samples array must not be empty",
        path
    );
    ensure!(
        samples.len() == iterations,
        "{} samples length {} does not match iterations {} for backend {}",
        path,
        samples.len(),
        iterations,
        expected_backend_name
    );

    Ok(ValidatedBenchmarkMetadata {
        git_commit: git_commit.to_owned(),
        device_label: device_label.to_owned(),
        device_model: ensure_json_string(&json, "device_model", path)?.to_owned(),
        device_class: ensure_json_string(&json, "device_class", path)?.to_owned(),
        benchmark_scenario_id: ensure_json_string(&json, "benchmark_scenario_id", path)?.to_owned(),
        artifact_version: artifact_version.to_owned(),
        zkey_sha256: zkey_sha256.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        artifact_bundle_sha256: artifact_bundle_sha256.to_owned(),
    })
}

fn validate_mobile_smoke_evidence(path: &Utf8PathBuf, expected_commit: &str) -> Result<()> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let json: Value =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;

    validate_mobile_smoke_evidence_value(&json, path, expected_commit)
}

fn validate_mobile_smoke_evidence_value(
    json: &Value,
    path: &Utf8PathBuf,
    expected_commit: &str,
) -> Result<()> {
    let commit = ensure_json_string(json, "commit", path)?;
    ensure!(
        commit == expected_commit,
        "{} commit mismatch: expected {} but found {}",
        path,
        expected_commit,
        commit
    );

    validate_mobile_evidence_identity(json, path)?;

    let surfaces = json
        .get("surfaces")
        .and_then(Value::as_object)
        .with_context(|| format!("{} missing object field `surfaces`", path))?;
    for surface in [
        "iosNative",
        "iosReactNative",
        "androidNative",
        "androidReactNative",
    ] {
        let status = surfaces
            .get(surface)
            .and_then(Value::as_str)
            .with_context(|| format!("{} missing string field `surfaces.{surface}`", path))?;
        ensure!(
            status == "passed",
            "{} surfaces.{surface} status must be `passed`, found `{status}`",
            path
        );
    }

    for platform in ["ios", "android"] {
        let status = ensure_json_string(json, platform, path)?;
        ensure!(
            status == "passed",
            "{} {platform} status must be `passed`, found `{status}`",
            path
        );
    }

    Ok(())
}

fn validate_mobile_parity_evidence(path: &Utf8PathBuf, expected_commit: &str) -> Result<Value> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let json: Value =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;

    validate_mobile_parity_evidence_value(&json, path, expected_commit)
}

fn validate_mobile_parity_evidence_value(
    json: &Value,
    path: &Utf8PathBuf,
    expected_commit: &str,
) -> Result<Value> {
    let commit = ensure_json_string(json, "commit", path)?;
    ensure!(
        commit == expected_commit,
        "{} commit mismatch: expected {} but found {}",
        path,
        expected_commit,
        commit
    );

    validate_mobile_evidence_identity(json, path)?;

    let total_checks = ensure_json_u64(json, "totalChecks", path)?;
    let passed = ensure_json_u64(json, "passed", path)?;
    let failed = ensure_json_u64(json, "failed", path)?;
    ensure!(
        total_checks > 0 && failed == 0 && passed == total_checks,
        "{} parity summary must have all checks passing",
        path
    );

    let mut platform_summaries = Vec::new();
    for platform in ["ios", "android"] {
        let report = json
            .get(platform)
            .and_then(Value::as_object)
            .with_context(|| format!("{} missing object field `{platform}`", path))?;
        let platform_total = ensure_json_u64_object(report, "totalChecks", path, platform)?;
        let platform_passed = ensure_json_u64_object(report, "passed", path, platform)?;
        let platform_failed = ensure_json_u64_object(report, "failed", path, platform)?;
        ensure!(
            platform_total > 0 && platform_failed == 0 && platform_passed == platform_total,
            "{} {platform}.parity must contain only passing checks",
            path
        );
        let native = validate_mobile_surface_report(
            report
                .get("native")
                .with_context(|| format!("{} missing object field `{platform}.native`", path))?,
            path,
            platform,
            "native",
            "native",
        )?;
        let react_native = validate_mobile_surface_report(
            report.get("reactNative").with_context(|| {
                format!("{} missing object field `{platform}.reactNative`", path)
            })?,
            path,
            platform,
            "react-native-app",
            "react-native",
        )?;

        ensure!(
            platform_total == native.total_checks + react_native.total_checks,
            "{} {platform}.totalChecks must equal native + reactNative totals",
            path
        );
        ensure!(
            platform_passed == native.passed + react_native.passed,
            "{} {platform}.passed must equal native + reactNative passed",
            path
        );
        ensure!(
            platform_failed == native.failed + react_native.failed,
            "{} {platform}.failed must equal native + reactNative failed",
            path
        );

        platform_summaries.push(json!({
            "platform": platform,
            "totalChecks": platform_total,
            "nativeBenchmarkSamples": native.benchmark_samples,
            "reactNativeBenchmarkSamples": react_native.benchmark_samples,
        }));
    }

    Ok(json!({
        "path": path.as_str(),
        "totalChecks": total_checks,
        "passed": passed,
        "failed": failed,
        "platforms": platform_summaries,
    }))
}

fn validate_mobile_evidence_identity(json: &Value, path: &Utf8PathBuf) -> Result<()> {
    let source = ensure_json_string(json, "source", path)?;
    let workflow = ensure_json_string(json, "workflow", path)?;
    let run_url = ensure_json_string(json, "run_url", path)?;

    match (source, workflow) {
        ("github-workflow", "mobile-smoke") => {
            ensure!(
                run_url.starts_with("https://"),
                "{} hosted mobile evidence run_url must be an https URL",
                path
            );
        }
        ("local-xtask", "mobile-smoke-local") => {
            ensure!(
                run_url == "local://mobile-smoke-local",
                "{} local mobile evidence run_url must be local://mobile-smoke-local",
                path
            );
        }
        ("github-workflow", other) => {
            bail!(
                "{} workflow mismatch for hosted mobile evidence: expected mobile-smoke but found {}",
                path,
                other
            );
        }
        ("local-xtask", other) => {
            bail!(
                "{} workflow mismatch for local mobile evidence: expected mobile-smoke-local but found {}",
                path,
                other
            );
        }
        (other, _) => {
            bail!(
                "{} source mismatch: expected github-workflow or local-xtask but found {}",
                path,
                other
            );
        }
    }

    Ok(())
}

#[derive(Debug)]
struct MobileSurfaceSummary {
    total_checks: u64,
    passed: u64,
    failed: u64,
    benchmark_samples: usize,
}

fn validate_mobile_surface_report(
    value: &Value,
    path: &Utf8PathBuf,
    expected_platform: &str,
    expected_runtime: &str,
    expected_surface: &str,
) -> Result<MobileSurfaceSummary> {
    let report = value.as_object().with_context(|| {
        format!(
            "{} {} {} report must be an object",
            path, expected_platform, expected_surface
        )
    })?;
    ensure!(
        report
            .get("runtime")
            .and_then(Value::as_str)
            .is_some_and(|runtime| runtime == expected_runtime),
        "{} {} {} runtime must equal `{expected_runtime}`",
        path,
        expected_platform,
        expected_surface
    );
    ensure!(
        report
            .get("platform")
            .and_then(Value::as_str)
            .is_some_and(|platform| platform == expected_platform),
        "{} {} {} platform must equal `{expected_platform}`",
        path,
        expected_platform,
        expected_surface
    );
    ensure!(
        report
            .get("surface")
            .and_then(Value::as_str)
            .is_some_and(|surface| surface == expected_surface),
        "{} {} {} surface must equal `{expected_surface}`",
        path,
        expected_platform,
        expected_surface
    );

    let smoke = report
        .get("smoke")
        .and_then(Value::as_object)
        .with_context(|| {
            format!(
                "{} missing object field `{expected_platform}.{expected_surface}.smoke`",
                path
            )
        })?;
    for field in [
        "commitmentVerified",
        "withdrawalVerified",
        "executionSubmitted",
        "signedManifestVerified",
        "wrongSignedManifestPublicKeyRejected",
        "tamperedSignedManifestArtifactsRejected",
        "tamperedProofRejected",
        "handleKindMismatchRejected",
        "staleVerifiedProofHandleRejected",
        "staleCommitmentSessionRejected",
        "staleWithdrawalSessionRejected",
        "wrongRootRejected",
        "wrongChainIdRejected",
        "wrongCodeHashRejected",
        "wrongSignerRejected",
    ] {
        ensure!(
            smoke
                .get(field)
                .and_then(Value::as_bool)
                .is_some_and(|value| value),
            "{} {} {}.smoke.{field} must be true",
            path,
            expected_platform,
            expected_surface
        );
    }

    let parity = report
        .get("parity")
        .and_then(Value::as_object)
        .with_context(|| {
            format!(
                "{} missing object field `{expected_platform}.{expected_surface}.parity`",
                path
            )
        })?;
    let total_checks = parity
        .get("totalChecks")
        .and_then(Value::as_u64)
        .with_context(|| {
            format!(
                "{} missing `{expected_platform}.{expected_surface}.parity.totalChecks`",
                path
            )
        })?;
    let passed = parity
        .get("passed")
        .and_then(Value::as_u64)
        .with_context(|| {
            format!(
                "{} missing `{expected_platform}.{expected_surface}.parity.passed`",
                path
            )
        })?;
    let failed = parity
        .get("failed")
        .and_then(Value::as_u64)
        .with_context(|| {
            format!(
                "{} missing `{expected_platform}.{expected_surface}.parity.failed`",
                path
            )
        })?;
    ensure!(
        total_checks > 0 && failed == 0 && passed == total_checks,
        "{} {} {} parity must contain only passing checks",
        path,
        expected_platform,
        expected_surface
    );

    let benchmark = report
        .get("benchmark")
        .and_then(Value::as_object)
        .with_context(|| {
            format!(
                "{} missing object field `{expected_platform}.{expected_surface}.benchmark`",
                path
            )
        })?;
    let samples = benchmark
        .get("samples")
        .and_then(Value::as_array)
        .with_context(|| {
            format!(
                "{} missing `{expected_platform}.{expected_surface}.benchmark.samples`",
                path
            )
        })?;
    ensure!(
        !samples.is_empty(),
        "{} {} {}.benchmark.samples must not be empty",
        path,
        expected_platform,
        expected_surface
    );

    Ok(MobileSurfaceSummary {
        total_checks,
        passed,
        failed,
        benchmark_samples: samples.len(),
    })
}

fn ensure_json_u64_object(
    object: &serde_json::Map<String, Value>,
    field: &str,
    path: &Utf8PathBuf,
    context: &str,
) -> Result<u64> {
    object.get(field).and_then(Value::as_u64).with_context(|| {
        format!(
            "{} missing unsigned integer field `{context}.{field}`",
            path
        )
    })
}

fn ensure_json_string<'a>(json: &'a Value, field: &str, path: &Utf8PathBuf) -> Result<&'a str> {
    json.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{} missing non-empty string field `{field}`", path))
}

fn ensure_json_number(json: &Value, field: &str, path: &Utf8PathBuf) -> Result<f64> {
    json.get(field)
        .and_then(Value::as_f64)
        .filter(|value| *value >= 0.0)
        .with_context(|| format!("{} missing non-negative numeric field `{field}`", path))
}

fn ensure_json_u64(json: &Value, field: &str, path: &Utf8PathBuf) -> Result<u64> {
    json.get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("{} missing unsigned integer field `{field}`", path))
}

fn is_hex_commit(value: &str) -> bool {
    let length = value.len();
    (7..=40).contains(&length) && value.chars().all(|character| character.is_ascii_hexdigit())
}

