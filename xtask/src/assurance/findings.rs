fn assurance_selected_specs(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
) -> Result<Vec<AssuranceCheckSpec>> {
    let benchmark_report = options.out_dir.join(format!(
        "{}-withdraw-{}.json",
        options.device_label,
        options.backend.as_str()
    ));
    let rust_compare_report = options.out_dir.join("v1-rust-comparison.json");
    let rust_compare_raw_report = options.out_dir.join("v1-rust-parity-rust.json");
    let browser_compare_report = options.out_dir.join("v1-npm-comparison.json");
    let browser_compare_smoke_report = options.out_dir.join("v1-npm-comparison-smoke.json");

    let specs = build_assurance_catalog(
        workspace_root,
        options,
        &benchmark_report,
        &rust_compare_report,
        &rust_compare_raw_report,
        &browser_compare_report,
        &browser_compare_smoke_report,
    )
    .into_iter()
    .filter(|spec| profile_selected(options.profile, &spec.allowed_profiles))
    .filter(|spec| runtime_selected(options.runtime, &spec.runtimes))
    .collect::<Vec<_>>();

    filter_assurance_specs_for_requested_checks(specs, options.only_checks.as_ref())
}

fn filter_assurance_specs_for_requested_checks(
    specs: Vec<AssuranceCheckSpec>,
    requested: Option<&Vec<String>>,
) -> Result<Vec<AssuranceCheckSpec>> {
    let Some(requested) = requested else {
        return Ok(specs);
    };

    let spec_lookup = specs
        .iter()
        .map(|spec| (spec.id.clone(), spec))
        .collect::<BTreeMap<_, _>>();
    let mut required = BTreeSet::<String>::new();
    let mut queue = requested.clone();

    while let Some(id) = queue.pop() {
        let spec = spec_lookup.get(&id).with_context(|| {
            format!("unknown assurance check id `{id}` for this profile/runtime")
        })?;
        if !required.insert(id.clone()) {
            continue;
        }
        queue.extend(spec.depends_on.iter().cloned());
    }

    Ok(specs
        .into_iter()
        .filter(|spec| required.contains(&spec.id))
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn assurance_check_spec(
    id: impl Into<String>,
    label: impl Into<String>,
    runtimes: Vec<AssuranceRuntime>,
    risk_class: &'static str,
    mode: AssuranceCheckMode,
    program: impl Into<String>,
    args: Vec<String>,
    current_dir: Utf8PathBuf,
    envs: Vec<(String, String)>,
    log_name: impl Into<String>,
    expected_outputs: Vec<Utf8PathBuf>,
    thresholds: Option<Value>,
) -> AssuranceCheckSpec {
    let label = label.into();
    AssuranceCheckSpec {
        id: id.into(),
        label: label.clone(),
        runtimes,
        allowed_profiles: vec![
            AssuranceProfile::Pr,
            AssuranceProfile::Nightly,
            AssuranceProfile::Release,
        ],
        depends_on: Vec::new(),
        scenario_tags: vec![],
        risk_class,
        mode,
        program: program.into(),
        args,
        current_dir,
        envs,
        log_name: log_name.into(),
        rationale: format!("Run `{label}` to cover {risk_class} regressions in this lane."),
        inputs: Value::Null,
        expected_outputs,
        thresholds,
    }
}

fn assurance_check_with_profiles(
    mut spec: AssuranceCheckSpec,
    allowed_profiles: Vec<AssuranceProfile>,
) -> AssuranceCheckSpec {
    spec.allowed_profiles = allowed_profiles;
    spec
}

fn assurance_check_with_dependencies(
    mut spec: AssuranceCheckSpec,
    depends_on: Vec<String>,
) -> AssuranceCheckSpec {
    spec.depends_on = depends_on;
    spec
}

fn finalize_assurance_check_spec(mut spec: AssuranceCheckSpec) -> AssuranceCheckSpec {
    if spec.inputs.is_null() {
        spec.inputs = json!({
            "workingDirectory": spec.current_dir.as_str(),
            "args": spec.args.clone(),
            "env": spec
                .envs
                .iter()
                .map(|(key, value)| json!({ "key": key, "value": value }))
                .collect::<Vec<_>>(),
            "dependsOn": spec.depends_on.clone(),
            "expectedOutputs": spec.expected_outputs.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
            "thresholds": spec.thresholds.clone(),
        });
    }

    spec.scenario_tags = match spec.id.as_str() {
        "artifact-fingerprints" => vec![
            "artifact-fingerprint-drift".to_owned(),
            "verification-key-drift".to_owned(),
        ],
        "signed-manifest-sample-check" => {
            vec!["manifest-artifact-tamper-rejection".to_owned()]
        }
        "rust-malformed-input-check" => vec!["malformed-input-rejection".to_owned()],
        "rust-secret-hardening-check"
        | "release-debug-node-react-native"
        | "release-debug-browser" => {
            vec!["secret-redaction-serialization-rejection".to_owned()]
        }
        "rust-verified-proof-safety-check" => {
            vec!["handle-kind-mismatch-rejection".to_owned()]
        }
        "rust-chain-rejection-checks" => vec![
            "cross-circuit-replay-rejection".to_owned(),
            "wrong-root-rejection".to_owned(),
            "wrong-chain-id-rejection".to_owned(),
            "wrong-code-hash-rejection".to_owned(),
            "wrong-signer-rejection".to_owned(),
        ],
        "rust-signer-local-tests" => vec![
            "malformed-input-rejection".to_owned(),
            "wrong-chain-id-rejection".to_owned(),
        ],
        "compare-rust-goldens-rust"
        | "compare-rust-goldens-node"
        | "compare-rust-goldens-browser"
        | "compare-rust-goldens-react-native" => vec![
            "deterministic-derivation".to_owned(),
            "merkle-witness".to_owned(),
        ],
        "compare-rust-stateful-node" | "compare-rust-stateful-react-native" => {
            vec!["stateful-wrapper-parity".to_owned()]
        }
        "sdk-browser-smoke" => vec!["signed-manifest-prove-verify-happy-path".to_owned()],
        "compare-v1-rust" => vec![
            "public-signal-canonicalization".to_owned(),
            "proof-field-canonicalization".to_owned(),
            "v1-proof-interoperability".to_owned(),
            "proof-tamper-rejection".to_owned(),
        ],
        "sdk-node-fail-closed-checks" => vec![
            "manifest-artifact-tamper-rejection".to_owned(),
            "proof-tamper-rejection".to_owned(),
            "malformed-input-rejection".to_owned(),
            "wrong-root-rejection".to_owned(),
            "wrong-chain-id-rejection".to_owned(),
            "wrong-code-hash-rejection".to_owned(),
            "wrong-signer-rejection".to_owned(),
            "stale-session-rejection".to_owned(),
            "handle-kind-mismatch-rejection".to_owned(),
        ],
        "sdk-browser-fail-closed-checks" => vec![
            "manifest-artifact-tamper-rejection".to_owned(),
            "malformed-input-rejection".to_owned(),
        ],
        "sdk-browser-core" => vec![
            "proof-tamper-rejection".to_owned(),
            "stale-session-rejection".to_owned(),
            "handle-kind-mismatch-rejection".to_owned(),
        ],
        "sdk-browser-direct-execution" => vec![
            "wrong-root-rejection".to_owned(),
            "wrong-chain-id-rejection".to_owned(),
            "wrong-code-hash-rejection".to_owned(),
            "wrong-signer-rejection".to_owned(),
        ],
        "mobile-evidence-check" => vec![
            "react-native-app-smoke".to_owned(),
            "react-native-app-parity".to_owned(),
            "manifest-artifact-tamper-rejection".to_owned(),
            "proof-tamper-rejection".to_owned(),
            "stale-session-rejection".to_owned(),
            "handle-kind-mismatch-rejection".to_owned(),
            "wrong-root-rejection".to_owned(),
            "wrong-chain-id-rejection".to_owned(),
            "wrong-code-hash-rejection".to_owned(),
            "wrong-signer-rejection".to_owned(),
        ],
        _ => spec.scenario_tags,
    };

    spec.rationale = match spec.id.as_str() {
        "artifact-fingerprints" => {
            "Fail closed when proving manifests, artifact bundles, or verification keys drift.".to_owned()
        }
        "signed-manifest-sample-check" => {
            "Exercise the signed-manifest verification path in every fast assurance run.".to_owned()
        }
        "rust-malformed-input-check" => {
            "Pin malformed wire and decimal rejection to a narrow Rust check instead of inferring it from the full workspace suite.".to_owned()
        }
        "rust-secret-hardening-check" => {
            "Keep secret-domain hardening on an explicit compile-fail check instead of proxying through the workspace test umbrella.".to_owned()
        }
        "rust-verified-proof-safety-check" => {
            "Keep verified-proof handle safety tied to an explicit compile-fail planner check.".to_owned()
        }
        "rust-chain-rejection-checks" => {
            "Run exact chain-level rejection checks for replay, root, chain-id, code-hash, and signer mismatches.".to_owned()
        }
        "rust-signer-local-tests" => {
            "Run the signer crate's local-mnemonic tests explicitly so bad-mnemonic and zero-chain-id regressions stay PR-gated.".to_owned()
        }
        "compare-rust-goldens-rust" => {
            "Keep the Rust semantic source aligned with checked-in deterministic goldens.".to_owned()
        }
        "compare-rust-goldens-node" => {
            "Require the Node wrapper to match Rust deterministic goldens.".to_owned()
        }
        "compare-rust-goldens-browser" => {
            "Require the browser/WASM wrapper to match Rust deterministic goldens.".to_owned()
        }
        "compare-rust-goldens-react-native" => {
            "Require the React Native wrapper to match Rust deterministic goldens.".to_owned()
        }
        "compare-rust-stateful-node" => {
            "Require the Node wrapper to match Rust stateful session and execution traces.".to_owned()
        }
        "compare-rust-stateful-react-native" => {
            "Require the React Native wrapper to match Rust stateful session and execution traces.".to_owned()
        }
        "sdk-node-fail-closed-checks" => {
            "Back Node scenario coverage with exact fail-closed tests instead of treating the full Node suite as proxy evidence.".to_owned()
        }
        "sdk-browser-fail-closed-checks" => {
            "Back browser PR coverage with exact fail-closed checks that stay off the heavy worker and verify paths.".to_owned()
        }
        "sdk-browser-core" => {
            "Keep the heavier browser verify, stale-session, and handle-mismatch checks in nightly and release instead of the fast PR lane.".to_owned()
        }
        "mobile-evidence-check" => {
            "Require nightly and release lanes to ingest passing native and React Native mobile smoke/parity evidence for both iOS and Android.".to_owned()
        }
        "release-acceptance-check" => {
            "Require release evidence to satisfy the release assurance policy for coverage, attestations, packaged signed-manifest binding, and the canonical browser package artifact.".to_owned()
        }
        "compare-v1-rust" => {
            "Run the full Rust-v1.2.0 compatibility differential before nightly and release evidence.".to_owned()
        }
        "compare-v1-npm" | "compare-v1-npm-smoke" => {
            "Collect browser-to-v1 compatibility evidence without making v1 the primary semantic source.".to_owned()
        }
        "zizmor" => {
            "Lint workflow definitions so supply-chain regressions fail before merge.".to_owned()
        }
        "geiger-delta-check" => {
            "Keep unsafe usage pinned to the reviewed allowlist.".to_owned()
        }
        "cargo-mutants-high-risk" => {
            "Scope mutation testing to the highest-risk crates instead of running it everywhere.".to_owned()
        }
        "sdk-native-build" => {
            "Build the native Node addon before wrapper parity and smoke checks consume it.".to_owned()
        }
        "sdk-native-build-release" | "release-debug-node-react-native" | "sdk-web-release-build"
        | "release-debug-browser" => {
            "Confirm release builds keep published debug escape hatches fail-closed.".to_owned()
        }
        "cargo-cyclonedx-rust" | "npm-sbom-sdk" | "npm-sbom-react-native" => {
            "Produce machine-readable SBOM evidence only in deeper assurance lanes.".to_owned()
        }
        "benchmark-withdraw" => {
            "Capture informational benchmark evidence with stable threshold metadata.".to_owned()
        }
        _ => spec.rationale,
    };

    spec
}

fn profile_selected(selected: AssuranceProfile, allowed_profiles: &[AssuranceProfile]) -> bool {
    allowed_profiles.contains(&selected)
}

fn runtime_selected(selected: AssuranceRuntime, runtimes: &[AssuranceRuntime]) -> bool {
    if matches!(selected, AssuranceRuntime::All) {
        return true;
    }
    runtimes.iter().any(|runtime| match selected {
        AssuranceRuntime::Rust => {
            matches!(runtime, AssuranceRuntime::Shared) || *runtime == AssuranceRuntime::Rust
        }
        AssuranceRuntime::Node => *runtime == AssuranceRuntime::Node,
        AssuranceRuntime::Browser => *runtime == AssuranceRuntime::Browser,
        AssuranceRuntime::ReactNative => *runtime == AssuranceRuntime::ReactNative,
        AssuranceRuntime::Shared | AssuranceRuntime::All => false,
    })
}

fn read_assurance_matrix_entries(
    workspace_root: &Utf8PathBuf,
) -> Result<Vec<AssuranceMatrixEntry>> {
    let path = workspace_root.join("security/assurance-matrix.json");
    let contents = read_required_text_file(&path)?;
    let raw_entries: Vec<AssuranceMatrixEntryRaw> =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;
    ensure!(
        !raw_entries.is_empty(),
        "{} must declare at least one assurance matrix entry",
        path
    );

    raw_entries
        .into_iter()
        .map(|entry| {
            let runtime = AssuranceRuntime::parse(&entry.runtime)?;
            ensure!(
                !matches!(runtime, AssuranceRuntime::Shared | AssuranceRuntime::All),
                "{} contains unsupported matrix runtime `{}`",
                path,
                entry.runtime
            );
            ensure!(
                !entry.profiles.is_empty(),
                "{} matrix entry for `{}` must include at least one profile",
                path,
                entry.runtime
            );
            ensure!(
                !entry.scenario_tags.is_empty(),
                "{} matrix entry for `{}` must include at least one scenario tag",
                path,
                entry.runtime
            );

            let mut seen_profiles = BTreeSet::new();
            let mut profiles = Vec::new();
            for profile in entry.profiles {
                let parsed = AssuranceProfile::parse(&profile)?;
                ensure!(
                    seen_profiles.insert(parsed.as_str().to_owned()),
                    "{} matrix entry for `{}` duplicates profile `{}`",
                    path,
                    entry.runtime,
                    profile
                );
                profiles.push(parsed);
            }

            let mut seen_tags = BTreeSet::new();
            let mut scenario_tags = Vec::new();
            for tag in entry.scenario_tags {
                ensure!(
                    seen_tags.insert(tag.clone()),
                    "{} matrix entry for `{}` duplicates scenario tag `{}`",
                    path,
                    entry.runtime,
                    tag
                );
                scenario_tags.push(tag);
            }

            Ok(AssuranceMatrixEntry {
                runtime,
                profiles,
                scenario_tags,
            })
        })
        .collect()
}

fn validate_scenario_coverage(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    selected_specs: &[AssuranceCheckSpec],
) -> Result<()> {
    let matrix = read_assurance_matrix_entries(workspace_root)?;
    let nightly_mobile_available = matches!(options.profile, AssuranceProfile::Nightly)
        && options
            .external_evidence_dir
            .as_ref()
            .map(|dir| mobile_evidence_files_present(&resolve_path_for_child(workspace_root, dir)))
            .unwrap_or(false);

    for entry in matrix {
        if !entry.profiles.contains(&options.profile)
            || !runtime_requested(options.runtime, entry.runtime)
        {
            continue;
        }

        for tag in entry.scenario_tags {
            if matches!(options.profile, AssuranceProfile::Nightly)
                && entry.runtime == AssuranceRuntime::ReactNative
                && !nightly_mobile_available
                && matches!(
                    tag.as_str(),
                    "react-native-app-smoke"
                        | "react-native-app-parity"
                        | "manifest-artifact-tamper-rejection"
                        | "proof-tamper-rejection"
                        | "stale-session-rejection"
                        | "handle-kind-mismatch-rejection"
                )
            {
                continue;
            }
            let covering_specs = selected_specs
                .iter()
                .filter(|spec| {
                    scenario_covers_runtime(spec, entry.runtime)
                        && spec.scenario_tags.iter().any(|entry| entry == &tag)
                })
                .collect::<Vec<_>>();
            ensure!(
                !covering_specs.is_empty(),
                "assurance scenario coverage is missing `{tag}` for runtime `{}` in profile `{}`",
                entry.runtime.as_str(),
                options.profile.as_str()
            );
            let exact_coverage = covering_specs
                .iter()
                .any(|spec| !is_proxy_scenario_check_id(&spec.id));
            ensure!(
                exact_coverage,
                "assurance scenario coverage for `{tag}` on runtime `{}` in profile `{}` relies only on proxy checks: {}",
                entry.runtime.as_str(),
                options.profile.as_str(),
                covering_specs
                    .iter()
                    .map(|spec| spec.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    Ok(())
}

fn runtime_requested(selected: AssuranceRuntime, required: AssuranceRuntime) -> bool {
    matches!(selected, AssuranceRuntime::All) || selected == required
}

fn scenario_covers_runtime(spec: &AssuranceCheckSpec, runtime: AssuranceRuntime) -> bool {
    spec.runtimes.iter().any(|entry| match runtime {
        AssuranceRuntime::Rust => {
            matches!(entry, AssuranceRuntime::Shared) || *entry == AssuranceRuntime::Rust
        }
        _ => *entry == runtime,
    })
}

fn is_proxy_scenario_check_id(id: &str) -> bool {
    matches!(
        id,
        "cargo-test-workspace" | "sdk-node-smoke" | "react-native-smoke"
    )
}

fn blocked_dependencies(
    spec: &AssuranceCheckSpec,
    check_statuses: &BTreeMap<String, String>,
) -> Vec<String> {
    spec.depends_on
        .iter()
        .filter(|dependency| {
            matches!(
                check_statuses.get(*dependency).map(String::as_str),
                Some("failed" | "blocked")
            )
        })
        .cloned()
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn assurance_environment_value(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    commit: &str,
    branch: &str,
    external_evidence: Option<&Value>,
    assessment: &Value,
    status: &str,
    failure_reason: Option<&str>,
) -> Result<Value> {
    let trusted_artifacts = trusted_artifact_environment(workspace_root)?;
    Ok(json!({
        "generatedAtUnixSeconds": current_unix_seconds()?,
        "gitCommit": commit,
        "branch": branch,
        "status": status,
        "failureReason": failure_reason,
        "profile": options.profile.as_str(),
        "runtime": options.runtime.as_str(),
        "reportMode": options.report_mode.as_str(),
        "backend": options.backend.as_str(),
        "deviceLabel": options.device_label.clone(),
        "deviceModel": options.device_model.clone(),
        "v1PackagePath": options.v1_package_path.as_str(),
        "v1SourcePath": options.v1_source_path.as_str(),
        "externalEvidenceDir": options.external_evidence_dir.as_ref().map(|path| path.as_str()),
        "fuzzRuns": options.fuzz_runs,
        "skipFuzz": options.skip_fuzz,
        "toolchain": {
            "rustcVerbose": command_stdout("rustc", &["-Vv"], workspace_root, "rustc -Vv failed")?.trim(),
            "cargoVersion": command_stdout("cargo", &["--version"], workspace_root, "cargo --version failed")?.trim(),
        },
        "host": {
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "deviceModel": detect_device_model(workspace_root)?,
            "cpuModel": detect_cpu_model(workspace_root)?,
        },
        "assessment": assessment,
        "trustedArtifacts": trusted_artifacts,
        "externalEvidence": external_evidence,
        "signedManifestPublicKeyConfigured": env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY").ok().is_some(),
    }))
}

fn assurance_check_record(
    spec: &AssuranceCheckSpec,
    status: &str,
    duration_ms: Option<u64>,
    log_path: &Utf8PathBuf,
    report_path: &Utf8PathBuf,
    error_message: Option<&str>,
    blocked_by: &[String],
) -> Value {
    json!({
        "id": spec.id,
        "label": spec.label,
        "runtime": spec.runtimes.iter().map(|runtime| runtime.as_str()).collect::<Vec<_>>(),
        "allowedProfiles": spec.allowed_profiles.iter().map(|profile| profile.as_str()).collect::<Vec<_>>(),
        "dependsOn": spec.depends_on.clone(),
        "blockedBy": blocked_by,
        "scenarioTags": spec.scenario_tags.clone(),
        "riskClass": spec.risk_class,
        "mode": spec.mode.as_str(),
        "normative": spec.mode.is_normative(),
        "status": status,
        "durationMs": duration_ms,
        "rationale": spec.rationale,
        "inputs": spec.inputs.clone(),
        "command": format_command(&spec.program, &spec.args),
        "logPath": log_path.as_str(),
        "reportPath": report_path.as_str(),
        "error": error_message,
        "expectedOutputs": spec.expected_outputs.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
        "thresholds": spec.thresholds.clone(),
    })
}

fn assessment_status_for_selected_checks<'a, I>(checks: I) -> AssessmentStatus
where
    I: IntoIterator<Item = &'a Value>,
{
    let collected = checks.into_iter().collect::<Vec<_>>();
    if collected.is_empty() {
        return AssessmentStatus::NotRun;
    }
    if collected
        .iter()
        .all(|check| check["status"].as_str() == Some("passed"))
    {
        AssessmentStatus::Pass
    } else if collected
        .iter()
        .all(|check| matches!(check["status"].as_str(), Some("skipped" | "missing")))
    {
        AssessmentStatus::NotRun
    } else {
        AssessmentStatus::Fail
    }
}

fn assurance_slowest_checks(checks: &[Value], limit: usize) -> Vec<Value> {
    let mut ranked = checks
        .iter()
        .filter_map(|check| {
            check["durationMs"].as_u64().map(|duration_ms| {
                (
                    duration_ms,
                    json!({
                        "id": check["id"].as_str().unwrap_or("unknown"),
                        "status": check["status"].as_str().unwrap_or("unknown"),
                        "mode": check["mode"].as_str().unwrap_or("unknown"),
                        "durationMs": duration_ms,
                    }),
                )
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(
        |(left_duration, left_check), (right_duration, right_check)| {
            right_duration
                .cmp(left_duration)
                .then_with(|| left_check["id"].as_str().cmp(&right_check["id"].as_str()))
        },
    );
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, value)| value)
        .collect()
}

fn assurance_assessment(
    _options: &AssuranceOptions,
    checks: &[Value],
    external_evidence: Option<&Value>,
) -> Value {
    let funds_safety = assessment_status_for_selected_checks(
        checks
            .iter()
            .filter(|check| check["mode"] == "normative" && check["riskClass"] == "funds-safety"),
    );
    let semantic_tags = [
        "deterministic-derivation",
        "merkle-witness",
        "public-signal-canonicalization",
        "proof-field-canonicalization",
        "v1-proof-interoperability",
    ];
    let semantic_alignment = assessment_status_for_selected_checks(checks.iter().filter(|check| {
        check["mode"] == "normative"
            && check["scenarioTags"].as_array().is_some_and(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .any(|tag| semantic_tags.iter().any(|expected| expected == &tag))
            })
    }));
    let mobile_app_evidence = external_evidence
        .and_then(|value| value.get("mobileEvidence"))
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .map_or(AssessmentStatus::NotRun, |status| match status {
            "pass" => AssessmentStatus::Pass,
            "fail" => AssessmentStatus::Fail,
            _ => AssessmentStatus::NotRun,
        });
    let ci_trend_performance = checks
        .iter()
        .find(|check| check["id"] == "benchmark-withdraw")
        .map_or(AssessmentStatus::NotRun, |check| {
            if check["status"] == "passed" {
                AssessmentStatus::Pass
            } else {
                AssessmentStatus::Fail
            }
        });
    let reference_performance = external_evidence
        .and_then(|value| value.get("referencePerformance"))
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .map_or(ReferencePerformanceStatus::Missing, |status| match status {
            "fresh" => ReferencePerformanceStatus::Fresh,
            "stale" => ReferencePerformanceStatus::Stale,
            _ => ReferencePerformanceStatus::Missing,
        });

    json!({
        "fundsSafety": funds_safety.as_str(),
        "semanticAlignment": semantic_alignment.as_str(),
        "mobileAppEvidence": mobile_app_evidence.as_str(),
        "ciTrendPerformance": ci_trend_performance.as_str(),
        "referencePerformance": reference_performance.as_str(),
    })
}

#[allow(clippy::too_many_arguments)]
fn assurance_findings(
    options: &AssuranceOptions,
    commit: &str,
    branch: &str,
    checks: &[Value],
    index_path: &Utf8PathBuf,
    findings_path: &Utf8PathBuf,
    environment_path: &Utf8PathBuf,
    benchmark_report: Option<&Utf8PathBuf>,
    rust_compare_report: Option<&Utf8PathBuf>,
    rust_compare_raw_report: Option<&Utf8PathBuf>,
    browser_report_path: Option<&Utf8PathBuf>,
    logs_dir: &Utf8PathBuf,
    external_evidence: Option<&Value>,
    assessment: &Value,
    status: &str,
    failure_reason: Option<&str>,
) -> String {
    let normative_checks = checks
        .iter()
        .filter(|check| check["mode"] == "normative")
        .count();
    let informational_checks = checks
        .iter()
        .filter(|check| check["mode"] == "informational")
        .count();
    let slowest_checks = assurance_slowest_checks(checks, 5);

    if matches!(options.report_mode, AssuranceReportMode::Standard) {
        let slowest_checks_summary = if slowest_checks.is_empty() {
            String::new()
        } else {
            let mut summary = String::from("\nslowest checks:\n");
            for check in &slowest_checks {
                let _ = writeln!(
                    summary,
                    "- `{}` ({}, {} ms)",
                    check["id"].as_str().unwrap_or("unknown"),
                    check["status"].as_str().unwrap_or("unknown"),
                    check["durationMs"].as_u64().unwrap_or_default()
                );
            }
            summary
        };
        return format!(
            "# Assurance Summary\n\n## Current Assessment\n\nblocking signals:\n- fundsSafety: {}\n- semanticAlignment: {}\n- mobileAppEvidence: {}\n\ninformational signals:\n- ciTrendPerformance: {}\n- referencePerformance: {}\n\nstatus: {status}\n{}profile: {}\nruntime: {}\ncommit: {commit}\nbranch: {branch}\nbackend: {}\ndevice: {} / {}\n\nsummary:\n- normative checks passed: {normative_checks}\n- informational checks passed: {informational_checks}\n- skipped checks: {}\n{}\
\noutputs:\n- assurance index: {index_path}\n- findings: {findings_path}\n- environment: {environment_path}\n- logs directory: {logs_dir}\n",
            assessment["fundsSafety"].as_str().unwrap_or("unknown"),
            assessment["semanticAlignment"]
                .as_str()
                .unwrap_or("unknown"),
            assessment["mobileAppEvidence"]
                .as_str()
                .unwrap_or("unknown"),
            assessment["ciTrendPerformance"]
                .as_str()
                .unwrap_or("unknown"),
            assessment["referencePerformance"]
                .as_str()
                .unwrap_or("unknown"),
            failure_reason
                .map(|reason| format!("failure: {reason}\n"))
                .unwrap_or_default(),
            options.profile.as_str(),
            options.runtime.as_str(),
            options.backend.as_str(),
            options.device_label,
            options.device_model,
            checks
                .iter()
                .filter(|check| check["status"] == "skipped")
                .count(),
            slowest_checks_summary,
        );
    }

    let mut findings = String::new();
    findings.push_str("# Assurance Audit Report\n\n");
    findings.push_str("## Current Assessment\n\n");
    findings.push_str(&format!(
        "- fundsSafety: {}\n",
        assessment["fundsSafety"].as_str().unwrap_or("unknown")
    ));
    findings.push_str(&format!(
        "- semanticAlignment: {}\n",
        assessment["semanticAlignment"]
            .as_str()
            .unwrap_or("unknown")
    ));
    findings.push_str(&format!(
        "- mobileAppEvidence: {}\n",
        assessment["mobileAppEvidence"]
            .as_str()
            .unwrap_or("unknown")
    ));
    findings.push_str(&format!(
        "- ciTrendPerformance: {}\n",
        assessment["ciTrendPerformance"]
            .as_str()
            .unwrap_or("unknown")
    ));
    findings.push_str(&format!(
        "- referencePerformance: {}\n\n",
        assessment["referencePerformance"]
            .as_str()
            .unwrap_or("unknown")
    ));
    findings.push_str(&format!("status: {status}\n"));
    if let Some(reason) = failure_reason {
        findings.push_str(&format!("failure: {reason}\n"));
    }
    findings.push_str(&format!("profile: {}\n", options.profile.as_str()));
    findings.push_str(&format!("runtime: {}\n", options.runtime.as_str()));
    findings.push_str(&format!("commit: {commit}\n"));
    findings.push_str(&format!("branch: {branch}\n"));
    findings.push_str(&format!("backend: {}\n", options.backend.as_str()));
    findings.push_str(&format!(
        "device: {} / {}\n\n",
        options.device_label, options.device_model
    ));
    if !slowest_checks.is_empty() {
        findings.push_str("slowest checks:\n");
        for check in &slowest_checks {
            findings.push_str(&format!(
                "- `{}` ({}, {} ms)\n",
                check["id"].as_str().unwrap_or("unknown"),
                check["status"].as_str().unwrap_or("unknown"),
                check["durationMs"].as_u64().unwrap_or_default(),
            ));
        }
        findings.push('\n');
    }
    findings.push_str("check rationale:\n");
    for risk_class in [
        "funds-safety",
        "correctness",
        "supply-chain",
        "performance",
        "packaging",
        "documentation",
    ] {
        let matching: Vec<&Value> = checks
            .iter()
            .filter(|check| check["riskClass"] == risk_class)
            .collect();
        if matching.is_empty() {
            continue;
        }
        findings.push_str(&format!("\n## {risk_class}\n"));
        for check in matching {
            findings.push_str(&format!(
                "- `{}`: {} (mode: {}, status: {}, durationMs: {})\n",
                check["id"].as_str().unwrap_or("unknown"),
                check["rationale"]
                    .as_str()
                    .unwrap_or("no rationale provided"),
                check["mode"].as_str().unwrap_or("unknown"),
                check["status"].as_str().unwrap_or("unknown"),
                check["durationMs"]
                    .as_u64()
                    .map_or_else(|| "n/a".to_owned(), |value| value.to_string()),
            ));
        }
    }
    findings.push_str("\nintentional divergence:\n");
    findings.push_str("- pool state root compatibility follows Privacy Pool `currentRoot()` semantics, not Entrypoint `latestRoot()`.\n");
    findings.push_str("\noutputs:\n");
    findings.push_str(&format!("- assurance index: {index_path}\n"));
    findings.push_str(&format!("- findings: {findings_path}\n"));
    findings.push_str(&format!("- environment: {environment_path}\n"));
    if let Some(path) = benchmark_report {
        findings.push_str(&format!("- benchmark report: {path}\n"));
    }
    if let Some(path) = rust_compare_report {
        findings.push_str(&format!("- rust comparison report: {path}\n"));
    }
    if let Some(path) = rust_compare_raw_report {
        findings.push_str(&format!("- rust raw report: {path}\n"));
    }
    if let Some(path) = browser_report_path {
        findings.push_str(&format!("- browser comparison report: {path}\n"));
    }
    if let Some(value) = external_evidence {
        findings.push_str(&format!(
            "- external evidence digest: {}\n",
            value["digestSha256"].as_str().unwrap_or("unknown")
        ));
    }
    findings.push_str(&format!("- logs directory: {logs_dir}\n"));
    findings
}

fn append_release_acceptance_check(
    checks: &mut Vec<AssuranceCheckSpec>,
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
) {
    if !matches!(options.profile, AssuranceProfile::Release) {
        return;
    }

    let release_evidence_dir = resolve_path_for_child(
        workspace_root,
        options
            .external_evidence_dir
            .as_ref()
            .expect("release assurance requires external evidence"),
    );
    checks.push(assurance_check_with_profiles(
        assurance_check_with_dependencies(
            assurance_check_spec(
                "release-acceptance-check",
                "cargo run -p xtask -- release-acceptance-check",
                vec![AssuranceRuntime::Shared],
                "supply-chain",
                AssuranceCheckMode::Normative,
                "cargo",
                vec![
                    "run".to_owned(),
                    "-p".to_owned(),
                    "xtask".to_owned(),
                    "--".to_owned(),
                    "release-acceptance-check".to_owned(),
                    "--dir".to_owned(),
                    release_evidence_dir.to_string(),
                    "--backend".to_owned(),
                    options.backend.as_str().to_owned(),
                ],
                workspace_root.clone(),
                vec![],
                "release-acceptance-check.log",
                vec![],
                None,
            ),
            vec![
                "external-evidence-validation".to_owned(),
                "scenario-coverage-validation".to_owned(),
            ],
        ),
        vec![AssuranceProfile::Release],
    ));
}

fn append_informational_sbom_and_benchmark_checks(
    checks: &mut Vec<AssuranceCheckSpec>,
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    benchmark_report: &Utf8PathBuf,
    sdk_sbom_report: &Utf8PathBuf,
    react_native_sbom_report: &Utf8PathBuf,
) {
    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "cargo-cyclonedx-rust",
            "cargo cyclonedx --format json",
            vec![AssuranceRuntime::Shared],
            "supply-chain",
            AssuranceCheckMode::Informational,
            "bash",
            vec![
                "-lc".to_owned(),
                format!(
                    "mkdir -p {bundle_dir} && cargo cyclonedx --format json --override-filename rust.cdx && while IFS= read -r path; do rel=\"${{path%/rust.cdx.json}}\"; name=\"${{rel//\\//__}}.rust.cdx.json\"; cp \"$path\" {bundle_dir}/\"$name\"; rm -f \"$path\"; done < <(find crates xtask -name rust.cdx.json | sort)",
                    bundle_dir = shell_escape_path(&options.out_dir.join("sbom/rust")),
                ),
            ],
            workspace_root.clone(),
            vec![],
            "cargo-cyclonedx-rust.log",
            vec![options.out_dir.join("sbom/rust.cdx.json")],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "npm-sbom-sdk",
            "npm sbom --json",
            vec![AssuranceRuntime::Node, AssuranceRuntime::Browser],
            "supply-chain",
            AssuranceCheckMode::Informational,
            "sh",
            vec![
                "-lc".to_owned(),
                format!(
                    "npm sbom --json --sbom-format spdx > {}",
                    shell_escape_path(sdk_sbom_report)
                ),
            ],
            workspace_root.join("packages/sdk"),
            vec![],
            "npm-sbom-sdk.log",
            vec![options.out_dir.join("sbom/sdk.spdx.json")],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "npm-sbom-react-native",
            "node ./scripts/generate-react-native-sbom.mjs",
            vec![AssuranceRuntime::ReactNative],
            "supply-chain",
            AssuranceCheckMode::Informational,
            "node",
            vec![
                "./scripts/generate-react-native-sbom.mjs".to_owned(),
                "--output".to_owned(),
                react_native_sbom_report.to_string(),
            ],
            workspace_root.join("packages/sdk"),
            vec![],
            "npm-sbom-react-native.log",
            vec![options.out_dir.join("sbom/react-native.spdx.json")],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    let benchmark_args = vec![
        "run".to_owned(),
        "--locked".to_owned(),
        "--release".to_owned(),
        "-p".to_owned(),
        "privacy-pools-sdk-cli".to_owned(),
        "--".to_owned(),
        "benchmark-withdraw".to_owned(),
        "--manifest".to_owned(),
        workspace_root
            .join("fixtures/artifacts/withdrawal-proving-manifest.json")
            .to_string(),
        "--artifacts-root".to_owned(),
        workspace_root.join("fixtures/artifacts").to_string(),
        "--backend".to_owned(),
        options.backend.as_str().to_owned(),
        "--warmup".to_owned(),
        "1".to_owned(),
        "--iterations".to_owned(),
        "5".to_owned(),
        "--report-json".to_owned(),
        benchmark_report.to_string(),
        "--device-label".to_owned(),
        options.device_label.clone(),
        "--device-model".to_owned(),
        options.device_model.clone(),
    ];
    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "benchmark-withdraw",
            "cargo run --locked --release -p privacy-pools-sdk-cli -- benchmark-withdraw",
            vec![AssuranceRuntime::Rust],
            "performance",
            AssuranceCheckMode::Informational,
            "cargo",
            benchmark_args,
            workspace_root.clone(),
            vec![],
            "benchmark-withdraw.log",
            vec![benchmark_report.clone()],
            Some(json!({
                "helperMaxDelta": 0.05,
                "proofMaxDelta": 0.15,
                "nodeWrapperOverheadMax": 0.10,
                "browserWrapperOverheadMax": 0.20,
                "reactNativeWrapperOverheadMax": 0.25,
            })),
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));
}

fn ensure_expected_outputs(spec: &AssuranceCheckSpec) -> Result<()> {
    for path in &spec.expected_outputs {
        ensure!(
            path.exists(),
            "assurance check `{}` did not produce expected output {}",
            spec.id,
            path
        );
    }
    Ok(())
}
