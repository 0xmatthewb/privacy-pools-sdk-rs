fn run_assurance(workspace_root: &Utf8PathBuf, options: &AssuranceOptions) -> Result<()> {
    if matches!(options.profile, AssuranceProfile::Release)
        && options.external_evidence_dir.is_none()
    {
        bail!("release assurance requires --external-evidence-dir");
    }

    reset_directory(&options.out_dir)?;
    let logs_dir = options.out_dir.join("logs");
    let checks_dir = options.out_dir.join("checks");
    fs::create_dir_all(&logs_dir).with_context(|| format!("failed to create {}", logs_dir))?;
    fs::create_dir_all(&checks_dir).with_context(|| format!("failed to create {}", checks_dir))?;

    let commit = current_git_commit(workspace_root)?;
    let branch = current_git_branch(workspace_root)?;
    let benchmark_report = options.out_dir.join(format!(
        "{}-withdraw-{}.json",
        options.device_label,
        options.backend.as_str()
    ));
    let rust_compare_report = options.out_dir.join("v1-rust-comparison.json");
    let rust_compare_raw_report = options.out_dir.join("v1-rust-parity-rust.json");
    let browser_compare_report = options.out_dir.join("v1-npm-comparison.json");
    let browser_compare_smoke_report = options.out_dir.join("v1-npm-comparison-smoke.json");
    let environment_path = options.out_dir.join("environment.json");
    let index_path = options.out_dir.join("assurance-index.json");
    let findings_path = options.out_dir.join("findings.md");

    let selected_specs = assurance_selected_specs(workspace_root, options)?;
    let mut failure_messages = Vec::<String>::new();
    let mut checks = Vec::new();
    let mut check_statuses = BTreeMap::<String, String>::new();
    let external_evidence = match validate_external_evidence(workspace_root, options, &commit) {
        Ok(value) => {
            check_statuses.insert(
                "external-evidence-validation".to_owned(),
                "passed".to_owned(),
            );
            value
        }
        Err(error) => {
            let message = format!(
                "failed to validate external assurance evidence{}: {error:#}",
                options
                    .external_evidence_dir
                    .as_ref()
                    .map_or(String::new(), |path| format!(" at {path}"))
            );
            record_assurance_precheck_failure(
                &mut checks,
                &mut check_statuses,
                &mut failure_messages,
                &logs_dir,
                &checks_dir,
                options.runtime,
                options.profile,
                "external-evidence-validation",
                "validate external assurance evidence",
                "supply-chain",
                &message,
            )?;
            None
        }
    };
    if options.only_checks.is_some() {
        check_statuses.insert(
            "scenario-coverage-validation".to_owned(),
            "skipped".to_owned(),
        );
    } else if let Err(error) = validate_scenario_coverage(workspace_root, options, &selected_specs)
    {
        let message = format!("assurance scenario coverage validation failed: {error:#}");
        record_assurance_precheck_failure(
            &mut checks,
            &mut check_statuses,
            &mut failure_messages,
            &logs_dir,
            &checks_dir,
            options.runtime,
            options.profile,
            "scenario-coverage-validation",
            "validate assurance scenario coverage",
            "correctness",
            &message,
        )?;
    } else {
        check_statuses.insert(
            "scenario-coverage-validation".to_owned(),
            "passed".to_owned(),
        );
    }

    for spec in &selected_specs {
        let log_path = logs_dir.join(&spec.log_name);
        let check_report_path = checks_dir.join(format!("{}.json", spec.id));
        let blocked_by = blocked_dependencies(spec, &check_statuses);
        let (status, duration_ms, error_message) = if !blocked_by.is_empty() {
            (
                "blocked".to_owned(),
                None,
                Some(format!(
                    "blocked by prerequisite checks: {}",
                    blocked_by.join(", ")
                )),
            )
        } else if options.skip_fuzz && spec.id.starts_with("fuzz-") {
            ("skipped".to_owned(), None, None)
        } else if spec.id == "release-acceptance-check" {
            let started_at = Instant::now();
            match external_evidence
                .as_ref()
                .context("release-acceptance-check requires validated external evidence")
            {
                Ok(external_evidence) => {
                    match evaluate_release_acceptance_from_external_evidence(
                        workspace_root,
                        options,
                        &selected_specs,
                        external_evidence,
                    ) {
                        Ok(evaluation) => {
                            let summary = format!(
                                "release-acceptance-check ok\nreference benchmarks: {}\nattestations: {}\n",
                                evaluation.benchmark_count, evaluation.attestation_count
                            );
                            fs::write(&log_path, summary)
                                .with_context(|| format!("failed to write {}", log_path))?;
                            (
                                "passed".to_owned(),
                                Some(started_at.elapsed().as_millis() as u64),
                                None,
                            )
                        }
                        Err(error) => {
                            let message = error.to_string();
                            fs::write(&log_path, format!("{message}\n"))
                                .with_context(|| format!("failed to write {}", log_path))?;
                            (
                                "failed".to_owned(),
                                Some(started_at.elapsed().as_millis() as u64),
                                Some(message),
                            )
                        }
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    fs::write(&log_path, format!("{message}\n"))
                        .with_context(|| format!("failed to write {}", log_path))?;
                    ("failed".to_owned(), None, Some(message))
                }
            }
        } else {
            let args_ref: Vec<&str> = spec.args.iter().map(String::as_str).collect();
            let env_ref: Vec<(&str, &str)> = spec
                .envs
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            match run_command_capture(
                &spec.program,
                &args_ref,
                &spec.current_dir,
                &env_ref,
                &log_path,
                &format!("assurance check `{}` failed", spec.id),
            ) {
                Ok(duration_ms) => match ensure_expected_outputs(spec) {
                    Ok(()) => ("passed".to_owned(), Some(duration_ms), None),
                    Err(error) => {
                        let message = error.to_string();
                        ("failed".to_owned(), Some(duration_ms), Some(message))
                    }
                },
                Err(error) => {
                    let message = error.to_string();
                    ("failed".to_owned(), None, Some(message))
                }
            }
        };

        if status == "failed" && spec.mode.is_normative() {
            failure_messages.push(
                error_message
                    .clone()
                    .unwrap_or_else(|| format!("assurance check `{}` failed", spec.id)),
            );
        }
        check_statuses.insert(spec.id.clone(), status.clone());

        let record = assurance_check_record(
            spec,
            &status,
            duration_ms,
            &log_path,
            &check_report_path,
            error_message.as_deref(),
            &blocked_by,
        );
        fs::write(
            &check_report_path,
            serde_json::to_vec_pretty(&record)
                .context("failed to serialize assurance check record")?,
        )
        .with_context(|| format!("failed to write {}", check_report_path))?;
        checks.push(record);
    }

    let mut browser_report_path = None;
    if browser_compare_report.exists() {
        match validate_browser_comparison_report(&browser_compare_report) {
            Ok(()) => browser_report_path = Some(browser_compare_report.clone()),
            Err(error) => {
                failure_messages.push(format!(
                    "invalid browser comparison report in assurance output: {error:#}"
                ));
            }
        }
    } else if browser_compare_smoke_report.exists() {
        match validate_browser_comparison_report(&browser_compare_smoke_report) {
            Ok(()) => browser_report_path = Some(browser_compare_smoke_report.clone()),
            Err(error) => {
                failure_messages.push(format!(
                    "invalid browser smoke comparison report in assurance output: {error:#}"
                ));
            }
        }
    }

    let rust_comparison = if rust_compare_report.exists() {
        match validate_rust_comparison_report(&rust_compare_report) {
            Ok(value) => Some(value),
            Err(error) => {
                failure_messages.push(format!(
                    "invalid rust comparison report in assurance output: {error:#}"
                ));
                None
            }
        }
    } else {
        None
    };

    if benchmark_report.exists()
        && let Err(error) = validate_benchmark_report(
            &benchmark_report,
            &commit,
            &options.device_label,
            options.backend.report_label(),
            options.backend.as_str(),
        )
    {
        let message = format!("invalid benchmark report in assurance output: {error:#}");
        if let Some(record) = checks
            .iter_mut()
            .find(|check| check["id"] == "benchmark-withdraw")
        {
            record["status"] = Value::String("missing".to_owned());
            record["error"] = Value::String(message.clone());
        } else {
            let log_path = logs_dir.join("benchmark-withdraw.log");
            fs::write(&log_path, format!("{message}\n"))
                .with_context(|| format!("failed to write {}", log_path))?;
            let report_path = checks_dir.join("benchmark-withdraw.json");
            let record = json!({
                "id": "benchmark-withdraw",
                "label": "benchmark-withdraw",
                "runtime": vec![options.runtime.as_str()],
                "allowedProfiles": vec![options.profile.as_str()],
                "dependsOn": [],
                "blockedBy": [],
                "scenarioTags": [],
                "riskClass": "performance",
                "mode": AssuranceCheckMode::Informational.as_str(),
                "normative": false,
                "status": "missing",
                "durationMs": Value::Null,
                "rationale": Value::Null,
                "inputs": Value::Array(Vec::new()),
                "command": Value::Null,
                "logPath": log_path.as_str(),
                "reportPath": report_path.as_str(),
                "error": message,
                "expectedOutputs": Value::Array(Vec::new()),
                "thresholds": Value::Null,
            });
            fs::write(
                &report_path,
                serde_json::to_vec_pretty(&record)
                    .context("failed to serialize benchmark failure record")?,
            )
            .with_context(|| format!("failed to write {}", report_path))?;
            checks.push(record);
        }
    }

    let safety_passed = rust_comparison
        .as_ref()
        .and_then(|value| value.get("safety"))
        .and_then(|value| value.get("passed"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let performance_regressions = rust_comparison
        .as_ref()
        .and_then(|value| value.get("performance"))
        .and_then(|value| value.get("regressions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let assessment = assurance_assessment(options, &checks, external_evidence.as_ref());
    let failure_reason = failure_messages.first().cloned();
    let overall_status = if failure_reason.is_some() {
        "failed"
    } else {
        "passed"
    };
    let environment = assurance_environment_value(
        workspace_root,
        options,
        &commit,
        &branch,
        external_evidence.as_ref(),
        &assessment,
        overall_status,
        failure_reason.as_deref(),
    )?;
    fs::write(
        &environment_path,
        serde_json::to_vec_pretty(&environment)
            .context("failed to serialize assurance environment")?,
    )
    .with_context(|| format!("failed to write {}", environment_path))?;

    let index = json!({
        "generatedAtUnixSeconds": current_unix_seconds()?,
        "gitCommit": commit.clone(),
        "branch": branch.clone(),
        "status": overall_status,
        "failureReason": failure_reason,
        "profile": options.profile.as_str(),
        "runtime": options.runtime.as_str(),
        "reportMode": options.report_mode.as_str(),
        "backend": options.backend.as_str(),
        "deviceLabel": options.device_label.clone(),
        "deviceModel": options.device_model.clone(),
        "externalEvidenceDir": options.external_evidence_dir.as_ref().map(|path| path.as_str()),
        "v1PackagePath": options.v1_package_path.as_str(),
        "v1SourcePath": options.v1_source_path.as_str(),
        "skipFuzz": options.skip_fuzz,
        "fuzzRuns": options.fuzz_runs,
        "checks": checks,
        "reports": {
            "environment": environment_path.as_str(),
            "benchmark": benchmark_report.exists().then_some(benchmark_report.as_str()),
            "rustComparison": rust_compare_report.exists().then_some(rust_compare_report.as_str()),
            "rustRawReport": rust_compare_raw_report.exists().then_some(rust_compare_raw_report.as_str()),
            "browserComparison": browser_report_path.as_ref().map(|path| path.as_str()),
            "findings": findings_path.as_str(),
            "logs": logs_dir.as_str(),
            "externalEvidence": external_evidence.as_ref(),
        },
        "summary": {
            "selectedChecks": checks.len(),
            "normativeChecksPassed": checks.iter().filter(|check| check["mode"] == "normative" && check["status"] == "passed").count(),
            "informationalChecksPassed": checks.iter().filter(|check| check["mode"] == "informational" && check["status"] == "passed").count(),
            "skippedChecks": checks.iter().filter(|check| check["status"] == "skipped").count(),
            "totalDurationMs": checks.iter().filter_map(|check| check["durationMs"].as_u64()).sum::<u64>(),
            "slowestChecks": assurance_slowest_checks(&checks, 5),
            "rustSafetyChecksPassed": safety_passed,
            "performanceRegressions": performance_regressions,
        },
        "assessment": assessment,
    });
    fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).context("failed to serialize assurance index")?,
    )
    .with_context(|| format!("failed to write {}", index_path))?;

    let findings = assurance_findings(
        options,
        &commit,
        &branch,
        &checks,
        &index_path,
        &findings_path,
        &environment_path,
        benchmark_report.exists().then_some(&benchmark_report),
        rust_compare_report.exists().then_some(&rust_compare_report),
        rust_compare_raw_report
            .exists()
            .then_some(&rust_compare_raw_report),
        browser_report_path.as_ref(),
        &logs_dir,
        external_evidence.as_ref(),
        &assessment,
        overall_status,
        failure_reason.as_deref(),
    );
    fs::write(&findings_path, findings)
        .with_context(|| format!("failed to write {}", findings_path))?;

    if matches!(options.report_mode, AssuranceReportMode::Audit) {
        let audit_index_path = options.out_dir.join("audit-index.json");
        fs::copy(&index_path, &audit_index_path)
            .with_context(|| format!("failed to write compatibility alias {}", audit_index_path))?;
    }

    if let Some(message) = index["failureReason"].as_str() {
        bail!("{message}");
    }

    println!("assurance ok");
    println!("profile: {}", options.profile.as_str());
    println!("runtime: {}", options.runtime.as_str());
    println!("commit: {commit}");
    println!("output directory: {}", options.out_dir);
    Ok(())
}

