#[allow(clippy::too_many_arguments)]
fn synthetic_assurance_failure_record(
    id: &str,
    label: &str,
    runtime: AssuranceRuntime,
    profile: AssuranceProfile,
    risk_class: &str,
    log_path: &Utf8PathBuf,
    report_path: &Utf8PathBuf,
    error_message: &str,
) -> Value {
    json!({
        "id": id,
        "label": label,
        "runtime": vec![runtime.as_str()],
        "allowedProfiles": vec![profile.as_str()],
        "dependsOn": [],
        "blockedBy": [],
        "scenarioTags": [],
        "riskClass": risk_class,
        "mode": AssuranceCheckMode::Normative.as_str(),
        "normative": true,
        "status": "failed",
        "durationMs": Value::Null,
        "rationale": Value::Null,
        "inputs": Value::Array(Vec::new()),
        "command": Value::Null,
        "logPath": log_path.as_str(),
        "reportPath": report_path.as_str(),
        "error": error_message,
        "expectedOutputs": Value::Array(Vec::new()),
        "thresholds": Value::Null,
    })
}

#[allow(clippy::too_many_arguments)]
fn record_assurance_precheck_failure(
    checks: &mut Vec<Value>,
    check_statuses: &mut BTreeMap<String, String>,
    failure_messages: &mut Vec<String>,
    logs_dir: &Utf8PathBuf,
    checks_dir: &Utf8PathBuf,
    runtime: AssuranceRuntime,
    profile: AssuranceProfile,
    id: &str,
    label: &str,
    risk_class: &str,
    error_message: &str,
) -> Result<()> {
    let log_path = logs_dir.join(format!("{id}.log"));
    let report_path = checks_dir.join(format!("{id}.json"));
    fs::write(&log_path, format!("{error_message}\n"))
        .with_context(|| format!("failed to write {}", log_path))?;
    let record = synthetic_assurance_failure_record(
        id,
        label,
        runtime,
        profile,
        risk_class,
        &log_path,
        &report_path,
        error_message,
    );
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&record)
            .context("failed to serialize assurance precheck record")?,
    )
    .with_context(|| format!("failed to write {}", report_path))?;
    checks.push(record);
    check_statuses.insert(id.to_owned(), "failed".to_owned());
    failure_messages.push(error_message.to_owned());
    Ok(())
}

fn assurance_merge_group_name(input: &Utf8PathBuf) -> String {
    input.file_name().map_or_else(
        || "group".to_owned(),
        |name| {
            name.trim_start_matches("assurance-pr-")
                .trim_start_matches("assurance-")
                .to_owned()
        },
    )
}

fn remap_subgroup_path(path: &str, source_root: &Utf8PathBuf, group_root: &Utf8PathBuf) -> String {
    path.strip_prefix(source_root.as_str())
        .map(|suffix| format!("{group_root}{suffix}"))
        .unwrap_or_else(|| path.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn record_merge_failure(
    checks: &mut Vec<Value>,
    failure_messages: &mut Vec<String>,
    logs_dir: &Utf8PathBuf,
    checks_dir: &Utf8PathBuf,
    runtime: AssuranceRuntime,
    profile: AssuranceProfile,
    id: &str,
    label: &str,
    risk_class: &str,
    error_message: &str,
) -> Result<()> {
    let log_path = logs_dir.join(format!("{id}.log"));
    let report_path = checks_dir.join(format!("{id}.json"));
    fs::write(&log_path, format!("{error_message}\n"))
        .with_context(|| format!("failed to write {}", log_path))?;
    let record = synthetic_assurance_failure_record(
        id,
        label,
        runtime,
        profile,
        risk_class,
        &log_path,
        &report_path,
        error_message,
    );
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&record)
            .context("failed to serialize assurance merge failure record")?,
    )
    .with_context(|| format!("failed to write {}", report_path))?;
    checks.push(record);
    failure_messages.push(error_message.to_owned());
    Ok(())
}

fn merge_assurance_outputs(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceMergeOptions,
) -> Result<()> {
    reset_directory(&options.out_dir)?;
    let logs_dir = options.out_dir.join("logs");
    let checks_dir = options.out_dir.join("checks");
    let groups_dir = options.out_dir.join("groups");
    fs::create_dir_all(&logs_dir).with_context(|| format!("failed to create {}", logs_dir))?;
    fs::create_dir_all(&checks_dir).with_context(|| format!("failed to create {}", checks_dir))?;
    fs::create_dir_all(&groups_dir).with_context(|| format!("failed to create {}", groups_dir))?;

    let commit = current_git_commit(workspace_root)?;
    let branch = current_git_branch(workspace_root)?;
    let environment_path = options.out_dir.join("environment.json");
    let index_path = options.out_dir.join("assurance-index.json");
    let findings_path = options.out_dir.join("findings.md");

    let aggregate_options = AssuranceOptions {
        profile: options.profile,
        runtime: options.runtime,
        report_mode: AssuranceReportMode::Standard,
        out_dir: options.out_dir.clone(),
        backend: BenchmarkBackendProfile::Stable,
        device_label: "desktop".to_owned(),
        device_model: detect_device_model(workspace_root)?,
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: None,
        fuzz_runs: 0,
        skip_fuzz: true,
        only_checks: None,
    };
    let expected_specs = assurance_selected_specs(workspace_root, &aggregate_options)?;
    let expected_ids = expected_specs
        .iter()
        .map(|spec| spec.id.clone())
        .collect::<BTreeSet<_>>();

    let mut seen_ids = BTreeSet::<String>::new();
    let mut group_environments = serde_json::Map::<String, Value>::new();
    let mut checks = Vec::<Value>::new();
    let mut failure_messages = Vec::<String>::new();

    for input in &options.inputs {
        let group_name = assurance_merge_group_name(input);
        let group_root = groups_dir.join(&group_name);

        if !input.exists() {
            let id = format!("missing-{}-artifact", group_name);
            let message = format!("missing subgroup assurance artifact at {}", input);
            record_merge_failure(
                &mut checks,
                &mut failure_messages,
                &logs_dir,
                &checks_dir,
                options.runtime,
                options.profile,
                &id,
                &format!("load {} subgroup artifact", group_name),
                "correctness",
                &message,
            )?;
            continue;
        }

        stage_directory(input, &group_root)?;

        let environment = match read_required_json(&group_root.join("environment.json")) {
            Ok(value) => value,
            Err(error) => {
                let id = format!("invalid-{}-environment", group_name);
                let message = format!(
                    "failed to load subgroup environment for {}: {error:#}",
                    group_name
                );
                record_merge_failure(
                    &mut checks,
                    &mut failure_messages,
                    &logs_dir,
                    &checks_dir,
                    options.runtime,
                    options.profile,
                    &id,
                    &format!("load {} subgroup environment", group_name),
                    "correctness",
                    &message,
                )?;
                continue;
            }
        };
        if environment
            .get("gitCommit")
            .and_then(Value::as_str)
            .is_some_and(|value| value != commit)
        {
            let id = format!("stale-{}-artifact", group_name);
            let message = format!(
                "subgroup {} was built for commit {} instead of {}",
                group_name,
                environment["gitCommit"].as_str().unwrap_or("unknown"),
                commit
            );
            record_merge_failure(
                &mut checks,
                &mut failure_messages,
                &logs_dir,
                &checks_dir,
                options.runtime,
                options.profile,
                &id,
                &format!("validate {} subgroup commit", group_name),
                "correctness",
                &message,
            )?;
        }
        group_environments.insert(group_name.clone(), environment);

        let subgroup_index = match read_required_json(&group_root.join("assurance-index.json")) {
            Ok(value) => value,
            Err(error) => {
                let id = format!("invalid-{}-index", group_name);
                let message = format!(
                    "failed to load subgroup index for {}: {error:#}",
                    group_name
                );
                record_merge_failure(
                    &mut checks,
                    &mut failure_messages,
                    &logs_dir,
                    &checks_dir,
                    options.runtime,
                    options.profile,
                    &id,
                    &format!("load {} subgroup index", group_name),
                    "correctness",
                    &message,
                )?;
                continue;
            }
        };
        let subgroup_checks = match subgroup_index.get("checks").and_then(Value::as_array) {
            Some(value) => value,
            None => {
                let id = format!("invalid-{}-checks", group_name);
                let message = format!("subgroup {} index is missing `checks`", group_name);
                record_merge_failure(
                    &mut checks,
                    &mut failure_messages,
                    &logs_dir,
                    &checks_dir,
                    options.runtime,
                    options.profile,
                    &id,
                    &format!("load {} subgroup checks", group_name),
                    "correctness",
                    &message,
                )?;
                continue;
            }
        };
        let original_group_root = subgroup_index
            .get("reports")
            .and_then(|reports| reports.get("environment"))
            .and_then(Value::as_str)
            .and_then(|path| Utf8PathBuf::from(path).parent().map(Utf8PathBuf::from))
            .unwrap_or_else(|| input.clone());

        for subgroup_check in subgroup_checks {
            let mut record = subgroup_check.clone();
            let id = record
                .get("id")
                .and_then(Value::as_str)
                .with_context(|| format!("subgroup {} check record is missing id", group_name))?
                .to_owned();
            ensure!(
                seen_ids.insert(id.clone()),
                "assurance-merge found duplicate check id `{}` across subgroup inputs",
                id
            );

            let merged_log_path = logs_dir.join(format!(
                "{}-{}",
                group_name,
                record
                    .get("logPath")
                    .and_then(Value::as_str)
                    .and_then(|path| Utf8PathBuf::from(path).file_name().map(str::to_owned))
                    .unwrap_or_else(|| format!("{id}.log"))
            ));
            if let Some(source_log) = record.get("logPath").and_then(Value::as_str) {
                let source_log_path = Utf8PathBuf::from(remap_subgroup_path(
                    source_log,
                    &original_group_root,
                    &group_root,
                ));
                if source_log_path.exists() {
                    fs::copy(&source_log_path, &merged_log_path).with_context(|| {
                        format!("failed to copy {} to {}", source_log_path, merged_log_path)
                    })?;
                } else {
                    fs::write(
                        &merged_log_path,
                        format!("original subgroup log is missing at {}\n", source_log_path),
                    )
                    .with_context(|| format!("failed to write {}", merged_log_path))?;
                }
            }

            let merged_report_path = checks_dir.join(format!("{id}.json"));
            record["logPath"] = Value::String(merged_log_path.to_string());
            record["reportPath"] = Value::String(merged_report_path.to_string());

            if let Some(outputs) = record
                .get_mut("expectedOutputs")
                .and_then(Value::as_array_mut)
            {
                for output in outputs {
                    if let Some(path) = output.as_str() {
                        *output = Value::String(remap_subgroup_path(
                            path,
                            &original_group_root,
                            &group_root,
                        ));
                    }
                }
            }

            fs::write(
                &merged_report_path,
                serde_json::to_vec_pretty(&record)
                    .context("failed to serialize merged assurance check record")?,
            )
            .with_context(|| format!("failed to write {}", merged_report_path))?;
            checks.push(record);
        }
    }

    let actual_catalog_ids = checks
        .iter()
        .filter_map(|check| check.get("id").and_then(Value::as_str))
        .filter(|id| expected_ids.contains(*id))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let missing_expected_checks = expected_ids
        .difference(&actual_catalog_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_expected_checks.is_empty() {
        let id = "missing-required-checks";
        let message = format!(
            "aggregate rust assurance is missing required checks: {}",
            missing_expected_checks.join(", ")
        );
        record_merge_failure(
            &mut checks,
            &mut failure_messages,
            &logs_dir,
            &checks_dir,
            options.runtime,
            options.profile,
            id,
            "validate merged subgroup coverage",
            "correctness",
            &message,
        )?;
    }

    if let Err(error) =
        validate_scenario_coverage(workspace_root, &aggregate_options, &expected_specs)
    {
        let id = "scenario-coverage-validation";
        let message = format!("assurance scenario coverage validation failed: {error:#}");
        record_merge_failure(
            &mut checks,
            &mut failure_messages,
            &logs_dir,
            &checks_dir,
            options.runtime,
            options.profile,
            id,
            "validate assurance scenario coverage",
            "correctness",
            &message,
        )?;
    }

    let assessment = assurance_assessment(&aggregate_options, &checks, None);
    let failure_reason = failure_messages.first().cloned().or_else(|| {
        checks.iter().find_map(|check| {
            let status = check.get("status").and_then(Value::as_str)?;
            let normative = check
                .get("normative")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if normative && matches!(status, "failed" | "blocked") {
                Some(
                    check
                        .get("error")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| {
                            format!(
                                "assurance check `{}` failed",
                                check["id"].as_str().unwrap_or("unknown")
                            )
                        }),
                )
            } else {
                None
            }
        })
    });
    let overall_status = if failure_reason.is_some() {
        "failed"
    } else {
        "passed"
    };
    let mut environment = assurance_environment_value(
        workspace_root,
        &aggregate_options,
        &commit,
        &branch,
        None,
        &assessment,
        overall_status,
        failure_reason.as_deref(),
    )?;
    environment["groups"] = Value::Object(group_environments);
    fs::write(
        &environment_path,
        serde_json::to_vec_pretty(&environment)
            .context("failed to serialize merged assurance environment")?,
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
        "reportMode": AssuranceReportMode::Standard.as_str(),
        "backend": BenchmarkBackendProfile::Stable.as_str(),
        "deviceLabel": "desktop",
        "deviceModel": aggregate_options.device_model.clone(),
        "externalEvidenceDir": Value::Null,
        "v1PackagePath": aggregate_options.v1_package_path.as_str(),
        "v1SourcePath": aggregate_options.v1_source_path.as_str(),
        "skipFuzz": true,
        "fuzzRuns": 0,
        "checks": checks,
        "reports": {
            "environment": environment_path.as_str(),
            "benchmark": Value::Null,
            "rustComparison": Value::Null,
            "rustRawReport": Value::Null,
            "browserComparison": Value::Null,
            "findings": findings_path.as_str(),
            "logs": logs_dir.as_str(),
            "externalEvidence": Value::Null,
        },
        "summary": {
            "selectedChecks": checks.len(),
            "normativeChecksPassed": checks.iter().filter(|check| check["mode"] == "normative" && check["status"] == "passed").count(),
            "informationalChecksPassed": checks.iter().filter(|check| check["mode"] == "informational" && check["status"] == "passed").count(),
            "skippedChecks": checks.iter().filter(|check| check["status"] == "skipped").count(),
            "totalDurationMs": checks.iter().filter_map(|check| check["durationMs"].as_u64()).sum::<u64>(),
            "slowestChecks": assurance_slowest_checks(&checks, 5),
            "rustSafetyChecksPassed": 0,
            "performanceRegressions": 0,
        },
        "assessment": assessment,
    });
    fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).context("failed to serialize merged assurance index")?,
    )
    .with_context(|| format!("failed to write {}", index_path))?;

    let findings = assurance_findings(
        &aggregate_options,
        &commit,
        &branch,
        index["checks"].as_array().unwrap(),
        &index_path,
        &findings_path,
        &environment_path,
        None,
        None,
        None,
        None,
        &logs_dir,
        None,
        &assessment,
        overall_status,
        index["failureReason"].as_str(),
    );
    fs::write(&findings_path, findings)
        .with_context(|| format!("failed to write {}", findings_path))?;

    if let Some(message) = index["failureReason"].as_str() {
        bail!("{message}");
    }

    println!("assurance-merge ok");
    println!("profile: {}", options.profile.as_str());
    println!("runtime: {}", options.runtime.as_str());
    println!("commit: {commit}");
    println!("output directory: {}", options.out_dir);
    Ok(())
}
