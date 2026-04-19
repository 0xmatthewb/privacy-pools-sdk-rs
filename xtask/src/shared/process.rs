fn run_shell_script(
    workspace_root: &Utf8PathBuf,
    script: &Utf8PathBuf,
    error_context: &str,
) -> Result<()> {
    let status = Command::new("bash")
        .arg(script)
        .current_dir(workspace_root)
        .status()
        .with_context(|| format!("failed to invoke {}", script))?;

    if !status.success() {
        bail!("{error_context}");
    }

    Ok(())
}

fn stage_directory(source: &Utf8PathBuf, destination: &Utf8PathBuf) -> Result<()> {
    if !source.exists() {
        bail!("expected source directory at {}", source);
    }

    reset_directory(destination)?;
    copy_directory_contents(source, destination)
}

fn copy_directory_contents(source: &Utf8PathBuf, destination: &Utf8PathBuf) -> Result<()> {
    for entry in fs::read_dir(source).with_context(|| format!("failed to read {}", source))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", source))?;
        let entry_path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("path is not valid UTF-8: {:?}", raw))?;
        let entry_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path))?;
        let destination_path = destination.join(
            entry_path
                .file_name()
                .context("entry path has no file name")?,
        );

        if entry_type.is_dir() {
            fs::create_dir_all(&destination_path)
                .with_context(|| format!("failed to create {}", destination_path))?;
            copy_directory_contents(&entry_path, &destination_path)?;
        } else if entry_type.is_file() {
            fs::copy(&entry_path, &destination_path).with_context(|| {
                format!("failed to copy {} to {}", entry_path, destination_path)
            })?;
        } else {
            bail!("unsupported entry type while copying {}", entry_path);
        }
    }

    Ok(())
}

fn remove_path_if_exists(path: &Utf8PathBuf) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("failed to remove {}", path))?;
    } else {
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path))?;
    }

    Ok(())
}

fn reset_directory(path: &Utf8PathBuf) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("failed to clear {}", path))?;
    }
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path))?;
    Ok(())
}

fn pack_npm_package(package_root: &Utf8PathBuf, output_root: &Utf8PathBuf) -> Result<Utf8PathBuf> {
    fs::create_dir_all(output_root).with_context(|| format!("failed to create {}", output_root))?;

    let output = Command::new("npm")
        .args(["pack", "--json"])
        .current_dir(package_root)
        .output()
        .with_context(|| format!("failed to invoke npm pack in {}", package_root))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("npm pack failed in {}: {}", package_root, stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("npm pack produced non-UTF-8 stdout")?;
    let pack_result: Value =
        serde_json::from_str(&stdout).context("failed to parse npm pack JSON output")?;
    let filename = pack_result
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("filename"))
        .and_then(Value::as_str)
        .context("npm pack JSON output did not include a filename")?;

    let source = package_root.join(filename);
    let destination = output_root.join(filename);

    if destination.exists() {
        remove_path_if_exists(&destination)?;
    }

    fs::rename(&source, &destination)
        .with_context(|| format!("failed to move {} to {}", source, destination))?;

    Ok(destination)
}

fn run_command(
    program: &str,
    args: &[&str],
    current_dir: &Utf8PathBuf,
    error_context: &str,
) -> Result<()> {
    run_command_with_env(program, args, current_dir, &[], error_context)
}

fn run_command_with_env(
    program: &str,
    args: &[&str],
    current_dir: &Utf8PathBuf,
    envs: &[(&str, &str)],
    error_context: &str,
) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args).current_dir(current_dir);
    for (key, value) in envs {
        command.env(key, value);
    }

    let status = command
        .status()
        .with_context(|| format!("failed to invoke {} in {}", program, current_dir))?;

    if !status.success() {
        bail!("{error_context}");
    }

    Ok(())
}

fn command_stdout(
    program: &str,
    args: &[&str],
    current_dir: &Utf8PathBuf,
    error_context: &str,
) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(current_dir)
        .output()
        .with_context(|| format!("failed to invoke {program} in {current_dir}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{error_context}: {}", stderr.trim());
    }

    String::from_utf8(output.stdout).context("command produced non-UTF-8 stdout")
}

fn assert_wasm_bindgen_cli_version(workspace_root: &Utf8PathBuf) -> Result<()> {
    let manifest =
        read_required_text_file(&workspace_root.join("crates/privacy-pools-sdk-web/Cargo.toml"))?;
    let expected = manifest
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("wasm-bindgen = { version = \"")
                .and_then(|rest| rest.split('"').next())
        })
        .context("failed to locate wasm-bindgen crate version in crates/privacy-pools-sdk-web/Cargo.toml")?;
    let actual = command_stdout(
        "wasm-bindgen",
        &["--version"],
        workspace_root,
        "failed to read wasm-bindgen-cli version; install wasm-bindgen-cli and ensure it is on PATH",
    )?;
    let actual = actual
        .trim()
        .strip_prefix("wasm-bindgen ")
        .unwrap_or(actual.trim());
    ensure!(
        actual == expected,
        "wasm-bindgen-cli version mismatch: expected {expected}, found {actual}"
    );
    Ok(())
}

fn command_output_bytes(
    program: &str,
    args: &[&str],
    current_dir: &Utf8PathBuf,
    error_context: &str,
) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .current_dir(current_dir)
        .output()
        .with_context(|| format!("failed to invoke {program} in {current_dir}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{error_context}: {}", stderr.trim());
    }

    Ok(output.stdout)
}

fn run_command_capture(
    program: &str,
    args: &[&str],
    current_dir: &Utf8PathBuf,
    envs: &[(&str, &str)],
    log_path: &Utf8PathBuf,
    error_context: &str,
) -> Result<u64> {
    let started_at = Instant::now();
    let mut command = Command::new(program);
    command.args(args).current_dir(current_dir);
    for (key, value) in envs {
        command.env(key, value);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to invoke {program} in {current_dir}"))?;

    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
    }
    let mut log = String::new();
    log.push_str("$ ");
    log.push_str(program);
    for arg in args {
        log.push(' ');
        log.push_str(arg);
    }
    log.push('\n');
    log.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !log.ends_with('\n') {
            log.push('\n');
        }
        log.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    fs::write(log_path, &log).with_context(|| format!("failed to write {}", log_path))?;

    if !output.status.success() {
        let log_tail = log_tail_for_error(&log, 400);
        bail!("{error_context}; see {}\n\n{}", log_path, log_tail);
    }

    Ok(started_at
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX))
}

fn log_tail_for_error(log: &str, max_lines: usize) -> String {
    let lines = log.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    let tail = lines[start..].join("\n");
    format!("--- command log tail ---\n{tail}")
}

