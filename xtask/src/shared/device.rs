fn detect_device_model(workspace_root: &Utf8PathBuf) -> Result<String> {
    if cfg!(target_os = "macos") {
        let model = command_stdout(
            "sysctl",
            &["-n", "hw.model"],
            workspace_root,
            "failed to detect macOS device model",
        )?;
        let trimmed = model.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }

    let arch = command_stdout(
        "uname",
        &["-m"],
        workspace_root,
        "failed to detect device architecture",
    )?;
    let trimmed = arch.trim();
    if trimmed.is_empty() {
        return Ok("unspecified".to_owned());
    }
    Ok(trimmed.to_owned())
}

fn detect_cpu_model(workspace_root: &Utf8PathBuf) -> Result<String> {
    if cfg!(target_os = "macos") {
        let cpu = command_stdout(
            "sysctl",
            &["-n", "machdep.cpu.brand_string"],
            workspace_root,
            "failed to detect macOS CPU model",
        )?;
        let trimmed = cpu.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }

    if cfg!(target_os = "linux") {
        let cpu = command_stdout(
            "sh",
            &["-lc", "lscpu | awk -F: '/Model name/ {print $2; exit}'"],
            workspace_root,
            "failed to detect Linux CPU model",
        )?;
        let trimmed = cpu.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }

    detect_device_model(workspace_root)
}

fn current_unix_seconds() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

