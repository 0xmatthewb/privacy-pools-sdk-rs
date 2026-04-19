fn normalize_generated_directory(path: &Utf8PathBuf) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path))?;
        let entry_path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("generated path is not valid UTF-8: {:?}", raw))?;

        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path))?
            .is_dir()
        {
            normalize_generated_directory(&entry_path)?;
            continue;
        }

        let contents = fs::read_to_string(&entry_path)
            .with_context(|| format!("failed to read generated file {}", entry_path))?;
        let normalized = strip_trailing_whitespace(&contents);

        if normalized != contents {
            fs::write(&entry_path, normalized)
                .with_context(|| format!("failed to normalize generated file {}", entry_path))?;
        }
    }

    Ok(())
}

fn wasm_remap_rustflags(workspace_root: &Utf8PathBuf) -> String {
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    push_rustflag(
        &mut rustflags,
        format!("--remap-path-prefix={workspace_root}=."),
    );

    if let Some(cargo_home) = env::var("CARGO_HOME")
        .ok()
        .or_else(|| env::var("HOME").ok().map(|home| format!("{home}/.cargo")))
    {
        push_rustflag(
            &mut rustflags,
            format!("--remap-path-prefix={cargo_home}=~/.cargo"),
        );
    }

    rustflags
}

fn push_rustflag(rustflags: &mut String, flag: String) {
    if !rustflags.is_empty() {
        rustflags.push(' ');
    }
    rustflags.push_str(&flag);
}

fn strip_wasm_custom_sections(path: &Utf8PathBuf) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("failed to read generated wasm {path}"))?;
    ensure!(
        bytes.len() >= 8 && &bytes[..4] == b"\0asm",
        "generated wasm {path} has an invalid header"
    );

    let mut stripped = bytes[..8].to_vec();
    let mut cursor = 8;

    while cursor < bytes.len() {
        let section_id = bytes[cursor];
        cursor += 1;

        let length_start = cursor;
        let payload_len = read_wasm_u32(&bytes, &mut cursor)? as usize;
        let length_end = cursor;
        let payload_start = cursor;
        let payload_end = payload_start
            .checked_add(payload_len)
            .filter(|end| *end <= bytes.len())
            .with_context(|| format!("generated wasm {path} has a truncated section"))?;

        if section_id != 0 {
            stripped.push(section_id);
            stripped.extend_from_slice(&bytes[length_start..length_end]);
            stripped.extend_from_slice(&bytes[payload_start..payload_end]);
        }

        cursor = payload_end;
    }

    if stripped.len() != bytes.len() {
        fs::write(path, stripped)
            .with_context(|| format!("failed to write stripped generated wasm {path}"))?;
    }

    Ok(())
}

fn optimize_wasm(path: &Utf8PathBuf, threaded: bool) -> Result<()> {
    if threaded {
        println!(
            "skipping wasm-opt for experimental threaded artifact; keep the Rust release profile output to preserve a practical opt-in build gate for shared-memory WASM"
        );
        return Ok(());
    }

    let optimized = path.with_extension("opt.wasm");
    let mut args = vec![
        "-O4",
        "--enable-bulk-memory-opt",
        "--enable-bulk-memory",
        "--enable-sign-ext",
        "--enable-nontrapping-float-to-int",
    ];
    args.extend(["-o", optimized.as_str(), path.as_str()]);

    let status = Command::new("wasm-opt").args(args).status().with_context(
        || "failed to invoke wasm-opt; install binaryen before release browser builds",
    )?;

    if !status.success() {
        bail!("wasm-opt failed for {path}");
    }

    fs::rename(&optimized, path)
        .with_context(|| format!("failed to replace {path} with optimized wasm"))?;

    Ok(())
}
fn read_wasm_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut result = 0u32;

    for byte_index in 0..5 {
        ensure!(
            *cursor < bytes.len(),
            "generated wasm has a truncated unsigned LEB128 value"
        );

        let byte = bytes[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7f) as u32) << (byte_index * 7);

        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }

    bail!("generated wasm has an invalid unsigned LEB128 value")
}

fn strip_trailing_whitespace(contents: &str) -> String {
    let ends_with_newline = contents.ends_with('\n');
    let mut normalized_lines: Vec<String> = contents
        .lines()
        .map(|line| line.trim_end_matches([' ', '\t']).to_owned())
        .collect();

    if ends_with_newline {
        normalized_lines.push(String::new());
    }

    normalized_lines.join("\n")
}

fn workspace_root() -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask manifest has no parent")?
            .to_path_buf(),
    )
    .map_err(|path| anyhow::anyhow!("workspace root is not valid UTF-8: {:?}", path))
}
