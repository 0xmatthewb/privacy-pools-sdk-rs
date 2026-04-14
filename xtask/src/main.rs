use anyhow::{Context, Result, bail};
use camino::Utf8PathBuf;
use std::{env, fs, process::Command};
use uniffi::{
    GenerateOptions, SwiftBindingsOptions, TargetLanguage, generate, generate_swift_bindings,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("bindings") => generate_bindings(false),
        Some("bindings-release") => generate_bindings(true),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => bail!("unknown xtask command: {other}"),
    }
}

fn print_help() {
    println!("xtask");
    println!();
    println!("commands:");
    println!("  bindings         build the FFI cdylib and generate Swift/Kotlin bindings");
    println!("  bindings-release build release FFI artifacts and generate bindings from them");
}

fn generate_bindings(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let profile_dir = if release { "release" } else { "debug" };

    build_ffi_cdylib(&workspace_root, release)?;

    let library_path = workspace_root
        .join("target")
        .join(profile_dir)
        .join(cdylib_filename());

    if !library_path.exists() {
        bail!("expected FFI library at {}", library_path);
    }

    let swift_out = workspace_root.join("bindings/ios/generated");
    let kotlin_out = workspace_root.join("bindings/android/generated/src/main/java");

    reset_directory(&swift_out)?;
    reset_directory(&kotlin_out)?;

    generate_swift_bindings(SwiftBindingsOptions {
        generate_swift_sources: true,
        generate_headers: true,
        generate_modulemap: true,
        source: library_path.clone(),
        out_dir: swift_out,
        xcframework: true,
        module_name: Some("PrivacyPoolsSdkFFI".to_owned()),
        modulemap_filename: Some("PrivacyPoolsSdkFFI.modulemap".to_owned()),
        metadata_no_deps: false,
        link_frameworks: vec![],
    })
    .context("failed to generate Swift bindings")?;

    generate(GenerateOptions {
        languages: vec![TargetLanguage::Kotlin],
        source: library_path,
        out_dir: kotlin_out,
        config_override: None,
        format: false,
        crate_filter: None,
        metadata_no_deps: false,
    })
    .context("failed to generate Kotlin bindings")?;

    normalize_generated_directory(&workspace_root.join("bindings/ios/generated"))?;
    normalize_generated_directory(&workspace_root.join("bindings/android/generated"))?;

    println!("generated bindings into bindings/ios/generated and bindings/android/generated");
    Ok(())
}

fn build_ffi_cdylib(workspace_root: &Utf8PathBuf, release: bool) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("-p")
        .arg("privacy-pools-sdk-ffi")
        .arg("--lib");

    if release {
        command.arg("--release");
    }

    let status = command
        .current_dir(workspace_root)
        .status()
        .context("failed to invoke cargo build for privacy-pools-sdk-ffi")?;

    if !status.success() {
        bail!("cargo build for privacy-pools-sdk-ffi failed");
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

fn cdylib_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libprivacy_pools_sdk_ffi.dylib"
    } else if cfg!(target_os = "windows") {
        "privacy_pools_sdk_ffi.dll"
    } else {
        "libprivacy_pools_sdk_ffi.so"
    }
}
