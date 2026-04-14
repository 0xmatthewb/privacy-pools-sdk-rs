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
        Some("react-native-package") => stage_react_native_package(args.collect()),
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
    println!("  react-native-package");
    println!("                   stage package-local React Native bindings");
    println!(
        "                   flags: --release --with-ios-native --with-android-native --with-native"
    );
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

fn stage_react_native_package(args: Vec<String>) -> Result<()> {
    let options = ReactNativePackageOptions::parse(args)?;
    let workspace_root = workspace_root()?;
    let effective_release =
        options.release || options.with_ios_native || options.with_android_native;

    generate_bindings(effective_release)?;

    if options.with_ios_native {
        build_ios_native_artifacts(&workspace_root)?;
    }

    if options.with_android_native {
        build_android_native_artifacts(&workspace_root)?;
    }

    let package_root = workspace_root.join("packages/react-native");

    stage_directory(
        &workspace_root.join("bindings/android/generated/src/main/java"),
        &package_root.join("android/generated/src/main/java"),
    )?;
    stage_directory(
        &workspace_root.join("bindings/android/src/main/kotlin"),
        &package_root.join("android/src/main/kotlin"),
    )?;
    stage_directory(
        &workspace_root.join("bindings/ios/generated"),
        &package_root.join("ios/generated"),
    )?;
    stage_directory(
        &workspace_root.join("bindings/ios/Sources/PrivacyPoolsSdk"),
        &package_root.join("ios/generated/support"),
    )?;

    let android_jni_dir = package_root.join("android/src/main/jniLibs");
    if options.with_android_native {
        stage_directory(
            &workspace_root.join("bindings/android/src/main/jniLibs"),
            &android_jni_dir,
        )?;
    } else {
        remove_path_if_exists(&android_jni_dir)?;
    }

    let ios_frameworks_dir = package_root.join("ios/frameworks");
    if options.with_ios_native {
        stage_directory(
            &workspace_root.join("bindings/ios/build/PrivacyPoolsSdkFFI.xcframework"),
            &ios_frameworks_dir.join("PrivacyPoolsSdkFFI.xcframework"),
        )?;
    } else {
        remove_path_if_exists(&ios_frameworks_dir)?;
    }

    println!("staged React Native package assets into packages/react-native");
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

fn build_ios_native_artifacts(workspace_root: &Utf8PathBuf) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("--with-ios-native requires running on macOS");
    }

    run_shell_script(
        workspace_root,
        &workspace_root.join("bindings/ios/scripts/build-xcframework.sh"),
        "failed to build iOS XCFramework",
    )
}

fn build_android_native_artifacts(workspace_root: &Utf8PathBuf) -> Result<()> {
    run_shell_script(
        workspace_root,
        &workspace_root.join("bindings/android/scripts/build-aar.sh"),
        "failed to build Android native libraries",
    )
}

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

#[derive(Debug, Default)]
struct ReactNativePackageOptions {
    release: bool,
    with_ios_native: bool,
    with_android_native: bool,
}

impl ReactNativePackageOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut options = Self::default();

        for arg in args {
            match arg.as_str() {
                "--release" => options.release = true,
                "--with-ios-native" => options.with_ios_native = true,
                "--with-android-native" => options.with_android_native = true,
                "--with-native" => {
                    options.with_ios_native = true;
                    options.with_android_native = true;
                }
                other => bail!("unknown react-native-package flag: {other}"),
            }
        }

        Ok(options)
    }
}
