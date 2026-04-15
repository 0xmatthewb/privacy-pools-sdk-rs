use anyhow::{Context, Result, bail, ensure};
use camino::Utf8PathBuf;
use serde_json::Value;
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
        Some("react-native-smoke") => react_native_smoke(),
        Some("react-native-app-smoke-ios") => react_native_app_smoke("ios"),
        Some("react-native-app-smoke-android") => react_native_app_smoke("android"),
        Some("sdk-web-package") => stage_sdk_web_package(args.collect()),
        Some("sdk-smoke") => sdk_smoke(),
        Some("examples-check") => examples_check(),
        Some("feature-check") => feature_check(),
        Some("package-check") => package_check(),
        Some("dependency-check") => dependency_check(),
        Some("release-check") => release_check(args.collect()),
        Some("evidence-check") => evidence_check(args.collect()),
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
    println!("  react-native-smoke");
    println!(
        "                   install the packed RN package into the sample app and typecheck it"
    );
    println!("  react-native-app-smoke-ios");
    println!("                   run the packed RN package in an iOS Simulator app process");
    println!("  react-native-app-smoke-android");
    println!("                   run the packed RN package in an Android Emulator app process");
    println!("  sdk-web-package");
    println!("                   build optimized browser WASM bindings");
    println!("                   flags: --debug");
    println!("  sdk-smoke");
    println!("                   build the SDK package runtimes and run the JS integration tests");
    println!("  examples-check   run lightweight Rust SDK examples");
    println!("  feature-check    check supported Rust feature and wasm combinations");
    println!("  package-check    run the workspace package dry run");
    println!("  dependency-check validate accepted dependency-risk advisories");
    println!("  release-check    validate release-channel versions across public surfaces");
    println!("                   flags: --channel alpha|beta|rc|stable");
    println!("  evidence-check   validate release evidence for a channel");
    println!(
        "                   flags: --channel alpha|beta|rc|stable --dir <path> [--backend stable|fast]"
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
    } else if !android_jni_dir.exists() {
        println!(
            "warning: package-local Android native binaries are absent; run react-native-package --with-android-native before publishing"
        );
    }

    let ios_frameworks_dir = package_root.join("ios/frameworks");
    if options.with_ios_native {
        stage_directory(
            &workspace_root.join("bindings/ios/build/PrivacyPoolsSdkFFI.xcframework"),
            &ios_frameworks_dir.join("PrivacyPoolsSdkFFI.xcframework"),
        )?;
    } else if !ios_frameworks_dir.exists() {
        println!(
            "warning: package-local iOS native frameworks are absent; run react-native-package --with-ios-native before publishing"
        );
    }

    println!("staged React Native package assets into packages/react-native");
    Ok(())
}

fn react_native_smoke() -> Result<()> {
    let workspace_root = workspace_root()?;
    stage_react_native_package(Vec::new())?;

    let smoke_root = workspace_root.join("target/react-native-smoke");
    let app_template_root = workspace_root.join("examples/react-native-smoke");
    let app_root = smoke_root.join("app");
    let npm_cache_root = smoke_root.join(".npm-cache");

    stage_directory(&app_template_root, &app_root)?;
    fs::create_dir_all(&npm_cache_root)
        .with_context(|| format!("failed to create {}", npm_cache_root))?;

    let package_tarball =
        pack_npm_package(&workspace_root.join("packages/react-native"), &smoke_root)?;

    run_command_with_env(
        "npm",
        &["install", "--no-package-lock", "--ignore-scripts"],
        &app_root,
        &[("npm_config_cache", npm_cache_root.as_str())],
        "failed to install React Native smoke-app dependencies",
    )?;
    run_command_with_env(
        "npm",
        &[
            "install",
            "--no-package-lock",
            "--ignore-scripts",
            "--no-save",
            package_tarball.as_str(),
        ],
        &app_root,
        &[("npm_config_cache", npm_cache_root.as_str())],
        "failed to install packed React Native SDK into smoke app",
    )?;
    run_command(
        "npm",
        &["run", "typecheck"],
        &app_root,
        "React Native smoke app typecheck failed",
    )?;

    println!("react native smoke ok");
    Ok(())
}

fn react_native_app_smoke(platform: &str) -> Result<()> {
    let workspace_root = workspace_root()?;
    let package_args = match platform {
        "ios" => vec!["--release".to_owned(), "--with-ios-native".to_owned()],
        "android" => vec!["--release".to_owned(), "--with-android-native".to_owned()],
        _ => bail!("unknown React Native app smoke platform: {platform}"),
    };
    if react_native_app_smoke_package_ready(&workspace_root, platform) {
        println!("using existing staged React Native {platform} package assets");
    } else {
        stage_react_native_package(package_args)?;
    }

    let smoke_root = workspace_root.join("target/react-native-app-smoke");
    let npm_cache_root = smoke_root.join(".npm-cache");
    fs::create_dir_all(&npm_cache_root)
        .with_context(|| format!("failed to create {}", npm_cache_root))?;

    let package_tarball =
        pack_npm_package(&workspace_root.join("packages/react-native"), &smoke_root)?;
    let script = workspace_root.join("examples/react-native-app-smoke/scripts/run-smoke.mjs");

    run_command_with_env(
        "node",
        &[
            script.as_str(),
            platform,
            "--workspace",
            workspace_root.as_str(),
            "--tarball",
            package_tarball.as_str(),
        ],
        &workspace_root,
        &[("npm_config_cache", npm_cache_root.as_str())],
        "React Native app-process smoke failed",
    )?;

    println!("react native {platform} app-process smoke ok");
    Ok(())
}

fn react_native_app_smoke_package_ready(workspace_root: &Utf8PathBuf, platform: &str) -> bool {
    let package_root = workspace_root.join("packages/react-native");
    let common_files = [
        package_root.join("android/generated/src/main/java"),
        package_root.join("android/src/main/kotlin"),
        package_root.join("ios/generated/PrivacyPoolsSdk.swift"),
        package_root.join("ios/generated/support/PrivacyPoolsSdkClient.swift"),
    ];
    let platform_files = match platform {
        "ios" => {
            vec![package_root.join("ios/frameworks/PrivacyPoolsSdkFFI.xcframework/Info.plist")]
        }
        "android" => {
            vec![package_root.join("android/src/main/jniLibs/x86_64/libprivacy_pools_sdk_ffi.so")]
        }
        _ => return false,
    };

    common_files
        .iter()
        .chain(platform_files.iter())
        .all(|path| path.exists())
}

fn stage_sdk_web_package(args: Vec<String>) -> Result<()> {
    let mut release = true;
    for arg in args {
        match arg.as_str() {
            "--debug" => release = false,
            "--release" => release = true,
            _ => bail!("unknown sdk-web-package flag: {arg}"),
        }
    }

    let workspace_root = workspace_root()?;
    let profile = if release { "wasm-release" } else { "debug" };
    let generated_root = workspace_root.join("packages/sdk/src/browser/generated");
    let rustflags = wasm_remap_rustflags(&workspace_root);
    reset_directory(&generated_root)?;

    run_command_with_env(
        "cargo",
        &[
            "build",
            "-p",
            "privacy-pools-sdk-web",
            "--target",
            "wasm32-unknown-unknown",
            "--lib",
            if release {
                "--profile=wasm-release"
            } else {
                "--quiet"
            },
        ],
        &workspace_root,
        &[("RUSTFLAGS", rustflags.as_str())],
        "failed to build privacy-pools-sdk-web for wasm32-unknown-unknown",
    )?;

    let wasm_path = workspace_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join(profile)
        .join("privacy_pools_sdk_web.wasm");
    ensure!(
        wasm_path.exists(),
        "expected browser wasm artifact at {}",
        wasm_path
    );

    run_command(
        "wasm-bindgen",
        &[
            "--target",
            "web",
            "--out-dir",
            generated_root.as_str(),
            "--out-name",
            "privacy_pools_sdk_web",
            wasm_path.as_str(),
        ],
        &workspace_root,
        "failed to generate browser WASM bindings; install wasm-bindgen-cli and ensure it is on PATH",
    )?;

    strip_wasm_custom_sections(&generated_root.join("privacy_pools_sdk_web_bg.wasm"))?;
    if release {
        optimize_wasm(&generated_root.join("privacy_pools_sdk_web_bg.wasm"))?;
    }

    println!("staged browser WASM bindings into packages/sdk/src/browser/generated");
    Ok(())
}

fn sdk_smoke() -> Result<()> {
    let workspace_root = workspace_root()?;
    run_command(
        "npm",
        &["test"],
        &workspace_root.join("packages/sdk"),
        "SDK package integration tests failed",
    )?;

    println!("sdk smoke ok");
    Ok(())
}

fn examples_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let examples_dir = workspace_root.join("crates/privacy-pools-sdk/examples");
    let examples = discover_example_names(&examples_dir)?;
    validate_required_examples(&examples)?;

    for example in required_example_names() {
        run_command(
            "cargo",
            &["run", "-p", "privacy-pools-sdk", "--example", example],
            &workspace_root,
            &format!("Rust SDK example `{example}` failed"),
        )?;
    }

    println!("examples-check ok");
    Ok(())
}

fn feature_check() -> Result<()> {
    let workspace_root = workspace_root()?;

    for command in feature_check_commands() {
        run_command(
            command.program,
            command.args,
            &workspace_root,
            command.error_context,
        )?;
    }

    println!("feature-check ok");
    Ok(())
}

fn package_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    run_command(
        "cargo",
        package_check_args(),
        &workspace_root,
        "workspace package dry run failed",
    )?;

    println!("package-check ok");
    Ok(())
}

fn dependency_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let audit_stdout = command_stdout(
        "cargo",
        &["audit", "--ignore", "RUSTSEC-2025-0055", "--json"],
        &workspace_root,
        "cargo audit failed",
    )?;
    let audit_json: Value =
        serde_json::from_str(&audit_stdout).context("failed to parse cargo audit JSON output")?;

    let vulnerabilities_found = audit_json
        .get("vulnerabilities")
        .and_then(|value| value.get("found"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ensure!(
        !vulnerabilities_found,
        "cargo audit reported blocking vulnerabilities"
    );

    let mut advisory_ids = collect_advisory_ids(&audit_json, "unmaintained");
    advisory_ids.extend(collect_advisory_ids(&audit_json, "unsound"));
    advisory_ids.sort_unstable();

    let expected = vec![
        "RUSTSEC-2024-0388".to_owned(),
        "RUSTSEC-2024-0436".to_owned(),
        "RUSTSEC-2026-0097".to_owned(),
    ];
    ensure!(
        advisory_ids == expected,
        "unexpected dependency advisory set: expected {:?}, found {:?}",
        expected,
        advisory_ids
    );

    if advisory_ids
        .iter()
        .any(|advisory| advisory == "RUSTSEC-2026-0097")
    {
        let rand_tree = command_stdout(
            "cargo",
            &[
                "tree",
                "-e",
                "features",
                "-i",
                "rand@0.8.5",
                "-p",
                "privacy-pools-sdk",
            ],
            &workspace_root,
            "cargo tree for rand 0.8.5 failed",
        )?;
        ensure!(
            !rand_tree.contains("rand feature \"log\""),
            "rand 0.8.5 advisory became reachable because the `log` feature is enabled"
        );
    }

    println!("dependency-check ok");
    println!("accepted advisories: {}", advisory_ids.join(", "));
    println!("rand 0.8.5 reachable condition: `log` feature disabled");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: &'static [&'static str],
    error_context: &'static str,
}

fn required_example_names() -> &'static [&'static str] {
    &[
        "basic",
        "npm_migration",
        "client_builder",
        "withdrawal_paths",
        "recovery_fixture",
    ]
}

fn discover_example_names(examples_dir: &Utf8PathBuf) -> Result<Vec<String>> {
    let mut examples = Vec::new();
    for entry in fs::read_dir(examples_dir)
        .with_context(|| format!("failed to read examples directory {}", examples_dir))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", examples_dir))?;
        let entry_path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("example path is not valid UTF-8: {:?}", raw))?;

        if !entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path))?
            .is_file()
        {
            continue;
        }

        if entry_path.extension() == Some("rs") {
            examples.push(
                entry_path
                    .file_stem()
                    .context("example file path has no stem")?
                    .to_owned(),
            );
        }
    }

    examples.sort_unstable();
    Ok(examples)
}

fn validate_required_examples(examples: &[String]) -> Result<()> {
    for required in required_example_names() {
        ensure!(
            examples.iter().any(|example| example == required),
            "missing required Rust SDK example `{required}`"
        );
    }

    Ok(())
}

fn feature_check_commands() -> &'static [CommandSpec] {
    &[
        CommandSpec {
            program: "cargo",
            args: &[
                "hack",
                "check",
                "-p",
                "privacy-pools-sdk-prover",
                "--each-feature",
                "--no-dev-deps",
            ],
            error_context: "privacy-pools-sdk-prover cargo-hack feature check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-prover",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-prover no-default-features check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &["check", "-p", "privacy-pools-sdk-prover", "--all-features"],
            error_context: "privacy-pools-sdk-prover all-features check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-web",
                "--target",
                "wasm32-unknown-unknown",
            ],
            error_context: "privacy-pools-sdk-web wasm32 check failed",
        },
    ]
}

fn package_check_args() -> &'static [&'static str] {
    &["package", "--workspace", "--allow-dirty", "--no-verify"]
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

fn optimize_wasm(path: &Utf8PathBuf) -> Result<()> {
    let optimized = path.with_extension("opt.wasm");
    let status = Command::new("wasm-opt")
        .args(["-O4", "-o", optimized.as_str(), path.as_str()])
        .status()
        .with_context(
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

    let commit = read_required_text_file(&options.dir.join("commit.txt"))?;
    ensure!(
        is_hex_commit(&commit),
        "commit.txt must contain a short or full hex git commit, found `{commit}`"
    );

    let release_artifacts = read_required_text_file(&options.dir.join("release-artifacts.txt"))?;
    ensure!(
        !release_artifacts.is_empty(),
        "release-artifacts.txt must not be empty"
    );

    let canary_notes = read_required_text_file(&options.dir.join("canary-notes.md"))?;
    ensure!(
        !canary_notes.is_empty(),
        "canary-notes.md must not be empty"
    );

    validate_mobile_smoke_evidence(&options.dir.join("mobile-smoke.json"), &commit)?;

    let expected_backend_profile = options.backend.report_label();
    let mut artifact_version = None::<String>;
    let mut zkey_sha256 = None::<String>;
    for device in ["desktop", "ios", "android"] {
        let report_path = options.dir.join(format!(
            "{}-withdraw-{}.json",
            device,
            options.backend.as_str()
        ));
        let metadata = validate_benchmark_report(
            &report_path,
            &commit,
            device,
            expected_backend_profile,
            options.backend.as_str(),
        )
        .with_context(|| format!("invalid benchmark report for {device}"))?;

        match &artifact_version {
            Some(expected) => ensure!(
                metadata.artifact_version == *expected,
                "benchmark artifact_version mismatch: expected {expected} but found {} in {}",
                metadata.artifact_version,
                report_path
            ),
            None => artifact_version = Some(metadata.artifact_version.clone()),
        }

        match &zkey_sha256 {
            Some(expected) => ensure!(
                metadata.zkey_sha256 == *expected,
                "benchmark zkey_sha256 mismatch: expected {expected} but found {} in {}",
                metadata.zkey_sha256,
                report_path
            ),
            None => zkey_sha256 = Some(metadata.zkey_sha256.clone()),
        }
    }

    println!("evidence-check ok");
    println!("channel: {}", options.channel.as_str());
    println!("backend: {}", options.backend.as_str());
    println!("commit: {commit}");
    println!("evidence directory: {}", options.dir);
    Ok(())
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

#[derive(Debug, Clone, Copy)]
enum ReleaseChannel {
    Alpha,
    Beta,
    Rc,
    Stable,
}

impl ReleaseChannel {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "alpha" => Ok(Self::Alpha),
            "beta" => Ok(Self::Beta),
            "rc" => Ok(Self::Rc),
            "stable" => Ok(Self::Stable),
            other => bail!("unsupported release channel: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
            Self::Rc => "rc",
            Self::Stable => "stable",
        }
    }

    fn validate_mobile_version(self, version: &str) -> Result<()> {
        match self {
            Self::Stable => ensure!(
                !version.contains('-'),
                "stable releases must not use a prerelease suffix: {version}"
            ),
            Self::Alpha | Self::Beta | Self::Rc => {
                let (_, prerelease) = version.split_once('-').with_context(|| {
                    format!(
                        "{} releases must use a prerelease suffix: {version}",
                        self.as_str()
                    )
                })?;
                ensure!(
                    prerelease.starts_with(&format!("{}.", self.as_str())),
                    "version {version} does not match {} release channel",
                    self.as_str()
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ReleaseCheckOptions {
    channel: ReleaseChannel,
}

impl ReleaseCheckOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut channel = None;
        let mut iter = args.into_iter();

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--channel" => {
                    channel = Some(ReleaseChannel::parse(
                        &iter.next().context("--channel requires a value")?,
                    )?);
                }
                other => bail!("unknown release-check flag: {other}"),
            }
        }

        Ok(Self {
            channel: channel.context("--channel is required")?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum BenchmarkBackendProfile {
    Stable,
    Fast,
}

impl BenchmarkBackendProfile {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "stable" => Ok(Self::Stable),
            "fast" => Ok(Self::Fast),
            other => bail!("unsupported benchmark backend: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Fast => "fast",
        }
    }

    fn report_label(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Fast => "Fast",
        }
    }
}

#[derive(Debug, Clone)]
struct EvidenceCheckOptions {
    channel: ReleaseChannel,
    dir: Utf8PathBuf,
    backend: BenchmarkBackendProfile,
}

impl EvidenceCheckOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut channel = None;
        let mut dir = None;
        let mut backend = BenchmarkBackendProfile::Stable;
        let mut iter = args.into_iter();

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--channel" => {
                    channel = Some(ReleaseChannel::parse(
                        &iter.next().context("--channel requires a value")?,
                    )?);
                }
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
                other => bail!("unknown evidence-check flag: {other}"),
            }
        }

        Ok(Self {
            channel: channel.context("--channel is required")?,
            dir: dir.context("--dir is required")?,
            backend,
        })
    }
}

fn read_package_json_version(path: &Utf8PathBuf) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let json: Value =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;

    json.get("version")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("package.json is missing a string version field: {}", path))
}

fn read_keyed_string(path: &Utf8PathBuf, prefix: &str) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;

    contents
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix(prefix)
                .map(|value| value.trim().trim_matches('"').to_owned())
        })
        .with_context(|| format!("failed to find `{prefix}` in {}", path))
}

fn ensure_same_versions(label: &str, versions: &[(String, String)]) -> Result<String> {
    let first = versions
        .first()
        .context("no versions were collected for release validation")?;
    let expected = first.1.clone();

    for (path, version) in versions.iter().skip(1) {
        ensure!(
            *version == expected,
            "{label} mismatch: expected {expected} but found {version} in {path}"
        );
    }

    Ok(expected)
}

fn base_version(version: &str) -> &str {
    version.split_once('-').map_or(version, |(base, _)| base)
}

fn read_required_text_file(path: &Utf8PathBuf) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let trimmed = contents.trim().to_owned();
    ensure!(!trimmed.is_empty(), "{} must not be empty", path);
    Ok(trimmed)
}

struct ValidatedBenchmarkMetadata {
    artifact_version: String,
    zkey_sha256: String,
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

fn validate_benchmark_report(
    path: &Utf8PathBuf,
    expected_commit: &str,
    expected_device_label: &str,
    expected_backend_profile: &str,
    expected_backend_name: &str,
) -> Result<ValidatedBenchmarkMetadata> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let json: Value =
        serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path))?;

    ensure_json_u64(&json, "generated_at_unix_seconds", path)?;
    let git_commit = ensure_json_string(&json, "git_commit", path)?;
    ensure!(
        git_commit == expected_commit,
        "{} git_commit mismatch: expected {} but found {}",
        path,
        expected_commit,
        git_commit
    );
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
    ensure_json_string(&json, "os_name", path)?;
    ensure_json_string(&json, "os_version", path)?;
    let artifact_version = ensure_json_string(&json, "artifact_version", path)?;
    let zkey_sha256 = ensure_json_string(&json, "zkey_sha256", path)?;
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
        artifact_version: artifact_version.to_owned(),
        zkey_sha256: zkey_sha256.to_owned(),
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

    let workflow = ensure_json_string(json, "workflow", path)?;
    ensure!(
        workflow == "mobile-smoke",
        "{} workflow mismatch: expected mobile-smoke but found {}",
        path,
        workflow
    );

    let run_url = ensure_json_string(json, "run_url", path)?;
    ensure!(
        run_url.starts_with("https://"),
        "{} run_url must be an https URL",
        path
    );

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn evidence_path() -> Utf8PathBuf {
        Utf8PathBuf::from("mobile-smoke.json")
    }

    fn mobile_smoke_fixture(commit: &str) -> Value {
        json!({
            "commit": commit,
            "workflow": "mobile-smoke",
            "run_url": "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
            "ios": "passed",
            "android": "passed"
        })
    }

    fn benchmark_report(commit: &str, device: &str) -> Value {
        json!({
            "generated_at_unix_seconds": 1,
            "git_commit": commit,
            "sdk_version": "0.1.0-alpha.0",
            "backend_name": "stable",
            "device_label": device,
            "device_model": "fixture",
            "os_name": "fixture-os",
            "os_version": "fixture-version",
            "artifact_version": "fixture-artifacts",
            "zkey_sha256": "fixture-zkey",
            "manifest_path": "fixtures/artifacts/sample-proving-manifest.json",
            "artifacts_root": "fixtures/artifacts",
            "backend_profile": "Stable",
            "artifact_resolution_ms": 0.0,
            "bundle_verification_ms": 0.0,
            "session_preload_ms": 0.0,
            "first_input_preparation_ms": 0.0,
            "first_witness_generation_ms": 0.0,
            "first_proof_generation_ms": 0.0,
            "first_verification_ms": 0.0,
            "first_prove_and_verify_ms": 0.0,
            "iterations": 1,
            "warmup": 0,
            "input_preparation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
            "witness_generation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
            "proof_generation": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
            "verification": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
            "prove_and_verify": { "average_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0 },
            "samples": [{}]
        })
    }

    fn write_json(path: &Utf8PathBuf, value: &Value) {
        fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    #[test]
    fn examples_validation_rejects_missing_required_examples() {
        let examples = vec![
            "basic".to_owned(),
            "npm_migration".to_owned(),
            "client_builder".to_owned(),
        ];

        let error = validate_required_examples(&examples)
            .unwrap_err()
            .to_string();

        assert!(error.contains("withdrawal_paths"));
    }

    #[test]
    fn feature_check_invokes_targeted_feature_combinations() {
        let commands = feature_check_commands();

        assert!(commands.iter().any(|command| {
            command.args.contains(&"hack")
                && command.args.contains(&"--each-feature")
                && command.args.contains(&"privacy-pools-sdk-prover")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"--no-default-features")
                && command.args.contains(&"privacy-pools-sdk-prover")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"--all-features")
                && command.args.contains(&"privacy-pools-sdk-prover")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"privacy-pools-sdk-web")
                && command.args.contains(&"wasm32-unknown-unknown")
        }));
    }

    #[test]
    fn package_check_uses_workspace_dry_run() {
        let args = package_check_args();

        assert!(args.contains(&"package"));
        assert!(args.contains(&"--workspace"));
        assert!(args.contains(&"--allow-dirty"));
        assert!(args.contains(&"--no-verify"));
    }

    #[test]
    fn mobile_smoke_evidence_accepts_passed_same_commit_statuses() {
        let commit = "abcdef0";
        let evidence = mobile_smoke_fixture(commit);

        validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit).unwrap();
    }

    #[test]
    fn mobile_smoke_evidence_rejects_commit_mismatch() {
        let evidence = mobile_smoke_fixture("abcdef0");

        let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), "1234567")
            .unwrap_err()
            .to_string();

        assert!(error.contains("commit mismatch"));
    }

    #[test]
    fn mobile_smoke_evidence_rejects_failed_platform_status() {
        let commit = "abcdef0";
        let mut evidence = mobile_smoke_fixture(commit);
        evidence["android"] = json!("failed");

        let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("android status"));
    }

    #[test]
    fn mobile_smoke_evidence_rejects_missing_fields() {
        let commit = "abcdef0";
        let evidence = json!({
            "commit": commit,
            "workflow": "mobile-smoke",
            "ios": "passed",
            "android": "passed"
        });

        let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("run_url"));
    }

    #[test]
    fn evidence_check_accepts_complete_same_commit_alpha_fixture() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = "abcdef0";

        fs::write(dir.join("commit.txt"), commit).unwrap();
        fs::write(
            dir.join("release-artifacts.txt"),
            "release workflow artifacts",
        )
        .unwrap();
        fs::write(dir.join("canary-notes.md"), "canary cohort passed").unwrap();
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(commit),
        );
        for device in ["desktop", "ios", "android"] {
            write_json(
                &dir.join(format!("{device}-withdraw-stable.json")),
                &benchmark_report(commit, device),
            );
        }

        evidence_check(vec![
            "--channel".to_owned(),
            "alpha".to_owned(),
            "--dir".to_owned(),
            dir.to_string(),
        ])
        .unwrap();
    }
}
