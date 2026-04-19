use anyhow::{Context, Result, anyhow, bail, ensure};
use camino::Utf8PathBuf;
use privacy_pools_sdk_artifacts::verify_signed_manifest_artifact_files;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write,
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
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
        Some("mobile-smoke-local") => mobile_smoke_local(args.collect()),
        Some("sdk-web-package") => stage_sdk_web_package(args.collect()),
        Some("sdk-smoke") => sdk_smoke(),
        Some("examples-check") => examples_check(),
        Some("feature-check") => feature_check(),
        Some("package-check") => package_check(),
        Some("dependency-check") => dependency_check(),
        Some("docs-check") => docs_check(),
        Some("artifact-fingerprints") => artifact_fingerprints(args.collect()),
        Some("geiger-delta-check") => geiger_delta_check(),
        Some("signed-manifest-sample-check") => signed_manifest_sample_check(),
        Some("release-check") => release_check(args.collect()),
        Some("evidence-check") => evidence_check(args.collect()),
        Some("mobile-evidence-check") => mobile_evidence_check(args.collect()),
        Some("release-acceptance-check") => release_acceptance_check(args.collect()),
        Some("external-evidence-assemble") => external_evidence_assemble(args.collect()),
        Some("assurance") => assurance(args.collect()),
        Some("assurance-merge") => assurance_merge(args.collect()),
        Some("audit-pack") => audit_pack(args.collect()),
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
    println!("  mobile-smoke-local");
    println!(
        "                   run local mobile smoke orchestration for ios|android|all and native|react-native|all surfaces"
    );
    println!(
        "                   flags: [--platform ios|android|all] [--surface native|react-native|all] [--out-dir <path>] [--evidence-out-dir <path>]"
    );
    println!("  sdk-web-package");
    println!("                   build optimized browser WASM bindings");
    println!("                   flags: --debug --release --experimental-threaded");
    println!("  sdk-smoke");
    println!("                   build the SDK package runtimes and run the JS integration tests");
    println!("  examples-check   run lightweight Rust SDK examples");
    println!("  feature-check    check supported Rust feature and wasm combinations");
    println!("  package-check    run the workspace package dry run");
    println!("  dependency-check validate accepted dependency-risk advisories");
    println!("  docs-check       validate dependency-policy docs stay in sync");
    println!("  artifact-fingerprints");
    println!("                   verify or refresh checked-in artifact fingerprint snapshots");
    println!("                   flags: --check | --update");
    println!("  geiger-delta-check");
    println!("                   validate unsafe usage against security/unsafe-allowlist.json");
    println!("  signed-manifest-sample-check");
    println!("                   validate the checked-in signed manifest fixture");
    println!("  release-check    validate release-channel versions across public surfaces");
    println!("                   flags: --channel alpha|beta|rc|stable");
    println!("  evidence-check   compatibility alias for external assurance evidence validation");
    println!(
        "                   flags: --channel alpha|beta|rc|stable --dir <path> [--backend stable] [--signed-manifest-public-key <hex>]"
    );
    println!("  mobile-evidence-check");
    println!("                   validate mobile-smoke.json and mobile-parity.json evidence");
    println!("                   flags: --dir <path>");
    println!("  release-acceptance-check");
    println!("                   validate release evidence against the release assurance policy");
    println!("                   flags: --dir <path> [--backend stable]");
    println!("  external-evidence-assemble");
    println!(
        "                   materialize the shared external evidence layout for nightly or release"
    );
    println!(
        "                   flags: --mode nightly|release --out-dir <path> [--mobile-evidence-dir <path>] [--reference-benchmarks-dir <path>] [--sbom-dir <path>] [--packages-dir <path>] [--attestation-metadata-dir <path>]"
    );
    println!("  assurance        run the shared assurance catalog for one profile/runtime");
    println!(
        "                   flags: --profile pr|nightly|release --runtime rust|node|browser|react-native|all [--report-mode standard|audit] [--out-dir <path>] [--backend stable] [--device-label desktop] [--device-model <model>] [--v1-package-path <path>] [--v1-source-path <path>] [--external-evidence-dir <path>] [--fuzz-runs <n>] [--skip-fuzz] [--only-checks <id,id,...>]"
    );
    println!("  assurance-merge  merge subgroup assurance outputs into one aggregate bundle");
    println!(
        "                   flags: --profile pr|nightly|release --runtime rust|node|browser|react-native|all --inputs <path> [--inputs <path> ...] --out-dir <path>"
    );
    println!("  audit-pack       assemble a one-time Rust SDK audit evidence pack");
    println!(
        "                   flags: [--out-dir <path>] [--backend stable] [--device-label desktop] [--device-model <model>] [--v1-package-path <path>] [--v1-source-path <path>] [--external-evidence-dir <path>] [--fuzz-runs <n>] [--skip-fuzz]"
    );
    println!("                   note: release assurance requires --external-evidence-dir");
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
    let effective_release = options.release || options.native_targets.any();

    generate_bindings(effective_release)?;

    if options.native_targets.includes_ios() {
        build_ios_native_artifacts(&workspace_root)?;
    }

    if options.native_targets.includes_android() {
        build_android_native_artifacts(&workspace_root)?;
    }

    let package_root = workspace_root.join("packages/react-native");
    write_typescript_testing_surface_flag(
        &package_root.join("src/build-flags.ts"),
        options.enable_testing_surface || !effective_release,
    )?;

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
    if options.native_targets.includes_android() {
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
    if options.native_targets.includes_ios() {
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

fn write_javascript_testing_surface_flag(path: &Utf8PathBuf, enabled: bool) -> Result<()> {
    fs::write(
        path,
        format!(
            "export const TESTING_SURFACE_ENABLED = {};\nexport const TESTING_SURFACE_DISABLED_ERROR =\n  \"testing-only artifact loading is disabled in this build\";\n",
            if enabled { "true" } else { "false" }
        ),
    )
    .with_context(|| format!("failed to write {}", path))?;
    Ok(())
}

fn write_typescript_testing_surface_flag(path: &Utf8PathBuf, enabled: bool) -> Result<()> {
    fs::write(
        path,
        format!(
            "export const TESTING_SURFACE_ENABLED = {};\nexport const TESTING_SURFACE_DISABLED_ERROR =\n  \"testing-only artifact loading is disabled in this build\";\n",
            if enabled { "true" } else { "false" }
        ),
    )
    .with_context(|| format!("failed to write {}", path))?;
    Ok(())
}

fn with_preserved_file_contents<T, F>(path: &Utf8PathBuf, operation: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let original = if path.exists() {
        Some(fs::read(path).with_context(|| format!("failed to read {}", path))?)
    } else {
        None
    };

    let result = operation();

    match original {
        Some(contents) => fs::write(path, contents),
        None => {
            if path.exists() {
                fs::remove_file(path)
            } else {
                Ok(())
            }
        }
    }
    .with_context(|| format!("failed to restore {}", path))?;

    result
}

fn react_native_smoke() -> Result<()> {
    let workspace_root = workspace_root()?;
    let build_flags_path = workspace_root.join("packages/react-native/src/build-flags.ts");
    with_preserved_file_contents(&build_flags_path, || {
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
    })
}

fn react_native_app_smoke(platform: &str) -> Result<()> {
    let workspace_root = workspace_root()?;
    let build_flags_path = workspace_root.join("packages/react-native/src/build-flags.ts");
    with_preserved_file_contents(&build_flags_path, || {
        let mobile_platform = MobilePlatform::parse(platform)?;
        let package_args = mobile_platform.react_native_smoke_package_args();
        if react_native_app_smoke_package_ready(&workspace_root, platform, true) {
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
        let report_path = smoke_root.join(format!("{platform}-app-report.json"));

        run_command_with_env(
            "node",
            &[
                script.as_str(),
                platform,
                "--workspace",
                workspace_root.as_str(),
                "--tarball",
                package_tarball.as_str(),
                "--report",
                report_path.as_str(),
            ],
            &workspace_root,
            &[("npm_config_cache", npm_cache_root.as_str())],
            "React Native app-process smoke failed",
        )?;

        println!("react native {platform} app-process smoke ok");
        println!("report: {}", report_path);
        Ok(())
    })
}

fn mobile_smoke_local(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let build_flags_path = workspace_root.join("packages/react-native/src/build-flags.ts");
    with_preserved_file_contents(&build_flags_path, || {
        let options = MobileSmokeLocalOptions::parse(args, &workspace_root)?;
        options.validate()?;
        fs::create_dir_all(&options.out_dir)
            .with_context(|| format!("failed to create {}", options.out_dir))?;

        let mut failures = Vec::new();

        for platform in options.platforms() {
            if let Err(error) = ensure_mobile_smoke_package(&workspace_root, platform) {
                let message = format!(
                    "{} mobile smoke package prep failed: {error:#}",
                    platform.as_str()
                );
                for surface in options.surfaces() {
                    write_mobile_surface_failure_report(
                        &mobile_surface_output_path(&options.out_dir, platform, surface),
                        platform,
                        surface,
                        &message,
                    )?;
                }
                failures.push(message);
                continue;
            }

            for surface in options.surfaces() {
                if let Err(error) =
                    run_mobile_smoke_surface(&workspace_root, &options.out_dir, platform, surface)
                {
                    failures.push(format!(
                        "{} {} smoke failed: {error:#}",
                        platform.as_str(),
                        surface.as_str()
                    ));
                }
            }
        }

        if failures.is_empty() {
            if let Some(evidence_out_dir) = options.evidence_out_dir.as_ref() {
                let commit = current_git_commit(&workspace_root)?;
                assemble_mobile_smoke_evidence(
                    &workspace_root,
                    &options.out_dir,
                    evidence_out_dir,
                    &commit,
                    "local-xtask",
                    "mobile-smoke-local",
                    "local://mobile-smoke-local",
                )?;
                println!("evidence: {}", evidence_out_dir);
            }
            println!("mobile-smoke-local ok");
            println!("reports: {}", options.out_dir);
            return Ok(());
        }

        bail!("mobile smoke failed:\n- {}", failures.join("\n- "))
    })
}

fn assemble_mobile_smoke_evidence(
    workspace_root: &Utf8PathBuf,
    reports_dir: &Utf8PathBuf,
    out_dir: &Utf8PathBuf,
    commit: &str,
    source: &str,
    workflow: &str,
    workflow_url: &str,
) -> Result<()> {
    let script = workspace_root.join("packages/sdk/scripts/assemble-mobile-smoke-evidence.mjs");

    run_command(
        "node",
        &[
            script.as_str(),
            "--ios-native-report",
            reports_dir.join("ios-native/report.json").as_str(),
            "--ios-react-native-report",
            reports_dir
                .join("ios-react-native/ios-app-report.json")
                .as_str(),
            "--android-native-report",
            reports_dir.join("android-native/report.json").as_str(),
            "--android-react-native-report",
            reports_dir
                .join("android-react-native/android-app-report.json")
                .as_str(),
            "--commit",
            commit,
            "--source",
            source,
            "--workflow",
            workflow,
            "--workflow-url",
            workflow_url,
            "--out-dir",
            out_dir.as_str(),
        ],
        workspace_root,
        "failed to assemble mobile smoke evidence",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MobilePlatform {
    Ios,
    Android,
}

impl MobilePlatform {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ios" => Ok(Self::Ios),
            "android" => Ok(Self::Android),
            other => bail!("unknown mobile platform: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }

    fn react_native_release_package_args(self) -> Vec<String> {
        match self {
            Self::Ios => vec!["--release".to_owned(), "--with-ios-native".to_owned()],
            Self::Android => vec!["--release".to_owned(), "--with-android-native".to_owned()],
        }
    }

    fn react_native_smoke_package_args(self) -> Vec<String> {
        let mut args = self.react_native_release_package_args();
        args.push("--enable-testing-surface".to_owned());
        args
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MobileSurface {
    Native,
    ReactNative,
}

impl MobileSurface {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "react-native" => Ok(Self::ReactNative),
            other => bail!("unknown mobile surface: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::ReactNative => "react-native",
        }
    }

    fn runtime(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::ReactNative => "react-native-app",
        }
    }

    fn report_source_path(
        self,
        workspace_root: &Utf8PathBuf,
        platform: MobilePlatform,
    ) -> Utf8PathBuf {
        match (platform, self) {
            (MobilePlatform::Ios, Self::Native) => {
                workspace_root.join("target/ios-native-smoke/report.json")
            }
            (MobilePlatform::Ios, Self::ReactNative) => {
                workspace_root.join("target/react-native-app-smoke/ios-app-report.json")
            }
            (MobilePlatform::Android, Self::Native) => {
                workspace_root.join("target/android-native-smoke/report.json")
            }
            (MobilePlatform::Android, Self::ReactNative) => {
                workspace_root.join("target/react-native-app-smoke/android-app-report.json")
            }
        }
    }
}

#[derive(Debug, Clone)]
struct MobileSmokeLocalOptions {
    platforms: Vec<MobilePlatform>,
    surfaces: Vec<MobileSurface>,
    out_dir: Utf8PathBuf,
    evidence_out_dir: Option<Utf8PathBuf>,
}

impl MobileSmokeLocalOptions {
    fn parse(args: Vec<String>, workspace_root: &Utf8PathBuf) -> Result<Self> {
        let mut platform = None;
        let mut surface = None;
        let mut out_dir = None;
        let mut evidence_out_dir = None;
        let mut iter = args.into_iter();

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--platform" => {
                    platform = Some(iter.next().context("--platform requires a value")?);
                }
                "--surface" => {
                    surface = Some(iter.next().context("--surface requires a value")?);
                }
                "--out-dir" => {
                    out_dir = Some(Utf8PathBuf::from(
                        iter.next().context("--out-dir requires a value")?,
                    ));
                }
                "--evidence-out-dir" => {
                    evidence_out_dir = Some(Utf8PathBuf::from(
                        iter.next().context("--evidence-out-dir requires a value")?,
                    ));
                }
                other => bail!("unknown mobile-smoke-local flag: {other}"),
            }
        }

        let platforms = match platform.as_deref().unwrap_or("all") {
            "all" => vec![MobilePlatform::Ios, MobilePlatform::Android],
            value => vec![MobilePlatform::parse(value)?],
        };
        let surfaces = match surface.as_deref().unwrap_or("all") {
            "all" => vec![MobileSurface::Native, MobileSurface::ReactNative],
            value => vec![MobileSurface::parse(value)?],
        };

        Ok(Self {
            platforms,
            surfaces,
            out_dir: out_dir.unwrap_or_else(|| workspace_root.join("target/mobile-smoke-local")),
            evidence_out_dir,
        })
    }

    fn platforms(&self) -> impl Iterator<Item = MobilePlatform> + '_ {
        self.platforms.iter().copied()
    }

    fn surfaces(&self) -> impl Iterator<Item = MobileSurface> + '_ {
        self.surfaces.iter().copied()
    }

    fn validate(&self) -> Result<()> {
        if self.evidence_out_dir.is_some() && !self.is_full_suite() {
            bail!("mobile-smoke-local --evidence-out-dir requires --platform all --surface all");
        }

        Ok(())
    }

    fn is_full_suite(&self) -> bool {
        self.platforms.len() == 2
            && self.surfaces.len() == 2
            && self.platforms.contains(&MobilePlatform::Ios)
            && self.platforms.contains(&MobilePlatform::Android)
            && self.surfaces.contains(&MobileSurface::Native)
            && self.surfaces.contains(&MobileSurface::ReactNative)
    }
}

fn ensure_mobile_smoke_package(
    workspace_root: &Utf8PathBuf,
    platform: MobilePlatform,
) -> Result<()> {
    if react_native_app_smoke_package_ready(workspace_root, platform.as_str(), false) {
        println!(
            "using existing staged React Native {} package assets",
            platform.as_str()
        );
        return Ok(());
    }

    stage_react_native_package(platform.react_native_release_package_args())
}

fn run_mobile_smoke_surface(
    workspace_root: &Utf8PathBuf,
    out_dir: &Utf8PathBuf,
    platform: MobilePlatform,
    surface: MobileSurface,
) -> Result<()> {
    let source_path = surface.report_source_path(workspace_root, platform);
    let output_path = mobile_surface_output_path(out_dir, platform, surface);
    remove_path_if_exists(&source_path)?;
    remove_path_if_exists(&output_path)?;

    let run_result = match (platform, surface) {
        (MobilePlatform::Ios, MobileSurface::Native) => run_ios_native_smoke(workspace_root),
        (MobilePlatform::Ios, MobileSurface::ReactNative) => react_native_app_smoke("ios"),
        (MobilePlatform::Android, MobileSurface::Native) => {
            run_android_native_smoke(workspace_root)
        }
        (MobilePlatform::Android, MobileSurface::ReactNative) => react_native_app_smoke("android"),
    };

    let failure_message = match &run_result {
        Ok(()) if source_path.exists() => None,
        Ok(()) => Some(format!(
            "{} {} smoke completed without producing {}",
            platform.as_str(),
            surface.as_str(),
            source_path
        )),
        Err(error) => Some(format!(
            "{} {} smoke failed: {error:#}",
            platform.as_str(),
            surface.as_str()
        )),
    };

    if let Some(message) = failure_message {
        write_mobile_surface_failure_report(&source_path, platform, surface, &message)?;
        copy_file_if_present(&source_path, &output_path)?;
        bail!("{message}");
    }

    ensure!(
        copy_file_if_present(&source_path, &output_path)?,
        "{} {} smoke did not write {}",
        platform.as_str(),
        surface.as_str(),
        output_path
    );
    println!(
        "{} {} report: {}",
        platform.as_str(),
        surface.as_str(),
        output_path
    );
    Ok(())
}

fn run_ios_native_smoke(workspace_root: &Utf8PathBuf) -> Result<()> {
    let script = workspace_root.join("bindings/ios/scripts/run-smoke-xctest.sh");
    run_command(
        "bash",
        &[script.as_str()],
        workspace_root,
        "iOS native smoke failed",
    )
}

fn run_android_native_smoke(workspace_root: &Utf8PathBuf) -> Result<()> {
    let assets_root = workspace_root.join("target/android-native-smoke-assets");
    let vectors_root = assets_root.join("vectors");
    let report_dir = workspace_root.join("target/android-native-smoke");
    let report_path = report_dir.join("report.json");
    let execution_fixture_path = vectors_root.join("mobile-execution-fixture.json");

    fs::create_dir_all(&vectors_root)
        .with_context(|| format!("failed to create {}", vectors_root))?;
    fs::create_dir_all(&report_dir).with_context(|| format!("failed to create {}", report_dir))?;
    remove_path_if_exists(&execution_fixture_path)?;

    let withdrawal_fixture =
        read_required_json(&workspace_root.join("fixtures/vectors/withdrawal-circuit-input.json"))?;
    let state_root = json_scalar_to_string(
        withdrawal_fixture
            .get("stateWitness")
            .and_then(|value| value.get("root"))
            .context("withdrawal-circuit-input.json missing stateWitness.root")?,
    )?;
    let asp_root = json_scalar_to_string(
        withdrawal_fixture
            .get("aspWitness")
            .and_then(|value| value.get("root"))
            .context("withdrawal-circuit-input.json missing aspWitness.root")?,
    )?;

    let mut execution_fixture = Command::new("node");
    execution_fixture
        .arg("./packages/sdk/scripts/start-mobile-execution-fixture-servers.mjs")
        .args([
            "--platform",
            "android",
            "--bind-host",
            "0.0.0.0",
            "--public-host",
            "10.0.2.2",
            "--state-root",
            state_root.as_str(),
            "--asp-root",
            asp_root.as_str(),
        ])
        .current_dir(workspace_root)
        .stdout(
            fs::File::create(&execution_fixture_path)
                .with_context(|| format!("failed to create {}", execution_fixture_path))?,
        )
        .stderr(Stdio::inherit());

    let child = execution_fixture.spawn().with_context(|| {
        format!(
            "failed to start mobile execution fixture server in {}",
            workspace_root
        )
    })?;
    let _execution_fixture_guard = ChildGuard::new(child);
    wait_for_nonempty_file(
        &execution_fixture_path,
        50,
        Duration::from_millis(200),
        "android execution fixture server did not produce output",
    )?;
    let execution_fixture = read_required_json(&execution_fixture_path)?;
    let reversed_ports = configure_android_reverse_ports(
        execution_fixture_urls(&execution_fixture)?,
        workspace_root,
    )?;
    wait_for_android_device_ready(workspace_root)?;

    let mut last_error = None;
    for attempt in 1..=2 {
        run_command_allow_failure("adb", &["logcat", "-c"], workspace_root);
        remove_path_if_exists(&report_path)?;

        let gradle_result = run_command_with_env(
            "gradle",
            &["connectedDebugAndroidTest", "--stacktrace"],
            &workspace_root.join("bindings/android"),
            &[(
                "PRIVACY_POOLS_ANDROID_TEST_ASSETS_DIR",
                assets_root.as_str(),
            )],
            "Android native smoke failed",
        );

        if let Ok(logcat) = command_stdout(
            "adb",
            &["logcat", "-d", "-s", "PrivacyPoolsNativeSmoke:I", "*:S"],
            workspace_root,
            "failed to collect Android native smoke logs",
        ) && let Some(report_json) = extract_android_native_report_from_logcat(&logcat)
        {
            fs::write(&report_path, report_json)
                .with_context(|| format!("failed to write {}", report_path))?;
        }

        match gradle_result {
            Ok(()) if report_path.exists() => {
                clear_android_reverse_ports(&reversed_ports, workspace_root)?;
                return Ok(());
            }
            Ok(()) => {
                let error = anyhow!(
                    "Android native smoke completed without producing {}",
                    report_path
                );
                if attempt == 1 {
                    eprintln!(
                        "android native smoke attempt {attempt} completed without a report; retrying once"
                    );
                    wait_for_android_device_ready(workspace_root)?;
                    last_error = Some(error);
                    continue;
                }
                last_error = Some(error);
            }
            Err(error) if !report_path.exists() && attempt == 1 => {
                eprintln!(
                    "android native smoke attempt {attempt} failed before producing a report; retrying once: {error:#}"
                );
                wait_for_android_device_ready(workspace_root)?;
                last_error = Some(error);
                continue;
            }
            Err(error) => {
                last_error = Some(error);
            }
        }

        break;
    }

    clear_android_reverse_ports(&reversed_ports, workspace_root)?;
    Err(last_error.unwrap_or_else(|| anyhow!("Android native smoke failed")))
}

fn extract_android_native_report_from_logcat(logcat: &str) -> Option<&str> {
    const REPORT_MARKER: &str = "PRIVACY_POOLS_ANDROID_NATIVE_REPORT ";

    logcat
        .lines()
        .rev()
        .find_map(|line| {
            line.split_once(REPORT_MARKER)
                .map(|(_, payload)| payload.trim())
        })
        .filter(|payload| !payload.is_empty())
}

fn wait_for_android_device_ready(workspace_root: &Utf8PathBuf) -> Result<()> {
    run_command(
        "adb",
        &["wait-for-device"],
        workspace_root,
        "failed waiting for Android device",
    )?;

    for _ in 0..30 {
        if let Ok(boot_completed) = command_stdout(
            "adb",
            &["shell", "getprop", "sys.boot_completed"],
            workspace_root,
            "failed to query Android boot state",
        ) && boot_completed.trim().ends_with('1')
        {
            return Ok(());
        }

        thread::sleep(Duration::from_secs(1));
    }

    bail!("Android device did not finish booting")
}

fn execution_fixture_urls(fixture: &Value) -> Result<[&str; 4]> {
    let fixture_path = Utf8PathBuf::from("<execution-fixture>");
    Ok([
        ensure_json_string(fixture, "validRpcUrl", &fixture_path)?,
        ensure_json_string(fixture, "wrongRootRpcUrl", &fixture_path)?,
        ensure_json_string(fixture, "signerUrl", &fixture_path)?,
        ensure_json_string(fixture, "wrongSignerUrl", &fixture_path)?,
    ])
}

fn configure_android_reverse_ports(
    urls: [&str; 4],
    workspace_root: &Utf8PathBuf,
) -> Result<Vec<String>> {
    let mut ports = BTreeSet::new();
    for url in urls {
        let (_, remainder) = url
            .rsplit_once(':')
            .with_context(|| format!("failed to parse Android fixture url port from {url}"))?;
        let port = remainder.trim_end_matches('/');
        ensure!(
            !port.is_empty() && port.parse::<u16>().is_ok(),
            "invalid Android fixture url port in {url}"
        );
        ports.insert(port.to_owned());
    }

    for port in &ports {
        run_command_allow_failure(
            "adb",
            &["reverse", "--remove", &format!("tcp:{port}")],
            workspace_root,
        );
        run_command(
            "adb",
            &["reverse", &format!("tcp:{port}"), &format!("tcp:{port}")],
            workspace_root,
            "failed to configure Android reverse port forwarding",
        )?;
    }

    Ok(ports.into_iter().collect())
}

fn clear_android_reverse_ports(ports: &[String], workspace_root: &Utf8PathBuf) -> Result<()> {
    for port in ports {
        run_command_allow_failure(
            "adb",
            &["reverse", "--remove", &format!("tcp:{port}")],
            workspace_root,
        );
    }

    Ok(())
}

fn run_command_allow_failure(program: &str, args: &[&str], current_dir: &Utf8PathBuf) {
    let mut command = Command::new(program);
    command.args(args).current_dir(current_dir);
    let _ = command.status();
}

fn mobile_surface_output_path(
    out_dir: &Utf8PathBuf,
    platform: MobilePlatform,
    surface: MobileSurface,
) -> Utf8PathBuf {
    match (platform, surface) {
        (MobilePlatform::Ios, MobileSurface::Native) => out_dir.join("ios-native/report.json"),
        (MobilePlatform::Ios, MobileSurface::ReactNative) => {
            out_dir.join("ios-react-native/ios-app-report.json")
        }
        (MobilePlatform::Android, MobileSurface::Native) => {
            out_dir.join("android-native/report.json")
        }
        (MobilePlatform::Android, MobileSurface::ReactNative) => {
            out_dir.join("android-react-native/android-app-report.json")
        }
    }
}

fn write_mobile_surface_failure_report(
    path: &Utf8PathBuf,
    platform: MobilePlatform,
    surface: MobileSurface,
    failure: &str,
) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(&mobile_surface_failure_report(platform, surface, failure))
            .context("failed to serialize mobile surface failure report")?,
    )
    .with_context(|| format!("failed to write {}", path))?;
    Ok(())
}

fn mobile_surface_failure_report(
    platform: MobilePlatform,
    surface: MobileSurface,
    failure: &str,
) -> Value {
    json!({
        "generatedAt": chrono_like_now(),
        "runtime": surface.runtime(),
        "platform": platform.as_str(),
        "surface": surface.as_str(),
        "smoke": {
            "backend": "unknown",
            "commitmentVerified": false,
            "withdrawalVerified": false,
            "executionSubmitted": false,
            "signedManifestVerified": false,
            "wrongSignedManifestPublicKeyRejected": false,
            "tamperedSignedManifestArtifactsRejected": false,
            "tamperedProofRejected": false,
            "handleKindMismatchRejected": false,
            "staleVerifiedProofHandleRejected": false,
            "staleCommitmentSessionRejected": false,
            "staleWithdrawalSessionRejected": false,
            "wrongRootRejected": false,
            "wrongChainIdRejected": false,
            "wrongCodeHashRejected": false,
            "wrongSignerRejected": false,
        },
        "parity": {
            "totalChecks": 1,
            "passed": 0,
            "failed": 1,
            "failedChecks": [failure],
        },
        "benchmark": {
            "artifactResolutionMs": 0.0,
            "bundleVerificationMs": 0.0,
            "sessionPreloadMs": 0.0,
            "firstInputPreparationMs": 0.0,
            "firstWitnessGenerationMs": 0.0,
            "firstProofGenerationMs": 0.0,
            "firstVerificationMs": 0.0,
            "firstProveAndVerifyMs": 0.0,
            "iterations": 1,
            "warmup": 0,
            "peakResidentMemoryBytes": Value::Null,
            "samples": [{
                "inputPreparationMs": 0.0,
                "witnessGenerationMs": 0.0,
                "proofGenerationMs": 0.0,
                "verificationMs": 0.0,
                "proveAndVerifyMs": 0.0,
            }],
        },
    })
}

fn json_scalar_to_string(value: &Value) -> Result<String> {
    match value {
        Value::String(inner) => Ok(inner.clone()),
        Value::Number(inner) => Ok(inner.to_string()),
        other => bail!("expected string or number, found {other}"),
    }
}

fn wait_for_nonempty_file(
    path: &Utf8PathBuf,
    attempts: usize,
    delay: Duration,
    error_context: &str,
) -> Result<()> {
    for _ in 0..attempts {
        if path.exists()
            && path
                .metadata()
                .map(|metadata| metadata.len() > 0)
                .unwrap_or(false)
        {
            return Ok(());
        }
        thread::sleep(delay);
    }
    bail!("{error_context}: {}", path);
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn chrono_like_now() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            current_unix_seconds()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| "0".to_owned())
        })
}

fn react_native_app_smoke_package_ready(
    workspace_root: &Utf8PathBuf,
    platform: &str,
    testing_surface_enabled: bool,
) -> bool {
    let package_root = workspace_root.join("packages/react-native");
    let common_files = [
        package_root.join("android/generated/src/main/java"),
        package_root.join("android/src/main/java"),
        package_root.join("ios/generated/PrivacyPoolsSdk.swift"),
        package_root.join("ios/generated/support/PrivacyPoolsSdkClient.swift"),
        package_root.join("src/build-flags.ts"),
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

    let build_flags_path = package_root.join("src/build-flags.ts");
    let expected_flag = if testing_surface_enabled {
        "export const TESTING_SURFACE_ENABLED = true;"
    } else {
        "export const TESTING_SURFACE_ENABLED = false;"
    };

    common_files
        .iter()
        .chain(platform_files.iter())
        .all(|path| path.exists())
        && fs::read_to_string(&build_flags_path)
            .map(|contents| contents.contains(expected_flag))
            .unwrap_or(false)
}

fn stage_sdk_web_package(args: Vec<String>) -> Result<()> {
    let mut release = true;
    let mut experimental_threaded = false;
    for arg in args {
        match arg.as_str() {
            "--debug" => release = false,
            "--release" => release = true,
            "--experimental-threaded" => experimental_threaded = true,
            _ => bail!("unknown sdk-web-package flag: {arg}"),
        }
    }

    let workspace_root = workspace_root()?;
    let generated_root = workspace_root.join("packages/sdk/src/browser/generated");
    let threaded_root = workspace_root.join("packages/sdk/src/browser/generated-threaded");
    if experimental_threaded {
        stage_sdk_web_artifact(&workspace_root, &threaded_root, release, true)?;
        println!(
            "staged experimental threaded browser WASM bindings into packages/sdk/src/browser/generated-threaded"
        );
        return Ok(());
    }

    stage_sdk_web_artifact(&workspace_root, &generated_root, release, false)?;
    ensure_threaded_wasm_fallback_stub(&threaded_root)?;

    println!("staged browser WASM bindings into packages/sdk/src/browser/generated");
    Ok(())
}

fn stage_sdk_web_artifact(
    workspace_root: &Utf8PathBuf,
    generated_root: &Utf8PathBuf,
    release: bool,
    experimental_threaded: bool,
) -> Result<()> {
    let browser_flags_path = workspace_root.join("packages/sdk/src/browser/build-flags.mjs");
    let original_browser_flags = fs::read_to_string(&browser_flags_path)
        .with_context(|| format!("failed to read {}", browser_flags_path))?;
    let result = (|| {
        write_javascript_testing_surface_flag(&browser_flags_path, !release)?;
        let profile = if release {
            "wasm-release"
        } else {
            "wasm-debug"
        };
        let mut rustflags = wasm_remap_rustflags(workspace_root);
        if experimental_threaded {
            for flag in [
                "-Ctarget-feature=+atomics,+bulk-memory",
                "-Clink-arg=--import-memory",
                "-Clink-arg=--shared-memory",
                "-Clink-arg=--max-memory=1073741824",
                "-Clink-arg=--export=__wasm_init_tls",
                "-Clink-arg=--export=__tls_size",
                "-Clink-arg=--export=__tls_align",
                "-Clink-arg=--export=__tls_base",
            ] {
                push_rustflag(&mut rustflags, flag.to_owned());
            }
        }
        reset_directory(generated_root)?;

        let mut cargo_args = vec!["build"];
        if experimental_threaded {
            ensure_threaded_wasm_toolchain(workspace_root)?;
            cargo_args.splice(0..0, ["+nightly", "-Z", "build-std=panic_abort,std"]);
        }
        cargo_args.extend([
            "-p",
            "privacy-pools-sdk-web",
            "--target",
            "wasm32-unknown-unknown",
            "--lib",
        ]);
        let mut feature_flags = Vec::new();
        if experimental_threaded {
            feature_flags.push("threaded");
        }
        if !release {
            feature_flags.push("dangerous-exports");
        }
        let feature_args = if feature_flags.is_empty() {
            None
        } else {
            Some(feature_flags.join(","))
        };
        if let Some(feature_args) = &feature_args {
            cargo_args.extend(["--features", feature_args.as_str()]);
        }
        cargo_args.push(if release {
            "--profile=wasm-release"
        } else {
            "--profile=wasm-debug"
        });

        let build_context = if experimental_threaded {
            "failed to build privacy-pools-sdk-web experimental threaded artifact; install the nightly toolchain with rust-src and wasm32-unknown-unknown support"
        } else {
            "failed to build privacy-pools-sdk-web for wasm32-unknown-unknown"
        };
        run_command_with_env(
            "cargo",
            &cargo_args,
            workspace_root,
            &[("RUSTFLAGS", rustflags.as_str())],
            build_context,
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
                "--out-name",
                if experimental_threaded {
                    "privacy_pools_sdk_web_threaded"
                } else {
                    "privacy_pools_sdk_web"
                },
                "--out-dir",
                generated_root.as_str(),
                wasm_path.as_str(),
            ],
            workspace_root,
            "failed to generate browser WASM bindings; install wasm-bindgen-cli and ensure it is on PATH",
        )?;

        let output_wasm = generated_root.join(if experimental_threaded {
            "privacy_pools_sdk_web_threaded_bg.wasm"
        } else {
            "privacy_pools_sdk_web_bg.wasm"
        });
        strip_wasm_custom_sections(&output_wasm)?;
        if release {
            optimize_wasm(&output_wasm, experimental_threaded)?;
        }
        if experimental_threaded {
            write_threaded_artifact_availability(generated_root, true)?;
        }

        Ok(())
    })();

    fs::write(&browser_flags_path, original_browser_flags)
        .with_context(|| format!("failed to restore {}", browser_flags_path))?;

    result
}

fn ensure_threaded_wasm_fallback_stub(generated_root: &Utf8PathBuf) -> Result<()> {
    fs::create_dir_all(generated_root)
        .with_context(|| format!("failed to create {generated_root}"))?;
    let stub_path = generated_root.join("privacy_pools_sdk_web_threaded.js");
    let availability_path = generated_root.join("availability.mjs");
    if stub_path.exists() && availability_path.exists() {
        return Ok(());
    }
    fs::write(
        &stub_path,
        "export default async function initThreadedWasmFallback() {\n  throw new Error(\"experimental threaded WASM artifact was not built\");\n}\n\nexport async function initThreadPool() {\n  throw new Error(\"experimental threaded WASM artifact was not built\");\n}\n",
    )
    .with_context(|| format!("failed to write {stub_path}"))?;
    write_threaded_artifact_availability(generated_root, false)?;
    Ok(())
}

fn ensure_threaded_wasm_toolchain(workspace_root: &Utf8PathBuf) -> Result<()> {
    run_command(
        "rustup",
        &["component", "add", "rust-src", "--toolchain", "nightly"],
        workspace_root,
        "failed to install rust-src for nightly threaded browser builds",
    )?;
    run_command(
        "rustup",
        &[
            "target",
            "add",
            "wasm32-unknown-unknown",
            "--toolchain",
            "nightly",
        ],
        workspace_root,
        "failed to install wasm32-unknown-unknown target for nightly threaded browser builds",
    )?;
    Ok(())
}

fn write_threaded_artifact_availability(
    generated_root: &Utf8PathBuf,
    available: bool,
) -> Result<()> {
    let availability_path = generated_root.join("availability.mjs");
    fs::write(
        &availability_path,
        format!(
            "export const THREADED_ARTIFACT_BUILT = {};\n",
            if available { "true" } else { "false" }
        ),
    )
    .with_context(|| format!("failed to write {availability_path}"))?;
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
    let policy = read_advisory_policy(&workspace_root)?;
    let deny_ignore = read_deny_advisory_ids(&workspace_root)?;

    ensure!(
        deny_ignore == policy.cargo_deny_ignore,
        "deny.toml advisory ignore set is out of sync with security/advisories.toml: expected {:?}, found {:?}",
        policy.cargo_deny_ignore,
        deny_ignore
    );

    let audit_args = audit_command_args(&policy.cargo_audit_ignore);
    let audit_args_ref: Vec<&str> = audit_args.iter().map(String::as_str).collect();
    let audit_stdout = command_stdout(
        "cargo",
        &audit_args_ref,
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

    ensure!(
        advisory_ids == policy.dependency_check_warnings,
        "unexpected dependency advisory set: expected {:?}, found {:?}",
        policy.dependency_check_warnings,
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
    println!(
        "cargo audit ignores: {}",
        policy.cargo_audit_ignore.join(", ")
    );
    println!(
        "cargo deny ignores: {}",
        policy.cargo_deny_ignore.join(", ")
    );
    println!("rand 0.8.5 reachable condition: `log` feature disabled");
    Ok(())
}

fn docs_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let policy = read_advisory_policy(&workspace_root)?;

    let dependency_audit =
        read_required_text_file(&workspace_root.join("docs/dependency-audit.md"))?;
    ensure!(
        dependency_audit.contains("security/advisories.toml"),
        "docs/dependency-audit.md must reference security/advisories.toml"
    );
    ensure!(
        collect_rustsec_ids(&dependency_audit) == policy.all_ids(),
        "docs/dependency-audit.md advisory IDs are out of sync with security/advisories.toml"
    );

    let release_checklist = read_required_text_file(&workspace_root.join("RELEASE_CHECKLIST.md"))?;
    ensure!(
        release_checklist.contains("security/advisories.toml"),
        "RELEASE_CHECKLIST.md must reference security/advisories.toml"
    );
    ensure!(
        release_checklist.contains("cargo vet"),
        "RELEASE_CHECKLIST.md must mention cargo vet"
    );

    let security_policy = read_required_text_file(&workspace_root.join("SECURITY.md"))?;
    ensure!(
        security_policy.contains("security/advisories.toml"),
        "SECURITY.md must reference security/advisories.toml"
    );

    println!("docs-check ok");
    Ok(())
}

fn artifact_fingerprints(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let snapshot_path = workspace_root.join("fixtures/artifacts/fingerprints.lock.json");
    let snapshot = artifact_fingerprint_snapshot(&workspace_root)?;
    let rendered = serde_json::to_string_pretty(&snapshot)
        .context("failed to serialize artifact fingerprint snapshot")?;

    let mode = match args.as_slice() {
        [flag] if flag == "--check" => "check",
        [flag] if flag == "--update" => "update",
        [] => bail!("artifact-fingerprints requires --check or --update"),
        _ => bail!("artifact-fingerprints accepts only --check or --update"),
    };

    if mode == "update" {
        if let Some(parent) = snapshot_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
        }
        fs::write(&snapshot_path, format!("{rendered}\n"))
            .with_context(|| format!("failed to write {}", snapshot_path))?;
        println!("artifact-fingerprints updated {}", snapshot_path);
        return Ok(());
    }

    let existing = read_required_json(&snapshot_path)?;
    ensure!(
        existing == snapshot,
        "artifact fingerprint snapshot is out of date: run `cargo run -p xtask -- artifact-fingerprints --update`"
    );
    println!("artifact-fingerprints ok");
    Ok(())
}

fn geiger_delta_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let allowlist_path = workspace_root.join("security/unsafe-allowlist.json");
    let allowlist: UnsafeAllowlist =
        serde_json::from_value(read_required_json(&allowlist_path)?)
            .with_context(|| format!("failed to parse {}", allowlist_path))?;
    let findings = workspace_unsafe_matches(&workspace_root)?;
    let allowlist_set: BTreeSet<_> = allowlist.allowed_matches.into_iter().collect();
    let findings_set: BTreeSet<_> = findings.iter().cloned().collect();
    let unexpected: Vec<_> = findings_set.difference(&allowlist_set).cloned().collect();
    ensure!(
        unexpected.is_empty(),
        "unexpected unsafe matches detected outside allowlist: {:?}",
        unexpected
    );
    println!("geiger-delta-check ok");
    println!("tracked matches: {}", findings.len());
    Ok(())
}

fn signed_manifest_sample_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let fixture_dir = workspace_root.join("fixtures/artifacts/signed-manifest");
    let public_key = env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(read_required_text_file(
            &fixture_dir.join("public-key.hex"),
        )?);
    let validated = validate_signed_manifest_directory(&fixture_dir, &public_key)?;
    println!("signed-manifest-sample-check ok");
    println!(
        "version: {}",
        validated["version"].as_str().unwrap_or("unknown")
    );
    println!(
        "artifacts: {}",
        validated["artifactCount"].as_u64().unwrap_or(0)
    );
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
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-web",
                "--no-default-features",
                "--features",
                "dangerous-exports",
                "--target",
                "wasm32-unknown-unknown",
            ],
            error_context: "privacy-pools-sdk-web dangerous-exports gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-signer default gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
                "--features",
                "local-mnemonic",
            ],
            error_context: "privacy-pools-sdk-signer local-mnemonic gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
                "--features",
                "dangerous-key-export",
            ],
            error_context: "privacy-pools-sdk-signer dangerous-key-export gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-chain",
                "--no-default-features",
                "--features",
                "local-signer-client",
            ],
            error_context: "privacy-pools-sdk-chain local-signer-client gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-node",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-node default feature gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-node",
                "--no-default-features",
                "--features",
                "dangerous-exports",
            ],
            error_context: "privacy-pools-sdk-node dangerous-exports gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-ffi",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-ffi default feature gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "-p",
                "privacy-pools-sdk-ffi",
                "--no-default-features",
                "--features",
                "dangerous-exports",
            ],
            error_context: "privacy-pools-sdk-ffi dangerous-exports gate check failed",
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

    if !release {
        command.arg("--features").arg("dangerous-exports");
    }

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

fn current_git_commit(workspace_root: &Utf8PathBuf) -> Result<String> {
    Ok(command_stdout(
        "git",
        &["rev-parse", "HEAD"],
        workspace_root,
        "git rev-parse HEAD failed",
    )?
    .trim()
    .to_owned())
}

fn current_git_branch(workspace_root: &Utf8PathBuf) -> Result<String> {
    Ok(command_stdout(
        "git",
        &["branch", "--show-current"],
        workspace_root,
        "git branch --show-current failed",
    )?
    .trim()
    .to_owned())
}

fn current_github_repository_slug(workspace_root: &Utf8PathBuf) -> Result<String> {
    let remote = command_stdout(
        "git",
        &["config", "--get", "remote.origin.url"],
        workspace_root,
        "git config --get remote.origin.url failed",
    )?;
    parse_github_repository_slug(remote.trim()).with_context(|| {
        format!(
            "failed to parse GitHub repository slug from remote origin URL `{}`",
            remote.trim()
        )
    })
}

fn parse_github_repository_slug(remote: &str) -> Result<String> {
    let trimmed = remote.trim().trim_end_matches(".git");
    if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    bail!("unsupported remote origin URL: {trimmed}")
}

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
        "--enable-bulk-memory",
        "--enable-sign-ext",
        "--enable-nontrapping-float-to-int",
    ];
    if wasm_opt_supports_flag("--enable-bulk-memory-opt")? {
        args.push("--enable-bulk-memory-opt");
    } else {
        println!(
            "wasm-opt does not support --enable-bulk-memory-opt; continuing without that optional optimization"
        );
    }
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

fn wasm_opt_supports_flag(flag: &str) -> Result<bool> {
    let output = Command::new("wasm-opt")
        .arg("--help")
        .output()
        .with_context(|| "failed to invoke wasm-opt --help while probing feature support")?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(stdout.contains(flag) || stderr.contains(flag))
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
    let workspace_root = workspace_root()?;
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

    let mobile_smoke_path = options.dir.join("mobile-smoke.json");
    let mobile_smoke = read_required_json(&mobile_smoke_path)?;
    let commit = ensure_json_string(&mobile_smoke, "commit", &mobile_smoke_path)?.to_owned();
    ensure!(
        is_hex_commit(&commit),
        "mobile-smoke.json commit must contain a short or full hex git commit, found `{commit}`"
    );
    let external_evidence = validate_external_evidence_dir(
        &workspace_root,
        &options.dir,
        AssuranceProfile::Release,
        options.backend,
        &commit,
        options.signed_manifest_public_key.as_deref(),
    )?;

    println!("evidence-check ok");
    println!("mode: compatibility alias");
    println!("channel: {}", options.channel.as_str());
    println!("backend: {}", options.backend.as_str());
    println!("commit: {commit}");
    println!("evidence directory: {}", options.dir);
    println!(
        "digest: {}",
        external_evidence["digestSha256"]
            .as_str()
            .unwrap_or("unknown")
    );
    Ok(())
}

fn mobile_evidence_check(args: Vec<String>) -> Result<()> {
    let options = MobileEvidenceCheckOptions::parse(args)?;
    ensure!(
        options.dir.exists() && options.dir.is_dir(),
        "mobile evidence directory does not exist: {}",
        options.dir
    );

    let mobile_smoke_path = options.dir.join("mobile-smoke.json");
    let mobile_smoke = read_required_json(&mobile_smoke_path)?;
    let commit = ensure_json_string(&mobile_smoke, "commit", &mobile_smoke_path)?.to_owned();
    ensure!(
        is_hex_commit(&commit),
        "mobile-smoke.json commit must contain a short or full hex git commit, found `{commit}`"
    );
    let mobile_parity_path = options.dir.join("mobile-parity.json");
    validate_mobile_smoke_evidence_value(&mobile_smoke, &mobile_smoke_path, &commit)?;
    let parity = validate_mobile_parity_evidence(&mobile_parity_path, &commit)?;

    println!("mobile-evidence-check ok");
    println!("commit: {commit}");
    println!("mobile evidence directory: {}", options.dir);
    println!(
        "parity checks: {}/{}",
        parity["passed"].as_u64().unwrap_or(0),
        parity["totalChecks"].as_u64().unwrap_or(0)
    );
    Ok(())
}

struct ReleaseAcceptanceEvaluation {
    benchmark_count: usize,
    attestation_count: u64,
}

fn evaluate_release_acceptance_from_external_evidence(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    selected_specs: &[AssuranceCheckSpec],
    external_evidence: &Value,
) -> Result<ReleaseAcceptanceEvaluation> {
    validate_scenario_coverage(workspace_root, options, selected_specs)?;

    let benchmark_count = external_evidence
        .get("benchmarks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let attestation_count = external_evidence
        .get("attestationCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    ensure!(
        attestation_count > 0,
        "release acceptance evidence must include attestation metadata"
    );
    let sdk_web_package_binding = external_evidence
        .get("sdkWebPackageBinding")
        .context("release acceptance evidence must include sdkWebPackageBinding")?;
    ensure!(
        sdk_web_package_binding
            .get("browserWasmSha256")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "release acceptance sdkWebPackageBinding is missing browserWasmSha256"
    );

    Ok(ReleaseAcceptanceEvaluation {
        benchmark_count,
        attestation_count,
    })
}

fn release_acceptance_check(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let mut dir = None::<Utf8PathBuf>;
    let mut backend = BenchmarkBackendProfile::Stable;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
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
            other => bail!("unknown release-acceptance-check flag: {other}"),
        }
    }

    let dir = dir.context("release-acceptance-check requires --dir <path>")?;
    let commit = current_git_commit(&workspace_root)?;
    let external_evidence = validate_external_evidence_dir(
        &workspace_root,
        &dir,
        AssuranceProfile::Release,
        backend,
        &commit,
        None,
    )?;
    let options = AssuranceOptions {
        profile: AssuranceProfile::Release,
        runtime: AssuranceRuntime::All,
        report_mode: AssuranceReportMode::Audit,
        out_dir: workspace_root.join("target/release-acceptance"),
        backend,
        device_label: "desktop".to_owned(),
        device_model: detect_device_model(&workspace_root)?,
        v1_package_path: workspace_root.join("packages/sdk"),
        v1_source_path: workspace_root.join("packages/sdk"),
        external_evidence_dir: Some(dir.clone()),
        fuzz_runs: 1,
        skip_fuzz: true,
        only_checks: None,
    };
    let selected_specs = assurance_selected_specs(&workspace_root, &options)?;
    let evaluation = evaluate_release_acceptance_from_external_evidence(
        &workspace_root,
        &options,
        &selected_specs,
        &external_evidence,
    )?;

    println!("release-acceptance-check ok");
    println!("commit: {commit}");
    println!("backend: {}", backend.as_str());
    println!("evidence directory: {}", dir);
    println!("reference benchmarks: {}", evaluation.benchmark_count);
    println!("attestations: {}", evaluation.attestation_count);
    Ok(())
}

fn assurance(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = AssuranceOptions::parse(args, &workspace_root)?;
    run_assurance(&workspace_root, &options)
}

fn assurance_merge(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = AssuranceMergeOptions::parse(args)?;
    merge_assurance_outputs(&workspace_root, &options)
}

fn audit_pack(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options =
        AssuranceOptions::from_audit_pack(AuditPackOptions::parse(args, &workspace_root)?);
    run_assurance(&workspace_root, &options)
}

fn external_evidence_assemble(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = ExternalEvidenceAssembleOptions::parse(args, &workspace_root)?;
    let commit = current_git_commit(&workspace_root)?;
    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit)
        .with_context(|| {
            format!(
                "failed to assemble {} external evidence at {}",
                options.mode.as_str(),
                options.out_dir
            )
        })?;

    println!("external-evidence-assemble ok");
    println!("mode: {}", options.mode.as_str());
    println!("commit: {commit}");
    println!("output directory: {}", options.out_dir);
    println!(
        "reference performance: {}",
        manifest["referencePerformance"]["status"]
            .as_str()
            .unwrap_or("unknown")
    );
    Ok(())
}

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

fn build_assurance_catalog(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    benchmark_report: &Utf8PathBuf,
    rust_compare_report: &Utf8PathBuf,
    rust_compare_raw_report: &Utf8PathBuf,
    browser_compare_report: &Utf8PathBuf,
    browser_compare_smoke_report: &Utf8PathBuf,
) -> Vec<AssuranceCheckSpec> {
    let rust_goldens_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("rust-goldens-comparison.json"),
    );
    let node_goldens_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("node-goldens-comparison.json"),
    );
    let browser_goldens_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("browser-goldens-comparison.json"),
    );
    let react_native_goldens_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("react-native-goldens-comparison.json"),
    );
    let node_stateful_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("node-stateful-comparison.json"),
    );
    let react_native_stateful_report = resolve_path_for_child(
        workspace_root,
        &options
            .out_dir
            .join("react-native-stateful-comparison.json"),
    );
    let rust_compare_report_for_child = resolve_path_for_child(workspace_root, rust_compare_report);
    let rust_compare_raw_report_for_child =
        resolve_path_for_child(workspace_root, rust_compare_raw_report);
    let browser_compare_report_for_child =
        resolve_path_for_child(workspace_root, browser_compare_report);
    let browser_compare_smoke_report_for_child =
        resolve_path_for_child(workspace_root, browser_compare_smoke_report);
    let sdk_sbom_report =
        resolve_path_for_child(workspace_root, &options.out_dir.join("sbom/sdk.spdx.json"));
    let react_native_sbom_report = resolve_path_for_child(
        workspace_root,
        &options.out_dir.join("sbom/react-native.spdx.json"),
    );
    let node_fail_closed_pattern = [
        "Circuits rejects unsigned manifests unless the test-only override is enabled",
        "Circuits rejects signed manifests with the wrong public key",
        "Circuits rejects tampered signed-manifest artifact bytes",
        "node addon rejects malformed proof bundle shapes",
        "node addon enforces secret and verified proof handle kinds",
        "node addon rejects invalid execution preflight policies and signer mismatches",
        "node addon proves and verifies withdrawal proofs",
        "node addon fails closed for invalid proving artifacts and stale sessions",
    ]
    .join("|");
    let mut checks = vec![
        assurance_check_spec(
            "rust-fmt",
            "cargo fmt --all --check",
            vec![AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec!["fmt".to_owned(), "--all".to_owned(), "--check".to_owned()],
            workspace_root.clone(),
            vec![],
            "rust-fmt.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "rust-clippy",
            "cargo clippy --workspace --all-targets --all-features -- -D warnings",
            vec![AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "clippy".to_owned(),
                "--workspace".to_owned(),
                "--all-targets".to_owned(),
                "--all-features".to_owned(),
                "--".to_owned(),
                "-D".to_owned(),
                "warnings".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "rust-clippy.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "cargo-test-workspace",
            "cargo test --workspace",
            vec![AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec!["test".to_owned(), "--workspace".to_owned()],
            workspace_root.clone(),
            vec![],
            "cargo-test-workspace.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "rust-malformed-input-check",
            "cargo test -p privacy-pools-sdk-core malformed_",
            vec![AssuranceRuntime::Rust],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "test".to_owned(),
                "-p".to_owned(),
                "privacy-pools-sdk-core".to_owned(),
                "malformed_".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "rust-malformed-input-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "rust-secret-hardening-check",
            "cargo test -p privacy-pools-sdk-core secret_domain_traits_do_not_compile",
            vec![AssuranceRuntime::Rust],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "test".to_owned(),
                "-p".to_owned(),
                "privacy-pools-sdk-core".to_owned(),
                "secret_domain_traits_do_not_compile".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "rust-secret-hardening-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "rust-verified-proof-safety-check",
            "cargo test -p privacy-pools-sdk verified_proof_planners_reject_raw_proof_bundles",
            vec![AssuranceRuntime::Rust],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "test".to_owned(),
                "-p".to_owned(),
                "privacy-pools-sdk".to_owned(),
                "verified_proof_planners_reject_raw_proof_bundles".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "rust-verified-proof-safety-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "rust-chain-rejection-checks",
            "cargo test -p privacy-pools-sdk-chain rejects_",
            vec![AssuranceRuntime::Rust],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "test".to_owned(),
                "-p".to_owned(),
                "privacy-pools-sdk-chain".to_owned(),
                "rejects_".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "rust-chain-rejection-checks.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "cargo-test-doc-workspace",
            "cargo test --doc --workspace",
            vec![AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "test".to_owned(),
                "--doc".to_owned(),
                "--workspace".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "cargo-test-doc-workspace.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "examples-check",
            "cargo run -p xtask -- examples-check",
            vec![AssuranceRuntime::Rust, AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "examples-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "examples-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "feature-check",
            "cargo run -p xtask -- feature-check",
            vec![AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "feature-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "feature-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "package-check",
            "cargo run -p xtask -- package-check",
            vec![AssuranceRuntime::Shared],
            "packaging",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "package-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "package-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "dependency-check",
            "cargo run -p xtask -- dependency-check",
            vec![AssuranceRuntime::Shared],
            "supply-chain",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "dependency-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "dependency-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "docs-check",
            "cargo run -p xtask -- docs-check",
            vec![AssuranceRuntime::Shared],
            "documentation",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "docs-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "docs-check.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "artifact-fingerprints",
            "cargo run -p xtask -- artifact-fingerprints --check",
            vec![AssuranceRuntime::Shared],
            "supply-chain",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "artifact-fingerprints".to_owned(),
                "--check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "artifact-fingerprints.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "signed-manifest-sample-check",
            "cargo run -p xtask -- signed-manifest-sample-check",
            vec![AssuranceRuntime::Shared],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "signed-manifest-sample-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "signed-manifest-sample-check.log",
            vec![],
            None,
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "cargo-deny-policy",
                "cargo deny check bans licenses sources",
                vec![AssuranceRuntime::Shared],
                "supply-chain",
                AssuranceCheckMode::Normative,
                "cargo",
                vec![
                    "deny".to_owned(),
                    "check".to_owned(),
                    "bans".to_owned(),
                    "licenses".to_owned(),
                    "sources".to_owned(),
                ],
                workspace_root.clone(),
                vec![],
                "cargo-deny-policy.log",
                vec![],
                None,
            ),
            vec![
                AssuranceProfile::Pr,
                AssuranceProfile::Nightly,
                AssuranceProfile::Release,
            ],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "cargo-deny-advisories",
                "cargo deny check advisories",
                vec![AssuranceRuntime::Shared],
                "supply-chain",
                AssuranceCheckMode::Normative,
                "cargo",
                vec![
                    "deny".to_owned(),
                    "check".to_owned(),
                    "advisories".to_owned(),
                ],
                workspace_root.clone(),
                vec![],
                "cargo-deny-advisories.log",
                vec![],
                None,
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "cargo-vet",
                "cargo vet",
                vec![AssuranceRuntime::Shared],
                "supply-chain",
                AssuranceCheckMode::Normative,
                "cargo",
                vec!["vet".to_owned()],
                workspace_root.clone(),
                vec![],
                "cargo-vet.log",
                vec![],
                None,
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "zizmor",
                "zizmor .github/workflows",
                vec![AssuranceRuntime::Shared],
                "supply-chain",
                AssuranceCheckMode::Normative,
                "zizmor",
                vec![".github/workflows".to_owned()],
                workspace_root.clone(),
                vec![],
                "zizmor.log",
                vec![],
                None,
            ),
            vec![
                AssuranceProfile::Pr,
                AssuranceProfile::Nightly,
                AssuranceProfile::Release,
            ],
        ),
        assurance_check_spec(
            "bindings-generate",
            "cargo run -p xtask -- bindings",
            vec![AssuranceRuntime::ReactNative, AssuranceRuntime::Shared],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "bindings".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "bindings-generate.log",
            vec![],
            None,
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "bindings-drift-check",
                "git diff --exit-code -- bindings/ios/generated bindings/android/generated",
                vec![AssuranceRuntime::ReactNative, AssuranceRuntime::Shared],
                "correctness",
                AssuranceCheckMode::Normative,
                "git",
                vec![
                    "diff".to_owned(),
                    "--exit-code".to_owned(),
                    "--".to_owned(),
                    "bindings/ios/generated".to_owned(),
                    "bindings/android/generated".to_owned(),
                ],
                workspace_root.clone(),
                vec![],
                "bindings-drift-check.log",
                vec![],
                None,
            ),
            vec!["bindings-generate".to_owned()],
        ),
        assurance_check_spec(
            "sdk-native-build",
            "npm run build:native",
            vec![AssuranceRuntime::Node, AssuranceRuntime::ReactNative],
            "correctness",
            AssuranceCheckMode::Normative,
            "npm",
            vec!["run".to_owned(), "build:native".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![],
            "sdk-native-build.log",
            vec![],
            None,
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-node-smoke",
                "npm run test:node",
                vec![AssuranceRuntime::Node],
                "correctness",
                AssuranceCheckMode::Normative,
                "npm",
                vec!["run".to_owned(), "test:node".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![],
                "sdk-node-smoke.log",
                vec![],
                None,
            ),
            vec!["sdk-native-build".to_owned()],
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-node-fail-closed-checks",
                "node --test ./test/facade.test.mjs ./test/node.test.mjs --test-name-pattern <node fail-closed>",
                vec![AssuranceRuntime::Node],
                "funds-safety",
                AssuranceCheckMode::Normative,
                "node",
                vec![
                    "--test".to_owned(),
                    "--test-name-pattern".to_owned(),
                    node_fail_closed_pattern,
                    "./test/facade.test.mjs".to_owned(),
                    "./test/node.test.mjs".to_owned(),
                ],
                workspace_root.join("packages/sdk"),
                vec![],
                "sdk-node-fail-closed-checks.log",
                vec![],
                None,
            ),
            vec!["sdk-native-build".to_owned()],
        ),
        assurance_check_spec(
            "sdk-browser-build",
            "cargo run -p xtask -- sdk-web-package --debug",
            vec![AssuranceRuntime::Browser],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "sdk-web-package".to_owned(),
                "--debug".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "sdk-browser-build.log",
            vec![],
            None,
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-browser-smoke",
                "npm run test:browser:smoke",
                vec![AssuranceRuntime::Browser],
                "correctness",
                AssuranceCheckMode::Normative,
                "npm",
                vec!["run".to_owned(), "test:browser:smoke".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![],
                "sdk-browser-smoke.log",
                vec![],
                None,
            ),
            vec!["sdk-browser-build".to_owned()],
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-browser-generated-drift-check",
                "node ./scripts/check-generated.mjs --mode pr-safe",
                vec![AssuranceRuntime::Browser],
                "correctness",
                AssuranceCheckMode::Normative,
                "node",
                vec![
                    "./scripts/check-generated.mjs".to_owned(),
                    "--mode".to_owned(),
                    "pr-safe".to_owned(),
                ],
                workspace_root.join("packages/sdk"),
                vec![],
                "sdk-browser-generated-drift-check.log",
                vec![],
                None,
            ),
            vec!["sdk-browser-build".to_owned()],
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-browser-fail-closed-checks",
                "npm run test:browser:pr-fail-closed",
                vec![AssuranceRuntime::Browser],
                "funds-safety",
                AssuranceCheckMode::Normative,
                "npm",
                vec!["run".to_owned(), "test:browser:pr-fail-closed".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![],
                "sdk-browser-fail-closed-checks.log",
                vec![],
                None,
            ),
            vec!["sdk-browser-build".to_owned()],
        ),
        assurance_check_with_profiles(
            assurance_check_with_dependencies(
                assurance_check_spec(
                    "sdk-browser-core",
                    "npm run test:browser:core",
                    vec![AssuranceRuntime::Browser],
                    "correctness",
                    AssuranceCheckMode::Normative,
                    "npm",
                    vec!["run".to_owned(), "test:browser:core".to_owned()],
                    workspace_root.join("packages/sdk"),
                    vec![],
                    "sdk-browser-core.log",
                    vec![],
                    None,
                ),
                vec!["sdk-browser-build".to_owned()],
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_with_dependencies(
                assurance_check_spec(
                    "sdk-browser-direct-execution",
                    "npm run test:browser:direct",
                    vec![AssuranceRuntime::Browser],
                    "correctness",
                    AssuranceCheckMode::Normative,
                    "npm",
                    vec!["run".to_owned(), "test:browser:direct".to_owned()],
                    workspace_root.join("packages/sdk"),
                    vec![],
                    "sdk-browser-direct-execution.log",
                    vec![],
                    None,
                ),
                vec!["sdk-browser-build".to_owned()],
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_with_dependencies(
                assurance_check_spec(
                    "sdk-browser-worker-suite",
                    "npm run test:browser:worker",
                    vec![AssuranceRuntime::Browser],
                    "correctness",
                    AssuranceCheckMode::Normative,
                    "npm",
                    vec!["run".to_owned(), "test:browser:worker".to_owned()],
                    workspace_root.join("packages/sdk"),
                    vec![],
                    "sdk-browser-worker-suite.log",
                    vec![],
                    None,
                ),
                vec!["sdk-browser-build".to_owned()],
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "browser-threaded-build",
                "npm run build:web:experimental-threaded",
                vec![AssuranceRuntime::Browser],
                "correctness",
                AssuranceCheckMode::Normative,
                "npm",
                vec![
                    "run".to_owned(),
                    "build:web:experimental-threaded".to_owned(),
                ],
                workspace_root.join("packages/sdk"),
                vec![],
                "browser-threaded-build.log",
                vec![],
                None,
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_with_dependencies(
                assurance_check_spec(
                    "browser-threaded-drift-check",
                    "git diff --exit-code -- packages/sdk/src/browser/generated-threaded",
                    vec![AssuranceRuntime::Browser],
                    "correctness",
                    AssuranceCheckMode::Normative,
                    "git",
                    vec![
                        "diff".to_owned(),
                        "--exit-code".to_owned(),
                        "--".to_owned(),
                        "packages/sdk/src/browser/generated-threaded".to_owned(),
                    ],
                    workspace_root.clone(),
                    vec![],
                    "browser-threaded-drift-check.log",
                    vec![],
                    None,
                ),
                vec!["browser-threaded-build".to_owned()],
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_spec(
            "sdk-package-dry-run",
            "npm pack --dry-run --json",
            vec![AssuranceRuntime::Node, AssuranceRuntime::Browser],
            "packaging",
            AssuranceCheckMode::Normative,
            "npm",
            vec![
                "pack".to_owned(),
                "--dry-run".to_owned(),
                "--json".to_owned(),
            ],
            workspace_root.join("packages/sdk"),
            vec![],
            "sdk-package-dry-run.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "react-native-package",
            "cargo run -p xtask -- react-native-package",
            vec![AssuranceRuntime::ReactNative],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "react-native-package".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "react-native-package.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "react-native-smoke",
            "cargo run -p xtask -- react-native-smoke",
            vec![AssuranceRuntime::ReactNative],
            "correctness",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "react-native-smoke".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "react-native-smoke.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "react-native-package-dry-run",
            "npm pack --dry-run --json",
            vec![AssuranceRuntime::ReactNative],
            "packaging",
            AssuranceCheckMode::Normative,
            "npm",
            vec![
                "pack".to_owned(),
                "--dry-run".to_owned(),
                "--json".to_owned(),
            ],
            workspace_root.join("packages/react-native"),
            vec![],
            "react-native-package-dry-run.log",
            vec![],
            None,
        ),
        assurance_check_spec(
            "compare-rust-goldens-rust",
            "node ./scripts/compare-rust-goldens.mjs",
            vec![AssuranceRuntime::Rust],
            "correctness",
            AssuranceCheckMode::Normative,
            "node",
            vec!["./scripts/compare-rust-goldens.mjs".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![
                (
                    "PRIVACY_POOLS_GOLDENS_RUNTIME".to_owned(),
                    "rust".to_owned(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_REPORT".to_owned(),
                    rust_goldens_report.to_string(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_SMOKE".to_owned(),
                    if matches!(options.profile, AssuranceProfile::Pr) {
                        "1".to_owned()
                    } else {
                        "0".to_owned()
                    },
                ),
            ],
            "compare-rust-goldens-rust.log",
            vec![options.out_dir.join("rust-goldens-comparison.json")],
            None,
        ),
        assurance_check_spec(
            "compare-rust-goldens-node",
            "node ./scripts/compare-rust-goldens.mjs",
            vec![AssuranceRuntime::Node],
            "correctness",
            AssuranceCheckMode::Normative,
            "node",
            vec!["./scripts/compare-rust-goldens.mjs".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![
                (
                    "PRIVACY_POOLS_GOLDENS_RUNTIME".to_owned(),
                    "node".to_owned(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_REPORT".to_owned(),
                    node_goldens_report.to_string(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_SMOKE".to_owned(),
                    if matches!(options.profile, AssuranceProfile::Pr) {
                        "1".to_owned()
                    } else {
                        "0".to_owned()
                    },
                ),
            ],
            "compare-rust-goldens-node.log",
            vec![options.out_dir.join("node-goldens-comparison.json")],
            None,
        ),
        assurance_check_with_dependencies(
            assurance_check_spec(
                "compare-rust-goldens-browser",
                "node ./scripts/compare-rust-goldens.mjs",
                vec![AssuranceRuntime::Browser],
                "correctness",
                AssuranceCheckMode::Normative,
                "node",
                vec!["./scripts/compare-rust-goldens.mjs".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![
                    (
                        "PRIVACY_POOLS_GOLDENS_RUNTIME".to_owned(),
                        "browser".to_owned(),
                    ),
                    (
                        "PRIVACY_POOLS_GOLDENS_REPORT".to_owned(),
                        browser_goldens_report.to_string(),
                    ),
                    (
                        "PRIVACY_POOLS_GOLDENS_SMOKE".to_owned(),
                        if matches!(options.profile, AssuranceProfile::Pr) {
                            "1".to_owned()
                        } else {
                            "0".to_owned()
                        },
                    ),
                ],
                "compare-rust-goldens-browser.log",
                vec![options.out_dir.join("browser-goldens-comparison.json")],
                None,
            ),
            vec!["sdk-browser-build".to_owned()],
        ),
        assurance_check_spec(
            "compare-rust-goldens-react-native",
            "node ./scripts/compare-rust-goldens.mjs",
            vec![AssuranceRuntime::ReactNative],
            "correctness",
            AssuranceCheckMode::Normative,
            "node",
            vec!["./scripts/compare-rust-goldens.mjs".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![
                (
                    "PRIVACY_POOLS_GOLDENS_RUNTIME".to_owned(),
                    "react-native".to_owned(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_REPORT".to_owned(),
                    react_native_goldens_report.to_string(),
                ),
                (
                    "PRIVACY_POOLS_GOLDENS_SMOKE".to_owned(),
                    if matches!(options.profile, AssuranceProfile::Pr) {
                        "1".to_owned()
                    } else {
                        "0".to_owned()
                    },
                ),
            ],
            "compare-rust-goldens-react-native.log",
            vec![options.out_dir.join("react-native-goldens-comparison.json")],
            None,
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "compare-rust-stateful-node",
                "node ./scripts/compare-rust-stateful.mjs",
                vec![AssuranceRuntime::Node],
                "correctness",
                AssuranceCheckMode::Normative,
                "node",
                vec!["./scripts/compare-rust-stateful.mjs".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![
                    (
                        "PRIVACY_POOLS_STATEFUL_RUNTIME".to_owned(),
                        "node".to_owned(),
                    ),
                    (
                        "PRIVACY_POOLS_STATEFUL_REPORT".to_owned(),
                        node_stateful_report.to_string(),
                    ),
                ],
                "compare-rust-stateful-node.log",
                vec![options.out_dir.join("node-stateful-comparison.json")],
                None,
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "compare-rust-stateful-react-native",
                "node ./scripts/compare-rust-stateful.mjs",
                vec![AssuranceRuntime::ReactNative],
                "correctness",
                AssuranceCheckMode::Normative,
                "node",
                vec!["./scripts/compare-rust-stateful.mjs".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![
                    (
                        "PRIVACY_POOLS_STATEFUL_RUNTIME".to_owned(),
                        "react-native".to_owned(),
                    ),
                    (
                        "PRIVACY_POOLS_STATEFUL_REPORT".to_owned(),
                        react_native_stateful_report.to_string(),
                    ),
                ],
                "compare-rust-stateful-react-native.log",
                vec![
                    options
                        .out_dir
                        .join("react-native-stateful-comparison.json"),
                ],
                None,
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
        assurance_check_with_profiles(
            assurance_check_spec(
                "compare-v1-rust",
                "npm run compare:v1-rust",
                vec![AssuranceRuntime::Rust],
                "funds-safety",
                AssuranceCheckMode::Normative,
                "npm",
                vec!["run".to_owned(), "compare:v1-rust".to_owned()],
                workspace_root.join("packages/sdk"),
                vec![
                    (
                        "PRIVACY_POOLS_COMPARE_RUST_REPORT".to_owned(),
                        rust_compare_report_for_child.to_string(),
                    ),
                    (
                        "PRIVACY_POOLS_COMPARE_RUST_CLI_REPORT".to_owned(),
                        rust_compare_raw_report_for_child.to_string(),
                    ),
                    (
                        "PRIVACY_POOLS_V1_BASELINE_PATH".to_owned(),
                        options.v1_package_path.to_string(),
                    ),
                    (
                        "PRIVACY_POOLS_V1_SOURCE_PATH".to_owned(),
                        options.v1_source_path.to_string(),
                    ),
                ],
                "compare-v1-rust.log",
                vec![rust_compare_report.clone(), rust_compare_raw_report.clone()],
                Some(json!({ "helperMaxRatio": 1.05, "proofMaxRatio": 1.15 })),
            ),
            vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
        ),
    ];

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "compare-v1-npm-smoke",
            "npm run compare:v1-npm (smoke)",
            vec![AssuranceRuntime::Browser],
            "correctness",
            AssuranceCheckMode::Informational,
            "npm",
            vec!["run".to_owned(), "compare:v1-npm".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![
                (
                    "PRIVACY_POOLS_COMPARE_REPORT".to_owned(),
                    browser_compare_smoke_report_for_child.to_string(),
                ),
                (
                    "PRIVACY_POOLS_V1_BASELINE_PATH".to_owned(),
                    options.v1_package_path.to_string(),
                ),
                (
                    "PRIVACY_POOLS_COMPARE_HELPER_ITERS".to_owned(),
                    "1".to_owned(),
                ),
                (
                    "PRIVACY_POOLS_COMPARE_PROOF_ITERS".to_owned(),
                    "1".to_owned(),
                ),
            ],
            "compare-v1-npm-smoke.log",
            vec![browser_compare_smoke_report.clone()],
            None,
        ),
        vec![AssuranceProfile::Nightly],
    ));

    let fuzz_targets = [
        "field_parsing",
        "wire_conversion",
        "proof_bundle_parsing",
        "manifest_parsing",
        "json_boundaries",
        "artifact_bundle_resolution",
        "session_invalidation",
        "execution_policy_inputs",
    ];
    for target in fuzz_targets {
        let runs_arg = format!("-runs={}", options.fuzz_runs);
        checks.push(assurance_check_with_profiles(
            assurance_check_spec(
                format!("fuzz-{target}"),
                format!("cargo fuzz run {target} -- {runs_arg}"),
                vec![AssuranceRuntime::Rust],
                "funds-safety",
                AssuranceCheckMode::Normative,
                "cargo",
                vec![
                    "fuzz".to_owned(),
                    "run".to_owned(),
                    target.to_owned(),
                    "--".to_owned(),
                    runs_arg,
                ],
                workspace_root.join("fuzz"),
                vec![],
                format!("fuzz-{target}.log"),
                vec![],
                None,
            ),
            vec![AssuranceProfile::Nightly],
        ));
    }

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "compare-v1-npm",
            "npm run compare:v1-npm",
            vec![AssuranceRuntime::Browser],
            "correctness",
            AssuranceCheckMode::Informational,
            "npm",
            vec!["run".to_owned(), "compare:v1-npm".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![
                (
                    "PRIVACY_POOLS_COMPARE_REPORT".to_owned(),
                    browser_compare_report_for_child.to_string(),
                ),
                (
                    "PRIVACY_POOLS_V1_BASELINE_PATH".to_owned(),
                    options.v1_package_path.to_string(),
                ),
            ],
            "compare-v1-npm.log",
            vec![browser_compare_report.clone()],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "sdk-native-build-release",
            "npm run build:native:release",
            vec![AssuranceRuntime::Node, AssuranceRuntime::ReactNative],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "npm",
            vec!["run".to_owned(), "build:native:release".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![],
            "sdk-native-build-release.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "release-debug-node-react-native",
            "node ./scripts/check-release-debug-node-react-native.mjs",
            vec![AssuranceRuntime::Node, AssuranceRuntime::ReactNative],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "node",
            vec!["./scripts/check-release-debug-node-react-native.mjs".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![],
            "release-debug-node-react-native.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "sdk-web-release-build",
            "npm run build:web:release",
            vec![AssuranceRuntime::Browser],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "npm",
            vec!["run".to_owned(), "build:web:release".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![],
            "sdk-web-release-build.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "release-debug-browser",
            "node ./scripts/check-release-debug-browser.mjs",
            vec![AssuranceRuntime::Browser],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "node",
            vec!["./scripts/check-release-debug-browser.mjs".to_owned()],
            workspace_root.join("packages/sdk"),
            vec![],
            "release-debug-browser.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "geiger-delta-check",
            "cargo run -p xtask -- geiger-delta-check",
            vec![AssuranceRuntime::Shared],
            "supply-chain",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "run".to_owned(),
                "-p".to_owned(),
                "xtask".to_owned(),
                "--".to_owned(),
                "geiger-delta-check".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "geiger-delta-check.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    checks.push(assurance_check_with_profiles(
        assurance_check_spec(
            "cargo-mutants-high-risk",
            "cargo mutants --in-place --baseline skip",
            vec![AssuranceRuntime::Rust],
            "funds-safety",
            AssuranceCheckMode::Normative,
            "cargo",
            vec![
                "mutants".to_owned(),
                "--in-place".to_owned(),
                "--baseline".to_owned(),
                "skip".to_owned(),
                "--timeout".to_owned(),
                "1200".to_owned(),
                "--minimum-test-timeout".to_owned(),
                "60".to_owned(),
                "--jobs".to_owned(),
                "2".to_owned(),
                "--package".to_owned(),
                "privacy-pools-sdk-artifacts".to_owned(),
                "--package".to_owned(),
                "privacy-pools-sdk-verifier".to_owned(),
                "--package".to_owned(),
                "privacy-pools-sdk-chain".to_owned(),
            ],
            workspace_root.clone(),
            vec![],
            "cargo-mutants-high-risk.log",
            vec![],
            None,
        ),
        vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
    ));

    if let Some(external_evidence_dir) = options.external_evidence_dir.as_ref() {
        let mobile_evidence_dir = resolve_path_for_child(workspace_root, external_evidence_dir);
        if mobile_evidence_files_present(&mobile_evidence_dir) {
            checks.push(assurance_check_with_profiles(
                assurance_check_with_dependencies(
                    assurance_check_spec(
                        "mobile-evidence-check",
                        "cargo run -p xtask -- mobile-evidence-check",
                        vec![AssuranceRuntime::ReactNative],
                        "correctness",
                        AssuranceCheckMode::Normative,
                        "cargo",
                        vec![
                            "run".to_owned(),
                            "-p".to_owned(),
                            "xtask".to_owned(),
                            "--".to_owned(),
                            "mobile-evidence-check".to_owned(),
                            "--dir".to_owned(),
                            mobile_evidence_dir.to_string(),
                        ],
                        workspace_root.clone(),
                        vec![],
                        "mobile-evidence-check.log",
                        vec![],
                        None,
                    ),
                    vec!["external-evidence-validation".to_owned()],
                ),
                vec![AssuranceProfile::Nightly, AssuranceProfile::Release],
            ));
        }
    }

    if matches!(options.profile, AssuranceProfile::Release) {
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
                    shell_escape_path(&sdk_sbom_report)
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
            "cargo run --release -p privacy-pools-sdk-cli -- benchmark-withdraw",
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

    checks
        .into_iter()
        .map(finalize_assurance_check_spec)
        .collect()
}

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

fn trusted_artifact_environment(workspace_root: &Utf8PathBuf) -> Result<Value> {
    Ok(json!({
        "snapshotPath": workspace_root.join("fixtures/artifacts/fingerprints.lock.json").as_str(),
        "fingerprints": artifact_fingerprint_snapshot(workspace_root)?,
    }))
}

fn artifact_fingerprint_snapshot(workspace_root: &Utf8PathBuf) -> Result<Value> {
    let artifacts_root = workspace_root.join("fixtures/artifacts");
    Ok(json!({
        "artifactsRoot": "fixtures/artifacts",
        "manifests": {
            "commitment": manifest_fingerprint(
                &artifacts_root,
                &artifacts_root.join("commitment-proving-manifest.json"),
            )?,
            "withdrawal": manifest_fingerprint(
                &artifacts_root,
                &artifacts_root.join("withdrawal-proving-manifest.json"),
            )?,
        },
    }))
}

fn manifest_fingerprint(
    artifacts_root: &Utf8PathBuf,
    manifest_path: &Utf8PathBuf,
) -> Result<Value> {
    let manifest_bytes =
        fs::read(manifest_path).with_context(|| format!("failed to read {}", manifest_path))?;
    let manifest_json: Value = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("failed to parse {}", manifest_path))?;
    let artifacts = manifest_json
        .get("artifacts")
        .and_then(Value::as_array)
        .with_context(|| format!("{} missing `artifacts` array", manifest_path))?;

    let mut bundle_entries = Vec::new();
    let mut artifact_records = Vec::new();
    let mut vkey_sha256 = None::<String>;

    for artifact in artifacts {
        let filename = artifact
            .get("filename")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing filename", manifest_path))?;
        let kind = artifact
            .get("kind")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing kind", manifest_path))?;
        let circuit = artifact
            .get("circuit")
            .and_then(Value::as_str)
            .with_context(|| format!("{} artifact missing circuit", manifest_path))?;
        let path = artifacts_root.join(filename);
        let sha256 = if path.exists() {
            sha256_hex(&fs::read(&path).with_context(|| format!("failed to read {}", path))?)
        } else {
            artifact
                .get("sha256")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .with_context(|| format!("{} missing sha256 for {}", manifest_path, filename))?
        };
        if kind == "vkey" {
            vkey_sha256 = Some(sha256.clone());
        }
        bundle_entries.push(format!("{circuit}:{kind}:{filename}:{sha256}"));
        artifact_records.push(json!({
            "circuit": circuit,
            "kind": kind,
            "filename": filename,
            "sha256": sha256,
        }));
    }
    bundle_entries.sort_unstable();
    artifact_records
        .sort_by(|left, right| left["filename"].as_str().cmp(&right["filename"].as_str()));

    Ok(json!({
        "manifestSha256": sha256_hex(&manifest_bytes),
        "artifactBundleSha256": sha256_hex(bundle_entries.join("\n").as_bytes()),
        "vkeyFingerprint": vkey_sha256,
        "artifacts": artifact_records,
    }))
}

fn validate_external_evidence(
    workspace_root: &Utf8PathBuf,
    options: &AssuranceOptions,
    commit: &str,
) -> Result<Option<Value>> {
    let Some(dir) = options.external_evidence_dir.as_ref() else {
        return Ok(None);
    };
    validate_external_evidence_dir(
        workspace_root,
        dir,
        options.profile,
        options.backend,
        commit,
        None,
    )
    .map(Some)
}

fn validate_mobile_evidence_subset(
    dir: &Utf8PathBuf,
    expected_commit: &str,
    required: bool,
) -> Result<Value> {
    let mobile_smoke_path = dir.join("mobile-smoke.json");
    let mobile_parity_path = dir.join("mobile-parity.json");
    let mobile_smoke_exists = mobile_smoke_path.exists();
    let mobile_parity_exists = mobile_parity_path.exists();

    ensure!(
        mobile_smoke_exists == mobile_parity_exists,
        "external mobile evidence in {} must contain both mobile-smoke.json and mobile-parity.json",
        dir
    );

    if !mobile_smoke_exists {
        ensure!(
            !required,
            "external evidence directory is missing mobile app evidence in {}",
            dir
        );
        return Ok(json!({
            "status": AssessmentStatus::NotRun.as_str(),
            "mobileSmokePath": Value::Null,
            "mobileParityPath": Value::Null,
            "mobileParity": Value::Null,
        }));
    }

    validate_mobile_smoke_evidence(&mobile_smoke_path, expected_commit)?;
    let mobile_parity = validate_mobile_parity_evidence(&mobile_parity_path, expected_commit)?;

    Ok(json!({
        "status": AssessmentStatus::Pass.as_str(),
        "mobileSmokePath": mobile_smoke_path.as_str(),
        "mobileParityPath": mobile_parity_path.as_str(),
        "mobileParity": mobile_parity,
    }))
}

fn mobile_evidence_files_present(dir: &Utf8PathBuf) -> bool {
    dir.join("mobile-smoke.json").exists() && dir.join("mobile-parity.json").exists()
}

fn reference_device_registry(workspace_root: &Utf8PathBuf) -> Result<ReferenceDeviceRegistry> {
    let registry_path = workspace_root.join("security/reference-devices.json");
    serde_json::from_value(read_required_json(&registry_path)?)
        .with_context(|| format!("failed to parse {}", registry_path))
}

fn validate_reference_benchmark_evidence(
    workspace_root: &Utf8PathBuf,
    benchmark_dir: &Utf8PathBuf,
    _profile: AssuranceProfile,
    backend: BenchmarkBackendProfile,
    commit: &str,
) -> Result<Value> {
    let benchmark_files = [
        "rust-desktop-stable.json",
        "node-desktop-stable.json",
        "browser-desktop-stable.json",
        "react-native-ios-stable.json",
        "react-native-android-stable.json",
    ];
    let existing_count = benchmark_files
        .iter()
        .filter(|file| benchmark_dir.join(file).exists())
        .count();

    if existing_count == 0 {
        return Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
        }));
    }

    if existing_count != benchmark_files.len() {
        return Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
            "error": format!(
                "reference benchmark evidence in {} is incomplete: expected {} reports but found {}",
                benchmark_dir,
                benchmark_files.len(),
                existing_count
            ),
        }));
    }

    let validate_complete = || -> Result<Value> {
        let registry = reference_device_registry(workspace_root)?;
        let expected_backend_profile = backend.report_label();
        let mut benchmark_summaries = Vec::new();
        let mut reference_device_ids = BTreeSet::new();
        let mut artifact_version = None::<String>;
        let mut zkey_sha256 = None::<String>;
        let mut manifest_sha256 = None::<String>;
        let mut artifact_bundle_sha256 = None::<String>;
        let mut reference_status = ReferencePerformanceStatus::Fresh;

        for benchmark_file in benchmark_files {
            let path = benchmark_dir.join(benchmark_file);
            let expected_device_label = if benchmark_file.contains("-ios-") {
                "ios"
            } else if benchmark_file.contains("-android-") {
                "android"
            } else {
                "desktop"
            };
            let metadata = validate_benchmark_report_with_commit_policy(
                &path,
                commit,
                expected_device_label,
                expected_backend_profile,
                backend.as_str(),
                true,
            )
            .with_context(|| format!("invalid benchmark report for {}", benchmark_file))?;

            if metadata.git_commit != commit {
                reference_status = ReferencePerformanceStatus::Stale;
            }

            match &artifact_version {
                Some(expected) => ensure!(
                    metadata.artifact_version == *expected,
                    "{} artifact_version mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.artifact_version
                ),
                None => artifact_version = Some(metadata.artifact_version.clone()),
            }
            match &zkey_sha256 {
                Some(expected) => ensure!(
                    metadata.zkey_sha256 == *expected,
                    "{} zkey_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.zkey_sha256
                ),
                None => zkey_sha256 = Some(metadata.zkey_sha256.clone()),
            }
            match &manifest_sha256 {
                Some(expected) => ensure!(
                    metadata.manifest_sha256 == *expected,
                    "{} manifest_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.manifest_sha256
                ),
                None => manifest_sha256 = Some(metadata.manifest_sha256.clone()),
            }
            match &artifact_bundle_sha256 {
                Some(expected) => ensure!(
                    metadata.artifact_bundle_sha256 == *expected,
                    "{} artifact_bundle_sha256 mismatch: expected {} but found {}",
                    path,
                    expected,
                    metadata.artifact_bundle_sha256
                ),
                None => artifact_bundle_sha256 = Some(metadata.artifact_bundle_sha256.clone()),
            }

            let device = registry
                .devices
                .iter()
                .find(|device| {
                    device.label == metadata.device_label
                        && device.model == metadata.device_model
                        && device.device_class == metadata.device_class
                        && device.evidence.iter().any(|entry| entry == benchmark_file)
                })
                .with_context(|| {
                    format!(
                        "{} does not match any entry in {}",
                        path,
                        workspace_root.join("security/reference-devices.json")
                    )
                })?;
            reference_device_ids.insert(device.id.clone());
            benchmark_summaries.push(json!({
                "path": path.as_str(),
                "deviceId": device.id,
                "deviceLabel": metadata.device_label,
                "deviceModel": metadata.device_model,
                "deviceClass": metadata.device_class,
                "benchmarkScenarioId": metadata.benchmark_scenario_id,
                "artifactVersion": metadata.artifact_version,
                "manifestSha256": metadata.manifest_sha256,
                "artifactBundleSha256": metadata.artifact_bundle_sha256,
                "gitCommit": metadata.git_commit,
            }));
        }

        Ok(json!({
            "status": reference_status.as_str(),
            "path": benchmark_dir.as_str(),
            "referenceDeviceIds": reference_device_ids.into_iter().collect::<Vec<_>>(),
            "artifactVersion": artifact_version,
            "zkeySha256": zkey_sha256,
            "manifestSha256": manifest_sha256,
            "artifactBundleSha256": artifact_bundle_sha256,
            "benchmarks": benchmark_summaries,
        }))
    };

    match validate_complete() {
        Ok(value) => Ok(value),
        Err(error) => Ok(json!({
            "status": ReferencePerformanceStatus::Missing.as_str(),
            "path": benchmark_dir.as_str(),
            "benchmarks": [],
            "referenceDeviceIds": [],
            "error": error.to_string(),
        })),
    }
}

fn validate_sbom_evidence(sbom_dir: &Utf8PathBuf, required: bool) -> Result<Vec<Utf8PathBuf>> {
    let candidate_dir = if sbom_dir.join("sbom").is_dir() {
        sbom_dir.join("sbom")
    } else {
        sbom_dir.clone()
    };
    let mut rust_paths = Vec::new();
    let rust_bundle_dir = candidate_dir.join("rust");
    if rust_bundle_dir.is_dir() {
        let mut entries = fs::read_dir(&rust_bundle_dir)
            .with_context(|| format!("failed to read {}", rust_bundle_dir))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to enumerate {}", rust_bundle_dir))?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = Utf8PathBuf::from_path_buf(entry.path())
                .map_err(|path| anyhow!("non-utf8 Rust SBOM evidence path: {}", path.display()))?;
            if path
                .file_name()
                .is_some_and(|name| name.ends_with(".cdx.json"))
            {
                rust_paths.push(path);
            }
        }
    }
    if rust_paths.is_empty() {
        let legacy_rust_path = candidate_dir.join("rust.cdx.json");
        if legacy_rust_path.exists() {
            rust_paths.push(legacy_rust_path);
        }
    }

    let supplementary_paths = vec![
        candidate_dir.join("sdk.spdx.json"),
        candidate_dir.join("react-native.spdx.json"),
    ];

    if rust_paths.is_empty() && supplementary_paths.iter().all(|path| !path.exists()) {
        ensure!(
            !required,
            "SBOM evidence directory does not contain rust.cdx.json, rust/*.cdx.json, sdk.spdx.json, and react-native.spdx.json: {}",
            candidate_dir
        );
        return Ok(Vec::new());
    }

    ensure!(
        !rust_paths.is_empty(),
        "SBOM evidence directory does not contain rust.cdx.json or rust/*.cdx.json: {}",
        candidate_dir
    );

    let mut sbom_paths = rust_paths;
    sbom_paths.extend(supplementary_paths);

    for path in &sbom_paths {
        let _ = read_required_json(path)?;
    }

    Ok(sbom_paths)
}

fn validate_attestation_verification_record(
    record: &AttestationRecord,
    verification: &AttestationVerificationRecord,
    expected_repo: &str,
    expected_signer_workflow: &str,
) -> Result<()> {
    ensure!(
        verification.verified,
        "attestation verification result must set verified=true for {}",
        record.subject_path
    );
    ensure!(
        !verification.verified_at.trim().is_empty(),
        "attestation verification result must include verifiedAt for {}",
        record.subject_path
    );
    ensure!(
        verification.repo == expected_repo,
        "attestation verification repo mismatch for {}: expected {} but found {}",
        record.subject_path,
        expected_repo,
        verification.repo
    );
    ensure!(
        verification.signer_workflow == expected_signer_workflow,
        "attestation signer workflow mismatch for {}: expected {} but found {}",
        record.subject_path,
        expected_signer_workflow,
        verification.signer_workflow
    );
    ensure!(
        verification.subject_path == record.subject_path,
        "attestation verification subjectPath mismatch for {}: expected {} but found {}",
        record.subject_path,
        record.subject_path,
        verification.subject_path
    );
    ensure!(
        verification.subject_sha256 == record.sha256,
        "attestation verification sha256 mismatch for {}: expected {} but found {}",
        record.subject_path,
        record.sha256,
        verification.subject_sha256
    );
    ensure!(
        verification
            .predicate_type
            .as_deref()
            .is_some_and(|value| value == "https://slsa.dev/provenance/v1"),
        "attestation verification predicate type mismatch for {}",
        record.subject_path
    );
    ensure!(
        verification.verification_count > 0,
        "attestation verification result must include at least one verified attestation for {}",
        record.subject_path
    );
    let subject_path = Utf8PathBuf::from(record.subject_path.as_str());
    let expected_basename = subject_path
        .file_name()
        .unwrap_or(record.subject_path.as_str());
    ensure!(
        verification
            .attested_subject_basename
            .as_deref()
            .is_some_and(|value| value == expected_basename),
        "attestation verification subject name mismatch for {}",
        record.subject_path
    );

    Ok(())
}

fn validate_attestation_records_for_packages(
    workspace_root: &Utf8PathBuf,
    dir: &Utf8PathBuf,
    packages_root: &Utf8PathBuf,
    attestations: &[AttestationRecord],
) -> Result<()> {
    ensure!(
        packages_root.exists() && packages_root.is_dir(),
        "external package evidence directory does not exist: {}",
        packages_root
    );
    ensure!(
        !attestations.is_empty(),
        "{} must contain at least one attestation record",
        dir.join("attestations.json")
    );
    let expected_repo = current_github_repository_slug(workspace_root)?;
    let expected_signer_workflow = format!("{expected_repo}/.github/workflows/release.yml");

    for record in attestations {
        ensure!(
            !record.subject_path.trim().is_empty(),
            "attestation subjectPath must not be empty"
        );
        ensure!(
            !record.sha256.trim().is_empty(),
            "attestation sha256 must not be empty"
        );
        ensure!(
            !record.attestation_url.trim().is_empty(),
            "attestation attestationUrl must not be empty"
        );
        ensure!(
            !record.workflow_run_url.trim().is_empty(),
            "attestation workflowRunUrl must not be empty"
        );
        ensure!(
            !record.verification_path.trim().is_empty(),
            "attestation verificationPath must not be empty"
        );

        let subject_path = Utf8PathBuf::from(record.subject_path.as_str());
        let resolved_subject = if subject_path.is_absolute() {
            subject_path
        } else {
            dir.join(subject_path)
        };
        ensure!(
            resolved_subject.exists(),
            "attestation subjectPath does not exist: {}",
            resolved_subject
        );
        let actual_sha256 =
            sha256_hex(&fs::read(&resolved_subject).with_context(|| {
                format!("failed to read attestation subject {}", resolved_subject)
            })?);
        ensure!(
            record.sha256 == actual_sha256,
            "attestation sha256 mismatch for {}: expected {} but found {}",
            resolved_subject,
            record.sha256,
            actual_sha256
        );

        let verification_path = Utf8PathBuf::from(record.verification_path.as_str());
        let resolved_verification = if verification_path.is_absolute() {
            verification_path
        } else {
            dir.join(verification_path)
        };
        ensure!(
            resolved_verification.exists(),
            "attestation verificationPath does not exist: {}",
            resolved_verification
        );
        let verification: AttestationVerificationRecord = serde_json::from_value(
            read_required_json(&resolved_verification)?,
        )
        .with_context(|| {
            format!(
                "failed to parse attestation verification {}",
                resolved_verification
            )
        })?;
        validate_attestation_verification_record(
            record,
            &verification,
            &expected_repo,
            &expected_signer_workflow,
        )?;
    }

    let mut package_files = Vec::new();
    collect_files_recursive(packages_root, &mut package_files)?;
    package_files.sort();
    let attested_subjects = attestations
        .iter()
        .map(|record| record.subject_path.clone())
        .collect::<BTreeSet<_>>();
    for file in package_files {
        let relative = file
            .strip_prefix(dir.as_path())
            .unwrap_or(file.as_path())
            .as_str()
            .trim_start_matches('/')
            .to_owned();
        ensure!(
            attested_subjects.contains(&relative),
            "missing attestation metadata for packaged subject {}",
            relative
        );
    }

    Ok(())
}

fn validate_external_evidence_dir(
    workspace_root: &Utf8PathBuf,
    dir: &Utf8PathBuf,
    profile: AssuranceProfile,
    backend: BenchmarkBackendProfile,
    commit: &str,
    signed_manifest_public_key_override: Option<&str>,
) -> Result<Value> {
    ensure!(
        dir.exists() && dir.is_dir(),
        "external evidence directory does not exist: {}",
        dir
    );

    let mobile_evidence =
        validate_mobile_evidence_subset(dir, commit, matches!(profile, AssuranceProfile::Release))?;
    let reference_benchmarks = validate_reference_benchmark_evidence(
        workspace_root,
        &dir.join("benchmarks"),
        profile,
        backend,
        commit,
    )?;
    let digest_sha256 = sha256_hex(directory_digest_bytes(dir)?.as_slice());

    if matches!(profile, AssuranceProfile::Nightly) {
        return Ok(json!({
            "path": dir.as_str(),
            "digestSha256": digest_sha256,
            "mobileSmokePath": mobile_evidence["mobileSmokePath"],
            "mobileParityPath": mobile_evidence["mobileParityPath"],
            "mobileParity": mobile_evidence["mobileParity"],
            "mobileEvidence": mobile_evidence,
            "referencePerformance": reference_benchmarks,
            "referenceDeviceIds": reference_benchmarks["referenceDeviceIds"],
            "benchmarks": reference_benchmarks["benchmarks"],
        }));
    }

    let signed_manifest_dir = dir.join("signed-manifest");
    let signed_manifest_public_key = signed_manifest_public_key_override
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .context(
            "external signed manifest evidence requires PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY or --signed-manifest-public-key",
        )?;
    let signed_manifest =
        validate_signed_manifest_directory(&signed_manifest_dir, &signed_manifest_public_key)?;
    let sbom_paths = validate_sbom_evidence(&dir.join("sbom"), true)?;

    let packages_root = dir.join("packages");
    let attestations_path = dir.join("attestations.json");
    let attestations: Vec<AttestationRecord> =
        serde_json::from_value(read_required_json(&attestations_path)?)
            .with_context(|| format!("failed to parse {}", attestations_path))?;
    validate_attestation_records_for_packages(workspace_root, dir, &packages_root, &attestations)?;
    let signed_manifest_package_binding = validate_signed_manifest_package_binding(
        dir,
        &packages_root,
        &attestations,
        &signed_manifest,
    )?;
    let sdk_web_package_binding = validate_sdk_web_package_binding(dir, &attestations)?;

    Ok(json!({
        "path": dir.as_str(),
        "digestSha256": digest_sha256,
        "referenceDeviceIds": reference_benchmarks["referenceDeviceIds"],
        "mobileSmokePath": mobile_evidence["mobileSmokePath"],
        "mobileParityPath": mobile_evidence["mobileParityPath"],
        "mobileParity": mobile_evidence["mobileParity"],
        "mobileEvidence": mobile_evidence,
        "signedManifest": signed_manifest,
        "signedManifestPackageBinding": signed_manifest_package_binding,
        "sdkWebPackageBinding": sdk_web_package_binding,
        "referencePerformance": reference_benchmarks,
        "benchmarks": reference_benchmarks["benchmarks"],
        "sboms": sbom_paths.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
        "attestationsPath": attestations_path.as_str(),
        "attestationCount": attestations.len(),
    }))
}

fn resolve_evidence_source_dir(source: &Utf8PathBuf, nested: &str) -> Utf8PathBuf {
    let nested_path = source.join(nested);
    if nested_path.is_dir() {
        nested_path
    } else {
        source.clone()
    }
}

fn copy_file_if_present(source: &Utf8PathBuf, destination: &Utf8PathBuf) -> Result<bool> {
    if !source.exists() {
        return Ok(false);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
    }
    fs::copy(source, destination)
        .with_context(|| format!("failed to copy {} to {}", source, destination))?;
    Ok(true)
}

fn collect_attestation_metadata_records(dir: &Utf8PathBuf) -> Result<Vec<AttestationRecord>> {
    let root = resolve_evidence_source_dir(dir, "attestation-metadata");
    ensure!(
        root.exists() && root.is_dir(),
        "attestation metadata directory does not exist: {}",
        root
    );

    let mut files = Vec::new();
    collect_files_recursive(&root, &mut files)?;
    files.sort();

    let mut records = Vec::new();
    let mut seen_subjects = BTreeSet::new();
    for path in files {
        if path
            .components()
            .any(|component| component.as_str() == "attestation-verification")
        {
            continue;
        }
        if path.extension() != Some("json") {
            continue;
        }
        let parsed: Vec<AttestationRecord> = serde_json::from_value(read_required_json(&path)?)
            .with_context(|| format!("failed to parse {}", path))?;
        for record in parsed {
            ensure!(
                seen_subjects.insert(record.subject_path.clone()),
                "duplicate attestation metadata for {}",
                record.subject_path
            );
            records.push(record);
        }
    }

    ensure!(
        !records.is_empty(),
        "attestation metadata directory must contain at least one JSON record set: {}",
        root
    );
    records.sort_by(|left, right| left.subject_path.cmp(&right.subject_path));
    Ok(records)
}

fn write_external_evidence_manifest(path: &Utf8PathBuf, value: &Value) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value)
            .context("failed to serialize external evidence manifest")?,
    )
    .with_context(|| format!("failed to write {}", path))
}

fn assemble_external_evidence_dir(
    workspace_root: &Utf8PathBuf,
    options: &ExternalEvidenceAssembleOptions,
    commit: &str,
) -> Result<Value> {
    reset_directory(&options.out_dir)?;
    let signed_manifest_source = workspace_root.join("fixtures/artifacts/signed-manifest");
    stage_directory(
        &signed_manifest_source,
        &options.out_dir.join("signed-manifest"),
    )?;

    let mut mobile_source = None::<String>;
    if let Some(dir) = options.mobile_evidence_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let copied_smoke = copy_file_if_present(
            &source.join("mobile-smoke.json"),
            &options.out_dir.join("mobile-smoke.json"),
        )?;
        let copied_parity = copy_file_if_present(
            &source.join("mobile-parity.json"),
            &options.out_dir.join("mobile-parity.json"),
        )?;
        ensure!(
            copied_smoke == copied_parity,
            "mobile evidence source {} must contain both mobile-smoke.json and mobile-parity.json",
            source
        );
        if copied_smoke {
            mobile_source = Some(source.to_string());
        }
    }

    let mut reference_source = None::<String>;
    if let Some(dir) = options.reference_benchmarks_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let benchmark_source = resolve_evidence_source_dir(&source, "benchmarks");
        if benchmark_source.exists() {
            stage_directory(&benchmark_source, &options.out_dir.join("benchmarks"))?;
            reference_source = Some(benchmark_source.to_string());
        }
    }

    let mut sbom_source = None::<String>;
    if let Some(dir) = options.sbom_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let resolved = resolve_evidence_source_dir(&source, "sbom");
        if resolved.exists() {
            stage_directory(&resolved, &options.out_dir.join("sbom"))?;
            sbom_source = Some(resolved.to_string());
        }
    }

    let mut packages_source = None::<String>;
    if let Some(dir) = options.packages_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let resolved = resolve_evidence_source_dir(&source, "packages");
        if resolved.exists() {
            stage_directory(&resolved, &options.out_dir.join("packages"))?;
            packages_source = Some(resolved.to_string());
        }
    }

    let mut attestation_source = None::<String>;
    if let Some(dir) = options.attestation_metadata_dir.as_ref() {
        let source = resolve_path_for_child(workspace_root, dir);
        let records = collect_attestation_metadata_records(&source)?;
        let verification_source = resolve_evidence_source_dir(&source, "attestation-verification");
        if verification_source.exists() {
            stage_directory(
                &verification_source,
                &options.out_dir.join("attestation-verification"),
            )?;
        }
        write_external_evidence_manifest(
            &options.out_dir.join("attestations.json"),
            &serde_json::to_value(&records).context("failed to encode attestation metadata")?,
        )?;
        attestation_source = Some(source.to_string());
    }

    match options.mode {
        ExternalEvidenceMode::Nightly => {
            let _ = validate_mobile_evidence_subset(&options.out_dir, commit, false)?;
            let _ = validate_reference_benchmark_evidence(
                workspace_root,
                &options.out_dir.join("benchmarks"),
                AssuranceProfile::Nightly,
                BenchmarkBackendProfile::Stable,
                commit,
            )?;
        }
        ExternalEvidenceMode::Release => {
            ensure!(
                mobile_source.is_some(),
                "release external evidence assembly requires --mobile-evidence-dir"
            );
            ensure!(
                sbom_source.is_some(),
                "release external evidence assembly requires --sbom-dir"
            );
            ensure!(
                packages_source.is_some(),
                "release external evidence assembly requires --packages-dir"
            );
            ensure!(
                attestation_source.is_some(),
                "release external evidence assembly requires --attestation-metadata-dir"
            );

            let _ = validate_mobile_evidence_subset(&options.out_dir, commit, true)?;
            let _ = validate_reference_benchmark_evidence(
                workspace_root,
                &options.out_dir.join("benchmarks"),
                AssuranceProfile::Release,
                BenchmarkBackendProfile::Stable,
                commit,
            )?;
            let _ = validate_sbom_evidence(&options.out_dir.join("sbom"), true)?;
            let attestations: Vec<AttestationRecord> = serde_json::from_value(read_required_json(
                &options.out_dir.join("attestations.json"),
            )?)
            .with_context(|| {
                format!(
                    "failed to parse {}",
                    options.out_dir.join("attestations.json")
                )
            })?;
            validate_attestation_records_for_packages(
                workspace_root,
                &options.out_dir,
                &options.out_dir.join("packages"),
                &attestations,
            )?;
        }
    }

    let mobile_evidence = validate_mobile_evidence_subset(
        &options.out_dir,
        commit,
        matches!(options.mode, ExternalEvidenceMode::Release),
    )?;
    let reference_performance = validate_reference_benchmark_evidence(
        workspace_root,
        &options.out_dir.join("benchmarks"),
        if matches!(options.mode, ExternalEvidenceMode::Release) {
            AssuranceProfile::Release
        } else {
            AssuranceProfile::Nightly
        },
        BenchmarkBackendProfile::Stable,
        commit,
    )?;
    let assembly_manifest = json!({
        "generatedAtUnixSeconds": current_unix_seconds()?,
        "mode": options.mode.as_str(),
        "gitCommit": commit,
        "outDir": options.out_dir.as_str(),
        "sources": {
            "mobileEvidenceDir": mobile_source,
            "referenceBenchmarksDir": reference_source,
            "sbomDir": sbom_source,
            "packagesDir": packages_source,
            "attestationMetadataDir": attestation_source,
            "signedManifestDir": signed_manifest_source.as_str(),
        },
        "mobileEvidence": {
            "status": mobile_evidence["status"],
            "mobileSmokePath": mobile_evidence["mobileSmokePath"],
            "mobileParityPath": mobile_evidence["mobileParityPath"],
        },
        "referencePerformance": {
            "status": reference_performance["status"],
            "benchmarkCount": reference_performance["benchmarks"]
                .as_array()
                .map_or(0, Vec::len),
            "referenceDeviceIds": reference_performance["referenceDeviceIds"],
        },
    });
    write_external_evidence_manifest(
        &options.out_dir.join("assembly-manifest.json"),
        &assembly_manifest,
    )?;

    Ok(assembly_manifest)
}

fn validate_signed_manifest_directory(dir: &Utf8PathBuf, public_key_hex: &str) -> Result<Value> {
    let payload_path = dir.join("payload.json");
    let signature_path = dir.join("signature");
    let artifacts_root = dir.join("artifacts");
    ensure!(
        artifacts_root.exists() && artifacts_root.is_dir(),
        "signed manifest artifact directory does not exist: {}",
        artifacts_root
    );
    let payload_json =
        fs::read(&payload_path).with_context(|| format!("failed to read {}", payload_path))?;
    let signature = read_required_text_file(&signature_path)?;
    let verified = verify_signed_manifest_artifact_files(
        &payload_json,
        signature.trim(),
        public_key_hex.trim(),
        artifacts_root.as_std_path(),
    )
    .with_context(|| format!("signed manifest validation failed for {}", dir))?;
    let artifacts_digest_sha256 = sha256_hex(directory_digest_bytes(&artifacts_root)?.as_slice());

    Ok(json!({
        "path": dir.as_str(),
        "version": verified.payload().manifest.version,
        "artifactCount": verified.artifact_count(),
        "payloadSha256": sha256_hex(&payload_json),
        "signatureSha256": sha256_hex(signature.trim().as_bytes()),
        "artifactsDigestSha256": artifacts_digest_sha256,
    }))
}

fn archive_signed_manifest_package_summary(
    archive_path: &Utf8PathBuf,
    current_dir: &Utf8PathBuf,
) -> Result<Value> {
    let payload_path = "artifacts/signed-manifest/payload.json";
    let signature_path = "artifacts/signed-manifest/signature";

    let payload = command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), payload_path],
        current_dir,
        &format!("failed to read {payload_path} from {}", archive_path),
    )?;
    let signature = command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), signature_path],
        current_dir,
        &format!("failed to read {signature_path} from {}", archive_path),
    )?;
    let payload_json: Value = serde_json::from_slice(&payload)
        .with_context(|| format!("failed to parse {payload_path} from {}", archive_path))?;
    let manifest = payload_json
        .get("manifest")
        .and_then(Value::as_object)
        .with_context(|| format!("{payload_path} from {} is missing manifest", archive_path))?;
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .with_context(|| {
            format!(
                "{payload_path} from {} is missing manifest.version",
                archive_path
            )
        })?;
    let artifact_entries = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .with_context(|| {
            format!(
                "{payload_path} from {} is missing manifest.artifacts",
                archive_path
            )
        })?;
    ensure!(
        !artifact_entries.is_empty(),
        "{} does not contain any signed manifest artifact entries",
        archive_path,
    );

    let mut digest = Sha256::new();
    for entry in artifact_entries {
        let relative = entry
            .get("filename")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "{payload_path} from {} has an artifact without filename",
                    archive_path
                )
            })?;
        let expected_sha256 = entry
            .get("sha256")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "{payload_path} from {} has an artifact without sha256",
                    archive_path
                )
            })?;
        let archive_entry = format!("artifacts/{relative}");
        let bytes = command_output_bytes(
            "tar",
            &["-xOf", archive_path.as_str(), &archive_entry],
            current_dir,
            &format!("failed to read {archive_entry} from {}", archive_path),
        )?;
        ensure!(
            sha256_hex(&bytes) == expected_sha256,
            "packaged circuit artifact {} in {} does not match embedded signed manifest",
            archive_entry,
            archive_path
        );
        digest.update(relative.as_bytes());
        digest.update(b"\n");
        digest.update(&bytes);
        digest.update(b"\n");
    }

    Ok(json!({
        "version": version,
        "artifactCount": artifact_entries.len(),
        "payloadSha256": sha256_hex(&payload),
        "signatureSha256": sha256_hex(signature.trim_ascii()),
        "artifactsDigestSha256": sha256_hex(&digest.finalize()),
    }))
}

fn archive_entry_bytes(
    archive_path: &Utf8PathBuf,
    archive_entry: &str,
    current_dir: &Utf8PathBuf,
) -> Result<Vec<u8>> {
    command_output_bytes(
        "tar",
        &["-xOf", archive_path.as_str(), archive_entry],
        current_dir,
        &format!("failed to read {archive_entry} from {}", archive_path),
    )
}

fn validate_signed_manifest_package_binding(
    dir: &Utf8PathBuf,
    packages_root: &Utf8PathBuf,
    attestations: &[AttestationRecord],
    signed_manifest: &Value,
) -> Result<Value> {
    let package_records = attestations
        .iter()
        .filter(|record| record.subject_path.starts_with("packages/circuits/"))
        .collect::<Vec<_>>();
    ensure!(
        !package_records.is_empty(),
        "missing attestation metadata for packaged circuit artifacts under {}",
        packages_root
    );
    ensure!(
        package_records.len() == 1,
        "expected exactly one packaged circuit-artifact attestation subject under {} but found {}",
        packages_root,
        package_records.len()
    );
    let package_record = package_records[0];
    let archive_path = dir.join(&package_record.subject_path);
    ensure!(
        archive_path.exists(),
        "packaged circuit-artifact subject does not exist: {}",
        archive_path
    );

    let archive_summary = archive_signed_manifest_package_summary(&archive_path, dir)?;
    for field in ["payloadSha256", "signatureSha256", "artifactsDigestSha256"] {
        ensure!(
            archive_summary[field] == signed_manifest[field],
            "packaged circuit-artifact signed-manifest {} mismatch for {}",
            field,
            archive_path
        );
    }

    Ok(json!({
        "subjectPath": package_record.subject_path,
        "archivePath": archive_path.as_str(),
        "version": archive_summary["version"],
        "artifactCount": archive_summary["artifactCount"],
        "payloadSha256": archive_summary["payloadSha256"],
        "signatureSha256": archive_summary["signatureSha256"],
        "artifactsDigestSha256": archive_summary["artifactsDigestSha256"],
    }))
}

fn validate_sdk_web_package_binding(
    dir: &Utf8PathBuf,
    attestations: &[AttestationRecord],
) -> Result<Value> {
    let package_records = attestations
        .iter()
        .filter(|record| {
            (record.subject_path.starts_with("packages/sdk/")
                && Path::new(&record.subject_path)
                    .extension()
                    .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("tgz")))
                || record.subject_path == "packages/sdk.tgz"
        })
        .collect::<Vec<_>>();
    ensure!(
        package_records.len() == 1,
        "expected exactly one packaged browser npm tarball attestation subject but found {}",
        package_records.len()
    );
    let package_record = package_records[0];
    let package_path = dir.join(&package_record.subject_path);
    ensure!(
        package_path.exists(),
        "packaged browser npm tarball subject does not exist: {}",
        package_path
    );

    let wasm_records = attestations
        .iter()
        .filter(|record| {
            record
                .subject_path
                .ends_with("/privacy_pools_sdk_web_bg.wasm")
                || record.subject_path == "packages/privacy_pools_sdk_web_bg.wasm"
        })
        .collect::<Vec<_>>();
    ensure!(
        wasm_records.len() == 1,
        "expected exactly one packaged browser wasm attestation subject but found {}",
        wasm_records.len()
    );
    let wasm_record = wasm_records[0];
    let wasm_path = dir.join(&wasm_record.subject_path);
    ensure!(
        wasm_path.exists(),
        "packaged browser wasm subject does not exist: {}",
        wasm_path
    );

    let packaged_wasm = archive_entry_bytes(
        &package_path,
        "package/src/browser/generated/privacy_pools_sdk_web_bg.wasm",
        dir,
    )?;
    let exported_wasm =
        fs::read(&wasm_path).with_context(|| format!("failed to read {}", wasm_path))?;
    let packaged_wasm_sha256 = sha256_hex(&packaged_wasm);
    let exported_wasm_sha256 = sha256_hex(&exported_wasm);
    ensure!(
        packaged_wasm == exported_wasm,
        "packaged browser WASM mismatch: {} embeds {} but {} has {}",
        package_path,
        packaged_wasm_sha256,
        wasm_path,
        exported_wasm_sha256
    );

    Ok(json!({
        "packageSubjectPath": package_record.subject_path,
        "packagePath": package_path.as_str(),
        "wasmSubjectPath": wasm_record.subject_path,
        "wasmPath": wasm_path.as_str(),
        "browserWasmSha256": exported_wasm_sha256,
    }))
}

fn directory_digest_bytes(dir: &Utf8PathBuf) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, &mut files)?;
    files.sort();

    let mut digest = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(dir.as_path())
            .unwrap_or(path.as_path())
            .as_str()
            .trim_start_matches('/');
        digest.update(relative.as_bytes());
        digest.update(b"\n");
        digest.update(&fs::read(&path).with_context(|| format!("failed to read {}", path))?);
        digest.update(b"\n");
    }
    Ok(digest.finalize().to_vec())
}

fn collect_files_recursive(root: &Utf8PathBuf, output: &mut Vec<Utf8PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root))?;
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("path is not valid UTF-8: {:?}", raw))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path))?
            .is_dir()
        {
            collect_files_recursive(&path, output)?;
        } else {
            output.push(path);
        }
    }
    Ok(())
}

fn workspace_unsafe_matches(workspace_root: &Utf8PathBuf) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let root = workspace_root.join("crates");
    if root.exists() {
        collect_files_recursive(&root, &mut files)?;
    }
    files.sort();

    let mut matches = Vec::new();
    for path in files {
        if path.extension() != Some("rs") {
            continue;
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("failed to read {}", path))?;
        for (index, line) in contents.lines().enumerate() {
            if line.contains("unsafe") {
                matches.push(format!("{}:{}:{}", path, index + 1, line.trim()));
            }
        }
    }
    Ok(matches)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn format_command(program: &str, args: &[String]) -> String {
    let mut command = program.to_owned();
    for arg in args {
        command.push(' ');
        command.push_str(arg);
    }
    command
}

fn shell_escape_path(path: &Utf8PathBuf) -> String {
    format!("'{}'", path.as_str().replace('\'', "'\"'\"'"))
}

fn resolve_path_for_child(workspace_root: &Utf8PathBuf, path: &Utf8PathBuf) -> Utf8PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        workspace_root.join(path)
    }
}

#[cfg(test)]
fn validate_signed_manifest_evidence(
    dir: &Utf8PathBuf,
    public_key_hex: Option<&str>,
) -> Result<Option<(String, usize)>> {
    let payload_path = dir.join("signed-artifact-manifest.payload.json");
    if !payload_path.exists() {
        return Ok(None);
    }

    let public_key_hex = public_key_hex.context(
        "signed-artifact-manifest.payload.json is present; pass --signed-manifest-public-key or set PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY",
    )?;
    let signature = read_required_text_file(&dir.join("signed-artifact-manifest.signature"))?;
    let artifact_root = signed_manifest_artifact_root(dir);
    ensure!(
        artifact_root.exists() && artifact_root.is_dir(),
        "signed artifact manifest artifact root does not exist: {}",
        artifact_root
    );
    let payload_json =
        fs::read(&payload_path).with_context(|| format!("failed to read {payload_path}"))?;
    let verified = verify_signed_manifest_artifact_files(
        &payload_json,
        signature.trim(),
        public_key_hex.trim(),
        artifact_root.as_std_path(),
    )
    .with_context(|| {
        format!(
            "signed artifact manifest validation failed for {}",
            payload_path
        )
    })?;

    Ok(Some((
        verified.payload().manifest.version.clone(),
        verified.artifact_count(),
    )))
}

#[cfg(test)]
fn signed_manifest_artifact_root(dir: &Utf8PathBuf) -> Utf8PathBuf {
    for candidate in [
        dir.join("signed-artifact-manifest-artifacts"),
        dir.join("artifacts"),
    ] {
        if candidate.is_dir() {
            return candidate;
        }
    }
    dir.clone()
}

fn validate_browser_comparison_report(path: &Utf8PathBuf) -> Result<()> {
    let json = read_required_json(path)?;
    let browser = json
        .get("browserPerformance")
        .with_context(|| format!("{path} missing `browserPerformance`"))?;
    for circuit in ["commitment", "withdrawal"] {
        let report = browser
            .get(circuit)
            .with_context(|| format!("{path} missing `browserPerformance.{circuit}`"))?;

        for suite in ["directCold", "directWarm", "workerCold", "workerWarm"] {
            let metric = report
                .get(suite)
                .with_context(|| format!("{path} missing browser {circuit} suite `{suite}`"))?;
            ensure_json_u64(metric, "iterations", path)?;
            validate_metric_summary(
                metric
                    .get("total")
                    .with_context(|| format!("{path} missing `{circuit}.{suite}.total`"))?,
                &format!("{circuit}.{suite}.total"),
                path,
            )?;
            let slices = metric
                .get("slices")
                .with_context(|| format!("{path} missing `{circuit}.{suite}.slices`"))?;
            for slice in [
                "preloadMs",
                "witnessParseMs",
                "witnessTransferMs",
                "witnessMs",
                "proveMs",
                "verifyMs",
                "totalMs",
            ] {
                validate_metric_summary(
                    slices.get(slice).with_context(|| {
                        format!("{path} missing `{circuit}.{suite}.slices.{slice}`")
                    })?,
                    &format!("{circuit}.{suite}.slices.{slice}"),
                    path,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_rust_comparison_report(path: &Utf8PathBuf) -> Result<Value> {
    let json = read_required_json(path)?;
    ensure_json_string(&json, "gitCommit", path)?;
    ensure_json_string(&json, "sdkVersion", path)?;
    let baseline = json
        .get("baseline")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `baseline` object"))?;
    ensure!(
        baseline
            .get("packagePath")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "{path} missing `baseline.packagePath`"
    );
    ensure!(
        baseline
            .get("sourcePath")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "{path} missing `baseline.sourcePath`"
    );

    let safety = json
        .get("safety")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `safety` object"))?;
    let failed = safety
        .get("failed")
        .and_then(Value::as_u64)
        .with_context(|| format!("{path} missing `safety.failed`"))?;
    ensure!(
        failed == 0,
        "{path} recorded {failed} Rust-v1 safety failures"
    );
    let checks = safety
        .get("checks")
        .and_then(Value::as_array)
        .with_context(|| format!("{path} missing `safety.checks`"))?;
    ensure!(
        !checks.is_empty(),
        "{path} safety checks array must not be empty"
    );

    let performance = json
        .get("performance")
        .and_then(Value::as_object)
        .with_context(|| format!("{path} missing `performance` object"))?;
    let regressions = performance
        .get("regressions")
        .and_then(Value::as_array)
        .with_context(|| format!("{path} missing `performance.regressions`"))?;
    ensure!(
        regressions.is_empty(),
        "{path} recorded {} unexplained performance regressions",
        regressions.len()
    );

    Ok(json)
}

fn validate_metric_summary(metric: &Value, label: &str, path: &Utf8PathBuf) -> Result<()> {
    for field in ["averageMs", "minMs", "maxMs"] {
        let value = metric
            .get(field)
            .and_then(Value::as_f64)
            .with_context(|| format!("{path} missing numeric `{label}.{field}`"))?;
        ensure!(
            value.is_finite() && value >= 0.0,
            "{} has invalid `{label}.{field}`: {value}",
            path
        );
    }
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

#[derive(Debug, Clone, Copy, Default)]
enum NativeTargets {
    #[default]
    None,
    Ios,
    Android,
    Both,
}

impl NativeTargets {
    fn add_ios(&mut self) {
        *self = match self {
            Self::None | Self::Ios => Self::Ios,
            Self::Android | Self::Both => Self::Both,
        };
    }

    fn add_android(&mut self) {
        *self = match self {
            Self::None | Self::Android => Self::Android,
            Self::Ios | Self::Both => Self::Both,
        };
    }

    fn includes_ios(self) -> bool {
        matches!(self, Self::Ios | Self::Both)
    }

    fn includes_android(self) -> bool {
        matches!(self, Self::Android | Self::Both)
    }

    fn any(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Default)]
struct ReactNativePackageOptions {
    release: bool,
    native_targets: NativeTargets,
    enable_testing_surface: bool,
}

impl ReactNativePackageOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut options = Self::default();

        for arg in args {
            match arg.as_str() {
                "--release" => options.release = true,
                "--with-ios-native" => options.native_targets.add_ios(),
                "--with-android-native" => options.native_targets.add_android(),
                "--with-native" => {
                    options.native_targets.add_ios();
                    options.native_targets.add_android();
                }
                "--enable-testing-surface" => options.enable_testing_surface = true,
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
}

impl BenchmarkBackendProfile {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "stable" => Ok(Self::Stable),
            other => bail!("unsupported benchmark backend: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
        }
    }

    fn report_label(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
        }
    }
}

#[derive(Debug, Clone)]
struct EvidenceCheckOptions {
    channel: ReleaseChannel,
    dir: Utf8PathBuf,
    backend: BenchmarkBackendProfile,
    signed_manifest_public_key: Option<String>,
}

#[derive(Debug, Clone)]
struct MobileEvidenceCheckOptions {
    dir: Utf8PathBuf,
}

impl MobileEvidenceCheckOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut dir = None;
        let mut iter = args.into_iter();

        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--dir" => {
                    dir = Some(Utf8PathBuf::from(
                        iter.next().context("--dir requires a value")?,
                    ));
                }
                other => bail!("unknown mobile-evidence-check flag: {other}"),
            }
        }

        Ok(Self {
            dir: dir.context("--dir is required")?,
        })
    }
}

impl EvidenceCheckOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut channel = None;
        let mut dir = None;
        let mut backend = BenchmarkBackendProfile::Stable;
        let mut signed_manifest_public_key = None;
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
                "--signed-manifest-public-key" => {
                    signed_manifest_public_key = Some(
                        iter.next()
                            .context("--signed-manifest-public-key requires a value")?,
                    );
                }
                other => bail!("unknown evidence-check flag: {other}"),
            }
        }

        let signed_manifest_public_key = signed_manifest_public_key.or_else(|| {
            env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });

        Ok(Self {
            channel: channel.context("--channel is required")?,
            dir: dir.context("--dir is required")?,
            backend,
            signed_manifest_public_key,
        })
    }
}

#[derive(Debug, Clone)]
struct AuditPackOptions {
    out_dir: Utf8PathBuf,
    backend: BenchmarkBackendProfile,
    device_label: String,
    device_model: String,
    v1_package_path: Utf8PathBuf,
    v1_source_path: Utf8PathBuf,
    external_evidence_dir: Option<Utf8PathBuf>,
    fuzz_runs: usize,
    skip_fuzz: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ReferenceDeviceRegistry {
    devices: Vec<ReferenceDevice>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceDevice {
    id: String,
    label: String,
    model: String,
    device_class: String,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UnsafeAllowlist {
    allowed_matches: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationRecord {
    subject_path: String,
    sha256: String,
    attestation_url: String,
    workflow_run_url: String,
    verification_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationVerificationRecord {
    verified: bool,
    verified_at: String,
    repo: String,
    signer_workflow: String,
    subject_path: String,
    subject_sha256: String,
    attested_subject_name: Option<String>,
    attested_subject_basename: Option<String>,
    predicate_type: Option<String>,
    verification_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalEvidenceMode {
    Nightly,
    Release,
}

impl ExternalEvidenceMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "nightly" => Ok(Self::Nightly),
            "release" => Ok(Self::Release),
            other => bail!("unknown external evidence assembly mode: {other}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Nightly => "nightly",
            Self::Release => "release",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssessmentStatus {
    Pass,
    Fail,
    NotRun,
}

impl AssessmentStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not-run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferencePerformanceStatus {
    Fresh,
    Stale,
    Missing,
}

impl ReferencePerformanceStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssuranceProfile {
    Pr,
    Nightly,
    Release,
}

impl AssuranceProfile {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "pr" => Ok(Self::Pr),
            "nightly" => Ok(Self::Nightly),
            "release" => Ok(Self::Release),
            other => bail!("unknown assurance profile: {other}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Pr => "pr",
            Self::Nightly => "nightly",
            Self::Release => "release",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssuranceRuntime {
    Rust,
    Node,
    Browser,
    ReactNative,
    Shared,
    All,
}

impl AssuranceRuntime {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "rust" => Ok(Self::Rust),
            "node" => Ok(Self::Node),
            "browser" => Ok(Self::Browser),
            "react-native" => Ok(Self::ReactNative),
            "all" => Ok(Self::All),
            other => bail!("unknown assurance runtime: {other}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Node => "node",
            Self::Browser => "browser",
            Self::ReactNative => "react-native",
            Self::Shared => "shared",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssuranceReportMode {
    Standard,
    Audit,
}

impl AssuranceReportMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "standard" => Ok(Self::Standard),
            "audit" => Ok(Self::Audit),
            other => bail!("unknown assurance report mode: {other}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Audit => "audit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssuranceCheckMode {
    Normative,
    Informational,
}

impl AssuranceCheckMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normative => "normative",
            Self::Informational => "informational",
        }
    }

    const fn is_normative(self) -> bool {
        matches!(self, Self::Normative)
    }
}

#[derive(Debug, Clone)]
struct AssuranceOptions {
    profile: AssuranceProfile,
    runtime: AssuranceRuntime,
    report_mode: AssuranceReportMode,
    out_dir: Utf8PathBuf,
    backend: BenchmarkBackendProfile,
    device_label: String,
    device_model: String,
    v1_package_path: Utf8PathBuf,
    v1_source_path: Utf8PathBuf,
    external_evidence_dir: Option<Utf8PathBuf>,
    fuzz_runs: usize,
    skip_fuzz: bool,
    only_checks: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct AssuranceMergeOptions {
    profile: AssuranceProfile,
    runtime: AssuranceRuntime,
    out_dir: Utf8PathBuf,
    inputs: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone)]
struct ExternalEvidenceAssembleOptions {
    mode: ExternalEvidenceMode,
    out_dir: Utf8PathBuf,
    mobile_evidence_dir: Option<Utf8PathBuf>,
    reference_benchmarks_dir: Option<Utf8PathBuf>,
    sbom_dir: Option<Utf8PathBuf>,
    packages_dir: Option<Utf8PathBuf>,
    attestation_metadata_dir: Option<Utf8PathBuf>,
}

#[derive(Debug, Clone)]
struct AssuranceCheckSpec {
    id: String,
    label: String,
    runtimes: Vec<AssuranceRuntime>,
    allowed_profiles: Vec<AssuranceProfile>,
    depends_on: Vec<String>,
    scenario_tags: Vec<String>,
    risk_class: &'static str,
    mode: AssuranceCheckMode,
    program: String,
    args: Vec<String>,
    current_dir: Utf8PathBuf,
    envs: Vec<(String, String)>,
    log_name: String,
    rationale: String,
    inputs: Value,
    expected_outputs: Vec<Utf8PathBuf>,
    thresholds: Option<Value>,
}

#[derive(Debug, Clone)]
struct AssuranceMatrixEntry {
    runtime: AssuranceRuntime,
    profiles: Vec<AssuranceProfile>,
    scenario_tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AssuranceMatrixEntryRaw {
    runtime: String,
    profiles: Vec<String>,
    scenario_tags: Vec<String>,
}

impl AuditPackOptions {
    fn parse(args: Vec<String>, workspace_root: &Utf8PathBuf) -> Result<Self> {
        let mut out_dir = workspace_root.join("dist/audit-pack");
        let mut backend = BenchmarkBackendProfile::Stable;
        let mut device_label = "desktop".to_owned();
        let mut device_model = detect_device_model(workspace_root)?;
        let mut v1_package_path = Utf8PathBuf::from(
            "/Users/matthewb/Documents/0xbow/v1 SDK/npm/privacy-pools-core-sdk-1.2.0/package",
        );
        let mut v1_source_path =
            Utf8PathBuf::from("/Users/matthewb/Documents/0xbow/v1 SDK/privacy-pools-core");
        let mut external_evidence_dir = None;
        let mut fuzz_runs = 1000usize;
        let mut skip_fuzz = false;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--out-dir" => {
                    out_dir = Utf8PathBuf::from(iter.next().context("--out-dir requires a value")?);
                }
                "--backend" => {
                    backend = BenchmarkBackendProfile::parse(
                        &iter.next().context("--backend requires a value")?,
                    )?;
                }
                "--device-label" => {
                    device_label = iter.next().context("--device-label requires a value")?;
                }
                "--device-model" => {
                    device_model = iter.next().context("--device-model requires a value")?;
                }
                "--v1-package-path" => {
                    v1_package_path = Utf8PathBuf::from(
                        iter.next().context("--v1-package-path requires a value")?,
                    );
                }
                "--v1-source-path" => {
                    v1_source_path = Utf8PathBuf::from(
                        iter.next().context("--v1-source-path requires a value")?,
                    );
                }
                "--external-evidence-dir" => {
                    external_evidence_dir = Some(Utf8PathBuf::from(
                        iter.next()
                            .context("--external-evidence-dir requires a value")?,
                    ));
                }
                "--fuzz-runs" => {
                    fuzz_runs = iter
                        .next()
                        .context("--fuzz-runs requires a value")?
                        .parse()
                        .context("failed to parse --fuzz-runs")?;
                }
                "--skip-fuzz" => {
                    skip_fuzz = true;
                }
                other => bail!("unknown audit-pack flag: {other}"),
            }
        }

        Ok(Self {
            out_dir,
            backend,
            device_label,
            device_model,
            v1_package_path,
            v1_source_path,
            external_evidence_dir,
            fuzz_runs,
            skip_fuzz,
        })
    }
}

impl ExternalEvidenceAssembleOptions {
    fn parse(args: Vec<String>, workspace_root: &Utf8PathBuf) -> Result<Self> {
        let mut mode = ExternalEvidenceMode::Nightly;
        let mut out_dir = workspace_root.join("target/external-evidence");
        let mut out_dir_overridden = false;
        let mut mobile_evidence_dir = None;
        let mut reference_benchmarks_dir = None;
        let mut sbom_dir = None;
        let mut packages_dir = None;
        let mut attestation_metadata_dir = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--mode" => {
                    mode = ExternalEvidenceMode::parse(
                        &iter.next().context("--mode requires a value")?,
                    )?;
                    if !out_dir_overridden {
                        out_dir = workspace_root
                            .join(format!("target/external-evidence-{}", mode.as_str()));
                    }
                }
                "--out-dir" => {
                    out_dir = Utf8PathBuf::from(iter.next().context("--out-dir requires a value")?);
                    out_dir_overridden = true;
                }
                "--mobile-evidence-dir" => {
                    mobile_evidence_dir = Some(Utf8PathBuf::from(
                        iter.next()
                            .context("--mobile-evidence-dir requires a value")?,
                    ));
                }
                "--reference-benchmarks-dir" => {
                    reference_benchmarks_dir = Some(Utf8PathBuf::from(
                        iter.next()
                            .context("--reference-benchmarks-dir requires a value")?,
                    ));
                }
                "--sbom-dir" => {
                    sbom_dir = Some(Utf8PathBuf::from(
                        iter.next().context("--sbom-dir requires a value")?,
                    ));
                }
                "--packages-dir" => {
                    packages_dir = Some(Utf8PathBuf::from(
                        iter.next().context("--packages-dir requires a value")?,
                    ));
                }
                "--attestation-metadata-dir" => {
                    attestation_metadata_dir = Some(Utf8PathBuf::from(
                        iter.next()
                            .context("--attestation-metadata-dir requires a value")?,
                    ));
                }
                other => bail!("unknown external-evidence-assemble flag: {other}"),
            }
        }

        Ok(Self {
            mode,
            out_dir,
            mobile_evidence_dir,
            reference_benchmarks_dir,
            sbom_dir,
            packages_dir,
            attestation_metadata_dir,
        })
    }
}

impl AssuranceOptions {
    fn parse(args: Vec<String>, workspace_root: &Utf8PathBuf) -> Result<Self> {
        let mut profile = AssuranceProfile::Pr;
        let mut runtime = AssuranceRuntime::All;
        let mut report_mode = AssuranceReportMode::Standard;
        let mut out_dir = workspace_root.join("dist/assurance/pr");
        let mut out_dir_overridden = false;
        let mut backend = BenchmarkBackendProfile::Stable;
        let mut device_label = "desktop".to_owned();
        let mut device_model = detect_device_model(workspace_root)?;
        let mut v1_package_path = Utf8PathBuf::from(
            "/Users/matthewb/Documents/0xbow/v1 SDK/npm/privacy-pools-core-sdk-1.2.0/package",
        );
        let mut v1_source_path =
            Utf8PathBuf::from("/Users/matthewb/Documents/0xbow/v1 SDK/privacy-pools-core");
        let mut external_evidence_dir = None;
        let mut fuzz_runs = 1000usize;
        let mut skip_fuzz = false;
        let mut only_checks = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--profile" => {
                    profile = AssuranceProfile::parse(
                        &iter.next().context("--profile requires a value")?,
                    )?;
                    if !out_dir_overridden {
                        out_dir =
                            workspace_root.join(format!("dist/assurance/{}", profile.as_str()));
                    }
                }
                "--runtime" => {
                    runtime = AssuranceRuntime::parse(
                        &iter.next().context("--runtime requires a value")?,
                    )?;
                }
                "--report-mode" => {
                    report_mode = AssuranceReportMode::parse(
                        &iter.next().context("--report-mode requires a value")?,
                    )?;
                }
                "--out-dir" => {
                    out_dir = Utf8PathBuf::from(iter.next().context("--out-dir requires a value")?);
                    out_dir_overridden = true;
                }
                "--backend" => {
                    backend = BenchmarkBackendProfile::parse(
                        &iter.next().context("--backend requires a value")?,
                    )?;
                }
                "--device-label" => {
                    device_label = iter.next().context("--device-label requires a value")?;
                }
                "--device-model" => {
                    device_model = iter.next().context("--device-model requires a value")?;
                }
                "--v1-package-path" => {
                    v1_package_path = Utf8PathBuf::from(
                        iter.next().context("--v1-package-path requires a value")?,
                    );
                }
                "--v1-source-path" => {
                    v1_source_path = Utf8PathBuf::from(
                        iter.next().context("--v1-source-path requires a value")?,
                    );
                }
                "--external-evidence-dir" => {
                    external_evidence_dir = Some(Utf8PathBuf::from(
                        iter.next()
                            .context("--external-evidence-dir requires a value")?,
                    ));
                }
                "--fuzz-runs" => {
                    fuzz_runs = iter
                        .next()
                        .context("--fuzz-runs requires a value")?
                        .parse()
                        .context("failed to parse --fuzz-runs")?;
                }
                "--skip-fuzz" => {
                    skip_fuzz = true;
                }
                "--only-checks" => {
                    let value = iter.next().context("--only-checks requires a value")?;
                    let checks = value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>();
                    ensure!(
                        !checks.is_empty(),
                        "--only-checks requires at least one check id"
                    );
                    only_checks = Some(checks);
                }
                other => bail!("unknown assurance flag: {other}"),
            }
        }

        Ok(Self {
            profile,
            runtime,
            report_mode,
            out_dir,
            backend,
            device_label,
            device_model,
            v1_package_path,
            v1_source_path,
            external_evidence_dir,
            fuzz_runs,
            skip_fuzz,
            only_checks,
        })
    }

    fn from_audit_pack(options: AuditPackOptions) -> Self {
        Self {
            profile: AssuranceProfile::Release,
            runtime: AssuranceRuntime::All,
            report_mode: AssuranceReportMode::Audit,
            out_dir: options.out_dir,
            backend: options.backend,
            device_label: options.device_label,
            device_model: options.device_model,
            v1_package_path: options.v1_package_path,
            v1_source_path: options.v1_source_path,
            external_evidence_dir: options.external_evidence_dir,
            fuzz_runs: options.fuzz_runs,
            skip_fuzz: options.skip_fuzz,
            only_checks: None,
        }
    }
}

impl AssuranceMergeOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut profile = AssuranceProfile::Pr;
        let mut runtime = AssuranceRuntime::All;
        let mut out_dir = None::<Utf8PathBuf>;
        let mut inputs = Vec::<Utf8PathBuf>::new();

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--profile" => {
                    profile = AssuranceProfile::parse(
                        &iter.next().context("--profile requires a value")?,
                    )?;
                }
                "--runtime" => {
                    runtime = AssuranceRuntime::parse(
                        &iter.next().context("--runtime requires a value")?,
                    )?;
                }
                "--out-dir" => {
                    out_dir = Some(Utf8PathBuf::from(
                        iter.next().context("--out-dir requires a value")?,
                    ));
                }
                "--inputs" => {
                    inputs.push(Utf8PathBuf::from(
                        iter.next().context("--inputs requires a value")?,
                    ));
                }
                other => bail!("unknown assurance-merge flag: {other}"),
            }
        }

        ensure!(
            !inputs.is_empty(),
            "assurance-merge requires at least one --inputs <path>"
        );

        Ok(Self {
            profile,
            runtime,
            out_dir: out_dir.context("assurance-merge requires --out-dir <path>")?,
            inputs,
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

fn read_required_json(path: &Utf8PathBuf) -> Result<Value> {
    let contents = read_required_text_file(path)?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse JSON from {}", path))
}

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
    for advisory_id in advisory_ids {
        let section_marker = format!("[metadata.{advisory_id}]");
        ensure!(
            contents.contains(&section_marker),
            "security/advisories.toml is missing metadata for {advisory_id}"
        );

        let section = advisory_metadata_section(contents, &section_marker)
            .with_context(|| format!("failed to read metadata section for {advisory_id}"))?;
        for required_key in ["owner", "review_date", "exit_condition"] {
            ensure!(
                section
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{required_key} ="))),
                "security/advisories.toml metadata for {advisory_id} must define `{required_key}`"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn evidence_path() -> Utf8PathBuf {
        Utf8PathBuf::from("mobile-smoke.json")
    }

    fn mobile_smoke_fixture(commit: &str) -> Value {
        mobile_smoke_fixture_with_identity(
            commit,
            "github-workflow",
            "mobile-smoke",
            "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
        )
    }

    fn mobile_smoke_fixture_with_identity(
        commit: &str,
        source: &str,
        workflow: &str,
        run_url: &str,
    ) -> Value {
        json!({
            "commit": commit,
            "source": source,
            "workflow": workflow,
            "run_url": run_url,
            "ios": "passed",
            "android": "passed",
            "surfaces": {
                "iosNative": "passed",
                "iosReactNative": "passed",
                "androidNative": "passed",
                "androidReactNative": "passed",
            }
        })
    }

    #[test]
    fn preserved_file_contents_restore_original_on_success() {
        let temp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().join("build-flags.ts")).unwrap();
        fs::write(&path, "original").unwrap();

        with_preserved_file_contents(&path, || {
            fs::write(&path, "modified").unwrap();
            Ok::<(), anyhow::Error>(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
    }

    #[test]
    fn preserved_file_contents_restore_original_on_error() {
        let temp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().join("build-flags.ts")).unwrap();
        fs::write(&path, "original").unwrap();

        let error = with_preserved_file_contents(&path, || {
            fs::write(&path, "modified").unwrap();
            Err::<(), anyhow::Error>(anyhow::anyhow!("expected failure"))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("expected failure"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
    }

    #[test]
    fn mobile_smoke_local_options_reject_partial_evidence_runs() {
        let workspace_root = workspace_root().unwrap();
        let options = MobileSmokeLocalOptions::parse(
            vec![
                "--platform".to_owned(),
                "ios".to_owned(),
                "--evidence-out-dir".to_owned(),
                "target/mobile-evidence".to_owned(),
            ],
            &workspace_root,
        )
        .unwrap();

        let error = options.validate().unwrap_err().to_string();

        assert!(error.contains("--evidence-out-dir"));
        assert!(error.contains("--platform all --surface all"));
    }

    #[test]
    fn mobile_smoke_local_options_allow_full_suite_evidence_runs() {
        let workspace_root = workspace_root().unwrap();
        let options = MobileSmokeLocalOptions::parse(
            vec![
                "--platform".to_owned(),
                "all".to_owned(),
                "--surface".to_owned(),
                "all".to_owned(),
                "--evidence-out-dir".to_owned(),
                "target/mobile-evidence".to_owned(),
            ],
            &workspace_root,
        )
        .unwrap();

        options.validate().unwrap();
        assert!(options.is_full_suite());
    }

    fn benchmark_fixture_metadata(file: &str) -> (&'static str, &'static str, &'static str) {
        match file {
            "rust-desktop-stable.json"
            | "node-desktop-stable.json"
            | "browser-desktop-stable.json" => {
                ("desktop", "reference-desktop", "desktop-reference")
            }
            "react-native-ios-stable.json" => ("ios", "reference-ios-device", "ios-reference"),
            "react-native-android-stable.json" => {
                ("android", "reference-android-device", "android-reference")
            }
            other => panic!("unexpected benchmark fixture file: {other}"),
        }
    }

    fn benchmark_report(commit: &str, file: &str) -> Value {
        let (device_label, device_model, device_class) = benchmark_fixture_metadata(file);
        json!({
            "generated_at_unix_seconds": 1,
            "git_commit": commit,
            "sdk_version": "0.1.0-alpha.0",
            "backend_name": "stable",
            "device_label": device_label,
            "device_model": device_model,
            "device_class": device_class,
            "cpu_model": "fixture-cpu",
            "os_name": "fixture-os",
            "os_version": "fixture-version",
            "rustc_version_verbose": "rustc 1.99.0",
            "cargo_version": "cargo 1.99.0",
            "benchmark_scenario_id": "withdraw-stable",
            "artifact_version": "fixture-artifacts",
            "zkey_sha256": "fixture-zkey",
            "manifest_sha256": "fixture-manifest",
            "artifact_bundle_sha256": "fixture-bundle",
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

    fn mobile_parity_fixture(commit: &str) -> Value {
        mobile_parity_fixture_with_identity(
            commit,
            "github-workflow",
            "mobile-smoke",
            "https://github.com/0xbow/privacy-pools-sdk-rs/actions/runs/123",
        )
    }

    fn mobile_parity_fixture_with_identity(
        commit: &str,
        source: &str,
        workflow: &str,
        run_url: &str,
    ) -> Value {
        json!({
            "commit": commit,
            "source": source,
            "workflow": workflow,
            "run_url": run_url,
            "totalChecks": 32,
            "passed": 32,
            "failed": 0,
            "ios": mobile_platform_rollup("ios"),
            "android": mobile_platform_rollup("android"),
        })
    }

    fn mobile_platform_rollup(platform: &str) -> Value {
        json!({
            "totalChecks": 16,
            "passed": 16,
            "failed": 0,
            "native": mobile_surface_report(platform, "native", "native"),
            "reactNative": mobile_surface_report(platform, "react-native-app", "react-native"),
        })
    }

    fn mobile_surface_report(platform: &str, runtime: &str, surface: &str) -> Value {
        json!({
            "generatedAt": "2026-01-01T00:00:00.000Z",
            "runtime": runtime,
            "platform": platform,
            "surface": surface,
            "smoke": {
                "backend": "arkworks",
                "commitmentVerified": true,
                "withdrawalVerified": true,
                "executionSubmitted": true,
                "signedManifestVerified": true,
                "wrongSignedManifestPublicKeyRejected": true,
                "tamperedSignedManifestArtifactsRejected": true,
                "tamperedProofRejected": true,
                "handleKindMismatchRejected": true,
                "staleVerifiedProofHandleRejected": true,
                "staleCommitmentSessionRejected": true,
                "staleWithdrawalSessionRejected": true,
                "wrongRootRejected": true,
                "wrongChainIdRejected": true,
                "wrongCodeHashRejected": true,
                "wrongSignerRejected": true,
            },
            "parity": {
                "totalChecks": 8,
                "passed": 8,
                "failed": 0,
                "failedChecks": [],
            },
            "benchmark": {
                "artifactResolutionMs": 1.0,
                "bundleVerificationMs": 1.0,
                "sessionPreloadMs": 1.0,
                "firstInputPreparationMs": 1.0,
                "firstWitnessGenerationMs": 1.0,
                "firstProofGenerationMs": 1.0,
                "firstVerificationMs": 1.0,
                "firstProveAndVerifyMs": 1.0,
                "iterations": 1,
                "warmup": 0,
                "peakResidentMemoryBytes": Value::Null,
                "samples": [
                    {
                        "inputPreparationMs": 1.0,
                        "witnessGenerationMs": 1.0,
                        "proofGenerationMs": 1.0,
                        "verificationMs": 1.0,
                        "proveAndVerifyMs": 1.0
                    }
                ]
            }
        })
    }

    fn browser_metric() -> Value {
        json!({
            "iterations": 1,
            "total": { "averageMs": 1.0, "minMs": 1.0, "maxMs": 1.0 },
            "slices": {
                "preloadMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "witnessParseMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "witnessTransferMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "witnessMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "proveMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "verifyMs": { "averageMs": 0.1, "minMs": 0.1, "maxMs": 0.1 },
                "totalMs": { "averageMs": 1.0, "minMs": 1.0, "maxMs": 1.0 }
            }
        })
    }

    fn browser_comparison_report() -> Value {
        json!({
            "generatedAt": "2026-01-01T00:00:00.000Z",
            "browserPerformance": {
                "commitment": {
                    "directCold": browser_metric(),
                    "directWarm": browser_metric(),
                    "workerCold": browser_metric(),
                    "workerWarm": browser_metric()
                },
                "withdrawal": {
                    "directCold": browser_metric(),
                    "directWarm": browser_metric(),
                    "workerCold": browser_metric(),
                    "workerWarm": browser_metric()
                }
            }
        })
    }

    fn write_json(path: &Utf8PathBuf, value: &Value) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    fn write_signed_manifest_fixture(dir: &Utf8PathBuf) -> String {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let artifact_bytes = b"signed manifest fixture artifact";
        let artifact_sha256 = hex::encode(Sha256::digest(artifact_bytes));
        let payload = json!({
            "manifest": {
                "version": "signed-fixture",
                "artifacts": [
                    {
                        "circuit": "withdraw",
                        "kind": "wasm",
                        "filename": "withdraw-fixture.wasm",
                        "sha256": artifact_sha256
                    }
                ]
            },
            "metadata": {
                "ceremony": "fixture ceremony",
                "build": "fixture build",
                "repository": "https://github.com/0xbow/privacy-pools-sdk-rs",
                "commit": "abcdef0"
            }
        });
        let payload_json = serde_json::to_vec_pretty(&payload).unwrap();
        let signature = signing_key.sign(&payload_json);
        let artifact_root = dir.join("signed-artifact-manifest-artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        fs::write(
            dir.join("signed-artifact-manifest.payload.json"),
            &payload_json,
        )
        .unwrap();
        fs::write(
            dir.join("signed-artifact-manifest.signature"),
            hex::encode(signature.to_bytes()),
        )
        .unwrap();
        fs::write(artifact_root.join("withdraw-fixture.wasm"), artifact_bytes).unwrap();

        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn write_external_signed_manifest_fixture(dir: &Utf8PathBuf) -> String {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let fixture_dir = dir.join("signed-manifest");
        let artifact_root = fixture_dir.join("artifacts");
        let artifact_bytes = b"signed manifest fixture artifact";
        let artifact_sha256 = hex::encode(Sha256::digest(artifact_bytes));
        let payload = json!({
            "manifest": {
                "version": "signed-fixture",
                "artifacts": [
                    {
                        "circuit": "withdraw",
                        "kind": "wasm",
                        "filename": "withdraw-fixture.wasm",
                        "sha256": artifact_sha256
                    }
                ]
            },
            "metadata": {
                "ceremony": "fixture ceremony",
                "build": "fixture build",
                "repository": "https://github.com/0xbow/privacy-pools-sdk-rs",
                "commit": "abcdef0"
            }
        });
        let payload_json = serde_json::to_vec_pretty(&payload).unwrap();
        let signature = signing_key.sign(&payload_json);
        fs::create_dir_all(&artifact_root).unwrap();
        fs::write(fixture_dir.join("payload.json"), &payload_json).unwrap();
        fs::write(
            fixture_dir.join("signature"),
            hex::encode(signature.to_bytes()),
        )
        .unwrap();
        fs::write(artifact_root.join("withdraw-fixture.wasm"), artifact_bytes).unwrap();
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn write_sdk_web_package_fixture(
        root: &Utf8PathBuf,
        package_dir: &Utf8PathBuf,
    ) -> (Utf8PathBuf, Utf8PathBuf) {
        let sdk_dir = package_dir.join("sdk");
        fs::create_dir_all(&sdk_dir).unwrap();

        let browser_wasm_bytes = b"browser wasm fixture";
        let external_wasm_path = sdk_dir.join("privacy_pools_sdk_web_bg.wasm");
        fs::write(&external_wasm_path, browser_wasm_bytes).unwrap();

        let package_fixture_root = root.join("sdk-package-fixture");
        let generated_root = package_fixture_root.join("package/src/browser/generated");
        fs::create_dir_all(&generated_root).unwrap();
        fs::create_dir_all(package_fixture_root.join("package")).unwrap();
        fs::write(
            generated_root.join("privacy_pools_sdk_web_bg.wasm"),
            browser_wasm_bytes,
        )
        .unwrap();
        fs::write(
            package_fixture_root.join("package/package.json"),
            r#"{"name":"@0xmatthewb/privacy-pools-sdk","version":"0.1.0-alpha.1"}"#,
        )
        .unwrap();

        let tarball_path = sdk_dir.join("privacy-pools-sdk-alpha.tgz");
        let status = Command::new("tar")
            .args([
                "-C",
                package_fixture_root.as_str(),
                "-czf",
                tarball_path.as_str(),
                "package",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        (tarball_path, external_wasm_path)
    }

    fn write_react_native_package_fixture(package_dir: &Utf8PathBuf) -> Utf8PathBuf {
        let react_native_dir = package_dir.join("react-native");
        fs::create_dir_all(&react_native_dir).unwrap();
        let package_path = react_native_dir.join("privacy-pools-sdk-react-native-alpha.tgz");
        fs::write(&package_path, b"react native package fixture").unwrap();
        package_path
    }

    fn attestation_verification_fixture(subject_path: &str, sha256: &str, repo: &str) -> Value {
        json!({
            "verified": true,
            "verifiedAt": "2026-04-17T00:00:00Z",
            "repo": repo,
            "signerWorkflow": format!("{repo}/.github/workflows/release.yml"),
            "subjectPath": subject_path,
            "subjectSha256": sha256,
            "attestedSubjectName": Utf8PathBuf::from(subject_path).file_name().unwrap_or(subject_path),
            "attestedSubjectBasename": Utf8PathBuf::from(subject_path).file_name().unwrap_or(subject_path),
            "predicateType": "https://slsa.dev/provenance/v1",
            "verificationCount": 1
        })
    }

    fn attestation_record_fixture(
        attestation_root: &Utf8PathBuf,
        subject_path: &str,
        sha256: &str,
        attestation_url: &str,
        workflow_run_url: &str,
        repo: &str,
    ) -> Value {
        let verification_relative = format!(
            "attestation-verification/{}.verified.json",
            subject_path.replace('/', "__")
        );
        write_json(
            &attestation_root.join(&verification_relative),
            &attestation_verification_fixture(subject_path, sha256, repo),
        );
        json!({
            "subjectPath": subject_path,
            "sha256": sha256,
            "attestationUrl": attestation_url,
            "workflowRunUrl": workflow_run_url,
            "verificationPath": verification_relative,
        })
    }

    fn read_attestation_records(path: &Utf8PathBuf) -> Vec<AttestationRecord> {
        serde_json::from_value(read_required_json(path).unwrap()).unwrap()
    }

    fn overwrite_attestation_verification(
        attestation_root: &Utf8PathBuf,
        record: &AttestationRecord,
        value: &Value,
    ) {
        write_json(&attestation_root.join(&record.verification_path), value);
    }

    fn write_external_evidence_fixture(dir: &Utf8PathBuf, commit: &str) -> String {
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(commit),
        );
        write_json(
            &dir.join("mobile-parity.json"),
            &mobile_parity_fixture(commit),
        );
        let public_key = write_external_signed_manifest_fixture(dir);

        let sbom_dir = dir.join("sbom");
        fs::create_dir_all(&sbom_dir).unwrap();
        write_json(
            &sbom_dir.join("rust.cdx.json"),
            &json!({ "bomFormat": "CycloneDX" }),
        );
        write_json(
            &sbom_dir.join("sdk.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );
        write_json(
            &sbom_dir.join("react-native.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );

        let benchmark_dir = dir.join("benchmarks");
        fs::create_dir_all(&benchmark_dir).unwrap();
        for file in [
            "rust-desktop-stable.json",
            "node-desktop-stable.json",
            "browser-desktop-stable.json",
            "react-native-ios-stable.json",
            "react-native-android-stable.json",
        ] {
            write_json(&benchmark_dir.join(file), &benchmark_report(commit, file));
        }

        let package_dir = dir.join("packages");
        fs::create_dir_all(&package_dir).unwrap();
        let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(dir, &package_dir);
        let react_native_package_path = write_react_native_package_fixture(&package_dir);
        let circuits_dir = package_dir.join("circuits");
        fs::create_dir_all(&circuits_dir).unwrap();
        let circuit_archive = circuits_dir.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
        let circuit_fixture_root = dir.join("circuit-fixture");
        let archive_artifacts_root = circuit_fixture_root.join("artifacts");
        fs::create_dir_all(&archive_artifacts_root).unwrap();
        fs::create_dir_all(archive_artifacts_root.join("signed-manifest")).unwrap();
        stage_directory(
            &dir.join("signed-manifest"),
            &archive_artifacts_root.join("signed-manifest"),
        )
        .unwrap();
        fs::write(
            archive_artifacts_root.join("withdraw-fixture.wasm"),
            b"signed manifest fixture artifact",
        )
        .unwrap();
        let status = Command::new("tar")
            .args([
                "-C",
                circuit_fixture_root.as_str(),
                "-czf",
                circuit_archive.as_str(),
                "artifacts",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let sdk_sha256 = sha256_hex(&fs::read(&sdk_package_path).unwrap());
        let sdk_wasm_sha256 = sha256_hex(&fs::read(&sdk_wasm_path).unwrap());
        let react_native_sha256 = sha256_hex(&fs::read(&react_native_package_path).unwrap());
        let circuit_sha256 = sha256_hex(&fs::read(&circuit_archive).unwrap());
        let repo = current_github_repository_slug(&workspace_root().unwrap()).unwrap();

        write_json(
            &dir.join("attestations.json"),
            &json!([
                attestation_record_fixture(
                    dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sdk_sha256,
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sdk_wasm_sha256,
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &react_native_sha256,
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &circuit_sha256,
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        public_key
    }

    fn write_release_assembly_inputs(
        root: &Utf8PathBuf,
        commit: &str,
    ) -> (
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
    ) {
        write_release_assembly_inputs_with_mobile_fixtures(
            root,
            &mobile_smoke_fixture(commit),
            &mobile_parity_fixture(commit),
        )
    }

    fn write_release_assembly_inputs_with_mobile_fixtures(
        root: &Utf8PathBuf,
        mobile_smoke: &Value,
        mobile_parity: &Value,
    ) -> (
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
        Utf8PathBuf,
    ) {
        let workspace_root = workspace_root().unwrap();
        let mobile_dir = root.join("mobile");
        fs::create_dir_all(&mobile_dir).unwrap();
        let commit = mobile_smoke["commit"].as_str().unwrap();
        write_json(&mobile_dir.join("mobile-smoke.json"), mobile_smoke);
        write_json(&mobile_dir.join("mobile-parity.json"), mobile_parity);

        let reference_dir = root.join("reference");
        let benchmark_dir = reference_dir.join("benchmarks");
        fs::create_dir_all(&benchmark_dir).unwrap();
        for file in [
            "rust-desktop-stable.json",
            "node-desktop-stable.json",
            "browser-desktop-stable.json",
            "react-native-ios-stable.json",
            "react-native-android-stable.json",
        ] {
            write_json(&benchmark_dir.join(file), &benchmark_report(commit, file));
        }

        let sbom_dir = root.join("sbom-inputs");
        let sbom_root = sbom_dir.join("sbom");
        fs::create_dir_all(&sbom_root).unwrap();
        write_json(
            &sbom_root.join("rust.cdx.json"),
            &json!({ "bomFormat": "CycloneDX" }),
        );
        write_json(
            &sbom_root.join("sdk.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );
        write_json(
            &sbom_root.join("react-native.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );

        let packages_dir = root.join("package-inputs");
        let package_root = packages_dir.join("packages");
        fs::create_dir_all(&package_root).unwrap();
        let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(root, &package_root);
        let react_native_package_path = write_react_native_package_fixture(&package_root);
        let circuits_root = package_root.join("circuits");
        fs::create_dir_all(&circuits_root).unwrap();
        let circuit_archive =
            circuits_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
        let status = Command::new("tar")
            .args([
                "-C",
                workspace_root.join("fixtures").as_str(),
                "-czf",
                circuit_archive.as_str(),
                "artifacts",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let sdk_sha256 = sha256_hex(&fs::read(&sdk_package_path).unwrap());
        let sdk_wasm_sha256 = sha256_hex(&fs::read(&sdk_wasm_path).unwrap());
        let react_native_sha256 = sha256_hex(&fs::read(&react_native_package_path).unwrap());
        let circuit_sha256 = sha256_hex(&fs::read(&circuit_archive).unwrap());
        let repo = current_github_repository_slug(&workspace_root).unwrap();

        let attestation_dir = root.join("attestation-inputs");
        fs::create_dir_all(&attestation_dir).unwrap();
        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sdk_sha256,
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sdk_wasm_sha256,
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &react_native_sha256,
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &circuit_sha256,
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        (
            mobile_dir,
            reference_dir,
            sbom_dir,
            packages_dir,
            attestation_dir,
        )
    }

    fn selected_assurance_specs(
        workspace_root: &Utf8PathBuf,
        options: &AssuranceOptions,
    ) -> Vec<AssuranceCheckSpec> {
        assurance_selected_specs(workspace_root, options).unwrap()
    }

    fn write_assurance_merge_fixture(
        dir: &Utf8PathBuf,
        commit: &str,
        check_ids: &[&str],
    ) -> Utf8PathBuf {
        fs::create_dir_all(dir).unwrap();
        let log_root = dir.join("logs");
        let checks_root = dir.join("checks");
        fs::create_dir_all(&log_root).unwrap();
        fs::create_dir_all(&checks_root).unwrap();

        let checks = check_ids
            .iter()
            .map(|id| {
                let log_path = log_root.join(format!("{id}.log"));
                let report_path = checks_root.join(format!("{id}.json"));
                fs::write(&log_path, format!("{id} ok\n")).unwrap();
                json!({
                    "id": id,
                    "label": id,
                    "runtime": ["rust"],
                    "allowedProfiles": ["pr"],
                    "dependsOn": [],
                    "blockedBy": [],
                    "scenarioTags": [],
                    "riskClass": "correctness",
                    "mode": "normative",
                    "normative": true,
                    "status": "passed",
                    "durationMs": 1,
                    "rationale": "fixture",
                    "inputs": [],
                    "command": "fixture",
                    "logPath": log_path.as_str(),
                    "reportPath": report_path.as_str(),
                    "error": Value::Null,
                    "expectedOutputs": [],
                    "thresholds": Value::Null,
                })
            })
            .collect::<Vec<_>>();

        write_json(
            &dir.join("environment.json"),
            &json!({
                "gitCommit": commit,
                "profile": "pr",
                "runtime": "rust",
                "status": "passed",
            }),
        );
        write_json(
            &dir.join("assurance-index.json"),
            &json!({
                "gitCommit": commit,
                "checks": checks,
            }),
        );
        dir.clone()
    }

    fn write_assurance_merge_fixture_with_original_root(
        dir: &Utf8PathBuf,
        original_root: &Utf8PathBuf,
        commit: &str,
        check_ids: &[&str],
    ) -> Utf8PathBuf {
        fs::create_dir_all(dir).unwrap();
        let log_root = dir.join("logs");
        let checks_root = dir.join("checks");
        fs::create_dir_all(&log_root).unwrap();
        fs::create_dir_all(&checks_root).unwrap();

        let checks = check_ids
            .iter()
            .map(|id| {
                let staged_log_path = log_root.join(format!("{id}.log"));
                fs::write(&staged_log_path, format!("{id} ok\n")).unwrap();
                json!({
                    "id": id,
                    "label": id,
                    "runtime": ["rust"],
                    "allowedProfiles": ["pr"],
                    "dependsOn": [],
                    "blockedBy": [],
                    "scenarioTags": [],
                    "riskClass": "correctness",
                    "mode": "normative",
                    "normative": true,
                    "status": "passed",
                    "durationMs": 1,
                    "rationale": "fixture",
                    "inputs": [],
                    "command": "fixture",
                    "logPath": original_root.join("logs").join(format!("{id}.log")).as_str(),
                    "reportPath": original_root
                        .join("checks")
                        .join(format!("{id}.json"))
                        .as_str(),
                    "error": Value::Null,
                    "expectedOutputs": [original_root.join("outputs").join(format!("{id}.txt")).as_str()],
                    "thresholds": Value::Null,
                })
            })
            .collect::<Vec<_>>();

        write_json(
            &dir.join("environment.json"),
            &json!({
                "gitCommit": commit,
                "profile": "pr",
                "runtime": "rust",
                "status": "passed",
            }),
        );
        write_json(
            &dir.join("assurance-index.json"),
            &json!({
                "gitCommit": commit,
                "checks": checks,
                "reports": {
                    "environment": original_root.join("environment.json").as_str(),
                },
            }),
        );
        dir.clone()
    }

    #[test]
    fn log_tail_for_error_limits_output_to_requested_lines() {
        let log = "one\ntwo\nthree\nfour";
        let tail = log_tail_for_error(log, 2);

        assert!(tail.contains("three\nfour"));
        assert!(!tail.contains("one"));
        assert!(!tail.contains("two"));
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
        assert!(commands.iter().any(|command| {
            command.args.contains(&"privacy-pools-sdk-signer")
                && command.args.contains(&"local-mnemonic")
                && !command.args.contains(&"dangerous-key-export")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"privacy-pools-sdk-signer")
                && command.args.contains(&"dangerous-key-export")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"privacy-pools-sdk-chain")
                && command.args.contains(&"local-signer-client")
        }));
        assert!(commands.iter().any(|command| {
            command.args.contains(&"privacy-pools-sdk-ffi")
                && command.args.contains(&"--no-default-features")
        }));
    }

    #[test]
    fn assurance_runtime_filter_keeps_shared_checks_on_rust_only() {
        assert!(runtime_selected(
            AssuranceRuntime::Rust,
            &[AssuranceRuntime::Shared]
        ));
        assert!(!runtime_selected(
            AssuranceRuntime::Browser,
            &[AssuranceRuntime::Shared]
        ));
        assert!(runtime_selected(
            AssuranceRuntime::Browser,
            &[AssuranceRuntime::Browser]
        ));
        assert!(runtime_selected(
            AssuranceRuntime::All,
            &[AssuranceRuntime::ReactNative]
        ));
    }

    #[test]
    fn audit_pack_alias_maps_to_release_audit_mode() {
        let options = AssuranceOptions::from_audit_pack(AuditPackOptions {
            out_dir: Utf8PathBuf::from("dist/audit-pack"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: Utf8PathBuf::from("/tmp/v1-package"),
            v1_source_path: Utf8PathBuf::from("/tmp/v1-source"),
            external_evidence_dir: Some(Utf8PathBuf::from("/tmp/external-evidence")),
            fuzz_runs: 12,
            skip_fuzz: true,
        });

        assert_eq!(options.profile, AssuranceProfile::Release);
        assert_eq!(options.runtime, AssuranceRuntime::All);
        assert_eq!(options.report_mode, AssuranceReportMode::Audit);
        assert_eq!(
            options.external_evidence_dir,
            Some(Utf8PathBuf::from("/tmp/external-evidence"))
        );
        assert_eq!(options.fuzz_runs, 12);
        assert!(options.skip_fuzz);
    }

    #[test]
    fn assurance_parse_preserves_explicit_out_dir_after_profile_flag() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions::parse(
            vec![
                "--out-dir".to_owned(),
                "/tmp/custom-assurance".to_owned(),
                "--profile".to_owned(),
                "release".to_owned(),
            ],
            &workspace_root,
        )
        .unwrap();

        assert_eq!(options.profile, AssuranceProfile::Release);
        assert_eq!(options.out_dir, Utf8PathBuf::from("/tmp/custom-assurance"));
    }

    #[test]
    fn assurance_parse_supports_only_checks_flag() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions::parse(
            vec![
                "--only-checks".to_owned(),
                "rust-fmt,rust-clippy".to_owned(),
            ],
            &workspace_root,
        )
        .unwrap();

        assert_eq!(
            options.only_checks,
            Some(vec!["rust-fmt".to_owned(), "rust-clippy".to_owned()])
        );
    }

    #[test]
    fn assurance_selected_specs_rejects_unknown_requested_check() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: Some(vec!["definitely-missing-check".to_owned()]),
        };

        let error = assurance_selected_specs(&workspace_root, &options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown assurance check id"));
    }

    #[test]
    fn assurance_selected_specs_include_transitive_dependencies() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::ReactNative,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: Some(vec!["bindings-drift-check".to_owned()]),
        };

        let selected_specs = selected_assurance_specs(&workspace_root, &options);
        let ids = selected_specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            ids,
            BTreeSet::from(["bindings-generate", "bindings-drift-check"])
        );
    }

    #[test]
    fn rust_pr_profile_uses_policy_checks_without_vet_or_advisories() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Rust,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };

        let selected_specs = selected_assurance_specs(&workspace_root, &options);
        let ids = selected_specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(ids.contains("cargo-deny-policy"));
        assert!(!ids.contains("cargo-deny-advisories"));
        assert!(!ids.contains("cargo-vet"));
    }

    #[test]
    fn fuzz_checks_are_nightly_only() {
        let workspace_root = workspace_root().unwrap();
        let nightly = AssuranceOptions {
            profile: AssuranceProfile::Nightly,
            runtime: AssuranceRuntime::Rust,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: false,
            only_checks: None,
        };
        let release = AssuranceOptions {
            profile: AssuranceProfile::Release,
            external_evidence_dir: Some(workspace_root.join("target/test-release-evidence")),
            ..nightly.clone()
        };

        let nightly_specs = selected_assurance_specs(&workspace_root, &nightly);
        let nightly_ids = nightly_specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<BTreeSet<_>>();
        let release_specs = selected_assurance_specs(&workspace_root, &release);
        let release_ids = release_specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<BTreeSet<_>>();

        assert!(nightly_ids.iter().any(|id| id.starts_with("fuzz-")));
        assert!(!release_ids.iter().any(|id| id.starts_with("fuzz-")));
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
    fn mobile_smoke_evidence_accepts_local_xtask_identity() {
        let commit = "abcdef0";
        let evidence = mobile_smoke_fixture_with_identity(
            commit,
            "local-xtask",
            "mobile-smoke-local",
            "local://mobile-smoke-local",
        );

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
            "source": "github-workflow",
            "workflow": "mobile-smoke",
            "ios": "passed",
            "android": "passed",
            "surfaces": {
                "iosNative": "passed",
                "iosReactNative": "passed",
                "androidNative": "passed",
                "androidReactNative": "passed",
            }
        });

        let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("run_url"));
    }

    #[test]
    fn mobile_smoke_evidence_rejects_malformed_source_workflow_pair() {
        let commit = "abcdef0";
        let evidence = mobile_smoke_fixture_with_identity(
            commit,
            "local-xtask",
            "mobile-smoke",
            "local://mobile-smoke-local",
        );

        let error = validate_mobile_smoke_evidence_value(&evidence, &evidence_path(), commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("workflow mismatch for local mobile evidence"));
    }

    #[test]
    fn mobile_parity_evidence_accepts_valid_fixture() {
        let commit = "abcdef0";
        let evidence = mobile_parity_fixture(commit);

        let summary =
            validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit).unwrap();

        assert_eq!(summary["passed"], 32);
        assert_eq!(summary["failed"], 0);
    }

    #[test]
    fn mobile_parity_evidence_accepts_local_xtask_identity() {
        let commit = "abcdef0";
        let evidence = mobile_parity_fixture_with_identity(
            commit,
            "local-xtask",
            "mobile-smoke-local",
            "local://mobile-smoke-local",
        );

        let summary =
            validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit).unwrap();

        assert_eq!(summary["passed"], 32);
        assert_eq!(summary["failed"], 0);
    }

    #[test]
    fn mobile_parity_evidence_rejects_commit_mismatch() {
        let evidence = mobile_parity_fixture("abcdef0");

        let error = validate_mobile_parity_evidence_value(&evidence, &evidence_path(), "1234567")
            .unwrap_err()
            .to_string();

        assert!(error.contains("commit mismatch"));
    }

    #[test]
    fn mobile_parity_evidence_rejects_missing_samples() {
        let commit = "abcdef0";
        let mut evidence = mobile_parity_fixture(commit);
        evidence["ios"]["native"]["benchmark"]["samples"] = json!([]);

        let error = validate_mobile_parity_evidence_value(&evidence, &evidence_path(), commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("benchmark.samples"));
    }

    #[test]
    fn browser_comparison_report_requires_all_timing_slices() {
        let temp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().join("v1-npm-comparison.json")).unwrap();
        let mut report = browser_comparison_report();
        report["browserPerformance"]["withdrawal"]["directCold"]["slices"]
            .as_object_mut()
            .unwrap()
            .remove("witnessTransferMs");
        write_json(&path, &report);

        let error = validate_browser_comparison_report(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("witnessTransferMs"));
    }

    #[test]
    fn signed_manifest_evidence_accepts_valid_fixture() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let public_key = write_signed_manifest_fixture(&dir);

        let verified = validate_signed_manifest_evidence(&dir, Some(&public_key))
            .unwrap()
            .unwrap();

        assert_eq!(verified, ("signed-fixture".to_owned(), 1));
    }

    #[test]
    fn signed_manifest_evidence_rejects_missing_public_key() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        write_signed_manifest_fixture(&dir);

        let error = validate_signed_manifest_evidence(&dir, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed-manifest-public-key"));
    }

    #[test]
    fn signed_manifest_evidence_rejects_wrong_public_key() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        write_signed_manifest_fixture(&dir);
        let wrong_key = hex::encode(
            SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
        );

        let error = validate_signed_manifest_evidence(&dir, Some(&wrong_key))
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed artifact manifest validation failed"));
    }

    #[test]
    fn signed_manifest_evidence_rejects_bad_signature() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let public_key = write_signed_manifest_fixture(&dir);
        fs::write(
            dir.join("signed-artifact-manifest.signature"),
            "00".repeat(64),
        )
        .unwrap();

        let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed artifact manifest validation failed"));
    }

    #[test]
    fn signed_manifest_evidence_rejects_modified_payload() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let public_key = write_signed_manifest_fixture(&dir);
        let mut payload =
            fs::read_to_string(dir.join("signed-artifact-manifest.payload.json")).unwrap();
        payload.push('\n');
        fs::write(dir.join("signed-artifact-manifest.payload.json"), payload).unwrap();

        let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed artifact manifest validation failed"));
    }

    #[test]
    fn signed_manifest_evidence_rejects_missing_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let public_key = write_signed_manifest_fixture(&dir);
        fs::remove_file(
            dir.join("signed-artifact-manifest-artifacts")
                .join("withdraw-fixture.wasm"),
        )
        .unwrap();

        let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed artifact manifest validation failed"));
    }

    #[test]
    fn signed_manifest_evidence_rejects_hash_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let public_key = write_signed_manifest_fixture(&dir);
        fs::write(
            dir.join("signed-artifact-manifest-artifacts")
                .join("withdraw-fixture.wasm"),
            b"tampered",
        )
        .unwrap();

        let error = validate_signed_manifest_evidence(&dir, Some(&public_key))
            .unwrap_err()
            .to_string();

        assert!(error.contains("signed artifact manifest validation failed"));
    }

    #[test]
    fn evidence_check_accepts_complete_same_commit_alpha_fixture() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = "abcdef0";
        let public_key = write_external_evidence_fixture(&dir, commit);

        evidence_check(vec![
            "--channel".to_owned(),
            "alpha".to_owned(),
            "--dir".to_owned(),
            dir.to_string(),
            "--signed-manifest-public-key".to_owned(),
            public_key,
        ])
        .unwrap();
    }

    #[test]
    fn scenario_coverage_requires_mobile_evidence_for_react_native_nightly() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Nightly,
            runtime: AssuranceRuntime::ReactNative,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };
        let selected_specs = selected_assurance_specs(&workspace_root, &options);

        let error = validate_scenario_coverage(&workspace_root, &options, &selected_specs)
            .unwrap_err()
            .to_string();

        assert!(error.contains("wrong-root-rejection"));
    }

    #[test]
    fn scenario_coverage_accepts_react_native_nightly_with_external_evidence() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let evidence_dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &evidence_dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &evidence_dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );
        let options = AssuranceOptions {
            profile: AssuranceProfile::Nightly,
            runtime: AssuranceRuntime::ReactNative,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: Some(evidence_dir),
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };
        let selected_specs = selected_assurance_specs(&workspace_root, &options);

        validate_scenario_coverage(&workspace_root, &options, &selected_specs).unwrap();
    }

    #[test]
    fn nightly_assessment_defaults_mobile_and_reference_to_not_run_and_missing() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Nightly,
            runtime: AssuranceRuntime::All,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };

        let assessment = assurance_assessment(&options, &[], None);

        assert_eq!(assessment["mobileAppEvidence"], "not-run");
        assert_eq!(assessment["referencePerformance"], "missing");
    }

    #[test]
    fn scenario_coverage_rejects_proxy_only_checks() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Node,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };
        let mut selected_specs = selected_assurance_specs(&workspace_root, &options);

        for spec in &mut selected_specs {
            match spec.id.as_str() {
                "sdk-node-smoke" => {
                    spec.scenario_tags
                        .push("manifest-artifact-tamper-rejection".to_owned());
                }
                "sdk-node-fail-closed-checks" => {
                    spec.scenario_tags
                        .retain(|tag| tag != "manifest-artifact-tamper-rejection");
                }
                _ => {}
            }
        }

        let error = validate_scenario_coverage(&workspace_root, &options, &selected_specs)
            .unwrap_err()
            .to_string();

        assert!(error.contains("relies only on proxy checks"));
        assert!(error.contains("sdk-node-smoke"));
    }

    #[test]
    fn pr_browser_profile_skips_v1_npm_smoke_compare() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Browser,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };

        let selected_specs = selected_assurance_specs(&workspace_root, &options);

        assert!(
            !selected_specs
                .iter()
                .any(|spec| spec.id == "compare-v1-npm-smoke"),
            "pr browser profile should not include compare-v1-npm-smoke"
        );
        for required in [
            "sdk-browser-build",
            "sdk-browser-smoke",
            "sdk-browser-generated-drift-check",
            "sdk-browser-fail-closed-checks",
        ] {
            assert!(
                selected_specs.iter().any(|spec| spec.id == required),
                "pr browser profile should include {required}"
            );
        }
        for excluded in [
            "sdk-browser-core",
            "sdk-browser-direct-execution",
            "sdk-browser-worker-suite",
            "browser-threaded-build",
            "browser-threaded-drift-check",
        ] {
            assert!(
                !selected_specs.iter().any(|spec| spec.id == excluded),
                "pr browser profile should exclude {excluded}"
            );
        }
    }

    #[test]
    fn nightly_external_evidence_reports_missing_reference_benchmarks() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );

        let evidence = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Nightly,
            BenchmarkBackendProfile::Stable,
            &commit,
            None,
        )
        .unwrap();

        assert_eq!(evidence["referencePerformance"]["status"], "missing");
    }

    #[test]
    fn nightly_external_evidence_reports_stale_reference_benchmarks() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );
        let benchmark_dir = dir.join("benchmarks");
        fs::create_dir_all(&benchmark_dir).unwrap();
        for file in [
            "rust-desktop-stable.json",
            "node-desktop-stable.json",
            "browser-desktop-stable.json",
            "react-native-ios-stable.json",
            "react-native-android-stable.json",
        ] {
            write_json(
                &benchmark_dir.join(file),
                &benchmark_report("1234567", file),
            );
        }

        let evidence = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Nightly,
            BenchmarkBackendProfile::Stable,
            &commit,
            None,
        )
        .unwrap();

        assert_eq!(evidence["referencePerformance"]["status"], "stale");
        assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 5);
    }

    #[test]
    fn nightly_external_evidence_reports_missing_for_incomplete_reference_benchmarks() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );
        let benchmark_dir = dir.join("benchmarks");
        fs::create_dir_all(&benchmark_dir).unwrap();
        write_json(
            &benchmark_dir.join("rust-desktop-stable.json"),
            &benchmark_report(&commit, "rust-desktop-stable.json"),
        );

        let evidence = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Nightly,
            BenchmarkBackendProfile::Stable,
            &commit,
            None,
        )
        .unwrap();

        assert_eq!(evidence["referencePerformance"]["status"], "missing");
        assert!(
            evidence["referencePerformance"]["error"]
                .as_str()
                .is_some_and(|value| value.contains("incomplete"))
        );
    }

    #[test]
    fn nightly_external_evidence_reports_fresh_reference_benchmarks() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );
        let benchmark_dir = dir.join("benchmarks");
        fs::create_dir_all(&benchmark_dir).unwrap();
        for file in [
            "rust-desktop-stable.json",
            "node-desktop-stable.json",
            "browser-desktop-stable.json",
            "react-native-ios-stable.json",
            "react-native-android-stable.json",
        ] {
            write_json(&benchmark_dir.join(file), &benchmark_report(&commit, file));
        }

        let evidence = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Nightly,
            BenchmarkBackendProfile::Stable,
            &commit,
            None,
        )
        .unwrap();

        assert_eq!(evidence["referencePerformance"]["status"], "fresh");
        assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 5);
    }

    #[test]
    fn release_external_evidence_assembly_allows_missing_reference_benchmarks() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let mobile_dir = root.join("mobile");
        fs::create_dir_all(&mobile_dir).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        write_json(
            &mobile_dir.join("mobile-smoke.json"),
            &mobile_smoke_fixture(&commit),
        );
        write_json(
            &mobile_dir.join("mobile-parity.json"),
            &mobile_parity_fixture(&commit),
        );
        let sbom_dir = root.join("sbom-inputs");
        let sbom_root = sbom_dir.join("sbom");
        fs::create_dir_all(&sbom_root).unwrap();
        write_json(
            &sbom_root.join("rust.cdx.json"),
            &json!({ "bomFormat": "CycloneDX" }),
        );
        write_json(
            &sbom_root.join("sdk.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );
        write_json(
            &sbom_root.join("react-native.spdx.json"),
            &json!({ "spdxVersion": "SPDX-2.3" }),
        );
        let packages_dir = root.join("package-inputs");
        let package_root = packages_dir.join("packages");
        fs::create_dir_all(&package_root).unwrap();
        let (sdk_package_path, sdk_wasm_path) = write_sdk_web_package_fixture(&root, &package_root);
        let react_native_package_path = write_react_native_package_fixture(&package_root);
        let circuits_root = package_root.join("circuits");
        fs::create_dir_all(&circuits_root).unwrap();
        let circuit_archive =
            circuits_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
        let status = Command::new("tar")
            .args([
                "-C",
                workspace_root.join("fixtures").as_str(),
                "-czf",
                circuit_archive.as_str(),
                "artifacts",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let attestation_dir = root.join("attestation-inputs");
        fs::create_dir_all(&attestation_dir).unwrap();
        let repo = current_github_repository_slug(&workspace_root).unwrap();
        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sha256_hex(&fs::read(&sdk_package_path).unwrap()),
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sha256_hex(&fs::read(&sdk_wasm_path).unwrap()),
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &sha256_hex(&fs::read(&react_native_package_path).unwrap()),
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &sha256_hex(&fs::read(&circuit_archive).unwrap()),
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );
        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: None,
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };

        let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        assert_eq!(manifest["referencePerformance"]["status"], "missing");
    }

    #[test]
    fn release_external_evidence_assembly_requires_remaining_inputs() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);

        let cases = [
            (
                "--mobile-evidence-dir",
                ExternalEvidenceAssembleOptions {
                    mode: ExternalEvidenceMode::Release,
                    out_dir: root.join("assembled-missing-mobile"),
                    mobile_evidence_dir: None,
                    reference_benchmarks_dir: Some(reference_dir.clone()),
                    sbom_dir: Some(sbom_dir.clone()),
                    packages_dir: Some(packages_dir.clone()),
                    attestation_metadata_dir: Some(attestation_dir.clone()),
                },
            ),
            (
                "--sbom-dir",
                ExternalEvidenceAssembleOptions {
                    mode: ExternalEvidenceMode::Release,
                    out_dir: root.join("assembled-missing-sbom"),
                    mobile_evidence_dir: Some(mobile_dir.clone()),
                    reference_benchmarks_dir: Some(reference_dir.clone()),
                    sbom_dir: None,
                    packages_dir: Some(packages_dir.clone()),
                    attestation_metadata_dir: Some(attestation_dir.clone()),
                },
            ),
            (
                "--packages-dir",
                ExternalEvidenceAssembleOptions {
                    mode: ExternalEvidenceMode::Release,
                    out_dir: root.join("assembled-missing-packages"),
                    mobile_evidence_dir: Some(mobile_dir.clone()),
                    reference_benchmarks_dir: Some(reference_dir.clone()),
                    sbom_dir: Some(sbom_dir.clone()),
                    packages_dir: None,
                    attestation_metadata_dir: Some(attestation_dir.clone()),
                },
            ),
            (
                "--attestation-metadata-dir",
                ExternalEvidenceAssembleOptions {
                    mode: ExternalEvidenceMode::Release,
                    out_dir: root.join("assembled-missing-attestations"),
                    mobile_evidence_dir: Some(mobile_dir.clone()),
                    reference_benchmarks_dir: Some(reference_dir.clone()),
                    sbom_dir: Some(sbom_dir.clone()),
                    packages_dir: Some(packages_dir.clone()),
                    attestation_metadata_dir: None,
                },
            ),
        ];

        for (expected_flag, options) in cases {
            let error = assemble_external_evidence_dir(&workspace_root, &options, &commit)
                .unwrap_err()
                .to_string();

            assert!(error.contains(expected_flag), "{error}");
        }
    }

    #[test]
    fn release_external_evidence_assembly_accepts_complete_inputs() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);
        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };

        let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        assert_eq!(manifest["mobileEvidence"]["status"], "pass");
        assert_eq!(manifest["referencePerformance"]["status"], "fresh");

        let public_key = read_required_text_file(
            &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
        )
        .unwrap();
        let evidence = validate_external_evidence_dir(
            &workspace_root,
            &options.out_dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap();

        assert_eq!(evidence["attestationCount"], 4);
        assert_eq!(evidence["benchmarks"].as_array().map_or(0, Vec::len), 5);
        assert_eq!(
            evidence["signedManifestPackageBinding"]["subjectPath"],
            "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
        );
        assert_eq!(
            evidence["sdkWebPackageBinding"]["packageSubjectPath"],
            "packages/sdk/privacy-pools-sdk-alpha.tgz"
        );
        assert_eq!(
            evidence["sdkWebPackageBinding"]["wasmSubjectPath"],
            "packages/sdk/privacy_pools_sdk_web_bg.wasm"
        );
    }

    #[test]
    fn release_external_evidence_assembly_accepts_local_mobile_evidence() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let local_mobile_smoke = mobile_smoke_fixture_with_identity(
            &commit,
            "local-xtask",
            "mobile-smoke-local",
            "local://mobile-smoke-local",
        );
        let local_mobile_parity = mobile_parity_fixture_with_identity(
            &commit,
            "local-xtask",
            "mobile-smoke-local",
            "local://mobile-smoke-local",
        );
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs_with_mobile_fixtures(
                &root,
                &local_mobile_smoke,
                &local_mobile_parity,
            );
        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled-local"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };

        let public_key = read_required_text_file(
            &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
        )
        .unwrap();
        assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        validate_external_evidence_dir(
            &workspace_root,
            &options.out_dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap();
    }

    #[test]
    fn release_external_evidence_assembly_rejects_browser_wasm_attestation_mismatch() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);
        let repo = current_github_repository_slug(&workspace_root).unwrap();
        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &"00".repeat(32),
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled-digest-mismatch"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };

        let error = assemble_external_evidence_dir(&workspace_root, &options, &commit)
            .unwrap_err()
            .to_string();

        assert!(error.contains("attestation sha256 mismatch"), "{error}");
    }

    #[test]
    fn release_external_evidence_rejects_browser_package_wasm_mismatch() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);
        let wasm_path = packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm");
        fs::write(&wasm_path, b"tampered browser wasm").unwrap();
        let repo = current_github_repository_slug(&workspace_root).unwrap();

        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sha256_hex(&fs::read(&wasm_path).unwrap()),
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled-browser-wasm-mismatch"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };
        let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        let public_key = read_required_text_file(
            &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
        )
        .unwrap();

        let error = validate_external_evidence_dir(
            &workspace_root,
            &options.out_dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(manifest["referencePerformance"]["status"], "fresh");
        assert!(error.contains("packaged browser WASM mismatch"), "{error}");
    }

    #[test]
    fn evidence_check_accepts_malformed_optional_reference_benchmarks() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = "abcdef0";
        let public_key = write_external_evidence_fixture(&dir, commit);
        fs::write(dir.join("benchmarks/rust-desktop-stable.json"), "{").unwrap();

        evidence_check(vec![
            "--channel".to_owned(),
            "alpha".to_owned(),
            "--dir".to_owned(),
            dir.to_string(),
            "--signed-manifest-public-key".to_owned(),
            public_key,
        ])
        .unwrap();
    }

    #[test]
    fn blocked_dependencies_report_failed_prerequisites() {
        let mut statuses = BTreeMap::new();
        statuses.insert("sdk-browser-build".to_owned(), "failed".to_owned());
        statuses.insert(
            "external-evidence-validation".to_owned(),
            "passed".to_owned(),
        );
        let spec = assurance_check_with_dependencies(
            assurance_check_spec(
                "sdk-browser-smoke",
                "npm run test:browser:smoke",
                vec![AssuranceRuntime::Browser],
                "correctness",
                AssuranceCheckMode::Normative,
                "npm",
                vec!["run".to_owned(), "test:browser:smoke".to_owned()],
                Utf8PathBuf::from("packages/sdk"),
                vec![],
                "sdk-browser-smoke.log",
                vec![],
                None,
            ),
            vec![
                "sdk-browser-build".to_owned(),
                "external-evidence-validation".to_owned(),
            ],
        );

        assert_eq!(
            blocked_dependencies(&spec, &statuses),
            vec!["sdk-browser-build".to_owned()]
        );
    }

    #[test]
    fn browser_goldens_depend_on_browser_build() {
        let workspace_root = workspace_root().unwrap();
        let options = AssuranceOptions {
            profile: AssuranceProfile::Pr,
            runtime: AssuranceRuntime::Browser,
            report_mode: AssuranceReportMode::Standard,
            out_dir: workspace_root.join("target/test-assurance"),
            backend: BenchmarkBackendProfile::Stable,
            device_label: "desktop".to_owned(),
            device_model: "fixture".to_owned(),
            v1_package_path: workspace_root.join("packages/sdk"),
            v1_source_path: workspace_root.join("packages/sdk"),
            external_evidence_dir: None,
            fuzz_runs: 8,
            skip_fuzz: true,
            only_checks: None,
        };

        let selected_specs = selected_assurance_specs(&workspace_root, &options);
        let spec = selected_specs
            .iter()
            .find(|spec| spec.id == "compare-rust-goldens-browser")
            .unwrap();
        assert_eq!(spec.depends_on, vec!["sdk-browser-build".to_owned()]);

        let mut statuses = BTreeMap::new();
        statuses.insert("sdk-browser-build".to_owned(), "failed".to_owned());
        assert_eq!(
            blocked_dependencies(spec, &statuses),
            vec!["sdk-browser-build".to_owned()]
        );
    }

    #[test]
    fn browser_smoke_is_not_treated_as_proxy_coverage() {
        assert!(!is_proxy_scenario_check_id("sdk-browser-smoke"));
    }

    #[test]
    fn assurance_merge_rejects_duplicate_check_ids() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let input_a = write_assurance_merge_fixture(
            &root.join("assurance-pr-rust-core"),
            &commit,
            &["rust-fmt"],
        );
        let input_b = write_assurance_merge_fixture(
            &root.join("assurance-pr-rust-generated"),
            &commit,
            &["rust-fmt"],
        );

        let error = merge_assurance_outputs(
            &workspace_root,
            &AssuranceMergeOptions {
                profile: AssuranceProfile::Pr,
                runtime: AssuranceRuntime::Rust,
                out_dir: root.join("merged"),
                inputs: vec![input_a, input_b],
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("duplicate check id `rust-fmt`"));
    }

    #[test]
    fn assurance_merge_reports_missing_subgroup_artifacts() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let missing = root.join("assurance-pr-rust-core");

        let error = merge_assurance_outputs(
            &workspace_root,
            &AssuranceMergeOptions {
                profile: AssuranceProfile::Pr,
                runtime: AssuranceRuntime::Rust,
                out_dir: root.join("merged"),
                inputs: vec![missing.clone()],
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing subgroup assurance artifact"));
        assert!(error.contains(missing.as_str()));
    }

    #[test]
    fn assurance_merge_uses_staged_logs_for_downloaded_artifacts() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let original_root = Utf8PathBuf::from("/tmp/original-assurance-pr-rust-core");
        let input = write_assurance_merge_fixture_with_original_root(
            &root.join("assurance-pr-rust-core"),
            &original_root,
            &commit,
            &["rust-fmt"],
        );
        let merged_out = root.join("merged");

        let error = merge_assurance_outputs(
            &workspace_root,
            &AssuranceMergeOptions {
                profile: AssuranceProfile::Pr,
                runtime: AssuranceRuntime::Rust,
                out_dir: merged_out.clone(),
                inputs: vec![input],
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing required checks"));
        let merged_log =
            fs::read_to_string(merged_out.join("logs/rust-core-rust-fmt.log")).unwrap();
        assert!(merged_log.contains("rust-fmt ok"));
        let merged_check = read_required_json(&merged_out.join("checks/rust-fmt.json")).unwrap();
        assert_eq!(
            merged_check["expectedOutputs"][0].as_str().unwrap(),
            merged_out
                .join("groups/rust-core/outputs/rust-fmt.txt")
                .as_str()
        );
    }

    #[test]
    fn assurance_merge_writes_failure_bundle_for_malformed_subgroup_index() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let input = root.join("assurance-pr-rust-core");
        fs::create_dir_all(&input).unwrap();
        write_json(
            &input.join("environment.json"),
            &json!({
                "gitCommit": commit,
                "profile": "pr",
                "runtime": "rust",
                "status": "passed",
            }),
        );
        fs::write(input.join("assurance-index.json"), "{").unwrap();
        let merged_out = root.join("merged");

        let error = merge_assurance_outputs(
            &workspace_root,
            &AssuranceMergeOptions {
                profile: AssuranceProfile::Pr,
                runtime: AssuranceRuntime::Rust,
                out_dir: merged_out.clone(),
                inputs: vec![input],
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("failed to load subgroup index"));
        assert!(merged_out.join("assurance-index.json").exists());
        assert!(merged_out.join("findings.md").exists());
        let merged_index = read_required_json(&merged_out.join("assurance-index.json")).unwrap();
        assert!(
            merged_index["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["id"] == "invalid-rust-core-index")
        );
    }

    #[test]
    fn release_external_evidence_rejects_missing_attestation_verification_file() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let public_key = write_external_evidence_fixture(&dir, &commit);
        let records = read_attestation_records(&dir.join("attestations.json"));
        let verification_path = dir.join(&records[0].verification_path);
        fs::remove_file(&verification_path).unwrap();

        let error = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("attestation verificationPath does not exist"));
    }

    #[test]
    fn release_external_evidence_rejects_malformed_attestation_verification_file() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let public_key = write_external_evidence_fixture(&dir, &commit);
        let records = read_attestation_records(&dir.join("attestations.json"));
        fs::write(dir.join(&records[0].verification_path), "{").unwrap();

        let error = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("failed to parse") && error.contains("attestation-verification"),
            "{error}"
        );
    }

    #[test]
    fn release_external_evidence_rejects_attestation_verification_digest_mismatch() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let public_key = write_external_evidence_fixture(&dir, &commit);
        let records = read_attestation_records(&dir.join("attestations.json"));
        let record = &records[0];
        let repo = current_github_repository_slug(&workspace_root).unwrap();
        let mut verification =
            attestation_verification_fixture(&record.subject_path, &record.sha256, &repo);
        verification["subjectSha256"] = json!("00".repeat(32));
        overwrite_attestation_verification(&dir, record, &verification);

        let error = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("attestation verification sha256 mismatch"));
    }

    #[test]
    fn release_external_evidence_rejects_attestation_verification_repo_mismatch() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let public_key = write_external_evidence_fixture(&dir, &commit);
        let records = read_attestation_records(&dir.join("attestations.json"));
        let record = &records[0];
        let verification =
            attestation_verification_fixture(&record.subject_path, &record.sha256, "wrong/repo");
        overwrite_attestation_verification(&dir, record, &verification);

        let error = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("attestation verification repo mismatch"));
    }

    #[test]
    fn release_external_evidence_rejects_attestation_verification_workflow_mismatch() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let public_key = write_external_evidence_fixture(&dir, &commit);
        let records = read_attestation_records(&dir.join("attestations.json"));
        let record = &records[0];
        let repo = current_github_repository_slug(&workspace_root).unwrap();
        let mut verification =
            attestation_verification_fixture(&record.subject_path, &record.sha256, &repo);
        verification["signerWorkflow"] = json!("wrong/repo/.github/workflows/other.yml");
        overwrite_attestation_verification(&dir, record, &verification);

        let error = validate_external_evidence_dir(
            &workspace_root,
            &dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("attestation signer workflow mismatch"));
    }

    #[test]
    fn release_external_evidence_rejects_duplicate_circuit_attestation_subjects() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);
        let packages_root = packages_dir.join("packages/circuits");
        let source_archive = packages_root.join("privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
        let duplicate_archive =
            packages_root.join("privacy-pools-sdk-circuit-artifacts-beta.tar.gz");
        fs::copy(&source_archive, &duplicate_archive).unwrap();
        let repo = current_github_repository_slug(&workspace_root).unwrap();

        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &sha256_hex(&fs::read(&source_archive).unwrap()),
                    "https://example.invalid/attestations/circuits-alpha",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-beta.tar.gz",
                    &sha256_hex(&fs::read(&duplicate_archive).unwrap()),
                    "https://example.invalid/attestations/circuits-beta",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled-duplicate-circuits"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };
        let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        let public_key = read_required_text_file(
            &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
        )
        .unwrap();

        let error = validate_external_evidence_dir(
            &workspace_root,
            &options.out_dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(manifest["referencePerformance"]["status"].is_string());
        assert!(error.contains("exactly one"), "{error}");
    }

    #[test]
    fn release_external_evidence_rejects_tampered_top_level_circuit_artifacts() {
        let workspace_root = workspace_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let commit = current_git_commit(&workspace_root).unwrap();
        let (mobile_dir, reference_dir, sbom_dir, packages_dir, attestation_dir) =
            write_release_assembly_inputs(&root, &commit);
        let circuit_archive =
            packages_dir.join("packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz");
        let unpacked = root.join("tampered-circuit");
        fs::create_dir_all(&unpacked).unwrap();
        let status = Command::new("tar")
            .args(["-xzf", circuit_archive.as_str(), "-C", unpacked.as_str()])
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(
            unpacked.join("artifacts/withdraw-fixture.wasm"),
            b"tampered packaged circuit artifact",
        )
        .unwrap();
        let status = Command::new("tar")
            .args([
                "-C",
                unpacked.as_str(),
                "-czf",
                circuit_archive.as_str(),
                "artifacts",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let repo = current_github_repository_slug(&workspace_root).unwrap();
        write_json(
            &attestation_dir.join("records.json"),
            &json!([
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy-pools-sdk-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy-pools-sdk-alpha.tgz"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/sdk/privacy_pools_sdk_web_bg.wasm",
                    &sha256_hex(
                        &fs::read(packages_dir.join("packages/sdk/privacy_pools_sdk_web_bg.wasm"))
                            .unwrap()
                    ),
                    "https://example.invalid/attestations/sdk-wasm",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz",
                    &sha256_hex(
                        &fs::read(packages_dir.join(
                            "packages/react-native/privacy-pools-sdk-react-native-alpha.tgz"
                        ))
                        .unwrap()
                    ),
                    "https://example.invalid/attestations/react-native",
                    "https://example.invalid/workflows/release",
                    &repo
                ),
                attestation_record_fixture(
                    &attestation_dir,
                    "packages/circuits/privacy-pools-sdk-circuit-artifacts-alpha.tar.gz",
                    &sha256_hex(&fs::read(&circuit_archive).unwrap()),
                    "https://example.invalid/attestations/circuits",
                    "https://example.invalid/workflows/release",
                    &repo
                )
            ]),
        );

        let options = ExternalEvidenceAssembleOptions {
            mode: ExternalEvidenceMode::Release,
            out_dir: root.join("assembled-tampered-circuit"),
            mobile_evidence_dir: Some(mobile_dir),
            reference_benchmarks_dir: Some(reference_dir),
            sbom_dir: Some(sbom_dir),
            packages_dir: Some(packages_dir),
            attestation_metadata_dir: Some(attestation_dir),
        };
        let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit).unwrap();
        let public_key = read_required_text_file(
            &workspace_root.join("fixtures/artifacts/signed-manifest/public-key.hex"),
        )
        .unwrap();

        let error = validate_external_evidence_dir(
            &workspace_root,
            &options.out_dir,
            AssuranceProfile::Release,
            BenchmarkBackendProfile::Stable,
            &commit,
            Some(&public_key),
        )
        .unwrap_err()
        .to_string();

        assert!(manifest["referencePerformance"]["status"].is_string());
        assert!(
            error.contains("does not match embedded signed manifest"),
            "{error}"
        );
    }
}
