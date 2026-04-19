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
            "--locked",
        ]);
        let mut feature_flags = Vec::new();
        if experimental_threaded {
            feature_flags.push("threaded");
        }
        if !release {
            feature_flags.push("dangerous-exports");
            feature_flags.push("dangerous-key-export");
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

        assert_wasm_bindgen_cli_version(workspace_root)?;
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
        write_wasm_sha256_file(&output_wasm)?;
        if experimental_threaded {
            write_threaded_artifact_availability(generated_root, true)?;
        }

        Ok(())
    })();

    fs::write(&browser_flags_path, original_browser_flags)
        .with_context(|| format!("failed to restore {}", browser_flags_path))?;

    result
}

fn write_wasm_sha256_file(wasm_path: &Utf8PathBuf) -> Result<()> {
    let bytes = fs::read(wasm_path).with_context(|| format!("failed to read {wasm_path}"))?;
    let hash_path = Utf8PathBuf::from(format!("{wasm_path}.sha256"));
    fs::write(&hash_path, format!("{}\n", sha256_hex(&bytes)))
        .with_context(|| format!("failed to write {hash_path}"))?;
    Ok(())
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
