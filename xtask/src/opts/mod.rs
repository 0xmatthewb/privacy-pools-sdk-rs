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

