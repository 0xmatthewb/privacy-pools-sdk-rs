use alloy_primitives::{U256, address, bytes};
use anyhow::{Context, Result, bail, ensure};
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{ArtifactKind, ArtifactManifest},
    core,
    prover::{self, BackendPolicy, BackendProfile},
};
use serde::Serialize;
use serde_json::Value;
use std::{
    env, fs,
    panic::{self, AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::SystemTime,
    time::{Duration, Instant},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, get_current_pid};

#[derive(Debug, Clone)]
struct BenchmarkArgs {
    manifest: PathBuf,
    artifacts_root: PathBuf,
    backend: BackendProfile,
    iterations: usize,
    warmup: usize,
    allow_debug_build: bool,
    report_json: Option<PathBuf>,
    device_label: Option<String>,
    device_model: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkIteration {
    input_preparation: Duration,
    witness_generation: Duration,
    proof_generation: Duration,
    verification: Duration,
    prove_and_verify: Duration,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkIterationReport {
    iteration: usize,
    input_preparation_ms: f64,
    witness_generation_ms: f64,
    proof_generation_ms: f64,
    verification_ms: f64,
    prove_and_verify_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkSummary {
    average_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkReportContext<'a> {
    artifact_version: &'a str,
    zkey_sha256: &'a str,
    bundle_verification: Duration,
    session_preload: Duration,
    first_iteration: BenchmarkIteration,
    peak_resident_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkReport {
    generated_at_unix_seconds: u64,
    git_commit: String,
    sdk_version: String,
    backend_profile: String,
    backend_name: String,
    device_label: String,
    device_model: String,
    os_name: String,
    os_version: String,
    artifact_version: String,
    zkey_sha256: String,
    manifest_path: String,
    artifacts_root: String,
    artifact_resolution_ms: f64,
    bundle_verification_ms: f64,
    session_preload_ms: f64,
    first_input_preparation_ms: f64,
    first_witness_generation_ms: f64,
    first_proof_generation_ms: f64,
    first_verification_ms: f64,
    first_prove_and_verify_ms: f64,
    peak_resident_memory_bytes: Option<u64>,
    iterations: usize,
    warmup: usize,
    input_preparation: BenchmarkSummary,
    witness_generation: BenchmarkSummary,
    proof_generation: BenchmarkSummary,
    verification: BenchmarkSummary,
    prove_and_verify: BenchmarkSummary,
    samples: Vec<BenchmarkIterationReport>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("benchmark-withdraw") => benchmark_withdraw(BenchmarkArgs::parse(args.collect())?),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => bail!("unknown command: {other}"),
    }
}

fn print_help() {
    println!("privacy-pools-sdk-cli");
    println!("workspace tooling for vectors, benchmarks, and release checks");
    println!();
    println!("commands:");
    println!("  benchmark-withdraw");
    println!("    benchmark the compiled Rust withdraw proving path");
    println!(
        "    flags: --manifest <path> --artifacts-root <path> [--backend stable|fast] [--iterations n] [--warmup n] [--allow-debug-build] [--report-json path --device-label desktop|ios|android --device-model model]"
    );
}

impl BenchmarkArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut manifest = None;
        let mut artifacts_root = None;
        let mut backend = BackendProfile::Stable;
        let mut iterations = 5usize;
        let mut warmup = 1usize;
        let mut allow_debug_build = false;
        let mut report_json = None;
        let mut device_label = None;
        let mut device_model = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--manifest" => {
                    manifest = Some(PathBuf::from(
                        iter.next().context("--manifest requires a path value")?,
                    ));
                }
                "--artifacts-root" => {
                    artifacts_root = Some(PathBuf::from(
                        iter.next()
                            .context("--artifacts-root requires a path value")?,
                    ));
                }
                "--backend" => {
                    backend = parse_backend(&iter.next().context("--backend requires a value")?)?;
                }
                "--iterations" => {
                    iterations = iter
                        .next()
                        .context("--iterations requires a value")?
                        .parse()
                        .context("failed to parse --iterations")?;
                }
                "--warmup" => {
                    warmup = iter
                        .next()
                        .context("--warmup requires a value")?
                        .parse()
                        .context("failed to parse --warmup")?;
                }
                "--allow-debug-build" => {
                    allow_debug_build = true;
                }
                "--report-json" => {
                    report_json = Some(PathBuf::from(
                        iter.next().context("--report-json requires a path value")?,
                    ));
                }
                "--device-label" => {
                    device_label = Some(iter.next().context("--device-label requires a value")?);
                }
                "--device-model" => {
                    device_model = Some(iter.next().context("--device-model requires a value")?);
                }
                other => bail!("unknown flag: {other}"),
            }
        }

        if report_json.is_some() {
            ensure!(
                device_label.is_some(),
                "--device-label is required when --report-json is set"
            );
            ensure!(
                device_model.is_some(),
                "--device-model is required when --report-json is set"
            );
        }

        Ok(Self {
            manifest: manifest.context("--manifest is required")?,
            artifacts_root: artifacts_root.context("--artifacts-root is required")?,
            backend,
            iterations,
            warmup,
            allow_debug_build,
            report_json,
            device_label,
            device_model,
        })
    }
}

fn parse_backend(value: &str) -> Result<BackendProfile> {
    match value {
        "stable" => Ok(BackendProfile::Stable),
        "fast" => Ok(BackendProfile::Fast),
        _ => bail!("unsupported backend profile: {value}"),
    }
}

fn benchmark_withdraw(args: BenchmarkArgs) -> Result<()> {
    ensure_release_build(args.allow_debug_build)?;

    let manifest: ArtifactManifest = serde_json::from_slice(
        &fs::read(&args.manifest)
            .with_context(|| format!("failed to read manifest {}", args.manifest.display()))?,
    )
    .context("failed to parse artifact manifest JSON")?;

    let sdk = PrivacyPoolsSdk::new(BackendPolicy {
        allow_fast_backend: matches!(args.backend, BackendProfile::Fast),
    });
    let request = reference_withdrawal_request(&sdk)?;

    let bundle_verification_start = Instant::now();
    let bundle = sdk
        .load_verified_artifact_bundle(&manifest, &args.artifacts_root, "withdraw")
        .with_context(|| {
            format!(
                "failed to load a verified withdraw artifact bundle from {}",
                args.artifacts_root.display()
            )
        })?;
    let bundle_verification = bundle_verification_start.elapsed();

    let zkey = bundle
        .artifact(ArtifactKind::Zkey)
        .context("withdraw bundle is missing the zkey descriptor")?;
    let zkey_sha256 = zkey.descriptor().sha256.clone();

    let session_preload_start = Instant::now();
    let session = sdk
        .prepare_withdrawal_circuit_session_from_bundle(bundle.clone())
        .context("failed to prepare cached withdraw artifacts for benchmarking")?;
    let session_preload = session_preload_start.elapsed();

    println!("privacy-pools-sdk-cli withdraw benchmark");
    println!("backend profile: {:?}", args.backend);
    println!("artifact version: {}", bundle.version());
    println!("artifact root: {}", args.artifacts_root.display());
    println!("zkey sha256: {}", zkey_sha256);
    println!("bundle verification: {:?}", bundle_verification);
    println!("session preload: {:?}", session_preload);
    println!("iterations: {}", args.iterations);
    println!("warmup: {}", args.warmup);
    println!();

    let first_iteration = run_iteration(&sdk, &session, args.backend, &request)
        .context("first proof iteration failed")?;

    println!(
        "first proof latency: prove {:?}, verify {:?}, prove+verify {:?}",
        first_iteration.proof_generation,
        first_iteration.verification,
        first_iteration.prove_and_verify
    );

    for index in 0..args.warmup {
        let _ = run_iteration(&sdk, &session, args.backend, &request)
            .with_context(|| format!("warmup iteration {} failed", index + 1))?;
    }

    let mut metrics = Vec::with_capacity(args.iterations);
    for index in 0..args.iterations {
        let iteration = run_iteration(&sdk, &session, args.backend, &request)
            .with_context(|| format!("benchmark iteration {} failed", index + 1))?;
        println!(
            "iteration {:>2}: prove {:?}, verify {:?}, prove+verify {:?}",
            index + 1,
            iteration.proof_generation,
            iteration.verification,
            iteration.prove_and_verify
        );
        metrics.push(iteration);
    }

    println!();
    print_duration_summary(
        "input preparation",
        metrics.iter().map(|value| value.input_preparation),
    );
    print_duration_summary(
        "compiled witness",
        metrics.iter().map(|value| value.witness_generation),
    );
    print_duration_summary(
        "proof generation",
        metrics.iter().map(|value| value.proof_generation),
    );
    print_duration_summary(
        "proof verification",
        metrics.iter().map(|value| value.verification),
    );
    print_duration_summary(
        "prove + verify",
        metrics.iter().map(|value| value.prove_and_verify),
    );
    if let Some(memory_bytes) = peak_resident_memory_bytes() {
        println!("{:>18}: {} bytes", "peak rss", memory_bytes);
    }
    if let Some(report_path) = &args.report_json {
        write_report(
            report_path,
            &args,
            BenchmarkReportContext {
                artifact_version: bundle.version(),
                zkey_sha256: &zkey_sha256,
                bundle_verification,
                session_preload,
                first_iteration,
                peak_resident_memory_bytes: peak_resident_memory_bytes(),
            },
            &metrics,
        )?;
        println!();
        println!("wrote benchmark report to {}", report_path.display());
    }
    println!();
    println!("note: input preparation and compiled witness timings are diagnostic slices;");
    println!(
        "      prove + verify reflects the real Rust SDK flow and is the most relevant headline metric."
    );

    Ok(())
}

fn run_iteration(
    sdk: &PrivacyPoolsSdk,
    session: &privacy_pools_sdk::WithdrawalCircuitSession,
    backend: BackendProfile,
    request: &core::WithdrawalWitnessRequest,
) -> Result<BenchmarkIteration> {
    let input_start = Instant::now();
    let input = sdk.build_withdrawal_circuit_input(request)?;
    let _serialized = sdk.serialize_withdrawal_circuit_input(&input)?;
    let input_preparation = input_start.elapsed();

    let witness_start = Instant::now();
    let _witness = prover::generate_withdrawal_witness(&input)?;
    let witness_generation = witness_start.elapsed();

    let prove_and_verify_start = Instant::now();

    let proof_start = Instant::now();
    let proof =
        catch_panics_silently(|| sdk.prove_withdrawal_with_session(backend, session, request))
            .map_err(|_| {
            anyhow::anyhow!("prover backend panicked while reading proving artifacts")
        })??;
    let proof_generation = proof_start.elapsed();

    let verify_start = Instant::now();
    let verified = catch_panics_silently(|| {
        sdk.verify_withdrawal_proof_with_session(backend, session, &proof.proof)
    })
    .map_err(|_| anyhow::anyhow!("prover backend panicked while verifying the proof bundle"))??;
    let verification = verify_start.elapsed();
    ensure!(verified, "local proof verification returned false");

    Ok(BenchmarkIteration {
        input_preparation,
        witness_generation,
        proof_generation,
        verification,
        prove_and_verify: prove_and_verify_start.elapsed(),
    })
}

fn ensure_release_build(allow_debug_build: bool) -> Result<()> {
    if cfg!(debug_assertions) {
        if allow_debug_build {
            eprintln!(
                "warning: benchmark-withdraw is running in a debug build; timings are not representative"
            );
            return Ok(());
        }

        bail!(
            "benchmark-withdraw must be run with `cargo run --release -p privacy-pools-sdk-cli -- benchmark-withdraw ...`; pass --allow-debug-build only for diagnostic runs"
        );
    }

    Ok(())
}

fn print_duration_summary(label: &str, durations: impl Iterator<Item = Duration>) {
    let summary = summarize_durations(durations.collect::<Vec<_>>());
    if summary.is_none() {
        return;
    }
    let summary = summary.expect("summary already checked");

    println!(
        "{label:>18}: avg {:>8.2} ms | min {:>8.2} ms | max {:>8.2} ms",
        summary.average_ms, summary.min_ms, summary.max_ms
    );
}

fn summarize_durations(durations: Vec<Duration>) -> Option<BenchmarkSummary> {
    if durations.is_empty() {
        return None;
    }

    let total = durations
        .iter()
        .copied()
        .fold(Duration::ZERO, |sum, value| sum + value);
    let min = durations.iter().copied().min().unwrap_or(Duration::ZERO);
    let max = durations.iter().copied().max().unwrap_or(Duration::ZERO);
    let average = total / (durations.len() as u32);

    Some(BenchmarkSummary {
        average_ms: duration_ms(average),
        min_ms: duration_ms(min),
        max_ms: duration_ms(max),
    })
}

fn catch_panics_silently<T>(operation: impl FnOnce() -> T) -> std::thread::Result<T> {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(operation));
    panic::set_hook(hook);
    result
}

fn reference_withdrawal_request(sdk: &PrivacyPoolsSdk) -> Result<core::WithdrawalWitnessRequest> {
    let crypto_fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/vectors/crypto-compatibility.json"
    ))
    .context("failed to parse crypto fixture")?;
    let withdrawal_fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/vectors/withdrawal-circuit-input.json"
    ))
    .context("failed to parse withdrawal fixture")?;

    let keys = sdk
        .generate_master_keys(
            crypto_fixture["mnemonic"]
                .as_str()
                .context("missing mnemonic")?,
        )
        .context("failed to derive master keys from reference mnemonic")?;
    let scope = parse_u256(&crypto_fixture["scope"])?;
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(&keys, scope, U256::ZERO)
        .context("failed to derive deposit secrets for benchmark request")?;

    Ok(core::WithdrawalWitnessRequest {
        commitment: sdk.build_commitment(
            parse_u256(&withdrawal_fixture["existingValue"])?,
            parse_u256(&withdrawal_fixture["label"])?,
            deposit_nullifier,
            deposit_secret,
        )?,
        withdrawal: core::Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        },
        scope,
        withdrawal_amount: parse_u256(&withdrawal_fixture["withdrawalAmount"])?,
        state_witness: parse_circuit_witness(&withdrawal_fixture["stateWitness"])?,
        asp_witness: parse_circuit_witness(&withdrawal_fixture["aspWitness"])?,
        new_nullifier: parse_u256(&withdrawal_fixture["newNullifier"])?.into(),
        new_secret: parse_u256(&withdrawal_fixture["newSecret"])?.into(),
    })
}

fn parse_circuit_witness(value: &Value) -> Result<core::CircuitMerkleWitness> {
    Ok(core::CircuitMerkleWitness {
        root: parse_u256(&value["root"])?,
        leaf: parse_u256(&value["leaf"])?,
        index: value["index"]
            .as_u64()
            .context("missing merkle witness index")? as usize,
        siblings: value["siblings"]
            .as_array()
            .context("missing merkle witness siblings")?
            .iter()
            .map(parse_u256)
            .collect::<Result<Vec<_>>>()?,
        depth: value["depth"]
            .as_u64()
            .context("missing merkle witness depth")? as usize,
    })
}

fn parse_u256(value: &Value) -> Result<U256> {
    U256::from_str(
        value
            .as_str()
            .context("expected decimal field element string in fixture")?,
    )
    .context("failed to parse decimal field element")
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn peak_resident_memory_bytes() -> Option<u64> {
    let pid = get_current_pid().ok()?;
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system.process(pid).map(|process| process.memory())
}

fn write_report(
    report_path: &Path,
    args: &BenchmarkArgs,
    context: BenchmarkReportContext<'_>,
    metrics: &[BenchmarkIteration],
) -> Result<()> {
    let report = BenchmarkReport {
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs(),
        git_commit: current_git_commit()?,
        sdk_version: PrivacyPoolsSdk::version().to_owned(),
        backend_profile: format!("{:?}", args.backend),
        backend_name: backend_name(args.backend).to_owned(),
        device_label: args
            .device_label
            .clone()
            .unwrap_or_else(|| "desktop".to_owned()),
        device_model: args
            .device_model
            .clone()
            .unwrap_or_else(|| "unspecified".to_owned()),
        os_name: System::name().unwrap_or_else(|| env::consts::OS.to_owned()),
        os_version: System::long_os_version()
            .or_else(System::os_version)
            .unwrap_or_else(|| "unknown".to_owned()),
        artifact_version: context.artifact_version.to_owned(),
        zkey_sha256: context.zkey_sha256.to_owned(),
        manifest_path: args.manifest.display().to_string(),
        artifacts_root: args.artifacts_root.display().to_string(),
        artifact_resolution_ms: duration_ms(context.bundle_verification + context.session_preload),
        bundle_verification_ms: duration_ms(context.bundle_verification),
        session_preload_ms: duration_ms(context.session_preload),
        first_input_preparation_ms: duration_ms(context.first_iteration.input_preparation),
        first_witness_generation_ms: duration_ms(context.first_iteration.witness_generation),
        first_proof_generation_ms: duration_ms(context.first_iteration.proof_generation),
        first_verification_ms: duration_ms(context.first_iteration.verification),
        first_prove_and_verify_ms: duration_ms(context.first_iteration.prove_and_verify),
        peak_resident_memory_bytes: context.peak_resident_memory_bytes,
        iterations: args.iterations,
        warmup: args.warmup,
        input_preparation: summarize_durations(
            metrics
                .iter()
                .map(|value| value.input_preparation)
                .collect(),
        )
        .context("missing input preparation metrics")?,
        witness_generation: summarize_durations(
            metrics
                .iter()
                .map(|value| value.witness_generation)
                .collect(),
        )
        .context("missing witness metrics")?,
        proof_generation: summarize_durations(
            metrics.iter().map(|value| value.proof_generation).collect(),
        )
        .context("missing proof metrics")?,
        verification: summarize_durations(metrics.iter().map(|value| value.verification).collect())
            .context("missing verification metrics")?,
        prove_and_verify: summarize_durations(
            metrics.iter().map(|value| value.prove_and_verify).collect(),
        )
        .context("missing prove_and_verify metrics")?,
        samples: metrics
            .iter()
            .enumerate()
            .map(|(index, value)| BenchmarkIterationReport {
                iteration: index + 1,
                input_preparation_ms: duration_ms(value.input_preparation),
                witness_generation_ms: duration_ms(value.witness_generation),
                proof_generation_ms: duration_ms(value.proof_generation),
                verification_ms: duration_ms(value.verification),
                prove_and_verify_ms: duration_ms(value.prove_and_verify),
            })
            .collect(),
    };

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create benchmark report directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(
        report_path,
        serde_json::to_vec_pretty(&report).context("failed to serialize benchmark report")?,
    )
    .with_context(|| format!("failed to write benchmark report {}", report_path.display()))
}

fn backend_name(profile: BackendProfile) -> &'static str {
    match profile {
        BackendProfile::Stable => "stable",
        BackendProfile::Fast => "fast",
    }
}

fn current_git_commit() -> Result<String> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("failed to resolve workspace root")?;
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(&workspace_root)
        .output()
        .context("failed to run git rev-parse HEAD")?;
    ensure!(output.status.success(), "git rev-parse HEAD failed");

    let commit =
        String::from_utf8(output.stdout).context("git rev-parse HEAD returned non-utf8")?;
    let commit = commit.trim().to_owned();
    ensure!(
        !commit.is_empty(),
        "git rev-parse HEAD returned an empty commit"
    );
    Ok(commit)
}
