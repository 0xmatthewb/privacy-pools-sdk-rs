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
    str::FromStr,
    time::SystemTime,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
struct BenchmarkArgs {
    manifest: PathBuf,
    artifacts_root: PathBuf,
    backend: BackendProfile,
    iterations: usize,
    warmup: usize,
    report_json: Option<PathBuf>,
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

#[derive(Debug, Clone, Serialize)]
struct BenchmarkReport {
    generated_at_unix_seconds: u64,
    backend_profile: String,
    artifact_version: String,
    manifest_path: String,
    artifacts_root: String,
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
        "    flags: --manifest <path> --artifacts-root <path> [--backend stable|fast] [--iterations n] [--warmup n] [--report-json path]"
    );
}

impl BenchmarkArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut manifest = None;
        let mut artifacts_root = None;
        let mut backend = BackendProfile::Stable;
        let mut iterations = 5usize;
        let mut warmup = 1usize;
        let mut report_json = None;

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
                "--report-json" => {
                    report_json = Some(PathBuf::from(
                        iter.next().context("--report-json requires a path value")?,
                    ));
                }
                other => bail!("unknown flag: {other}"),
            }
        }

        Ok(Self {
            manifest: manifest.context("--manifest is required")?,
            artifacts_root: artifacts_root.context("--artifacts-root is required")?,
            backend,
            iterations,
            warmup,
            report_json,
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
    let manifest: ArtifactManifest = serde_json::from_slice(
        &fs::read(&args.manifest)
            .with_context(|| format!("failed to read manifest {}", args.manifest.display()))?,
    )
    .context("failed to parse artifact manifest JSON")?;

    let sdk = PrivacyPoolsSdk::new(BackendPolicy {
        allow_fast_backend: matches!(args.backend, BackendProfile::Fast),
    });
    let request = reference_withdrawal_request(&sdk)?;

    let bundle = sdk
        .resolve_verified_artifact_bundle(&manifest, &args.artifacts_root, "withdraw")
        .with_context(|| {
            format!(
                "failed to resolve a verified withdraw artifact bundle from {}",
                args.artifacts_root.display()
            )
        })?;
    let zkey_path = bundle
        .artifact(ArtifactKind::Zkey)
        .context("withdraw bundle is missing the zkey descriptor")?;

    println!("privacy-pools-sdk-cli withdraw benchmark");
    println!("backend profile: {:?}", args.backend);
    println!("artifact version: {}", bundle.version);
    println!("artifact root: {}", args.artifacts_root.display());
    println!("zkey path: {}", zkey_path.path.display());
    println!("iterations: {}", args.iterations);
    println!("warmup: {}", args.warmup);
    println!();

    for index in 0..args.warmup {
        let _ = run_iteration(
            &sdk,
            &manifest,
            &args.artifacts_root,
            args.backend,
            &request,
        )
        .with_context(|| format!("warmup iteration {} failed", index + 1))?;
    }

    let mut metrics = Vec::with_capacity(args.iterations);
    for index in 0..args.iterations {
        let iteration = run_iteration(
            &sdk,
            &manifest,
            &args.artifacts_root,
            args.backend,
            &request,
        )
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
    if let Some(report_path) = &args.report_json {
        write_report(report_path, &args, &bundle.version, &metrics)?;
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
    manifest: &ArtifactManifest,
    artifacts_root: &Path,
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
        catch_panics_silently(|| sdk.prove_withdrawal(backend, manifest, artifacts_root, request))
            .map_err(|_| {
                anyhow::anyhow!("prover backend panicked while reading proving artifacts")
            })??;
    let proof_generation = proof_start.elapsed();

    let verify_start = Instant::now();
    let verified = catch_panics_silently(|| {
        sdk.verify_withdrawal_proof(backend, manifest, artifacts_root, &proof.proof)
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
        commitment: sdk.get_commitment(
            parse_u256(&withdrawal_fixture["existingValue"])?,
            parse_u256(&withdrawal_fixture["label"])?,
            deposit_nullifier,
            deposit_secret,
        )?,
        withdrawal: core::Withdrawal {
            processooor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        },
        scope,
        withdrawal_amount: parse_u256(&withdrawal_fixture["withdrawalAmount"])?,
        state_witness: parse_circuit_witness(&withdrawal_fixture["stateWitness"])?,
        asp_witness: parse_circuit_witness(&withdrawal_fixture["aspWitness"])?,
        new_nullifier: parse_u256(&withdrawal_fixture["newNullifier"])?,
        new_secret: parse_u256(&withdrawal_fixture["newSecret"])?,
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

fn write_report(
    report_path: &Path,
    args: &BenchmarkArgs,
    artifact_version: &str,
    metrics: &[BenchmarkIteration],
) -> Result<()> {
    let report = BenchmarkReport {
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs(),
        backend_profile: format!("{:?}", args.backend),
        artifact_version: artifact_version.to_owned(),
        manifest_path: args.manifest.display().to_string(),
        artifacts_root: args.artifacts_root.display().to_string(),
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
