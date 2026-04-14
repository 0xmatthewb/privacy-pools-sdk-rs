use alloy_primitives::{U256, address, bytes};
use anyhow::{Context, Result, bail, ensure};
use privacy_pools_sdk::{
    PrivacyPoolsSdk,
    artifacts::{ArtifactKind, ArtifactManifest},
    core,
    prover::{self, BackendPolicy, BackendProfile},
};
use serde_json::Value;
use std::{
    env, fs,
    panic::{self, AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
struct BenchmarkArgs {
    manifest: PathBuf,
    artifacts_root: PathBuf,
    backend: BackendProfile,
    iterations: usize,
    warmup: usize,
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkIteration {
    input_preparation: Duration,
    witness_generation: Duration,
    proof_generation: Duration,
    verification: Duration,
    prove_and_verify: Duration,
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
        "    flags: --manifest <path> --artifacts-root <path> [--backend stable|fast] [--iterations n] [--warmup n]"
    );
}

impl BenchmarkArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut manifest = None;
        let mut artifacts_root = None;
        let mut backend = BackendProfile::Stable;
        let mut iterations = 5usize;
        let mut warmup = 1usize;

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
                other => bail!("unknown flag: {other}"),
            }
        }

        Ok(Self {
            manifest: manifest.context("--manifest is required")?,
            artifacts_root: artifacts_root.context("--artifacts-root is required")?,
            backend,
            iterations,
            warmup,
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
    let durations = durations.collect::<Vec<_>>();
    if durations.is_empty() {
        return;
    }

    let total = durations
        .iter()
        .copied()
        .fold(Duration::ZERO, |sum, value| sum + value);
    let min = durations.iter().copied().min().unwrap_or(Duration::ZERO);
    let max = durations.iter().copied().max().unwrap_or(Duration::ZERO);
    let average = total / (durations.len() as u32);

    println!(
        "{label:>18}: avg {:>8.2} ms | min {:>8.2} ms | max {:>8.2} ms",
        average.as_secs_f64() * 1_000.0,
        min.as_secs_f64() * 1_000.0,
        max.as_secs_f64() * 1_000.0
    );
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
