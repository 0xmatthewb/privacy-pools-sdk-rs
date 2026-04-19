use alloy_primitives::{Address, B256, Bytes, U256, address, bytes};
use anyhow::{Context, Result, bail, ensure};
use privacy_pools_sdk::{
    PrivacyPoolsSdk, SessionCache, SessionCacheKey,
    artifacts::{ArtifactKind, ArtifactManifest},
    chain, core,
    core::wire::{
        WireCommitment, WireCommitmentCircuitInput, WireMasterKeys, WireWithdrawal,
        WireWithdrawalCircuitInput,
    },
    prover::{self, BackendPolicy, BackendProfile},
    signer::LocalMnemonicSigner,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

#[derive(Debug, Clone)]
struct BenchmarkReportContext<'a> {
    artifact_version: &'a str,
    zkey_sha256: &'a str,
    manifest_sha256: String,
    artifact_bundle_sha256: String,
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
    device_class: String,
    cpu_model: String,
    os_name: String,
    os_version: String,
    rustc_version_verbose: String,
    cargo_version: String,
    benchmark_scenario_id: String,
    artifact_version: String,
    zkey_sha256: String,
    manifest_sha256: String,
    artifact_bundle_sha256: String,
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

#[derive(Debug, Clone)]
struct AuditParityReportArgs {
    cases_json: PathBuf,
    commitment_manifest: PathBuf,
    withdrawal_manifest: PathBuf,
    artifacts_root: PathBuf,
    backend: BackendProfile,
    report_json: PathBuf,
}

#[derive(Debug, Clone)]
struct AuditVerifyProofArgs {
    circuit: AuditCircuit,
    manifest: PathBuf,
    artifacts_root: PathBuf,
    backend: BackendProfile,
    proof_json: PathBuf,
}

#[derive(Debug, Clone)]
struct AuditStatefulReportArgs {
    input_json: PathBuf,
    backend: BackendProfile,
    report_json: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditCircuit {
    Commitment,
    Withdrawal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditCaseFixture {
    comparison_cases: Vec<AuditComparisonCase>,
    merkle_cases: Vec<AuditMerkleCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditComparisonCase {
    name: String,
    mnemonic: String,
    scope: String,
    label: String,
    deposit_index: String,
    withdrawal_index: String,
    value: String,
    withdrawal_amount: String,
    withdrawal: AuditWithdrawalFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditWithdrawalFixture {
    processooor: String,
    data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditMerkleCase {
    name: String,
    leaves: Vec<String>,
    leaf: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditParityReport {
    generated_at_unix_seconds: u64,
    git_commit: String,
    sdk_version: String,
    backend_profile: String,
    backend_name: String,
    fixtures: AuditFixtureMetadata,
    artifacts: AuditArtifactMetadata,
    root_reads: AuditRootReadReport,
    cases: Vec<AuditComparisonResult>,
    merkle_cases: Vec<AuditMerkleResult>,
    performance: AuditPerformanceMetrics,
    proofs: AuditProofReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditFixtureMetadata {
    cases_path: String,
    crypto_fixture_path: String,
    withdrawal_fixture_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditArtifactMetadata {
    artifacts_root: String,
    commitment_manifest_path: String,
    withdrawal_manifest_path: String,
    commitment_artifact_version: String,
    withdrawal_artifact_version: String,
    commitment_zkey_sha256: String,
    withdrawal_zkey_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditRootReadReport {
    pool_state: core::RootRead,
    asp: core::RootRead,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditComparisonResult {
    name: String,
    inputs: AuditComparisonCase,
    master_keys: WireMasterKeys,
    deposit_secrets: AuditSecretPair,
    withdrawal_secrets: AuditSecretPair,
    precommitment_hash: String,
    commitment: WireCommitment,
    withdrawal_context_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditSecretPair {
    nullifier: String,
    secret: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditMerkleResult {
    name: String,
    leaves: Vec<String>,
    leaf: String,
    proof: AuditMerkleProof,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditMerkleProof {
    root: String,
    leaf: String,
    index: usize,
    siblings: Vec<String>,
}

#[derive(Debug, Clone)]
struct AuditHelperDurations {
    generate_master_keys: Duration,
    generate_deposit_secrets: Duration,
    generate_withdrawal_secrets: Duration,
    compute_precommitment_hash: Duration,
    build_commitment: Duration,
    calculate_withdrawal_context: Duration,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditPerformanceMetrics {
    helper_operations: AuditHelperPerformanceReport,
    proof_operations: AuditProofPerformanceReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditHelperPerformanceReport {
    generate_master_keys: AuditMetricSummary,
    generate_deposit_secrets: AuditMetricSummary,
    generate_withdrawal_secrets: AuditMetricSummary,
    compute_precommitment_hash: AuditMetricSummary,
    build_commitment: AuditMetricSummary,
    calculate_withdrawal_context: AuditMetricSummary,
    generate_merkle_proof: AuditMetricSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditProofPerformanceReport {
    prove_commitment: AuditMetricSummary,
    verify_commitment: AuditMetricSummary,
    prove_withdrawal: AuditMetricSummary,
    verify_withdrawal: AuditMetricSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditMetricSummary {
    iterations: usize,
    average_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditProofReport {
    commitment: AuditCommitmentProofReport,
    withdrawal: AuditWithdrawalProofReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditCommitmentProofReport {
    circuit_input: WireCommitmentCircuitInput,
    proof: core::ProofBundle,
    matches_request: bool,
    verified_by_rust: bool,
    tampered_rejected_by_rust: bool,
    formatted_proof: core::FormattedGroth16Proof,
    ragequit_plan: core::TransactionPlan,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditWithdrawalProofReport {
    circuit_input: WireWithdrawalCircuitInput,
    proof: core::ProofBundle,
    matches_request: bool,
    verified_by_rust: bool,
    tampered_rejected_by_rust: bool,
    formatted_proof: core::FormattedGroth16Proof,
    withdrawal_plan: core::TransactionPlan,
}

#[derive(Debug, Clone, Serialize)]
struct AuditVerifyProofResult {
    verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatefulParityFixture {
    session_lifecycle: StatefulSessionFixture,
    execution_lifecycle: StatefulExecutionFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatefulSessionFixture {
    crypto_fixture_path: String,
    withdrawal_fixture_path: String,
    artifacts_root: String,
    withdrawal_manifest_path: String,
    expected: StatefulSessionExpected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatefulSessionExpected {
    withdrawal_circuit: String,
    withdrawal_public_signals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatefulExecutionFixture {
    chain_id: u64,
    caller: String,
    pool_address: String,
    entrypoint_address: String,
    pool_code_hash: String,
    entrypoint_code_hash: String,
    valid_rpc_url: String,
    wrong_root_rpc_url: String,
    withdrawal: AuditWithdrawalFixture,
    signing_mnemonic: String,
    wrong_signing_mnemonic: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStatefulReport {
    runtime: String,
    fixture_path: String,
    backend_profile: String,
    trace: AuditStatefulTrace,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStatefulTrace {
    session_lifecycle: AuditStatefulSessionTrace,
    execution_lifecycle: AuditStatefulExecutionTrace,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct AuditStatefulSessionTrace {
    circuit: String,
    artifact_version: String,
    public_signals: Vec<String>,
    verified: bool,
    tampered_rejected: bool,
    removed: bool,
    stale_session_rejected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct AuditStatefulExecutionTrace {
    transaction: core::TransactionPlan,
    preflight: core::ExecutionPreflightReport,
    finalized_request: core::FinalizedTransactionRequest,
    submitted_receipt: core::TransactionReceiptSummary,
    wrong_chain_rejected: bool,
    wrong_code_hash_rejected: bool,
    wrong_root_rejected: bool,
    wrong_signer_rejected: bool,
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
        Some("audit-parity-report") => {
            audit_parity_report(AuditParityReportArgs::parse(args.collect())?)
        }
        Some("audit-verify-proof") => {
            audit_verify_proof(AuditVerifyProofArgs::parse(args.collect())?)
        }
        Some("audit-stateful-report") => {
            audit_stateful_report(AuditStatefulReportArgs::parse(args.collect())?)
        }
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
        "    flags: --manifest <path> --artifacts-root <path> [--backend stable] [--iterations n] [--warmup n] [--allow-debug-build] [--report-json path --device-label desktop|ios|android --device-model model]"
    );
    println!("  audit-parity-report");
    println!("    emit a machine-readable Rust parity report for the pinned audit fixtures");
    println!(
        "    flags: --cases-json <path> --commitment-manifest <path> --withdrawal-manifest <path> --artifacts-root <path> --report-json <path> [--backend stable]"
    );
    println!("  audit-verify-proof");
    println!("    verify one proof bundle against the pinned Rust proving artifacts");
    println!(
        "    flags: --circuit commitment|withdrawal --manifest <path> --artifacts-root <path> --proof-json <path> [--backend stable]"
    );
    println!("  audit-stateful-report");
    println!("    emit a machine-readable Rust stateful parity trace");
    println!("    flags: --input-json <path> --report-json <path> [--backend stable]");
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

impl AuditParityReportArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut cases_json = None;
        let mut commitment_manifest = None;
        let mut withdrawal_manifest = None;
        let mut artifacts_root = None;
        let mut backend = BackendProfile::Stable;
        let mut report_json = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--cases-json" => {
                    cases_json = Some(PathBuf::from(
                        iter.next().context("--cases-json requires a path value")?,
                    ));
                }
                "--commitment-manifest" => {
                    commitment_manifest = Some(PathBuf::from(
                        iter.next()
                            .context("--commitment-manifest requires a path value")?,
                    ));
                }
                "--withdrawal-manifest" => {
                    withdrawal_manifest = Some(PathBuf::from(
                        iter.next()
                            .context("--withdrawal-manifest requires a path value")?,
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
                "--report-json" => {
                    report_json = Some(PathBuf::from(
                        iter.next().context("--report-json requires a path value")?,
                    ));
                }
                other => bail!("unknown flag: {other}"),
            }
        }

        Ok(Self {
            cases_json: cases_json.context("--cases-json is required")?,
            commitment_manifest: commitment_manifest
                .context("--commitment-manifest is required")?,
            withdrawal_manifest: withdrawal_manifest
                .context("--withdrawal-manifest is required")?,
            artifacts_root: artifacts_root.context("--artifacts-root is required")?,
            backend,
            report_json: report_json.context("--report-json is required")?,
        })
    }
}

impl AuditStatefulReportArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut input_json = None;
        let mut backend = BackendProfile::Stable;
        let mut report_json = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--input-json" => {
                    input_json = Some(PathBuf::from(
                        iter.next().context("--input-json requires a path value")?,
                    ));
                }
                "--backend" => {
                    backend = parse_backend(&iter.next().context("--backend requires a value")?)?;
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
            input_json: input_json.context("--input-json is required")?,
            backend,
            report_json: report_json.context("--report-json is required")?,
        })
    }
}

impl AuditVerifyProofArgs {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut circuit = None;
        let mut manifest = None;
        let mut artifacts_root = None;
        let mut backend = BackendProfile::Stable;
        let mut proof_json = None;

        let mut iter = args.into_iter();
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--circuit" => {
                    circuit = Some(AuditCircuit::parse(
                        &iter.next().context("--circuit requires a value")?,
                    )?);
                }
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
                "--proof-json" => {
                    proof_json = Some(PathBuf::from(
                        iter.next().context("--proof-json requires a path value")?,
                    ));
                }
                other => bail!("unknown flag: {other}"),
            }
        }

        Ok(Self {
            circuit: circuit.context("--circuit is required")?,
            manifest: manifest.context("--manifest is required")?,
            artifacts_root: artifacts_root.context("--artifacts-root is required")?,
            backend,
            proof_json: proof_json.context("--proof-json is required")?,
        })
    }
}

impl AuditCircuit {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "commitment" => Ok(Self::Commitment),
            "withdrawal" => Ok(Self::Withdrawal),
            other => bail!("unsupported audit circuit: {other}"),
        }
    }
}

fn parse_backend(value: &str) -> Result<BackendProfile> {
    match value {
        "stable" => Ok(BackendProfile::Stable),
        _ => bail!("unsupported backend profile: {value}"),
    }
}

fn audit_parity_report(args: AuditParityReportArgs) -> Result<()> {
    let sdk = PrivacyPoolsSdk::new(BackendPolicy);
    let cases = read_audit_case_fixture(&args.cases_json)?;
    let commitment_manifest = read_manifest(&args.commitment_manifest)?;
    let withdrawal_manifest = read_manifest(&args.withdrawal_manifest)?;

    let commitment_bundle = sdk.load_verified_artifact_bundle(
        &commitment_manifest,
        &args.artifacts_root,
        "commitment",
    )?;
    let withdrawal_bundle =
        sdk.load_verified_artifact_bundle(&withdrawal_manifest, &args.artifacts_root, "withdraw")?;
    let commitment_session =
        sdk.prepare_commitment_circuit_session_from_bundle(commitment_bundle.clone())?;
    let withdrawal_session =
        sdk.prepare_withdrawal_circuit_session_from_bundle(withdrawal_bundle.clone())?;

    let mut helper_durations = Vec::with_capacity(cases.comparison_cases.len());
    let mut comparison_results = Vec::with_capacity(cases.comparison_cases.len());
    for case in &cases.comparison_cases {
        let (result, durations) = build_audit_comparison_result(&sdk, case)?;
        comparison_results.push(result);
        helper_durations.push(durations);
    }
    let mut merkle_durations = Vec::with_capacity(cases.merkle_cases.len());
    let mut merkle_results = Vec::with_capacity(cases.merkle_cases.len());
    for case in &cases.merkle_cases {
        let (result, duration) = build_audit_merkle_result(&sdk, case)?;
        merkle_results.push(result);
        merkle_durations.push(duration);
    }

    let withdrawal_request = reference_withdrawal_request(&sdk)?;
    let commitment_request = core::CommitmentWitnessRequest {
        commitment: withdrawal_request.commitment.clone(),
    };

    let commitment_input = sdk.build_commitment_circuit_input(&commitment_request)?;
    let commitment_prove_start = Instant::now();
    let commitment_proving =
        sdk.prove_commitment_with_session(args.backend, &commitment_session, &commitment_request)?;
    let commitment_prove_duration = commitment_prove_start.elapsed();
    sdk.validate_commitment_proof_against_request(&commitment_request, &commitment_proving.proof)?;
    let commitment_verify_start = Instant::now();
    let commitment_verified = sdk.verify_commitment_proof_with_session(
        args.backend,
        &commitment_session,
        &commitment_proving.proof,
    )?;
    let commitment_verify_duration = commitment_verify_start.elapsed();
    ensure!(
        commitment_verified,
        "generated commitment proof failed verification"
    );
    let mut tampered_commitment = commitment_proving.proof.clone();
    "9".clone_into(&mut tampered_commitment.public_signals[0]);
    let commitment_tampered_rejected = !sdk.verify_commitment_proof_with_session(
        args.backend,
        &commitment_session,
        &tampered_commitment,
    )?;
    let commitment_formatted = sdk.format_groth16_proof(&commitment_proving.proof)?;
    let ragequit_plan = sdk.plan_ragequit_transaction(
        1,
        address!("0987654321098765432109876543210987654321"),
        &commitment_proving.proof,
    )?;

    let withdrawal_input = sdk.build_withdrawal_circuit_input(&withdrawal_request)?;
    let withdrawal_prove_start = Instant::now();
    let withdrawal_proving =
        sdk.prove_withdrawal_with_session(args.backend, &withdrawal_session, &withdrawal_request)?;
    let withdrawal_prove_duration = withdrawal_prove_start.elapsed();
    sdk.validate_withdrawal_proof_against_request(&withdrawal_request, &withdrawal_proving.proof)?;
    let withdrawal_verify_start = Instant::now();
    let withdrawal_verified = sdk.verify_withdrawal_proof_with_session(
        args.backend,
        &withdrawal_session,
        &withdrawal_proving.proof,
    )?;
    let withdrawal_verify_duration = withdrawal_verify_start.elapsed();
    ensure!(
        withdrawal_verified,
        "generated withdrawal proof failed verification"
    );
    let mut tampered_withdrawal = withdrawal_proving.proof.clone();
    "9".clone_into(&mut tampered_withdrawal.public_signals[2]);
    let withdrawal_tampered_rejected = !sdk.verify_withdrawal_proof_with_session(
        args.backend,
        &withdrawal_session,
        &tampered_withdrawal,
    )?;
    let withdrawal_formatted = sdk.format_groth16_proof(&withdrawal_proving.proof)?;
    let withdrawal_plan = sdk.plan_withdrawal_transaction(
        1,
        address!("0987654321098765432109876543210987654321"),
        &withdrawal_request.withdrawal,
        &withdrawal_proving.proof,
    )?;

    let pool_address = address!("0987654321098765432109876543210987654321");
    let entrypoint_address = address!("1234567890123456789012345678901234567890");
    let report = AuditParityReport {
        generated_at_unix_seconds: unix_timestamp_now()?,
        git_commit: current_git_commit()?,
        sdk_version: PrivacyPoolsSdk::version().to_owned(),
        backend_profile: format!("{:?}", args.backend),
        backend_name: backend_name(args.backend).to_owned(),
        fixtures: AuditFixtureMetadata {
            cases_path: display_path(&args.cases_json),
            crypto_fixture_path: display_path(&fixture_path(
                "fixtures/vectors/crypto-compatibility.json",
            )?),
            withdrawal_fixture_path: display_path(&fixture_path(
                "fixtures/vectors/withdrawal-circuit-input.json",
            )?),
        },
        artifacts: AuditArtifactMetadata {
            artifacts_root: display_path(&args.artifacts_root),
            commitment_manifest_path: display_path(&args.commitment_manifest),
            withdrawal_manifest_path: display_path(&args.withdrawal_manifest),
            commitment_artifact_version: commitment_bundle.version().to_owned(),
            withdrawal_artifact_version: withdrawal_bundle.version().to_owned(),
            commitment_zkey_sha256: artifact_sha256(&commitment_bundle, ArtifactKind::Zkey)?,
            withdrawal_zkey_sha256: artifact_sha256(&withdrawal_bundle, ArtifactKind::Zkey)?,
        },
        root_reads: AuditRootReadReport {
            pool_state: sdk.plan_pool_state_root_read(pool_address),
            asp: sdk.plan_asp_root_read(entrypoint_address, pool_address),
        },
        cases: comparison_results,
        merkle_cases: merkle_results,
        performance: AuditPerformanceMetrics {
            helper_operations: AuditHelperPerformanceReport {
                generate_master_keys: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.generate_master_keys)
                        .collect(),
                )
                .context("missing generate_master_keys timings")?,
                generate_deposit_secrets: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.generate_deposit_secrets)
                        .collect(),
                )
                .context("missing generate_deposit_secrets timings")?,
                generate_withdrawal_secrets: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.generate_withdrawal_secrets)
                        .collect(),
                )
                .context("missing generate_withdrawal_secrets timings")?,
                compute_precommitment_hash: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.compute_precommitment_hash)
                        .collect(),
                )
                .context("missing compute_precommitment_hash timings")?,
                build_commitment: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.build_commitment)
                        .collect(),
                )
                .context("missing build_commitment timings")?,
                calculate_withdrawal_context: summarize_metric(
                    helper_durations
                        .iter()
                        .map(|value| value.calculate_withdrawal_context)
                        .collect(),
                )
                .context("missing calculate_withdrawal_context timings")?,
                generate_merkle_proof: summarize_metric(merkle_durations)
                    .context("missing generate_merkle_proof timings")?,
            },
            proof_operations: AuditProofPerformanceReport {
                prove_commitment: summarize_metric(vec![commitment_prove_duration])
                    .context("missing prove_commitment timing")?,
                verify_commitment: summarize_metric(vec![commitment_verify_duration])
                    .context("missing verify_commitment timing")?,
                prove_withdrawal: summarize_metric(vec![withdrawal_prove_duration])
                    .context("missing prove_withdrawal timing")?,
                verify_withdrawal: summarize_metric(vec![withdrawal_verify_duration])
                    .context("missing verify_withdrawal timing")?,
            },
        },
        proofs: AuditProofReport {
            commitment: AuditCommitmentProofReport {
                circuit_input: WireCommitmentCircuitInput::from(&commitment_input),
                proof: commitment_proving.proof,
                matches_request: true,
                verified_by_rust: true,
                tampered_rejected_by_rust: commitment_tampered_rejected,
                formatted_proof: commitment_formatted,
                ragequit_plan,
            },
            withdrawal: AuditWithdrawalProofReport {
                circuit_input: WireWithdrawalCircuitInput::from(&withdrawal_input),
                proof: withdrawal_proving.proof,
                matches_request: true,
                verified_by_rust: true,
                tampered_rejected_by_rust: withdrawal_tampered_rejected,
                formatted_proof: withdrawal_formatted,
                withdrawal_plan,
            },
        },
    };

    write_json_report(&args.report_json, &report)?;
    println!(
        "wrote audit parity report to {}",
        args.report_json.display()
    );
    Ok(())
}

fn audit_verify_proof(args: AuditVerifyProofArgs) -> Result<()> {
    let sdk = PrivacyPoolsSdk::new(BackendPolicy);
    let manifest = read_manifest(&args.manifest)?;
    let proof: core::ProofBundle = serde_json::from_slice(
        &fs::read(&args.proof_json)
            .with_context(|| format!("failed to read proof JSON {}", args.proof_json.display()))?,
    )
    .with_context(|| format!("failed to parse proof JSON {}", args.proof_json.display()))?;

    let verified = match args.circuit {
        AuditCircuit::Commitment => {
            let session =
                sdk.prepare_commitment_circuit_session(&manifest, &args.artifacts_root)?;
            sdk.verify_commitment_proof_with_session(args.backend, &session, &proof)?
        }
        AuditCircuit::Withdrawal => {
            let session =
                sdk.prepare_withdrawal_circuit_session(&manifest, &args.artifacts_root)?;
            sdk.verify_withdrawal_proof_with_session(args.backend, &session, &proof)?
        }
    };

    println!(
        "{}",
        serde_json::to_string(&AuditVerifyProofResult { verified })
            .context("failed to serialize verify-proof result")?
    );
    Ok(())
}

fn audit_stateful_report(args: AuditStatefulReportArgs) -> Result<()> {
    let fixture: StatefulParityFixture = read_json_file(&args.input_json)?;
    let trace = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime for stateful audit report")?
        .block_on(build_stateful_trace(&fixture, args.backend))?;
    let report = AuditStatefulReport {
        runtime: "rust".to_owned(),
        fixture_path: args.input_json.display().to_string(),
        backend_profile: format!("{:?}", args.backend),
        trace,
    };

    write_json_report(&args.report_json, &report)?;
    println!(
        "wrote audit stateful report to {}",
        args.report_json.display()
    );
    Ok(())
}

async fn build_stateful_trace(
    fixture: &StatefulParityFixture,
    backend: BackendProfile,
) -> Result<AuditStatefulTrace> {
    let sdk = PrivacyPoolsSdk::new(BackendPolicy);
    let request = build_reference_withdrawal_request(
        &sdk,
        &fixture.session_lifecycle.crypto_fixture_path,
        &fixture.session_lifecycle.withdrawal_fixture_path,
        None,
    )?;
    let manifest = read_manifest(&resolve_fixture_path(
        &fixture.session_lifecycle.withdrawal_manifest_path,
    )?)?;
    let artifacts_root = resolve_fixture_path(&fixture.session_lifecycle.artifacts_root)?;
    let bundle = sdk
        .load_verified_artifact_bundle(&manifest, &artifacts_root, "withdraw")
        .context("failed to load verified withdrawal artifact bundle")?;
    let key = SessionCacheKey::from_verified_bundle(backend, &bundle);
    let mut cache = SessionCache::new(1);
    let session = cache
        .get_or_prepare_withdrawal_from_bundle(&sdk, backend, bundle)
        .context("failed to prepare withdrawal session")?;
    let proving = sdk
        .prove_withdrawal_with_session(backend, &session, &request)
        .context("failed to prove withdrawal in stateful report")?;
    let verified = sdk
        .verify_withdrawal_proof_with_session(backend, &session, &proving.proof)
        .context("failed to verify withdrawal proof in stateful report")?;
    let mut tampered = proving.proof.clone();
    "9".clone_into(&mut tampered.public_signals[0]);
    let tampered_rejected = !sdk
        .verify_withdrawal_proof_with_session(backend, &session, &tampered)
        .context("failed to tamper-check withdrawal proof in stateful report")?;
    let removed = cache.remove(&key);
    let stale_session_rejected = cache.withdrawal(&key).is_none();
    let session_lifecycle = AuditStatefulSessionTrace {
        circuit: session.circuit().to_owned(),
        artifact_version: session.artifact_version().to_owned(),
        public_signals: proving.proof.public_signals.clone(),
        verified,
        tampered_rejected,
        removed,
        stale_session_rejected,
    };

    let execution_request = build_reference_withdrawal_request(
        &sdk,
        &fixture.session_lifecycle.crypto_fixture_path,
        &fixture.session_lifecycle.withdrawal_fixture_path,
        Some(core::Withdrawal {
            processor: Address::from_str(&fixture.execution_lifecycle.withdrawal.processooor)
                .context("failed to parse execution withdrawal processor")?,
            data: Bytes::from_str(&fixture.execution_lifecycle.withdrawal.data)
                .context("failed to parse execution withdrawal data")?,
        }),
    )?;
    let execution_lifecycle =
        build_stateful_execution_trace(&sdk, backend, fixture, &execution_request).await?;

    Ok(AuditStatefulTrace {
        session_lifecycle,
        execution_lifecycle,
    })
}

async fn build_stateful_execution_trace(
    sdk: &PrivacyPoolsSdk,
    backend: BackendProfile,
    fixture: &StatefulParityFixture,
    request: &core::WithdrawalWitnessRequest,
) -> Result<AuditStatefulExecutionTrace> {
    let execution = &fixture.execution_lifecycle;
    let manifest = read_manifest(&resolve_fixture_path(
        &fixture.session_lifecycle.withdrawal_manifest_path,
    )?)?;
    let artifacts_root = resolve_fixture_path(&fixture.session_lifecycle.artifacts_root)?;
    let session = sdk
        .prepare_withdrawal_circuit_session(&manifest, &artifacts_root)
        .context("failed to prepare execution withdrawal session")?;
    let proving = sdk
        .prove_withdrawal_with_session(backend, &session, request)
        .context("failed to prove execution withdrawal in stateful report")?;
    let verified = sdk
        .verify_withdrawal_proof_for_request_with_session(
            backend,
            &session,
            request,
            &proving.proof,
        )
        .context("failed to request-verify execution withdrawal proof in stateful report")?;
    let pool_address = Address::from_str(&execution.pool_address)
        .context("failed to parse stateful execution pool address")?;
    let policy = core::ExecutionPolicy {
        expected_chain_id: execution.chain_id,
        caller: Address::from_str(&execution.caller)
            .context("failed to parse stateful execution caller")?,
        expected_pool_code_hash: Some(
            B256::from_str(&execution.pool_code_hash)
                .context("failed to parse stateful pool code hash")?,
        ),
        expected_entrypoint_code_hash: Some(
            B256::from_str(&execution.entrypoint_code_hash)
                .context("failed to parse stateful entrypoint code hash")?,
        ),
        read_consistency: core::ReadConsistency::Latest,
        max_fee_quote_wei: None,
        mode: core::ExecutionPolicyMode::Strict,
    };
    let valid_client = chain::HttpExecutionClient::new(&execution.valid_rpc_url)
        .context("failed to create valid execution client")?;
    let preflight = sdk
        .preflight_verified_withdrawal_transaction_with_client(
            &core::WithdrawalExecutionConfig {
                chain_id: execution.chain_id,
                pool_address,
                policy: policy.clone(),
            },
            &verified,
            &valid_client,
        )
        .await
        .context("failed to preflight withdrawal in stateful report")?;
    let finalized = sdk
        .finalize_preflighted_transaction_with_client(preflight.clone(), &valid_client)
        .await
        .context("failed to finalize withdrawal in stateful report")?;
    let signer = LocalMnemonicSigner::from_phrase_nth(&execution.signing_mnemonic, 0)
        .context("failed to construct stateful signing mnemonic signer")?;
    let signed = signer
        .sign_transaction_request(finalized.request())
        .context("failed to sign finalized withdrawal request")?;
    let submitted = sdk
        .submit_finalized_preflighted_transaction_with_client(
            finalized.clone(),
            &signed,
            &valid_client,
        )
        .await
        .context("failed to submit finalized withdrawal request")?;

    let wrong_chain_rejected = sdk
        .preflight_verified_withdrawal_transaction_with_client(
            &core::WithdrawalExecutionConfig {
                chain_id: execution.chain_id + 1,
                pool_address,
                policy: policy.clone(),
            },
            &verified,
            &valid_client,
        )
        .await
        .is_err();
    let wrong_code_hash_rejected = sdk
        .preflight_verified_withdrawal_transaction_with_client(
            &core::WithdrawalExecutionConfig {
                chain_id: execution.chain_id,
                pool_address,
                policy: core::ExecutionPolicy {
                    expected_pool_code_hash: Some(B256::repeat_byte(0x11)),
                    ..policy.clone()
                },
            },
            &verified,
            &valid_client,
        )
        .await
        .is_err();
    let wrong_root_client = chain::HttpExecutionClient::new(&execution.wrong_root_rpc_url)
        .context("failed to create wrong-root execution client")?;
    let wrong_root_rejected = sdk
        .preflight_verified_withdrawal_transaction_with_client(
            &core::WithdrawalExecutionConfig {
                chain_id: execution.chain_id,
                pool_address,
                policy: policy.clone(),
            },
            &verified,
            &wrong_root_client,
        )
        .await
        .is_err();
    let wrong_signer = LocalMnemonicSigner::from_phrase_nth(&execution.wrong_signing_mnemonic, 0)
        .context("failed to construct wrong stateful signer")?;
    let wrong_signed = wrong_signer
        .sign_transaction_request(finalized.request())
        .context("failed to sign wrong-signer finalized request")?;
    let wrong_signer_rejected = sdk
        .submit_finalized_preflighted_transaction_with_client(
            finalized.clone(),
            &wrong_signed,
            &valid_client,
        )
        .await
        .is_err();

    Ok(AuditStatefulExecutionTrace {
        transaction: preflight.plan().clone(),
        preflight: preflight.preflight().clone(),
        finalized_request: finalized.request().clone(),
        submitted_receipt: submitted.receipt().clone(),
        wrong_chain_rejected,
        wrong_code_hash_rejected,
        wrong_root_rejected,
        wrong_signer_rejected,
    })
}

fn build_reference_withdrawal_request(
    sdk: &PrivacyPoolsSdk,
    crypto_fixture_path: &str,
    withdrawal_fixture_path: &str,
    override_withdrawal: Option<core::Withdrawal>,
) -> Result<core::WithdrawalWitnessRequest> {
    let crypto_fixture: Value = read_json_file(&resolve_fixture_path(crypto_fixture_path)?)?;
    let withdrawal_fixture: Value =
        read_json_file(&resolve_fixture_path(withdrawal_fixture_path)?)?;
    let keys = sdk
        .generate_master_keys(
            crypto_fixture["mnemonic"]
                .as_str()
                .context("crypto fixture mnemonic must be a string")?,
        )
        .context("failed to derive reference master keys")?;
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(
            &keys,
            U256::from_str(
                crypto_fixture["scope"]
                    .as_str()
                    .context("crypto fixture scope must be a string")?,
            )
            .context("failed to parse reference scope")?,
            U256::ZERO,
        )
        .context("failed to derive reference deposit secrets")?;

    Ok(core::WithdrawalWitnessRequest {
        commitment: sdk
            .build_commitment(
                U256::from_str(
                    withdrawal_fixture["existingValue"]
                        .as_str()
                        .context("withdrawal fixture existingValue must be a string")?,
                )
                .context("failed to parse existing value")?,
                U256::from_str(
                    withdrawal_fixture["label"]
                        .as_str()
                        .context("withdrawal fixture label must be a string")?,
                )
                .context("failed to parse label")?,
                deposit_nullifier,
                deposit_secret,
            )
            .context("failed to build reference commitment")?,
        withdrawal: override_withdrawal.unwrap_or(core::Withdrawal {
            processor: address!("1111111111111111111111111111111111111111"),
            data: bytes!("1234"),
        }),
        scope: U256::from_str(
            crypto_fixture["scope"]
                .as_str()
                .context("crypto fixture scope must be a string")?,
        )
        .context("failed to parse reference scope")?,
        withdrawal_amount: U256::from_str(
            withdrawal_fixture["withdrawalAmount"]
                .as_str()
                .context("withdrawal fixture withdrawalAmount must be a string")?,
        )
        .context("failed to parse withdrawal amount")?,
        state_witness: read_circuit_witness(
            withdrawal_fixture["stateWitness"]
                .as_object()
                .context("withdrawal fixture stateWitness must be an object")?,
        )?,
        asp_witness: read_circuit_witness(
            withdrawal_fixture["aspWitness"]
                .as_object()
                .context("withdrawal fixture aspWitness must be an object")?,
        )?,
        new_nullifier: U256::from_str(
            withdrawal_fixture["newNullifier"]
                .as_str()
                .context("withdrawal fixture newNullifier must be a string")?,
        )
        .context("failed to parse new nullifier")?
        .into(),
        new_secret: U256::from_str(
            withdrawal_fixture["newSecret"]
                .as_str()
                .context("withdrawal fixture newSecret must be a string")?,
        )
        .context("failed to parse new secret")?
        .into(),
    })
}

fn read_circuit_witness(
    witness: &serde_json::Map<String, Value>,
) -> Result<core::CircuitMerkleWitness> {
    Ok(core::CircuitMerkleWitness {
        root: U256::from_str(
            witness["root"]
                .as_str()
                .context("witness root must be a string")?,
        )
        .context("failed to parse witness root")?,
        leaf: U256::from_str(
            witness["leaf"]
                .as_str()
                .context("witness leaf must be a string")?,
        )
        .context("failed to parse witness leaf")?,
        index: witness["index"]
            .as_u64()
            .context("witness index must be a number")? as usize,
        siblings: witness["siblings"]
            .as_array()
            .context("witness siblings must be an array")?
            .iter()
            .map(|value| {
                U256::from_str(value.as_str().context("witness sibling must be a string")?)
                    .context("failed to parse witness sibling")
            })
            .collect::<Result<Vec<_>>>()?,
        depth: witness["depth"]
            .as_u64()
            .context("witness depth must be a number")? as usize,
    })
}

fn resolve_fixture_path(path: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(workspace_root()?.join(candidate))
    }
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("failed to read JSON fixture {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse JSON fixture {}", path.display()))
}

fn build_audit_comparison_result(
    sdk: &PrivacyPoolsSdk,
    case: &AuditComparisonCase,
) -> Result<(AuditComparisonResult, AuditHelperDurations)> {
    let scope = parse_u256_string(&case.scope)?;
    let label = parse_u256_string(&case.label)?;
    let deposit_index = parse_u256_string(&case.deposit_index)?;
    let withdrawal_index = parse_u256_string(&case.withdrawal_index)?;
    let value = parse_u256_string(&case.value)?;
    let generate_master_keys_start = Instant::now();
    let keys = sdk
        .generate_master_keys(&case.mnemonic)
        .with_context(|| format!("failed to derive master keys for {}", case.name))?;
    let generate_master_keys = generate_master_keys_start.elapsed();
    let generate_deposit_secrets_start = Instant::now();
    let (deposit_nullifier, deposit_secret) = sdk
        .generate_deposit_secrets(&keys, scope, deposit_index)
        .with_context(|| format!("failed to derive deposit secrets for {}", case.name))?;
    let generate_deposit_secrets = generate_deposit_secrets_start.elapsed();
    let generate_withdrawal_secrets_start = Instant::now();
    let (withdrawal_nullifier, withdrawal_secret) = sdk
        .generate_withdrawal_secrets(&keys, label, withdrawal_index)
        .with_context(|| format!("failed to derive withdrawal secrets for {}", case.name))?;
    let generate_withdrawal_secrets = generate_withdrawal_secrets_start.elapsed();
    let compute_precommitment_hash_start = Instant::now();
    let precommitment_hash = sdk
        .compute_precommitment_hash(deposit_nullifier.clone(), deposit_secret.clone())
        .with_context(|| format!("failed to compute precommitment hash for {}", case.name))?;
    let compute_precommitment_hash = compute_precommitment_hash_start.elapsed();
    let build_commitment_start = Instant::now();
    let commitment = sdk
        .build_commitment(
            value,
            label,
            deposit_nullifier.clone(),
            deposit_secret.clone(),
        )
        .with_context(|| format!("failed to build commitment for {}", case.name))?;
    let build_commitment = build_commitment_start.elapsed();
    let withdrawal = WireWithdrawal {
        processooor: case.withdrawal.processooor.clone(),
        data: case.withdrawal.data.clone(),
    }
    .try_into()
    .with_context(|| format!("failed to parse withdrawal payload for {}", case.name))?;
    let calculate_withdrawal_context_start = Instant::now();
    let withdrawal_context_hex = sdk
        .calculate_withdrawal_context(&withdrawal, scope)
        .with_context(|| format!("failed to calculate withdrawal context for {}", case.name))?;
    let calculate_withdrawal_context = calculate_withdrawal_context_start.elapsed();

    Ok((
        AuditComparisonResult {
            name: case.name.clone(),
            inputs: case.clone(),
            master_keys: WireMasterKeys::from(&keys),
            deposit_secrets: AuditSecretPair {
                nullifier: deposit_nullifier.to_decimal_string(),
                secret: deposit_secret.to_decimal_string(),
            },
            withdrawal_secrets: AuditSecretPair {
                nullifier: withdrawal_nullifier.to_decimal_string(),
                secret: withdrawal_secret.to_decimal_string(),
            },
            precommitment_hash: precommitment_hash.to_string(),
            commitment: WireCommitment::from(&commitment),
            withdrawal_context_hex,
        },
        AuditHelperDurations {
            generate_master_keys,
            generate_deposit_secrets,
            generate_withdrawal_secrets,
            compute_precommitment_hash,
            build_commitment,
            calculate_withdrawal_context,
        },
    ))
}

fn build_audit_merkle_result(
    sdk: &PrivacyPoolsSdk,
    case: &AuditMerkleCase,
) -> Result<(AuditMerkleResult, Duration)> {
    let leaves = case
        .leaves
        .iter()
        .map(|value| parse_u256_string(value))
        .collect::<Result<Vec<_>>>()?;
    let leaf = parse_u256_string(&case.leaf)?;
    let generate_merkle_proof_start = Instant::now();
    let proof = sdk
        .generate_merkle_proof(&leaves, leaf)
        .with_context(|| format!("failed to generate Merkle proof for {}", case.name))?;
    let generate_merkle_proof = generate_merkle_proof_start.elapsed();

    Ok((
        AuditMerkleResult {
            name: case.name.clone(),
            leaves: case.leaves.clone(),
            leaf: case.leaf.clone(),
            proof: AuditMerkleProof {
                root: proof.root.to_string(),
                leaf: proof.leaf.to_string(),
                index: proof.index,
                siblings: proof.siblings.iter().map(ToString::to_string).collect(),
            },
        },
        generate_merkle_proof,
    ))
}

fn read_audit_case_fixture(path: &Path) -> Result<AuditCaseFixture> {
    serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("failed to read audit cases {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse audit cases {}", path.display()))
}

fn read_manifest(path: &Path) -> Result<ArtifactManifest> {
    serde_json::from_slice(
        &fs::read(path).with_context(|| format!("failed to read manifest {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse manifest {}", path.display()))
}

fn artifact_sha256(
    bundle: &privacy_pools_sdk::artifacts::VerifiedArtifactBundle,
    kind: ArtifactKind,
) -> Result<String> {
    Ok(bundle
        .artifact(kind)
        .with_context(|| format!("verified bundle is missing {kind:?}"))?
        .descriptor()
        .sha256
        .clone())
}

fn fixture_path(relative: &str) -> Result<PathBuf> {
    Ok(workspace_root()?.join(relative))
}

fn display_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn unix_timestamp_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

fn parse_u256_string(value: &str) -> Result<U256> {
    U256::from_str(value)
        .with_context(|| format!("failed to parse decimal field element `{value}`"))
}

fn summarize_metric(durations: Vec<Duration>) -> Option<AuditMetricSummary> {
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

    Some(AuditMetricSummary {
        iterations: durations.len(),
        average_ms: duration_ms(average),
        min_ms: duration_ms(min),
        max_ms: duration_ms(max),
    })
}

fn benchmark_withdraw(args: BenchmarkArgs) -> Result<()> {
    ensure_release_build(args.allow_debug_build)?;

    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("failed to read manifest {}", args.manifest.display()))?;
    let manifest: ArtifactManifest = serde_json::from_slice(&manifest_bytes)
        .context("failed to parse artifact manifest JSON")?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);

    let sdk = PrivacyPoolsSdk::new(BackendPolicy);
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
    let artifact_bundle_sha256 = verified_bundle_sha256(&bundle)?;

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
                manifest_sha256,
                artifact_bundle_sha256,
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

fn write_json_report<T: Serialize>(report_path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create report directory {}", parent.display()))?;
    }
    fs::write(
        report_path,
        serde_json::to_vec_pretty(value).context("failed to serialize JSON report")?,
    )
    .with_context(|| format!("failed to write JSON report {}", report_path.display()))
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
        device_class: benchmark_device_class(args),
        cpu_model: detect_cpu_model()?,
        os_name: System::name().unwrap_or_else(|| env::consts::OS.to_owned()),
        os_version: System::long_os_version()
            .or_else(System::os_version)
            .unwrap_or_else(|| "unknown".to_owned()),
        rustc_version_verbose: command_stdout("rustc", &["-Vv"], "rustc -Vv failed")?,
        cargo_version: command_stdout("cargo", &["--version"], "cargo --version failed")?,
        benchmark_scenario_id: "withdraw-stable".to_owned(),
        artifact_version: context.artifact_version.to_owned(),
        zkey_sha256: context.zkey_sha256.to_owned(),
        manifest_sha256: context.manifest_sha256,
        artifact_bundle_sha256: context.artifact_bundle_sha256,
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

    write_json_report(report_path, &report)
}

fn benchmark_device_class(args: &BenchmarkArgs) -> String {
    format!(
        "{}-{}",
        args.device_label.as_deref().unwrap_or("desktop"),
        env::consts::ARCH
    )
}

fn detect_cpu_model() -> Result<String> {
    let workspace_root = workspace_root()?;

    if cfg!(target_os = "macos") {
        let cpu = command_stdout(
            "sysctl",
            &["-n", "machdep.cpu.brand_string"],
            "failed to detect macOS CPU model",
        )?;
        let trimmed = cpu.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }

    if cfg!(target_os = "linux") {
        let cpu = Command::new("sh")
            .args(["-lc", "lscpu | awk -F: '/Model name/ {print $2; exit}'"])
            .current_dir(&workspace_root)
            .output()
            .context("failed to detect Linux CPU model")?;
        ensure!(cpu.status.success(), "failed to detect Linux CPU model");
        let trimmed = String::from_utf8(cpu.stdout)
            .context("Linux CPU model output was not utf-8")?
            .trim()
            .to_owned();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    Ok(env::consts::ARCH.to_owned())
}

fn command_stdout(program: &str, args: &[&str], error_context: &str) -> Result<String> {
    let workspace_root = workspace_root()?;
    let output = Command::new(program)
        .args(args)
        .current_dir(workspace_root)
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    ensure!(output.status.success(), "{error_context}");
    Ok(String::from_utf8(output.stdout)
        .context("command output was not utf-8")?
        .trim()
        .to_owned())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_args_require_device_metadata_when_writing_a_report() {
        let error = BenchmarkArgs::parse(vec![
            "--manifest".to_owned(),
            "manifest.json".to_owned(),
            "--artifacts-root".to_owned(),
            "artifacts".to_owned(),
            "--report-json".to_owned(),
            "report.json".to_owned(),
        ])
        .expect_err("report output without device metadata must fail");

        assert!(
            error
                .to_string()
                .contains("--device-label is required when --report-json is set")
        );
    }

    #[test]
    fn audit_parity_report_args_require_cases_json() {
        let error = AuditParityReportArgs::parse(vec![
            "--commitment-manifest".to_owned(),
            "commitment.json".to_owned(),
            "--withdrawal-manifest".to_owned(),
            "withdrawal.json".to_owned(),
            "--artifacts-root".to_owned(),
            "artifacts".to_owned(),
            "--report-json".to_owned(),
            "report.json".to_owned(),
        ])
        .expect_err("missing cases json must fail");

        assert!(error.to_string().contains("--cases-json is required"));
    }

    #[test]
    fn parse_backend_rejects_unknown_profiles() {
        let error = parse_backend("fast").expect_err("unknown backend profile must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported backend profile: fast")
        );
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn verified_bundle_sha256(
    bundle: &privacy_pools_sdk::artifacts::VerifiedArtifactBundle,
) -> Result<String> {
    let mut digest = Sha256::new();
    for artifact in bundle.artifacts() {
        digest.update(bundle.circuit().as_bytes());
        digest.update([0]);
        digest.update(format!("{:?}", artifact.descriptor().kind).as_bytes());
        digest.update([0]);
        digest.update(artifact.descriptor().filename.as_bytes());
        digest.update([0]);
        digest.update(artifact.descriptor().sha256.as_bytes());
        digest.update([0]);
        digest.update(artifact.bytes());
        digest.update([0xff]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn backend_name(_profile: BackendProfile) -> &'static str {
    "stable"
}

fn current_git_commit() -> Result<String> {
    let workspace_root = workspace_root()?;
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(workspace_root)
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

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("failed to resolve workspace root")
}
