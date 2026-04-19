import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
export const packageRoot = join(scriptDir, "..");
export const workspaceRoot = join(packageRoot, "..", "..");
export const fixturesRoot = join(workspaceRoot, "fixtures");
export const artifactsRoot = join(fixturesRoot, "artifacts");
export const withdrawalManifestPath = join(
  artifactsRoot,
  "withdrawal-proving-manifest.json",
);
export const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");
export const withdrawalFixture = readFixtureJson("vectors/withdrawal-circuit-input.json");

export function readFixtureText(path) {
  return readFileSync(join(fixturesRoot, path), "utf8");
}

export function readFixtureJson(path) {
  return JSON.parse(readFixtureText(path));
}

export function readPackageVersion() {
  return JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")).version;
}

export function currentGitCommit() {
  return commandStdout("git", ["rev-parse", "HEAD"], workspaceRoot);
}

export function rustcVerbose() {
  return commandStdout("rustc", ["-Vv"], workspaceRoot);
}

export function cargoVersion() {
  return commandStdout("cargo", ["--version"], workspaceRoot);
}

export function hostOsVersion() {
  return `${os.platform()} ${os.release()}`;
}

export function detectCpuModel() {
  return os.cpus()[0]?.model ?? "unknown-cpu";
}

export function sha256Hex(value) {
  const digest = createHash("sha256");
  digest.update(value);
  return digest.digest("hex");
}

export function manifestFingerprint(manifestJson, artifactsRootPath) {
  const manifestBytes = Buffer.from(manifestJson, "utf8");
  const manifest = JSON.parse(manifestJson);
  const entries = [];
  const artifacts = [];
  let zkeySha256 = null;

  for (const artifact of manifest.artifacts ?? []) {
    const artifactPath = join(artifactsRootPath, artifact.filename);
    const sha256 = artifact.sha256 ?? sha256Hex(readFileSync(artifactPath));
    if (artifact.kind === "zkey" && zkeySha256 == null) {
      zkeySha256 = sha256;
    }
    entries.push(
      `${artifact.circuit}:${artifact.kind}:${artifact.filename}:${sha256}`,
    );
    artifacts.push({
      circuit: artifact.circuit,
      kind: artifact.kind,
      filename: artifact.filename,
      sha256,
    });
  }

  entries.sort();
  artifacts.sort((left, right) => left.filename.localeCompare(right.filename));

  return {
    manifestSha256: sha256Hex(manifestBytes),
    artifactBundleSha256: sha256Hex(Buffer.from(entries.join("\n"), "utf8")),
    zkeySha256,
    artifacts,
    version: manifest.version,
  };
}

export function summarize(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const averageMs = values.reduce((sum, value) => sum + value, 0) / values.length;
  return {
    average_ms: averageMs,
    min_ms: sorted[0] ?? 0,
    max_ms: sorted.at(-1) ?? 0,
  };
}

export function buildBenchmarkReport({
  deviceLabel,
  deviceModel,
  deviceClass,
  samples,
  artifactResolutionMs,
  bundleVerificationMs,
  sessionPreloadMs,
  peakResidentMemoryBytes = null,
  manifestPath = withdrawalManifestPath,
  artifactsRootPath = artifactsRoot,
  benchmarkScenarioId = "withdraw-stable",
}) {
  const manifestJson = readFileSync(manifestPath, "utf8");
  const fingerprint = manifestFingerprint(manifestJson, artifactsRootPath);
  const inputPreparationValues = samples.map((sample) => sample.inputPreparationMs);
  const witnessGenerationValues = samples.map((sample) => sample.witnessGenerationMs);
  const proofGenerationValues = samples.map((sample) => sample.proofGenerationMs);
  const verificationValues = samples.map((sample) => sample.verificationMs);
  const proveAndVerifyValues = samples.map((sample) => sample.proveAndVerifyMs);
  const firstSample = samples[0] ?? {
    inputPreparationMs: 0,
    witnessGenerationMs: 0,
    proofGenerationMs: 0,
    verificationMs: 0,
    proveAndVerifyMs: 0,
  };

  return {
    generated_at_unix_seconds: Math.floor(Date.now() / 1000),
    git_commit: currentGitCommit(),
    sdk_version: readPackageVersion(),
    backend_profile: "Stable",
    backend_name: "stable",
    device_label: deviceLabel,
    device_model: deviceModel,
    device_class: deviceClass,
    cpu_model: detectCpuModel(),
    os_name: os.platform(),
    os_version: hostOsVersion(),
    rustc_version_verbose: rustcVerbose(),
    cargo_version: cargoVersion(),
    benchmark_scenario_id: benchmarkScenarioId,
    artifact_version: fingerprint.version,
    zkey_sha256: fingerprint.zkeySha256,
    manifest_sha256: fingerprint.manifestSha256,
    artifact_bundle_sha256: fingerprint.artifactBundleSha256,
    manifest_path: manifestPath,
    artifacts_root: artifactsRootPath,
    artifact_resolution_ms: artifactResolutionMs,
    bundle_verification_ms: bundleVerificationMs,
    session_preload_ms: sessionPreloadMs,
    first_input_preparation_ms: firstSample.inputPreparationMs,
    first_witness_generation_ms: firstSample.witnessGenerationMs,
    first_proof_generation_ms: firstSample.proofGenerationMs,
    first_verification_ms: firstSample.verificationMs,
    first_prove_and_verify_ms: firstSample.proveAndVerifyMs,
    peak_resident_memory_bytes: peakResidentMemoryBytes,
    iterations: samples.length,
    warmup: 0,
    input_preparation: summarize(inputPreparationValues),
    witness_generation: summarize(witnessGenerationValues),
    proof_generation: summarize(proofGenerationValues),
    verification: summarize(verificationValues),
    prove_and_verify: summarize(proveAndVerifyValues),
    samples: samples.map((sample, index) => ({
      iteration: index + 1,
      input_preparation_ms: sample.inputPreparationMs,
      witness_generation_ms: sample.witnessGenerationMs,
      proof_generation_ms: sample.proofGenerationMs,
      verification_ms: sample.verificationMs,
      prove_and_verify_ms: sample.proveAndVerifyMs,
    })),
  };
}

export function writeReport(path, report) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
}

export function nowMs() {
  return Date.now();
}

export function peakRssBytes() {
  return process.memoryUsage().rss;
}

function commandStdout(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
  }).trim();
}
