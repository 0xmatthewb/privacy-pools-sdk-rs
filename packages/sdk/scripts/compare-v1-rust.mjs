import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const V1_PACKAGE = "@0xbow/privacy-pools-core-sdk";
const V1_VERSION = "1.2.0";
const HELPER_THRESHOLD_RATIO = 1.05;
const PROOF_THRESHOLD_RATIO = 1.15;

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");
const defaultV1PackageRoot = join(
  packageRoot,
  "node_modules",
  "@0xbow",
  "privacy-pools-core-sdk",
);

const v1PackageRoot = process.env.PRIVACY_POOLS_V1_BASELINE_PATH ?? defaultV1PackageRoot;
const v1SourceRoot = process.env.PRIVACY_POOLS_V1_SOURCE_PATH ?? null;
const reportPath =
  process.env.PRIVACY_POOLS_COMPARE_RUST_REPORT ??
  join(workspaceRoot, "dist", "v1-rust-comparison.json");
const rustReportPath =
  process.env.PRIVACY_POOLS_COMPARE_RUST_CLI_REPORT ??
  join(workspaceRoot, "dist", "v1-rust-parity-rust.json");

const parityCases = readFixtureJson("vectors/audit-parity-cases.json");
const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");
const withdrawalFixture = readFixtureJson("vectors/withdrawal-circuit-input.json");
const commitmentManifestPath = join(fixturesRoot, "artifacts", "commitment-proving-manifest.json");
const withdrawalManifestPath = join(fixturesRoot, "artifacts", "withdrawal-proving-manifest.json");
const artifactsRoot = join(fixturesRoot, "artifacts");

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  assert.ok(
    existsSync(v1PackageRoot),
    `missing pinned ${V1_PACKAGE}@${V1_VERSION} baseline at ${v1PackageRoot}; run npm ci in packages/sdk`,
  );
  const resolvedV1PackageRoot = v1PackageRoot;
  const resolvedV1SourceRoot =
    process.env.PRIVACY_POOLS_V1_SOURCE_PATH ??
    (v1SourceRoot && existsSync(v1SourceRoot) ? v1SourceRoot : null);
  const v1 = await import(pathToFileURL(join(resolvedV1PackageRoot, "dist", "esm", "index.mjs")));
  const rustReport = runRustParityReport();
  const server = createArtifactServer();

  try {
    await server.start();
    const safety = await runSafetyComparisons(v1, rustReport, server);
    const performance = await runPerformanceComparisons(v1, rustReport, server);
    const report = {
      generatedAt: new Date().toISOString(),
      gitCommit: rustReport.gitCommit,
      sdkVersion: rustReport.sdkVersion,
      baseline: {
        packagePath: resolvedV1PackageRoot,
        sourcePath: resolvedV1SourceRoot,
        version: V1_VERSION,
        currentRootSemanticFix:
          "Rust treats pool state roots as Privacy Pool currentRoot() values, not Entrypoint latestRoot() values.",
      },
      rustReportPath,
      rust: rustReport,
      safety,
      performance,
    };

    mkdirSync(dirname(reportPath), { recursive: true });
    writeFileSync(reportPath, `${JSON.stringify(report, replacer, 2)}\n`);
    console.log(`rust-v1 safety checks passed: ${safety.passed}`);
    console.log(`wrote comparison report to ${reportPath}`);
    if (safety.failed > 0 || performance.regressions.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    await server.stop();
  }
}

function runRustParityReport() {
  execFileSync(
    "cargo",
    [
      "run",
      "--release",
      "-p",
      "privacy-pools-sdk-cli",
      "--",
      "audit-parity-report",
      "--cases-json",
      join(fixturesRoot, "vectors", "audit-parity-cases.json"),
      "--commitment-manifest",
      commitmentManifestPath,
      "--withdrawal-manifest",
      withdrawalManifestPath,
      "--artifacts-root",
      artifactsRoot,
      "--report-json",
      rustReportPath,
    ],
    {
      cwd: workspaceRoot,
      stdio: "inherit",
    },
  );

  return JSON.parse(readFileSync(rustReportPath, "utf8"));
}

async function runSafetyComparisons(v1, rustReport, server) {
  const checks = [];
  const failures = [];

  const v1Circuits = new v1.Circuits({ baseUrl: `${server.origin}/`, browser: true });
  const v1Sdk = new v1.PrivacyPoolSDK(v1Circuits);

  const rustCaseMap = new Map(rustReport.cases.map((entry) => [entry.name, entry]));
  for (const caseFixture of parityCases.comparisonCases) {
    const rustCase = rustCaseMap.get(caseFixture.name);
    assert.ok(rustCase, `missing Rust parity case ${caseFixture.name}`);
    assert.ok(
      caseFixture.expected,
      `missing checked-in expected outputs for ${caseFixture.name}`,
    );
    const expected = caseFixture.expected;

    const keys = normalizeBigints(v1.generateMasterKeys(caseFixture.mnemonic));
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: generateMasterKeys snapshot`,
      deepEqual(keys, expected.masterKeys),
      { expected: expected.masterKeys, actual: keys },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust generateMasterKeys snapshot`,
      deepEqual(rustCase.masterKeys, expected.masterKeys),
      { expected: expected.masterKeys, actual: rustCase.masterKeys },
    );

    const depositSecrets = normalizeBigints(
      v1.generateDepositSecrets(
        v1.generateMasterKeys(caseFixture.mnemonic),
        BigInt(caseFixture.scope),
        BigInt(caseFixture.depositIndex),
      ),
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: generateDepositSecrets snapshot`,
      deepEqual(depositSecrets, expected.depositSecrets),
      { expected: expected.depositSecrets, actual: depositSecrets },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust generateDepositSecrets snapshot`,
      deepEqual(rustCase.depositSecrets, expected.depositSecrets),
      { expected: expected.depositSecrets, actual: rustCase.depositSecrets },
    );

    const withdrawalSecrets = normalizeBigints(
      v1.generateWithdrawalSecrets(
        v1.generateMasterKeys(caseFixture.mnemonic),
        BigInt(caseFixture.label),
        BigInt(caseFixture.withdrawalIndex),
      ),
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: generateWithdrawalSecrets snapshot`,
      deepEqual(withdrawalSecrets, expected.withdrawalSecrets),
      { expected: expected.withdrawalSecrets, actual: withdrawalSecrets },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust generateWithdrawalSecrets snapshot`,
      deepEqual(rustCase.withdrawalSecrets, expected.withdrawalSecrets),
      { expected: expected.withdrawalSecrets, actual: rustCase.withdrawalSecrets },
    );

    const precommitmentHash = String(
      v1.hashPrecommitment(BigInt(depositSecrets.nullifier), BigInt(depositSecrets.secret)),
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: hashPrecommitment snapshot`,
      precommitmentHash === expected.precommitmentHash,
      { expected: expected.precommitmentHash, actual: precommitmentHash },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust hashPrecommitment snapshot`,
      rustCase.precommitmentHash === expected.precommitmentHash,
      { expected: expected.precommitmentHash, actual: rustCase.precommitmentHash },
    );

    const commitment = normalizeCommitment(
      v1.getCommitment(
        BigInt(caseFixture.value),
        BigInt(caseFixture.label),
        BigInt(depositSecrets.nullifier),
        BigInt(depositSecrets.secret),
      ),
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: getCommitment snapshot`,
      deepEqual(commitment, expected.commitment),
      { expected: expected.commitment, actual: commitment },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust getCommitment snapshot`,
      deepEqual(rustCase.commitment, expected.commitment),
      { expected: expected.commitment, actual: rustCase.commitment },
    );

    const context = String(
      v1.calculateContext(caseFixture.withdrawal, BigInt(caseFixture.scope)),
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: calculateContext snapshot`,
      context === expected.withdrawalContextHex,
      { expected: expected.withdrawalContextHex, actual: context },
    );
    recordCheck(
      checks,
      failures,
      `${caseFixture.name}: rust calculateContext snapshot`,
      rustCase.withdrawalContextHex === expected.withdrawalContextHex,
      { expected: expected.withdrawalContextHex, actual: rustCase.withdrawalContextHex },
    );
  }

  const rustMerkleMap = new Map(rustReport.merkleCases.map((entry) => [entry.name, entry]));
  for (const merkleCase of parityCases.merkleCases) {
    const rustMerkle = rustMerkleMap.get(merkleCase.name);
    assert.ok(rustMerkle, `missing Rust merkle case ${merkleCase.name}`);
    const v1Merkle = normalizeBigints(
      v1.generateMerkleProof(
        merkleCase.leaves.map(BigInt),
        BigInt(merkleCase.leaf),
      ),
    );
    recordCheck(
      checks,
      failures,
      `${merkleCase.name}: generateMerkleProof`,
      deepEqual(
        normalizeMerkleProof(v1Merkle),
        normalizeMerkleProof(rustMerkle.proof),
      ),
      {
        expected: normalizeMerkleProof(v1Merkle),
        actual: normalizeMerkleProof(rustMerkle.proof),
      },
    );
  }

  const rustCommitmentProof = rustReport.proofs.commitment.proof;
  const rustWithdrawalProof = rustReport.proofs.withdrawal.proof;
  const v1Commitment = v1.getCommitment(
    BigInt(withdrawalFixture.existingValue),
    BigInt(withdrawalFixture.label),
    BigInt(cryptoFixture.depositSecrets.nullifier),
    BigInt(cryptoFixture.depositSecrets.secret),
  );
  const v1CommitmentProof = await v1Sdk.proveCommitment(
    BigInt(withdrawalFixture.existingValue),
    BigInt(withdrawalFixture.label),
    BigInt(cryptoFixture.depositSecrets.nullifier),
    BigInt(cryptoFixture.depositSecrets.secret),
  );
  const v1WithdrawalProof = await v1Sdk.proveWithdrawal(
    v1Commitment,
    referenceV1WithdrawalInput(v1),
  );

  recordCheck(
    checks,
    failures,
    "commitment proof publicSignals",
    deepEqual(
      stringArray(v1CommitmentProof.publicSignals),
      stringArray(rustCommitmentProof.public_signals),
    ),
    {
      expected: stringArray(v1CommitmentProof.publicSignals),
      actual: stringArray(rustCommitmentProof.public_signals),
    },
  );
  recordCheck(
    checks,
    failures,
    "withdrawal proof publicSignals",
    deepEqual(
      stringArray(v1WithdrawalProof.publicSignals),
      stringArray(rustWithdrawalProof.public_signals),
    ),
    {
      expected: stringArray(v1WithdrawalProof.publicSignals),
      actual: stringArray(rustWithdrawalProof.public_signals),
    },
  );

  recordCheck(
    checks,
    failures,
    "rust verifies v1 commitment proof",
    verifyProofWithRustCli("commitment", commitmentManifestPath, normalizeProofForRust(v1CommitmentProof)),
    {},
  );
  recordCheck(
    checks,
    failures,
    "rust verifies v1 withdrawal proof",
    verifyProofWithRustCli("withdrawal", withdrawalManifestPath, normalizeProofForRust(v1WithdrawalProof)),
    {},
  );
  recordCheck(
    checks,
    failures,
    "v1 verifies rust commitment proof",
    await v1Sdk.verifyCommitment(normalizeProofForV1(rustCommitmentProof)),
    {},
  );
  recordCheck(
    checks,
    failures,
    "v1 verifies rust withdrawal proof",
    await v1Sdk.verifyWithdrawal(normalizeProofForV1(rustWithdrawalProof)),
    {},
  );

  const tamperedV1Commitment = normalizeProofForRust(v1CommitmentProof);
  tamperedV1Commitment.public_signals[0] = "9";
  recordCheck(
    checks,
    failures,
    "rust rejects tampered v1 commitment proof",
    !verifyProofWithRustCli("commitment", commitmentManifestPath, tamperedV1Commitment),
    {},
  );
  const tamperedV1Withdrawal = normalizeProofForRust(v1WithdrawalProof);
  tamperedV1Withdrawal.public_signals[2] = "9";
  recordCheck(
    checks,
    failures,
    "rust rejects tampered v1 withdrawal proof",
    !verifyProofWithRustCli("withdrawal", withdrawalManifestPath, tamperedV1Withdrawal),
    {},
  );
  const tamperedRustCommitment = normalizeProofForV1(rustCommitmentProof);
  tamperedRustCommitment.publicSignals[0] = "9";
  recordCheck(
    checks,
    failures,
    "v1 rejects tampered rust commitment proof",
    !(await v1Sdk.verifyCommitment(tamperedRustCommitment)),
    {},
  );
  const tamperedRustWithdrawal = normalizeProofForV1(rustWithdrawalProof);
  tamperedRustWithdrawal.publicSignals[2] = "9";
  recordCheck(
    checks,
    failures,
    "v1 rejects tampered rust withdrawal proof",
    !(await v1Sdk.verifyWithdrawal(tamperedRustWithdrawal)),
    {},
  );

  recordCheck(
    checks,
    failures,
    "rust pool state root read uses pool_state kind",
    rustReport.rootReads.poolState?.kind === "pool_state",
    { actual: rustReport.rootReads.poolState },
  );
  recordCheck(
    checks,
    failures,
    "rust pool state root read targets currentRoot call data",
    rustReport.rootReads.poolState?.contract_address ===
      rustReport.rootReads.poolState?.pool_address,
    { actual: rustReport.rootReads.poolState },
  );

  return {
    passed: checks.filter((check) => check.passed).length,
    failed: failures.length,
    checks,
    failures,
  };
}

async function runPerformanceComparisons(v1, rustReport, server) {
  const v1Circuits = new v1.Circuits({ baseUrl: `${server.origin}/`, browser: true });
  const v1Sdk = new v1.PrivacyPoolSDK(v1Circuits);

  const helperMetrics = {
    generateMasterKeys: summarize(
      parityCases.comparisonCases.map((testCase) =>
        measureSync(() => v1.generateMasterKeys(testCase.mnemonic)),
      ),
    ),
    generateDepositSecrets: summarize(
      parityCases.comparisonCases.map((testCase) =>
        measureSync(() =>
          v1.generateDepositSecrets(
            v1.generateMasterKeys(testCase.mnemonic),
            BigInt(testCase.scope),
            BigInt(testCase.depositIndex),
          ),
        ),
      ),
    ),
    generateWithdrawalSecrets: summarize(
      parityCases.comparisonCases.map((testCase) =>
        measureSync(() =>
          v1.generateWithdrawalSecrets(
            v1.generateMasterKeys(testCase.mnemonic),
            BigInt(testCase.label),
            BigInt(testCase.withdrawalIndex),
          ),
        ),
      ),
    ),
    computePrecommitmentHash: summarize(
      parityCases.comparisonCases.map((testCase) => {
        const keys = v1.generateMasterKeys(testCase.mnemonic);
        const secrets = v1.generateDepositSecrets(
          keys,
          BigInt(testCase.scope),
          BigInt(testCase.depositIndex),
        );
        return measureSync(() =>
          v1.hashPrecommitment(secrets.nullifier, secrets.secret),
        );
      }),
    ),
    buildCommitment: summarize(
      parityCases.comparisonCases.map((testCase) => {
        const keys = v1.generateMasterKeys(testCase.mnemonic);
        const secrets = v1.generateDepositSecrets(
          keys,
          BigInt(testCase.scope),
          BigInt(testCase.depositIndex),
        );
        return measureSync(() =>
          v1.getCommitment(
            BigInt(testCase.value),
            BigInt(testCase.label),
            secrets.nullifier,
            secrets.secret,
          ),
        );
      }),
    ),
    calculateWithdrawalContext: summarize(
      parityCases.comparisonCases.map((testCase) =>
        measureSync(() =>
          v1.calculateContext(testCase.withdrawal, BigInt(testCase.scope)),
        ),
      ),
    ),
    generateMerkleProof: summarize(
      parityCases.merkleCases.map((testCase) =>
        measureSync(() =>
          v1.generateMerkleProof(testCase.leaves.map(BigInt), BigInt(testCase.leaf)),
        ),
      ),
    ),
  };

  const v1CommitmentProof = await measureAsync(() =>
    v1Sdk.proveCommitment(
      BigInt(withdrawalFixture.existingValue),
      BigInt(withdrawalFixture.label),
      BigInt(cryptoFixture.depositSecrets.nullifier),
      BigInt(cryptoFixture.depositSecrets.secret),
    ),
  );
  const v1CommitmentProofBundle = v1CommitmentProof.result;
  const v1CommitmentVerify = await measureAsync(() =>
    v1Sdk.verifyCommitment(v1CommitmentProofBundle),
  );

  const v1Commitment = v1.getCommitment(
    BigInt(withdrawalFixture.existingValue),
    BigInt(withdrawalFixture.label),
    BigInt(cryptoFixture.depositSecrets.nullifier),
    BigInt(cryptoFixture.depositSecrets.secret),
  );
  const v1WithdrawalProof = await measureAsync(() =>
    v1Sdk.proveWithdrawal(v1Commitment, referenceV1WithdrawalInput(v1)),
  );
  const v1WithdrawalProofBundle = v1WithdrawalProof.result;
  const v1WithdrawalVerify = await measureAsync(() =>
    v1Sdk.verifyWithdrawal(v1WithdrawalProofBundle),
  );

  const rustHelpers = rustReport.performance.helperOperations;
  const rustProofs = rustReport.performance.proofOperations;
  const metrics = {
    generateMasterKeys: compareMetric(
      helperMetrics.generateMasterKeys,
      rustHelpers.generateMasterKeys,
      HELPER_THRESHOLD_RATIO,
    ),
    generateDepositSecrets: compareMetric(
      helperMetrics.generateDepositSecrets,
      rustHelpers.generateDepositSecrets,
      HELPER_THRESHOLD_RATIO,
    ),
    generateWithdrawalSecrets: compareMetric(
      helperMetrics.generateWithdrawalSecrets,
      rustHelpers.generateWithdrawalSecrets,
      HELPER_THRESHOLD_RATIO,
    ),
    computePrecommitmentHash: compareMetric(
      helperMetrics.computePrecommitmentHash,
      rustHelpers.computePrecommitmentHash,
      HELPER_THRESHOLD_RATIO,
    ),
    buildCommitment: compareMetric(
      helperMetrics.buildCommitment,
      rustHelpers.buildCommitment,
      HELPER_THRESHOLD_RATIO,
    ),
    calculateWithdrawalContext: compareMetric(
      helperMetrics.calculateWithdrawalContext,
      rustHelpers.calculateWithdrawalContext,
      HELPER_THRESHOLD_RATIO,
    ),
    generateMerkleProof: compareMetric(
      helperMetrics.generateMerkleProof,
      rustHelpers.generateMerkleProof,
      HELPER_THRESHOLD_RATIO,
    ),
    proveCommitment: compareMetric(
      summarize([v1CommitmentProof.durationMs]),
      rustProofs.proveCommitment,
      PROOF_THRESHOLD_RATIO,
    ),
    verifyCommitment: compareMetric(
      summarize([v1CommitmentVerify.durationMs]),
      rustProofs.verifyCommitment,
      PROOF_THRESHOLD_RATIO,
    ),
    proveWithdrawal: compareMetric(
      summarize([v1WithdrawalProof.durationMs]),
      rustProofs.proveWithdrawal,
      PROOF_THRESHOLD_RATIO,
    ),
    verifyWithdrawal: compareMetric(
      summarize([v1WithdrawalVerify.durationMs]),
      rustProofs.verifyWithdrawal,
      PROOF_THRESHOLD_RATIO,
    ),
  };

  const regressions = Object.entries(metrics)
    .filter(([, metric]) => !metric.withinThreshold)
    .map(([name, metric]) => ({ name, ...metric }));

  return {
    thresholds: {
      helperMaxRatio: HELPER_THRESHOLD_RATIO,
      proofMaxRatio: PROOF_THRESHOLD_RATIO,
    },
    metrics,
    regressions,
  };
}

function verifyProofWithRustCli(circuit, manifestPath, proofBundle) {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rust-proof-"));
  const proofPath = join(tempRoot, "proof.json");

  try {
    writeFileSync(proofPath, `${JSON.stringify(proofBundle)}\n`);
    const output = execFileSync(
      "cargo",
      [
        "run",
        "--release",
        "-p",
        "privacy-pools-sdk-cli",
        "--",
        "audit-verify-proof",
        "--circuit",
        circuit,
        "--manifest",
        manifestPath,
        "--artifacts-root",
        artifactsRoot,
        "--proof-json",
        proofPath,
      ],
      {
        cwd: workspaceRoot,
        encoding: "utf8",
      },
    );
    return JSON.parse(output).verified === true;
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function compareMetric(v1Metric, rustMetric, thresholdRatio) {
  const rustToV1Ratio = rustMetric.averageMs / v1Metric.averageMs;
  return {
    thresholdRatio,
    v1: v1Metric,
    rust: rustMetric,
    rustToV1Ratio,
    withinThreshold: rustToV1Ratio <= thresholdRatio,
  };
}

function summarize(durations) {
  const sorted = [...durations].sort((a, b) => a - b);
  const total = durations.reduce((sum, value) => sum + value, 0);
  return {
    iterations: durations.length,
    averageMs: total / durations.length,
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1],
  };
}

function measureSync(operation) {
  const start = performance.now();
  operation();
  return performance.now() - start;
}

async function measureAsync(operation) {
  const start = performance.now();
  const result = await operation();
  return {
    durationMs: performance.now() - start,
    result,
  };
}

function recordCheck(checks, failures, name, passed, details) {
  const check = { name, passed, details };
  checks.push(check);
  if (!passed) {
    failures.push(check);
  }
}

function deepEqual(left, right) {
  try {
    assert.deepEqual(left, right);
    return true;
  } catch {
    return false;
  }
}

function normalizeBigints(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(normalizeBigints);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, normalizeBigints(entry)]),
    );
  }
  return value;
}

function normalizeCommitment(commitment) {
  return {
    hash: String(commitment.hash),
    nullifierHash: String(
      commitment.nullifierHash ??
        commitment.precommitmentHash ??
        commitment.preimage?.precommitment?.hash,
    ),
    precommitmentHash: String(
      commitment.precommitmentHash ??
        commitment.nullifierHash ??
        commitment.preimage?.precommitment?.hash,
    ),
    value: String(commitment.value ?? commitment.preimage?.value),
    label: String(commitment.label ?? commitment.preimage?.label),
    nullifier: String(
      commitment.nullifier ?? commitment.preimage?.precommitment?.nullifier,
    ),
    secret: String(commitment.secret ?? commitment.preimage?.precommitment?.secret),
  };
}

function normalizeMerkleProof(proof) {
  const siblings = [...(proof.siblings ?? [])].map(String);
  while (siblings.length > 0 && siblings[siblings.length - 1] === "0") {
    siblings.pop();
  }
  return {
    root: String(proof.root),
    leaf: String(proof.leaf),
    index: proof.index,
    siblings,
  };
}

function referenceV1WithdrawalInput(v1) {
  return {
    context: BigInt(
      v1.calculateContext(
        {
          processooor: "0x1111111111111111111111111111111111111111",
          data: "0x1234",
        },
        BigInt(cryptoFixture.scope),
      ),
    ),
    withdrawalAmount: BigInt(withdrawalFixture.withdrawalAmount),
    stateMerkleProof: toV1MerkleWitness(withdrawalFixture.stateWitness),
    aspMerkleProof: toV1MerkleWitness(withdrawalFixture.aspWitness),
    stateRoot: BigInt(withdrawalFixture.stateWitness.root),
    stateTreeDepth: BigInt(withdrawalFixture.stateWitness.depth),
    aspRoot: BigInt(withdrawalFixture.aspWitness.root),
    aspTreeDepth: BigInt(withdrawalFixture.aspWitness.depth),
    newNullifier: BigInt(withdrawalFixture.newNullifier),
    newSecret: BigInt(withdrawalFixture.newSecret),
  };
}

function toV1MerkleWitness(witness) {
  return {
    root: BigInt(witness.root),
    leaf: BigInt(witness.leaf),
    index: witness.index,
    siblings: witness.siblings.map(BigInt),
  };
}

function normalizeProofForRust(proofBundle) {
  return {
    proof: {
      pi_a: stringArray((proofBundle.proof.pi_a ?? proofBundle.proof.piA).slice(0, 2)),
      pi_b: (proofBundle.proof.pi_b ?? proofBundle.proof.piB)
        .slice(0, 2)
        .map((row) => stringArray(row.slice(0, 2))),
      pi_c: stringArray((proofBundle.proof.pi_c ?? proofBundle.proof.piC).slice(0, 2)),
      protocol: proofBundle.proof.protocol,
      curve: proofBundle.proof.curve,
    },
    public_signals: stringArray(
      proofBundle.public_signals ?? proofBundle.publicSignals,
    ),
  };
}

function normalizeProofForV1(proofBundle) {
  return {
    proof: {
      pi_a: toProjectiveG1(proofBundle.proof.pi_a ?? proofBundle.proof.piA),
      pi_b: toProjectiveG2(proofBundle.proof.pi_b ?? proofBundle.proof.piB),
      pi_c: toProjectiveG1(proofBundle.proof.pi_c ?? proofBundle.proof.piC),
      protocol: proofBundle.proof.protocol,
      curve: proofBundle.proof.curve,
    },
    publicSignals: stringArray(
      proofBundle.public_signals ?? proofBundle.publicSignals,
    ),
  };
}

function toProjectiveG1(pair) {
  return pair.length >= 3 ? stringArray(pair) : [...stringArray(pair), "1"];
}

function toProjectiveG2(rows) {
  return rows.length >= 3
    ? rows.map((row) => stringArray(row))
    : [...rows.map((row) => stringArray(row)), ["1", "0"]];
}

function stringArray(values) {
  return values.map(String);
}

function createArtifactServer() {
  const pathMap = new Map([
    ["artifacts/withdraw.wasm", "circuits/withdraw/withdraw.wasm"],
    ["artifacts/withdraw.vkey", "artifacts/withdraw.vkey.json"],
    ["artifacts/withdraw.vkey.json", "artifacts/withdraw.vkey.json"],
    ["artifacts/withdraw.zkey", "artifacts/withdraw.zkey"],
    ["artifacts/commitment.wasm", "circuits/commitment/commitment.wasm"],
    ["artifacts/commitment.vkey", "artifacts/commitment.vkey.json"],
    ["artifacts/commitment.vkey.json", "artifacts/commitment.vkey.json"],
    ["artifacts/commitment.zkey", "artifacts/commitment.zkey"],
    ["circuits/withdraw/withdraw.wasm", "circuits/withdraw/withdraw.wasm"],
    ["circuits/commitment/commitment.wasm", "circuits/commitment/commitment.wasm"],
  ]);
  const server = createServer((request, response) => {
    response.setHeader("access-control-allow-origin", "*");
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const requested = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const fixturePath = pathMap.get(requested) ?? normalize(requested);
    if (!fixturePath || fixturePath.startsWith("..")) {
      response.statusCode = 404;
      response.end("not found");
      return;
    }

    try {
      const bytes = readFileSync(join(fixturesRoot, fixturePath));
      response.statusCode = 200;
      response.setHeader("connection", "close");
      response.setHeader("content-length", String(bytes.byteLength));
      response.setHeader("content-type", contentType(fixturePath));
      response.end(bytes);
    } catch {
      response.statusCode = 404;
      response.end("not found");
    }
  });

  return {
    origin: "",
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      this.origin = `http://127.0.0.1:${address.port}`;
    },
    async stop() {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    },
  };
}

function contentType(path) {
  if (path.endsWith(".wasm")) {
    return "application/wasm";
  }
  if (path.endsWith(".json")) {
    return "application/json; charset=utf-8";
  }
  return "application/octet-stream";
}

function readFixtureText(path) {
  return readFileSync(join(fixturesRoot, path), "utf8");
}

function readFixtureJson(path) {
  return JSON.parse(readFixtureText(path));
}

function replacer(_key, value) {
  return typeof value === "bigint" ? value.toString() : value;
}
