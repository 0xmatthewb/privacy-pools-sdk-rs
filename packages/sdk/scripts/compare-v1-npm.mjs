import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const V1_PACKAGE = "@0xbow/privacy-pools-core-sdk";
const V1_VERSION = "1.2.0";
const helperIterations = Number(process.env.PRIVACY_POOLS_COMPARE_HELPER_ITERS ?? 10);
const proofIterations = Number(process.env.PRIVACY_POOLS_COMPARE_PROOF_ITERS ?? 1);
const npmEnv = {
  ...process.env,
  NO_UPDATE_NOTIFIER: "1",
  npm_config_update_notifier: "false",
};

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");
const reportPath =
  process.env.PRIVACY_POOLS_COMPARE_REPORT ??
  join(workspaceRoot, "dist", "v1-npm-comparison.json");

const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");
const withdrawalFixture = readFixtureJson("vectors/withdrawal-circuit-input.json");
const withdrawalProvingManifest = readFixtureText(
  "artifacts/withdrawal-proving-manifest.json",
);
const commitmentProvingManifest = readFixtureText(
  "artifacts/commitment-proving-manifest.json",
);

const comparisonCases = [
  {
    mnemonic: cryptoFixture.mnemonic,
    scope: 123n,
    label: 456n,
    depositIndex: 0n,
    withdrawalIndex: 1n,
    value: 1000n,
    withdrawalAmount: 250n,
  },
  {
    mnemonic: "test test test test test test test test test test test junk",
    scope: 987654321n,
    label: 123456789n,
    depositIndex: 2n,
    withdrawalIndex: 3n,
    value: 42n,
    withdrawalAmount: 17n,
  },
  {
    mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    scope: 2n ** 64n - 1n,
    label: 2n ** 128n + 99n,
    depositIndex: 7n,
    withdrawalIndex: 11n,
    value: 10n ** 18n,
    withdrawalAmount: 10n ** 17n,
  },
];

const merkleCases = [
  { leaves: [11n, 22n, 33n, 44n, 55n], leaf: 44n },
  { leaves: [1n], leaf: 1n },
  { leaves: [3n, 5n, 8n, 13n, 21n, 34n], leaf: 21n },
];

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  const tempRoot = await mkdtemp(join(tmpdir(), "privacy-pools-v1-compare-"));
  const registry = npmView(tempRoot);
  let server;

  try {
    installV1(tempRoot);
    const v1Root = join(tempRoot, "node_modules", "@0xbow", "privacy-pools-core-sdk");
    const v1 = await import(pathToFileURL(join(v1Root, "dist", "esm", "index.mjs")));
    const rust = await import(
      pathToFileURL(join(packageRoot, "src", "browser", "index.mjs"))
    );

    const safetyChecks = await runSafetyComparisons(v1, rust);
    server = createArtifactServer();
    await server.start();

    const proofSafety = await runProofSafety(v1, rust, server);
    safetyChecks.push(...proofSafety.checks);

    const performance = await runPerformance(v1, rust, server);
    const report = {
      generatedAt: new Date().toISOString(),
      npmBaseline: registry,
      localPackage: "@0xmatthewb/privacy-pools-sdk",
      webAssumption:
        "compares the npm browser ESM export with the local Rust browser/WASM entrypoint",
      safety: {
        passed: safetyChecks.length,
        checks: safetyChecks,
      },
      performance,
    };

    mkdirSync(dirname(reportPath), { recursive: true });
    writeFileSync(reportPath, `${JSON.stringify(report, replacer, 2)}\n`);

    console.log(`safety checks passed: ${safetyChecks.length}`);
    console.log("performance summary (ms):");
    for (const [name, metric] of Object.entries(performance)) {
      console.log(
        `${name.padEnd(34)} v1 avg ${metric.v1.averageMs.toFixed(2).padStart(8)} | rust avg ${metric.rust.averageMs.toFixed(2).padStart(8)} | ratio ${metric.rustToV1Ratio.toFixed(2)}`,
      );
    }
    console.log(`wrote comparison report to ${reportPath}`);
  } finally {
    await server?.stop();
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function runSafetyComparisons(v1, rust) {
  const checks = [];

  assert.equal(rust.CircuitName.Commitment, v1.CircuitName.Commitment);
  checks.push("CircuitName.Commitment");
  assert.equal(rust.CircuitName.Withdraw, v1.CircuitName.Withdraw);
  checks.push("CircuitName.Withdraw");
  assert.deepEqual(rust.DEFAULT_LOG_FETCH_CONFIG, v1.DEFAULT_LOG_FETCH_CONFIG);
  checks.push("DEFAULT_LOG_FETCH_CONFIG");

  for (const [index, testCase] of comparisonCases.entries()) {
    const prefix = `case ${index + 1}`;
    const v1Keys = v1.generateMasterKeys(testCase.mnemonic);
    const rustKeys = await rust.generateMasterKeys(testCase.mnemonic);
    assert.deepEqual(rustKeys, v1Keys);
    checks.push(`${prefix}: generateMasterKeys`);

    const v1Deposit = v1.generateDepositSecrets(
      v1Keys,
      testCase.scope,
      testCase.depositIndex,
    );
    const rustDeposit = await rust.generateDepositSecrets(
      rustKeys,
      testCase.scope,
      testCase.depositIndex,
    );
    assert.deepEqual(rustDeposit, v1Deposit);
    checks.push(`${prefix}: generateDepositSecrets`);

    const v1Withdrawal = v1.generateWithdrawalSecrets(
      v1Keys,
      testCase.label,
      testCase.withdrawalIndex,
    );
    const rustWithdrawal = await rust.generateWithdrawalSecrets(
      rustKeys,
      testCase.label,
      testCase.withdrawalIndex,
    );
    assert.deepEqual(rustWithdrawal, v1Withdrawal);
    checks.push(`${prefix}: generateWithdrawalSecrets`);

    const v1Precommitment = v1.hashPrecommitment(
      v1Deposit.nullifier,
      v1Deposit.secret,
    );
    const rustPrecommitment = await rust.hashPrecommitment(
      rustDeposit.nullifier,
      rustDeposit.secret,
    );
    assert.equal(rustPrecommitment, v1Precommitment);
    checks.push(`${prefix}: hashPrecommitment`);

    const v1Commitment = v1.getCommitment(
      testCase.value,
      testCase.label,
      v1Deposit.nullifier,
      v1Deposit.secret,
    );
    const rustCommitment = await rust.getCommitment(
      testCase.value,
      testCase.label,
      rustDeposit.nullifier,
      rustDeposit.secret,
    );
    assert.deepEqual(rustCommitment, v1Commitment);
    checks.push(`${prefix}: getCommitment`);

    const withdrawal = {
      processooor: "0x1111111111111111111111111111111111111111",
      data: index % 2 === 0 ? "0x1234" : "0x",
    };
    assert.equal(
      await rust.calculateContext(withdrawal, testCase.scope),
      v1.calculateContext(withdrawal, testCase.scope),
    );
    checks.push(`${prefix}: calculateContext`);

    assert.equal(rust.bigintToHash(testCase.value), v1.bigintToHash(testCase.value));
    checks.push(`${prefix}: bigintToHash`);
    assert.equal(rust.bigintToHex(testCase.value), v1.bigintToHex(testCase.value));
    checks.push(`${prefix}: bigintToHex`);
  }

  for (const [index, testCase] of merkleCases.entries()) {
    assert.deepEqual(
      await rust.generateMerkleProof(testCase.leaves, testCase.leaf),
      v1.generateMerkleProof(testCase.leaves, testCase.leaf),
    );
    checks.push(`merkle ${index + 1}: generateMerkleProof`);
  }

  return checks;
}

async function runProofSafety(v1, rust, server) {
  const checks = [];
  const rustClient = new rust.PrivacyPoolsSdkClient();
  const artifactsRoot = `${server.origin}/artifacts/`;
  const v1Circuits = new v1.Circuits({ baseUrl: `${server.origin}/`, browser: true });
  const v1Sdk = new v1.PrivacyPoolSDK(v1Circuits);

  const v1Commitment = v1.getCommitment(
    BigInt(withdrawalFixture.existingValue),
    BigInt(withdrawalFixture.label),
    BigInt(cryptoFixture.depositSecrets.nullifier),
    BigInt(cryptoFixture.depositSecrets.secret),
  );
  const rustCommitment = await rustClient.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    cryptoFixture.depositSecrets.nullifier,
    cryptoFixture.depositSecrets.secret,
  );

  const commitmentSession = await rustClient.prepareCommitmentCircuitSession(
    commitmentProvingManifest,
    artifactsRoot,
  );
  try {
    const v1Proof = await v1Sdk.proveCommitment(
      BigInt(withdrawalFixture.existingValue),
      BigInt(withdrawalFixture.label),
      BigInt(cryptoFixture.depositSecrets.nullifier),
      BigInt(cryptoFixture.depositSecrets.secret),
    );
    const rustProof = await rustClient.proveCommitmentWithSession(
      "stable",
      commitmentSession.handle,
      { commitment: rustCommitment },
    );

    assert.deepEqual(
      stringArray(rustProof.proof.publicSignals),
      stringArray(v1Proof.publicSignals),
    );
    checks.push("commitment proof publicSignals");
    assert.equal(
      await rustClient.verifyCommitmentProofWithSession(
        "stable",
        commitmentSession.handle,
        normalizeProofForRust(v1Proof),
      ),
      true,
    );
    checks.push("rust verifies v1 commitment proof");
    assert.equal(
      await v1Sdk.verifyCommitment(normalizeProofForV1(rustProof.proof)),
      true,
    );
    checks.push("v1 verifies rust commitment proof");

    const tampered = structuredClone(normalizeProofForRust(v1Proof));
    tampered.publicSignals[0] = "9";
    assert.equal(
      await rustClient.verifyCommitmentProofWithSession(
        "stable",
        commitmentSession.handle,
        tampered,
      ),
      false,
    );
    checks.push("rust rejects tampered commitment proof");
  } finally {
    await rustClient.removeCommitmentCircuitSession(commitmentSession.handle);
  }

  const v1WithdrawalInput = {
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
  const rustWithdrawalRequest = {
    commitment: rustCommitment,
    withdrawal: {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    scope: cryptoFixture.scope,
    withdrawalAmount: withdrawalFixture.withdrawalAmount,
    stateWitness: withdrawalFixture.stateWitness,
    aspWitness: withdrawalFixture.aspWitness,
    newNullifier: withdrawalFixture.newNullifier,
    newSecret: withdrawalFixture.newSecret,
  };

  const withdrawalSession = await rustClient.prepareWithdrawalCircuitSession(
    withdrawalProvingManifest,
    artifactsRoot,
  );
  try {
    const v1Proof = await v1Sdk.proveWithdrawal(v1Commitment, v1WithdrawalInput);
    const rustProof = await rustClient.proveWithdrawalWithSession(
      "stable",
      withdrawalSession.handle,
      rustWithdrawalRequest,
    );

    assert.deepEqual(
      stringArray(rustProof.proof.publicSignals),
      stringArray(v1Proof.publicSignals),
    );
    checks.push("withdrawal proof publicSignals");
    assert.equal(
      await rustClient.verifyWithdrawalProofWithSession(
        "stable",
        withdrawalSession.handle,
        normalizeProofForRust(v1Proof),
      ),
      true,
    );
    checks.push("rust verifies v1 withdrawal proof");
    assert.equal(
      await v1Sdk.verifyWithdrawal(normalizeProofForV1(rustProof.proof)),
      true,
    );
    checks.push("v1 verifies rust withdrawal proof");

    const tampered = structuredClone(normalizeProofForRust(v1Proof));
    tampered.publicSignals[2] = "9";
    assert.equal(
      await rustClient.verifyWithdrawalProofWithSession(
        "stable",
        withdrawalSession.handle,
        tampered,
      ),
      false,
    );
    checks.push("rust rejects tampered withdrawal proof");
  } finally {
    await rustClient.removeWithdrawalCircuitSession(withdrawalSession.handle);
  }

  return { checks };
}

async function runPerformance(v1, rust, server) {
  const testCase = comparisonCases[0];
  const v1Keys = v1.generateMasterKeys(testCase.mnemonic);
  const rustKeys = await rust.generateMasterKeys(testCase.mnemonic);
  const rustClient = new rust.PrivacyPoolsSdkClient();
  const artifactsRoot = `${server.origin}/artifacts/`;
  const v1Circuits = new v1.Circuits({ baseUrl: `${server.origin}/`, browser: true });
  const v1Sdk = new v1.PrivacyPoolSDK(v1Circuits);

  const metrics = {};
  metrics.generateMasterKeys = await compareMetric(
    () => v1.generateMasterKeys(testCase.mnemonic),
    () => rust.generateMasterKeys(testCase.mnemonic),
    helperIterations,
  );
  metrics.generateDepositSecrets = await compareMetric(
    () => v1.generateDepositSecrets(v1Keys, testCase.scope, testCase.depositIndex),
    () => rust.generateDepositSecrets(rustKeys, testCase.scope, testCase.depositIndex),
    helperIterations,
  );
  metrics.getCommitment = await compareMetric(
    () =>
      v1.getCommitment(
        testCase.value,
        testCase.label,
        BigInt(cryptoFixture.depositSecrets.nullifier),
        BigInt(cryptoFixture.depositSecrets.secret),
      ),
    () =>
      rust.getCommitment(
        testCase.value,
        testCase.label,
        BigInt(cryptoFixture.depositSecrets.nullifier),
        BigInt(cryptoFixture.depositSecrets.secret),
      ),
    helperIterations,
  );
  metrics.generateMerkleProof = await compareMetric(
    () => v1.generateMerkleProof(merkleCases[0].leaves, merkleCases[0].leaf),
    () => rust.generateMerkleProof(merkleCases[0].leaves, merkleCases[0].leaf),
    helperIterations,
  );
  metrics.calculateContext = await compareMetric(
    () =>
      v1.calculateContext(
        {
          processooor: "0x1111111111111111111111111111111111111111",
          data: "0x1234",
        },
        testCase.scope,
      ),
    () =>
      rust.calculateContext(
        {
          processooor: "0x1111111111111111111111111111111111111111",
          data: "0x1234",
        },
        testCase.scope,
      ),
    helperIterations,
  );

  const rustCommitment = await rustClient.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    cryptoFixture.depositSecrets.nullifier,
    cryptoFixture.depositSecrets.secret,
  );
  const v1Commitment = v1.getCommitment(
    BigInt(withdrawalFixture.existingValue),
    BigInt(withdrawalFixture.label),
    BigInt(cryptoFixture.depositSecrets.nullifier),
    BigInt(cryptoFixture.depositSecrets.secret),
  );

  const commitmentSession = await rustClient.prepareCommitmentCircuitSession(
    commitmentProvingManifest,
    artifactsRoot,
  );
  try {
    metrics.proveCommitment = await compareMetric(
      () =>
        v1Sdk.proveCommitment(
          BigInt(withdrawalFixture.existingValue),
          BigInt(withdrawalFixture.label),
          BigInt(cryptoFixture.depositSecrets.nullifier),
          BigInt(cryptoFixture.depositSecrets.secret),
        ),
      () =>
        rustClient.proveCommitmentWithSession("stable", commitmentSession.handle, {
          commitment: rustCommitment,
        }),
      proofIterations,
    );
  } finally {
    await rustClient.removeCommitmentCircuitSession(commitmentSession.handle);
  }

  const withdrawalSession = await rustClient.prepareWithdrawalCircuitSession(
    withdrawalProvingManifest,
    artifactsRoot,
  );
  try {
    metrics.proveWithdrawal = await compareMetric(
      () => v1Sdk.proveWithdrawal(v1Commitment, referenceV1WithdrawalInput(v1)),
      () =>
        rustClient.proveWithdrawalWithSession(
          "stable",
          withdrawalSession.handle,
          referenceRustWithdrawalRequest(rustCommitment),
        ),
      proofIterations,
    );
  } finally {
    await rustClient.removeWithdrawalCircuitSession(withdrawalSession.handle);
  }

  return metrics;
}

async function compareMetric(v1Operation, rustOperation, iterations) {
  const v1Durations = [];
  const rustDurations = [];
  for (let index = 0; index < iterations; index += 1) {
    v1Durations.push(await measure(v1Operation));
    rustDurations.push(await measure(rustOperation));
  }

  const v1 = summarize(v1Durations);
  const rust = summarize(rustDurations);
  return {
    iterations,
    v1,
    rust,
    rustToV1Ratio: rust.averageMs / v1.averageMs,
  };
}

async function measure(operation) {
  const start = performance.now();
  await operation();
  return performance.now() - start;
}

function summarize(durations) {
  const sorted = [...durations].sort((a, b) => a - b);
  const total = durations.reduce((sum, value) => sum + value, 0);
  return {
    averageMs: total / durations.length,
    minMs: sorted[0],
    medianMs: sorted[Math.floor(sorted.length / 2)],
    maxMs: sorted[sorted.length - 1],
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

function referenceRustWithdrawalRequest(commitment) {
  return {
    commitment,
    withdrawal: {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    scope: cryptoFixture.scope,
    withdrawalAmount: withdrawalFixture.withdrawalAmount,
    stateWitness: withdrawalFixture.stateWitness,
    aspWitness: withdrawalFixture.aspWitness,
    newNullifier: withdrawalFixture.newNullifier,
    newSecret: withdrawalFixture.newSecret,
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
      piA: proofBundle.proof.piA ?? proofBundle.proof.pi_a,
      piB: proofBundle.proof.piB ?? proofBundle.proof.pi_b,
      piC: proofBundle.proof.piC ?? proofBundle.proof.pi_c,
      protocol: proofBundle.proof.protocol,
      curve: proofBundle.proof.curve,
    },
    publicSignals: stringArray(proofBundle.publicSignals),
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
    publicSignals: stringArray(proofBundle.publicSignals),
  };
}

function toProjectiveG1(pair) {
  return pair.length >= 3 ? pair : [...pair, "1"];
}

function toProjectiveG2(rows) {
  return rows.length >= 3 ? rows : [...rows, ["1", "0"]];
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
    const fixturePath = pathMap.get(requested);
    if (!fixturePath) {
      response.statusCode = 404;
      response.end("not found");
      return;
    }

    try {
      const bytes = readFileSync(join(fixturesRoot, fixturePath));
      response.statusCode = 200;
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

function npmView(tempRoot) {
  return JSON.parse(
    execFileSync(
      "npm",
      [
        "view",
        `${V1_PACKAGE}@${V1_VERSION}`,
        "name",
        "version",
        "dist-tags",
        "browser",
        "--cache",
        join(tempRoot, ".npm-cache"),
        "--json",
      ],
      { encoding: "utf8", env: npmEnv },
    ),
  );
}

function installV1(tempRoot) {
  execFileSync("npm", ["init", "-y"], {
    cwd: tempRoot,
    env: npmEnv,
    stdio: "ignore",
  });
  execFileSync(
    "npm",
    [
      "install",
      "--silent",
      "--cache",
      join(tempRoot, ".npm-cache"),
      `${V1_PACKAGE}@${V1_VERSION}`,
    ],
    {
      cwd: tempRoot,
      env: npmEnv,
      stdio: "inherit",
    },
  );
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
