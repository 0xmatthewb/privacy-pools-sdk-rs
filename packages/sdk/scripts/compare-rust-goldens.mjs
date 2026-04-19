import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");

const runtime = process.env.PRIVACY_POOLS_GOLDENS_RUNTIME ?? "node";
const smoke = process.env.PRIVACY_POOLS_GOLDENS_SMOKE === "1";
const reportPath =
  process.env.PRIVACY_POOLS_GOLDENS_REPORT ??
  join(workspaceRoot, "dist", `${runtime}-goldens-comparison.json`);

const goldens = readFixtureJson("vectors/assurance-goldens.json");
const parityCases = readFixtureJson("vectors/audit-parity-cases.json");

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  const checks = [];
  const caseLimit = smoke ? 1 : undefined;
  const comparisonCases = parityCases.comparisonCases.slice(0, caseLimit);
  const merkleCases = parityCases.merkleCases.slice(0, caseLimit);
  const goldenCaseMap = new Map(goldens.cases.map((entry) => [entry.name, entry]));
  const goldenMerkleMap = new Map(goldens.merkleCases.map((entry) => [entry.name, entry]));

  if (runtime === "rust") {
    const rawReport = runRustParityReport();
    const rawCaseMap = new Map(rawReport.cases.map((entry) => [entry.name, entry]));
    const rawMerkleMap = new Map(rawReport.merkleCases.map((entry) => [entry.name, entry]));

    for (const entry of comparisonCases) {
      const actual = rawCaseMap.get(entry.name);
      const expected = goldenCaseMap.get(entry.name);
      assert.ok(actual, `missing Rust report case ${entry.name}`);
      assert.ok(expected, `missing golden case ${entry.name}`);
      compare(checks, `${entry.name}: masterKeys`, actual.masterKeys, expected.masterKeys);
      compare(
        checks,
        `${entry.name}: depositSecrets`,
        actual.depositSecrets,
        expected.depositSecrets,
      );
      compare(
        checks,
        `${entry.name}: withdrawalSecrets`,
        actual.withdrawalSecrets,
        expected.withdrawalSecrets,
      );
      compare(
        checks,
        `${entry.name}: precommitmentHash`,
        actual.precommitmentHash,
        expected.precommitmentHash,
      );
      compare(checks, `${entry.name}: commitment`, actual.commitment, expected.commitment);
      compare(
        checks,
        `${entry.name}: withdrawalContextHex`,
        actual.withdrawalContextHex,
        expected.withdrawalContextHex,
      );
    }

    for (const entry of merkleCases) {
      const actual = rawMerkleMap.get(entry.name);
      const expected = goldenMerkleMap.get(entry.name);
      assert.ok(actual, `missing Rust merkle case ${entry.name}`);
      assert.ok(expected, `missing golden merkle case ${entry.name}`);
      compare(checks, `${entry.name}: merkleProof`, actual.proof, expected.proof);
    }
  } else if (runtime === "react-native") {
    checks.push(
      ...runReactNativeGoldenChecks(
        comparisonCases,
        merkleCases,
        goldens.cases.filter((entry) => goldenCaseMap.has(entry.name)),
        goldens.merkleCases.filter((entry) => goldenMerkleMap.has(entry.name)),
      ),
    );
  } else {
    const entry = await loadRuntimeEntry(runtime);

    for (const fixture of comparisonCases) {
      const expected = goldenCaseMap.get(fixture.name);
      assert.ok(expected, `missing golden case ${fixture.name}`);
      const masterKeys = normalize(await entry.generateMasterKeys(fixture.mnemonic));
      compare(checks, `${fixture.name}: masterKeys`, masterKeys, expected.masterKeys);

      const depositSecrets = normalize(
        await entry.generateDepositSecrets(masterKeys, fixture.scope, fixture.depositIndex),
      );
      compare(
        checks,
        `${fixture.name}: depositSecrets`,
        depositSecrets,
        expected.depositSecrets,
      );

      const withdrawalSecrets = normalize(
        await entry.generateWithdrawalSecrets(masterKeys, fixture.label, fixture.withdrawalIndex),
      );
      compare(
        checks,
        `${fixture.name}: withdrawalSecrets`,
        withdrawalSecrets,
        expected.withdrawalSecrets,
      );

      const precommitmentHash = normalize(
        await entry.hashPrecommitment(depositSecrets.nullifier, depositSecrets.secret),
      );
      compare(
        checks,
        `${fixture.name}: precommitmentHash`,
        precommitmentHash,
        expected.precommitmentHash,
      );

      const commitment = normalize(
        await entry.getCommitment(
          fixture.value,
          fixture.label,
          depositSecrets.nullifier,
          depositSecrets.secret,
        ),
      );
      compare(
        checks,
        `${fixture.name}: commitment`,
        normalizeCommitment(commitment),
        expected.commitment,
      );

      const withdrawalContextHex = normalize(
        await entry.calculateContext(fixture.withdrawal, fixture.scope),
      );
      compare(
        checks,
        `${fixture.name}: withdrawalContextHex`,
        withdrawalContextHex,
        expected.withdrawalContextHex,
      );
    }

    for (const fixture of merkleCases) {
      const expected = goldenMerkleMap.get(fixture.name);
      assert.ok(expected, `missing golden merkle case ${fixture.name}`);
      const proof = normalize(await entry.generateMerkleProof(fixture.leaves, fixture.leaf));
      compare(
        checks,
        `${fixture.name}: merkleProof`,
        normalizeMerkleProof(proof),
        expected.proof,
      );
    }
  }

  const failed = checks.filter((check) => !check.passed);
  const report = {
    generatedAt: new Date().toISOString(),
    runtime,
    smoke,
    source: {
      goldens: join(fixturesRoot, "vectors", "assurance-goldens.json"),
      cases: join(fixturesRoot, "vectors", "audit-parity-cases.json"),
    },
    totalChecks: checks.length,
    passed: checks.length - failed.length,
    failed: failed.length,
    checks,
  };

  writeReport(reportPath, report);
  console.log(`${runtime} goldens checks passed: ${report.passed}/${report.totalChecks}`);
  console.log(`wrote goldens report to ${reportPath}`);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

function runRustParityReport() {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rust-goldens-"));
  const reportJson = join(tempRoot, "rust-parity-report.json");
  try {
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
        join(fixturesRoot, "artifacts", "commitment-proving-manifest.json"),
        "--withdrawal-manifest",
        join(fixturesRoot, "artifacts", "withdrawal-proving-manifest.json"),
        "--artifacts-root",
        join(fixturesRoot, "artifacts"),
        "--report-json",
        reportJson,
      ],
      {
        cwd: workspaceRoot,
        stdio: "inherit",
      },
    );
    return JSON.parse(readFileSync(reportJson, "utf8"));
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function loadRuntimeEntry(selectedRuntime) {
  const modulePath =
    selectedRuntime === "browser"
      ? join(packageRoot, "src", "browser", "index.mjs")
      : join(packageRoot, "src", "node", "index.mjs");
  return import(pathToFileURL(modulePath));
}

function runReactNativeGoldenChecks(
  comparisonCases,
  merkleCases,
  expectedCases,
  expectedMerkleCases,
) {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rn-goldens-"));
  const reactNativeStubRoot = join(tempRoot, "node_modules", "react-native");
  const rnIndexPath = join(
    workspaceRoot,
    "packages",
    "react-native",
    "src",
    "index.ts",
  );
  const inputJson = join(tempRoot, "input.json");
  const runnerPath = join(tempRoot, "runner.mjs");
  const nativeModuleUrl = pathToFileURL(join(packageRoot, "src", "native.mjs")).href;

  try {
    mkdirSync(reactNativeStubRoot, { recursive: true });
    writeFileSync(
      join(reactNativeStubRoot, "package.json"),
      `${JSON.stringify(
        {
          name: "react-native",
          type: "module",
          exports: "./index.js",
        },
        null,
        2,
      )}\n`,
    );
    writeFileSync(
      join(reactNativeStubRoot, "index.js"),
      `import { native } from ${JSON.stringify(nativeModuleUrl)};

function unwrapNativeValue(result) {
  if (result instanceof Error) {
    throw result;
  }
  return result;
}

function parseNativeJson(result) {
  return JSON.parse(unwrapNativeValue(result));
}

const module = {
  deriveMasterKeys: async (mnemonic) => {
    const masterKeys = parseNativeJson(native.deriveMasterKeys(mnemonic));
    return {
      master_nullifier: masterKeys.masterNullifier ?? masterKeys.master_nullifier,
      master_secret: masterKeys.masterSecret ?? masterKeys.master_secret,
    };
  },
  deriveDepositSecrets: async (masterNullifier, masterSecret, scope, index) =>
    parseNativeJson(
      native.deriveDepositSecrets(
        JSON.stringify({
          masterNullifier,
          masterSecret,
        }),
        scope,
        index,
      ),
    ),
  deriveWithdrawalSecrets: async (masterNullifier, masterSecret, label, index) =>
    parseNativeJson(
      native.deriveWithdrawalSecrets(
        JSON.stringify({
          masterNullifier,
          masterSecret,
        }),
        label,
        index,
      ),
    ),
  getCommitment: async (value, label, nullifier, secret) => {
    const commitment = parseNativeJson(native.getCommitment(value, label, nullifier, secret));
    return {
      hash: commitment.hash,
      nullifier_hash: commitment.nullifierHash ?? commitment.nullifier_hash,
      precommitment_hash:
        commitment.precommitmentHash ??
        commitment.precommitment_hash ??
        commitment.preimage?.precommitment?.hash,
      value: commitment.value ?? commitment.preimage?.value,
      label: commitment.label ?? commitment.preimage?.label,
      nullifier:
        commitment.nullifier ??
        commitment.preimage?.precommitment?.nullifier,
      secret:
        commitment.secret ??
        commitment.preimage?.precommitment?.secret,
    };
  },
  calculateWithdrawalContext: async (withdrawal, scope) =>
    unwrapNativeValue(native.calculateWithdrawalContext(JSON.stringify(withdrawal), scope)),
  generateMerkleProof: async (leaves, leaf) =>
    parseNativeJson(native.generateMerkleProof(JSON.stringify(leaves), leaf)),
};

export const NativeModules = { PrivacyPoolsSdk: module };
export const Platform = {
  OS: "ios",
  select(value) {
    if (value && typeof value === "object") {
      return value.ios ?? value.native ?? value.default ?? null;
    }
    return value ?? null;
  },
};

export default {
  NativeModules,
  Platform,
};
`,
    );
    writeFileSync(join(tempRoot, "index.ts"), readFileSync(rnIndexPath, "utf8"));
    writeFileSync(
      inputJson,
      `${JSON.stringify(
        {
          comparisonCases,
          merkleCases,
          expectedCases,
          expectedMerkleCases,
        },
        null,
        2,
      )}\n`,
    );
    writeFileSync(
      runnerPath,
      `import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as entry from "./index.ts";

const payload = JSON.parse(readFileSync(new URL("./input.json", import.meta.url), "utf8"));
const expectedCaseMap = new Map(payload.expectedCases.map((value) => [value.name, value]));
const expectedMerkleMap = new Map(
  payload.expectedMerkleCases.map((value) => [value.name, value]),
);
const checks = [];

for (const fixture of payload.comparisonCases) {
  const expected = expectedCaseMap.get(fixture.name);
  assert.ok(expected, \`missing golden case \${fixture.name}\`);

  const masterKeysRaw = await entry.deriveMasterKeys(fixture.mnemonic);
  const masterKeys = {
    masterNullifier: masterKeysRaw.master_nullifier,
    masterSecret: masterKeysRaw.master_secret,
  };
  compare(checks, \`\${fixture.name}: masterKeys\`, normalize(masterKeys), expected.masterKeys);

  const depositSecrets = normalize(
    await entry.deriveDepositSecrets(
      masterKeysRaw.master_nullifier,
      masterKeysRaw.master_secret,
      fixture.scope,
      fixture.depositIndex,
    ),
  );
  compare(checks, \`\${fixture.name}: depositSecrets\`, depositSecrets, expected.depositSecrets);

  const withdrawalSecrets = normalize(
    await entry.deriveWithdrawalSecrets(
      masterKeysRaw.master_nullifier,
      masterKeysRaw.master_secret,
      fixture.label,
      fixture.withdrawalIndex,
    ),
  );
  compare(
    checks,
    \`\${fixture.name}: withdrawalSecrets\`,
    withdrawalSecrets,
    expected.withdrawalSecrets,
  );

  const commitment = normalize(
    await entry.getCommitment(
      fixture.value,
      fixture.label,
      depositSecrets.nullifier,
      depositSecrets.secret,
    ),
  );
  compare(
    checks,
    \`\${fixture.name}: precommitmentHash\`,
    commitment.precommitment_hash,
    expected.precommitmentHash,
  );
  compare(
    checks,
    \`\${fixture.name}: commitment\`,
    normalizeCommitment(commitment),
    expected.commitment,
  );

  const withdrawalContextHex = normalize(
    await entry.calculateWithdrawalContext(fixture.withdrawal, fixture.scope),
  );
  compare(
    checks,
    \`\${fixture.name}: withdrawalContextHex\`,
    withdrawalContextHex,
    expected.withdrawalContextHex,
  );
}

for (const fixture of payload.merkleCases) {
  const expected = expectedMerkleMap.get(fixture.name);
  assert.ok(expected, \`missing golden merkle case \${fixture.name}\`);
  const proof = normalize(await entry.generateMerkleProof(fixture.leaves, fixture.leaf));
  compare(
    checks,
    \`\${fixture.name}: merkleProof\`,
    normalizeMerkleProof(proof),
    expected.proof,
  );
}

process.stdout.write(JSON.stringify(checks));

function compare(checks, name, actual, expected) {
  const passed = JSON.stringify(actual) === JSON.stringify(expected);
  checks.push({
    name,
    passed,
    actual: passed ? undefined : actual,
    expected: passed ? undefined : expected,
  });
}

function normalize(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, normalize(entry)]),
    );
  }
  return value;
}

function normalizeCommitment(commitment) {
  return {
    hash: commitment.hash,
    nullifierHash: commitment.nullifier_hash,
    precommitmentHash: commitment.precommitment_hash,
    value: commitment.value,
    label: commitment.label,
    nullifier: commitment.nullifier,
    secret: commitment.secret,
  };
}

function normalizeMerkleProof(proof) {
  if (!Array.isArray(proof?.siblings)) {
    return proof;
  }

  let siblings = [...proof.siblings];
  while (siblings.length > 0 && siblings.at(-1) === "0") {
    siblings = siblings.slice(0, -1);
  }

  return {
    ...proof,
    siblings,
  };
}
`,
    );

    return JSON.parse(
      execFileSync("node", ["--experimental-strip-types", runnerPath], {
        cwd: tempRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "inherit"],
      }),
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function compare(checks, name, actual, expected) {
  const passed = deepEqual(actual, expected);
  checks.push({
    name,
    passed,
    actual: passed ? undefined : actual,
    expected: passed ? undefined : expected,
  });
}

function normalize(value) {
  if (value && typeof value.then === "function") {
    return value.then((resolved) => normalize(resolved));
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, normalize(entry)]),
    );
  }
  return value;
}

function normalizeCommitment(commitment) {
  if (!commitment?.preimage?.precommitment) {
    return commitment;
  }

  return {
    hash: commitment.hash,
    nullifierHash: commitment.nullifierHash,
    precommitmentHash: commitment.preimage.precommitment.hash,
    value: commitment.preimage.value,
    label: commitment.preimage.label,
    nullifier: commitment.preimage.precommitment.nullifier,
    secret: commitment.preimage.precommitment.secret,
  };
}

function normalizeMerkleProof(proof) {
  if (!Array.isArray(proof?.siblings)) {
    return proof;
  }

  let siblings = [...proof.siblings];
  while (siblings.length > 0 && siblings.at(-1) === "0") {
    siblings = siblings.slice(0, -1);
  }

  return {
    ...proof,
    siblings,
  };
}

function deepEqual(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function readFixtureJson(relativePath) {
  return JSON.parse(readFileSync(join(fixturesRoot, relativePath), "utf8"));
}

function writeReport(path, report) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
}
