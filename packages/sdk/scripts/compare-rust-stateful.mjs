import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import * as nodeEntry from "../src/node/index.mjs";
import * as nodeDebug from "../src/node/debug.mjs";
import {
  EXECUTION_FIXTURE,
  EXECUTION_SIGNER_MNEMONIC,
  WRONG_EXECUTION_SIGNER_MNEMONIC,
  signFinalizedTransactionRequest,
  signFinalizedTransactionRequestWithWrongSigner,
} from "../test/execution-fixture.mjs";
import { buildStatefulTrace, normalizeStatefulTrace } from "./stateful-trace.mjs";

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");

const runtime = process.env.PRIVACY_POOLS_STATEFUL_RUNTIME ?? "node";
const reportPath =
  process.env.PRIVACY_POOLS_STATEFUL_REPORT ??
  join(workspaceRoot, "dist", `${runtime}-stateful-comparison.json`);
const fixturePath = join(fixturesRoot, "spec", "stateful-wrapper-parity.json");

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  const baseFixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const withdrawalFixture = JSON.parse(
    readFileSync(join(fixturesRoot, "vectors", "withdrawal-circuit-input.json"), "utf8"),
  );
  const validRpcServer = await startExecutionRpcFixtureServer({
    stateRoot: withdrawalFixture.stateWitness.root,
    aspRoot: withdrawalFixture.aspWitness.root,
  });
  const wrongRootServer = await startExecutionRpcFixtureServer({
    stateRoot: "999",
    aspRoot: withdrawalFixture.aspWitness.root,
  });

  try {
    const hydratedFixture = hydrateFixture(baseFixture, {
      validRpcUrl: validRpcServer.url,
      wrongRootRpcUrl: wrongRootServer.url,
    });
    const nodeClient = new nodeEntry.PrivacyPoolsSdkClient();
    const nodeFacade = {
      deriveMasterKeys: (mnemonic) => nodeClient.deriveMasterKeys(mnemonic),
      deriveMasterKeysHandle: (mnemonic) => nodeClient.deriveMasterKeysHandle(mnemonic),
      deriveDepositSecrets: (masterNullifier, masterSecret, scope, index) =>
        nodeClient.deriveDepositSecrets({ masterNullifier, masterSecret }, scope, index),
      generateDepositSecretsHandle: (masterKeysHandle, scope, index) =>
        nodeClient.generateDepositSecretsHandle(masterKeysHandle, scope, index),
      deriveWithdrawalSecrets: (masterNullifier, masterSecret, label, index) =>
        nodeClient.deriveWithdrawalSecrets({ masterNullifier, masterSecret }, label, index),
      generateWithdrawalSecretsHandle: (masterKeysHandle, label, index) =>
        nodeClient.generateWithdrawalSecretsHandle(masterKeysHandle, label, index),
      getCommitment: (...args) => nodeClient.getCommitment(...args),
      getCommitmentFromHandles: (...args) => nodeClient.getCommitmentFromHandles(...args),
      prepareWithdrawalCircuitSessionFromBytes: (...args) =>
        nodeClient.prepareWithdrawalCircuitSessionFromBytes(...args),
      proveWithdrawalWithSession: (...args) => nodeClient.proveWithdrawalWithSession(...args),
      verifyWithdrawalProofWithSession: (...args) =>
        nodeClient.verifyWithdrawalProofWithSession(...args),
      removeWithdrawalCircuitSession: (...args) =>
        nodeClient.removeWithdrawalCircuitSession(...args),
      proveAndVerifyWithdrawalHandle: (...args) =>
        nodeClient.proveAndVerifyWithdrawalHandle(...args),
      preflightVerifiedWithdrawalTransactionWithHandle: (...args) =>
        nodeClient.preflightVerifiedWithdrawalTransactionWithHandle(...args),
      finalizePreflightedTransactionHandle: (...args) =>
        nodeClient.finalizePreflightedTransactionHandle(...args),
      submitFinalizedPreflightedTransactionHandle: (...args) =>
        nodeClient.submitFinalizedPreflightedTransactionHandle(...args),
      removeExecutionHandle: (...args) => nodeClient.removeExecutionHandle(...args),
      clearExecutionHandles: (...args) => nodeClient.clearExecutionHandles(...args),
      clearVerifiedProofHandles: (...args) => nodeClient.clearVerifiedProofHandles(...args),
      clearSecretHandles: (...args) => nodeClient.clearSecretHandles(...args),
    };
    const rustReport = await runRustStatefulReport(hydratedFixture);
    const runtimeTrace =
      runtime === "react-native"
        ? await runReactNativeStatefulTrace(hydratedFixture)
        : await buildStatefulTrace({
            runtime,
            entry: nodeFacade,
            debugEntry: nodeDebug,
            fixture: hydratedFixture,
            signFinalizedTransaction: signFinalizedTransactionRequest,
            signFinalizedTransactionWithWrongSigner:
              signFinalizedTransactionRequestWithWrongSigner,
          });
    const normalizedRuntimeTrace = runtimeTrace;
    const normalizedRustTrace = normalizeStatefulTrace(rustReport.trace);

    const checks = [];
    compare(
      checks,
      "sessionLifecycle",
      normalizedRuntimeTrace.sessionLifecycle,
      normalizedRustTrace.sessionLifecycle,
    );
    compare(
      checks,
      "executionLifecycle",
      normalizedRuntimeTrace.executionLifecycle,
      normalizedRustTrace.executionLifecycle,
    );

    const failed = checks.filter((check) => !check.passed);
    const report = {
      generatedAt: new Date().toISOString(),
      runtime,
      fixturePath,
      rustReportPath: rustReport.reportPath,
      totalChecks: checks.length,
      passed: checks.length - failed.length,
      failed: failed.length,
      checks,
    };
    writeReport(reportPath, report);
    console.log(`${runtime} stateful checks passed: ${report.passed}/${report.totalChecks}`);
    console.log(`wrote stateful comparison report to ${reportPath}`);
    if (failed.length > 0) {
      process.exitCode = 1;
    }
    await nodeClient.dispose?.();
  } finally {
    await wrongRootServer.stop();
    await validRpcServer.stop();
  }
}

function hydrateFixture(baseFixture, { validRpcUrl, wrongRootRpcUrl }) {
  return {
    ...baseFixture,
    executionLifecycle: {
      chainId: EXECUTION_FIXTURE.chainId,
      caller: EXECUTION_FIXTURE.caller,
      poolAddress: EXECUTION_FIXTURE.poolAddress,
      entrypointAddress: EXECUTION_FIXTURE.entrypointAddress,
      poolCodeHash: EXECUTION_FIXTURE.poolCodeHash,
      entrypointCodeHash: EXECUTION_FIXTURE.entrypointCodeHash,
      validRpcUrl,
      wrongRootRpcUrl,
      withdrawal: {
        ...baseFixture.executionLifecycle.withdrawal,
        processooor:
          baseFixture.executionLifecycle.withdrawal.processooor === "$entrypointAddress"
            ? EXECUTION_FIXTURE.entrypointAddress
            : baseFixture.executionLifecycle.withdrawal.processooor,
      },
      signingMnemonic:
        baseFixture.executionLifecycle.signingMnemonic ?? EXECUTION_SIGNER_MNEMONIC,
      wrongSigningMnemonic:
        baseFixture.executionLifecycle.wrongSigningMnemonic ??
        WRONG_EXECUTION_SIGNER_MNEMONIC,
    },
  };
}

async function runRustStatefulReport(fixture) {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rust-stateful-"));
  const inputJson = join(tempRoot, "stateful-input.json");
  const reportJson = join(tempRoot, "rust-stateful-report.json");
  try {
    writeFileSync(inputJson, `${JSON.stringify(fixture, null, 2)}\n`);
    await execFileAsync(
      "cargo",
      [
        "run",
        "--release",
        "-p",
        "privacy-pools-sdk-cli",
        "--",
        "audit-stateful-report",
        "--input-json",
        inputJson,
        "--report-json",
        reportJson,
      ],
      {
        cwd: workspaceRoot,
      },
    );
    return {
      reportPath: reportJson,
      trace: JSON.parse(readFileSync(reportJson, "utf8")).trace,
    };
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function runReactNativeStatefulTrace(fixture) {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rn-stateful-"));
  const reactNativeStubRoot = join(tempRoot, "node_modules", "react-native");
  const runnerPath = join(tempRoot, "runner.mjs");
  const inputJson = join(tempRoot, "input.json");
  const rnIndexPath = join(workspaceRoot, "packages", "react-native", "src", "index.ts");
  const rnDebugPath = join(workspaceRoot, "packages", "react-native", "src", "debug.ts");
  const nodeIndexUrl = pathToFileURL(join(packageRoot, "src", "node", "index.mjs")).href;
  const nodeDebugUrl = pathToFileURL(join(packageRoot, "src", "node", "debug.mjs")).href;
  const nativeUrl = pathToFileURL(join(packageRoot, "src", "native.mjs")).href;
  const helperUrl = pathToFileURL(join(scriptDir, "stateful-trace.mjs")).href;
  const fixtureHelpersUrl = pathToFileURL(join(packageRoot, "test", "execution-fixture.mjs")).href;

  try {
    mkdirSync(reactNativeStubRoot, { recursive: true });
    writeFileSync(
      join(reactNativeStubRoot, "package.json"),
      `${JSON.stringify({ name: "react-native", type: "module", exports: "./index.js" }, null, 2)}\n`,
    );
    writeFileSync(
      join(reactNativeStubRoot, "index.js"),
      `import * as nodeEntry from ${JSON.stringify(nodeIndexUrl)};
import * as nodeDebug from ${JSON.stringify(nodeDebugUrl)};
import { native } from ${JSON.stringify(nativeUrl)};

function hexFromBytes(value) {
  if (typeof value === "string") {
    return value;
  }
  return \`0x\${Array.from(value ?? []).map((byte) => byte.toString(16).padStart(2, "0")).join("")}\`;
}

function unwrapNativeValue(value) {
  if (typeof value !== "string") {
    return value;
  }
  const parsed = JSON.parse(value);
  if (parsed?.ok === false) {
    throw new Error(parsed.error ?? "native bridge request failed");
  }
  if (parsed && typeof parsed === "object" && "ok" in parsed) {
    return parsed.value;
  }
  return parsed;
}

function parseNativeJson(value) {
  return JSON.parse(unwrapNativeValue(value));
}

const nodeClient = new nodeEntry.PrivacyPoolsSdkClient();

const module = {
  deriveMasterKeys: (mnemonic) => nodeClient.deriveMasterKeys(mnemonic),
  deriveMasterKeysHandle: (mnemonic) => nodeClient.deriveMasterKeysHandle(mnemonic),
  deriveDepositSecrets: (masterNullifier, masterSecret, scope, index) =>
    nodeClient.deriveDepositSecrets({ masterNullifier, masterSecret }, scope, index),
  generateDepositSecretsHandle: (masterKeysHandle, scope, index) =>
    nodeClient.generateDepositSecretsHandle(masterKeysHandle, scope, index),
  deriveWithdrawalSecrets: (masterNullifier, masterSecret, label, index) =>
    nodeClient.deriveWithdrawalSecrets({ masterNullifier, masterSecret }, label, index),
  generateWithdrawalSecretsHandle: (masterKeysHandle, label, index) =>
    nodeClient.generateWithdrawalSecretsHandle(masterKeysHandle, label, index),
  getCommitment: (value, label, nullifier, secret) =>
    nodeClient.getCommitment(value, label, nullifier, secret),
  getCommitmentFromHandles: (value, label, secretsHandle) =>
    nodeClient.getCommitmentFromHandles(value, label, secretsHandle),
  dangerouslyExportSecret: (handle) => nodeDebug.dangerouslyExportSecret(handle),
  dangerouslyExportCommitmentPreimage: (handle) =>
    nodeDebug.dangerouslyExportCommitmentPreimage(handle),
  buildWithdrawalWitnessRequestHandle: (request) =>
    unwrapNativeValue(native.buildWithdrawalWitnessRequestHandle(JSON.stringify(request))),
  prepareWithdrawalCircuitSessionFromBytes: (manifestJson, artifacts) =>
    nodeClient.prepareWithdrawalCircuitSessionFromBytes(
      manifestJson,
      artifacts.map((artifact) => ({ ...artifact, bytes: Buffer.from(artifact.bytes) })),
    ),
  proveWithdrawalWithSession: (backendProfile, sessionHandle, request) =>
    nodeClient.proveWithdrawalWithSession(backendProfile, sessionHandle, {
      ...request,
      withdrawal: {
        ...request.withdrawal,
        data: hexFromBytes(request.withdrawal.data),
      },
    }),
  verifyWithdrawalProofWithSession: (backendProfile, sessionHandle, proof) =>
    nodeClient.verifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof),
  removeWithdrawalCircuitSession: (handle) => nodeClient.removeWithdrawalCircuitSession(handle),
  removeSecretHandle: (handle) => nodeClient.removeSecretHandle(handle),
  proveAndVerifyWithdrawalHandle: (backendProfile, manifestJson, artifactsRoot, requestHandle) =>
    unwrapNativeValue(
      native.proveAndVerifyWithdrawalHandle(
        backendProfile,
        manifestJson,
        artifactsRoot,
        requestHandle,
      ),
    ),
  preflightVerifiedWithdrawalTransactionWithHandle: (
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) =>
    nodeClient.preflightVerifiedWithdrawalTransactionWithHandle(
      chainId,
      poolAddress,
      rpcUrl,
      {
        expectedChainId: policy.expected_chain_id,
        caller: policy.caller,
        expectedPoolCodeHash: policy.expected_pool_code_hash,
        expectedEntrypointCodeHash: policy.expected_entrypoint_code_hash,
        mode: policy.mode,
      },
      proofHandle,
    ),
  removeVerifiedProofHandle: (handle) =>
    unwrapNativeValue(native.removeVerifiedProofHandle(handle)),
  finalizePreflightedTransactionHandle: (rpcUrl, preflightedHandle) =>
    nodeClient.finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle),
  submitFinalizedPreflightedTransactionHandle: (rpcUrl, finalizedHandle, signedTransaction) =>
    nodeClient.submitFinalizedPreflightedTransactionHandle(
      rpcUrl,
      finalizedHandle,
      signedTransaction,
    ),
  removeExecutionHandle: (handle) => nodeClient.removeExecutionHandle(handle),
  clearExecutionHandles: () => nodeClient.clearExecutionHandles(),
  clearVerifiedProofHandles: () => nodeClient.clearVerifiedProofHandles(),
  clearSecretHandles: () => nodeClient.clearSecretHandles(),
  dangerouslyExportPreflightedTransaction: (handle) =>
    nodeDebug.dangerouslyExportPreflightedTransaction(handle),
  dangerouslyExportFinalizedPreflightedTransaction: (handle) =>
    nodeDebug.dangerouslyExportFinalizedPreflightedTransaction(handle),
  dangerouslyExportSubmittedPreflightedTransaction: (handle) =>
    nodeDebug.dangerouslyExportSubmittedPreflightedTransaction(handle),
};

export const NativeModules = { PrivacyPoolsSdk: module };
export const Platform = { OS: "ios", select(value) { return value?.ios ?? value?.native ?? value?.default ?? null; } };
export default { NativeModules, Platform };
`,
    );
    writeFileSync(join(tempRoot, "index.ts"), readFileSync(rnIndexPath, "utf8"));
    writeFileSync(join(tempRoot, "debug.ts"), readFileSync(rnDebugPath, "utf8"));
    writeFileSync(inputJson, `${JSON.stringify(fixture, null, 2)}\n`);
    writeFileSync(
      runnerPath,
      `import { readFileSync } from "node:fs";
import { NativeModules } from "react-native";
import * as nodeCompat from ${JSON.stringify(nodeIndexUrl)};
import * as entry from "./index.ts";
import * as debugEntry from "./debug.ts";
import { buildStatefulTrace } from ${JSON.stringify(helperUrl)};
import {
  signFinalizedTransactionRequest,
  signFinalizedTransactionRequestWithWrongSigner,
} from ${JSON.stringify(fixtureHelpersUrl)};

const fixture = JSON.parse(readFileSync(new URL("./input.json", import.meta.url), "utf8"));
const nativeModule = NativeModules.PrivacyPoolsSdk;
const nodeClient = new nodeCompat.PrivacyPoolsSdkClient();
const bytesToHex = (value) =>
  typeof value === "string"
    ? value
    : \`0x\${Array.from(value ?? []).map((byte) => byte.toString(16).padStart(2, "0")).join("")}\`;
const facade = {
  deriveMasterKeys: (mnemonic) => entry.deriveMasterKeys(mnemonic),
  deriveMasterKeysHandle: (mnemonic) => entry.deriveMasterKeysHandle(mnemonic),
  deriveDepositSecrets: (masterNullifier, masterSecret, scope, index) =>
    entry.deriveDepositSecrets(masterNullifier, masterSecret, scope, index),
  generateDepositSecretsHandle: (masterKeysHandle, scope, index) =>
    entry.generateDepositSecretsHandle(masterKeysHandle, scope, index),
  deriveWithdrawalSecrets: (masterNullifier, masterSecret, label, index) =>
    entry.deriveWithdrawalSecrets(masterNullifier, masterSecret, label, index),
  generateWithdrawalSecretsHandle: (masterKeysHandle, label, index) =>
    entry.generateWithdrawalSecretsHandle(masterKeysHandle, label, index),
  getCommitment: (value, label, nullifier, secret) =>
    entry.getCommitment(value, label, nullifier, secret),
  getCommitmentFromHandles: (value, label, secretsHandle) =>
    entry.getCommitmentFromHandles(value, label, secretsHandle),
  prepareWithdrawalCircuitSessionFromBytes: (manifestJson, artifacts) =>
    entry.prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts),
  proveWithdrawalWithSession: (backendProfile, sessionHandle, request) =>
    entry.proveWithdrawalWithSession(backendProfile, sessionHandle, request),
  verifyWithdrawalProofWithSession: (backendProfile, sessionHandle, proof) =>
    entry.verifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof),
  removeWithdrawalCircuitSession: (handle) =>
    entry.removeWithdrawalCircuitSession(handle),
  async proveAndVerifyWithdrawalHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    withdrawal,
    scope,
    withdrawalAmount,
    stateWitness,
    aspWitness,
    newSecretsHandle,
  ) {
    return nodeClient.proveAndVerifyWithdrawalHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      { ...withdrawal, data: bytesToHex(withdrawal.data) },
      scope,
      withdrawalAmount,
      stateWitness,
      aspWitness,
      newSecretsHandle,
    );
  },
  preflightVerifiedWithdrawalTransactionWithHandle: (
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) =>
    entry.preflightVerifiedWithdrawalTransactionWithHandle(
      chainId,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    ),
  finalizePreflightedTransactionHandle: (rpcUrl, preflightedHandle) =>
    entry.finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle),
  submitFinalizedPreflightedTransactionHandle: (
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  ) =>
    entry.submitFinalizedPreflightedTransactionHandle(
      rpcUrl,
      finalizedHandle,
      signedTransaction,
    ),
  removeExecutionHandle: (handle) => entry.removeExecutionHandle(handle),
  clearExecutionHandles: () => entry.clearExecutionHandles(),
  clearVerifiedProofHandles: () => entry.clearVerifiedProofHandles(),
  clearSecretHandles: () => entry.clearSecretHandles(),
};
const trace = await buildStatefulTrace({
  runtime: "react-native",
  entry: facade,
  debugEntry,
  fixture,
  signFinalizedTransaction: signFinalizedTransactionRequest,
  signFinalizedTransactionWithWrongSigner: signFinalizedTransactionRequestWithWrongSigner,
});
process.stdout.write(JSON.stringify(trace));
`,
    );

    return JSON.parse(
      await execFileAsync("node", ["--experimental-strip-types", runnerPath], {
        cwd: tempRoot,
        encoding: "utf8",
      }),
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function startExecutionRpcFixtureServer(options) {
  const serverPath = fileURLToPath(new URL("../test/execution-rpc-server.mjs", import.meta.url));
  const child = spawn(process.execPath, [serverPath, JSON.stringify(options)], {
    cwd: packageRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const url = await new Promise((resolve, reject) => {
    let stdout = "";
    const onData = (chunk) => {
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline === -1) {
        return;
      }
      const line = stdout.slice(0, newline).trim();
      child.stdout.off("data", onData);
      try {
        resolve(JSON.parse(line).url);
      } catch (error) {
        reject(error);
      }
    };
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", onData);
    child.once("error", reject);
    child.once("exit", (code) => {
      reject(
        new Error(
          `execution rpc fixture server exited before reporting a URL (code ${code}): ${stderr}`,
        ),
      );
    });
  });

  return {
    url,
    async stop() {
      if (child.exitCode !== null) {
        return;
      }
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill("SIGTERM");
      });
    },
  };
}

function compare(checks, name, actual, expected) {
  const passed = JSON.stringify(actual) === JSON.stringify(expected);
  checks.push({
    name,
    passed,
    actual: passed ? undefined : actual,
    expected: passed ? undefined : expected,
  });
}

function writeReport(path, report) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
}

function execFileAsync(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, options, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(stdout ?? "");
    });
  });
}
