import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as browserSafeEntry from "../src/browser/safe.mjs";
import * as nodeSafeEntry from "../src/node/safe.mjs";
import * as nodeTestingEntry from "../src/node/testing.mjs";

const testDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(testDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");

const compatibilityShapes = JSON.parse(
  readFileSync(
    join(workspaceRoot, "fixtures", "compatibility-shapes", "sdk-json-shapes.json"),
    "utf8",
  ),
);

const reactNativeSource = readFileSync(
  join(workspaceRoot, "packages", "react-native", "src", "safe.ts"),
  "utf8",
);
const reactNativeIndexSource = readFileSync(
  join(workspaceRoot, "packages", "react-native", "src", "index.ts"),
  "utf8",
);
const reactNativeTestingSource = readFileSync(
  join(workspaceRoot, "packages", "react-native", "src", "testing.ts"),
  "utf8",
);
const reactNativeDebugSource = readFileSync(
  join(workspaceRoot, "packages", "react-native", "src", "debug.ts"),
  "utf8",
);
const sdkTypeDeclarations = readFileSync(
  join(packageRoot, "src", "safe.d.ts"),
  "utf8",
);
const sdkTestingDeclarations = readFileSync(
  join(packageRoot, "src", "index.d.ts"),
  "utf8",
);
const sdkDebugDeclarations = readFileSync(
  join(packageRoot, "src", "debug.d.ts"),
  "utf8",
);
const browserBuildFlagsSource = readFileSync(
  join(packageRoot, "src", "browser", "build-flags.mjs"),
  "utf8",
);
const browserWorkerSafeSource = readFileSync(
  join(packageRoot, "src", "browser", "worker-safe.mjs"),
  "utf8",
);
const browserWorkerDebugSource = readFileSync(
  join(packageRoot, "src", "browser", "worker.mjs"),
  "utf8",
);

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertExportedType(source, name, label) {
  assert.match(
    source,
    new RegExp(
      String.raw`(?:\bexport\s+type\s+${escapeRegExp(name)}\b|\bexport\s+type\s*\{[\s\S]*?\b${escapeRegExp(name)}\b[\s\S]*?\}|\bexport\s+\*\s+from\b)`,
    ),
    `${label} should export type ${name}`,
  );
}

function assertExportedCallable(source, name, label) {
  assert.match(
    source,
    new RegExp(
      String.raw`(?:\bexport\s+(?:const|function)\s+${escapeRegExp(name)}\b|\bexport\s*\{[\s\S]*?\b${escapeRegExp(name)}\b[\s\S]*?\}|\bexport\s+\*\s+from\b)`,
    ),
    `${label} should export ${name}`,
  );
}

function assertNotExportedCallable(source, name, label) {
  assert.doesNotMatch(
    source,
    new RegExp(
      String.raw`\b(?:export\s+(?:const|function)\s+${escapeRegExp(name)}\b|export\s*\{[\s\S]*?\b${escapeRegExp(name)}\b[\s\S]*?\})`,
    ),
    `${label} should not export ${name}`,
  );
}

function assertWarningMarkerNear(source, name, marker, label) {
  const symbolIndex = source.indexOf(name);
  assert.notEqual(symbolIndex, -1, `${label} should include ${name}`);
  const context = source.slice(Math.max(0, symbolIndex - 400), symbolIndex);
  assert.match(context, marker, `${label} should keep a warning marker on ${name}`);
}

function testingSurfaceEnabled(source) {
  return /\bTESTING_SURFACE_ENABLED\s*=\s*true\b/.test(source);
}

test("react native surface stays aligned with the frozen compatibility fixture", () => {
  const surface = compatibilityShapes.reactNative.surface;
  const testingOnlyRawArtifactExports = [
    "getArtifactStatuses",
    "prepareCommitmentCircuitSession",
    "prepareCommitmentCircuitSessionFromBytes",
    "prepareRelayExecution",
    "prepareWithdrawalCircuitSession",
    "prepareWithdrawalCircuitSessionFromBytes",
    "prepareWithdrawalExecution",
    "proveAndVerifyCommitmentHandle",
    "proveAndVerifyWithdrawalHandle",
    "proveCommitment",
    "proveCommitmentWithHandle",
    "proveCommitmentWithSession",
    "proveWithdrawal",
    "proveWithdrawalWithHandles",
    "proveWithdrawalWithSession",
    "resolveVerifiedArtifactBundle",
    "startPrepareRelayExecutionJob",
    "startPrepareWithdrawalExecutionJob",
    "startProveWithdrawalJob",
    "startProveWithdrawalJobWithSession",
    "verifyCommitmentProof",
    "verifyCommitmentProofForRequestHandle",
    "verifyCommitmentProofWithSession",
    "verifyRagequitProofForRequestHandle",
    "verifyWithdrawalProof",
    "verifyWithdrawalProofForRequestHandle",
    "verifyWithdrawalProofWithSession",
  ];

  for (const handleType of surface.handleTypes) {
    assertExportedType(reactNativeSource, handleType, "react native package");
  }

  for (const symbol of surface.secretHandleExports) {
    assertExportedCallable(reactNativeSource, symbol, "react native package");
  }

  for (const symbol of surface.debugSecretHandleExports) {
    assert.doesNotMatch(
      reactNativeSource,
      new RegExp(String.raw`\bexport\s+(?:const|function)\s+${escapeRegExp(symbol)}\b`),
      `react native package should not export ${symbol} on the default surface`,
    );
    assertExportedCallable(reactNativeDebugSource, symbol, "react native debug package");
  }

  for (const symbol of surface.verifiedProofHandleExports) {
    assertExportedCallable(reactNativeSource, symbol, "react native package");
  }

  for (const symbol of surface.executionHandleExports) {
    assertExportedCallable(reactNativeSource, symbol, "react native package");
  }

  for (const symbol of surface.debugExecutionHandleExports) {
    assert.doesNotMatch(
      reactNativeSource,
      new RegExp(String.raw`\bexport\s+(?:const|function)\s+${escapeRegExp(symbol)}\b`),
      `react native package should not export ${symbol} on the default surface`,
    );
    assertExportedCallable(reactNativeDebugSource, symbol, "react native debug package");
  }

  for (const symbol of surface.signedManifestExports) {
    assertExportedCallable(reactNativeSource, symbol, "react native package");
  }

  for (const symbol of testingOnlyRawArtifactExports) {
    assertNotExportedCallable(reactNativeSource, symbol, "react native package");
    assertExportedCallable(
      reactNativeTestingSource,
      symbol,
      "react native testing package",
    );
  }
});

test("dangerous export helpers live only on debug surfaces", () => {
  const compatibilityEscapeHatches = [
    "dangerouslyExportMasterKeys",
    "dangerouslyExportCommitmentPreimage",
    "dangerouslyExportSecret",
    "dangerouslyExportPreflightedTransaction",
    "dangerouslyExportFinalizedPreflightedTransaction",
    "dangerouslyExportSubmittedPreflightedTransaction",
  ];
  for (const symbol of compatibilityEscapeHatches) {
    assert.doesNotMatch(
      sdkTypeDeclarations,
      new RegExp(String.raw`\b${escapeRegExp(symbol)}\b`),
      `packages/sdk/src/index.d.ts should not expose ${symbol} by default`,
    );
    assertExportedCallable(
      sdkDebugDeclarations,
      symbol,
      "packages/sdk/src/debug.d.ts",
    );
    assert.doesNotMatch(
      reactNativeSource,
      new RegExp(String.raw`\bexport\s+(?:const|function)\s+${escapeRegExp(symbol)}\b`),
      `packages/react-native/src/index.ts should not expose ${symbol} by default`,
    );
    assertExportedCallable(
      reactNativeDebugSource,
      symbol,
      "packages/react-native/src/debug.ts",
    );
  }
});

test("string mnemonic helpers stay off safe/default surfaces", () => {
  assert.doesNotMatch(
    sdkTypeDeclarations,
    /\bderiveMasterKeysHandle\s*\(/,
    "packages/sdk/src/safe.d.ts should not expose deriveMasterKeysHandle by default",
  );
  assert.match(
    sdkTestingDeclarations,
    /\bderiveMasterKeysHandle\s*\(/,
    "packages/sdk/src/index.d.ts should keep deriveMasterKeysHandle for testing flows",
  );
  assert.doesNotMatch(
    reactNativeSource,
    /\bderiveMasterKeysHandle\b/,
    "packages/react-native/src/safe.ts should not expose deriveMasterKeysHandle by default",
  );
  assert.match(
    reactNativeIndexSource,
    /\bderiveMasterKeysHandle\s*\(/,
    "packages/react-native/src/index.ts should keep deriveMasterKeysHandle for testing flows",
  );
});

test("safe worker surface does not register dangerous export rpc methods", () => {
  for (const symbol of [
    "dangerouslyExportMasterKeys",
    "dangerouslyExportCommitmentPreimage",
    "dangerouslyExportSecret",
    "dangerouslyExportPreflightedTransaction",
    "dangerouslyExportFinalizedPreflightedTransaction",
    "dangerouslyExportSubmittedPreflightedTransaction",
  ]) {
    assert.doesNotMatch(
      browserWorkerSafeSource,
      new RegExp(String.raw`\b${escapeRegExp(symbol)}\b`),
      `packages/sdk/src/browser/worker-safe.mjs should not register ${symbol}`,
    );
    assert.match(
      browserWorkerDebugSource,
      new RegExp(String.raw`\b${escapeRegExp(symbol)}\b`),
      `packages/sdk/src/browser/worker.mjs should keep ${symbol} for explicit debug/testing flows`,
    );
  }
});

test("public sdk declarations keep low-level planner warnings attached", () => {
  const rawPlannerExports = [
    "planWithdrawalTransaction",
    "planRelayTransaction",
    "planRagequitTransaction",
  ];

  for (const symbol of rawPlannerExports) {
    assertWarningMarkerNear(
      sdkTypeDeclarations,
      symbol,
      /Low-level compatibility\/offline formatting API/,
      "packages/sdk/src/index.d.ts",
    );
    assertWarningMarkerNear(
      reactNativeIndexSource,
      symbol,
      /Low-level compatibility\/offline formatting API/,
      "packages/react-native/src/index.ts",
    );
  }
});

test("safe sdk declarations keep raw-manifest runtime entrypoints off the root surface", () => {
  const testingOnlyExports = [
    "proveCommitmentWithHandle",
    "proveWithdrawalWithHandles",
    "proveAndVerifyCommitmentHandle",
    "proveAndVerifyWithdrawalHandle",
    "verifyCommitmentProofForRequestHandle",
    "verifyRagequitProofForRequestHandle",
    "verifyWithdrawalProofForRequestHandle",
    "proveWithdrawalBinary",
    "proveCommitmentBinary",
  ];

  for (const symbol of testingOnlyExports) {
    assert.doesNotMatch(
      sdkTypeDeclarations,
      new RegExp(String.raw`\b${escapeRegExp(symbol)}\b`),
      `packages/sdk/src/safe.d.ts should not expose ${symbol}`,
    );
    assert.match(
      sdkTestingDeclarations,
      new RegExp(String.raw`\b${escapeRegExp(symbol)}\b`),
      `packages/sdk/src/index.d.ts should keep ${symbol} on the testing surface`,
    );
  }
});

test("safe sdk runtime modules expose testing-only raw-manifest exports only on /testing", async () => {
  const sharedTestingOnlyExports = [
    "proveCommitmentWithHandle",
    "proveWithdrawalWithHandles",
    "proveAndVerifyCommitmentHandle",
    "proveAndVerifyWithdrawalHandle",
    "verifyCommitmentProofForRequestHandle",
    "verifyRagequitProofForRequestHandle",
    "verifyWithdrawalProofForRequestHandle",
  ];
  const browserOnlyTestingExports = ["proveWithdrawalBinary", "proveCommitmentBinary"];
  const browserTestingEnabled = testingSurfaceEnabled(browserBuildFlagsSource);
  let browserTestingEntry = null;
  let browserTestingError = null;
  try {
    browserTestingEntry = await import("../src/browser/testing.mjs");
  } catch (error) {
    browserTestingError = error;
  }

  for (const symbol of sharedTestingOnlyExports) {
    assert.equal(symbol in nodeSafeEntry, false, `node safe entry should not export ${symbol}`);
    assert.equal(
      typeof nodeTestingEntry[symbol],
      "function",
      `node testing entry should export ${symbol}`,
    );
    assert.equal(
      symbol in browserSafeEntry,
      false,
      `browser safe entry should not export ${symbol}`,
    );
    if (browserTestingEnabled) {
      assert.equal(
        typeof browserTestingEntry?.[symbol],
        "function",
        `browser testing entry should export ${symbol}`,
      );
    }
  }

  for (const symbol of browserOnlyTestingExports) {
    assert.equal(symbol in nodeSafeEntry, false, `node safe entry should not export ${symbol}`);
    assert.equal(symbol in nodeTestingEntry, false, `node testing entry should not export ${symbol}`);
    assert.equal(
      symbol in browserSafeEntry,
      false,
      `browser safe entry should not export ${symbol}`,
    );
    if (browserTestingEnabled) {
      assert.equal(
        typeof browserTestingEntry?.[symbol],
        "function",
        `browser testing entry should export ${symbol}`,
      );
    }
  }

  if (browserTestingEnabled) {
    assert.equal(browserTestingError, null, "browser testing entry should import cleanly");
  } else {
    assert.match(
      String(browserTestingError?.message ?? browserTestingError),
      /testing-only artifact loading is disabled/i,
      "browser testing entry should fail closed when disabled in this build",
    );
  }
});

test("safe sdk Circuits rejects raw-manifest options on the root surface", async () => {
  for (const entry of [nodeSafeEntry, browserSafeEntry]) {
    assert.throws(
      () =>
        new entry.Circuits({
          artifactsRoot: "http://127.0.0.1:1/artifacts/",
          withdrawalManifestJson: "{}",
          allowUnsignedArtifactsForTesting: true,
        }),
      /\/testing/,
    );
  }
});
