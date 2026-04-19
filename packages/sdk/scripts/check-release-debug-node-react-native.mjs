import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import * as nodeDebug from "../src/node/debug.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = dirname(scriptDir);
const workspaceRoot = join(packageRoot, "..", "..");
const releaseDebugError = /dangerous export helpers are disabled in this build/i;
const releaseTestingError = /testing-only artifact loading is disabled in this build/i;

for (const [name, helper] of dangerousExportHelpers(nodeDebug)) {
  await expectDisabledDebugSurface(`node debug surface ${name}`, () => helper("debug-handle"));
}

runNodeTestingCheck();

runReactNativeDebugCheck();

console.log("release debug surfaces are fail-closed for node and react native");

function dangerousExportHelpers(module) {
  return [
    ["dangerouslyExportMasterKeys", module.dangerouslyExportMasterKeys],
    ["dangerouslyExportCommitmentPreimage", module.dangerouslyExportCommitmentPreimage],
    ["dangerouslyExportSecret", module.dangerouslyExportSecret],
    ["dangerouslyExportPreflightedTransaction", module.dangerouslyExportPreflightedTransaction],
    [
      "dangerouslyExportFinalizedPreflightedTransaction",
      module.dangerouslyExportFinalizedPreflightedTransaction,
    ],
    [
      "dangerouslyExportSubmittedPreflightedTransaction",
      module.dangerouslyExportSubmittedPreflightedTransaction,
    ],
  ];
}

async function expectDisabledDebugSurface(label, operation) {
  await assert.rejects(operation, releaseDebugError, `${label} must reject with the release-build disabled message`);
}

function runNodeTestingCheck() {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-node-testing-"));

  try {
    writeFileSync(
      join(tempRoot, "runner.mjs"),
      `import assert from "node:assert/strict";

const releaseTestingError = /testing-only artifact loading is disabled in this build/i;

await assert.rejects(
  () => import("./testing.mjs"),
  releaseTestingError,
  "node testing surface must reject with the release-build disabled message",
);
`,
    );
    writeFileSync(
      join(tempRoot, "testing.mjs"),
      `import {
  TESTING_SURFACE_DISABLED_ERROR,
  TESTING_SURFACE_ENABLED,
} from "./build-flags.mjs";

if (!TESTING_SURFACE_ENABLED) {
  throw new Error(TESTING_SURFACE_DISABLED_ERROR);
}
`,
    );
    writeFileSync(
      join(tempRoot, "build-flags.mjs"),
      `export const TESTING_SURFACE_ENABLED = false;
export const TESTING_SURFACE_DISABLED_ERROR =
  "testing-only artifact loading is disabled in this build";
`,
    );

    execFileSync("node", [join(tempRoot, "runner.mjs")], {
      cwd: tempRoot,
      stdio: "inherit",
    });
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function runReactNativeDebugCheck() {
  const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rn-debug-"));
  const reactNativeStubRoot = join(tempRoot, "node_modules", "react-native");
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
  dangerouslyExportMasterKeys: async (handle) =>
    parseNativeJson(native.dangerouslyExportMasterKeys(handle)),
  dangerouslyExportCommitmentPreimage: async (handle) =>
    parseNativeJson(native.dangerouslyExportCommitmentPreimage(handle)),
  dangerouslyExportSecret: async (handle) =>
    parseNativeJson(native.dangerouslyExportSecret(handle)),
  dangerouslyExportPreflightedTransaction: async (handle) =>
    parseNativeJson(native.dangerouslyExportPreflightedTransaction(handle)),
  dangerouslyExportFinalizedPreflightedTransaction: async (handle) =>
    parseNativeJson(native.dangerouslyExportFinalizedPreflightedTransaction(handle)),
  dangerouslyExportSubmittedPreflightedTransaction: async (handle) =>
    parseNativeJson(native.dangerouslyExportSubmittedPreflightedTransaction(handle)),
};

export const NativeModules = { PrivacyPoolsSdk: module };
export default { NativeModules };
`,
    );
    writeFileSync(
      join(tempRoot, "debug.ts"),
      readFileSync(join(workspaceRoot, "packages", "react-native", "src", "debug.ts"), "utf8"),
    );
    writeFileSync(
      join(tempRoot, "runner.mjs"),
      `import assert from "node:assert/strict";
import * as debugSurface from "./debug.ts";

const releaseDebugError = /dangerous export helpers are disabled in this build/i;
const releaseTestingError = /testing-only artifact loading is disabled in this build/i;

for (const helper of [
  debugSurface.dangerouslyExportMasterKeys,
  debugSurface.dangerouslyExportCommitmentPreimage,
  debugSurface.dangerouslyExportSecret,
  debugSurface.dangerouslyExportPreflightedTransaction,
  debugSurface.dangerouslyExportFinalizedPreflightedTransaction,
  debugSurface.dangerouslyExportSubmittedPreflightedTransaction,
]) {
  await assert.rejects(
    () => helper("debug-handle"),
    releaseDebugError,
    "react native debug surface must reject with the release-build disabled message",
  );
}

await assert.rejects(
  () => import("./testing.ts"),
  releaseTestingError,
  "react native testing surface must reject with the release-build disabled message",
);
`,
    );
    writeFileSync(
      join(tempRoot, "testing.ts"),
      `import {
  TESTING_SURFACE_DISABLED_ERROR,
  TESTING_SURFACE_ENABLED,
} from "./build-flags.js";

if (!TESTING_SURFACE_ENABLED) {
  throw new Error(TESTING_SURFACE_DISABLED_ERROR);
}
`,
    );
    writeFileSync(
      join(tempRoot, "build-flags.js"),
      `export const TESTING_SURFACE_ENABLED = false;
export const TESTING_SURFACE_DISABLED_ERROR =
  "testing-only artifact loading is disabled in this build";
`,
    );

    execFileSync("node", ["--experimental-strip-types", join(tempRoot, "runner.mjs")], {
      cwd: tempRoot,
      stdio: "inherit",
    });
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}
