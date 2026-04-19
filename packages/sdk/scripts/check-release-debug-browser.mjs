import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";

import * as browserDebug from "../src/browser/debug.mjs";

const releaseDebugError = /dangerous export helpers are disabled in this build/i;
const releaseTestingError = /testing-only artifact loading is disabled in this build/i;

await assert.rejects(
  () => import("../src/browser/testing.mjs"),
  releaseTestingError,
  "browser testing surface must reject with the release-build disabled message",
);

for (const helper of [
  browserDebug.dangerouslyExportMasterKeys,
  browserDebug.dangerouslyExportCommitmentPreimage,
  browserDebug.dangerouslyExportSecret,
  browserDebug.dangerouslyExportPreflightedTransaction,
  browserDebug.dangerouslyExportFinalizedPreflightedTransaction,
  browserDebug.dangerouslyExportSubmittedPreflightedTransaction,
]) {
  await assert.rejects(
    () => helper("debug-handle"),
    releaseDebugError,
    "browser debug surface must reject with the release-build disabled message",
  );
}

const worker = new Worker(new URL("../src/browser/worker-safe.mjs", import.meta.url), {
  type: "module",
});

try {
  const workerDebug = browserDebug.createWorkerDebugClient(worker);
  for (const helper of [
    workerDebug.dangerouslyExportMasterKeys.bind(workerDebug),
    workerDebug.dangerouslyExportCommitmentPreimage.bind(workerDebug),
    workerDebug.dangerouslyExportSecret.bind(workerDebug),
    workerDebug.dangerouslyExportPreflightedTransaction.bind(workerDebug),
    workerDebug.dangerouslyExportFinalizedPreflightedTransaction.bind(workerDebug),
    workerDebug.dangerouslyExportSubmittedPreflightedTransaction.bind(workerDebug),
  ]) {
    await assert.rejects(
      () => helper("debug-handle"),
      /unsupported worker method: dangerous/i,
      "browser safe worker surface must not expose dangerous export worker methods",
    );
  }
} finally {
  await worker.terminate();
}

console.log("release debug surface is fail-closed for browser");
