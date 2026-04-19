import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  trackedFilesForMode,
  validateCanonicalPackageWasm,
} from "./check-generated.mjs";

test("pr-safe generated check ignores raw wasm git drift", () => {
  const tracked = trackedFilesForMode("pr-safe");

  assert.deepEqual(tracked, [
    "src/browser/generated/privacy_pools_sdk_web.d.ts",
    "src/browser/generated/privacy_pools_sdk_web.js",
    "src/browser/generated/privacy_pools_sdk_web_bg.wasm.d.ts",
  ]);
  assert.ok(
    !tracked.includes("src/browser/generated/privacy_pools_sdk_web_bg.wasm"),
  );
});

test("canonical generated check rejects npm tarball wasm mismatch", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "sdk-generated-check-"));

  try {
    const generatedWasmPath = join(tempRoot, "privacy_pools_sdk_web_bg.wasm");
    const packageRoot = join(tempRoot, "package/src/browser/generated");
    const packageTarballPath = join(tempRoot, "sdk-package.tgz");
    mkdirSync(packageRoot, { recursive: true });

    writeFileSync(
      generatedWasmPath,
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    writeFileSync(
      join(packageRoot, "privacy_pools_sdk_web_bg.wasm"),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x01]),
    );
    execFileSync("tar", ["-C", tempRoot, "-czf", packageTarballPath, "package"]);

    assert.throws(
      () => validateCanonicalPackageWasm(generatedWasmPath, packageTarballPath),
      /packaged browser WASM/,
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});
