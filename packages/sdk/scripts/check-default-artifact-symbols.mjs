import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const workspaceRoot = join(packageRoot, "..", "..");

const nativeForbiddenPatterns = [
  /\bdangerouslyExport[A-Za-z]+\b/g,
  /\bdangerously_export_[a-z_]+\b/g,
  /\bderiveMasterKeys(?:Json)?\b/g,
  /\bderiveDepositSecrets(?:Json)?\b/g,
  /\bderiveWithdrawalSecrets(?:Json)?\b/g,
  /\bderive_master_keys\b/g,
  /\bderive_deposit_secrets\b/g,
  /\bderive_withdrawal_secrets\b/g,
];

main();

function main() {
  const ffiExtension =
    process.platform === "darwin"
      ? "dylib"
      : process.platform === "win32"
        ? "dll"
        : "so";
  const nodeArtifact = join(packageRoot, "privacy_pools_sdk_node.node");
  const ffiArtifact = join(
    workspaceRoot,
    "target",
    "release",
    process.platform === "win32"
      ? "privacy_pools_sdk_ffi.dll"
      : `libprivacy_pools_sdk_ffi.${ffiExtension}`,
  );
  const wasmArtifact = join(
    packageRoot,
    "src",
    "browser",
    "generated",
    "privacy_pools_sdk_web_bg.wasm",
  );

  for (const artifact of [
    { label: "node addon", path: nodeArtifact },
    { label: "ffi library", path: ffiArtifact },
  ]) {
    assertExists(artifact.path);
    assertNoForbiddenMatches(
      `${artifact.label} symbol scan`,
      `${runNm(artifact.path)}\n${runStrings(artifact.path)}`,
      nativeForbiddenPatterns,
    );
  }

  assertExists(wasmArtifact);
  assertNoForbiddenMatches(
    "browser wasm export scan",
    runWasmObjdump(wasmArtifact),
    nativeForbiddenPatterns,
  );
}

function assertExists(path) {
  if (!existsSync(path)) {
    throw new Error(`missing artifact for symbol scan: ${path}`);
  }
}

function run(command, args) {
  return execFileSync(command, args, {
    cwd: workspaceRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
}

function runNm(path) {
  if (process.platform === "darwin") {
    return run("nm", ["-gU", path]);
  }
  if (process.platform === "win32") {
    return run("llvm-nm", ["--defined-only", path]);
  }
  return run("nm", ["-D", "--defined-only", path]);
}

function runStrings(path) {
  return run("strings", [path]);
}

function runWasmObjdump(path) {
  try {
    return run("wasm-objdump", ["-x", path]);
  } catch (error) {
    return runStrings(path);
  }
}

function assertNoForbiddenMatches(label, haystack, patterns) {
  const matches = new Set();
  for (const pattern of patterns) {
    for (const match of haystack.matchAll(pattern)) {
      matches.add(match[0]);
    }
  }

  if (matches.size > 0) {
    throw new Error(`${label} exposed forbidden symbols: ${Array.from(matches).sort().join(", ")}`);
  }
}
