import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = dirname(scriptDir);
const workspaceRoot = join(packageRoot, "..", "..");
const release = process.argv.includes("--release");
const profile = release ? "release" : "debug";
const buildFlagsPath = join(packageRoot, "src", "node", "build-flags.mjs");
const originalBuildFlags = readFileSync(buildFlagsPath, "utf8");

try {
  writeTestingSurfaceFlags(buildFlagsPath, !release);

  const cargo = spawnSync(
    "cargo",
    [
      "build",
      "-p",
      "privacy-pools-sdk-node",
      ...(!release ? ["--features", "dangerous-exports,dangerous-key-export"] : []),
      ...(release ? ["--release"] : []),
    ],
    {
      cwd: workspaceRoot,
      stdio: "inherit",
    },
  );

  if (cargo.status !== 0) {
    process.exit(cargo.status ?? 1);
  }

  const sourceName =
    process.platform === "darwin"
      ? "libprivacy_pools_sdk_node.dylib"
      : process.platform === "linux"
        ? "libprivacy_pools_sdk_node.so"
        : process.platform === "win32"
          ? "privacy_pools_sdk_node.dll"
          : null;

  if (!sourceName) {
    throw new Error(`unsupported platform: ${process.platform}`);
  }

  const sourcePath = join(workspaceRoot, "target", profile, sourceName);
  if (!existsSync(sourcePath)) {
    throw new Error(`native addon build output not found: ${sourcePath}`);
  }

  const destinationPath = join(packageRoot, "privacy_pools_sdk_node.node");
  copyFileSync(sourcePath, destinationPath);
  console.log(`copied ${sourcePath} -> ${destinationPath}`);
} finally {
  writeFileSync(buildFlagsPath, originalBuildFlags);
}

function writeTestingSurfaceFlags(path, enabled) {
  const rendered = `export const TESTING_SURFACE_ENABLED = ${enabled ? "true" : "false"};\nexport const TESTING_SURFACE_DISABLED_ERROR =\n  "testing-only artifact loading is disabled in this build";\n`;
  writeFileSync(path, rendered);
}
