import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = dirname(scriptDir);
const workspaceRoot = join(packageRoot, "..", "..");
const debug = process.argv.includes("--debug");
const release = process.argv.includes("--release");
const experimentalThreaded = process.argv.includes("--experimental-threaded");

const xtask = spawnSync(
  "cargo",
  [
    "run",
    "-p",
    "xtask",
    "--",
    "sdk-web-package",
    ...(debug ? ["--debug"] : []),
    ...(release ? ["--release"] : []),
    ...(experimentalThreaded ? ["--experimental-threaded"] : []),
  ],
  {
    cwd: workspaceRoot,
    stdio: "inherit",
  },
);

if (xtask.status !== 0) {
  process.exit(xtask.status ?? 1);
}
