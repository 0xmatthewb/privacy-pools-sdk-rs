import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = dirname(scriptDir);
const workspaceRoot = join(packageRoot, "..", "..");
const reactNativePackageRoot = join(workspaceRoot, "packages", "react-native");

const outputPath = parseOutputPath(process.argv.slice(2));
const tempRoot = mkdtempSync(join(tmpdir(), "privacy-pools-rn-sbom-"));
const npmEnv = {
  ...process.env,
  npm_config_cache: join(tempRoot, ".npm-cache"),
};

try {
  writeFileSync(
    join(tempRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "privacy-pools-sdk-react-native-sbom",
        private: true,
        version: "0.0.0",
        dependencies: {
          "@types/react": "19.0.0",
          react: "19.0.0",
          "react-native": "0.79.7",
          typescript: "5.8.3",
        },
      },
      null,
      2,
    )}\n`,
  );

  execFileSync(
    "npm",
    ["install", "--ignore-scripts", "--fund=false", "--audit=false"],
    {
      cwd: tempRoot,
      env: npmEnv,
      stdio: "inherit",
    },
  );
  const packedTarball = execFileSync("npm", ["pack", reactNativePackageRoot], {
    cwd: tempRoot,
    env: npmEnv,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  })
    .trim()
    .split("\n")
    .at(-1);
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--fund=false",
      "--audit=false",
      packedTarball,
    ],
    {
      cwd: tempRoot,
      env: npmEnv,
      stdio: "inherit",
    },
  );

  const sbom = execFileSync(
    "npm",
    ["sbom", "--json", "--sbom-format", "spdx", "--omit", "peer"],
    {
      cwd: tempRoot,
      env: npmEnv,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    },
  );

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, sbom.endsWith("\n") ? sbom : `${sbom}\n`);
  console.log(`wrote react native sbom to ${outputPath}`);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function parseOutputPath(args) {
  const outputFlagIndex = args.indexOf("--output");
  if (outputFlagIndex === -1 || !args[outputFlagIndex + 1]) {
    throw new Error("--output is required");
  }
  return args[outputFlagIndex + 1];
}
