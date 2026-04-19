import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { extname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

import {
  artifactsRoot as fixtureArtifactsRoot,
  buildBenchmarkReport,
  cryptoFixture,
  fixturesRoot,
  nowMs,
  withdrawalFixture,
  withdrawalManifestPath,
  writeReport,
} from "./benchmark-common.mjs";

const options = parseArgs(process.argv.slice(2));
const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const manifestJson = readFileSync(withdrawalManifestPath, "utf8");

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function main() {
  const moduleServer = createStaticServer(packageRoot);
  const artifactServer = createStaticServer(fixturesRoot, { cors: true });
  const browser = await chromium.launch({ headless: true });

  await moduleServer.start();
  await artifactServer.start();

  try {
    const page = await browser.newPage();
    await page.goto(`${moduleServer.origin}/`);

    const result = await page.evaluate(
      async ({ cryptoFixture, withdrawalFixture, manifestJson, artifactsRoot, iterations }) => {
        const { PrivacyPoolsSdkClient } = await import("/src/browser/index.mjs");
        const sdk = new PrivacyPoolsSdkClient();
        try {
          const commitment = await sdk.getCommitment(
            withdrawalFixture.existingValue,
            withdrawalFixture.label,
            cryptoFixture.depositSecrets.nullifier,
            cryptoFixture.depositSecrets.secret,
          );
          const request = {
            commitment,
            withdrawal: {
              processooor: "0x1111111111111111111111111111111111111111",
              data: "0x1234",
            },
            scope: cryptoFixture.scope,
            withdrawalAmount: withdrawalFixture.withdrawalAmount,
            stateWitness: withdrawalFixture.stateWitness,
            aspWitness: withdrawalFixture.aspWitness,
            newNullifier: withdrawalFixture.newNullifier,
            newSecret: withdrawalFixture.newSecret,
          };

          const artifactResolutionStart = Date.now();
          await sdk.getArtifactStatuses(manifestJson, artifactsRoot);
          const artifactResolutionMs = Date.now() - artifactResolutionStart;

          const bundleVerificationStart = Date.now();
          await sdk.resolveVerifiedArtifactBundle(manifestJson, artifactsRoot);
          const bundleVerificationMs = Date.now() - bundleVerificationStart;

          const sessionPreloadStart = Date.now();
          const session = await sdk.prepareWithdrawalCircuitSession(
            manifestJson,
            artifactsRoot,
          );
          const sessionPreloadMs = Date.now() - sessionPreloadStart;

          const samples = [];
          for (let iteration = 0; iteration < iterations; iteration += 1) {
            const inputPreparationStart = Date.now();
            await sdk.buildWithdrawalCircuitInput(request);
            const inputPreparationMs = Date.now() - inputPreparationStart;

            const stageTimes = new Map();
            const proveStart = Date.now();
            const proof = await sdk.proveWithdrawalWithSession(
              "stable",
              session.handle,
              request,
              {
                onStatus(status) {
                  if (status?.stage && !stageTimes.has(status.stage)) {
                    stageTimes.set(status.stage, Date.now());
                  }
                },
              },
            );
            const proveFinishedAt = Date.now();
            const proveStageStartedAt = stageTimes.get("prove");
            const witnessGenerationMs =
              proveStageStartedAt == null
                ? proveFinishedAt - proveStart
                : Math.max(0, proveStageStartedAt - proveStart);
            const proofGenerationMs =
              proveStageStartedAt == null
                ? 0
                : Math.max(0, proveFinishedAt - proveStageStartedAt);

            const verificationStart = Date.now();
            const verified = await sdk.verifyWithdrawalProofWithSession(
              "stable",
              session.handle,
              proof.proof,
            );
            const verificationMs = Date.now() - verificationStart;
            if (!verified) {
              throw new Error("browser benchmark proof did not verify");
            }

            samples.push({
              inputPreparationMs,
              witnessGenerationMs,
              proofGenerationMs,
              verificationMs,
              proveAndVerifyMs: proveFinishedAt - proveStart + verificationMs,
            });
          }

          await sdk.dispose();
          return {
            artifactResolutionMs,
            bundleVerificationMs,
            sessionPreloadMs,
            samples,
          };
        } finally {
          await sdk.dispose();
        }
      },
      {
        cryptoFixture,
        withdrawalFixture,
        manifestJson,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
        iterations: options.iterations,
      },
    );

    const report = buildBenchmarkReport({
      deviceLabel: options.deviceLabel,
      deviceModel: options.deviceModel,
      deviceClass: options.deviceClass,
      samples: result.samples,
      artifactResolutionMs: result.artifactResolutionMs,
      bundleVerificationMs: result.bundleVerificationMs,
      sessionPreloadMs: result.sessionPreloadMs,
      peakResidentMemoryBytes: null,
      manifestPath: withdrawalManifestPath,
      artifactsRootPath: fixtureArtifactsRoot,
    });
    report.browser_transport = "direct";
    writeReport(options.report, report);
    console.log(`wrote browser benchmark report to ${options.report}`);
  } finally {
    await browser.close();
    await moduleServer.stop();
    await artifactServer.stop();
  }
}

function parseArgs(rawArgs) {
  const parsed = {
    report: "",
    iterations: 3,
    deviceLabel: "desktop",
    deviceModel: "reference-desktop",
    deviceClass: "desktop-reference",
  };

  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    switch (arg) {
      case "--report":
        parsed.report = rawArgs[++index] ?? "";
        break;
      case "--iterations":
        parsed.iterations = Number.parseInt(rawArgs[++index] ?? "3", 10);
        break;
      case "--device-label":
        parsed.deviceLabel = rawArgs[++index] ?? "";
        break;
      case "--device-model":
        parsed.deviceModel = rawArgs[++index] ?? "";
        break;
      case "--device-class":
        parsed.deviceClass = rawArgs[++index] ?? "";
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!parsed.report) {
    throw new Error("--report is required");
  }

  return parsed;
}

function createStaticServer(root, options = {}) {
  const requests = [];
  const server = createServer((request, response) => {
    const relativePath = normalize(new URL(request.url ?? "/", "http://local").pathname)
      .replace(/^\/+/, "")
      .replace(/\.\.(\/|\\)/g, "");

    if (options.cors) {
      response.setHeader("access-control-allow-origin", "*");
    }
    if (!relativePath) {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><html><body>privacy pools benchmark</body></html>");
      return;
    }

    requests.push(`/${relative(root, join(root, relativePath)).replaceAll("\\", "/")}`);
    const filePath = join(root, relativePath);
    try {
      const body = readFileSync(filePath);
      response.writeHead(200, { "content-type": contentType(extname(filePath)) });
      response.end(body);
    } catch {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("not found");
    }
  });

  return {
    origin: "",
    requests,
    async start() {
      await new Promise((resolve) => {
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      this.origin = `http://127.0.0.1:${address.port}`;
    },
    async stop() {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

function contentType(extension) {
  switch (extension) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".mjs":
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    default:
      return "application/octet-stream";
  }
}
