import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { extname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { preflightFixtureArtifacts } from "./browser-fixtures.mjs";

const testDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(testDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");

const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");
const withdrawalFixture = readFixtureJson("vectors/withdrawal-circuit-input.json");
const withdrawalProvingManifest = readFixtureText(
  "artifacts/withdrawal-proving-manifest.json",
);
const commitmentProvingManifest = readFixtureText(
  "artifacts/commitment-proving-manifest.json",
);

preflightFixtureArtifacts(withdrawalProvingManifest, commitmentProvingManifest);

test("browser module worker proves and verifies through Chromium", async ({ page }) => {
  markSlowOnCiLinux();
  const moduleServer = createStaticServer(packageRoot);
  const artifactServer = createStaticServer(fixturesRoot, {
    cors: true,
    recordRequests: true,
  });
  const pageErrors = [];
  const requestFailures = [];

  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("requestfailed", (request) => {
    requestFailures.push(`${request.url()} ${request.failure()?.errorText ?? ""}`);
  });

  await moduleServer.start();
  await artifactServer.start();

  try {
    await page.goto(`${moduleServer.origin}/`);

    const result = await page.evaluate(
      async ({
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot,
      }) => {
        const {
          createWorkerClient,
          getRuntimeCapabilities,
        } = await import("/src/browser/index.mjs");
        const directCapabilities = getRuntimeCapabilities();
        const worker = new Worker("/src/browser/worker.mjs", { type: "module" });
        const sdk = createWorkerClient(worker);

        try {
          const capabilities = await sdk.getRuntimeCapabilities();
          const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
          const commitment = await sdk.getCommitment(
            withdrawalFixture.existingValue,
            withdrawalFixture.label,
            cryptoFixture.depositSecrets.nullifier,
            cryptoFixture.depositSecrets.secret,
          );
          const withdrawalRequest = {
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

          const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
            withdrawalProvingManifest,
            artifactsRoot,
          );
          const withdrawalStatuses = [];
          const withdrawalProof = await sdk.proveWithdrawalWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalRequest,
            { onStatus: (status) => withdrawalStatuses.push(status) },
          );
          const withdrawalVerified = await sdk.verifyWithdrawalProofWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalProof.proof,
          );

          const commitmentSession = await sdk.prepareCommitmentCircuitSession(
            commitmentProvingManifest,
            artifactsRoot,
          );
          const commitmentStatuses = [];
          const commitmentProof = await sdk.proveCommitmentWithSession(
            "stable",
            commitmentSession.handle,
            { commitment },
            { onStatus: (status) => commitmentStatuses.push(status) },
          );
          const commitmentVerified = await sdk.verifyCommitmentProofWithSession(
            "stable",
            commitmentSession.handle,
            commitmentProof.proof,
          );

          const masterKeysHandle = await sdk.deriveMasterKeysHandle(
            cryptoFixture.mnemonic,
          );
          const depositSecretsHandle = await sdk.generateDepositSecretsHandle(
            masterKeysHandle,
            cryptoFixture.scope,
            "0",
          );
          const withdrawalSecretsHandle = await sdk.generateWithdrawalSecretsHandle(
            masterKeysHandle,
            cryptoFixture.label,
            "1",
          );
          const commitmentHandle = await sdk.getCommitmentFromHandles(
            withdrawalFixture.existingValue,
            cryptoFixture.label,
            depositSecretsHandle,
          );

          const handleCommitmentStatuses = [];
          const handleCommitmentProof = await sdk.proveCommitmentWithHandle(
            "stable",
            commitmentProvingManifest,
            artifactsRoot,
            commitmentHandle,
            { onStatus: (status) => handleCommitmentStatuses.push(status) },
          );
          const handleCommitmentVerified = await sdk.verifyCommitmentProof(
            "stable",
            commitmentProvingManifest,
            artifactsRoot,
            handleCommitmentProof.proof,
          );

          const handleWithdrawalStatuses = [];
          const handleWithdrawalProof = await sdk.proveWithdrawalWithHandles(
            "stable",
            withdrawalProvingManifest,
            artifactsRoot,
            commitmentHandle,
            {
              processooor: "0x1111111111111111111111111111111111111111",
              data: "0x1234",
            },
            cryptoFixture.scope,
            withdrawalFixture.withdrawalAmount,
            withdrawalFixture.stateWitness,
            withdrawalFixture.aspWitness,
            withdrawalSecretsHandle,
            { onStatus: (status) => handleWithdrawalStatuses.push(status) },
          );
          const handleWithdrawalVerified = await sdk.verifyWithdrawalProof(
            "stable",
            withdrawalProvingManifest,
            artifactsRoot,
            handleWithdrawalProof.proof,
          );

          await sdk.clearCircuitSessionCache();
          await sdk.clearSecretHandles();
          let staleSessionFailed = false;
          try {
            await sdk.verifyCommitmentProofWithSession(
              "stable",
              commitmentSession.handle,
              commitmentProof.proof,
            );
          } catch {
            staleSessionFailed = true;
          }

          return {
            capabilities,
            directCapabilities,
            masterNullifier: keys.masterNullifier,
            withdrawalBackend: withdrawalProof.backend,
            withdrawalVerified,
            withdrawalStatusStages: withdrawalStatuses.map((status) => status.stage),
            commitmentBackend: commitmentProof.backend,
            commitmentVerified,
            commitmentStatusStages: commitmentStatuses.map((status) => status.stage),
            handleCommitmentBackend: handleCommitmentProof.backend,
            handleCommitmentVerified,
            handleCommitmentStatusStages: handleCommitmentStatuses.map(
              (status) => status.stage,
            ),
            handleWithdrawalBackend: handleWithdrawalProof.backend,
            handleWithdrawalVerified,
            handleWithdrawalStatusStages: handleWithdrawalStatuses.map(
              (status) => status.stage,
            ),
            staleSessionFailed,
          };
        } finally {
          await sdk.dispose({ terminate: true });
        }
      },
      {
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
      },
    );

    expect(result.directCapabilities.runtime).toBe("browser");
    expect(result.capabilities.runtime).toBe("browser");
    expect(result.masterNullifier).toBe(cryptoFixture.keys.masterNullifier);
    expect(result.withdrawalBackend).toBe("arkworks");
    expect(result.withdrawalVerified).toBe(true);
    expect(result.withdrawalStatusStages).toEqual([
      "preload",
      "witness",
      "witness",
      "prove",
      "verify",
      "done",
    ]);
    expect(result.commitmentBackend).toBe("arkworks");
    expect(result.commitmentVerified).toBe(true);
    expect(result.commitmentStatusStages).toEqual([
      "preload",
      "witness",
      "witness",
      "prove",
      "verify",
      "done",
    ]);
    expect(result.handleCommitmentBackend).toBe("arkworks");
    expect(result.handleCommitmentVerified).toBe(true);
    expect(result.handleCommitmentStatusStages).toEqual([
      "preload",
      "witness",
      "witness-parse",
      "witness-transfer",
      "witness",
      "prove",
      "verify",
      "done",
    ]);
    expect(result.handleWithdrawalBackend).toBe("arkworks");
    expect(result.handleWithdrawalVerified).toBe(true);
    expect(result.handleWithdrawalStatusStages).toEqual([
      "preload",
      "witness",
      "witness-parse",
      "witness-transfer",
      "witness",
      "prove",
      "verify",
      "done",
    ]);
    expect(result.staleSessionFailed).toBe(true);

    expect(artifactServer.requests).toEqual(
      expect.arrayContaining([
        "/artifacts/withdraw.zkey",
        "/artifacts/withdraw.vkey.json",
        "/circuits/withdraw/withdraw.wasm",
        "/artifacts/commitment.zkey",
        "/artifacts/commitment.vkey.json",
        "/circuits/commitment/commitment.wasm",
      ]),
    );
    expect(pageErrors.filter((message) => /node:|fs\/promises/.test(message))).toEqual([]);
    expect(requestFailures.filter((message) => /node:|fs\/promises/.test(message))).toEqual([]);
  } finally {
    await artifactServer.stop();
    await moduleServer.stop();
  }
});

test("experimental threaded browser client falls back cleanly without cross-origin isolation", async ({
  page,
}) => {
  markSlowOnCiLinux();
  const moduleServer = createStaticServer(packageRoot);
  const artifactServer = createStaticServer(fixturesRoot, { cors: true });

  await moduleServer.start();
  await artifactServer.start();

  try {
    await page.goto(`${moduleServer.origin}/`);

    const fallbackResult = await page.evaluate(
      async ({
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        artifactsRoot,
      }) => {
        const threaded = await import("/src/browser/experimental-threaded.mjs");
        const capabilities = threaded.getExperimentalThreadedRuntimeCapabilities();
        const initialization = await threaded.initializeExperimentalThreadedProving({
          threadCount: 2,
        });
        const sdk = await threaded.createExperimentalThreadedBrowserClient({
          threadCount: 2,
        });

        try {
          const commitment = await sdk.getCommitment(
            withdrawalFixture.existingValue,
            withdrawalFixture.label,
            cryptoFixture.depositSecrets.nullifier,
            cryptoFixture.depositSecrets.secret,
          );
          const session = await sdk.prepareWithdrawalCircuitSession(
            withdrawalProvingManifest,
            artifactsRoot,
          );

          return {
            capabilities,
            initialization,
            commitmentHash: commitment.hash,
            sessionHandle: session.handle,
          };
        } finally {
          await sdk.dispose();
        }
      },
      {
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
      },
    );

    expect(fallbackResult.capabilities.threadedProvingAvailable).toBe(false);
    expect(fallbackResult.initialization.threadedProvingEnabled).toBe(false);
    expect(fallbackResult.initialization.fallback).toBe("stable-single-threaded");
    expect(fallbackResult.initialization.reason).toMatch(
      /SharedArrayBuffer|cross-origin isolation/i,
    );
    expect(fallbackResult.commitmentHash).toBe(cryptoFixture.commitment.hash);
    expect(fallbackResult.sessionHandle).toMatch(/^browser-withdraw-session-/);
  } finally {
    await artifactServer.stop();
    await moduleServer.stop();
  }
});

test("experimental threaded browser client matches stable proof invariants", async ({
  page,
}) => {
  markSlowOnCiLinux();
  const moduleServer = createStaticServer(packageRoot, {
    crossOriginIsolated: true,
  });
  const artifactServer = createStaticServer(fixturesRoot, {
    cors: true,
    crossOriginIsolated: true,
  });

  await moduleServer.start();
  await artifactServer.start();

  try {
    await page.goto(`${moduleServer.origin}/`);

    const stableResult = await page.evaluate(
      async ({
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot,
      }) => {
        const { PrivacyPoolsSdkClient } = await import("/src/browser/index.mjs");
        const sdk = new PrivacyPoolsSdkClient();

        try {
          const commitment = await sdk.getCommitment(
            withdrawalFixture.existingValue,
            withdrawalFixture.label,
            cryptoFixture.depositSecrets.nullifier,
            cryptoFixture.depositSecrets.secret,
          );
          const withdrawalRequest = {
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

          const commitmentSession = await sdk.prepareCommitmentCircuitSession(
            commitmentProvingManifest,
            artifactsRoot,
          );
          const commitmentProof = await sdk.proveCommitmentWithSession(
            "stable",
            commitmentSession.handle,
            { commitment },
          );

          const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
            withdrawalProvingManifest,
            artifactsRoot,
          );
          const withdrawalProof = await sdk.proveWithdrawalWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalRequest,
          );

          return {
            commitmentProof: commitmentProof.proof,
            withdrawalProof: withdrawalProof.proof,
          };
        } finally {
          await sdk.dispose();
        }
      },
      {
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
      },
    );

    await page.goto(`${moduleServer.origin}/threaded`);

    const threadedResult = await page.evaluate(
      async ({
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot,
        stableCommitmentProof,
        stableWithdrawalProof,
      }) => {
        const threaded = await import("/src/browser/experimental-threaded.mjs");
        const capabilities = threaded.getExperimentalThreadedRuntimeCapabilities();
        const initialization = await threaded.initializeExperimentalThreadedProving({
          threadCount: 2,
        });
        const sdk = await threaded.createExperimentalThreadedBrowserClient({
          threadCount: 2,
        });

        try {
          const commitment = await sdk.getCommitment(
            withdrawalFixture.existingValue,
            withdrawalFixture.label,
            cryptoFixture.depositSecrets.nullifier,
            cryptoFixture.depositSecrets.secret,
          );
          const withdrawalRequest = {
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

          const commitmentSession = await sdk.prepareCommitmentCircuitSession(
            commitmentProvingManifest,
            artifactsRoot,
          );
          const commitmentProof = await sdk.proveCommitmentWithSession(
            "stable",
            commitmentSession.handle,
            { commitment },
          );

          const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
            withdrawalProvingManifest,
            artifactsRoot,
          );
          const withdrawalProof = await sdk.proveWithdrawalWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalRequest,
          );

          return {
            capabilities,
            initialization,
            commitmentProof: commitmentProof.proof,
            withdrawalProof: withdrawalProof.proof,
            verifiesStableCommitment: await sdk.verifyCommitmentProofWithSession(
              "stable",
              commitmentSession.handle,
              stableCommitmentProof,
            ),
            verifiesStableWithdrawal: await sdk.verifyWithdrawalProofWithSession(
              "stable",
              withdrawalSession.handle,
              stableWithdrawalProof,
            ),
          };
        } finally {
          await sdk.dispose();
        }
      },
      {
        cryptoFixture,
        withdrawalFixture,
        withdrawalProvingManifest,
        commitmentProvingManifest,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
        stableCommitmentProof: stableResult.commitmentProof,
        stableWithdrawalProof: stableResult.withdrawalProof,
      },
    );

    expect(threadedResult.capabilities.threadedProvingAvailable).toBe(true);
    expect(threadedResult.initialization.threadedProvingEnabled).toBe(true);
    expect(threadedResult.initialization.fallback).toBeNull();
    expect(threadedResult.verifiesStableCommitment).toBe(true);
    expect(threadedResult.verifiesStableWithdrawal).toBe(true);
    expect(threadedResult.commitmentProof.publicSignals).toEqual(
      stableResult.commitmentProof.publicSignals,
    );
    expect(threadedResult.withdrawalProof.publicSignals).toEqual(
      stableResult.withdrawalProof.publicSignals,
    );

    await page.goto(`${moduleServer.origin}/stable-cross-verify`);

    const stableCrossVerification = await page.evaluate(
      async ({
        commitmentProvingManifest,
        withdrawalProvingManifest,
        artifactsRoot,
        threadedCommitmentProof,
        threadedWithdrawalProof,
      }) => {
        const { PrivacyPoolsSdkClient } = await import("/src/browser/index.mjs");
        const sdk = new PrivacyPoolsSdkClient();

        try {
          const commitmentSession = await sdk.prepareCommitmentCircuitSession(
            commitmentProvingManifest,
            artifactsRoot,
          );
          const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
            withdrawalProvingManifest,
            artifactsRoot,
          );

          return {
            verifiesThreadedCommitment: await sdk.verifyCommitmentProofWithSession(
              "stable",
              commitmentSession.handle,
              threadedCommitmentProof,
            ),
            verifiesThreadedWithdrawal: await sdk.verifyWithdrawalProofWithSession(
              "stable",
              withdrawalSession.handle,
              threadedWithdrawalProof,
            ),
          };
        } finally {
          await sdk.dispose();
        }
      },
      {
        commitmentProvingManifest,
        withdrawalProvingManifest,
        artifactsRoot: `${artifactServer.origin}/artifacts/`,
        threadedCommitmentProof: threadedResult.commitmentProof,
        threadedWithdrawalProof: threadedResult.withdrawalProof,
      },
    );

    expect(stableCrossVerification.verifiesThreadedCommitment).toBe(true);
    expect(stableCrossVerification.verifiesThreadedWithdrawal).toBe(true);
  } finally {
    await artifactServer.stop();
    await moduleServer.stop();
  }
});

function readFixtureText(path) {
  return readFileSync(join(fixturesRoot, path), "utf8");
}

function markSlowOnCiLinux() {
  if (process.platform === "linux" || process.env.CI) {
    test.slow();
  }
}

function readFixtureJson(path) {
  return JSON.parse(readFixtureText(path));
}

function createStaticServer(root, options = {}) {
  const requests = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (options.recordRequests) {
      requests.push(url.pathname);
    }
    if (options.crossOriginIsolated) {
      response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
      response.setHeader(
        "Cross-Origin-Resource-Policy",
        options.cors ? "cross-origin" : "same-origin",
      );
    }
    if (options.cors) {
      response.setHeader("access-control-allow-origin", "*");
      response.setHeader("access-control-allow-methods", "GET, OPTIONS");
      response.setHeader("access-control-allow-headers", "content-type");
      if (request.method === "OPTIONS") {
        response.statusCode = 204;
        response.end();
        return;
      }
    }

    if (url.pathname === "/") {
      response.statusCode = 200;
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.end("<!doctype html><title>privacy pools sdk browser test</title>");
      return;
    }

    const decodedPath = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const normalizedPath = normalize(decodedPath);
    const filePath = join(root, normalizedPath);
    if (relative(root, filePath).startsWith("..")) {
      response.statusCode = 403;
      response.end("forbidden");
      return;
    }

    try {
      const bytes = readFileSync(filePath);
      response.statusCode = 200;
      response.setHeader("content-type", mimeType(filePath));
      response.end(bytes);
    } catch {
      response.statusCode = 404;
      response.end("not found");
    }
  });

  return {
    origin: "",
    requests,
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      this.origin = `http://127.0.0.1:${address.port}`;
    },
    async stop() {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    },
  };
}

function mimeType(path) {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
    case ".mjs":
      return "text/javascript; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}
