import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

import {
  Circuits,
  PrivacyPoolsSdkClient,
  createWorkerClient,
} from "../src/browser/index.mjs";
import * as browserDebug from "../src/browser/debug.mjs";
import {
  createFixtureServer,
  fixturesRoot,
  preflightFixtureArtifacts,
  readFixtureJson,
} from "./browser-fixtures.mjs";

const sampleManifest = readFileSync(
  join(fixturesRoot, "artifacts", "sample-manifest.json"),
  "utf8",
);
const sampleProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "sample-proving-manifest.json"),
  "utf8",
);
const withdrawalProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "withdrawal-proving-manifest.json"),
  "utf8",
);
const sampleArtifact = readFileSync(
  join(fixturesRoot, "artifacts", "sample-artifact.bin"),
);
const browserVerificationProof = readFixtureJson(
  "vectors/browser-verification-proof.json",
);
const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");

test("browser pr fail-closed rejects unsigned manifests unless the test-only override is enabled", async () => {
  preflightFixtureArtifacts(withdrawalProvingManifest);
  const circuits = new Circuits({
    artifactsRoot: "http://127.0.0.1:1/artifacts/",
    withdrawalManifestJson: withdrawalProvingManifest,
  });

  await assert.rejects(
    () => circuits.downloadArtifacts(),
    /allowUnsignedArtifactsForTesting/i,
  );
});

test("browser pr fail-closed rejects signed manifests with the wrong public key and tampered artifact bytes", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const wrongPublicKey = generateKeyPairSync("ed25519").publicKey;
  const withdrawalFixture = createSignedManifestFixture("withdraw", privateKey, publicKey);
  const commitmentFixture = createSignedManifestFixture("commitment", privateKey, publicKey);
  const server = createFixtureServer({
    overrides: new Map([
      ...withdrawalFixture.artifacts.map((artifact) => [
        `artifacts/${artifact.filename}`,
        artifact.bytes,
      ]),
      ...commitmentFixture.artifacts.map((artifact) => [
        `artifacts/${artifact.filename}`,
        artifact.bytes,
      ]),
    ]),
  });
  await server.start();

  try {
    const wrongKeyCircuits = new Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalSignedManifestJson: withdrawalFixture.envelopeJson,
      commitmentSignedManifestJson: commitmentFixture.envelopeJson,
      signedManifestPublicKey: ed25519RawPublicKeyHex(wrongPublicKey),
    });
    await assert.rejects(() => wrongKeyCircuits.downloadArtifacts(), /signature/i);

    const tamperedServer = createFixtureServer({
      overrides: new Map([
        [
          `artifacts/${withdrawalFixture.artifacts[0].filename}`,
          Buffer.from("tampered withdraw browser pr test artifact"),
        ],
        [
          `artifacts/${commitmentFixture.artifacts[0].filename}`,
          commitmentFixture.artifacts[0].bytes,
        ],
      ]),
    });
    await tamperedServer.start();
    try {
      const tamperedCircuits = new Circuits({
        artifactsRoot: tamperedServer.rootUrl,
        withdrawalSignedManifestJson: withdrawalFixture.envelopeJson,
        commitmentSignedManifestJson: commitmentFixture.envelopeJson,
        signedManifestPublicKey: withdrawalFixture.publicKeyHex,
      });
      await assert.rejects(
        () => tamperedCircuits.downloadArtifacts(),
        /sha256|hash/i,
      );
    } finally {
      await tamperedServer.stop();
    }
  } finally {
    await server.stop();
  }
});

test("browser pr fail-closed rejects malformed proving artifacts and proof bundle shapes", async () => {
  preflightFixtureArtifacts(sampleProvingManifest);
  const sdk = new PrivacyPoolsSdkClient();

  try {
    await assert.rejects(
      () =>
        sdk.prepareWithdrawalCircuitSessionFromBytes(sampleProvingManifest, [
          { kind: "wasm", bytes: sampleArtifact },
          { kind: "zkey", bytes: sampleArtifact },
          { kind: "vkey", bytes: sampleArtifact },
        ]),
      /invalid zkey|unexpected end of zkey header|missing Groth16 header/,
    );

    const malformedShape = JSON.parse(JSON.stringify(browserVerificationProof));
    malformedShape.proof.piB = [["69"], ["12", "123"]];
    await assert.rejects(
      () => sdk.formatGroth16ProofBundle(malformedShape),
      /proof shape|pi_b|piB/i,
    );
  } finally {
    await sdk.dispose();
  }
});

test("browser safe worker surface rejects dangerous exports while the debug worker still allows them", async () => {
  const debugWorker = new Worker(new URL("../src/browser/worker.mjs", import.meta.url), {
    type: "module",
  });
  const debugSdk = createWorkerClient(debugWorker);
  const debugClient = browserDebug.createWorkerDebugClient(debugWorker);
  const safeWorker = new Worker(new URL("../src/browser/worker-safe.mjs", import.meta.url), {
    type: "module",
  });
  const safeSdk = createWorkerClient(safeWorker);
  const safeDebugClient = browserDebug.createWorkerDebugClient(safeWorker);

  try {
    const masterKeysHandle = await debugSdk.deriveMasterKeysHandle(cryptoFixture.mnemonic);
    const exportedMasterKeys =
      await debugClient.dangerouslyExportMasterKeys(masterKeysHandle);
    assert.equal(exportedMasterKeys.masterNullifier, cryptoFixture.keys.masterNullifier);

    await assert.rejects(
      () =>
        safeSdk.prepareWithdrawalCircuitSession(
          withdrawalProvingManifest,
          "http://127.0.0.1:1/artifacts/",
        ),
      /unsupported worker method: prepareWithdrawalCircuitSession/i,
    );
    await assert.rejects(
      () => safeDebugClient.dangerouslyExportMasterKeys("debug-handle"),
      /unsupported worker method: dangerouslyExportMasterKeys/i,
    );
    await assert.rejects(
      () => safeDebugClient.dangerouslyExportPreflightedTransaction("debug-handle"),
      /unsupported worker method: dangerouslyExportPreflightedTransaction/i,
    );
  } finally {
    await safeWorker.terminate();
    await debugWorker.terminate();
  }
});

function createSignedManifestFixture(circuit, privateKey, publicKey) {
  const artifacts = [
    {
      circuit,
      kind: "wasm",
      filename: `signed-${circuit}.wasm`,
      bytes: Buffer.from(`signed ${circuit} browser pr test artifact`),
    },
  ];
  const payload = {
    manifest: {
      version: "signed-browser-pr-test",
      artifacts: artifacts.map((artifact) => ({
        circuit: artifact.circuit,
        kind: artifact.kind,
        filename: artifact.filename,
        sha256: createHash("sha256").update(artifact.bytes).digest("hex"),
      })),
    },
    metadata: {
      build: "browser-pr-test",
      repository: "0xbow/privacy-pools-sdk-rs",
      commit: "abcdef0",
    },
  };
  const payloadJson = JSON.stringify(payload);
  return {
    artifacts,
    publicKeyHex: ed25519RawPublicKeyHex(publicKey),
    envelopeJson: JSON.stringify({
      payloadJson,
      signatureHex: sign(null, Buffer.from(payloadJson), privateKey).toString("hex"),
    }),
  };
}

function ed25519RawPublicKeyHex(publicKey) {
  return Buffer.from(
    publicKey.export({ format: "der", type: "spki" }),
  )
    .subarray(-32)
    .toString("hex");
}
