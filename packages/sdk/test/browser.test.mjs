import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import {
  BrowserRuntimeUnavailableError,
  PrivacyPoolsSdkClient,
  createWorkerClient,
  getRuntimeCapabilities,
} from "../src/browser/index.mjs";
import {
  PrivacyPoolsSdkClient as NodePrivacyPoolsSdkClient,
} from "../src/node/index.mjs";

const testDir = fileURLToPath(new URL(".", import.meta.url));
const workspaceRoot = join(testDir, "..", "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");

const cryptoFixture = JSON.parse(
  readFileSync(join(fixturesRoot, "vectors", "crypto-compatibility.json"), "utf8"),
);
const withdrawalFixture = JSON.parse(
  readFileSync(
    join(fixturesRoot, "vectors", "withdrawal-circuit-input.json"),
    "utf8",
  ),
);
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
const withdrawalVerificationManifest = readFileSync(
  join(fixturesRoot, "artifacts", "withdrawal-verification-manifest.json"),
  "utf8",
);
const browserVerificationManifest = readFileSync(
  join(fixturesRoot, "artifacts", "browser-verification-manifest.json"),
  "utf8",
);
const commitmentProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "commitment-proving-manifest.json"),
  "utf8",
);
const commitmentVerificationManifest = readFileSync(
  join(fixturesRoot, "artifacts", "commitment-verification-manifest.json"),
  "utf8",
);
const sampleArtifact = readFileSync(
  join(fixturesRoot, "artifacts", "sample-artifact.bin"),
);
const browserVerificationProof = JSON.parse(
  readFileSync(
    join(fixturesRoot, "vectors", "browser-verification-proof.json"),
    "utf8",
  ),
);
const artifactsFixtureRoot = join(fixturesRoot, "artifacts");
const BN254_BASE_FIELD_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

test("browser runtime reports browser verification capabilities", () => {
  assert.deepEqual(getRuntimeCapabilities(), {
    runtime: "browser",
    provingAvailable: true,
    verificationAvailable: true,
    workerAvailable: true,
    reason:
      "Browser proving and verification are available through Rust/WASM with browser-native circuit witness execution.",
  });
});

test("browser wasm runtime matches reference helper vectors", async () => {
  const sdk = new PrivacyPoolsSdkClient();

  assert.deepEqual(await sdk.getRuntimeCapabilities(), getRuntimeCapabilities());
  assert.equal(await sdk.getStableBackendName(), "Arkworks");
  assert.equal(await sdk.fastBackendSupportedOnTarget(), false);

  const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
  assert.equal(keys.masterNullifier, cryptoFixture.keys.masterNullifier);
  assert.equal(keys.masterSecret, cryptoFixture.keys.masterSecret);

  const depositSecrets = await sdk.deriveDepositSecrets(
    keys,
    cryptoFixture.scope,
    "0",
  );
  assert.deepEqual(depositSecrets, cryptoFixture.depositSecrets);

  const withdrawalSecrets = await sdk.deriveWithdrawalSecrets(
    keys,
    cryptoFixture.label,
    "1",
  );
  assert.deepEqual(withdrawalSecrets, cryptoFixture.withdrawalSecrets);

  const commitment = await sdk.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
  );
  assert.equal(commitment.hash, cryptoFixture.commitment.hash);
  assert.equal(commitment.nullifierHash, cryptoFixture.commitment.nullifierHash);

  const merkleProof = await sdk.generateMerkleProof(
    ["11", "22", "33", "44", "55"],
    "44",
  );
  assert.equal(merkleProof.root, cryptoFixture.merkleProof.root);

  const paddedWitness = await sdk.buildCircuitMerkleWitness(merkleProof, 32);
  assert.deepEqual(paddedWitness.siblings, cryptoFixture.merkleProof.siblings);

  const context = await sdk.calculateWithdrawalContext(
    {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    cryptoFixture.scope,
  );
  assert.equal(context, cryptoFixture.context);

  const input = await sdk.buildWithdrawalCircuitInput({
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
  });
  assert.equal(input.context, withdrawalFixture.expected.normalizedInputs.context[0]);
  assert.equal(
    input.withdrawnValue,
    withdrawalFixture.expected.normalizedInputs.withdrawnValue[0],
  );

  const websiteShapedRequest = {
    commitment,
    withdrawal: {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    scope: cryptoFixture.scope,
    withdrawalAmount: withdrawalFixture.withdrawalAmount,
    stateWitness: { ...withdrawalFixture.stateWitness, depth: 32 },
    aspWitness: { ...withdrawalFixture.aspWitness, depth: 32 },
    newNullifier: withdrawalFixture.newNullifier,
    newSecret: withdrawalFixture.newSecret,
  };
  const websiteShapedInput =
    await sdk.buildWithdrawalCircuitInput(websiteShapedRequest);
  assert.equal(websiteShapedInput.stateTreeDepth, 32);
  assert.equal(websiteShapedInput.aspTreeDepth, 32);
  assert.equal(websiteShapedInput.stateRoot, withdrawalFixture.stateWitness.root);
  assert.equal(websiteShapedInput.aspRoot, withdrawalFixture.aspWitness.root);

  const commitmentInput = await sdk.buildCommitmentCircuitInput({ commitment });
  assert.equal(commitmentInput.value, withdrawalFixture.existingValue);
  assert.equal(commitmentInput.label, withdrawalFixture.label);
  assert.equal(commitmentInput.nullifier, depositSecrets.nullifier);
  assert.equal(commitmentInput.secret, depositSecrets.secret);
});

test("browser wasm runtime verifies artifact bytes without base64 bridging", async () => {
  const sdk = new PrivacyPoolsSdkClient();

  const verified = await sdk.verifyArtifactBytes(sampleManifest, "withdraw", [
    { kind: "wasm", bytes: sampleArtifact },
  ]);
  assert.equal(verified.artifacts.length, 1);
  assert.equal(verified.artifacts[0].kind, "wasm");

  const provingBundle = await sdk.verifyArtifactBytes(
    sampleProvingManifest,
    "withdraw",
    [
      { kind: "wasm", bytes: sampleArtifact },
      { kind: "zkey", bytes: sampleArtifact },
      { kind: "vkey", bytes: sampleArtifact },
    ],
  );
  assert.equal(provingBundle.artifacts.length, 3);
});

test("browser runtime fetches and verifies manifest-bound artifact URLs", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const rootUrl = server.rootUrl;
    const statuses = await sdk.getArtifactStatuses(sampleManifest, rootUrl);
    assert.equal(statuses.length, 1);
    assert.equal(statuses[0].exists, true);
    assert.equal(statuses[0].verified, true);
    assert.match(statuses[0].path, /^http:\/\//);

    const bundle = await sdk.resolveVerifiedArtifactBundle(sampleManifest, rootUrl);
    assert.equal(bundle.artifacts.length, 1);
    assert.equal(bundle.artifacts[0].kind, "wasm");
    assert.match(bundle.artifacts[0].path, /^http:\/\//);
  } finally {
    await server.stop();
  }
});

test("browser runtime verifies proofs through Rust/WASM sessions", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const nodeSdk = new NodePrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const withdrawalRequest = await buildWithdrawalRequest(nodeSdk);
    const withdrawalSession = await nodeSdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      artifactsFixtureRoot,
    );
    const withdrawalProof = await nodeSdk.proveWithdrawalWithSession(
      "stable",
      withdrawalSession.handle,
      withdrawalRequest,
    );
    await nodeSdk.removeWithdrawalCircuitSession(withdrawalSession.handle);

    const commitment = await nodeSdk.getCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );
    const commitmentSession = await nodeSdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      artifactsFixtureRoot,
    );
    const commitmentProof = await nodeSdk.proveCommitmentWithSession(
      "stable",
      commitmentSession.handle,
      { commitment },
    );
    await nodeSdk.removeCommitmentCircuitSession(commitmentSession.handle);

    const verified = await sdk.verifyWithdrawalProof(
      "stable",
      withdrawalVerificationManifest,
      server.rootUrl,
      withdrawalProof.proof,
    );
    assert.equal(verified, true);
    assert.equal(
      await sdk.verifyCommitmentProof(
        "stable",
        commitmentVerificationManifest,
        server.rootUrl,
        commitmentProof.proof,
      ),
      true,
    );

    const session = await sdk.prepareWithdrawalCircuitSession(
      withdrawalVerificationManifest,
      server.rootUrl,
    );
    assert.equal(session.circuit, "withdraw");
    assert.equal(
      await sdk.verifyWithdrawalProofWithSession(
        "stable",
        session.handle,
        withdrawalProof.proof,
      ),
      true,
    );
    assert.equal(await sdk.removeWithdrawalCircuitSession(session.handle), true);

    const browserCommitmentSession = await sdk.prepareCommitmentCircuitSession(
      commitmentVerificationManifest,
      server.rootUrl,
    );
    assert.equal(browserCommitmentSession.circuit, "commitment");
    assert.equal(
      await sdk.verifyCommitmentProofWithSession(
        "stable",
        browserCommitmentSession.handle,
        commitmentProof.proof,
      ),
      true,
    );
    assert.equal(
      await sdk.removeCommitmentCircuitSession(browserCommitmentSession.handle),
      true,
    );
  } finally {
    await server.stop();
  }
});

test("browser runtime fails closed on artifact, proof, and session mismatches", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const tamperedArtifact = Uint8Array.from(sampleArtifact);
    tamperedArtifact[0] ^= 0xff;
    await assert.rejects(
      () =>
        sdk.verifyArtifactBytes(sampleManifest, "withdraw", [
          { kind: "wasm", bytes: tamperedArtifact },
        ]),
      /sha256 mismatch/,
    );

    const tamperedProof = JSON.parse(JSON.stringify(browserVerificationProof));
    tamperedProof.publicSignals[0] = "9";
    assert.equal(
      await sdk.verifyWithdrawalProof(
        "stable",
        browserVerificationManifest,
        server.rootUrl,
        tamperedProof,
      ),
      false,
    );

    const noncanonicalSignalProof = JSON.parse(
      JSON.stringify(browserVerificationProof),
    );
    noncanonicalSignalProof.publicSignals[0] = addModulus(
      noncanonicalSignalProof.publicSignals[0],
      BN254_SCALAR_FIELD_MODULUS,
    );
    await assert.rejects(
      () =>
        sdk.verifyWithdrawalProof(
          "stable",
          browserVerificationManifest,
          server.rootUrl,
          noncanonicalSignalProof,
        ),
      /not canonical/,
    );

    const noncanonicalCoordinateProof = JSON.parse(
      JSON.stringify(browserVerificationProof),
    );
    noncanonicalCoordinateProof.proof.piA[0] = addModulus(
      noncanonicalCoordinateProof.proof.piA[0],
      BN254_BASE_FIELD_MODULUS,
    );
    await assert.rejects(
      () =>
        sdk.verifyWithdrawalProof(
          "stable",
          browserVerificationManifest,
          server.rootUrl,
          noncanonicalCoordinateProof,
        ),
      /not canonical/,
    );

    await assert.rejects(
      () =>
        sdk.verifyWithdrawalProof(
          "fast",
          browserVerificationManifest,
          server.rootUrl,
          browserVerificationProof,
        ),
      (error) =>
        error instanceof BrowserRuntimeUnavailableError &&
        error.message.includes("stable backend"),
    );

    const session = await sdk.prepareWithdrawalCircuitSession(
      browserVerificationManifest,
      server.rootUrl,
    );
    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    await assert.rejects(
      () =>
        sdk.proveWithdrawalWithSession(
          "stable",
          session.handle,
          withdrawalRequest,
        ),
      /not proof-capable/,
    );
    assert.equal(await sdk.removeWithdrawalCircuitSession(session.handle), true);
    await assert.rejects(
      () =>
        sdk.verifyWithdrawalProofWithSession(
          "stable",
          session.handle,
          browserVerificationProof,
      ),
      /unknown browser withdrawal circuit session/,
    );
  } finally {
    await server.stop();
  }
});

test("browser worker client proves and verifies through real wasm-backed sessions", async () => {
  const worker = new Worker(new URL("../src/browser/worker.mjs", import.meta.url), {
    type: "module",
  });
  const sdk = createWorkerClient(worker);
  const server = createFixtureServer();
  await server.start();

  try {
    assert.deepEqual(await sdk.getRuntimeCapabilities(), getRuntimeCapabilities());

    const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
    assert.equal(keys.masterNullifier, cryptoFixture.keys.masterNullifier);

    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    assert.equal(withdrawalSession.provingAvailable, true);
    assert.equal(withdrawalSession.verificationAvailable, true);

    const withdrawalStatuses = [];
    const withdrawalProof = await sdk.proveWithdrawalWithSession(
      "stable",
      withdrawalSession.handle,
      withdrawalRequest,
      { onStatus: (status) => withdrawalStatuses.push(status) },
    );
    assert.equal(withdrawalProof.backend, "arkworks");
    assert.equal(
      await sdk.verifyWithdrawalProofWithSession(
        "stable",
        withdrawalSession.handle,
        withdrawalProof.proof,
      ),
      true,
    );
    assert.deepEqual(
      withdrawalStatuses.map((status) => status.stage),
      ["preload", "witness", "witness", "prove", "verify", "done"],
    );

    const commitment = await sdk.getCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );
    const commitmentSession = await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );
    assert.equal(commitmentSession.provingAvailable, true);
    assert.equal(commitmentSession.verificationAvailable, true);

    const commitmentStatuses = [];
    const commitmentProof = await sdk.proveCommitmentWithSession(
      "stable",
      commitmentSession.handle,
      { commitment },
      (status) => commitmentStatuses.push(status),
    );
    assert.equal(commitmentProof.backend, "arkworks");
    assert.equal(
      await sdk.verifyCommitmentProofWithSession(
        "stable",
        commitmentSession.handle,
        commitmentProof.proof,
      ),
      true,
    );
    assert.deepEqual(
      commitmentStatuses.map((status) => status.stage),
      ["preload", "witness", "witness", "prove", "verify", "done"],
    );
  } finally {
    await server.stop();
    await worker.terminate();
  }
});

function addModulus(value, modulus) {
  return (BigInt(value) + modulus).toString();
}

async function buildWithdrawalRequest(sdk) {
  const commitment = await sdk.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    cryptoFixture.depositSecrets.nullifier,
    cryptoFixture.depositSecrets.secret,
  );

  return {
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
}

function createFixtureServer() {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const filename = url.pathname.replace(/^\/+/, "");
    try {
      const bytes = readFileSync(join(fixturesRoot, filename));
      response.statusCode = 200;
      response.setHeader("content-type", "application/octet-stream");
      response.end(bytes);
    } catch {
      response.statusCode = 404;
      response.end("not found");
    }
  });

  return {
    rootUrl: "",
    async start() {
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      this.rootUrl = `http://127.0.0.1:${address.port}/artifacts/`;
    },
    async stop() {
      await new Promise((resolve, reject) => server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      }));
    },
  };
}
