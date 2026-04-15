import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  PrivacyPoolsSdkClient,
  getRuntimeCapabilities,
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
const sampleArtifact = readFileSync(
  join(fixturesRoot, "artifacts", "sample-artifact.bin"),
);
const browserVerificationProof = JSON.parse(
  readFileSync(
    join(fixturesRoot, "vectors", "browser-verification-proof.json"),
    "utf8",
  ),
);

test("node runtime reports capabilities", () => {
  assert.deepEqual(getRuntimeCapabilities(), {
    runtime: "node",
    provingAvailable: true,
    verificationAvailable: true,
    workerAvailable: false,
  });
});

test("node addon matches reference crypto vectors", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  assert.deepEqual(await sdk.getRuntimeCapabilities(), getRuntimeCapabilities());

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
});

test("node addon matches merkle/context/input fixtures", async () => {
  const sdk = new PrivacyPoolsSdkClient();

  const merkleProof = await sdk.generateMerkleProof(
    ["11", "22", "33", "44", "55"],
    "44",
  );
  assert.equal(merkleProof.root, cryptoFixture.merkleProof.root);
  assert.equal(merkleProof.leaf, cryptoFixture.merkleProof.leaf);
  assert.equal(merkleProof.index, cryptoFixture.merkleProof.index);
  assert.deepEqual(
    merkleProof.siblings,
    cryptoFixture.merkleProof.siblings.slice(0, merkleProof.siblings.length),
  );

  const paddedWitness = await sdk.buildCircuitMerkleWitness(merkleProof, 32);
  assert.deepEqual(paddedWitness.siblings, cryptoFixture.merkleProof.siblings);
  assert.equal(paddedWitness.depth, 32);

  const context = await sdk.calculateWithdrawalContext(
    {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    cryptoFixture.scope,
  );
  assert.equal(context, cryptoFixture.context);

  const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
  const depositSecrets = await sdk.deriveDepositSecrets(
    keys,
    cryptoFixture.scope,
    "0",
  );
  const commitment = await sdk.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
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

  const input = await sdk.buildWithdrawalCircuitInput(request);
  assert.equal(input.context, withdrawalFixture.expected.normalizedInputs.context[0]);
  assert.equal(
    input.withdrawnValue,
    withdrawalFixture.expected.normalizedInputs.withdrawnValue[0],
  );
});

test("node addon verifies manifest-bound artifact bytes", async () => {
  const sdk = new PrivacyPoolsSdkClient();

  const verified = await sdk.verifyArtifactBytes(sampleManifest, "withdraw", [
    { kind: "wasm", bytes: sampleArtifact },
  ]);
  assert.equal(verified.version, "0.1.0-alpha.1");
  assert.equal(verified.circuit, "withdraw");
  assert.equal(verified.artifacts[0].kind, "wasm");

  const bundle = await sdk.verifyArtifactBytes(sampleProvingManifest, "withdraw", [
    { kind: "wasm", bytes: sampleArtifact },
    { kind: "zkey", bytes: sampleArtifact },
    { kind: "vkey", bytes: sampleArtifact },
  ]);
  assert.equal(bundle.artifacts.length, 3);
});

test("node addon reports artifact statuses from the sample manifest", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const statuses = await sdk.getArtifactStatuses(
    sampleManifest,
    join(fixturesRoot, "artifacts"),
  );
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0].kind, "wasm");
  assert.equal(statuses[0].verified, true);
});

test("node addon fails closed for stale sessions and invalid proving artifacts", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const session = await sdk.prepareWithdrawalCircuitSessionFromBytes(
    sampleProvingManifest,
    [
      { kind: "wasm", bytes: sampleArtifact },
      { kind: "zkey", bytes: sampleArtifact },
      { kind: "vkey", bytes: sampleArtifact },
    ],
  );
  assert.equal(session.circuit, "withdraw");

  const request = await buildWithdrawalRequest(sdk);
  await assert.rejects(
    () => sdk.proveWithdrawalWithSession("stable", session.handle, request),
    /invalid zkey|unexpected end of zkey header|missing Groth16 header/,
  );

  assert.equal(await sdk.removeWithdrawalCircuitSession(session.handle), true);
  await assert.rejects(
    () =>
      sdk.verifyWithdrawalProofWithSession(
        "stable",
        session.handle,
        browserVerificationProof,
      ),
    /withdrawal circuit session handle not found/,
  );
});

async function buildWithdrawalRequest(sdk) {
  const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
  const depositSecrets = await sdk.deriveDepositSecrets(
    keys,
    cryptoFixture.scope,
    "0",
  );
  const commitment = await sdk.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
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
