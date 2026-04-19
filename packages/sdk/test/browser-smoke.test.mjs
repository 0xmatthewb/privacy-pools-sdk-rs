import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  CircuitName,
  Circuits,
  PrivacyPoolsSdkClient,
  getRuntimeCapabilities,
} from "../src/browser/index.mjs";
import {
  assertFixtureServerArtifacts,
  createFixtureServer,
  fixturesRoot,
  preflightFixtureArtifacts,
  readManifestArtifactBytes,
} from "./browser-fixtures.mjs";

const cryptoFixture = JSON.parse(
  readFileSync(join(fixturesRoot, "vectors", "crypto-compatibility.json"), "utf8"),
);
const withdrawalFixture = JSON.parse(
  readFileSync(join(fixturesRoot, "vectors", "withdrawal-circuit-input.json"), "utf8"),
);
const withdrawalProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "withdrawal-proving-manifest.json"),
  "utf8",
);
const commitmentProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "commitment-proving-manifest.json"),
  "utf8",
);
test("browser pr smoke proves and verifies through signed-manifest-backed artifacts", async () => {
  preflightFixtureArtifacts(withdrawalProvingManifest, commitmentProvingManifest);
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    assert.deepEqual(await sdk.getRuntimeCapabilities(), getRuntimeCapabilities());

    await assertFixtureServerArtifacts(server.rootUrl, withdrawalProvingManifest);

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const signedManifestPublicKeyHex = ed25519RawPublicKeyHex(publicKey);
    const withdrawalSignedManifestJson = createSignedManifestFixture(
      withdrawalProvingManifest,
      privateKey,
      publicKey,
    );
    const commitmentSignedManifestJson = createSignedManifestFixture(
      commitmentProvingManifest,
      privateKey,
      publicKey,
    );
    const withdrawalEnvelope = JSON.parse(withdrawalSignedManifestJson);
    const verifiedWithdrawalManifest = await smokeStep(
      "signed manifest verification",
      () =>
        sdk.verifySignedManifest(
          withdrawalEnvelope.payloadJson,
          withdrawalEnvelope.signatureHex,
          signedManifestPublicKeyHex,
        ),
    );
    assert.ok(
      verifiedWithdrawalManifest.payload.manifest.version.endsWith("-signed"),
    );
    const circuits = new Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalSignedManifestJson,
      commitmentSignedManifestJson,
      signedManifestPublicKey: signedManifestPublicKeyHex,
    });

    const bundle = await smokeStep("bundle resolution", () => circuits.downloadArtifacts());
    assert.equal(Object.keys(bundle.withdraw).length, 3);
    assert.equal(Object.keys(bundle.commitment).length, 3);

    const session = await smokeStep("session preparation", async () =>
      sdk.prepareWithdrawalCircuitSessionFromBytes(
        await circuits.manifestFor(CircuitName.Withdraw),
        await circuits.artifactInputsFor(CircuitName.Withdraw),
      ),
    );

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
    const withdrawal = {
      processooor: "0x1111111111111111111111111111111111111111",
      data: `0x${[
        "0000000000000000000000002222222222222222222222222222222222222222",
        "0000000000000000000000003333333333333333333333333333333333333333",
        "0000000000000000000000000000000000000000000000000000000000000019",
      ].join("")}`,
    };
    try {
      const proof = await smokeStep("prove", () =>
        sdk.proveWithdrawalWithSessionBinary("stable", session.handle, {
          commitment,
          withdrawal,
          scope: cryptoFixture.scope,
          withdrawalAmount: withdrawalFixture.withdrawalAmount,
          stateWitness: withdrawalFixture.stateWitness,
          aspWitness: withdrawalFixture.aspWitness,
          newNullifier: withdrawalFixture.newNullifier,
          newSecret: withdrawalFixture.newSecret,
        }),
      );
      assert.equal(proof.backend, "arkworks");
      assert.equal(
        await smokeStep("verify", () =>
          sdk.verifyWithdrawalProofWithSession("stable", session.handle, proof.proof),
        ),
        true,
      );
    } finally {
      assert.equal(await sdk.removeWithdrawalCircuitSession(session.handle), true);
    }
  } finally {
    await sdk.dispose();
    await server.stop();
  }
});

function createSignedManifestFixture(manifestJson, privateKey, publicKey) {
  const manifest = JSON.parse(manifestJson);
  const artifactBytes = readManifestArtifactBytes(manifestJson);
  const payload = {
    manifest: {
      version: `${manifest.version}-signed`,
      artifacts: manifest.artifacts.map((artifact) => ({
        circuit: artifact.circuit,
        kind: artifact.kind,
        filename: artifact.filename,
        sha256: createHash("sha256")
          .update(
            artifactBytes.find((entry) => entry.kind === artifact.kind)?.bytes ?? Buffer.alloc(0),
          )
          .digest("hex"),
      })),
    },
    metadata: {
      build: "browser-pr-smoke",
      repository: "0xbow/privacy-pools-sdk-rs",
      commit: "browser-smoke",
    },
  };
  const payloadJson = JSON.stringify(payload);
  return JSON.stringify({
    payloadJson,
    signatureHex: sign(null, Buffer.from(payloadJson), privateKey).toString("hex"),
    publicKeyHex: ed25519RawPublicKeyHex(publicKey),
  });
}

function ed25519RawPublicKeyHex(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" }))
    .subarray(-32)
    .toString("hex");
}

async function smokeStep(label, fn) {
  try {
    return await fn();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`browser smoke ${label} failed: ${message}`);
  }
}
