import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import {
  BrowserRuntimeUnavailableError,
  Circuits,
  PrivacyPoolsSdkClient,
  createWorkerClient,
  getRuntimeCapabilities,
} from "../src/browser/index.mjs";
import * as browserDebug from "../src/browser/debug.mjs";
import {
  __buildWithdrawalWitnessBinaryForTests,
  __proveWithdrawalSessionWitnessBinaryForTests,
  __setWitnessResetProbeOverrideForTests,
} from "../src/browser/runtime.mjs";
import {
  preflightFixtureArtifacts,
} from "./browser-fixtures.mjs";
import {
  EXECUTION_FIXTURE,
  createExecutionRpcFixtureServer,
  signFinalizedTransactionRequest,
  signFinalizedTransactionRequestWithWrongSigner,
  strictExecutionPolicy,
} from "./execution-fixture.mjs";

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
const compatibilityShapes = JSON.parse(
  readFileSync(
    join(fixturesRoot, "compatibility-shapes", "sdk-json-shapes.json"),
    "utf8",
  ),
);
const artifactsFixtureRoot = join(fixturesRoot, "artifacts");
const BN254_BASE_FIELD_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN254_SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

preflightFixtureArtifacts(
  sampleManifest,
  sampleProvingManifest,
  commitmentProvingManifest,
  commitmentVerificationManifest,
  withdrawalProvingManifest,
  withdrawalVerificationManifest,
  browserVerificationManifest,
);

afterEach(async () => {
  __setWitnessResetProbeOverrideForTests("auto");
  await new PrivacyPoolsSdkClient().dispose();
});

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

  const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
  assertCompatibilityShape("browserDirect", "masterKeys", keys);
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
  assertCompatibilityShape("browserDirect", "commitment", commitment);
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
  assertCompatibilityShape(
    "browserDirect",
    "withdrawalWitnessRequest",
    withdrawalRequest,
  );

  const input = await sdk.buildWithdrawalCircuitInput(withdrawalRequest);
  assertCompatibilityShape("browserDirect", "withdrawalCircuitInput", input);
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

  const commitmentRequest = { commitment };
  assertCompatibilityShape(
    "browserDirect",
    "commitmentWitnessRequest",
    commitmentRequest,
  );
  const commitmentInput = await sdk.buildCommitmentCircuitInput(commitmentRequest);
  assertCompatibilityShape("browserDirect", "commitmentCircuitInput", commitmentInput);
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

test("browser wasm runtime verifies signed artifact manifests", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const fixture = signedManifestFixture("browser-direct");

  const verified = await sdk.verifySignedManifest(
    fixture.payloadJson,
    fixture.signatureHex,
    fixture.publicKeyHex,
  );
  assertCompatibilityShape("browserDirect", "verifiedSignedManifest", verified);
  assert.equal(verified.payload.manifest.version, "signed-browser-direct");
  assert.equal(verified.payload.metadata.build, "browser-direct");
  assert.equal(verified.artifactCount, 0);

  const verifiedArtifacts = await sdk.verifySignedManifestArtifacts(
    fixture.payloadJson,
    fixture.signatureHex,
    fixture.publicKeyHex,
    [{ filename: "signed.wasm", bytes: new Uint8Array(fixture.artifactBytes) }],
  );
  assertCompatibilityShape(
    "browserDirect",
    "verifiedSignedManifest",
    verifiedArtifacts,
  );
  assert.equal(verifiedArtifacts.artifactCount, 1);

  await assert.rejects(
    () =>
      sdk.verifySignedManifest(
        `${fixture.payloadJson} `,
        fixture.signatureHex,
        fixture.publicKeyHex,
      ),
    /signature/i,
  );
  await assert.rejects(
    () =>
      sdk.verifySignedManifestArtifacts(
        fixture.payloadJson,
        fixture.signatureHex,
        fixture.publicKeyHex,
        [{ filename: "signed.wasm", bytes: new Uint8Array([1, 2, 3]) }],
      ),
    /sha256|hash/i,
  );
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

test("Circuits rejects unsigned manifests unless the test-only override is enabled", async () => {
  const circuits = new Circuits({
    artifactsRoot: "http://127.0.0.1:1/artifacts/",
    withdrawalManifestJson: withdrawalProvingManifest,
  });

  await assert.rejects(
    () => circuits.downloadArtifacts(),
    /allowUnsignedArtifactsForTesting/i,
  );
});

test("Circuits rejects signed manifests with the wrong public key", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const wrongPublicKey = generateKeyPairSync("ed25519").publicKey;
  const withdrawalFixture = createSignedManifestFixture("withdraw", privateKey, publicKey);
  const commitmentFixture = createSignedManifestFixture("commitment", privateKey, publicKey);
  const server = createFixtureServer({
    overrides: new Map(
      [...withdrawalFixture.artifacts, ...commitmentFixture.artifacts].map((artifact) => [
        `artifacts/${artifact.filename}`,
        artifact.bytes,
      ]),
    ),
  });
  await server.start();

  try {
    const circuits = new Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalSignedManifestJson: withdrawalFixture.envelopeJson,
      commitmentSignedManifestJson: commitmentFixture.envelopeJson,
      signedManifestPublicKey: ed25519RawPublicKeyHex(wrongPublicKey),
    });
    await assert.rejects(() => circuits.downloadArtifacts(), /signature/i);
  } finally {
    await server.stop();
  }
});

test("Circuits rejects tampered signed-manifest artifact bytes", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const withdrawalFixture = createSignedManifestFixture("withdraw", privateKey, publicKey);
  const commitmentFixture = createSignedManifestFixture("commitment", privateKey, publicKey);
  const server = createFixtureServer({
    overrides: new Map([
      [
        `artifacts/${withdrawalFixture.artifacts[0].filename}`,
        Buffer.from("tampered withdraw browser test artifact"),
      ],
      [
        `artifacts/${commitmentFixture.artifacts[0].filename}`,
        commitmentFixture.artifacts[0].bytes,
      ],
    ]),
  });
  await server.start();

  try {
    const circuits = new Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalSignedManifestJson: withdrawalFixture.envelopeJson,
      commitmentSignedManifestJson: commitmentFixture.envelopeJson,
      signedManifestPublicKey: withdrawalFixture.publicKeyHex,
    });
    await assert.rejects(() => circuits.downloadArtifacts(), /sha256|hash/i);
  } finally {
    await server.stop();
  }
});

test("browser runtime verifies fixture and browser proofs through sessions", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    assert.equal(
      await sdk.verifyWithdrawalProof(
        "stable",
        browserVerificationManifest,
        server.rootUrl,
        browserVerificationProof,
      ),
      true,
    );

    const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
      browserVerificationManifest,
      server.rootUrl,
    );
    assert.equal(withdrawalSession.circuit, "withdraw");
    assert.equal(
      await sdk.verifyWithdrawalProofWithSession(
        "stable",
        withdrawalSession.handle,
        browserVerificationProof,
      ),
      true,
    );
    assert.equal(await sdk.removeWithdrawalCircuitSession(withdrawalSession.handle), true);

    const commitment = await sdk.getCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );
    const commitmentRequest = { commitment };
    const commitmentSession = await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );
    const commitmentProof = await sdk.proveCommitmentWithSession(
      "stable",
      commitmentSession.handle,
      commitmentRequest,
    );

    const verified = await sdk.verifyCommitmentProof(
      "stable",
      commitmentVerificationManifest,
      server.rootUrl,
      commitmentProof.proof,
    );
    assert.equal(verified, true);

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

test("browser JSON and binary witness proving agree on public signals", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    const commitment = withdrawalRequest.commitment;
    let jsonCommitmentProof;
    let binaryCommitmentProof;

    const commitmentSession = await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );
    try {
      jsonCommitmentProof = await sdk.proveCommitmentWithSession(
        "stable",
        commitmentSession.handle,
        { commitment },
      );
      binaryCommitmentProof = await sdk.proveCommitmentWithSessionBinary(
        "stable",
        commitmentSession.handle,
        { commitment },
      );
      assert.deepEqual(
        binaryCommitmentProof.proof.publicSignals,
        jsonCommitmentProof.proof.publicSignals,
      );
      assert.equal(
        await sdk.verifyCommitmentProofWithSession(
          "stable",
          commitmentSession.handle,
          jsonCommitmentProof.proof,
        ),
        true,
      );
      assert.equal(
        await sdk.verifyCommitmentProofWithSession(
          "stable",
          commitmentSession.handle,
          binaryCommitmentProof.proof,
        ),
        true,
      );
    } finally {
      await sdk.removeCommitmentCircuitSession(commitmentSession.handle);
    }

    const withdrawalSession = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    try {
      const jsonWithdrawalProof = await sdk.proveWithdrawalWithSession(
        "stable",
        withdrawalSession.handle,
        withdrawalRequest,
      );
      const binaryWithdrawalProof = await sdk.proveWithdrawalWithSessionBinary(
        "stable",
        withdrawalSession.handle,
        withdrawalRequest,
      );
      assert.deepEqual(
        binaryWithdrawalProof.proof.publicSignals,
        jsonWithdrawalProof.proof.publicSignals,
      );
      assert.equal(
        await sdk.verifyWithdrawalProofWithSession(
          "stable",
          withdrawalSession.handle,
          jsonWithdrawalProof.proof,
        ),
        true,
      );
      assert.equal(
        await sdk.verifyWithdrawalProofWithSession(
          "stable",
          withdrawalSession.handle,
          binaryWithdrawalProof.proof,
        ),
        true,
      );
      const jsonFormattedProof = await sdk.formatGroth16ProofBundle(
        jsonWithdrawalProof.proof,
      );
      const binaryFormattedProof = await sdk.formatGroth16ProofBundle(
        binaryWithdrawalProof.proof,
      );
      assert.deepEqual(
        {
          pubSignals: binaryFormattedProof.pubSignals,
        },
        {
          pubSignals: jsonFormattedProof.pubSignals,
        },
      );

      const withdrawal = withdrawalRequest.withdrawal;
      const jsonPlan = await sdk.planWithdrawalTransaction(
        1,
        "0x2222222222222222222222222222222222222222",
        withdrawal,
        jsonWithdrawalProof.proof,
      );
      const binaryPlan = await sdk.planWithdrawalTransaction(
        1,
        "0x2222222222222222222222222222222222222222",
        withdrawal,
        binaryWithdrawalProof.proof,
      );
      assert.deepEqual(
        {
          kind: binaryPlan.kind,
          chainId: binaryPlan.chainId,
          target: binaryPlan.target,
          value: binaryPlan.value,
          pubSignals: binaryPlan.proof.pubSignals,
        },
        {
          kind: jsonPlan.kind,
          chainId: jsonPlan.chainId,
          target: jsonPlan.target,
          value: jsonPlan.value,
          pubSignals: jsonPlan.proof.pubSignals,
        },
      );

      const jsonRelayPlan = await sdk.planRelayTransaction(
        1,
        EXECUTION_FIXTURE.entrypointAddress,
        {
          ...withdrawal,
          processooor: EXECUTION_FIXTURE.entrypointAddress,
          data: validRelayDataHex(),
        },
        jsonWithdrawalProof.proof,
        withdrawalRequest.scope,
      );
      const binaryRelayPlan = await sdk.planRelayTransaction(
        1,
        EXECUTION_FIXTURE.entrypointAddress,
        {
          ...withdrawal,
          processooor: EXECUTION_FIXTURE.entrypointAddress,
          data: validRelayDataHex(),
        },
        binaryWithdrawalProof.proof,
        withdrawalRequest.scope,
      );
      assert.deepEqual(
        {
          kind: binaryRelayPlan.kind,
          chainId: binaryRelayPlan.chainId,
          target: binaryRelayPlan.target,
          value: binaryRelayPlan.value,
          pubSignals: binaryRelayPlan.proof.pubSignals,
        },
        {
          kind: jsonRelayPlan.kind,
          chainId: jsonRelayPlan.chainId,
          target: jsonRelayPlan.target,
          value: jsonRelayPlan.value,
          pubSignals: jsonRelayPlan.proof.pubSignals,
        },
      );

      const jsonRagequitPlan = await sdk.planRagequitTransaction(
        1,
        "0x2222222222222222222222222222222222222222",
        jsonCommitmentProof.proof,
      );
      const binaryRagequitPlan = await sdk.planRagequitTransaction(
        1,
        "0x2222222222222222222222222222222222222222",
        binaryCommitmentProof.proof,
      );
      assert.deepEqual(
        {
          kind: binaryRagequitPlan.kind,
          chainId: binaryRagequitPlan.chainId,
          target: binaryRagequitPlan.target,
          value: binaryRagequitPlan.value,
          pubSignals: binaryRagequitPlan.proof.pubSignals,
        },
        {
          kind: jsonRagequitPlan.kind,
          chainId: jsonRagequitPlan.chainId,
          target: jsonRagequitPlan.target,
          value: jsonRagequitPlan.value,
          pubSignals: jsonRagequitPlan.proof.pubSignals,
        },
      );
    } finally {
      await sdk.removeWithdrawalCircuitSession(withdrawalSession.handle);
    }
  } finally {
    await server.stop();
  }
});

test("browser binary witness proving rejects malformed buffers", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const request = await buildWithdrawalRequest(sdk);
    const session = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    try {
      const validWitness = await __buildWithdrawalWitnessBinaryForTests(
        session.handle,
        request,
      );
      await assert.rejects(
        () =>
          __proveWithdrawalSessionWitnessBinaryForTests(
            session.handle,
            new Uint32Array(),
          ),
        /witness|empty|length/i,
      );
      await assert.rejects(
        () =>
          __proveWithdrawalSessionWitnessBinaryForTests(
            session.handle,
            validWitness.slice(0, validWitness.length - 1),
          ),
        /limb|length|witness/i,
      );
      await assert.rejects(
        () =>
          __proveWithdrawalSessionWitnessBinaryForTests(
            session.handle,
            validWitness.slice(0, validWitness.length - 8),
          ),
        /witness|count|length/i,
      );

      const nonCanonical = Uint32Array.from(validWitness);
      nonCanonical.set(u32Limbs(BN254_SCALAR_FIELD_MODULUS), 0);
      await assert.rejects(
        () =>
          __proveWithdrawalSessionWitnessBinaryForTests(
            session.handle,
            nonCanonical,
          ),
        /canonical|field|modulus/i,
      );
    } finally {
      await sdk.removeWithdrawalCircuitSession(session.handle);
    }
  } finally {
    await server.stop();
  }
});

test("browser witness reset probe falls back safely", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const request = await buildWithdrawalRequest(sdk);
    const session = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    const statuses = [];
    try {
      __setWitnessResetProbeOverrideForTests("fallback");
      const proof = await sdk.proveWithdrawalWithSessionBinary(
        "stable",
        session.handle,
        request,
        (status) => statuses.push(status),
      );
      assert.equal(
        statuses.filter((status) => status.stage === "witness").at(-1)
          .witnessRuntime,
        "fallback",
      );
      assert.equal(
        await sdk.verifyWithdrawalProofWithSession(
          "stable",
          session.handle,
          proof.proof,
        ),
        true,
      );
    } finally {
      __setWitnessResetProbeOverrideForTests("auto");
      await sdk.removeWithdrawalCircuitSession(session.handle);
    }
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

    const v1ShapedProof = toV1SnarkJsShape(browserVerificationProof);
    assert.equal(
      await sdk.verifyWithdrawalProof(
        "stable",
        browserVerificationManifest,
        server.rootUrl,
        v1ShapedProof,
      ),
      true,
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

test("direct browser proving verifies artifacts before witness execution", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer({
    mutate(filename, bytes) {
      if (
        filename === "circuits/withdraw/withdraw.wasm" ||
        filename === "circuits/commitment/commitment.wasm"
      ) {
        const tampered = Uint8Array.from(bytes);
        tampered[0] ^= 0xff;
        return tampered;
      }
      return bytes;
    },
  });
  await server.start();

  try {
    const withdrawalStatuses = [];
    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    await assert.rejects(
      () =>
        sdk.proveWithdrawal(
          "stable",
          withdrawalProvingManifest,
          server.rootUrl,
          withdrawalRequest,
          (status) => withdrawalStatuses.push(status),
        ),
      /sha256 mismatch/,
    );
    assert.deepEqual(
      withdrawalStatuses.map((status) => status.stage),
      ["preload"],
    );

    const commitmentStatuses = [];
    const commitment = await sdk.getCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );
    await assert.rejects(
      () =>
        sdk.proveCommitment(
          "stable",
          commitmentProvingManifest,
          server.rootUrl,
          { commitment },
          (status) => commitmentStatuses.push(status),
        ),
      /sha256 mismatch/,
    );
    assert.deepEqual(
      commitmentStatuses.map((status) => status.stage),
      ["preload"],
    );
  } finally {
    await server.stop();
  }
});

test("browser session artifact cache is explicit and bounded", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const server = createFixtureServer();
  await server.start();

  try {
    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    const commitment = await sdk.getCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );

    const removedSession = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    assert.equal(
      await sdk.removeWithdrawalCircuitSession(removedSession.handle),
      true,
    );
    await assert.rejects(
      () =>
        sdk.proveWithdrawalWithSession(
          "stable",
          removedSession.handle,
          withdrawalRequest,
        ),
      /not proof-capable|unknown browser withdrawal circuit session/,
    );

    const clearedSession = await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );
    await sdk.clearCircuitSessionCache();
    await assert.rejects(
      () =>
        sdk.proveCommitmentWithSession(
          "stable",
          clearedSession.handle,
          { commitment },
        ),
      /not proof-capable|unknown browser commitment circuit session/,
    );

    const firstWithdrawal = await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    const recentlyUsedCommitment = await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );
    await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );
    await sdk.prepareCommitmentCircuitSession(
      commitmentProvingManifest,
      server.rootUrl,
    );

    const commitmentProof = await sdk.proveCommitmentWithSession(
      "stable",
      recentlyUsedCommitment.handle,
      { commitment },
    );
    await sdk.prepareWithdrawalCircuitSession(
      withdrawalProvingManifest,
      server.rootUrl,
    );

    await assert.rejects(
      () =>
        sdk.proveWithdrawalWithSession(
          "stable",
          firstWithdrawal.handle,
          withdrawalRequest,
        ),
      /not proof-capable|unknown browser withdrawal circuit session/,
    );
    await assert.rejects(
      () =>
        sdk.verifyWithdrawalProofWithSession(
          "stable",
          firstWithdrawal.handle,
          browserVerificationProof,
        ),
      /unknown browser withdrawal circuit session/,
    );
    assert.equal(
      await sdk.verifyCommitmentProofWithSession(
        "stable",
        recentlyUsedCommitment.handle,
        commitmentProof.proof,
      ),
      true,
    );

    await sdk.clearCircuitSessionCache();
    await assert.rejects(
      () =>
        sdk.verifyCommitmentProofWithSession(
          "stable",
          recentlyUsedCommitment.handle,
          commitmentProof.proof,
        ),
      /unknown browser commitment circuit session/,
    );
  } finally {
    await sdk.clearCircuitSessionCache();
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
    assertCompatibilityShape("browserWorker", "masterKeys", keys);
    assert.equal(keys.masterNullifier, cryptoFixture.keys.masterNullifier);

    const withdrawalRequest = await buildWithdrawalRequest(sdk);
    assertCompatibilityShape(
      "browserWorker",
      "withdrawalWitnessRequest",
      withdrawalRequest,
    );
    const withdrawalInput =
      await sdk.buildWithdrawalCircuitInput(withdrawalRequest);
    assertCompatibilityShape(
      "browserWorker",
      "withdrawalCircuitInput",
      withdrawalInput,
    );
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
    assertCompatibilityShape("browserWorker", "proofBundle", withdrawalProof.proof);
    const withdrawalPlan = await sdk.planWithdrawalTransaction(
      1,
      "0x2222222222222222222222222222222222222222",
      withdrawalRequest.withdrawal,
      withdrawalProof.proof,
    );
    assertCompatibilityShape("browserWorker", "transactionPlan", withdrawalPlan);
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
    assertCompatibilityShape("browserWorker", "commitment", commitment);
    const commitmentRequest = { commitment };
    assertCompatibilityShape(
      "browserWorker",
      "commitmentWitnessRequest",
      commitmentRequest,
    );
    const commitmentInput =
      await sdk.buildCommitmentCircuitInput(commitmentRequest);
    assertCompatibilityShape(
      "browserWorker",
      "commitmentCircuitInput",
      commitmentInput,
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
      commitmentRequest,
      (status) => commitmentStatuses.push(status),
    );
    assertCompatibilityShape("browserWorker", "proofBundle", commitmentProof.proof);
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
    const signedFixture = signedManifestFixture("browser-worker");
    assert.equal(
      (
        await sdk.verifySignedManifest(
          signedFixture.payloadJson,
          signedFixture.signatureHex,
          signedFixture.publicKeyHex,
        )
      ).payload.metadata.build,
      "browser-worker",
    );
    await sdk.clearCircuitSessionCache();
    await assert.rejects(
      () =>
        sdk.verifyCommitmentProofWithSession(
          "stable",
          commitmentSession.handle,
          commitmentProof.proof,
        ),
      /unknown browser commitment circuit session/,
    );
  } finally {
    await server.stop();
    await worker.terminate();
  }
});

test("browser worker client fails closed on manifest tamper and handle mismatches", async () => {
  const worker = new Worker(new URL("../src/browser/worker.mjs", import.meta.url), {
    type: "module",
  });
  const sdk = createWorkerClient(worker);
  const server = createFixtureServer();
  await server.start();

  try {
    const signedFixture = signedManifestFixture("browser-worker-fail-closed");
    await assert.rejects(
      () =>
        sdk.verifySignedManifest(
          signedFixture.payloadJson,
          signedFixture.signatureHex,
          signedFixture.wrongPublicKeyHex,
        ),
      /signature|public key|length/i,
    );
    await assert.rejects(
      () =>
        sdk.verifySignedManifestArtifacts(
          signedFixture.payloadJson,
          signedFixture.signatureHex,
          signedFixture.publicKeyHex,
          [{ filename: "signed.wasm", bytes: new Uint8Array([1, 2, 3]) }],
        ),
      /sha256|hash/i,
    );

    const { verifiedWithdrawalHandle } = await buildBrowserExecutionHandleFixtures(
      sdk,
      server.rootUrl,
    );
    await assert.rejects(
      () =>
        sdk.planVerifiedRagequitTransactionWithHandle(
          1,
          EXECUTION_FIXTURE.poolAddress,
          verifiedWithdrawalHandle,
        ),
      /not.*ragequit/i,
    );
    assert.equal(await sdk.removeVerifiedProofHandle(verifiedWithdrawalHandle), true);
    await assert.rejects(
      () =>
        sdk.planVerifiedWithdrawalTransactionWithHandle(
          1,
          EXECUTION_FIXTURE.poolAddress,
          verifiedWithdrawalHandle,
        ),
      /verified proof handle|not found|unknown/i,
    );
  } finally {
    await server.stop();
    await worker.terminate();
  }
});

test("browser safe worker surface rejects raw-manifest proving methods", async () => {
  const worker = new Worker(new URL("../src/browser/worker-safe.mjs", import.meta.url), {
    type: "module",
  });
  const sdk = createWorkerClient(worker);
  const workerDebug = browserDebug.createWorkerDebugClient(worker);

  try {
    const signedFixture = signedManifestFixture("browser-worker-safe");
    const verified = await sdk.verifySignedManifest(
      signedFixture.payloadJson,
      signedFixture.signatureHex,
      signedFixture.publicKeyHex,
    );
    assert.equal(verified.payload.metadata.build, "browser-worker-safe");

    await assert.rejects(
      () =>
        sdk.getArtifactStatuses(
          withdrawalProvingManifest,
          "http://127.0.0.1:1/artifacts/",
        ),
      /unsupported worker method: getArtifactStatuses/i,
    );
    await assert.rejects(
      () =>
        sdk.prepareWithdrawalCircuitSession(
          withdrawalProvingManifest,
          "http://127.0.0.1:1/artifacts/",
        ),
      /unsupported worker method: prepareWithdrawalCircuitSession/i,
    );
    await assert.rejects(
      () => workerDebug.dangerouslyExportMasterKeys("debug-handle"),
      /unsupported worker method: dangerouslyExportMasterKeys/i,
    );
    await assert.rejects(
      () => workerDebug.dangerouslyExportPreflightedTransaction("debug-handle"),
      /unsupported worker method: dangerouslyExportPreflightedTransaction/i,
    );
  } finally {
    await worker.terminate();
  }
});

test("browser worker client runs execution-handle lifecycle and dispose clears state", async () => {
  const worker = new Worker(new URL("../src/browser/worker.mjs", import.meta.url), {
    type: "module",
  });
  const sdk = createWorkerClient(worker);
  const workerDebug = browserDebug.createWorkerDebugClient(worker);
  const artifactServer = createFixtureServer();
  const rpcServer = createExecutionRpcFixtureServer({
    stateRoot: withdrawalFixture.stateWitness.root,
    aspRoot: withdrawalFixture.aspWitness.root,
  });
  await artifactServer.start();
  await rpcServer.start();

  try {
    const { verifiedWithdrawalHandle, verifiedRagequitHandle } =
      await buildBrowserExecutionHandleFixtures(
      sdk,
      artifactServer.rootUrl,
    );

    const preflightCases = [
      {
        kind: "withdrawal",
        shape: "preflightedTransaction",
        expectedKind: "withdraw",
        run: () =>
          sdk.preflightVerifiedWithdrawalTransactionWithHandle(
            EXECUTION_FIXTURE.chainId,
            EXECUTION_FIXTURE.poolAddress,
            rpcServer.url,
            strictExecutionPolicy(),
            verifiedWithdrawalHandle,
          ),
      },
      {
        kind: "relay",
        shape: "preflightedTransaction",
        expectedKind: "relay",
        run: () =>
          sdk.preflightVerifiedRelayTransactionWithHandle(
            EXECUTION_FIXTURE.chainId,
            EXECUTION_FIXTURE.entrypointAddress,
            EXECUTION_FIXTURE.poolAddress,
            rpcServer.url,
            strictExecutionPolicy(),
            verifiedWithdrawalHandle,
          ),
      },
      {
        kind: "ragequit",
        shape: "ragequitPreflightedTransaction",
        expectedKind: "ragequit",
        run: () =>
          sdk.preflightVerifiedRagequitTransactionWithHandle(
            EXECUTION_FIXTURE.chainId,
            EXECUTION_FIXTURE.poolAddress,
            rpcServer.url,
            strictExecutionPolicy(),
            verifiedRagequitHandle,
          ),
      },
    ];

    const preflightedHandles = {};
    const finalizedHandles = {};
    const submittedHandles = {};

    for (const testCase of preflightCases) {
      const preflightedHandle = await testCase.run();
      assert.match(preflightedHandle, UUID_V4_RE);
      preflightedHandles[testCase.kind] = preflightedHandle;

      const preflighted = await workerDebug.dangerouslyExportPreflightedTransaction(
        preflightedHandle,
      );
      assertCompatibilityShape("browserWorker", testCase.shape, preflighted);
      assert.equal(preflighted.transaction.kind, testCase.expectedKind);
      if (testCase.kind === "ragequit") {
        assert.equal(preflighted.preflight.rootChecks.length, 0);
      } else {
        assert.equal(preflighted.preflight.mode, "strict");
      }

      await assert.rejects(
        () => sdk.submitPreflightedTransactionHandle(rpcServer.url, preflightedHandle),
        /requires a signer|externally signed transaction/i,
      );

      const finalizedHandle = await sdk.finalizePreflightedTransactionHandle(
        rpcServer.url,
        preflightedHandle,
      );
      assert.match(finalizedHandle, UUID_V4_RE);
      finalizedHandles[testCase.kind] = finalizedHandle;

      const finalized = await workerDebug.dangerouslyExportFinalizedPreflightedTransaction(
        finalizedHandle,
      );
      assertCompatibilityShape(
        "browserWorker",
        testCase.kind === "ragequit"
          ? "ragequitFinalizedPreflightedTransaction"
          : "finalizedPreflightedTransaction",
        finalized,
      );
      assert.equal(finalized.preflighted.transaction.kind, testCase.expectedKind);

      const signedTransaction = await signFinalizedTransactionRequest(finalized.request);
      const submittedHandle = await sdk.submitFinalizedPreflightedTransactionHandle(
        rpcServer.url,
        finalizedHandle,
        signedTransaction,
      );
      assert.match(submittedHandle, UUID_V4_RE);
      submittedHandles[testCase.kind] = submittedHandle;

      const submitted = await workerDebug.dangerouslyExportSubmittedPreflightedTransaction(
        submittedHandle,
      );
      assertCompatibilityShape(
        "browserWorker",
        testCase.kind === "ragequit"
          ? "ragequitSubmittedPreflightedTransaction"
          : "submittedPreflightedTransaction",
        submitted,
      );
      assertCompatibilityShape(
        "browserWorker",
        "transactionReceiptSummary",
        submitted.receipt,
      );
      assert.equal(submitted.preflighted.transaction.kind, testCase.expectedKind);
      assert.equal(rpcServer.rawTransactions.at(-1), signedTransaction);
      rpcServer.rawTransactions.length = 0;
    }

    assertCompatibilityShape("browserWorker", "executionHandles", {
      preflighted: preflightedHandles.withdrawal,
      finalized: finalizedHandles.withdrawal,
      submitted: submittedHandles.withdrawal,
    });

    await sdk.dispose();
    await assert.rejects(
      () => workerDebug.dangerouslyExportPreflightedTransaction(preflightedHandles.withdrawal),
      /execution handle|not found|unknown/i,
    );
    await assert.rejects(
      () => workerDebug.dangerouslyExportFinalizedPreflightedTransaction(finalizedHandles.withdrawal),
      /execution handle|not found|unknown/i,
    );
    await assert.rejects(
      () => workerDebug.dangerouslyExportSubmittedPreflightedTransaction(submittedHandles.withdrawal),
      /execution handle|not found|unknown/i,
    );
  } finally {
    await artifactServer.stop();
    await rpcServer.stop();
    await worker.terminate();
  }
});

test("browser worker transport transfers typed-array artifact payloads", async () => {
  const listeners = [];
  let capturedTransferList = [];
  const worker = {
    on(event, listener) {
      if (event === "message") {
        listeners.push(listener);
      }
    },
    postMessage(message, transferList = []) {
      capturedTransferList = transferList;
      queueMicrotask(() => {
        listeners.forEach((listener) =>
          listener({
            id: message.id,
            ok: true,
            result: {
              handle: "session-1",
              circuit: "withdraw",
              provingAvailable: true,
              verificationAvailable: true,
              artifactKinds: ["wasm"],
            },
          }),
        );
      });
    },
  };
  const sdk = createWorkerClient(worker);
  const bytes = new Uint8Array([1, 2, 3, 4]);

  await sdk.prepareWithdrawalCircuitSessionFromBytes(sampleManifest, [
    { kind: "wasm", bytes },
  ]);

  assert.equal(capturedTransferList.length, 1);
  assert.equal(capturedTransferList[0], bytes.buffer);

  capturedTransferList = [];
  await sdk.proveWithdrawalWithSessionBinary("stable", "session-1", {
    commitment: {
      hash: "1",
      nullifierHash: "2",
      precommitmentHash: "3",
      value: "4",
      label: "5",
      nullifier: "6",
      secret: "7",
    },
    withdrawal: { processooor: "0x1111111111111111111111111111111111111111", data: "0x" },
    scope: "8",
    withdrawalAmount: "1",
    stateWitness: { root: "1", leaf: "2", index: 0, siblings: [], depth: 0 },
    aspWitness: { root: "1", leaf: "2", index: 0, siblings: [], depth: 0 },
    newNullifier: "9",
    newSecret: "10",
  });
  assert.equal(capturedTransferList.length, 0);
});

function addModulus(value, modulus) {
  return (BigInt(value) + modulus).toString();
}

function u32Limbs(value) {
  let cursor = BigInt(value);
  const limbs = [];
  for (let index = 0; index < 8; index += 1) {
    limbs.push(Number(cursor & 0xffffffffn));
    cursor >>= 32n;
  }
  return limbs;
}

function validRelayDataHex() {
  return `0x${[
    "0000000000000000000000002222222222222222222222222222222222222222",
    "0000000000000000000000003333333333333333333333333333333333333333",
    "0000000000000000000000000000000000000000000000000000000000000019",
  ].join("")}`;
}

function toV1SnarkJsShape(proof) {
  return {
    proof: {
      pi_a: [...proof.proof.piA, "1"],
      pi_b: [...proof.proof.piB, ["1", "0"]],
      pi_c: [...proof.proof.piC, "1"],
      protocol: proof.proof.protocol,
      curve: proof.proof.curve,
    },
    publicSignals: proof.publicSignals,
  };
}

function assertCompatibilityShape(runtime, name, value) {
  const runtimeShapes = resolveShapeRef(compatibilityShapes, compatibilityShapes[runtime]);
  assert.deepEqual(
    shapeOf(value),
    resolveShapeRef(compatibilityShapes, runtimeShapes[name]),
    `${runtime}.${name}`,
  );
}

function signedManifestFixture(build) {
  const artifactBytes = Buffer.from(`signed manifest ${build} fixture`);
  const payload = {
    manifest: {
      version: `signed-${build}`,
      artifacts: [
        {
          circuit: "withdraw",
          kind: "wasm",
          filename: "signed.wasm",
          sha256: createHash("sha256").update(artifactBytes).digest("hex"),
        },
      ],
    },
    metadata: {
      ceremony: "test ceremony",
      build,
      repository: "0xbow/privacy-pools-sdk-rs",
      commit: "abc123",
    },
  };
  const payloadJson = JSON.stringify(payload);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    payloadJson,
    signatureHex: sign(null, Buffer.from(payloadJson), privateKey).toString("hex"),
    publicKeyHex: ed25519RawPublicKeyHex(publicKey),
    artifactBytes,
  };
}

function ed25519RawPublicKeyHex(publicKey) {
  return Buffer.from(
    publicKey.export({ format: "der", type: "spki" }),
  )
    .subarray(-32)
    .toString("hex");
}

function resolveShapeRef(root, value) {
  if (typeof value === "string" && value.startsWith("$ref:")) {
    return resolveShapeRef(root, lookupShapeRef(root, value.slice("$ref:".length)));
  }
  if (Array.isArray(value)) {
    return value.map((entry) => resolveShapeRef(root, entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, resolveShapeRef(root, entry)]),
    );
  }
  return value;
}

function lookupShapeRef(root, path) {
  return path.split(".").reduce((cursor, segment) => cursor?.[segment], root);
}

function shapeOf(value) {
  if (Array.isArray(value)) {
    return value.length === 0 ? [] : [shapeOf(value[0])];
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, shapeOf(value[key])]),
    );
  }
  if (value === null) {
    return "null";
  }
  return typeof value;
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

async function buildBrowserExecutionHandleFixtures(sdk, artifactsRoot) {
  const masterKeysHandle = await sdk.deriveMasterKeysHandle(cryptoFixture.mnemonic);
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
    withdrawalFixture.label,
    depositSecretsHandle,
  );
  const withdrawal = {
    processooor: EXECUTION_FIXTURE.entrypointAddress,
    data: validRelayDataHex(),
  };
  const commitmentProof = await sdk.proveCommitmentWithHandle(
    "stable",
    commitmentProvingManifest,
    artifactsRoot,
    commitmentHandle,
  );
  const verifiedRagequitHandle = await sdk.verifyRagequitProofForRequestHandle(
    "stable",
    commitmentVerificationManifest,
    artifactsRoot,
    commitmentHandle,
    commitmentProof.proof,
  );
  const withdrawalProof = await sdk.proveWithdrawalWithHandles(
    "stable",
    withdrawalProvingManifest,
    artifactsRoot,
    commitmentHandle,
    withdrawal,
    cryptoFixture.scope,
    withdrawalFixture.withdrawalAmount,
    withdrawalFixture.stateWitness,
    withdrawalFixture.aspWitness,
    withdrawalSecretsHandle,
  );
  const verifiedWithdrawalHandle = await sdk.verifyWithdrawalProofForRequestHandle(
    "stable",
    withdrawalVerificationManifest,
    artifactsRoot,
    commitmentHandle,
    withdrawal,
    cryptoFixture.scope,
    withdrawalFixture.withdrawalAmount,
    withdrawalFixture.stateWitness,
    withdrawalFixture.aspWitness,
    withdrawalSecretsHandle,
    withdrawalProof.proof,
  );
  return {
    verifiedWithdrawalHandle,
    verifiedRagequitHandle,
  };
}

function createSignedManifestFixture(circuit, privateKey, publicKey) {
  const artifacts = [
    {
      circuit,
      kind: "wasm",
      filename: `signed-${circuit}.wasm`,
      bytes: Buffer.from(`signed ${circuit} browser test artifact`),
    },
  ];
  const payload = {
    manifest: {
      version: "signed-browser-test",
      artifacts: artifacts.map((artifact) => ({
        circuit: artifact.circuit,
        kind: artifact.kind,
        filename: artifact.filename,
        sha256: createHash("sha256").update(artifact.bytes).digest("hex"),
      })),
    },
    metadata: {
      build: "browser-test",
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

function createFixtureServer(options = {}) {
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const filename = url.pathname.replace(/^\/+/, "");
    try {
      let bytes = options.overrides?.get(filename) ?? readFileSync(join(fixturesRoot, filename));
      if (options.mutate) {
        bytes = Buffer.from(options.mutate(filename, bytes) ?? bytes);
      }
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
