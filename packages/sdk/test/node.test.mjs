import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPoseidon } from "circomlibjs";

import {
  PrivacyPoolsSdkClient,
  getRuntimeCapabilities,
} from "../src/node/index.mjs";
import {
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportMasterKeys,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportSecret,
  dangerouslyExportSubmittedPreflightedTransaction,
} from "../src/node/debug.mjs";
import {
  EXECUTION_FIXTURE,
  EXECUTION_SIGNER_MNEMONIC,
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
const commitmentProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "commitment-proving-manifest.json"),
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
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

test("node runtime reports capabilities", () => {
  assert.deepEqual(getRuntimeCapabilities(), {
    runtime: "node",
    provingAvailable: true,
    verificationAvailable: true,
    workerAvailable: false,
  });
});

test("node accepts decimal and hex zero state roots equivalently", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  assert.equal(await sdk.isCurrentStateRoot("0", "0x0"), true);
  assert.equal(await sdk.isCurrentStateRoot("0x0", "0"), true);
  assert.equal(await sdk.isCurrentStateRoot("0", "1"), false);
});

test("node derives master key handles from mnemonic bytes", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const handle = await sdk.deriveMasterKeysHandleBytes(
    new TextEncoder().encode(cryptoFixture.mnemonic),
  );
  assert.match(handle, UUID_V4_RE);
  assert.equal(await sdk.removeSecretHandle(handle), true);
});

test("node execution signing matches Rust and viem transaction encodings", async () => {
  const legacyRequest = {
    kind: "withdraw",
    chainId: EXECUTION_FIXTURE.chainId,
    from: EXECUTION_FIXTURE.caller,
    to: EXECUTION_FIXTURE.poolAddress,
    nonce: Number(EXECUTION_FIXTURE.nonce),
    gasLimit: Number(EXECUTION_FIXTURE.estimatedGas),
    value: "0",
    data: "0x1234",
    gasPrice: EXECUTION_FIXTURE.gasPrice.toString(),
    maxFeePerGas: null,
    maxPriorityFeePerGas: null,
  };
  const eip1559Request = {
    ...legacyRequest,
    kind: "relay",
    to: EXECUTION_FIXTURE.entrypointAddress,
    gasPrice: null,
    maxFeePerGas: (EXECUTION_FIXTURE.gasPrice + 2n).toString(),
    maxPriorityFeePerGas: "1",
  };

  for (const request of [legacyRequest, eip1559Request]) {
    const rustSigned = await signFinalizedTransactionRequestWithRustExample(request);
    const viemSigned = await signFinalizedTransactionRequest(request);
    assert.equal(
      rustSigned,
      viemSigned,
      `Rust signer output must match viem for ${request.kind}`,
    );
  }
});

test("node addon matches circomlibjs poseidon precommitments across 1k random pairs", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const poseidon = await buildPoseidon();
  let seed = 0x1234_5678_9abcn;

  const nextFieldElement = () => {
    seed =
      (seed * 6364136223846793005n + 1442695040888963407n) % BN254_SCALAR_FIELD;
    return seed === 0n ? 1n : seed;
  };

  for (let index = 0; index < 1000; index += 1) {
    const nullifier = nextFieldElement();
    const secret = nextFieldElement();
    const commitment = await sdk.getCommitment(
      "1",
      "1",
      nullifier.toString(),
      secret.toString(),
    );
    const expected = poseidon.F.toString(poseidon([nullifier, secret]));
    assert.equal(
      commitment.precommitmentHash,
      expected,
      `poseidon precommitment mismatch at sample ${index}`,
    );
  }
});

test("node addon matches reference crypto vectors", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  assert.deepEqual(await sdk.getRuntimeCapabilities(), getRuntimeCapabilities());

  const keys = await sdk.deriveMasterKeys(cryptoFixture.mnemonic);
  assertCompatibilityShape("node", "masterKeys", keys);
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
  assertCompatibilityShape("node", "commitment", commitment);
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
  assertCompatibilityShape("node", "withdrawalWitnessRequest", request);

  const input = await sdk.buildWithdrawalCircuitInput(request);
  assertCompatibilityShape("node", "withdrawalCircuitInput", input);
  assert.equal(input.context, withdrawalFixture.expected.normalizedInputs.context[0]);
  assert.equal(
    input.withdrawnValue,
    withdrawalFixture.expected.normalizedInputs.withdrawnValue[0],
  );

  const websiteShapedRequest = JSON.parse(JSON.stringify(request));
  websiteShapedRequest.stateWitness.depth = 32;
  websiteShapedRequest.aspWitness.depth = 32;
  const websiteShapedInput =
    await sdk.buildWithdrawalCircuitInput(websiteShapedRequest);
  assert.equal(websiteShapedInput.stateTreeDepth, 32);
  assert.equal(websiteShapedInput.aspTreeDepth, 32);
  assert.equal(websiteShapedInput.stateRoot, request.stateWitness.root);
  assert.equal(websiteShapedInput.aspRoot, request.aspWitness.root);
});

test("node addon proves and verifies commitment ragequit proofs", async () => {
  const sdk = new PrivacyPoolsSdkClient();
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
  const request = { commitment };
  assertCompatibilityShape("node", "commitmentWitnessRequest", request);

  const input = await sdk.buildCommitmentCircuitInput(request);
  assertCompatibilityShape("node", "commitmentCircuitInput", input);
  assert.equal(input.value, withdrawalFixture.existingValue);
  assert.equal(input.label, withdrawalFixture.label);
  assert.equal(input.nullifier, depositSecrets.nullifier);
  assert.equal(input.secret, depositSecrets.secret);

  const session = await sdk.prepareCommitmentCircuitSession(
    commitmentProvingManifest,
    join(fixturesRoot, "artifacts"),
  );
  assert.equal(session.circuit, "commitment");
  assert.equal(session.artifactVersion, "v1.2.0");

  const proving = await sdk.proveCommitmentWithSession(
    "stable",
    session.handle,
    request,
  );
  assertCompatibilityShape("node", "proofBundle", proving.proof);
  assert.equal(proving.backend, "arkworks");
  assert.equal(proving.proof.publicSignals.length, 4);
  assert.equal(proving.proof.publicSignals[0], commitment.hash);
  assert.equal(proving.proof.publicSignals[2], withdrawalFixture.existingValue);
  assert.equal(proving.proof.publicSignals[3], withdrawalFixture.label);
  assert.equal(
    await sdk.verifyCommitmentProofWithSession(
      "stable",
      session.handle,
      proving.proof,
    ),
    true,
  );
  assert.equal(await sdk.removeCommitmentCircuitSession(session.handle), true);
});

test("node addon enforces secret and verified proof handle kinds", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const artifactsRoot = join(fixturesRoot, "artifacts");
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

  for (const handle of [
    masterKeysHandle,
    depositSecretsHandle,
    withdrawalSecretsHandle,
    commitmentHandle,
  ]) {
    assert.match(handle, UUID_V4_RE);
  }

  assert.deepEqual(
    await dangerouslyExportMasterKeys(masterKeysHandle),
    cryptoFixture.keys,
  );
  assert.deepEqual(
    await dangerouslyExportSecret(depositSecretsHandle),
    cryptoFixture.depositSecrets,
  );
  assert.equal(
    (await dangerouslyExportCommitmentPreimage(commitmentHandle)).hash,
    cryptoFixture.commitment.hash,
  );

  await assert.rejects(
    () =>
      sdk.proveCommitmentWithHandle(
        "stable",
        commitmentProvingManifest,
        artifactsRoot,
        depositSecretsHandle,
      ),
    /commitment witness request/i,
  );

  const verifiedCommitmentHandle = await sdk.proveAndVerifyCommitmentHandle(
    "stable",
    commitmentProvingManifest,
    artifactsRoot,
    commitmentHandle,
  );
  assert.match(verifiedCommitmentHandle, UUID_V4_RE);

  const withdrawal = {
    processooor: EXECUTION_FIXTURE.entrypointAddress,
    data: validRelayDataHex(),
  };
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
    withdrawalProvingManifest,
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
  assert.match(verifiedWithdrawalHandle, UUID_V4_RE);

  await assert.rejects(
    () =>
      sdk.planVerifiedRagequitTransactionWithHandle(
        1,
        "0x2222222222222222222222222222222222222222",
        verifiedCommitmentHandle,
      ),
    /not.*ragequit/i,
  );

  assert.equal(await sdk.removeVerifiedProofHandle(verifiedCommitmentHandle), true);
  assert.equal(await sdk.removeVerifiedProofHandle(verifiedWithdrawalHandle), true);
  assert.equal(await sdk.removeSecretHandle(commitmentHandle), true);
  assert.equal(await sdk.clearSecretHandles(), true);
  assert.equal(await sdk.clearVerifiedProofHandles(), true);
});

test("node addon preflights, finalizes, and submits execution handles", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const rpcServer = await startExecutionRpcFixtureServer({
    stateRoot: withdrawalFixture.stateWitness.root,
    aspRoot: withdrawalFixture.aspWitness.root,
  });

  try {
    const artifactsRoot = join(fixturesRoot, "artifacts");
    const {
      verifiedWithdrawalHandle,
      verifiedRagequitHandle,
    } = await buildExecutionHandleFixtures(sdk, artifactsRoot);

    const withdrawalPreflightedHandle =
      await sdk.preflightVerifiedWithdrawalTransactionWithHandle(
        EXECUTION_FIXTURE.chainId,
        EXECUTION_FIXTURE.poolAddress,
        rpcServer.url,
        strictExecutionPolicy(),
        verifiedWithdrawalHandle,
      );
    const relayPreflightedHandle =
      await sdk.preflightVerifiedRelayTransactionWithHandle(
        EXECUTION_FIXTURE.chainId,
        EXECUTION_FIXTURE.entrypointAddress,
        EXECUTION_FIXTURE.poolAddress,
        rpcServer.url,
        strictExecutionPolicy(),
        verifiedWithdrawalHandle,
      );
    const ragequitPreflightedHandle =
      await sdk.preflightVerifiedRagequitTransactionWithHandle(
        EXECUTION_FIXTURE.chainId,
        EXECUTION_FIXTURE.poolAddress,
        rpcServer.url,
        strictExecutionPolicy(),
        verifiedRagequitHandle,
      );

    for (const handle of [
      withdrawalPreflightedHandle,
      relayPreflightedHandle,
      ragequitPreflightedHandle,
    ]) {
      assert.match(handle, UUID_V4_RE);
    }

    const withdrawalPreflighted = await dangerouslyExportPreflightedTransaction(
      withdrawalPreflightedHandle,
    );
    const relayPreflighted = await dangerouslyExportPreflightedTransaction(
      relayPreflightedHandle,
    );
    const ragequitPreflighted = await dangerouslyExportPreflightedTransaction(
      ragequitPreflightedHandle,
    );
    assertCompatibilityShape("node", "preflightedTransaction", withdrawalPreflighted);
    assertCompatibilityShape("node", "preflightedTransaction", relayPreflighted);
    assertCompatibilityShape(
      "node",
      "ragequitPreflightedTransaction",
      ragequitPreflighted,
    );
    assert.equal(withdrawalPreflighted.preflight.mode, "strict");
    assert.equal(withdrawalPreflighted.preflight.codeHashChecks.length, 2);
    assert.equal(withdrawalPreflighted.preflight.rootChecks.length, 2);
    assert.equal(relayPreflighted.transaction.kind, "relay");
    assert.equal(ragequitPreflighted.transaction.kind, "ragequit");
    assert.equal(ragequitPreflighted.preflight.rootChecks.length, 0);

    await assert.rejects(
      () =>
        sdk.submitPreflightedTransactionHandle(
          rpcServer.url,
          withdrawalPreflightedHandle,
        ),
      /requires an in-process signer|requires a signer/i,
    );

    const finalizedHandle = await sdk.finalizePreflightedTransactionHandle(
      rpcServer.url,
      withdrawalPreflightedHandle,
    );
    assert.match(finalizedHandle, UUID_V4_RE);
    const finalized = await dangerouslyExportFinalizedPreflightedTransaction(
      finalizedHandle,
    );
    assertCompatibilityShape("node", "finalizedPreflightedTransaction", finalized);

    const signedTransaction = await signFinalizedTransactionRequest(finalized.request);
    const submittedHandle = await sdk.submitFinalizedPreflightedTransactionHandle(
      rpcServer.url,
      finalizedHandle,
      signedTransaction,
    );
    assert.match(submittedHandle, UUID_V4_RE);
    assertCompatibilityShape("node", "executionHandles", {
      preflighted: withdrawalPreflightedHandle,
      finalized: finalizedHandle,
      submitted: submittedHandle,
    });

    const submitted = await dangerouslyExportSubmittedPreflightedTransaction(
      submittedHandle,
    );
    assertCompatibilityShape("node", "submittedPreflightedTransaction", submitted);
    assertCompatibilityShape("node", "transactionReceiptSummary", submitted.receipt);
    assert.equal(submitted.receipt.transactionHash, EXECUTION_FIXTURE.transactionHash);

    assert.equal(await sdk.removeExecutionHandle(relayPreflightedHandle), true);
    assert.equal(await sdk.removeExecutionHandle(ragequitPreflightedHandle), true);
    assert.equal(await sdk.removeExecutionHandle(submittedHandle), true);
    assert.equal(await sdk.clearExecutionHandles(), true);
    await assert.rejects(
      () => dangerouslyExportPreflightedTransaction(withdrawalPreflightedHandle),
      /execution handle|not found|unknown/i,
    );
    await assert.rejects(
      () => dangerouslyExportFinalizedPreflightedTransaction(finalizedHandle),
      /execution handle|not found|unknown/i,
    );
  } finally {
    await sdk.dispose();
    await rpcServer.stop();
  }
});

test("node addon falls back to legacy fee pricing when 1559 RPC methods are unavailable", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const rpcServer = await startExecutionRpcFixtureServer({
    stateRoot: withdrawalFixture.stateWitness.root,
    aspRoot: withdrawalFixture.aspWitness.root,
  });

  try {
    const artifactsRoot = join(fixturesRoot, "artifacts");
    const { verifiedWithdrawalHandle } = await buildExecutionHandleFixtures(
      sdk,
      artifactsRoot,
    );
    const preflightedHandle =
      await sdk.preflightVerifiedWithdrawalTransactionWithHandle(
        EXECUTION_FIXTURE.chainId,
        EXECUTION_FIXTURE.poolAddress,
        rpcServer.url,
        strictExecutionPolicy(),
        verifiedWithdrawalHandle,
      );
    const finalizedHandle = await sdk.finalizePreflightedTransactionHandle(
      rpcServer.url,
      preflightedHandle,
    );
    const finalized = await dangerouslyExportFinalizedPreflightedTransaction(
      finalizedHandle,
    );

    assert.equal(finalized.request.gasPrice, EXECUTION_FIXTURE.gasPrice.toString());
    assert.equal(finalized.request.maxFeePerGas, null);
    assert.equal(finalized.request.maxPriorityFeePerGas, null);
  } finally {
    await sdk.dispose();
    await rpcServer.stop();
  }
});

test("node addon rejects invalid execution preflight policies and signer mismatches", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const validRpcServer = await startExecutionRpcFixtureServer({
    stateRoot: withdrawalFixture.stateWitness.root,
    aspRoot: withdrawalFixture.aspWitness.root,
  });
  const wrongRootServer = await startExecutionRpcFixtureServer({
    stateRoot: "999",
    aspRoot: withdrawalFixture.aspWitness.root,
  });

  try {
    const artifactsRoot = join(fixturesRoot, "artifacts");
    const { verifiedWithdrawalHandle } = await buildExecutionHandleFixtures(
      sdk,
      artifactsRoot,
    );

    await assert.rejects(
      () =>
        sdk.preflightVerifiedWithdrawalTransactionWithHandle(
          EXECUTION_FIXTURE.chainId,
          EXECUTION_FIXTURE.poolAddress,
          wrongRootServer.url,
          strictExecutionPolicy(),
          verifiedWithdrawalHandle,
        ),
      /state root mismatch|asp root mismatch|root mismatch/i,
    );

    const preflightedHandle =
      await sdk.preflightVerifiedWithdrawalTransactionWithHandle(
        EXECUTION_FIXTURE.chainId,
        EXECUTION_FIXTURE.poolAddress,
        validRpcServer.url,
        strictExecutionPolicy(),
        verifiedWithdrawalHandle,
      );
    const finalizedHandle = await sdk.finalizePreflightedTransactionHandle(
      validRpcServer.url,
      preflightedHandle,
    );
    const finalized = await dangerouslyExportFinalizedPreflightedTransaction(
      finalizedHandle,
    );

    const wrongSignedTransaction =
      await signFinalizedTransactionRequestWithWrongSigner(finalized.request);
    await assert.rejects(
      () =>
        sdk.submitFinalizedPreflightedTransactionHandle(
          validRpcServer.url,
          finalizedHandle,
          wrongSignedTransaction,
        ),
      /signer mismatch/i,
    );
  } finally {
    await sdk.dispose();
    await validRpcServer.stop();
    await wrongRootServer.stop();
  }
});

test("node addon proves and verifies withdrawal proofs", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const request = await buildWithdrawalRequest(sdk);
  const session = await sdk.prepareWithdrawalCircuitSession(
    withdrawalProvingManifest,
    join(fixturesRoot, "artifacts"),
  );
  assert.equal(session.circuit, "withdraw");
  assert.equal(session.artifactVersion, "v1.2.0");

  const proving = await sdk.proveWithdrawalWithSession(
    "stable",
    session.handle,
    request,
  );
  assertCompatibilityShape("node", "proofBundle", proving.proof);
  const transactionPlan = await sdk.planWithdrawalTransaction(
    1,
    "0x1111111111111111111111111111111111111111",
    request.withdrawal,
    proving.proof,
  );
  assertCompatibilityShape("node", "transactionPlan", transactionPlan);
  assert.equal(proving.backend, "arkworks");
  assert.equal(proving.proof.publicSignals.length, 8);
  assert.equal(proving.proof.publicSignals[2], withdrawalFixture.withdrawalAmount);
  assert.equal(proving.proof.publicSignals[3], withdrawalFixture.stateWitness.root);
  assert.equal(
    await sdk.verifyWithdrawalProofWithSession(
      "stable",
      session.handle,
      proving.proof,
    ),
    true,
  );

  const tamperedProof = JSON.parse(JSON.stringify(proving.proof));
  tamperedProof.publicSignals[0] = "9";
  assert.equal(
    await sdk.verifyWithdrawalProofWithSession(
      "stable",
      session.handle,
      tamperedProof,
    ),
    false,
  );
  assert.equal(await sdk.removeWithdrawalCircuitSession(session.handle), true);
});

test("node addon rejects malformed proof bundle shapes", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const request = await buildWithdrawalRequest(sdk);

  const malformedShape = JSON.parse(JSON.stringify(browserVerificationProof));
  malformedShape.proof.piB = [["69"], ["12", "123"]];
  await assert.rejects(
    () => sdk.formatGroth16ProofBundle(malformedShape),
    /proof shape|pi_b|piB/i,
  );

  const malformedSignals = JSON.parse(JSON.stringify(browserVerificationProof));
  malformedSignals.publicSignals = malformedSignals.publicSignals.slice(0, 7);
  await assert.rejects(
    () =>
      sdk.planWithdrawalTransaction(
        1,
        "0x1111111111111111111111111111111111111111",
        request.withdrawal,
        malformedSignals,
      ),
    /8 public signals|public signals/i,
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

test("node addon verifies signed artifact manifests and artifacts", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const fixture = signedManifestFixture();

  const verified = await sdk.verifySignedManifest(
    fixture.payloadJson,
    fixture.signatureHex,
    fixture.publicKeyHex,
  );
  assertCompatibilityShape("node", "verifiedSignedManifest", verified);
  assert.equal(verified.payload.manifest.version, "signed-node-test");
  assert.equal(verified.payload.metadata.build, "node-test");
  assert.equal(verified.artifactCount, 0);

  const verifiedArtifacts = await sdk.verifySignedManifestArtifacts(
    fixture.payloadJson,
    fixture.signatureHex,
    fixture.publicKeyHex,
    [{ filename: "signed.wasm", bytes: fixture.artifactBytes }],
  );
  assertCompatibilityShape("node", "verifiedSignedManifest", verifiedArtifacts);
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
      sdk.verifySignedManifest(
        fixture.payloadJson,
        fixture.signatureHex,
        fixture.wrongPublicKeyHex,
      ),
    /signature/i,
  );
  await assert.rejects(
    () =>
      sdk.verifySignedManifestArtifacts(
        fixture.payloadJson,
        fixture.signatureHex,
        fixture.publicKeyHex,
        [],
      ),
    /artifact file does not exist|missing/i,
  );
  await assert.rejects(
    () =>
      sdk.verifySignedManifestArtifacts(
        fixture.payloadJson,
        fixture.signatureHex,
        fixture.publicKeyHex,
        [{ filename: "signed.wasm", bytes: Buffer.from("tampered") }],
      ),
    /sha256|hash/i,
  );
  await assert.rejects(
    () =>
      sdk.verifySignedManifestArtifacts(
        fixture.payloadJson,
        fixture.signatureHex,
        fixture.publicKeyHex,
        [
          { filename: "signed.wasm", bytes: fixture.artifactBytes },
          { filename: "unexpected.wasm", bytes: Buffer.from("unexpected") },
        ],
      ),
    /unexpected/i,
  );
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

test("node addon keeps withdrawal and commitment artifact APIs circuit scoped", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  const artifactsRoot = join(fixturesRoot, "artifacts");

  const withdrawalStatuses = await sdk.getArtifactStatuses(
    withdrawalProvingManifest,
    artifactsRoot,
  );
  assert.equal(withdrawalStatuses.length, 3);
  assert.deepEqual(
    [...new Set(withdrawalStatuses.map((status) => status.circuit))],
    ["withdraw"],
  );
  assert.equal(withdrawalStatuses.every((status) => status.verified), true);

  const commitmentStatuses = await sdk.getCommitmentArtifactStatuses(
    commitmentProvingManifest,
    artifactsRoot,
  );
  assert.equal(commitmentStatuses.length, 3);
  assert.deepEqual(
    [...new Set(commitmentStatuses.map((status) => status.circuit))],
    ["commitment"],
  );
  assert.equal(commitmentStatuses.every((status) => status.verified), true);

  const withdrawalBundle = await sdk.resolveVerifiedArtifactBundle(
    withdrawalProvingManifest,
    artifactsRoot,
  );
  assert.equal(withdrawalBundle.circuit, "withdraw");
  assert.equal(withdrawalBundle.artifacts.length, 3);
  assert.deepEqual(
    [...new Set(withdrawalBundle.artifacts.map((artifact) => artifact.circuit))],
    ["withdraw"],
  );

  const commitmentBundle = await sdk.resolveVerifiedCommitmentArtifactBundle(
    commitmentProvingManifest,
    artifactsRoot,
  );
  assert.equal(commitmentBundle.circuit, "commitment");
  assert.equal(commitmentBundle.artifacts.length, 3);
  assert.deepEqual(
    [...new Set(commitmentBundle.artifacts.map((artifact) => artifact.circuit))],
    ["commitment"],
  );
});

test("node addon fails closed for invalid proving artifacts and stale sessions", async () => {
  const sdk = new PrivacyPoolsSdkClient();
  await assert.rejects(
    () =>
      sdk.prepareWithdrawalCircuitSessionFromBytes(sampleProvingManifest, [
        { kind: "wasm", bytes: sampleArtifact },
        { kind: "zkey", bytes: sampleArtifact },
        { kind: "vkey", bytes: sampleArtifact },
      ]),
    /invalid zkey|unexpected end of zkey header|missing Groth16 header/,
  );

  await assert.rejects(
    () =>
      sdk.verifyWithdrawalProofWithSession(
        "stable",
        "withdraw-session-missing",
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

async function buildExecutionHandleFixtures(sdk, artifactsRoot) {
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
  const verifiedWithdrawalHandle = await sdk.proveAndVerifyWithdrawalHandle(
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
  const commitmentProof = await sdk.proveCommitmentWithHandle(
    "stable",
    commitmentProvingManifest,
    artifactsRoot,
    commitmentHandle,
  );
  const verifiedRagequitHandle = await sdk.verifyRagequitProofForRequestHandle(
    "stable",
    commitmentProvingManifest,
    artifactsRoot,
    commitmentHandle,
    commitmentProof.proof,
  );
  return {
    masterKeysHandle,
    depositSecretsHandle,
    withdrawalSecretsHandle,
    commitmentHandle,
    verifiedWithdrawalHandle,
    verifiedRagequitHandle,
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

function signedManifestFixture() {
  const artifactBytes = Buffer.from("signed manifest node fixture");
  const payload = {
    manifest: {
      version: "signed-node-test",
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
      build: "node-test",
      repository: "0xbow/privacy-pools-sdk-rs",
      commit: "abc123",
    },
  };
  const payloadJson = JSON.stringify(payload);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const wrongKey = generateKeyPairSync("ed25519").publicKey;
  return {
    payloadJson,
    signatureHex: sign(null, Buffer.from(payloadJson), privateKey).toString("hex"),
    publicKeyHex: ed25519RawPublicKeyHex(publicKey),
    wrongPublicKeyHex: ed25519RawPublicKeyHex(wrongKey),
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

function unwrapNativeValue(value) {
  if (value instanceof Error) {
    throw value;
  }
  return value;
}

async function startExecutionRpcFixtureServer(options) {
  const serverPath = fileURLToPath(new URL("./execution-rpc-server.mjs", import.meta.url));
  const child = spawn(process.execPath, [serverPath, JSON.stringify(options)], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const url = await new Promise((resolve, reject) => {
    let stdout = "";
    const onData = (chunk) => {
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline === -1) {
        return;
      }
      const line = stdout.slice(0, newline).trim();
      child.stdout.off("data", onData);
      try {
        resolve(JSON.parse(line).url);
      } catch (error) {
        reject(error);
      }
    };
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", onData);
    child.once("error", reject);
    child.once("exit", (code) => {
      reject(
        new Error(
          `execution rpc fixture server exited before reporting a URL (code ${code}): ${stderr}`,
        ),
      );
    });
  });

  return {
    url,
    async stop() {
      if (child.exitCode !== null) {
        return;
      }
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill("SIGTERM");
      });
    },
  };
}

async function signFinalizedTransactionRequestWithRustExample(request) {
  const args = [
    "run",
    "--quiet",
    "-p",
    "privacy-pools-sdk-signer",
    "--example",
    "sign-finalized-request",
    "--features",
    "local-mnemonic",
    "--",
    EXECUTION_SIGNER_MNEMONIC,
    JSON.stringify(request),
  ];
  const child = spawn("cargo", args, {
    cwd: workspaceRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });

  if (exitCode !== 0) {
    throw new Error(
      `Rust signer example failed with code ${exitCode}: ${stderr.trim() || stdout.trim()}`,
    );
  }

  return stdout.trim();
}

function validRelayDataHex() {
  return `0x${[
    "0000000000000000000000002222222222222222222222222222222222222222",
    "0000000000000000000000003333333333333333333333333333333333333333",
    "0000000000000000000000000000000000000000000000000000000000000019",
  ].join("")}`;
}
