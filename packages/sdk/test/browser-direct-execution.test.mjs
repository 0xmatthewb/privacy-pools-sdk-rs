import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { PrivacyPoolsSdkClient } from "../src/browser/index.mjs";
import * as browserDebug from "../src/browser/debug.mjs";
import { __setWitnessResetProbeOverrideForTests } from "../src/browser/runtime.mjs";
import {
  EXECUTION_FIXTURE,
  createExecutionRpcFixtureServer,
  signFinalizedTransactionRequest,
  signFinalizedTransactionRequestWithWrongSigner,
  strictExecutionPolicy,
} from "./execution-fixture.mjs";
import {
  assertFixtureServerArtifacts,
  createFixtureServer as createBrowserFixtureServer,
  fixturesRoot,
  preflightFixtureArtifacts,
} from "./browser-fixtures.mjs";

const cryptoFixture = JSON.parse(
  readFileSync(join(fixturesRoot, "vectors", "crypto-compatibility.json"), "utf8"),
);
const withdrawalFixture = JSON.parse(
  readFileSync(
    join(fixturesRoot, "vectors", "withdrawal-circuit-input.json"),
    "utf8",
  ),
);
const withdrawalProvingManifest = readFileSync(
  join(fixturesRoot, "artifacts", "withdrawal-proving-manifest.json"),
  "utf8",
);
const withdrawalVerificationManifest = readFileSync(
  join(fixturesRoot, "artifacts", "withdrawal-verification-manifest.json"),
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
const compatibilityShapes = JSON.parse(
  readFileSync(
    join(fixturesRoot, "compatibility-shapes", "sdk-json-shapes.json"),
    "utf8",
  ),
);
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

preflightFixtureArtifacts(
  commitmentProvingManifest,
  commitmentVerificationManifest,
  withdrawalProvingManifest,
  withdrawalVerificationManifest,
);

afterEach(async () => {
  __setWitnessResetProbeOverrideForTests("auto");
  await new PrivacyPoolsSdkClient().dispose();
});

test(
  "browser runtime supports secret handles and binary witness proving",
  { concurrency: false },
  async () => {
    const sdk = new PrivacyPoolsSdkClient();
    const server = createBrowserFixtureServer();
    await server.start();

    try {
      await assertFixtureServerArtifacts(
        server.rootUrl,
        commitmentProvingManifest,
        commitmentVerificationManifest,
        withdrawalProvingManifest,
        withdrawalVerificationManifest,
      );
      assert.equal(await sdk.supportsExperimentalThreadedBrowserProving(), false);

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
        cryptoFixture.label,
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

      const exportedMasterKeys = await browserDebug.dangerouslyExportMasterKeys(
        masterKeysHandle,
      );
      assert.equal(exportedMasterKeys.masterNullifier, cryptoFixture.keys.masterNullifier);
      const exportedSecrets = await browserDebug.dangerouslyExportSecret(
        depositSecretsHandle,
      );
      assert.deepEqual(exportedSecrets, cryptoFixture.depositSecrets);
      const exportedCommitment = await browserDebug.dangerouslyExportCommitmentPreimage(
        commitmentHandle,
      );
      assert.equal(exportedCommitment.hash, cryptoFixture.commitment.hash);

      const commitmentStatuses = [];
      const commitmentProof = await sdk.proveCommitmentWithHandle(
        "stable",
        commitmentProvingManifest,
        server.rootUrl,
        commitmentHandle,
        { onStatus: (status) => commitmentStatuses.push(status) },
      );
      assert.equal(commitmentProof.backend, "arkworks");
      assert.equal(
        await sdk.verifyCommitmentProof(
          "stable",
          commitmentVerificationManifest,
          server.rootUrl,
          commitmentProof.proof,
        ),
        true,
      );
      assert.deepEqual(
        commitmentStatuses.map((status) => status.stage),
        [
          "preload",
          "witness",
          "witness-parse",
          "witness-transfer",
          "witness",
          "prove",
          "verify",
          "done",
        ],
      );
      assert.equal(
        commitmentStatuses.filter((status) => status.stage === "witness").at(-1)
          .witnessRuntime,
        "probe-reuse",
      );

      const withdrawal = {
        processooor: "0x1111111111111111111111111111111111111111",
        data: validRelayDataHex(),
      };
      const withdrawalStatuses = [];
      const withdrawalProof = await sdk.proveWithdrawalWithHandles(
        "stable",
        withdrawalProvingManifest,
        server.rootUrl,
        commitmentHandle,
        withdrawal,
        cryptoFixture.scope,
        withdrawalFixture.withdrawalAmount,
        withdrawalFixture.stateWitness,
        withdrawalFixture.aspWitness,
        withdrawalSecretsHandle,
        (status) => withdrawalStatuses.push(status),
      );
      assert.equal(withdrawalProof.backend, "arkworks");
      assert.equal(
        await sdk.verifyWithdrawalProof(
          "stable",
          withdrawalVerificationManifest,
          server.rootUrl,
          withdrawalProof.proof,
        ),
        true,
      );
      assert.deepEqual(
        withdrawalStatuses.map((status) => status.stage),
        [
          "preload",
          "witness",
          "witness-parse",
          "witness-transfer",
          "witness",
          "prove",
          "verify",
          "done",
        ],
      );
      assert.equal(
        withdrawalStatuses.filter((status) => status.stage === "witness").at(-1)
          .witnessRuntime,
        "probe-reuse",
      );

      const poolAddress = "0x2222222222222222222222222222222222222222";
      const entrypointAddress = withdrawal.processooor;
      const verifiedCommitmentHandle =
        await sdk.verifyCommitmentProofForRequestHandle(
          "stable",
          commitmentVerificationManifest,
          server.rootUrl,
          commitmentHandle,
          commitmentProof.proof,
        );
      const verifiedRagequitHandle = await sdk.verifyRagequitProofForRequestHandle(
        "stable",
        commitmentVerificationManifest,
        server.rootUrl,
        commitmentHandle,
        commitmentProof.proof,
      );
      const verifiedWithdrawalHandle =
        await sdk.verifyWithdrawalProofForRequestHandle(
          "stable",
          withdrawalVerificationManifest,
          server.rootUrl,
          commitmentHandle,
          withdrawal,
          cryptoFixture.scope,
          withdrawalFixture.withdrawalAmount,
          withdrawalFixture.stateWitness,
          withdrawalFixture.aspWitness,
          withdrawalSecretsHandle,
          withdrawalProof.proof,
        );
      for (const handle of [
        verifiedCommitmentHandle,
        verifiedRagequitHandle,
        verifiedWithdrawalHandle,
      ]) {
        assert.match(handle, UUID_V4_RE);
      }

      assert.deepEqual(
        await sdk.planVerifiedWithdrawalTransactionWithHandle(
          1,
          poolAddress,
          verifiedWithdrawalHandle,
        ),
        await sdk.planWithdrawalTransaction(
          1,
          poolAddress,
          withdrawal,
          withdrawalProof.proof,
        ),
      );
      assert.deepEqual(
        await sdk.planVerifiedRelayTransactionWithHandle(
          1,
          entrypointAddress,
          verifiedWithdrawalHandle,
        ),
        await sdk.planRelayTransaction(
          1,
          entrypointAddress,
          withdrawal,
          withdrawalProof.proof,
          cryptoFixture.scope,
        ),
      );
      assert.deepEqual(
        await sdk.planVerifiedRagequitTransactionWithHandle(
          1,
          poolAddress,
          verifiedRagequitHandle,
        ),
        await sdk.planRagequitTransaction(1, poolAddress, commitmentProof.proof),
      );
      assert.equal(await sdk.removeVerifiedProofHandle(verifiedCommitmentHandle), true);
      assert.equal(await sdk.removeVerifiedProofHandle(verifiedRagequitHandle), true);
      assert.equal(await sdk.removeVerifiedProofHandle(verifiedWithdrawalHandle), true);
      assert.equal(await sdk.clearVerifiedProofHandles(), false);

      assert.equal(await sdk.removeSecretHandle(masterKeysHandle), true);
      assert.equal(await sdk.removeSecretHandle(depositSecretsHandle), true);
      assert.equal(await sdk.removeSecretHandle(withdrawalSecretsHandle), true);
      assert.equal(await sdk.removeSecretHandle(commitmentHandle), true);
      assert.equal(await sdk.clearSecretHandles(), false);
    } finally {
      await sdk.dispose();
      await server.stop();
    }
  },
);

test(
  "browser direct client preflights, finalizes, and submits execution handles",
  { concurrency: false },
  async () => {
    const sdk = new PrivacyPoolsSdkClient();
    const artifactServer = createBrowserFixtureServer();
    const rpcServer = createExecutionRpcFixtureServer({
      stateRoot: withdrawalFixture.stateWitness.root,
      aspRoot: withdrawalFixture.aspWitness.root,
    });
    await artifactServer.start();
    await rpcServer.start();

    try {
      await assertFixtureServerArtifacts(
        artifactServer.rootUrl,
        commitmentProvingManifest,
        commitmentVerificationManifest,
        withdrawalProvingManifest,
        withdrawalVerificationManifest,
      );
      const {
        verifiedWithdrawalHandle,
        verifiedRagequitHandle,
      } = await buildBrowserExecutionHandleFixtures(sdk, artifactServer.rootUrl);

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

      const withdrawalPreflighted =
        await browserDebug.dangerouslyExportPreflightedTransaction(
          withdrawalPreflightedHandle,
        );
      const relayPreflighted = await browserDebug.dangerouslyExportPreflightedTransaction(
        relayPreflightedHandle,
      );
      const ragequitPreflighted =
        await browserDebug.dangerouslyExportPreflightedTransaction(
          ragequitPreflightedHandle,
        );
      assertCompatibilityShape(
        "browserDirect",
        "preflightedTransaction",
        withdrawalPreflighted,
      );
      assertCompatibilityShape("browserDirect", "preflightedTransaction", relayPreflighted);
      assertCompatibilityShape(
        "browserDirect",
        "ragequitPreflightedTransaction",
        ragequitPreflighted,
      );
      assert.equal(withdrawalPreflighted.preflight.mode, "strict");
      assert.equal(withdrawalPreflighted.preflight.codeHashChecks.length, 2);
      assert.equal(withdrawalPreflighted.preflight.rootChecks.length, 2);
      assert.equal(relayPreflighted.transaction.kind, "relay");
      assert.equal(ragequitPreflighted.preflight.rootChecks.length, 0);

      await assert.rejects(
        () =>
          sdk.submitPreflightedTransactionHandle(
            rpcServer.url,
            withdrawalPreflightedHandle,
          ),
        /requires a signer|externally signed transaction/i,
      );

      const finalizedHandle = await sdk.finalizePreflightedTransactionHandle(
        rpcServer.url,
        withdrawalPreflightedHandle,
      );
      assert.match(finalizedHandle, UUID_V4_RE);
      const finalized =
        await browserDebug.dangerouslyExportFinalizedPreflightedTransaction(
          finalizedHandle,
        );
      assertCompatibilityShape(
        "browserDirect",
        "finalizedPreflightedTransaction",
        finalized,
      );

      const signedTransaction = await signFinalizedTransactionRequest(finalized.request);
      const submittedHandle = await sdk.submitFinalizedPreflightedTransactionHandle(
        rpcServer.url,
        finalizedHandle,
        signedTransaction,
      );
      assert.match(submittedHandle, UUID_V4_RE);
      assertCompatibilityShape("browserDirect", "executionHandles", {
        preflighted: withdrawalPreflightedHandle,
        finalized: finalizedHandle,
        submitted: submittedHandle,
      });

      const submitted =
        await browserDebug.dangerouslyExportSubmittedPreflightedTransaction(
          submittedHandle,
        );
      assertCompatibilityShape(
        "browserDirect",
        "submittedPreflightedTransaction",
        submitted,
      );
      assertCompatibilityShape(
        "browserDirect",
        "transactionReceiptSummary",
        submitted.receipt,
      );
      assert.equal(submitted.receipt.transactionHash, EXECUTION_FIXTURE.transactionHash);
      assert.equal(rpcServer.rawTransactions.at(-1), signedTransaction);

      assert.equal(await sdk.removeExecutionHandle(relayPreflightedHandle), true);
      assert.equal(await sdk.removeExecutionHandle(ragequitPreflightedHandle), true);
      assert.equal(await sdk.removeExecutionHandle(submittedHandle), true);
      assert.equal(await sdk.clearExecutionHandles(), true);
      assert.equal(await sdk.clearExecutionHandles(), false);
      await assert.rejects(
        () =>
          browserDebug.dangerouslyExportPreflightedTransaction(
            withdrawalPreflightedHandle,
          ),
        /execution handle|not found|unknown/i,
      );
      await assert.rejects(
        () =>
          browserDebug.dangerouslyExportFinalizedPreflightedTransaction(finalizedHandle),
        /execution handle|not found|unknown/i,
      );
    } finally {
      await sdk.dispose();
      await artifactServer.stop();
      await rpcServer.stop();
    }
  },
);

test(
  "browser direct client rejects invalid execution preflight policies and signer mismatches",
  { concurrency: false },
  async () => {
    const sdk = new PrivacyPoolsSdkClient();
    const validArtifactServer = createBrowserFixtureServer();
    const validRpcServer = createExecutionRpcFixtureServer({
      stateRoot: withdrawalFixture.stateWitness.root,
      aspRoot: withdrawalFixture.aspWitness.root,
    });
    const wrongRootRpcServer = createExecutionRpcFixtureServer({
      stateRoot: "999",
      aspRoot: withdrawalFixture.aspWitness.root,
    });
    await validArtifactServer.start();
    await validRpcServer.start();
    await wrongRootRpcServer.start();

    try {
      await assertFixtureServerArtifacts(
        validArtifactServer.rootUrl,
        commitmentProvingManifest,
        commitmentVerificationManifest,
        withdrawalProvingManifest,
        withdrawalVerificationManifest,
      );
      const { verifiedWithdrawalHandle } = await buildBrowserExecutionHandleFixtures(
        sdk,
        validArtifactServer.rootUrl,
      );

      await assert.rejects(
        () =>
          sdk.preflightVerifiedWithdrawalTransactionWithHandle(
            EXECUTION_FIXTURE.chainId + 1,
            EXECUTION_FIXTURE.poolAddress,
            validRpcServer.url,
            strictExecutionPolicy(),
            verifiedWithdrawalHandle,
          ),
        /chain id mismatch|chain id does not match/i,
      );

      await assert.rejects(
        () =>
          sdk.preflightVerifiedWithdrawalTransactionWithHandle(
            EXECUTION_FIXTURE.chainId,
            EXECUTION_FIXTURE.poolAddress,
            validRpcServer.url,
            {
              ...strictExecutionPolicy(),
              expectedPoolCodeHash: `0x${"11".repeat(32)}`,
            },
            verifiedWithdrawalHandle,
          ),
        /code hash mismatch/i,
      );

      await assert.rejects(
        () =>
          sdk.preflightVerifiedWithdrawalTransactionWithHandle(
            EXECUTION_FIXTURE.chainId,
            EXECUTION_FIXTURE.poolAddress,
            wrongRootRpcServer.url,
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
      const finalized =
        await browserDebug.dangerouslyExportFinalizedPreflightedTransaction(
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
        /signer mismatch|sender does not match preflight caller/i,
      );
    } finally {
      await sdk.dispose();
      await validArtifactServer.stop();
      await validRpcServer.stop();
      await wrongRootRpcServer.stop();
    }
  },
);

function validRelayDataHex() {
  return `0x${[
    "0000000000000000000000002222222222222222222222222222222222222222",
    "0000000000000000000000003333333333333333333333333333333333333333",
    "0000000000000000000000000000000000000000000000000000000000000019",
  ].join("")}`;
}

function assertCompatibilityShape(runtime, name, value) {
  const runtimeShapes = resolveShapeRef(compatibilityShapes, compatibilityShapes[runtime]);
  assert.deepEqual(
    shapeOf(value),
    resolveShapeRef(compatibilityShapes, runtimeShapes[name]),
    `${runtime}.${name}`,
  );
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
