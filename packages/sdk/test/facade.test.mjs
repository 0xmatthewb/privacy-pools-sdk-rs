import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import * as browserEntry from "../src/browser/index.mjs";
import * as nodeEntry from "../src/node/index.mjs";

const testDir = fileURLToPath(new URL(".", import.meta.url));
const workspaceRoot = join(testDir, "..", "..", "..");
const fixturesRoot = join(workspaceRoot, "fixtures");

const cryptoFixture = readFixtureJson("vectors/crypto-compatibility.json");
const proofFormattingFixture = readFixtureJson("vectors/proof-formatting.json");
const withdrawalFixture = readFixtureJson("vectors/withdrawal-circuit-input.json");
const withdrawalProvingManifest = readFixtureText(
  "artifacts/withdrawal-proving-manifest.json",
);
const commitmentProvingManifest = readFixtureText(
  "artifacts/commitment-proving-manifest.json",
);

const expectedFacadeExports = [
  "AccountError",
  "AccountService",
  "BlockchainProvider",
  "CircuitInitialization",
  "Circuits",
  "CommitmentService",
  "CompatibilityError",
  "ContractError",
  "ContractInteractionsService",
  "DataError",
  "DataService",
  "FetchArtifact",
  "InvalidRpcUrl",
  "PrivacyPoolError",
  "PrivacyPoolSDK",
  "ProofError",
  "SDKError",
  "bigintToHash",
  "bigintToHex",
  "calculateContext",
  "checkpointRecovery",
  "deriveRecoveryKeyset",
  "formatGroth16ProofBundle",
  "generateDepositSecrets",
  "generateMasterKeys",
  "generateMerkleProof",
  "generateWithdrawalSecrets",
  "getCommitment",
  "hashPrecommitment",
  "isCurrentStateRoot",
  "planAspRootRead",
  "planPoolStateRootRead",
  "planRagequitTransaction",
  "planRelayTransaction",
  "planWithdrawalTransaction",
  "recoverAccountState",
  "recoverAccountStateWithKeyset",
];
const expectedObjectExports = [
  "CircuitName",
  "DEFAULT_LOG_FETCH_CONFIG",
  "ErrorCode",
  "Version",
  "circuitToAsset",
];

test("node and browser entrypoints expose the v1 compatibility facade", () => {
  for (const entry of [nodeEntry, browserEntry]) {
    for (const exportName of expectedFacadeExports) {
      assert.equal(typeof entry[exportName], "function", exportName);
    }
    for (const exportName of expectedObjectExports) {
      assert.equal(typeof entry[exportName], "object", exportName);
    }
    assert.equal(entry.CircuitName.Commitment, "commitment");
    assert.equal(entry.CircuitName.Withdraw, "withdraw");
    assert.equal(entry.Version.Latest, "latest");
    assert.equal(entry.circuitToAsset.withdraw.wasm, "withdraw.wasm");
    assert.equal(entry.DEFAULT_LOG_FETCH_CONFIG.blockChunkSize, 10000);
  }
});

test("v1 crypto helpers delegate to Rust-backed client methods", async () => {
  const keys = await nodeEntry.generateMasterKeys(cryptoFixture.mnemonic);
  assert.equal(keys.masterNullifier, BigInt(cryptoFixture.keys.masterNullifier));
  assert.equal(keys.masterSecret, BigInt(cryptoFixture.keys.masterSecret));

  const depositSecrets = await nodeEntry.generateDepositSecrets(
    keys,
    cryptoFixture.scope,
    0n,
  );
  assert.equal(depositSecrets.nullifier, BigInt(cryptoFixture.depositSecrets.nullifier));
  assert.equal(depositSecrets.secret, BigInt(cryptoFixture.depositSecrets.secret));

  const commitment = await nodeEntry.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
  );
  assert.equal(commitment.hash, BigInt(cryptoFixture.commitment.hash));
  assert.equal(commitment.nullifierHash, BigInt(cryptoFixture.commitment.nullifierHash));
  assert.equal(commitment.preimage.value, BigInt(withdrawalFixture.existingValue));
  assert.equal(commitment.preimage.precommitment.nullifier, depositSecrets.nullifier);
  assert.equal(
    await nodeEntry.hashPrecommitment(
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    ),
    BigInt(cryptoFixture.commitment.nullifierHash),
  );

  const context = await nodeEntry.calculateContext(
    {
      processooor: "0x1111111111111111111111111111111111111111",
      data: "0x1234",
    },
    cryptoFixture.scope,
  );
  assert.equal(context, cryptoFixture.context);
  assert.equal(nodeEntry.bigintToHex(255n), "0xff");
});

test("recovery facade exposes Rust-backed account-state DTOs", async () => {
  for (const entry of [nodeEntry, browserEntry]) {
    const policy = { compatibilityMode: "strict", failClosed: true };
    const keyset = await entry.deriveRecoveryKeyset(cryptoFixture.mnemonic, policy);
    assert.equal(
      keyset.safe.masterNullifier,
      cryptoFixture.keys.masterNullifier,
    );
    assert.equal(keyset.legacy, null);

    const poolInputs = await buildStrictRecoveryPool(entry);
    const recovered = await entry.recoverAccountState(
      cryptoFixture.mnemonic,
      poolInputs,
      policy,
    );
    assert.equal(
      recovered.safeMasterKeys.masterSecret,
      cryptoFixture.keys.masterSecret,
    );
    assert.equal(recovered.safeScopes.length, 1);
    assert.equal(recovered.safeScopes[0].scope, cryptoFixture.scope);
    assert.equal(recovered.safeScopes[0].accounts.length, 1);
    assert.equal(
      recovered.safeScopes[0].accounts[0].deposit.hash,
      cryptoFixture.commitment.hash,
    );
    assert.equal(recovered.safeSpendableCommitments.length, 1);
    assert.equal(
      recovered.safeSpendableCommitments[0].commitments[0].hash,
      cryptoFixture.commitment.hash,
    );

    const recoveredWithKeyset = await entry.recoverAccountStateWithKeyset(
      keyset,
      poolInputs,
      policy,
    );
    assert.deepEqual(recoveredWithKeyset, recovered);

    const accountService = new entry.AccountService({
      client: entry.createPrivacyPoolsSdkClient(),
    });
    assert.throws(
      () => accountService.getSpendableCommitments(),
      entry.CompatibilityError,
    );
    const serviceState = await accountService.recoverAccountState(
      cryptoFixture.mnemonic,
      poolInputs,
      policy,
    );
    assert.equal(
      accountService.getSpendableCommitments(serviceState)[0].commitments[0].hash,
      serviceState.safeSpendableCommitments[0].commitments[0].hash,
    );
  }
});

test("Circuits returns only manifest-verified artifact bytes", async () => {
  const server = createFixtureServer();
  await server.start();

  try {
    const circuits = new nodeEntry.Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalManifestJson: withdrawalProvingManifest,
      commitmentManifestJson: commitmentProvingManifest,
    });
    const artifacts = await circuits.downloadArtifacts();
    assert.ok(artifacts.withdraw.wasm instanceof Uint8Array);
    assert.ok(artifacts.withdraw.zkey instanceof Uint8Array);
    assert.ok(artifacts.withdraw.vkey instanceof Uint8Array);
    assert.ok(artifacts.commitment.wasm instanceof Uint8Array);
    assert.ok(await circuits.getWasm(nodeEntry.CircuitName.Withdraw));
    assert.ok(await circuits.getVerificationKey(nodeEntry.CircuitName.Commitment));
  } finally {
    await server.stop();
  }
});

test("PrivacyPoolSDK commitment facade proves and verifies with Rust backend", async () => {
  const server = createFixtureServer();
  await server.start();

  try {
    const circuits = new nodeEntry.Circuits({
      artifactsRoot: server.rootUrl,
      withdrawalManifestJson: withdrawalProvingManifest,
      commitmentManifestJson: commitmentProvingManifest,
    });
    const sdk = new nodeEntry.PrivacyPoolSDK(circuits);
    const proof = await sdk.proveCommitment(
      withdrawalFixture.existingValue,
      withdrawalFixture.label,
      cryptoFixture.depositSecrets.nullifier,
      cryptoFixture.depositSecrets.secret,
    );
    assert.equal(await sdk.verifyCommitment(proof), true);
  } finally {
    await server.stop();
  }
});

test("unsupported v1 legacy services fail with typed compatibility errors", async () => {
  assert.throws(
    () => new nodeEntry.BlockchainProvider("file:///tmp/rpc"),
    nodeEntry.InvalidRpcUrl,
  );
  await assert.rejects(
    () =>
      new nodeEntry.BlockchainProvider("http://127.0.0.1:8545").getBalance(
        "0x1111111111111111111111111111111111111111",
      ),
    nodeEntry.CompatibilityError,
  );
  await assert.rejects(
    () => new nodeEntry.DataService([]).getDeposits({}),
    nodeEntry.CompatibilityError,
  );
});

test("contract and recovery facade wrappers use Rust-backed Node bindings", async () => {
  const poolAddress = "0x0987654321098765432109876543210987654321";
  const entrypointAddress = "0x1234567890123456789012345678901234567890";
  const contractService = new nodeEntry.ContractInteractionsService();

  const stateRead = await contractService.getStateRoot(poolAddress);
  assert.equal(stateRead.kind, "pool_state");
  assert.equal(stateRead.contractAddress, poolAddress);
  assert.equal(stateRead.poolAddress, poolAddress);
  assert.match(stateRead.callData, /^0x[0-9a-f]+$/);

  const aspRead = await contractService.getScopeData(entrypointAddress, poolAddress);
  assert.equal(aspRead.kind, "asp");
  assert.equal(aspRead.contractAddress, entrypointAddress);
  assert.equal(aspRead.poolAddress, poolAddress);
  assert.notEqual(aspRead.callData, stateRead.callData);

  assert.equal(await contractService.isCurrentStateRoot("12", 12n), true);
  assert.equal(await nodeEntry.isCurrentStateRoot("12", "18"), false);

  const formatted = await contractService.formatGroth16Proof(proofFormattingFixture.input);
  assert.deepEqual(formatted.pA, proofFormattingFixture.expected.pA);
  assert.deepEqual(formatted.pB, proofFormattingFixture.expected.pB);
  assert.deepEqual(formatted.pC, proofFormattingFixture.expected.pC);
  assert.deepEqual(formatted.pubSignals, proofFormattingFixture.expected.pubSignals);

  const checkpoint = await nodeEntry.checkpointRecovery(
    [
      {
        blockNumber: 12,
        transactionIndex: 0,
        logIndex: 0,
        poolAddress: "0x1111111111111111111111111111111111111111",
        commitmentHash: "11",
      },
      {
        block_number: 18,
        transaction_index: 1,
        log_index: 3,
        pool_address: "0x1111111111111111111111111111111111111111",
        commitment_hash: "22",
      },
    ],
    { compatibility_mode: "strict", fail_closed: true },
  );
  assert.equal(checkpoint.latestBlock, 18);
  assert.equal(checkpoint.commitmentsSeen, 2);
});

function readFixtureText(path) {
  return readFileSync(join(fixturesRoot, path), "utf8");
}

function readFixtureJson(path) {
  return JSON.parse(readFixtureText(path));
}

async function buildStrictRecoveryPool(entry) {
  const masterKeys = await entry.generateMasterKeys(cryptoFixture.mnemonic);
  const depositSecrets = await entry.generateDepositSecrets(
    masterKeys,
    cryptoFixture.scope,
    0n,
  );
  const commitment = await entry.getCommitment(
    withdrawalFixture.existingValue,
    cryptoFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
  );
  return [
    {
      scope: cryptoFixture.scope,
      depositEvents: [
        {
          commitmentHash: commitment.hash,
          label: cryptoFixture.label,
          value: withdrawalFixture.existingValue,
          precommitmentHash: commitment.preimage.precommitment.hash,
          blockNumber: 10,
          transactionHash:
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        },
      ],
      withdrawalEvents: [],
      ragequitEvents: [],
    },
  ];
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
