import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const packageRoot = join(scriptDir, "..");
const workspaceRoot = join(packageRoot, "..", "..");

export async function buildStatefulTrace({
  runtime,
  entry,
  debugEntry,
  fixture,
  signFinalizedTransaction,
  signFinalizedTransactionWithWrongSigner,
}) {
  const cryptoFixture = readJson(resolveFixturePath(fixture.sessionLifecycle.cryptoFixturePath));
  const withdrawalFixture = readJson(
    resolveFixturePath(fixture.sessionLifecycle.withdrawalFixturePath),
  );
  const manifestPath = resolveFixturePath(fixture.sessionLifecycle.withdrawalManifestPath);
  const manifestJson = readFileSync(manifestPath, "utf8");
  const artifactsRoot = resolveFixturePath(fixture.sessionLifecycle.artifactsRoot);
  const session = await entry.prepareWithdrawalCircuitSessionFromBytes(
    manifestJson,
    artifactInputsForRuntime(runtime, readManifestArtifactBytes(manifestPath)),
  );
  const request = await buildWithdrawalRequest(entry, runtime, {
    cryptoFixture,
    withdrawalFixture,
  });
  const sessionHandle = extractHandle(session);
  const proving = await entry.proveWithdrawalWithSession("stable", sessionHandle, request);
  const verified = await entry.verifyWithdrawalProofWithSession(
    "stable",
    sessionHandle,
    proving.proof,
  );
  const tamperedProof = mutateProofBundle(proving.proof);
  const tamperedRejected = !(await entry.verifyWithdrawalProofWithSession(
    "stable",
    sessionHandle,
    tamperedProof,
  ));
  const removed = await entry.removeWithdrawalCircuitSession(sessionHandle);
  let staleSessionRejected = false;
  try {
    await entry.verifyWithdrawalProofWithSession("stable", sessionHandle, proving.proof);
  } catch {
    staleSessionRejected = true;
  }

  const executionHandles = await buildExecutionHandleFixtures(entry, runtime, fixture, {
    cryptoFixture,
    withdrawalFixture,
    artifactsRoot,
    manifestJson,
  });
  const executionPolicy = runtimeExecutionPolicy(runtime, fixture.executionLifecycle);
  const preflightedHandle = await entry.preflightVerifiedWithdrawalTransactionWithHandle(
    fixture.executionLifecycle.chainId,
    fixture.executionLifecycle.poolAddress,
    fixture.executionLifecycle.validRpcUrl,
    executionPolicy,
    executionHandles.verifiedWithdrawalHandle,
  );
  const preflighted = await debugEntry.dangerouslyExportPreflightedTransaction(preflightedHandle);
  const finalizedHandle = await entry.finalizePreflightedTransactionHandle(
    fixture.executionLifecycle.validRpcUrl,
    preflightedHandle,
  );
  const finalized = await debugEntry.dangerouslyExportFinalizedPreflightedTransaction(
    finalizedHandle,
  );
  const signedTransaction = await signFinalizedTransaction(finalized.request);
  const submittedHandle = await entry.submitFinalizedPreflightedTransactionHandle(
    fixture.executionLifecycle.validRpcUrl,
    finalizedHandle,
    signedTransaction,
  );
  const submitted = await debugEntry.dangerouslyExportSubmittedPreflightedTransaction(
    submittedHandle,
  );

  const wrongChainRejected = await expectRejects(async () => {
    await entry.preflightVerifiedWithdrawalTransactionWithHandle(
      fixture.executionLifecycle.chainId + 1,
      fixture.executionLifecycle.poolAddress,
      fixture.executionLifecycle.validRpcUrl,
      executionPolicy,
      executionHandles.verifiedWithdrawalHandle,
    );
  });
  const wrongCodeHashRejected = await expectRejects(async () => {
    await entry.preflightVerifiedWithdrawalTransactionWithHandle(
      fixture.executionLifecycle.chainId,
      fixture.executionLifecycle.poolAddress,
      fixture.executionLifecycle.validRpcUrl,
      {
        ...executionPolicy,
        ...(runtime === "react-native"
          ? { expected_pool_code_hash: mutateHex(fixture.executionLifecycle.poolCodeHash) }
          : { expectedPoolCodeHash: mutateHex(fixture.executionLifecycle.poolCodeHash) }),
      },
      executionHandles.verifiedWithdrawalHandle,
    );
  });
  const wrongRootRejected = await expectRejects(async () => {
    await entry.preflightVerifiedWithdrawalTransactionWithHandle(
      fixture.executionLifecycle.chainId,
      fixture.executionLifecycle.poolAddress,
      fixture.executionLifecycle.wrongRootRpcUrl,
      executionPolicy,
      executionHandles.verifiedWithdrawalHandle,
    );
  });
  const wrongSignedTransaction =
    await signFinalizedTransactionWithWrongSigner(finalized.request);
  const wrongSignerRejected = await expectRejects(async () => {
    await entry.submitFinalizedPreflightedTransactionHandle(
      fixture.executionLifecycle.validRpcUrl,
      finalizedHandle,
      wrongSignedTransaction,
    );
  });

  await Promise.allSettled([
    entry.removeExecutionHandle?.(submittedHandle),
    entry.clearExecutionHandles?.(),
    entry.clearVerifiedProofHandles?.(),
    entry.clearSecretHandles?.(),
  ]);

  return normalizeStatefulTrace({
    sessionLifecycle: {
      circuit: session.circuit ?? session.circuit_name ?? null,
      artifactVersion: session.artifactVersion ?? session.artifact_version ?? null,
      publicSignals: extractProofPublicSignals(proving.proof),
      verified,
      tamperedRejected,
      removed,
      staleSessionRejected,
    },
    executionLifecycle: {
      transaction: normalizeTransactionPlan(preflighted.transaction),
      preflight: normalizePreflight(preflighted.preflight),
      finalizedRequest: normalizeFinalizedRequest(finalized.request),
      submittedReceipt: normalizeReceipt(submitted.receipt),
      wrongChainRejected,
      wrongCodeHashRejected,
      wrongRootRejected,
      wrongSignerRejected,
    },
  });
}

export function normalizeStatefulTrace(trace) {
  return {
    sessionLifecycle: {
      circuit: trace.sessionLifecycle.circuit ?? null,
      artifactVersion:
        trace.sessionLifecycle.artifactVersion ??
        trace.sessionLifecycle.artifact_version ??
        null,
      publicSignals: (trace.sessionLifecycle.publicSignals ??
        trace.sessionLifecycle.public_signals ??
        []
      ).map(lowercaseHex),
      verified: Boolean(trace.sessionLifecycle.verified),
      tamperedRejected: Boolean(trace.sessionLifecycle.tamperedRejected),
      removed: Boolean(trace.sessionLifecycle.removed),
      staleSessionRejected: Boolean(trace.sessionLifecycle.staleSessionRejected),
    },
    executionLifecycle: {
      transaction: normalizeTransactionPlan(trace.executionLifecycle.transaction),
      preflight: normalizePreflight(trace.executionLifecycle.preflight),
      finalizedRequest: normalizeFinalizedRequest(trace.executionLifecycle.finalizedRequest),
      submittedReceipt: normalizeReceipt(trace.executionLifecycle.submittedReceipt),
      wrongChainRejected: Boolean(trace.executionLifecycle.wrongChainRejected),
      wrongCodeHashRejected: Boolean(trace.executionLifecycle.wrongCodeHashRejected),
      wrongRootRejected: Boolean(trace.executionLifecycle.wrongRootRejected),
      wrongSignerRejected: Boolean(trace.executionLifecycle.wrongSignerRejected),
    },
  };
}

function extractHandle(session) {
  return typeof session === "string" ? session : session.handle;
}

async function buildWithdrawalRequest(entry, runtime, { cryptoFixture, withdrawalFixture }) {
  const keys = await entry.deriveMasterKeys(cryptoFixture.mnemonic);
  const depositSecrets = await entry.deriveDepositSecrets(
    keys.masterNullifier ?? keys.master_nullifier,
    keys.masterSecret ?? keys.master_secret,
    cryptoFixture.scope,
    "0",
  );
  const commitment = await entry.getCommitment(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecrets.nullifier,
    depositSecrets.secret,
  );
  return {
    commitment,
    withdrawal: runtimeWithdrawal(
      runtime,
      {
        processooor: "0x1111111111111111111111111111111111111111",
        data: "0x1234",
      },
    ),
    scope: cryptoFixture.scope,
    withdrawalAmount: withdrawalFixture.withdrawalAmount,
    stateWitness: withdrawalFixture.stateWitness,
    aspWitness: withdrawalFixture.aspWitness,
    newNullifier: withdrawalFixture.newNullifier,
    newSecret: withdrawalFixture.newSecret,
  };
}

async function buildExecutionHandleFixtures(
  entry,
  runtime,
  fixture,
  { cryptoFixture, withdrawalFixture, artifactsRoot, manifestJson },
) {
  const masterKeysHandle = await entry.deriveMasterKeysHandle(cryptoFixture.mnemonic);
  const depositSecretsHandle = await entry.generateDepositSecretsHandle(
    masterKeysHandle,
    cryptoFixture.scope,
    "0",
  );
  const withdrawalSecretsHandle = await entry.generateWithdrawalSecretsHandle(
    masterKeysHandle,
    withdrawalFixture.label,
    "1",
  );
  const commitmentHandle = await entry.getCommitmentFromHandles(
    withdrawalFixture.existingValue,
    withdrawalFixture.label,
    depositSecretsHandle,
  );
  const verifiedWithdrawalHandle = await entry.proveAndVerifyWithdrawalHandle(
    "stable",
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    runtimeWithdrawal(runtime, fixture.executionLifecycle.withdrawal),
    cryptoFixture.scope,
    withdrawalFixture.withdrawalAmount,
    withdrawalFixture.stateWitness,
    withdrawalFixture.aspWitness,
    withdrawalSecretsHandle,
  );
  return {
    commitmentHandle,
    verifiedWithdrawalHandle,
  };
}

function artifactInputsForRuntime(runtime, inputs) {
  return inputs.map((artifact) => ({
    kind: artifact.kind,
    bytes: runtime === "react-native" ? [...artifact.bytes] : artifact.bytes,
  }));
}

function runtimeWithdrawal(runtime, withdrawal) {
  if (runtime === "react-native") {
    return {
      processooor: withdrawal.processooor,
      data: hexToBytes(withdrawal.data),
    };
  }
  return withdrawal;
}

function runtimeExecutionPolicy(runtime, executionLifecycle) {
  if (runtime === "react-native") {
    return {
      expected_chain_id: executionLifecycle.chainId,
      caller: executionLifecycle.caller,
      expected_pool_code_hash: executionLifecycle.poolCodeHash,
      expected_entrypoint_code_hash: executionLifecycle.entrypointCodeHash,
      mode: "strict",
    };
  }
  return {
    expectedChainId: executionLifecycle.chainId,
    caller: executionLifecycle.caller,
    expectedPoolCodeHash: executionLifecycle.poolCodeHash,
    expectedEntrypointCodeHash: executionLifecycle.entrypointCodeHash,
    mode: "strict",
  };
}

function mutateProofBundle(proofBundle) {
  const clone = JSON.parse(JSON.stringify(proofBundle));
  if (Array.isArray(clone.publicSignals)) {
    clone.publicSignals[0] = "9";
  } else if (Array.isArray(clone.public_signals)) {
    clone.public_signals[0] = "9";
  }
  return clone;
}

function normalizeTransactionPlan(plan) {
  return {
    kind: plan.kind,
    chain_id: Number(plan.chainId ?? plan.chain_id),
    target: lowercaseHex(plan.target),
    calldata: summarizeCalldata(plan.calldata),
    value: normalizeUint(plan.value),
    proof: summarizeProof(plan.proof),
  };
}

function normalizePreflight(report) {
  return {
    kind: report.kind,
    caller: lowercaseHex(report.caller),
    target: lowercaseHex(report.target),
    expected_chain_id: Number(report.expectedChainId ?? report.expected_chain_id),
    actual_chain_id: Number(report.actualChainId ?? report.actual_chain_id),
    chain_id_matches: Boolean(report.chainIdMatches ?? report.chain_id_matches),
    simulated: Boolean(report.simulated),
    estimated_gas: Number(report.estimatedGas ?? report.estimated_gas),
    mode: report.mode ?? null,
    code_hash_checks: (report.codeHashChecks ?? report.code_hash_checks ?? []).map((check) => ({
      address: lowercaseHex(check.address),
      expected_code_hash:
        check.expectedCodeHash ?? check.expected_code_hash ?? null,
      actual_code_hash: check.actualCodeHash ?? check.actual_code_hash,
      matches_expected: check.matchesExpected ?? check.matches_expected ?? null,
    })),
    root_checks: (report.rootChecks ?? report.root_checks ?? []).map((check) => ({
      kind: check.kind,
      contract_address: lowercaseHex(check.contractAddress ?? check.contract_address),
      pool_address: lowercaseHex(check.poolAddress ?? check.pool_address),
      expected_root: normalizeUint(check.expectedRoot ?? check.expected_root),
      actual_root: normalizeUint(check.actualRoot ?? check.actual_root),
      matches: Boolean(check.matches),
    })),
  };
}

function normalizeFinalizedRequest(request) {
  return {
    kind: request.kind,
    chain_id: Number(request.chainId ?? request.chain_id),
    from: lowercaseHex(request.from),
    to: lowercaseHex(request.to),
    nonce: Number(request.nonce),
    gas_limit: Number(request.gasLimit ?? request.gas_limit),
    value: normalizeUint(request.value),
    data: summarizeCalldata(request.data),
    gas_price: normalizeUintOrNull(request.gasPrice ?? request.gas_price),
    max_fee_per_gas: normalizeUintOrNull(request.maxFeePerGas ?? request.max_fee_per_gas),
    max_priority_fee_per_gas: normalizeUintOrNull(
      request.maxPriorityFeePerGas ?? request.max_priority_fee_per_gas,
    ),
  };
}

function normalizeReceipt(receipt) {
  return {
    transaction_hash: receipt.transactionHash ?? receipt.transaction_hash,
    block_hash: valueOrNull(receipt.blockHash ?? receipt.block_hash),
    block_number: numberOrNull(receipt.blockNumber ?? receipt.block_number),
    transaction_index: numberOrNull(receipt.transactionIndex ?? receipt.transaction_index),
    success: Boolean(receipt.success),
    gas_used: Number(receipt.gasUsed ?? receipt.gas_used),
    effective_gas_price: normalizeUint(
      receipt.effectiveGasPrice ?? receipt.effective_gas_price,
    ),
    from: lowercaseHex(receipt.from),
    to: lowercaseHex(receipt.to),
  };
}

function normalizeFormattedProof(proof) {
  const pA = proof?.pA ?? proof?.p_a ?? proof?.proof?.pi_a ?? [];
  const pB = proof?.pB ?? proof?.p_b ?? proof?.proof?.pi_b ?? [];
  const pC = proof?.pC ?? proof?.p_c ?? proof?.proof?.pi_c ?? [];
  const publicSignals =
    proof?.pubSignals ??
    proof?.pub_signals ??
    proof?.publicSignals ??
    proof?.public_signals ??
    [];
  return {
    p_a: pA.map(lowercaseHex),
    p_b: pB.map((pair) => pair.map(lowercaseHex)),
    p_c: pC.map(lowercaseHex),
    pub_signals: publicSignals.map(lowercaseHex),
  };
}

function summarizeProof(proof) {
  if (proof && typeof proof === "object" && ("public_signals" in proof || "proof_shape" in proof)) {
    return {
      public_signals: (
        proof.public_signals ??
        proof.publicSignals ??
        proof.pub_signals ??
        proof.pubSignals ??
        []
      ).map(lowercaseHex),
      proof_shape: normalizeProofShape(proof.proof_shape ?? proof.proofShape ?? null),
    };
  }
  const normalized = normalizeFormattedProof(proof);
  return {
    public_signals: normalized.pub_signals,
    proof_shape: {
      p_a: normalized.p_a.length,
      p_b: normalized.p_b.map((pair) => pair.length),
      p_c: normalized.p_c.length,
    },
  };
}

function summarizeCalldata(value) {
  if (value && typeof value === "object" && "selector" in value && "length" in value) {
    return {
      selector: lowercaseHex(value.selector),
      length: Number(value.length),
    };
  }
  const calldata =
    typeof value === "string"
      ? value
      : value == null
        ? ""
        : String(value);
  return {
    selector: calldata.slice(0, 10).toLowerCase(),
    length: calldata.length,
  };
}

function normalizeProofShape(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  return {
    p_a: Number(value.p_a ?? value.pA ?? 0),
    p_b: Array.isArray(value.p_b ?? value.pB)
      ? (value.p_b ?? value.pB).map((pair) => Number(pair))
      : [],
    p_c: Number(value.p_c ?? value.pC ?? 0),
  };
}

function extractProofPublicSignals(proofBundle) {
  return proofBundle.publicSignals ?? proofBundle.public_signals ?? [];
}

function readManifestArtifactBytes(manifestPath) {
  const manifest = readJson(manifestPath);
  const artifactsRoot = dirname(manifestPath);
  return manifest.artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytes: readFileSync(join(artifactsRoot, artifact.filename)),
  }));
}

function resolveFixturePath(relativePath) {
  return resolve(workspaceRoot, relativePath);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function hexToBytes(value) {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  const pairs = hex.length === 0 ? [] : hex.match(/.{1,2}/g) ?? [];
  return pairs.map((pair) => Number.parseInt(pair, 16));
}

function lowercaseHex(value) {
  if (typeof value !== "string") {
    return value ?? null;
  }
  return value.toLowerCase();
}

function mutateHex(value) {
  return `0x11${value.slice(4)}`;
}

function valueOrNull(value) {
  return value == null ? null : String(value);
}

function normalizeUint(value) {
  if (typeof value === "bigint") {
    return toNormalizedHex(value);
  }
  if (typeof value === "number") {
    return toNormalizedHex(BigInt(value));
  }
  if (typeof value !== "string") {
    return value == null ? "0x0" : String(value);
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return "0x0";
  }
  try {
    if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
      return toNormalizedHex(BigInt(trimmed));
    }
    return toNormalizedHex(BigInt(trimmed));
  } catch {
    return trimmed.toLowerCase();
  }
}

function normalizeUintOrNull(value) {
  return value == null ? null : normalizeUint(value);
}

function toNormalizedHex(value) {
  return `0x${value.toString(16)}`;
}

function numberOrNull(value) {
  return value == null ? null : Number(value);
}

async function expectRejects(fn) {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}
