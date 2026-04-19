import { THREADED_ARTIFACT_BUILT } from "./generated-threaded/availability.mjs";

const PROVER_UNAVAILABLE_MESSAGE =
  "Browser proving supports only the stable Rust/WASM backend.";
const BROWSER_CAPABILITIES = Object.freeze({
  runtime: "browser",
  provingAvailable: true,
  verificationAvailable: true,
  workerAvailable: true,
  reason:
    "Browser proving and verification are available through Rust/WASM with browser-native circuit witness execution.",
});

const STABLE_BACKEND_NAME = "Arkworks";
const DEFAULT_BROWSER_SESSION_ARTIFACT_CACHE_CAPACITY = 4;
const BINARY_WITNESS_LIMBS_PER_FIELD = 8;
const ROOT_HISTORY_SIZE = 64n;
const PRIVACY_POOL_ABI = [
  {
    type: "function",
    name: "ENTRYPOINT",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "currentRoot",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "currentRootIndex",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint32" }],
  },
  {
    type: "function",
    name: "roots",
    stateMutability: "view",
    inputs: [{ type: "uint256", name: "index" }],
    outputs: [{ type: "uint256" }],
  },
];
const ENTRYPOINT_ABI = [
  {
    type: "function",
    name: "latestRoot",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
];

let wasmModulePromise = null;
let wasmModuleFlavor = null;
let witnessResetProbeOverrideForTests = "auto";
let viemModulePromise = null;

export class BrowserRuntimeUnavailableError extends Error {
  constructor(message = PROVER_UNAVAILABLE_MESSAGE) {
    super(message);
    this.name = "BrowserRuntimeUnavailableError";
  }
}

export function getRuntimeCapabilities() {
  return { ...BROWSER_CAPABILITIES };
}

export async function getVersion() {
  const wasm = await getWasmModule();
  return wasm.getVersion();
}

export async function getStableBackendName() {
  const wasm = await getWasmModule();
  return wasm.getStableBackendName?.() ?? STABLE_BACKEND_NAME;
}

export function supportsExperimentalThreadedBrowserProving() {
  return (
    THREADED_ARTIFACT_BUILT &&
    typeof SharedArrayBuffer !== "undefined" &&
    globalThis.crossOriginIsolated === true
  );
}

export async function initializeExperimentalThreadedBrowserProving(options = {}) {
  if (!THREADED_ARTIFACT_BUILT) {
    return {
      threadedProvingEnabled: false,
      fallback: "stable-single-threaded",
      reason: "experimental threaded WASM artifact was not built",
    };
  }

  if (!supportsExperimentalThreadedBrowserProving()) {
    return {
      threadedProvingEnabled: false,
      fallback: "stable-single-threaded",
      reason: "SharedArrayBuffer and cross-origin isolation are required",
    };
  }

  if (wasmModulePromise && wasmModuleFlavor === "threaded") {
    await wasmModulePromise;
    return {
      threadedProvingEnabled: true,
      fallback: null,
      threadCount: normalizeThreadCount(options.threadCount),
    };
  }

  if (wasmModulePromise && wasmModuleFlavor !== "threaded") {
    return {
      threadedProvingEnabled: false,
      fallback: "stable-single-threaded",
      reason: "stable browser WASM runtime was already initialized",
    };
  }

  wasmModuleFlavor = "threaded";
  wasmModulePromise = initializeWasmModule({
    experimentalThreaded: true,
    threadCount: options.threadCount,
  }).catch((error) => {
    wasmModulePromise = null;
    wasmModuleFlavor = null;
    throw error;
  });

  try {
    await wasmModulePromise;
    return {
      threadedProvingEnabled: true,
      fallback: null,
      threadCount: normalizeThreadCount(options.threadCount),
    };
  } catch (error) {
    return {
      threadedProvingEnabled: false,
      fallback: "stable-single-threaded",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

export function __setWitnessResetProbeOverrideForTests(value) {
  witnessResetProbeOverrideForTests = value === "fallback" ? "fallback" : "auto";
}

export async function deriveMasterKeys(mnemonic) {
  return invokeJson("deriveMasterKeysJson", mnemonic);
}

export async function deriveMasterKeysHandle(mnemonic) {
  const wasm = await getWasmModule();
  return wasm.deriveMasterKeysHandle(mnemonic);
}

export async function deriveDepositSecrets(masterKeys, scope, index) {
  return invokeJson(
    "deriveDepositSecretsJson",
    JSON.stringify(masterKeys),
    scope,
    index,
  );
}

export async function generateDepositSecretsHandle(masterKeys, scope, index) {
  const wasm = await getWasmModule();
  const { handle, temporary } = await masterKeysHandleFor(wasm, masterKeys);
  try {
    return wasm.generateDepositSecretsHandle(handle, String(scope), String(index));
  } finally {
    if (temporary) {
      wasm.removeSecretHandle(handle);
    }
  }
}

export async function deriveWithdrawalSecrets(masterKeys, label, index) {
  return invokeJson(
    "deriveWithdrawalSecretsJson",
    JSON.stringify(masterKeys),
    label,
    index,
  );
}

export async function generateWithdrawalSecretsHandle(masterKeys, label, index) {
  const wasm = await getWasmModule();
  const { handle, temporary } = await masterKeysHandleFor(wasm, masterKeys);
  try {
    return wasm.generateWithdrawalSecretsHandle(handle, String(label), String(index));
  } finally {
    if (temporary) {
      wasm.removeSecretHandle(handle);
    }
  }
}

export async function getCommitment(value, label, nullifier, secret) {
  return invokeJson("getCommitmentJson", value, label, nullifier, secret);
}

export async function getCommitmentFromHandles(value, label, secretsHandle) {
  const wasm = await getWasmModule();
  return wasm.getCommitmentFromHandles(String(value), String(label), secretsHandle);
}

export async function proveCommitmentWithHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "commitment" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "commitment");
  try {
    const witnessInput =
      await buildCommitmentWitnessInputFromHandle(commitmentHandle);
    return await proveCommitmentWithPreparedWitnessInput(
      session.handle,
      witnessInput,
      status,
      false,
      true,
    );
  } finally {
    await removeCommitmentCircuitSession(session.handle);
  }
}

export async function proveWithdrawalWithHandles(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "withdraw" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "withdraw");
  try {
    const witnessInput = await buildWithdrawalWitnessInputFromHandles(
      commitmentHandle,
      withdrawal,
      scope,
      withdrawalAmount,
      stateWitness,
      aspWitness,
      newSecretsHandle,
    );
    return await proveWithdrawalWithPreparedWitnessInput(
      session.handle,
      witnessInput,
      status,
      false,
      true,
    );
  } finally {
    await removeWithdrawalCircuitSession(session.handle);
  }
}

export async function dangerouslyExportMasterKeys(handle) {
  return invokeJson("dangerouslyExportMasterKeys", handle);
}

export async function dangerouslyExportCommitmentPreimage(handle) {
  return invokeJson("dangerouslyExportCommitmentPreimage", handle);
}

export async function dangerouslyExportSecret(handle) {
  return invokeJson("dangerouslyExportSecret", handle);
}

export async function removeSecretHandle(handle) {
  const wasm = await getWasmModule();
  return wasm.removeSecretHandle(handle);
}

export async function clearSecretHandles() {
  const wasm = await getWasmModule();
  return wasm.clearSecretHandles();
}

export async function removeVerifiedProofHandle(handle) {
  const wasm = await getWasmModule();
  return wasm.removeVerifiedProofHandle(handle);
}

export async function clearVerifiedProofHandles() {
  const wasm = await getWasmModule();
  return wasm.clearVerifiedProofHandles();
}

export async function calculateWithdrawalContext(withdrawal, scope) {
  const wasm = await getWasmModule();
  return wasm.calculateWithdrawalContextJson(JSON.stringify(withdrawal), scope);
}

export async function generateMerkleProof(leaves, leaf) {
  return invokeJson("generateMerkleProofJson", JSON.stringify(leaves), leaf);
}

export async function buildCircuitMerkleWitness(proof, depth) {
  return invokeJson(
    "buildCircuitMerkleWitnessJson",
    JSON.stringify(proof),
    depth,
  );
}

export async function buildWithdrawalCircuitInput(request) {
  return invokeJson(
    "buildWithdrawalCircuitInputJson",
    JSON.stringify(request),
  );
}

export async function buildCommitmentCircuitInput(request) {
  return invokeJson(
    "buildCommitmentCircuitInputJson",
    JSON.stringify(request),
  );
}

export async function checkpointRecovery(events, policy) {
  return invokeJson(
    "checkpointRecoveryJson",
    JSON.stringify(events),
    JSON.stringify(policy),
  );
}

export async function deriveRecoveryKeyset(mnemonic, policy) {
  return invokeJson(
    "deriveRecoveryKeysetJson",
    mnemonic,
    JSON.stringify(policy),
  );
}

export async function recoverAccountState(mnemonic, pools, policy) {
  return invokeJson(
    "recoverAccountStateJson",
    mnemonic,
    JSON.stringify(pools),
    JSON.stringify(policy),
  );
}

export async function recoverAccountStateWithKeyset(keyset, pools, policy) {
  return invokeJson(
    "recoverAccountStateWithKeysetJson",
    JSON.stringify(keyset),
    JSON.stringify(pools),
    JSON.stringify(policy),
  );
}

export async function isCurrentStateRoot(expectedRoot, currentRoot) {
  const wasm = await getWasmModule();
  return wasm.isCurrentStateRoot(String(expectedRoot), String(currentRoot));
}

export async function formatGroth16ProofBundle(proof) {
  return invokeJson(
    "formatGroth16ProofBundleJson",
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function planPoolStateRootRead(poolAddress) {
  return invokeJson("planPoolStateRootReadJson", String(poolAddress));
}

export async function planAspRootRead(entrypointAddress, poolAddress) {
  return invokeJson(
    "planAspRootReadJson",
    String(entrypointAddress),
    String(poolAddress),
  );
}

export async function planWithdrawalTransaction(
  chainId,
  poolAddress,
  withdrawal,
  proof,
) {
  return invokeJson(
    "planWithdrawalTransactionJson",
    BigInt(chainId),
    String(poolAddress),
    JSON.stringify(withdrawal),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function planRelayTransaction(
  chainId,
  entrypointAddress,
  withdrawal,
  proof,
  scope,
) {
  return invokeJson(
    "planRelayTransactionJson",
    BigInt(chainId),
    String(entrypointAddress),
    JSON.stringify(withdrawal),
    JSON.stringify(encodeProofBundle(proof)),
    String(scope),
  );
}

export async function planRagequitTransaction(chainId, poolAddress, proof) {
  return invokeJson(
    "planRagequitTransactionJson",
    BigInt(chainId),
    String(poolAddress),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function planVerifiedWithdrawalTransactionWithHandle(
  chainId,
  poolAddress,
  proofHandle,
) {
  return invokeJson(
    "planVerifiedWithdrawalTransactionWithHandleJson",
    BigInt(chainId),
    String(poolAddress),
    proofHandle,
  );
}

export async function planVerifiedRelayTransactionWithHandle(
  chainId,
  entrypointAddress,
  proofHandle,
) {
  return invokeJson(
    "planVerifiedRelayTransactionWithHandleJson",
    BigInt(chainId),
    String(entrypointAddress),
    proofHandle,
  );
}

export async function planVerifiedRagequitTransactionWithHandle(
  chainId,
  poolAddress,
  proofHandle,
) {
  return invokeJson(
    "planVerifiedRagequitTransactionWithHandleJson",
    BigInt(chainId),
    String(poolAddress),
    proofHandle,
  );
}

export async function preflightVerifiedWithdrawalTransactionWithHandle(
  chainId,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) {
  const plan = await planVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );
  const preflight = await preflightBrowserTransaction({
    plan,
    rpcUrl,
    policy,
    poolAddress,
    expectedStateRoot: plan.proof.pubSignals[3],
    expectedAspRoot: plan.proof.pubSignals[5],
  });
  return registerVerifiedPreflightedTransaction("withdrawal", {
    proofHandle,
    poolAddress,
    plan,
    preflight,
  });
}

export async function preflightVerifiedRelayTransactionWithHandle(
  chainId,
  entrypointAddress,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) {
  const plan = await planVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    proofHandle,
  );
  const preflight = await preflightBrowserTransaction({
    plan,
    rpcUrl,
    policy,
    poolAddress,
    entrypointAddress,
    expectedStateRoot: plan.proof.pubSignals[3],
    expectedAspRoot: plan.proof.pubSignals[5],
  });
  return registerVerifiedPreflightedTransaction("relay", {
    proofHandle,
    entrypointAddress,
    poolAddress,
    plan,
    preflight,
  });
}

export async function preflightVerifiedRagequitTransactionWithHandle(
  chainId,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) {
  const plan = await planVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );
  const preflight = await preflightBrowserTransaction({
    plan,
    rpcUrl,
    policy,
    poolAddress,
  });
  return registerVerifiedPreflightedTransaction("ragequit", {
    proofHandle,
    poolAddress,
    plan,
    preflight,
  });
}

export async function finalizePreflightedTransactionHandle(
  rpcUrl,
  preflightedHandle,
) {
  const wasm = await getWasmModule();
  const preflighted = JSON.parse(
    wasm.dangerouslyExportPreflightedTransaction(preflightedHandle),
  );
  const refreshed = await reconfirmBrowserPreflight(preflighted, rpcUrl);
  const refreshedHandle = await registerReconfirmedPreflightedTransaction(
    preflightedHandle,
    refreshed,
  );
  const client = await createBrowserPublicClient(rpcUrl);
  const request = await finalizeBrowserTransactionRequest(
    preflighted.transaction,
    refreshed,
    client,
  );
  return wasm.registerFinalizedPreflightedTransactionJson(
    refreshedHandle,
    JSON.stringify(request),
  );
}

export async function submitPreflightedTransactionHandle() {
  throw new Error(
    "submitPreflightedTransactionHandle requires a signer; browser builds support finalizePreflightedTransactionHandle plus submitFinalizedPreflightedTransactionHandle with an externally signed transaction",
  );
}

export async function submitFinalizedPreflightedTransactionHandle(
  rpcUrl,
  finalizedHandle,
  signedTransaction,
) {
  const wasm = await getWasmModule();
  const finalized = JSON.parse(
    wasm.dangerouslyExportFinalizedPreflightedTransaction(finalizedHandle),
  );
  const refreshed = await reconfirmBrowserPreflight(finalized.preflighted, rpcUrl);
  const client = await createBrowserPublicClient(rpcUrl);
  const hash = await client.sendRawTransaction({
    serializedTransaction: normalizeHex(signedTransaction),
  });
  const receipt = await client.waitForTransactionReceipt({ hash });
  return wasm.registerSubmittedPreflightedTransactionJson(
    finalizedHandle,
    JSON.stringify(refreshed),
    JSON.stringify(toBrowserReceiptSummary(receipt)),
  );
}

export async function dangerouslyExportPreflightedTransaction(handle) {
  return invokeJson("dangerouslyExportPreflightedTransaction", handle);
}

export async function dangerouslyExportFinalizedPreflightedTransaction(handle) {
  return invokeJson("dangerouslyExportFinalizedPreflightedTransaction", handle);
}

export async function dangerouslyExportSubmittedPreflightedTransaction(handle) {
  return invokeJson("dangerouslyExportSubmittedPreflightedTransaction", handle);
}

export async function removeExecutionHandle(handle) {
  const wasm = await getWasmModule();
  return wasm.removeExecutionHandle(handle);
}

export async function clearExecutionHandles() {
  const wasm = await getWasmModule();
  return wasm.clearExecutionHandles();
}

export async function verifyArtifactBytes(manifestJson, circuit, artifacts) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  return JSON.parse(
    wasm.verifyArtifactBytes(manifestJson, circuit, normalizedArtifacts),
  );
}

export async function verifySignedManifest(payloadJson, signatureHex, publicKeyHex) {
  return invokeJson(
    "verifySignedManifest",
    payloadJson,
    signatureHex,
    publicKeyHex,
  );
}

export async function verifySignedManifestArtifacts(
  payloadJson,
  signatureHex,
  publicKeyHex,
  artifacts,
) {
  const wasm = await getWasmModule();
  return JSON.parse(
    wasm.verifySignedManifestArtifactsJson(
      payloadJson,
      signatureHex,
      publicKeyHex,
      JSON.stringify(encodeSignedManifestArtifactBytes(artifacts)),
    ),
  );
}

export async function getArtifactStatuses(manifestJson, artifactsRoot) {
  return getArtifactStatusesForCircuit(manifestJson, artifactsRoot, "withdraw");
}

export async function getCommitmentArtifactStatuses(manifestJson, artifactsRoot) {
  return getArtifactStatusesForCircuit(manifestJson, artifactsRoot, "commitment");
}

async function getArtifactStatusesForCircuit(manifestJson, artifactsRoot, circuit) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const verifiedKinds = new Set();

  if (fetchedArtifacts.every((artifact) => artifact.exists)) {
    try {
      const verifiedBundle = await verifyArtifactBytes(
        manifestJson,
        circuit,
        fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
      );
      for (const artifact of verifiedBundle.artifacts) {
        verifiedKinds.add(artifact.kind);
      }
    } catch {
      // Fail closed: fetched artifacts remain unverified unless the full bundle verifies.
    }
  }

  return fetchedArtifacts.map((artifact) => ({
    version: manifest.version,
    circuit: artifact.circuit,
    kind: artifact.kind,
    filename: artifact.filename,
    path: artifact.path,
    exists: artifact.exists,
    verified: artifact.exists && verifiedKinds.has(artifact.kind),
  }));
}

export async function resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
  return resolveVerifiedArtifactBundleForCircuit(manifestJson, artifactsRoot, "withdraw");
}

export async function resolveVerifiedCommitmentArtifactBundle(
  manifestJson,
  artifactsRoot,
) {
  return resolveVerifiedArtifactBundleForCircuit(
    manifestJson,
    artifactsRoot,
    "commitment",
  );
}

async function resolveVerifiedArtifactBundleForCircuit(
  manifestJson,
  artifactsRoot,
  circuit,
) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const bundle = await verifyArtifactBytes(
    manifestJson,
    circuit,
    fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
  );
  const urlsByKind = new Map(
    fetchedArtifacts.map((artifact) => [artifact.kind, artifact.path]),
  );

  return {
    version: bundle.version,
    circuit: bundle.circuit,
    artifacts: bundle.artifacts.map((artifact) => ({
      circuit: artifact.circuit,
      kind: artifact.kind,
      filename: artifact.filename,
      path: urlsByKind.get(artifact.kind) ?? "",
    })),
  };
}

export async function prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
  return prepareCircuitSession(manifestJson, artifactsRoot, "withdraw");
}

export async function prepareCommitmentCircuitSession(manifestJson, artifactsRoot) {
  return prepareCircuitSession(manifestJson, artifactsRoot, "commitment");
}

async function prepareCircuitSession(manifestJson, artifactsRoot, circuit) {
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, circuit);
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  const methodName =
    circuit === "commitment"
      ? "prepareCommitmentCircuitSessionFromBytes"
      : "prepareWithdrawalCircuitSessionFromBytes";
  const normalizedArtifacts = fetchedArtifacts.map(({ kind, bytes }) => ({
    kind,
    bytes,
  }));
  const session = JSON.parse(
    wasm[methodName](
      manifestJson,
      normalizeArtifactInputs(normalizedArtifacts),
    ),
  );
  await rememberSessionArtifacts(wasm, session, normalizedArtifacts);
  return session;
}

export async function prepareWithdrawalCircuitSessionFromBytes(
  manifestJson,
  artifacts,
) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  const session = JSON.parse(
    wasm.prepareWithdrawalCircuitSessionFromBytes(
      manifestJson,
      normalizedArtifacts,
    ),
  );
  await rememberSessionArtifacts(wasm, session, normalizedArtifacts);
  return session;
}

export async function prepareCommitmentCircuitSessionFromBytes(
  manifestJson,
  artifacts,
) {
  const wasm = await getWasmModule();
  const normalizedArtifacts = normalizeArtifactInputs(artifacts);
  const session = JSON.parse(
    wasm.prepareCommitmentCircuitSessionFromBytes(
      manifestJson,
      normalizedArtifacts,
    ),
  );
  await rememberSessionArtifacts(wasm, session, normalizedArtifacts);
  return session;
}

export async function removeWithdrawalCircuitSession(sessionHandle) {
  const wasm = await getWasmModule();
  const removed = wasm.removeWithdrawalCircuitSession(sessionHandle);
  if (removed) {
    browserSessionArtifacts.delete(sessionHandle);
  }
  return removed;
}

export async function removeCommitmentCircuitSession(sessionHandle) {
  const wasm = await getWasmModule();
  const removed = wasm.removeCommitmentCircuitSession(sessionHandle);
  if (removed) {
    browserSessionArtifacts.delete(sessionHandle);
  }
  return removed;
}

export async function clearBrowserCircuitSessionCache() {
  const wasm = await getWasmModule();
  await browserSessionArtifacts.clear(wasm);
}

export async function proveWithdrawal(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "withdraw" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "withdraw");
  try {
    return await proveWithdrawalWithPreparedSession(
      session.handle,
      request,
      status,
      false,
      false,
    );
  } finally {
    await removeWithdrawalCircuitSession(session.handle);
  }
}

export async function proveWithdrawalWithSession(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  return proveWithdrawalWithPreparedSession(
    sessionHandle,
    request,
    status,
    true,
    false,
  );
}

export async function proveWithdrawalBinary(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "withdraw" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "withdraw");
  try {
    return await proveWithdrawalWithPreparedSession(
      session.handle,
      request,
      status,
      false,
      true,
    );
  } finally {
    await removeWithdrawalCircuitSession(session.handle);
  }
}

export async function proveWithdrawalWithSessionBinary(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  return proveWithdrawalWithPreparedSession(
    sessionHandle,
    request,
    status,
    true,
    true,
  );
}

async function proveWithdrawalWithPreparedSession(
  sessionHandle,
  request,
  status,
  emitPreload,
  useBinaryWitness,
) {
  if (emitPreload) {
    emitStatus(status, { stage: "preload", circuit: "withdraw" });
  }
  const sessionArtifacts = getSessionArtifacts(sessionHandle, "withdraw");
  const witnessInput = await buildWithdrawalWitnessInput(request);
  return proveWithdrawalWithPreparedWitnessInput(
    sessionHandle,
    witnessInput,
    status,
    false,
    useBinaryWitness,
    sessionArtifacts,
  );
}

async function proveWithdrawalWithPreparedWitnessInput(
  sessionHandle,
  witnessInput,
  status,
  emitPreload,
  useBinaryWitness,
  sessionArtifacts = getSessionArtifacts(sessionHandle, "withdraw"),
) {
  if (emitPreload) {
    emitStatus(status, { stage: "preload", circuit: "withdraw" });
  }
  const supportsBinaryWitness =
    useBinaryWitness &&
    typeof (await getWasmModule()).proveWithdrawalWithSessionWitnessBinary === "function";
  const witness = supportsBinaryWitness
    ? await calculateCircuitWitnessBinary(
        sessionArtifacts,
        witnessInput,
        (payload) => emitStatus(status, { circuit: "withdraw", ...payload }),
      )
    : await calculateCircuitWitness(
        sessionArtifacts,
        witnessInput,
        (payload) => emitStatus(status, { circuit: "withdraw", ...payload }),
      );
  emitStatus(status, { stage: "prove", circuit: "withdraw" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    supportsBinaryWitness
      ? wasm.proveWithdrawalWithSessionWitnessBinary(sessionHandle, witness)
      : wasm.proveWithdrawalWithSessionWitnessJson(
          sessionHandle,
          JSON.stringify(witness),
        ),
  );
  emitStatus(status, { stage: "verify", circuit: "withdraw" });
  emitStatus(status, { stage: "done", circuit: "withdraw" });
  return proving;
}

export async function verifyWithdrawalProof(
  backendProfile,
  manifestJson,
  artifactsRoot,
  proof,
) {
  assertStableBackend(backendProfile);
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "withdraw");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProof(
    manifestJson,
    normalizeArtifactInputs(
      fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
    ),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function proveCommitment(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "commitment" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "commitment");
  try {
    return await proveCommitmentWithPreparedSession(
      session.handle,
      request,
      status,
      false,
      false,
    );
  } finally {
    await removeCommitmentCircuitSession(session.handle);
  }
}

export async function proveCommitmentWithSession(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  return proveCommitmentWithPreparedSession(
    sessionHandle,
    request,
    status,
    true,
    false,
  );
}

export async function proveCommitmentBinary(
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  emitStatus(status, { stage: "preload", circuit: "commitment" });
  const session = await prepareCircuitSession(manifestJson, artifactsRoot, "commitment");
  try {
    return await proveCommitmentWithPreparedSession(
      session.handle,
      request,
      status,
      false,
      true,
    );
  } finally {
    await removeCommitmentCircuitSession(session.handle);
  }
}

export async function proveCommitmentWithSessionBinary(
  backendProfile,
  sessionHandle,
  request,
  status,
) {
  assertStableBackend(backendProfile);
  return proveCommitmentWithPreparedSession(
    sessionHandle,
    request,
    status,
    true,
    true,
  );
}

async function proveCommitmentWithPreparedSession(
  sessionHandle,
  request,
  status,
  emitPreload,
  useBinaryWitness,
) {
  if (emitPreload) {
    emitStatus(status, { stage: "preload", circuit: "commitment" });
  }
  const sessionArtifacts = getSessionArtifacts(sessionHandle, "commitment");
  const witnessInput = await buildCommitmentWitnessInput(request);
  return proveCommitmentWithPreparedWitnessInput(
    sessionHandle,
    witnessInput,
    status,
    false,
    useBinaryWitness,
    sessionArtifacts,
  );
}

async function proveCommitmentWithPreparedWitnessInput(
  sessionHandle,
  witnessInput,
  status,
  emitPreload,
  useBinaryWitness,
  sessionArtifacts = getSessionArtifacts(sessionHandle, "commitment"),
) {
  if (emitPreload) {
    emitStatus(status, { stage: "preload", circuit: "commitment" });
  }
  const supportsBinaryWitness =
    useBinaryWitness &&
    typeof (await getWasmModule()).proveCommitmentWithSessionWitnessBinary === "function";
  const witness = supportsBinaryWitness
    ? await calculateCircuitWitnessBinary(
        sessionArtifacts,
        witnessInput,
        (payload) => emitStatus(status, { circuit: "commitment", ...payload }),
      )
    : await calculateCircuitWitness(
        sessionArtifacts,
        witnessInput,
        (payload) => emitStatus(status, { circuit: "commitment", ...payload }),
      );
  emitStatus(status, { stage: "prove", circuit: "commitment" });
  const wasm = await getWasmModule();
  const proving = JSON.parse(
    supportsBinaryWitness
      ? wasm.proveCommitmentWithSessionWitnessBinary(sessionHandle, witness)
      : wasm.proveCommitmentWithSessionWitnessJson(
          sessionHandle,
          JSON.stringify(witness),
        ),
  );
  emitStatus(status, { stage: "verify", circuit: "commitment" });
  emitStatus(status, { stage: "done", circuit: "commitment" });
  return proving;
}

export async function verifyCommitmentProof(
  backendProfile,
  manifestJson,
  artifactsRoot,
  proof,
) {
  assertStableBackend(backendProfile);
  const manifest = parseManifest(manifestJson);
  const fetchedArtifacts = await fetchArtifactInputs(manifest, artifactsRoot, "commitment");
  const missingArtifact = fetchedArtifacts.find((artifact) => !artifact.exists);
  if (missingArtifact) {
    throw new Error(`missing browser artifact: ${missingArtifact.path}`);
  }

  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProof(
    manifestJson,
    normalizeArtifactInputs(
      fetchedArtifacts.map(({ kind, bytes }) => ({ kind, bytes })),
    ),
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function verifyCommitmentProofWithSession(
  backendProfile,
  sessionHandle,
  proof,
) {
  assertStableBackend(backendProfile);
  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProofWithSession(
    sessionHandle,
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function verifyWithdrawalProofWithSession(
  backendProfile,
  sessionHandle,
  proof,
) {
  assertStableBackend(backendProfile);
  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProofWithSession(
    sessionHandle,
    JSON.stringify(encodeProofBundle(proof)),
  );
}

export async function proveAndVerifyCommitmentHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  status,
) {
  const proving = await proveCommitmentWithHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    status,
  );
  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProofForHandleJson(
    JSON.stringify(encodeProofBundle(proving.proof)),
    commitmentHandle,
  );
}

export async function proveAndVerifyWithdrawalHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
  status,
) {
  const proving = await proveWithdrawalWithHandles(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    withdrawal,
    scope,
    withdrawalAmount,
    stateWitness,
    aspWitness,
    newSecretsHandle,
    status,
  );
  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProofForHandlesJson(
    JSON.stringify(encodeProofBundle(proving.proof)),
    commitmentHandle,
    JSON.stringify(withdrawal),
    String(scope),
    String(withdrawalAmount),
    JSON.stringify(stateWitness),
    JSON.stringify(aspWitness),
    newSecretsHandle,
  );
}

export async function verifyCommitmentProofForRequestHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  proof,
) {
  const verified = await verifyCommitmentProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  );
  if (!verified) {
    throw new Error("commitment proof verification failed");
  }
  const wasm = await getWasmModule();
  return wasm.verifyCommitmentProofForHandleJson(
    JSON.stringify(encodeProofBundle(proof)),
    commitmentHandle,
  );
}

export async function verifyRagequitProofForRequestHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  proof,
) {
  const verified = await verifyCommitmentProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  );
  if (!verified) {
    throw new Error("ragequit proof verification failed");
  }
  const wasm = await getWasmModule();
  return wasm.verifyRagequitProofForHandleJson(
    JSON.stringify(encodeProofBundle(proof)),
    commitmentHandle,
  );
}

export async function verifyWithdrawalProofForRequestHandle(
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
  proof,
) {
  const verified = await verifyWithdrawalProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  );
  if (!verified) {
    throw new Error("withdrawal proof verification failed");
  }
  const wasm = await getWasmModule();
  return wasm.verifyWithdrawalProofForHandlesJson(
    JSON.stringify(encodeProofBundle(proof)),
    commitmentHandle,
    JSON.stringify(withdrawal),
    String(scope),
    String(withdrawalAmount),
    JSON.stringify(stateWitness),
    JSON.stringify(aspWitness),
    newSecretsHandle,
  );
}

export async function __buildWithdrawalWitnessBinaryForTests(sessionHandle, request) {
  const sessionArtifacts = getSessionArtifacts(sessionHandle, "withdraw");
  const witnessInput = await buildWithdrawalWitnessInput(request);
  return calculateCircuitWitnessBinary(sessionArtifacts, witnessInput);
}

export async function __proveWithdrawalSessionWitnessBinaryForTests(
  sessionHandle,
  witness,
) {
  const wasm = await getWasmModule();
  return JSON.parse(wasm.proveWithdrawalWithSessionWitnessBinary(sessionHandle, witness));
}

async function buildWithdrawalWitnessInput(request) {
  const wasm = await getWasmModule();
  return wasm.buildWithdrawalWitnessInputJson(JSON.stringify(request));
}

async function buildWithdrawalWitnessInputFromHandles(
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
) {
  const wasm = await getWasmModule();
  return wasm.buildWithdrawalWitnessInputFromHandlesJson(
    commitmentHandle,
    JSON.stringify(withdrawal),
    String(scope),
    String(withdrawalAmount),
    JSON.stringify(stateWitness),
    JSON.stringify(aspWitness),
    newSecretsHandle,
  );
}

async function buildCommitmentWitnessInput(request) {
  const wasm = await getWasmModule();
  return wasm.buildCommitmentWitnessInputJson(JSON.stringify(request));
}

async function buildCommitmentWitnessInputFromHandle(commitmentHandle) {
  const wasm = await getWasmModule();
  return wasm.buildCommitmentWitnessInputFromHandleJson(commitmentHandle);
}

async function rememberSessionArtifacts(wasm, session, artifacts) {
  const wasmArtifact = artifacts.find((artifact) => artifact.kind === "wasm");
  if (!wasmArtifact) {
    browserSessionArtifacts.delete(session.handle);
    return;
  }

  await browserSessionArtifacts.remember(wasm, session.handle, {
    circuit: session.circuit,
    wasmBytes: toUint8Array(wasmArtifact.bytes),
  });
}

function getSessionArtifacts(sessionHandle, expectedCircuit) {
  const artifacts = browserSessionArtifacts.get(sessionHandle, expectedCircuit);
  if (!artifacts) {
    throw new Error(
      `browser ${expectedCircuit} circuit session \`${sessionHandle}\` is not proof-capable`,
    );
  }
  if (artifacts.circuit !== expectedCircuit) {
    throw new Error(
      `browser session \`${sessionHandle}\` is for circuit \`${artifacts.circuit}\``,
    );
  }
  return artifacts;
}

class BrowserSessionArtifactCache {
  #capacity;
  #entries = new Map();

  constructor(capacity) {
    this.#capacity = capacity;
  }

  get(sessionHandle, expectedCircuit) {
    const artifacts = this.#entries.get(sessionHandle);
    if (!artifacts) {
      return undefined;
    }

    if (artifacts.circuit === expectedCircuit) {
      this.#entries.delete(sessionHandle);
      this.#entries.set(sessionHandle, artifacts);
    }
    return artifacts;
  }

  delete(sessionHandle) {
    return this.#entries.delete(sessionHandle);
  }

  async remember(wasm, sessionHandle, artifacts) {
    this.#entries.delete(sessionHandle);
    this.#entries.set(sessionHandle, {
      ...artifacts,
      witnessModulePromise: compileWitnessModule(artifacts.wasmBytes),
      witnessRuntimeExports: null,
      witnessRuntimeMode: "probe",
    });
    await this.#evictOverflow(wasm);
  }

  async clear(wasm) {
    const entries = [...this.#entries.entries()];
    this.#entries.clear();
    await Promise.all(
      entries.map(([sessionHandle, artifacts]) =>
        removeBrowserCircuitSession(wasm, sessionHandle, artifacts.circuit),
      ),
    );
  }

  async #evictOverflow(wasm) {
    while (this.#entries.size > this.#capacity) {
      const [sessionHandle, artifacts] = this.#entries.entries().next().value;
      this.#entries.delete(sessionHandle);
      await removeBrowserCircuitSession(wasm, sessionHandle, artifacts.circuit);
    }
  }
}

function removeBrowserCircuitSession(wasm, sessionHandle, circuit) {
  if (circuit === "commitment") {
    return wasm.removeCommitmentCircuitSession(sessionHandle);
  }
  return wasm.removeWithdrawalCircuitSession(sessionHandle);
}

const browserSessionArtifacts = new BrowserSessionArtifactCache(
  DEFAULT_BROWSER_SESSION_ARTIFACT_CACHE_CAPACITY,
);

async function getWasmModule() {
  if (!wasmModulePromise) {
    wasmModuleFlavor = "stable";
    wasmModulePromise = initializeWasmModule().catch((error) => {
      wasmModulePromise = null;
      wasmModuleFlavor = null;
      throw error;
    });
  }

  return wasmModulePromise;
}

function compileWitnessModule(wasmBytes) {
  return WebAssembly.compile(toUint8Array(wasmBytes));
}

async function getWitnessModule(sessionArtifacts) {
  if (!sessionArtifacts.witnessModulePromise) {
    sessionArtifacts.witnessModulePromise = compileWitnessModule(
      sessionArtifacts.wasmBytes,
    );
  }

  return sessionArtifacts.witnessModulePromise;
}

async function initializeWasmModule(options = {}) {
  const experimentalThreaded = options.experimentalThreaded === true;
  const wasmModule = experimentalThreaded
    ? await import("./generated-threaded/privacy_pools_sdk_web_threaded.js")
    : await import("./generated/privacy_pools_sdk_web.js");
  const init = wasmModule.default;
  const wasmUrl = new URL(
    experimentalThreaded
      ? "./generated-threaded/privacy_pools_sdk_web_threaded_bg.wasm"
      : "./generated/privacy_pools_sdk_web_bg.wasm",
    import.meta.url,
  );

  if (typeof process !== "undefined" && process.versions?.node && typeof document === "undefined") {
    const { readFile } = await import("node:fs/promises");
    const wasmBytes = await readFile(wasmUrl);
    await init({ module_or_path: wasmBytes });
  } else {
    await init({ module_or_path: wasmUrl });
  }

  if (experimentalThreaded) {
    if (typeof wasmModule.initThreadPool !== "function") {
      throw new Error("experimental threaded WASM artifact does not expose initThreadPool");
    }
    await wasmModule.initThreadPool(normalizeThreadCount(options.threadCount));
  }

  return wasmModule;
}

function normalizeThreadCount(threadCount) {
  const requested =
    threadCount ??
    (typeof navigator !== "undefined" ? navigator.hardwareConcurrency : undefined) ??
    2;
  const count = Math.floor(Number(requested));
  return Number.isFinite(count) && count > 0 ? count : 1;
}

async function invokeJson(methodName, ...args) {
  const wasm = await getWasmModule();
  return JSON.parse(wasm[methodName](...args));
}

function parseManifest(manifestJson) {
  const manifest = JSON.parse(manifestJson);
  if (!manifest || typeof manifest !== "object" || !Array.isArray(manifest.artifacts)) {
    throw new TypeError("manifestJson must describe an artifact manifest");
  }
  return manifest;
}

function assertStableBackend(backendProfile) {
  if (backendProfile === "stable") {
    return;
  }

  throw new BrowserRuntimeUnavailableError(
    "Browser proving and verification currently support only the stable backend.",
  );
}

async function masterKeysHandleFor(wasm, value) {
  if (typeof value === "string") {
    return { handle: value, temporary: false };
  }

  return {
    handle: wasm.importMasterKeysHandleJson(JSON.stringify(value)),
    temporary: true,
  };
}

async function calculateCircuitWitness(sessionArtifacts, inputJson, status) {
  return calculateCircuitWitnessWithResetGate(
    sessionArtifacts,
    inputJson,
    status,
    false,
  );
}

async function calculateCircuitWitnessBinary(sessionArtifacts, inputJson, status) {
  return calculateCircuitWitnessWithResetGate(
    sessionArtifacts,
    inputJson,
    status,
    true,
  );
}

async function calculateCircuitWitnessWithResetGate(
  sessionArtifacts,
  inputJson,
  status,
  binary,
) {
  // Host the manifest-pinned Circom witness artifact; protocol shaping stays in Rust/WASM.
  emitStatus(status, { stage: "witness" });
  if (
    sessionArtifacts.witnessRuntimeMode === "reuse" &&
    sessionArtifacts.witnessRuntimeExports
  ) {
    return runWitnessRuntime(
      sessionArtifacts.witnessRuntimeExports,
      inputJson,
      status,
      binary,
      "reuse",
    );
  }

  if (sessionArtifacts.witnessRuntimeMode === "fallback") {
    const runtimeExports = await instantiateWitnessRuntime(sessionArtifacts);
    return runWitnessRuntime(runtimeExports, inputJson, status, binary, "fallback");
  }

  const runtimeExports = await instantiateWitnessRuntime(sessionArtifacts);
  if (witnessResetProbeOverrideForTests === "fallback") {
    runWitnessRuntime(runtimeExports, inputJson, undefined, binary);
    sessionArtifacts.witnessRuntimeMode = "fallback";
    sessionArtifacts.witnessRuntimeExports = null;
    const fallbackExports = await instantiateWitnessRuntime(sessionArtifacts);
    return runWitnessRuntime(fallbackExports, inputJson, status, binary, "fallback");
  }

  const first = runWitnessRuntime(runtimeExports, inputJson, undefined, binary);
  const second = runWitnessRuntime(
    runtimeExports,
    inputJson,
    status,
    binary,
    "probe-reuse",
  );
  if (witnessesEqual(first, second, binary)) {
    sessionArtifacts.witnessRuntimeMode = "reuse";
    sessionArtifacts.witnessRuntimeExports = runtimeExports;
    return second;
  }

  sessionArtifacts.witnessRuntimeMode = "fallback";
  sessionArtifacts.witnessRuntimeExports = null;
  const fallbackExports = await instantiateWitnessRuntime(sessionArtifacts);
  return runWitnessRuntime(fallbackExports, inputJson, status, binary, "fallback");
}

async function instantiateWitnessRuntime(sessionArtifacts) {
  const module = await getWitnessModule(sessionArtifacts);
  const imports = {
    runtime: {
      exceptionHandler(code) {
        throw new Error(`circuit witness exception: ${code}`);
      },
      printErrorMessage() {},
      writeBufferMessage() {},
      showSharedRWMemory() {},
    },
  };
  const instance = await WebAssembly.instantiate(module, imports);
  return instance.instance?.exports ?? instance.exports;
}

function runWitnessRuntime(exports, inputJson, status, binary, witnessRuntime) {
  const n32 = Number(exports.getFieldNumLen32());
  if (binary && n32 !== BINARY_WITNESS_LIMBS_PER_FIELD) {
    throw new Error(
      `binary witness path expected ${BINARY_WITNESS_LIMBS_PER_FIELD} limbs per field but circuit reports ${n32}`,
    );
  }

  exports.init(0);

  const input = JSON.parse(inputJson);
  if (binary) {
    emitStatus(status, { stage: "witness-parse" });
  }
  for (const [name, values] of Object.entries(input)) {
    const [msb, lsb] = fnv64Parts(name);
    values.forEach((value, index) => {
      const limbs = toArray32(BigInt(value), n32);
      for (let cursor = 0; cursor < n32; cursor += 1) {
        exports.writeSharedRWMemory(cursor, limbs[n32 - 1 - cursor]);
      }
      exports.setInputSignal(msb, lsb, index);
    });
  }
  if (binary) {
    emitStatus(status, { stage: "witness-transfer" });
  }

  const witnessSize = Number(exports.getWitnessSize());
  const witness = binary ? new Uint32Array(witnessSize * n32) : [];
  if (binary) {
    for (let index = 0; index < witnessSize; index += 1) {
      exports.getWitness(index);
      for (let cursor = 0; cursor < n32; cursor += 1) {
        witness[index * n32 + cursor] = Number(exports.readSharedRWMemory(cursor));
      }
    }
  } else {
    for (let index = 0; index < witnessSize; index += 1) {
      exports.getWitness(index);
      const limbs = [];
      for (let cursor = 0; cursor < n32; cursor += 1) {
        limbs[n32 - 1 - cursor] = Number(exports.readSharedRWMemory(cursor));
      }
      witness.push(fromArray32(limbs).toString());
    }
  }
  emitStatus(status, {
    stage: "witness",
    witnessSize,
    ...(witnessRuntime ? { witnessRuntime } : {}),
  });
  return witness;
}

function witnessesEqual(left, right, binary) {
  if (left.length !== right.length) {
    return false;
  }

  for (let index = 0; index < left.length; index += 1) {
    const leftValue = binary ? left[index] : String(left[index]);
    const rightValue = binary ? right[index] : String(right[index]);
    if (leftValue !== rightValue) {
      return false;
    }
  }

  return true;
}

function fnv64Parts(value) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  const bytes = new TextEncoder().encode(value);
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * prime) & mask;
  }
  return [
    Number((hash >> 32n) & 0xffffffffn),
    Number(hash & 0xffffffffn),
  ];
}

function toArray32(value, size) {
  const limbs = Array(size).fill(0);
  let remaining = value;
  const radix = 0x100000000n;
  let cursor = size;
  while (remaining !== 0n) {
    cursor -= 1;
    if (cursor < 0) {
      throw new Error("circuit input value exceeds field limb width");
    }
    limbs[cursor] = Number(remaining % radix);
    remaining /= radix;
  }
  return limbs;
}

function fromArray32(limbs) {
  const radix = 0x100000000n;
  let value = 0n;
  for (const limb of limbs) {
    value = value * radix + BigInt(limb >>> 0);
  }
  return value;
}

async function registerVerifiedPreflightedTransaction(kind, options) {
  const wasm = await getWasmModule();
  const planJson = JSON.stringify(options.plan);
  const preflightJson = JSON.stringify(options.preflight);
  if (kind === "withdrawal") {
    return wasm.registerVerifiedWithdrawalPreflightedTransactionJson(
      options.proofHandle,
      String(options.poolAddress),
      planJson,
      preflightJson,
    );
  }
  if (kind === "relay") {
    return wasm.registerVerifiedRelayPreflightedTransactionJson(
      options.proofHandle,
      String(options.entrypointAddress),
      String(options.poolAddress),
      planJson,
      preflightJson,
    );
  }
  if (kind === "ragequit") {
    return wasm.registerVerifiedRagequitPreflightedTransactionJson(
      options.proofHandle,
      String(options.poolAddress),
      planJson,
      preflightJson,
    );
  }
  throw new Error(`unsupported preflighted transaction kind: ${kind}`);
}

async function registerReconfirmedPreflightedTransaction(preflightedHandle, preflight) {
  const wasm = await getWasmModule();
  return wasm.registerReconfirmedPreflightedTransactionJson(
    preflightedHandle,
    JSON.stringify(preflight),
  );
}

async function preflightBrowserTransaction({
  plan,
  rpcUrl,
  policy,
  poolAddress,
  entrypointAddress,
  expectedStateRoot,
  expectedAspRoot,
}) {
  const client = await createBrowserPublicClient(rpcUrl);
  const normalizedPolicy = normalizeExecutionPolicy(policy, plan);
  const actualChainId = Number(await client.getChainId());
  if (actualChainId !== normalizedPolicy.expectedChainId) {
    throw new Error(
      `live chain id mismatch: expected ${normalizedPolicy.expectedChainId}, got ${actualChainId}`,
    );
  }

  const kind = plan.kind;
  const pool = normalizeAddress(poolAddress ?? (kind === "relay" ? "" : plan.target));
  let entrypoint = entrypointAddress ? normalizeAddress(entrypointAddress) : null;
  if (kind === "withdraw") {
    entrypoint = await readPoolEntrypointAddress(client, pool);
  } else if (kind === "relay") {
    const actualEntrypoint = await readPoolEntrypointAddress(client, pool);
    if (normalizeAddress(actualEntrypoint) !== normalizeAddress(entrypoint)) {
      throw new Error(
        `pool entrypoint mismatch for ${pool}: expected ${entrypoint}, got ${actualEntrypoint}`,
      );
    }
  }

  const codeHashChecks = [];
  const codeExpectations =
    kind === "ragequit"
      ? [[pool, normalizedPolicy.expectedPoolCodeHash]]
      : [
          [pool, normalizedPolicy.expectedPoolCodeHash],
          [entrypoint, normalizedPolicy.expectedEntrypointCodeHash],
        ];
  for (const [address, expectedCodeHash] of codeExpectations) {
    if (!expectedCodeHash && normalizedPolicy.mode !== "insecure_dev") {
      throw new Error(`missing required code hash expectation for contract at ${address}`);
    }
    const actualCodeHash = await codeHash(client, address);
    if (
      expectedCodeHash &&
      normalizeHex(expectedCodeHash).toLowerCase() !== actualCodeHash.toLowerCase()
    ) {
      throw new Error(
        `contract code hash mismatch at ${address}: expected ${expectedCodeHash}, got ${actualCodeHash}`,
      );
    }
    codeHashChecks.push({
      address,
      expectedCodeHash: expectedCodeHash ?? null,
      actualCodeHash,
      matchesExpected: expectedCodeHash ? true : null,
    });
  }

  const rootChecks = [];
  if (kind !== "ragequit") {
    const stateRoot = stringifyField(expectedStateRoot);
    const actualStateRoot = await verifyKnownPoolRoot(client, pool, stateRoot);
    rootChecks.push({
      kind: "pool_state",
      contractAddress: pool,
      poolAddress: pool,
      expectedRoot: stateRoot,
      actualRoot: actualStateRoot,
      matches: true,
    });

    const aspRoot = stringifyField(expectedAspRoot);
    const actualAspRoot = (await client.readContract({
      address: entrypoint,
      abi: ENTRYPOINT_ABI,
      functionName: "latestRoot",
    })).toString();
    if (actualAspRoot !== aspRoot) {
      throw new Error(`asp root mismatch: expected ${aspRoot}, got ${actualAspRoot}`);
    }
    rootChecks.push({
      kind: "asp",
      contractAddress: entrypoint,
      poolAddress: pool,
      expectedRoot: aspRoot,
      actualRoot: actualAspRoot,
      matches: true,
    });
  }

  const estimatedGas = await client.estimateGas({
    account: normalizeAddress(normalizedPolicy.caller),
    to: normalizeAddress(plan.target),
    data: normalizeHex(plan.calldata),
    value: BigInt(plan.value ?? "0"),
  });

  return {
    kind,
    caller: normalizeAddress(normalizedPolicy.caller),
    target: normalizeAddress(plan.target),
    expectedChainId: normalizedPolicy.expectedChainId,
    actualChainId,
    chainIdMatches: true,
    simulated: true,
    estimatedGas: Number(estimatedGas),
    mode: normalizedPolicy.mode,
    codeHashChecks,
    rootChecks,
  };
}

async function reconfirmBrowserPreflight(preflighted, rpcUrl) {
  const { transaction, preflight } = preflighted;
  const poolRootCheck = preflight.rootChecks.find(
    (check) => check.kind === "pool_state",
  );
  const aspRootCheck = preflight.rootChecks.find((check) => check.kind === "asp");
  const poolAddress =
    poolRootCheck?.poolAddress ??
    (transaction.kind === "relay" ? undefined : transaction.target);
  const poolCodeHashCheck = preflight.codeHashChecks.find(
    (check) => normalizeAddress(check.address) === normalizeAddress(poolAddress),
  );
  const entrypointCodeHashCheck = preflight.codeHashChecks.find(
    (check) => normalizeAddress(check.address) !== normalizeAddress(poolAddress),
  );
  return preflightBrowserTransaction({
    plan: transaction,
    rpcUrl,
    policy: {
      expectedChainId: preflight.expectedChainId,
      caller: preflight.caller,
      expectedPoolCodeHash: poolCodeHashCheck?.expectedCodeHash ?? null,
      expectedEntrypointCodeHash: entrypointCodeHashCheck?.expectedCodeHash ?? null,
      mode: preflight.mode ?? "strict",
    },
    poolAddress,
    entrypointAddress: transaction.kind === "relay" ? transaction.target : undefined,
    expectedStateRoot: poolRootCheck?.expectedRoot,
    expectedAspRoot: aspRootCheck?.expectedRoot,
  });
}

async function finalizeBrowserTransactionRequest(plan, preflight, client) {
  const nonce = await client.getTransactionCount({
    address: normalizeAddress(preflight.caller),
  });
  const request = {
    kind: plan.kind,
    chainId: plan.chainId,
    from: normalizeAddress(preflight.caller),
    to: normalizeAddress(plan.target),
    nonce: Number(nonce),
    gasLimit: Number(preflight.estimatedGas),
    value: stringifyField(plan.value),
    data: normalizeHex(plan.calldata),
    gasPrice: null,
    maxFeePerGas: null,
    maxPriorityFeePerGas: null,
  };

  try {
    const fees = await client.estimateFeesPerGas();
    request.maxFeePerGas = fees.maxFeePerGas?.toString() ?? null;
    request.maxPriorityFeePerGas = fees.maxPriorityFeePerGas?.toString() ?? null;
  } catch {
    request.gasPrice = (await client.getGasPrice()).toString();
  }

  return request;
}

function toBrowserReceiptSummary(receipt) {
  return {
    transactionHash: receipt.transactionHash,
    blockHash: receipt.blockHash ?? null,
    blockNumber:
      receipt.blockNumber === null || receipt.blockNumber === undefined
        ? null
        : Number(receipt.blockNumber),
    transactionIndex:
      receipt.transactionIndex === null || receipt.transactionIndex === undefined
        ? null
        : Number(receipt.transactionIndex),
    success: receipt.status === "success",
    gasUsed: Number(receipt.gasUsed),
    effectiveGasPrice: receipt.effectiveGasPrice?.toString() ?? "0",
    from: normalizeAddress(receipt.from),
    to: receipt.to ? normalizeAddress(receipt.to) : null,
  };
}

async function verifyKnownPoolRoot(client, poolAddress, expectedRoot) {
  const currentRoot = (await client.readContract({
    address: normalizeAddress(poolAddress),
    abi: PRIVACY_POOL_ABI,
    functionName: "currentRoot",
  })).toString();
  if (currentRoot === expectedRoot) {
    return expectedRoot;
  }
  if (BigInt(expectedRoot) === 0n) {
    throw new Error(`state root mismatch: expected ${expectedRoot}, got ${currentRoot}`);
  }

  const currentIndex = BigInt(await client.readContract({
    address: normalizeAddress(poolAddress),
    abi: PRIVACY_POOL_ABI,
    functionName: "currentRootIndex",
  }));
  let index = currentIndex;
  for (let cursor = 0n; cursor < ROOT_HISTORY_SIZE; cursor += 1n) {
    const historicalRoot = (await client.readContract({
      address: normalizeAddress(poolAddress),
      abi: PRIVACY_POOL_ABI,
      functionName: "roots",
      args: [index],
    })).toString();
    if (historicalRoot === expectedRoot) {
      return expectedRoot;
    }
    index = (index + ROOT_HISTORY_SIZE - 1n) % ROOT_HISTORY_SIZE;
  }
  throw new Error(`state root mismatch: expected ${expectedRoot}, got ${currentRoot}`);
}

async function readPoolEntrypointAddress(client, poolAddress) {
  const entrypoint = await client.readContract({
    address: normalizeAddress(poolAddress),
    abi: PRIVACY_POOL_ABI,
    functionName: "ENTRYPOINT",
  });
  if (isZeroAddress(entrypoint)) {
    throw new Error("pool entrypoint address must be non-zero");
  }
  return normalizeAddress(entrypoint);
}

async function codeHash(client, address) {
  const { keccak256 } = await loadViem();
  const bytecode = await client.getBytecode({ address: normalizeAddress(address) });
  return keccak256(bytecode ?? "0x");
}

async function createBrowserPublicClient(rpcUrl) {
  if (!rpcUrl || !String(rpcUrl).startsWith("http")) {
    throw new Error(`invalid RPC URL: ${String(rpcUrl ?? "")}`);
  }
  const { createPublicClient, http } = await loadViem();
  return createPublicClient({ transport: http(String(rpcUrl)) });
}

async function loadViem() {
  viemModulePromise ??= import("viem");
  return viemModulePromise;
}

function normalizeExecutionPolicy(policy = {}, plan) {
  return {
    expectedChainId: Number(
      policy.expectedChainId ?? policy.expected_chain_id ?? plan.chainId,
    ),
    caller: normalizeAddress(policy.caller ?? ""),
    expectedPoolCodeHash:
      policy.expectedPoolCodeHash ?? policy.expected_pool_code_hash ?? null,
    expectedEntrypointCodeHash:
      policy.expectedEntrypointCodeHash ??
      policy.expected_entrypoint_code_hash ??
      null,
    mode: policy.mode ?? "strict",
  };
}

function normalizeAddress(value) {
  const address = String(value ?? "");
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`invalid address: ${address}`);
  }
  return `0x${address.slice(2).toLowerCase()}`;
}

function isZeroAddress(address) {
  return normalizeAddress(address) === "0x0000000000000000000000000000000000000000";
}

function normalizeHex(value) {
  const hex = String(value ?? "");
  const normalized = hex.startsWith("0x") ? hex : `0x${hex}`;
  if (!/^0x[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error(`invalid hex data: ${hex}`);
  }
  return normalized;
}

function stringifyField(value) {
  return BigInt(value ?? 0).toString();
}

function emitStatus(target, status) {
  if (typeof target === "function") {
    target(status);
    return;
  }
  if (target?.onStatus && typeof target.onStatus === "function") {
    target.onStatus(status);
  }
}

async function fetchArtifactInputs(manifest, artifactsRoot, circuit) {
  const descriptors = manifest.artifacts.filter((artifact) => artifact.circuit === circuit);
  if (descriptors.length === 0) {
    throw new Error(`manifest does not declare artifacts for circuit ${circuit}`);
  }

  const baseUrl = resolveArtifactsRoot(artifactsRoot);
  return Promise.all(
    descriptors.map(async (descriptor) => {
      const url = new URL(descriptor.filename, baseUrl).toString();
      try {
        const response = await fetch(url);
        if (!response.ok) {
          return descriptorStatus(descriptor, url, null);
        }

        const bytes = new Uint8Array(await response.arrayBuffer());
        return descriptorStatus(descriptor, url, bytes);
      } catch {
        return descriptorStatus(descriptor, url, null);
      }
    }),
  );
}

function descriptorStatus(descriptor, path, bytes) {
  return {
    circuit: descriptor.circuit,
    kind: descriptor.kind,
    filename: descriptor.filename,
    path,
    exists: bytes !== null,
    bytes,
  };
}

function resolveArtifactsRoot(artifactsRoot) {
  const normalizedRoot = artifactsRoot.endsWith("/")
    ? artifactsRoot
    : `${artifactsRoot}/`;

  if (typeof location !== "undefined") {
    return new URL(normalizedRoot, location.href);
  }

  return new URL(normalizedRoot);
}

function normalizeArtifactInputs(artifacts) {
  if (!Array.isArray(artifacts)) {
    throw new TypeError("artifacts must be an array");
  }

  return artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytes: toUint8Array(artifact.bytes),
  }));
}

function encodeSignedManifestArtifactBytes(artifacts) {
  if (!Array.isArray(artifacts)) {
    throw new TypeError("signed manifest artifacts must be an array");
  }

  return artifacts.map((artifact) => ({
    filename: String(artifact.filename),
    bytesBase64: bytesToBase64(toUint8Array(artifact.bytes)),
  }));
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function encodeProofBundle(bundle) {
  return {
    proof: {
      pi_a: normalizePair(bundle?.proof?.piA ?? bundle?.proof?.pi_a, "piA"),
      pi_b: normalizePairRows(bundle?.proof?.piB ?? bundle?.proof?.pi_b, "piB"),
      pi_c: normalizePair(bundle?.proof?.piC ?? bundle?.proof?.pi_c, "piC"),
      protocol: String(bundle?.proof?.protocol ?? ""),
      curve: String(bundle?.proof?.curve ?? ""),
    },
    public_signals: normalizeStringArray(
      bundle?.publicSignals ?? bundle?.public_signals,
      "publicSignals",
    ),
  };
}

function normalizePair(value, label) {
  if (!Array.isArray(value) || value.length < 2) {
    throw new TypeError(`${label} must contain at least two coordinates`);
  }
  for (const coordinate of value.slice(2)) {
    if (String(coordinate) !== "1") {
      throw new TypeError(`${label} projective coordinate must be 1`);
    }
  }

  return value.slice(0, 2).map((entry) => String(entry));
}

function normalizePairRows(value, label) {
  if (!Array.isArray(value) || value.length < 2) {
    throw new TypeError(`${label} must contain at least two rows`);
  }
  for (const row of value.slice(2)) {
    if (
      !Array.isArray(row) ||
      row.length < 2 ||
      String(row[0]) !== "1" ||
      String(row[1]) !== "0"
    ) {
      throw new TypeError(`${label} projective row must be [1, 0]`);
    }
  }

  return value.slice(0, 2).map((row) => normalizePair(row, label));
}

function normalizeStringArray(value, label) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array`);
  }

  return value.map((entry) => String(entry));
}

function toUint8Array(bytes) {
  if (bytes instanceof Uint8Array) {
    return bytes;
  }

  if (bytes instanceof ArrayBuffer) {
    return new Uint8Array(bytes);
  }

  if (ArrayBuffer.isView(bytes)) {
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  if (Array.isArray(bytes)) {
    return Uint8Array.from(bytes);
  }

  throw new TypeError("artifact bytes must be a Uint8Array, ArrayBuffer, or number[]");
}
