import {
  BrowserRuntimeUnavailableError,
  buildCircuitMerkleWitness,
  buildCommitmentCircuitInput,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  checkpointRecovery,
  clearBrowserCircuitSessionCache,
  deriveDepositSecrets,
  deriveMasterKeys,
  deriveRecoveryKeyset,
  deriveWithdrawalSecrets,
  fastBackendSupportedOnTarget,
  formatGroth16ProofBundle,
  generateMerkleProof,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  getCommitment,
  getRuntimeCapabilities,
  getStableBackendName,
  getVersion,
  isCurrentStateRoot,
  planAspRootRead,
  planPoolStateRootRead,
  planRagequitTransaction,
  planRelayTransaction,
  planWithdrawalTransaction,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  proveCommitment,
  proveCommitmentWithSession,
  proveWithdrawal,
  proveWithdrawalWithSession,
  recoverAccountState,
  recoverAccountStateWithKeyset,
  removeCommitmentCircuitSession,
  removeWithdrawalCircuitSession,
  resolveVerifiedCommitmentArtifactBundle,
  resolveVerifiedArtifactBundle,
  verifyArtifactBytes,
  verifyCommitmentProof,
  verifyCommitmentProofWithSession,
  verifyWithdrawalProof,
  verifyWithdrawalProofWithSession,
} from "./runtime.mjs";

const METHODS = {
  getVersion,
  getStableBackendName,
  fastBackendSupportedOnTarget,
  deriveMasterKeys,
  deriveDepositSecrets,
  deriveWithdrawalSecrets,
  getCommitment,
  calculateWithdrawalContext,
  generateMerkleProof,
  buildCircuitMerkleWitness,
  buildWithdrawalCircuitInput,
  buildCommitmentCircuitInput,
  checkpointRecovery,
  deriveRecoveryKeyset,
  recoverAccountState,
  recoverAccountStateWithKeyset,
  isCurrentStateRoot,
  formatGroth16ProofBundle,
  planWithdrawalTransaction,
  planRelayTransaction,
  planRagequitTransaction,
  planPoolStateRootRead,
  planAspRootRead,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  resolveVerifiedArtifactBundle,
  resolveVerifiedCommitmentArtifactBundle,
  verifyArtifactBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  removeWithdrawalCircuitSession,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  removeCommitmentCircuitSession,
  clearBrowserCircuitSessionCache,
  proveWithdrawal,
  proveWithdrawalWithSession,
  verifyWithdrawalProof,
  verifyWithdrawalProofWithSession,
  proveCommitment,
  proveCommitmentWithSession,
  verifyCommitmentProof,
  verifyCommitmentProofWithSession,
};

await attachWorkerHandler();

async function attachWorkerHandler() {
  if (typeof self !== "undefined" && typeof self.postMessage === "function") {
    self.addEventListener("message", (event) => {
      void handleMessage(event.data ?? {}, (payload) => self.postMessage(payload));
    });
    return;
  }

  const { parentPort } = await import("node:worker_threads");
  parentPort.on("message", (message) => {
    void handleMessage(message ?? {}, (payload) => parentPort.postMessage(payload));
  });
}

async function handleMessage(message, respond) {
  const { id, method, params = [] } = message;
  if (method === "getRuntimeCapabilities") {
    respond({ id, ok: true, result: getRuntimeCapabilities() });
    return;
  }

  const implementation = METHODS[method];
  if (!implementation) {
    respond({
      id,
      ok: false,
      error: serializeError(new Error(`unsupported worker method: ${method}`)),
    });
    return;
  }

  try {
    const result = await implementation(...params, (status) => {
      respond({ id, status });
    });
    respond({ id, ok: true, result });
  } catch (error) {
    respond({ id, status: { stage: "error", message: error?.message ?? String(error) } });
    respond({ id, ok: false, error: serializeError(error) });
  }
}

function serializeError(error) {
  if (error instanceof BrowserRuntimeUnavailableError) {
    return {
      name: error.name,
      message: error.message,
    };
  }

  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
    };
  }

  return {
    name: "Error",
    message: String(error),
  };
}
