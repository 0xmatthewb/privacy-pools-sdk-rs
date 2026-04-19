import {
  BrowserRuntimeUnavailableError,
  buildCircuitMerkleWitness,
  buildCommitmentCircuitInput,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  checkpointRecovery,
  clearBrowserCircuitSessionCache,
  clearExecutionHandles,
  clearVerifiedProofHandles,
  clearSecretHandles,
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportMasterKeys,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportSecret,
  dangerouslyExportSubmittedPreflightedTransaction,
  deriveDepositSecrets,
  deriveMasterKeysHandle,
  deriveMasterKeys,
  deriveRecoveryKeyset,
  deriveWithdrawalSecrets,
  formatGroth16ProofBundle,
  generateMerkleProof,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  getCommitmentFromHandles,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  getCommitment,
  getRuntimeCapabilities,
  getStableBackendName,
  getVersion,
  isCurrentStateRoot,
  finalizePreflightedTransactionHandle,
  planAspRootRead,
  planPoolStateRootRead,
  planRagequitTransaction,
  planVerifiedRagequitTransactionWithHandle,
  planVerifiedRelayTransactionWithHandle,
  planVerifiedWithdrawalTransactionWithHandle,
  planRelayTransaction,
  planWithdrawalTransaction,
  preflightVerifiedRagequitTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedWithdrawalTransactionWithHandle,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  proveAndVerifyCommitmentHandle,
  proveAndVerifyWithdrawalHandle,
  proveCommitmentWithHandle,
  proveCommitmentBinary,
  proveCommitmentWithSessionBinary,
  proveCommitment,
  proveCommitmentWithSession,
  proveWithdrawalWithHandles,
  proveWithdrawalBinary,
  proveWithdrawalWithSessionBinary,
  proveWithdrawal,
  proveWithdrawalWithSession,
  recoverAccountState,
  recoverAccountStateWithKeyset,
  removeExecutionHandle,
  removeVerifiedProofHandle,
  removeSecretHandle,
  removeCommitmentCircuitSession,
  removeWithdrawalCircuitSession,
  resolveVerifiedCommitmentArtifactBundle,
  resolveVerifiedArtifactBundle,
  submitFinalizedPreflightedTransactionHandle,
  submitPreflightedTransactionHandle,
  supportsExperimentalThreadedBrowserProving,
  verifyArtifactBytes,
  verifySignedManifest,
  verifySignedManifestArtifacts,
  verifyCommitmentProof,
  verifyCommitmentProofForRequestHandle,
  verifyCommitmentProofWithSession,
  verifyRagequitProofForRequestHandle,
  verifyWithdrawalProof,
  verifyWithdrawalProofForRequestHandle,
  verifyWithdrawalProofWithSession,
} from "./runtime.mjs";

const METHODS = {
  getVersion,
  getStableBackendName,
  supportsExperimentalThreadedBrowserProving,
  deriveMasterKeys,
  deriveMasterKeysHandle,
  deriveDepositSecrets,
  generateDepositSecretsHandle,
  deriveWithdrawalSecrets,
  generateWithdrawalSecretsHandle,
  getCommitment,
  getCommitmentFromHandles,
  proveCommitmentWithHandle,
  proveAndVerifyCommitmentHandle,
  proveWithdrawalWithHandles,
  proveAndVerifyWithdrawalHandle,
  dangerouslyExportMasterKeys,
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportSecret,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportSubmittedPreflightedTransaction,
  removeSecretHandle,
  removeVerifiedProofHandle,
  removeExecutionHandle,
  clearSecretHandles,
  clearVerifiedProofHandles,
  clearExecutionHandles,
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
  planVerifiedWithdrawalTransactionWithHandle,
  planVerifiedRelayTransactionWithHandle,
  planVerifiedRagequitTransactionWithHandle,
  preflightVerifiedWithdrawalTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedRagequitTransactionWithHandle,
  finalizePreflightedTransactionHandle,
  submitPreflightedTransactionHandle,
  submitFinalizedPreflightedTransactionHandle,
  planPoolStateRootRead,
  planAspRootRead,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  resolveVerifiedArtifactBundle,
  resolveVerifiedCommitmentArtifactBundle,
  verifyArtifactBytes,
  verifySignedManifest,
  verifySignedManifestArtifacts,
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
  verifyWithdrawalProofForRequestHandle,
  proveWithdrawalBinary,
  proveWithdrawalWithSessionBinary,
  proveCommitment,
  proveCommitmentWithSession,
  proveCommitmentBinary,
  proveCommitmentWithSessionBinary,
  verifyCommitmentProof,
  verifyCommitmentProofWithSession,
  verifyCommitmentProofForRequestHandle,
  verifyRagequitProofForRequestHandle,
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
