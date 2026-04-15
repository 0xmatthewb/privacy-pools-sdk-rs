import {
  BrowserRuntimeUnavailableError,
  buildCircuitMerkleWitness,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  deriveDepositSecrets,
  deriveMasterKeys,
  deriveWithdrawalSecrets,
  fastBackendSupportedOnTarget,
  generateMerkleProof,
  getArtifactStatuses,
  getCommitment,
  getRuntimeCapabilities,
  getStableBackendName,
  getVersion,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  proveWithdrawal,
  proveWithdrawalWithSession,
  removeWithdrawalCircuitSession,
  resolveVerifiedArtifactBundle,
  verifyArtifactBytes,
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
  getArtifactStatuses,
  resolveVerifiedArtifactBundle,
  verifyArtifactBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  removeWithdrawalCircuitSession,
  proveWithdrawal,
  proveWithdrawalWithSession,
  verifyWithdrawalProof,
  verifyWithdrawalProofWithSession,
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
    const result = await implementation(...params);
    respond({ id, ok: true, result });
  } catch (error) {
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
