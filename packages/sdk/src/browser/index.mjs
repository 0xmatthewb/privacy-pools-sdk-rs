import {
  BrowserRuntimeUnavailableError,
  buildCircuitMerkleWitness,
  buildCommitmentCircuitInput,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  clearBrowserCircuitSessionCache,
  deriveDepositSecrets,
  deriveMasterKeys,
  deriveWithdrawalSecrets,
  fastBackendSupportedOnTarget,
  generateMerkleProof as runtimeGenerateMerkleProof,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  getCommitment as runtimeGetCommitment,
  getRuntimeCapabilities,
  getStableBackendName,
  getVersion,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  proveCommitment,
  proveCommitmentWithSession,
  proveWithdrawal,
  proveWithdrawalWithSession,
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
import { createRuntimeFacade } from "../facade.mjs";

export {
  BrowserRuntimeUnavailableError,
  clearBrowserCircuitSessionCache,
  getRuntimeCapabilities,
};

export class PrivacyPoolsSdkClient {
  async getRuntimeCapabilities() {
    return getRuntimeCapabilities();
  }

  async getVersion() {
    return getVersion();
  }

  async getStableBackendName() {
    return getStableBackendName();
  }

  async fastBackendSupportedOnTarget() {
    return fastBackendSupportedOnTarget();
  }

  async deriveMasterKeys(mnemonic) {
    return deriveMasterKeys(mnemonic);
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return deriveDepositSecrets(masterKeys, scope, index);
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return deriveWithdrawalSecrets(masterKeys, label, index);
  }

  async getCommitment(value, label, nullifier, secret) {
    return runtimeGetCommitment(value, label, nullifier, secret);
  }

  async calculateWithdrawalContext(withdrawal, scope) {
    return calculateWithdrawalContext(withdrawal, scope);
  }

  async generateMerkleProof(leaves, leaf) {
    return runtimeGenerateMerkleProof(leaves, leaf);
  }

  async buildCircuitMerkleWitness(proof, depth) {
    return buildCircuitMerkleWitness(proof, depth);
  }

  async buildWithdrawalCircuitInput(request) {
    return buildWithdrawalCircuitInput(request);
  }

  async buildCommitmentCircuitInput(request) {
    return buildCommitmentCircuitInput(request);
  }

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return getArtifactStatuses(manifestJson, artifactsRoot);
  }

  async getCommitmentArtifactStatuses(manifestJson, artifactsRoot) {
    return getCommitmentArtifactStatuses(manifestJson, artifactsRoot);
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return resolveVerifiedArtifactBundle(manifestJson, artifactsRoot);
  }

  async resolveVerifiedCommitmentArtifactBundle(manifestJson, artifactsRoot) {
    return resolveVerifiedCommitmentArtifactBundle(manifestJson, artifactsRoot);
  }

  async verifyArtifactBytes(manifestJson, circuit, artifacts) {
    return verifyArtifactBytes(manifestJson, circuit, artifacts);
  }

  async prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
    return prepareWithdrawalCircuitSession(manifestJson, artifactsRoot);
  }

  async prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts) {
    return prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts);
  }

  async removeWithdrawalCircuitSession(sessionHandle) {
    return removeWithdrawalCircuitSession(sessionHandle);
  }

  async prepareCommitmentCircuitSession(manifestJson, artifactsRoot) {
    return prepareCommitmentCircuitSession(manifestJson, artifactsRoot);
  }

  async prepareCommitmentCircuitSessionFromBytes(manifestJson, artifacts) {
    return prepareCommitmentCircuitSessionFromBytes(manifestJson, artifacts);
  }

  async removeCommitmentCircuitSession(sessionHandle) {
    return removeCommitmentCircuitSession(sessionHandle);
  }

  async clearCircuitSessionCache() {
    return clearBrowserCircuitSessionCache();
  }

  async proveWithdrawal(backendProfile, manifestJson, artifactsRoot, request, status) {
    return proveWithdrawal(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      status,
    );
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request, status) {
    return proveWithdrawalWithSession(
      backendProfile,
      sessionHandle,
      request,
      status,
    );
  }

  async verifyWithdrawalProof(backendProfile, manifestJson, artifactsRoot, proof) {
    return verifyWithdrawalProof(
      backendProfile,
      manifestJson,
      artifactsRoot,
      proof,
    );
  }

  async verifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof) {
    return verifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof);
  }

  async proveCommitment(backendProfile, manifestJson, artifactsRoot, request, status) {
    return proveCommitment(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      status,
    );
  }

  async proveCommitmentWithSession(backendProfile, sessionHandle, request, status) {
    return proveCommitmentWithSession(
      backendProfile,
      sessionHandle,
      request,
      status,
    );
  }

  async verifyCommitmentProof(backendProfile, manifestJson, artifactsRoot, proof) {
    return verifyCommitmentProof(
      backendProfile,
      manifestJson,
      artifactsRoot,
      proof,
    );
  }

  async verifyCommitmentProofWithSession(backendProfile, sessionHandle, proof) {
    return verifyCommitmentProofWithSession(backendProfile, sessionHandle, proof);
  }
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

const facade = createRuntimeFacade(PrivacyPoolsSdkClient);

export const {
  AccountService,
  AccountError,
  BlockchainProvider,
  CircuitInitialization,
  CircuitName,
  Circuits,
  CommitmentService,
  CompatibilityError,
  ContractError,
  ContractInteractionsService,
  DataError,
  DataService,
  DEFAULT_LOG_FETCH_CONFIG,
  ErrorCode,
  FetchArtifact,
  InvalidRpcUrl,
  PrivacyPoolError,
  PrivacyPoolSDK,
  ProofError,
  SDKError,
  Version,
  bigintToHash,
  bigintToHex,
  calculateContext,
  checkpointRecovery,
  circuitToAsset,
  formatGroth16ProofBundle,
  generateDepositSecrets,
  generateMasterKeys,
  generateMerkleProof,
  generateWithdrawalSecrets,
  getCommitment,
  hashPrecommitment,
  isCurrentStateRoot,
  planAspRootRead,
  planPoolStateRootRead,
  planRagequitTransaction,
  planRelayTransaction,
  planWithdrawalTransaction,
} = facade;

export function createWorkerClient(worker) {
  return new WorkerPrivacyPoolsSdkClient(worker);
}

class WorkerPrivacyPoolsSdkClient {
  #worker;
  #nextId = 1;
  #pending = new Map();

  constructor(worker) {
    this.#worker = worker;
    registerWorkerListener(worker, (message) => {
      const pending = this.#pending.get(message.id);
      if (!pending) {
        return;
      }

      if (message.status) {
        pending.onStatus?.(message.status);
        return;
      }

      this.#pending.delete(message.id);
      if (message.ok) {
        pending.resolve(message.result);
        return;
      }

      pending.reject(deserializeWorkerError(message.error));
    });
  }

  async getRuntimeCapabilities() {
    return this.#send("getRuntimeCapabilities");
  }

  async getVersion() {
    return this.#send("getVersion");
  }

  async getStableBackendName() {
    return this.#send("getStableBackendName");
  }

  async fastBackendSupportedOnTarget() {
    return this.#send("fastBackendSupportedOnTarget");
  }

  async deriveMasterKeys(mnemonic) {
    return this.#send("deriveMasterKeys", [mnemonic]);
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return this.#send("deriveDepositSecrets", [masterKeys, scope, index]);
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return this.#send("deriveWithdrawalSecrets", [masterKeys, label, index]);
  }

  async getCommitment(value, label, nullifier, secret) {
    return this.#send("getCommitment", [value, label, nullifier, secret]);
  }

  async calculateWithdrawalContext(withdrawal, scope) {
    return this.#send("calculateWithdrawalContext", [withdrawal, scope]);
  }

  async generateMerkleProof(leaves, leaf) {
    return this.#send("generateMerkleProof", [leaves, leaf]);
  }

  async buildCircuitMerkleWitness(proof, depth) {
    return this.#send("buildCircuitMerkleWitness", [proof, depth]);
  }

  async buildWithdrawalCircuitInput(request) {
    return this.#send("buildWithdrawalCircuitInput", [request]);
  }

  async buildCommitmentCircuitInput(request) {
    return this.#send("buildCommitmentCircuitInput", [request]);
  }

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return this.#send("getArtifactStatuses", [manifestJson, artifactsRoot]);
  }

  async getCommitmentArtifactStatuses(manifestJson, artifactsRoot) {
    return this.#send("getCommitmentArtifactStatuses", [manifestJson, artifactsRoot]);
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return this.#send("resolveVerifiedArtifactBundle", [manifestJson, artifactsRoot]);
  }

  async resolveVerifiedCommitmentArtifactBundle(manifestJson, artifactsRoot) {
    return this.#send("resolveVerifiedCommitmentArtifactBundle", [
      manifestJson,
      artifactsRoot,
    ]);
  }

  async verifyArtifactBytes(manifestJson, circuit, artifacts) {
    return this.#send("verifyArtifactBytes", [manifestJson, circuit, artifacts]);
  }

  async prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
    return this.#send("prepareWithdrawalCircuitSession", [
      manifestJson,
      artifactsRoot,
    ]);
  }

  async prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts) {
    return this.#send("prepareWithdrawalCircuitSessionFromBytes", [
      manifestJson,
      artifacts,
    ]);
  }

  async removeWithdrawalCircuitSession(sessionHandle) {
    return this.#send("removeWithdrawalCircuitSession", [sessionHandle]);
  }

  async prepareCommitmentCircuitSession(manifestJson, artifactsRoot) {
    return this.#send("prepareCommitmentCircuitSession", [
      manifestJson,
      artifactsRoot,
    ]);
  }

  async prepareCommitmentCircuitSessionFromBytes(manifestJson, artifacts) {
    return this.#send("prepareCommitmentCircuitSessionFromBytes", [
      manifestJson,
      artifacts,
    ]);
  }

  async removeCommitmentCircuitSession(sessionHandle) {
    return this.#send("removeCommitmentCircuitSession", [sessionHandle]);
  }

  async clearCircuitSessionCache() {
    return this.#send("clearBrowserCircuitSessionCache");
  }

  async proveWithdrawal(backendProfile, manifestJson, artifactsRoot, request, status) {
    return this.#send("proveWithdrawal", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ], status);
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request, status) {
    return this.#send("proveWithdrawalWithSession", [
      backendProfile,
      sessionHandle,
      request,
    ], status);
  }

  async verifyWithdrawalProof(backendProfile, manifestJson, artifactsRoot, proof) {
    return this.#send("verifyWithdrawalProof", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      proof,
    ]);
  }

  async verifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof) {
    return this.#send("verifyWithdrawalProofWithSession", [
      backendProfile,
      sessionHandle,
      proof,
    ]);
  }

  async proveCommitment(backendProfile, manifestJson, artifactsRoot, request, status) {
    return this.#send("proveCommitment", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ], status);
  }

  async proveCommitmentWithSession(backendProfile, sessionHandle, request, status) {
    return this.#send("proveCommitmentWithSession", [
      backendProfile,
      sessionHandle,
      request,
    ], status);
  }

  async verifyCommitmentProof(backendProfile, manifestJson, artifactsRoot, proof) {
    return this.#send("verifyCommitmentProof", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      proof,
    ]);
  }

  async verifyCommitmentProofWithSession(backendProfile, sessionHandle, proof) {
    return this.#send("verifyCommitmentProofWithSession", [
      backendProfile,
      sessionHandle,
      proof,
    ]);
  }

  #send(method, params = [], status) {
    const onStatus =
      typeof status === "function"
        ? status
        : typeof status?.onStatus === "function"
          ? status.onStatus
          : undefined;
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, onStatus });
      this.#worker.postMessage({ id, method, params });
    });
  }
}

function registerWorkerListener(worker, onMessage) {
  if (typeof worker.addEventListener === "function") {
    worker.addEventListener("message", (event) => onMessage(event.data ?? {}));
    return;
  }

  if (typeof worker.on === "function") {
    worker.on("message", (message) => onMessage(message ?? {}));
    return;
  }

  throw new TypeError("worker must support message events");
}

function deserializeWorkerError(error) {
  const message = error?.message ?? "worker request failed";
  if (error?.name === "BrowserRuntimeUnavailableError") {
    return new BrowserRuntimeUnavailableError(message);
  }

  const runtimeError = new Error(message);
  if (error?.name) {
    runtimeError.name = error.name;
  }
  return runtimeError;
}
