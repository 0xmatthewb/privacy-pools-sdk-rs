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

export { BrowserRuntimeUnavailableError, getRuntimeCapabilities };

export class PrivacyPoolsSdkClient {
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
    return getCommitment(value, label, nullifier, secret);
  }

  async calculateWithdrawalContext(withdrawal, scope) {
    return calculateWithdrawalContext(withdrawal, scope);
  }

  async generateMerkleProof(leaves, leaf) {
    return generateMerkleProof(leaves, leaf);
  }

  async buildCircuitMerkleWitness(proof, depth) {
    return buildCircuitMerkleWitness(proof, depth);
  }

  async buildWithdrawalCircuitInput(request) {
    return buildWithdrawalCircuitInput(request);
  }

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return getArtifactStatuses(manifestJson, artifactsRoot);
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return resolveVerifiedArtifactBundle(manifestJson, artifactsRoot);
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

  async proveWithdrawal(backendProfile, manifestJson, artifactsRoot, request) {
    return proveWithdrawal(backendProfile, manifestJson, artifactsRoot, request);
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request) {
    return proveWithdrawalWithSession(backendProfile, sessionHandle, request);
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
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

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

      this.#pending.delete(message.id);
      if (message.ok) {
        pending.resolve(message.result);
        return;
      }

      pending.reject(deserializeWorkerError(message.error));
    });
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

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return this.#send("getArtifactStatuses", [manifestJson, artifactsRoot]);
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return this.#send("resolveVerifiedArtifactBundle", [manifestJson, artifactsRoot]);
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

  async proveWithdrawal(backendProfile, manifestJson, artifactsRoot, request) {
    return this.#send("proveWithdrawal", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ]);
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request) {
    return this.#send("proveWithdrawalWithSession", [
      backendProfile,
      sessionHandle,
      request,
    ]);
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

  #send(method, params = []) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
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
