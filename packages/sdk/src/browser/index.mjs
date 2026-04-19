import {
  BrowserRuntimeUnavailableError,
  buildCircuitMerkleWitness,
  buildCommitmentCircuitInput,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  checkpointRecovery as runtimeCheckpointRecovery,
  clearBrowserCircuitSessionCache,
  clearExecutionHandles,
  clearVerifiedProofHandles,
  clearSecretHandles,
  deriveDepositSecrets,
  deriveMasterKeysHandle,
  deriveMasterKeys,
  deriveRecoveryKeyset as runtimeDeriveRecoveryKeyset,
  deriveWithdrawalSecrets,
  formatGroth16ProofBundle as runtimeFormatGroth16ProofBundle,
  generateMerkleProof as runtimeGenerateMerkleProof,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  getCommitmentFromHandles,
  getArtifactStatuses,
  getCommitmentArtifactStatuses,
  getCommitment as runtimeGetCommitment,
  getRuntimeCapabilities,
  getStableBackendName,
  getVersion,
  finalizePreflightedTransactionHandle,
  initializeExperimentalThreadedBrowserProving,
  isCurrentStateRoot as runtimeIsCurrentStateRoot,
  planAspRootRead as runtimePlanAspRootRead,
  planPoolStateRootRead as runtimePlanPoolStateRootRead,
  planRagequitTransaction as runtimePlanRagequitTransaction,
  planVerifiedRagequitTransactionWithHandle,
  planVerifiedRelayTransactionWithHandle,
  planVerifiedWithdrawalTransactionWithHandle,
  planRelayTransaction as runtimePlanRelayTransaction,
  planWithdrawalTransaction as runtimePlanWithdrawalTransaction,
  preflightVerifiedRagequitTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedWithdrawalTransactionWithHandle,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  proveCommitmentBinary,
  proveAndVerifyCommitmentHandle,
  proveCommitmentWithHandle,
  proveCommitmentWithSessionBinary,
  proveCommitment,
  proveCommitmentWithSession,
  proveWithdrawalBinary,
  proveAndVerifyWithdrawalHandle,
  proveWithdrawalWithHandles,
  proveWithdrawalWithSessionBinary,
  proveWithdrawal,
  proveWithdrawalWithSession,
  recoverAccountState as runtimeRecoverAccountState,
  recoverAccountStateWithKeyset as runtimeRecoverAccountStateWithKeyset,
  removeCommitmentCircuitSession,
  removeExecutionHandle,
  removeWithdrawalCircuitSession,
  removeVerifiedProofHandle,
  removeSecretHandle,
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
import { createRuntimeFacade } from "../facade.mjs";

export {
  BrowserRuntimeUnavailableError,
  clearBrowserCircuitSessionCache,
  clearExecutionHandles,
  clearVerifiedProofHandles,
  clearSecretHandles,
  getRuntimeCapabilities,
  initializeExperimentalThreadedBrowserProving,
  supportsExperimentalThreadedBrowserProving,
  deriveMasterKeysHandle,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  getCommitmentFromHandles,
  proveAndVerifyCommitmentHandle,
  proveAndVerifyWithdrawalHandle,
  proveCommitmentWithHandle,
  proveWithdrawalWithHandles,
  proveWithdrawalBinary,
  proveWithdrawalWithSessionBinary,
  proveCommitmentBinary,
  proveCommitmentWithSessionBinary,
  removeVerifiedProofHandle,
  removeExecutionHandle,
  removeSecretHandle,
  verifyCommitmentProofForRequestHandle,
  verifyRagequitProofForRequestHandle,
  verifyWithdrawalProofForRequestHandle,
  planVerifiedWithdrawalTransactionWithHandle,
  planVerifiedRelayTransactionWithHandle,
  planVerifiedRagequitTransactionWithHandle,
  preflightVerifiedWithdrawalTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedRagequitTransactionWithHandle,
  finalizePreflightedTransactionHandle,
  submitPreflightedTransactionHandle,
  submitFinalizedPreflightedTransactionHandle,
  verifySignedManifest,
  verifySignedManifestArtifacts,
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

  async supportsExperimentalThreadedBrowserProving() {
    return supportsExperimentalThreadedBrowserProving();
  }

  async deriveMasterKeys(mnemonic) {
    return deriveMasterKeys(mnemonic);
  }

  async deriveMasterKeysHandle(mnemonic) {
    return deriveMasterKeysHandle(mnemonic);
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return deriveDepositSecrets(masterKeys, scope, index);
  }

  async generateDepositSecretsHandle(masterKeys, scope, index) {
    return generateDepositSecretsHandle(masterKeys, scope, index);
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return deriveWithdrawalSecrets(masterKeys, label, index);
  }

  async generateWithdrawalSecretsHandle(masterKeys, label, index) {
    return generateWithdrawalSecretsHandle(masterKeys, label, index);
  }

  async getCommitment(value, label, nullifier, secret) {
    return runtimeGetCommitment(value, label, nullifier, secret);
  }

  async getCommitmentFromHandles(value, label, secretsHandle) {
    return getCommitmentFromHandles(value, label, secretsHandle);
  }

  async proveCommitmentWithHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    status,
  ) {
    return proveCommitmentWithHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      status,
    );
  }

  async proveAndVerifyCommitmentHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    status,
  ) {
    return proveAndVerifyCommitmentHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      status,
    );
  }

  async proveWithdrawalWithHandles(
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
    return proveWithdrawalWithHandles(
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
  }

  async proveAndVerifyWithdrawalHandle(
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
    return proveAndVerifyWithdrawalHandle(
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
  }

  async removeSecretHandle(handle) {
    return removeSecretHandle(handle);
  }

  async removeVerifiedProofHandle(handle) {
    return removeVerifiedProofHandle(handle);
  }

  async removeExecutionHandle(handle) {
    return removeExecutionHandle(handle);
  }

  async clearSecretHandles() {
    return clearSecretHandles();
  }

  async clearVerifiedProofHandles() {
    return clearVerifiedProofHandles();
  }

  async clearExecutionHandles() {
    return clearExecutionHandles();
  }

  async dispose() {
    await Promise.allSettled([
      this.clearSecretHandles(),
      this.clearVerifiedProofHandles(),
      this.clearExecutionHandles(),
      this.clearCircuitSessionCache(),
    ]);
    return undefined;
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

  async checkpointRecovery(events, policy) {
    return runtimeCheckpointRecovery(events, policy);
  }

  async deriveRecoveryKeyset(mnemonic, policy) {
    return runtimeDeriveRecoveryKeyset(mnemonic, policy);
  }

  async recoverAccountState(mnemonic, pools, policy) {
    return runtimeRecoverAccountState(mnemonic, pools, policy);
  }

  async recoverAccountStateWithKeyset(keyset, pools, policy) {
    return runtimeRecoverAccountStateWithKeyset(keyset, pools, policy);
  }

  async isCurrentStateRoot(expectedRoot, currentRoot) {
    return runtimeIsCurrentStateRoot(expectedRoot, currentRoot);
  }

  async formatGroth16ProofBundle(proof) {
    return runtimeFormatGroth16ProofBundle(proof);
  }

  async planWithdrawalTransaction(chainId, poolAddress, withdrawal, proof) {
    return runtimePlanWithdrawalTransaction(chainId, poolAddress, withdrawal, proof);
  }

  async planRelayTransaction(chainId, entrypointAddress, withdrawal, proof, scope) {
    return runtimePlanRelayTransaction(
      chainId,
      entrypointAddress,
      withdrawal,
      proof,
      scope,
    );
  }

  async planRagequitTransaction(chainId, poolAddress, proof) {
    return runtimePlanRagequitTransaction(chainId, poolAddress, proof);
  }

  async planVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  ) {
    return planVerifiedWithdrawalTransactionWithHandle(
      chainId,
      poolAddress,
      proofHandle,
    );
  }

  async planVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    proofHandle,
  ) {
    return planVerifiedRelayTransactionWithHandle(
      chainId,
      entrypointAddress,
      proofHandle,
    );
  }

  async planVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  ) {
    return planVerifiedRagequitTransactionWithHandle(
      chainId,
      poolAddress,
      proofHandle,
    );
  }

  async preflightVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return preflightVerifiedWithdrawalTransactionWithHandle(
      chainId,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    );
  }

  async preflightVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return preflightVerifiedRelayTransactionWithHandle(
      chainId,
      entrypointAddress,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    );
  }

  async preflightVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return preflightVerifiedRagequitTransactionWithHandle(
      chainId,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    );
  }

  async finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle);
  }

  async submitPreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return submitPreflightedTransactionHandle(rpcUrl, preflightedHandle);
  }

  async submitFinalizedPreflightedTransactionHandle(
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  ) {
    return submitFinalizedPreflightedTransactionHandle(
      rpcUrl,
      finalizedHandle,
      signedTransaction,
    );
  }

  async planPoolStateRootRead(poolAddress) {
    return runtimePlanPoolStateRootRead(poolAddress);
  }

  async planAspRootRead(entrypointAddress, poolAddress) {
    return runtimePlanAspRootRead(entrypointAddress, poolAddress);
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

  async verifySignedManifest(payloadJson, signatureHex, publicKeyHex) {
    return verifySignedManifest(payloadJson, signatureHex, publicKeyHex);
  }

  async verifySignedManifestArtifacts(
    payloadJson,
    signatureHex,
    publicKeyHex,
    artifacts,
  ) {
    return verifySignedManifestArtifacts(
      payloadJson,
      signatureHex,
      publicKeyHex,
      artifacts,
    );
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

  async proveWithdrawalBinary(backendProfile, manifestJson, artifactsRoot, request, status) {
    return proveWithdrawalBinary(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      status,
    );
  }

  async proveWithdrawalWithSessionBinary(
    backendProfile,
    sessionHandle,
    request,
    status,
  ) {
    return proveWithdrawalWithSessionBinary(
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

  async verifyWithdrawalProofForRequestHandle(
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
    return verifyWithdrawalProofForRequestHandle(
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
    );
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

  async proveCommitmentBinary(backendProfile, manifestJson, artifactsRoot, request, status) {
    return proveCommitmentBinary(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      status,
    );
  }

  async proveCommitmentWithSessionBinary(
    backendProfile,
    sessionHandle,
    request,
    status,
  ) {
    return proveCommitmentWithSessionBinary(
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

  async verifyCommitmentProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return verifyCommitmentProofForRequestHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      proof,
    );
  }

  async verifyRagequitProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return verifyRagequitProofForRequestHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      proof,
    );
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
  deriveRecoveryKeyset,
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
  recoverAccountState,
  recoverAccountStateWithKeyset,
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

  async deriveMasterKeys(mnemonic) {
    return this.#send("deriveMasterKeys", [mnemonic]);
  }

  async deriveMasterKeysHandle(mnemonic) {
    return this.#send("deriveMasterKeysHandle", [mnemonic]);
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return this.#send("deriveDepositSecrets", [masterKeys, scope, index]);
  }

  async generateDepositSecretsHandle(masterKeys, scope, index) {
    return this.#send("generateDepositSecretsHandle", [masterKeys, scope, index]);
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return this.#send("deriveWithdrawalSecrets", [masterKeys, label, index]);
  }

  async generateWithdrawalSecretsHandle(masterKeys, label, index) {
    return this.#send("generateWithdrawalSecretsHandle", [masterKeys, label, index]);
  }

  async getCommitment(value, label, nullifier, secret) {
    return this.#send("getCommitment", [value, label, nullifier, secret]);
  }

  async getCommitmentFromHandles(value, label, secretsHandle) {
    return this.#send("getCommitmentFromHandles", [value, label, secretsHandle]);
  }

  async proveCommitmentWithHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    status,
  ) {
    return this.#send("proveCommitmentWithHandle", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
    ], status);
  }

  async proveAndVerifyCommitmentHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    status,
  ) {
    return this.#send("proveAndVerifyCommitmentHandle", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
    ], status);
  }

  async proveWithdrawalWithHandles(
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
    return this.#send("proveWithdrawalWithHandles", [
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
    ], status);
  }

  async proveAndVerifyWithdrawalHandle(
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
    return this.#send("proveAndVerifyWithdrawalHandle", [
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
    ], status);
  }

  async removeSecretHandle(handle) {
    return this.#send("removeSecretHandle", [handle]);
  }

  async removeVerifiedProofHandle(handle) {
    return this.#send("removeVerifiedProofHandle", [handle]);
  }

  async removeExecutionHandle(handle) {
    return this.#send("removeExecutionHandle", [handle]);
  }

  async clearSecretHandles() {
    return this.#send("clearSecretHandles");
  }

  async clearVerifiedProofHandles() {
    return this.#send("clearVerifiedProofHandles");
  }

  async clearExecutionHandles() {
    return this.#send("clearExecutionHandles");
  }

  async dispose({ terminate = false } = {}) {
    await Promise.allSettled([
      this.clearSecretHandles(),
      this.clearVerifiedProofHandles(),
      this.clearExecutionHandles(),
      this.clearCircuitSessionCache(),
    ]);
    if (terminate && typeof this.#worker.terminate === "function") {
      return this.#worker.terminate();
    }
    return undefined;
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

  async checkpointRecovery(events, policy) {
    return this.#send("checkpointRecovery", [events, policy]);
  }

  async deriveRecoveryKeyset(mnemonic, policy) {
    return this.#send("deriveRecoveryKeyset", [mnemonic, policy]);
  }

  async recoverAccountState(mnemonic, pools, policy) {
    return this.#send("recoverAccountState", [mnemonic, pools, policy]);
  }

  async recoverAccountStateWithKeyset(keyset, pools, policy) {
    return this.#send("recoverAccountStateWithKeyset", [keyset, pools, policy]);
  }

  async isCurrentStateRoot(expectedRoot, currentRoot) {
    return this.#send("isCurrentStateRoot", [expectedRoot, currentRoot]);
  }

  async formatGroth16ProofBundle(proof) {
    return this.#send("formatGroth16ProofBundle", [proof]);
  }

  async planWithdrawalTransaction(chainId, poolAddress, withdrawal, proof) {
    return this.#send("planWithdrawalTransaction", [
      chainId,
      poolAddress,
      withdrawal,
      proof,
    ]);
  }

  async planRelayTransaction(chainId, entrypointAddress, withdrawal, proof, scope) {
    return this.#send("planRelayTransaction", [
      chainId,
      entrypointAddress,
      withdrawal,
      proof,
      scope,
    ]);
  }

  async planRagequitTransaction(chainId, poolAddress, proof) {
    return this.#send("planRagequitTransaction", [chainId, poolAddress, proof]);
  }

  async planVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  ) {
    return this.#send("planVerifiedWithdrawalTransactionWithHandle", [
      chainId,
      poolAddress,
      proofHandle,
    ]);
  }

  async planVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    proofHandle,
  ) {
    return this.#send("planVerifiedRelayTransactionWithHandle", [
      chainId,
      entrypointAddress,
      proofHandle,
    ]);
  }

  async planVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  ) {
    return this.#send("planVerifiedRagequitTransactionWithHandle", [
      chainId,
      poolAddress,
      proofHandle,
    ]);
  }

  async preflightVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return this.#send("preflightVerifiedWithdrawalTransactionWithHandle", [
      chainId,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    ]);
  }

  async preflightVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return this.#send("preflightVerifiedRelayTransactionWithHandle", [
      chainId,
      entrypointAddress,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    ]);
  }

  async preflightVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return this.#send("preflightVerifiedRagequitTransactionWithHandle", [
      chainId,
      poolAddress,
      rpcUrl,
      policy,
      proofHandle,
    ]);
  }

  async finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return this.#send("finalizePreflightedTransactionHandle", [
      rpcUrl,
      preflightedHandle,
    ]);
  }

  async submitPreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return this.#send("submitPreflightedTransactionHandle", [
      rpcUrl,
      preflightedHandle,
    ]);
  }

  async submitFinalizedPreflightedTransactionHandle(
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  ) {
    return this.#send("submitFinalizedPreflightedTransactionHandle", [
      rpcUrl,
      finalizedHandle,
      signedTransaction,
    ]);
  }

  async planPoolStateRootRead(poolAddress) {
    return this.#send("planPoolStateRootRead", [poolAddress]);
  }

  async planAspRootRead(entrypointAddress, poolAddress) {
    return this.#send("planAspRootRead", [entrypointAddress, poolAddress]);
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

  async verifySignedManifest(payloadJson, signatureHex, publicKeyHex) {
    return this.#send("verifySignedManifest", [
      payloadJson,
      signatureHex,
      publicKeyHex,
    ]);
  }

  async verifySignedManifestArtifacts(
    payloadJson,
    signatureHex,
    publicKeyHex,
    artifacts,
  ) {
    return this.#send("verifySignedManifestArtifacts", [
      payloadJson,
      signatureHex,
      publicKeyHex,
      artifacts,
    ]);
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

  async proveWithdrawalBinary(backendProfile, manifestJson, artifactsRoot, request, status) {
    return this.#send("proveWithdrawalBinary", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ], status);
  }

  async proveWithdrawalWithSessionBinary(
    backendProfile,
    sessionHandle,
    request,
    status,
  ) {
    return this.#send("proveWithdrawalWithSessionBinary", [
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

  async verifyWithdrawalProofForRequestHandle(
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
    return this.#send("verifyWithdrawalProofForRequestHandle", [
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

  async proveCommitmentBinary(backendProfile, manifestJson, artifactsRoot, request, status) {
    return this.#send("proveCommitmentBinary", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ], status);
  }

  async proveCommitmentWithSessionBinary(
    backendProfile,
    sessionHandle,
    request,
    status,
  ) {
    return this.#send("proveCommitmentWithSessionBinary", [
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

  async verifyCommitmentProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return this.#send("verifyCommitmentProofForRequestHandle", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
      proof,
    ]);
  }

  async verifyRagequitProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return this.#send("verifyRagequitProofForRequestHandle", [
      backendProfile,
      manifestJson,
      artifactsRoot,
      commitmentHandle,
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
      const message = { id, method, params };
      const transferList = collectTransferList(params);
      try {
        if (transferList.length > 0) {
          this.#worker.postMessage(message, transferList);
        } else {
          this.#worker.postMessage(message);
        }
      } catch (error) {
        this.#pending.delete(id);
        reject(error);
      }
    });
  }
}

function collectTransferList(value, seen = new Set(), transfers = []) {
  if (!value) {
    return transfers;
  }

  if (value instanceof ArrayBuffer) {
    if (!seen.has(value) && value.byteLength > 0) {
      seen.add(value);
      transfers.push(value);
    }
    return transfers;
  }

  if (
    typeof SharedArrayBuffer !== "undefined" &&
    value instanceof SharedArrayBuffer
  ) {
    return transfers;
  }

  if (ArrayBuffer.isView(value)) {
    return collectTransferList(value.buffer, seen, transfers);
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectTransferList(item, seen, transfers);
    }
    return transfers;
  }

  if (typeof value === "object") {
    for (const item of Object.values(value)) {
      collectTransferList(item, seen, transfers);
    }
  }

  return transfers;
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
