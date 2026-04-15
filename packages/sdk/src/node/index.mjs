import { native } from "../native.mjs";
import { createRuntimeFacade } from "../facade.mjs";

export function getRuntimeCapabilities() {
  return {
    runtime: "node",
    provingAvailable: true,
    verificationAvailable: true,
    workerAvailable: false,
  };
}

export function createWorkerClient() {
  throw new Error("worker clients are only available in the browser runtime");
}

export class PrivacyPoolsSdkClient {
  async getRuntimeCapabilities() {
    return getRuntimeCapabilities();
  }

  async getVersion() {
    return unwrapNativeValue(native.getVersion());
  }

  async getStableBackendName() {
    return unwrapNativeValue(native.getStableBackendName());
  }

  async fastBackendSupportedOnTarget() {
    return unwrapNativeValue(native.fastBackendSupportedOnTarget());
  }

  async deriveMasterKeys(mnemonic) {
    return parseNativeJson(native.deriveMasterKeys(mnemonic));
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return parseNativeJson(
      native.deriveDepositSecrets(JSON.stringify(masterKeys), scope, index),
    );
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return parseNativeJson(
      native.deriveWithdrawalSecrets(JSON.stringify(masterKeys), label, index),
    );
  }

  async getCommitment(value, label, nullifier, secret) {
    return parseNativeJson(native.getCommitment(value, label, nullifier, secret));
  }

  async calculateWithdrawalContext(withdrawal, scope) {
    return unwrapNativeValue(
      native.calculateWithdrawalContext(
        JSON.stringify(withdrawal),
        scope,
      ),
    );
  }

  async generateMerkleProof(leaves, leaf) {
    return parseNativeJson(
      native.generateMerkleProof(JSON.stringify(leaves), leaf),
    );
  }

  async buildCircuitMerkleWitness(proof, depth) {
    return parseNativeJson(
      native.buildCircuitMerkleWitness(JSON.stringify(proof), depth),
    );
  }

  async buildWithdrawalCircuitInput(request) {
    return parseNativeJson(
      native.buildWithdrawalCircuitInput(JSON.stringify(request)),
    );
  }

  async buildCommitmentCircuitInput(request) {
    return parseNativeJson(
      native.buildCommitmentCircuitInput(JSON.stringify(request)),
    );
  }

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.getArtifactStatuses(manifestJson, artifactsRoot),
    );
  }

  async getCommitmentArtifactStatuses(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.getCommitmentArtifactStatuses(manifestJson, artifactsRoot),
    );
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.resolveVerifiedArtifactBundle(manifestJson, artifactsRoot),
    );
  }

  async resolveVerifiedCommitmentArtifactBundle(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.resolveVerifiedCommitmentArtifactBundle(
        manifestJson,
        artifactsRoot,
      ),
    );
  }

  async verifyArtifactBytes(manifestJson, circuit, artifacts) {
    return parseNativeJson(
      native.verifyArtifactBytes(
        manifestJson,
        circuit,
        JSON.stringify(encodeArtifactBytes(artifacts)),
      ),
    );
  }

  async prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.prepareWithdrawalCircuitSession(manifestJson, artifactsRoot),
    );
  }

  async prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts) {
    return parseNativeJson(
      native.prepareWithdrawalCircuitSessionFromBytes(
        manifestJson,
        JSON.stringify(encodeArtifactBytes(artifacts)),
      ),
    );
  }

  async removeWithdrawalCircuitSession(sessionHandle) {
    return unwrapNativeValue(native.removeWithdrawalCircuitSession(sessionHandle));
  }

  async prepareCommitmentCircuitSession(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.prepareCommitmentCircuitSession(manifestJson, artifactsRoot),
    );
  }

  async prepareCommitmentCircuitSessionFromBytes(manifestJson, artifacts) {
    return parseNativeJson(
      native.prepareCommitmentCircuitSessionFromBytes(
        manifestJson,
        JSON.stringify(encodeArtifactBytes(artifacts)),
      ),
    );
  }

  async removeCommitmentCircuitSession(sessionHandle) {
    return unwrapNativeValue(native.removeCommitmentCircuitSession(sessionHandle));
  }

  async proveWithdrawal(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
  ) {
    return parseNativeJson(
      native.proveWithdrawal(
        backendProfile,
        manifestJson,
        artifactsRoot,
        JSON.stringify(request),
      ),
    );
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request) {
    return parseNativeJson(
      native.proveWithdrawalWithSession(
        backendProfile,
        sessionHandle,
        JSON.stringify(request),
      ),
    );
  }

  async verifyWithdrawalProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyWithdrawalProof(
        backendProfile,
        manifestJson,
        artifactsRoot,
        JSON.stringify(proof),
      ),
    );
  }

  async verifyWithdrawalProofWithSession(
    backendProfile,
    sessionHandle,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyWithdrawalProofWithSession(
        backendProfile,
        sessionHandle,
        JSON.stringify(proof),
      ),
    );
  }

  async proveCommitment(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
  ) {
    return parseNativeJson(
      native.proveCommitment(
        backendProfile,
        manifestJson,
        artifactsRoot,
        JSON.stringify(request),
      ),
    );
  }

  async proveCommitmentWithSession(backendProfile, sessionHandle, request) {
    return parseNativeJson(
      native.proveCommitmentWithSession(
        backendProfile,
        sessionHandle,
        JSON.stringify(request),
      ),
    );
  }

  async verifyCommitmentProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyCommitmentProof(
        backendProfile,
        manifestJson,
        artifactsRoot,
        JSON.stringify(proof),
      ),
    );
  }

  async verifyCommitmentProofWithSession(
    backendProfile,
    sessionHandle,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyCommitmentProofWithSession(
        backendProfile,
        sessionHandle,
        JSON.stringify(proof),
      ),
    );
  }

  async formatGroth16ProofBundle(proof) {
    return parseNativeJson(native.formatGroth16ProofBundle(JSON.stringify(proof)));
  }

  async planWithdrawalTransaction(chainId, poolAddress, withdrawal, proof) {
    return parseNativeJson(
      native.planWithdrawalTransaction(
        String(chainId),
        poolAddress,
        JSON.stringify(withdrawal),
        JSON.stringify(proof),
      ),
    );
  }

  async planRelayTransaction(chainId, entrypointAddress, withdrawal, proof, scope) {
    return parseNativeJson(
      native.planRelayTransaction(
        String(chainId),
        entrypointAddress,
        JSON.stringify(withdrawal),
        JSON.stringify(proof),
        String(scope),
      ),
    );
  }

  async planRagequitTransaction(chainId, poolAddress, proof) {
    return parseNativeJson(
      native.planRagequitTransaction(
        String(chainId),
        poolAddress,
        JSON.stringify(proof),
      ),
    );
  }

  async planPoolStateRootRead(poolAddress) {
    return parseNativeJson(native.planPoolStateRootRead(poolAddress));
  }

  async planAspRootRead(entrypointAddress, poolAddress) {
    return parseNativeJson(native.planAspRootRead(entrypointAddress, poolAddress));
  }

  async isCurrentStateRoot(expectedRoot, currentRoot) {
    return unwrapNativeValue(
      native.isCurrentStateRoot(String(expectedRoot), String(currentRoot)),
    );
  }

  async checkpointRecovery(events, policy) {
    return parseNativeJson(
      native.checkpointRecovery(JSON.stringify(events), JSON.stringify(policy)),
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

function encodeArtifactBytes(artifacts) {
  return artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytesBase64: Buffer.from(artifact.bytes).toString("base64"),
  }));
}

function parseNativeJson(payload) {
  unwrapNativeValue(payload);

  try {
    return JSON.parse(payload);
  } catch (error) {
    const message = String(payload);
    if (message.startsWith("Error: ")) {
      throw new Error(message.slice("Error: ".length));
    }

    throw error;
  }
}

function unwrapNativeValue(value) {
  if (value instanceof Error) {
    throw value;
  }

  return value;
}
