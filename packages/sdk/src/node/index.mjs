import { native } from "../native.mjs";

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
  async getVersion() {
    return native.getVersion();
  }

  async getStableBackendName() {
    return native.getStableBackendName();
  }

  async fastBackendSupportedOnTarget() {
    return native.fastBackendSupportedOnTarget();
  }

  async deriveMasterKeys(mnemonic) {
    return JSON.parse(native.deriveMasterKeys(mnemonic));
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return JSON.parse(
      native.deriveDepositSecrets(JSON.stringify(masterKeys), scope, index),
    );
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return JSON.parse(
      native.deriveWithdrawalSecrets(JSON.stringify(masterKeys), label, index),
    );
  }

  async getCommitment(value, label, nullifier, secret) {
    return JSON.parse(native.getCommitment(value, label, nullifier, secret));
  }

  async calculateWithdrawalContext(withdrawal, scope) {
    return native.calculateWithdrawalContext(
      JSON.stringify(withdrawal),
      scope,
    );
  }

  async generateMerkleProof(leaves, leaf) {
    return JSON.parse(
      native.generateMerkleProof(JSON.stringify(leaves), leaf),
    );
  }

  async buildCircuitMerkleWitness(proof, depth) {
    return JSON.parse(
      native.buildCircuitMerkleWitness(JSON.stringify(proof), depth),
    );
  }

  async buildWithdrawalCircuitInput(request) {
    return JSON.parse(
      native.buildWithdrawalCircuitInput(JSON.stringify(request)),
    );
  }

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return JSON.parse(
      native.getArtifactStatuses(manifestJson, artifactsRoot),
    );
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return JSON.parse(
      native.resolveVerifiedArtifactBundle(manifestJson, artifactsRoot),
    );
  }

  async verifyArtifactBytes(manifestJson, circuit, artifacts) {
    return JSON.parse(
      native.verifyArtifactBytes(
        manifestJson,
        circuit,
        JSON.stringify(encodeArtifactBytes(artifacts)),
      ),
    );
  }

  async prepareWithdrawalCircuitSession(manifestJson, artifactsRoot) {
    return JSON.parse(
      native.prepareWithdrawalCircuitSession(manifestJson, artifactsRoot),
    );
  }

  async prepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts) {
    return JSON.parse(
      native.prepareWithdrawalCircuitSessionFromBytes(
        manifestJson,
        JSON.stringify(encodeArtifactBytes(artifacts)),
      ),
    );
  }

  async removeWithdrawalCircuitSession(sessionHandle) {
    return native.removeWithdrawalCircuitSession(sessionHandle);
  }

  async proveWithdrawal(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
  ) {
    return JSON.parse(
      native.proveWithdrawal(
        backendProfile,
        manifestJson,
        artifactsRoot,
        JSON.stringify(request),
      ),
    );
  }

  async proveWithdrawalWithSession(backendProfile, sessionHandle, request) {
    return JSON.parse(
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
    return native.verifyWithdrawalProof(
      backendProfile,
      manifestJson,
      artifactsRoot,
      JSON.stringify(proof),
    );
  }

  async verifyWithdrawalProofWithSession(
    backendProfile,
    sessionHandle,
    proof,
  ) {
    return native.verifyWithdrawalProofWithSession(
      backendProfile,
      sessionHandle,
      JSON.stringify(proof),
    );
  }
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

function encodeArtifactBytes(artifacts) {
  return artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytesBase64: Buffer.from(artifact.bytes).toString("base64"),
  }));
}
