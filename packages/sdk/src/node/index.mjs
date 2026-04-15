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

  async getArtifactStatuses(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.getArtifactStatuses(manifestJson, artifactsRoot),
    );
  }

  async resolveVerifiedArtifactBundle(manifestJson, artifactsRoot) {
    return parseNativeJson(
      native.resolveVerifiedArtifactBundle(manifestJson, artifactsRoot),
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
