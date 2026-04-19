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

function buildWithdrawalWitnessRequestHandle(
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
) {
  return unwrapNativeValue(
    native.buildWithdrawalWitnessRequestHandleFromHandles(
      commitmentHandle,
      JSON.stringify(withdrawal),
      String(scope),
      String(withdrawalAmount),
      JSON.stringify(stateWitness),
      JSON.stringify(aspWitness),
      newSecretsHandle,
    ),
  );
}

async function withWithdrawalWitnessRequestHandle(
  commitmentHandle,
  withdrawal,
  scope,
  withdrawalAmount,
  stateWitness,
  aspWitness,
  newSecretsHandle,
  callback,
) {
  const requestHandle = buildWithdrawalWitnessRequestHandle(
    commitmentHandle,
    withdrawal,
    scope,
    withdrawalAmount,
    stateWitness,
    aspWitness,
    newSecretsHandle,
  );
  try {
    return await callback(requestHandle);
  } finally {
    try {
      unwrapNativeValue(native.removeSecretHandle(requestHandle));
    } catch {
      // Best-effort cleanup for temporary internal request handles.
    }
  }
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

  async deriveMasterKeys(mnemonic) {
    return parseNativeJson(native.deriveMasterKeys(mnemonic));
  }

  async deriveMasterKeysHandle(mnemonic) {
    return unwrapNativeValue(native.deriveMasterKeysHandle(mnemonic));
  }

  async deriveMasterKeysHandleBytes(mnemonicBytes) {
    return unwrapNativeValue(
      native.deriveMasterKeysHandleBytes(normalizeNodeBytes(mnemonicBytes)),
    );
  }

  async deriveDepositSecrets(masterKeys, scope, index) {
    return parseNativeJson(
      native.deriveDepositSecrets(JSON.stringify(masterKeys), scope, index),
    );
  }

  async generateDepositSecretsHandle(masterKeys, scope, index) {
    if (typeof masterKeys !== "string") {
      throw new Error(
        "Node handle APIs require a master key handle; exporting raw master keys into the handle registry is intentionally unsupported",
      );
    }
    return unwrapNativeValue(
      native.generateDepositSecretsHandle(masterKeys, String(scope), String(index)),
    );
  }

  async deriveWithdrawalSecrets(masterKeys, label, index) {
    return parseNativeJson(
      native.deriveWithdrawalSecrets(JSON.stringify(masterKeys), label, index),
    );
  }

  async generateWithdrawalSecretsHandle(masterKeys, label, index) {
    if (typeof masterKeys !== "string") {
      throw new Error(
        "Node handle APIs require a master key handle; exporting raw master keys into the handle registry is intentionally unsupported",
      );
    }
    return unwrapNativeValue(
      native.generateWithdrawalSecretsHandle(masterKeys, String(label), String(index)),
    );
  }

  async getCommitment(value, label, nullifier, secret) {
    return parseNativeJson(native.getCommitment(value, label, nullifier, secret));
  }

  async getCommitmentFromHandles(value, label, secretsHandle) {
    return unwrapNativeValue(
      native.getCommitmentFromHandles(String(value), String(label), secretsHandle),
    );
  }

  async removeSecretHandle(handle) {
    return unwrapNativeValue(native.removeSecretHandle(handle));
  }

  async clearSecretHandles() {
    return unwrapNativeValue(native.clearSecretHandles());
  }

  async removeVerifiedProofHandle(handle) {
    return unwrapNativeValue(native.removeVerifiedProofHandle(handle));
  }

  async clearVerifiedProofHandles() {
    return unwrapNativeValue(native.clearVerifiedProofHandles());
  }

  async removeExecutionHandle(handle) {
    return unwrapNativeValue(native.removeExecutionHandle(handle));
  }

  async clearExecutionHandles() {
    return unwrapNativeValue(native.clearExecutionHandles());
  }

  async dispose() {
    await Promise.allSettled([
      this.clearSecretHandles(),
      this.clearVerifiedProofHandles(),
      this.clearExecutionHandles(),
    ]);
    return undefined;
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

  async verifySignedManifest(payloadJson, signatureHex, publicKeyHex) {
    return parseNativeJson(
      native.verifySignedManifest(payloadJson, signatureHex, publicKeyHex),
    );
  }

  async verifySignedManifestArtifacts(
    payloadJson,
    signatureHex,
    publicKeyHex,
    artifacts,
  ) {
    return parseNativeJson(
      native.verifySignedManifestArtifacts(
        payloadJson,
        signatureHex,
        publicKeyHex,
        JSON.stringify(encodeSignedManifestArtifactBytes(artifacts)),
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
  ) {
    return withWithdrawalWitnessRequestHandle(
      commitmentHandle,
      withdrawal,
      scope,
      withdrawalAmount,
      stateWitness,
      aspWitness,
      newSecretsHandle,
      async (requestHandle) =>
        parseNativeJson(
          native.proveWithdrawalWithHandles(
            backendProfile,
            manifestJson,
            artifactsRoot,
            requestHandle,
          ),
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

  async proveCommitmentWithHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
  ) {
    return parseNativeJson(
      native.proveCommitmentWithHandle(
        backendProfile,
        manifestJson,
        artifactsRoot,
        commitmentHandle,
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

  async proveAndVerifyCommitmentHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
  ) {
    return unwrapNativeValue(
      native.proveAndVerifyCommitmentHandle(
        backendProfile,
        manifestJson,
        artifactsRoot,
        commitmentHandle,
      ),
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
  ) {
    return withWithdrawalWitnessRequestHandle(
      commitmentHandle,
      withdrawal,
      scope,
      withdrawalAmount,
      stateWitness,
      aspWitness,
      newSecretsHandle,
      async (requestHandle) =>
        unwrapNativeValue(
          native.proveAndVerifyWithdrawalHandle(
            backendProfile,
            manifestJson,
            artifactsRoot,
            requestHandle,
          ),
        ),
    );
  }

  async verifyCommitmentProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyCommitmentProofForRequestHandle(
        backendProfile,
        manifestJson,
        artifactsRoot,
        commitmentHandle,
        JSON.stringify(proof),
      ),
    );
  }

  async verifyRagequitProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  ) {
    return unwrapNativeValue(
      native.verifyRagequitProofForRequestHandle(
        backendProfile,
        manifestJson,
        artifactsRoot,
        commitmentHandle,
        JSON.stringify(proof),
      ),
    );
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
    return withWithdrawalWitnessRequestHandle(
      commitmentHandle,
      withdrawal,
      scope,
      withdrawalAmount,
      stateWitness,
      aspWitness,
      newSecretsHandle,
      async (requestHandle) =>
        unwrapNativeValue(
          native.verifyWithdrawalProofForRequestHandle(
            backendProfile,
            manifestJson,
            artifactsRoot,
            requestHandle,
            JSON.stringify(proof),
          ),
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

  async planVerifiedWithdrawalTransactionWithHandle(chainId, poolAddress, proofHandle) {
    return parseNativeJson(
      native.planVerifiedWithdrawalTransactionWithHandle(
        String(chainId),
        poolAddress,
        proofHandle,
      ),
    );
  }

  async planVerifiedRelayTransactionWithHandle(chainId, entrypointAddress, proofHandle) {
    return parseNativeJson(
      native.planVerifiedRelayTransactionWithHandle(
        String(chainId),
        entrypointAddress,
        proofHandle,
      ),
    );
  }

  async planVerifiedRagequitTransactionWithHandle(chainId, poolAddress, proofHandle) {
    return parseNativeJson(
      native.planVerifiedRagequitTransactionWithHandle(
        String(chainId),
        poolAddress,
        proofHandle,
      ),
    );
  }

  async preflightVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return unwrapNativeValue(
      native.preflightVerifiedWithdrawalTransactionWithHandle(
        String(chainId),
        poolAddress,
        rpcUrl,
        JSON.stringify(normalizeExecutionPolicy(policy, chainId)),
        proofHandle,
      ),
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
    return unwrapNativeValue(
      native.preflightVerifiedRelayTransactionWithHandle(
        String(chainId),
        entrypointAddress,
        poolAddress,
        rpcUrl,
        JSON.stringify(normalizeExecutionPolicy(policy, chainId)),
        proofHandle,
      ),
    );
  }

  async preflightVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  ) {
    return unwrapNativeValue(
      native.preflightVerifiedRagequitTransactionWithHandle(
        String(chainId),
        poolAddress,
        rpcUrl,
        JSON.stringify(normalizeExecutionPolicy(policy, chainId)),
        proofHandle,
      ),
    );
  }

  async finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return unwrapNativeValue(
      native.finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle),
    );
  }

  async submitPreflightedTransactionHandle(rpcUrl, preflightedHandle) {
    return unwrapNativeValue(
      native.submitPreflightedTransactionHandle(rpcUrl, preflightedHandle),
    );
  }

  async submitFinalizedPreflightedTransactionHandle(
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  ) {
    return unwrapNativeValue(
      native.submitFinalizedPreflightedTransactionHandle(
        rpcUrl,
        finalizedHandle,
        signedTransaction,
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

  async deriveRecoveryKeyset(mnemonic, policy) {
    return parseNativeJson(
      native.deriveRecoveryKeyset(mnemonic, JSON.stringify(policy)),
    );
  }

  async recoverAccountState(mnemonic, pools, policy) {
    return parseNativeJson(
      native.recoverAccountState(
        mnemonic,
        JSON.stringify(pools),
        JSON.stringify(policy),
      ),
    );
  }

  async recoverAccountStateWithKeyset(keyset, pools, policy) {
    return parseNativeJson(
      native.recoverAccountStateWithKeyset(
        JSON.stringify(keyset),
        JSON.stringify(pools),
        JSON.stringify(policy),
      ),
    );
  }
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

const defaultClient = createPrivacyPoolsSdkClient();

export const deriveMasterKeysHandle = (mnemonic) =>
  defaultClient.deriveMasterKeysHandle(mnemonic);
export const deriveMasterKeysHandleBytes = (mnemonicBytes) =>
  defaultClient.deriveMasterKeysHandleBytes(mnemonicBytes);
export const generateDepositSecretsHandle = (masterKeys, scope, index) =>
  defaultClient.generateDepositSecretsHandle(masterKeys, scope, index);
export const generateWithdrawalSecretsHandle = (masterKeys, label, index) =>
  defaultClient.generateWithdrawalSecretsHandle(masterKeys, label, index);
export const getCommitmentFromHandles = (value, label, secretsHandle) =>
  defaultClient.getCommitmentFromHandles(value, label, secretsHandle);
export const proveCommitmentWithHandle = (
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
) =>
  defaultClient.proveCommitmentWithHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
  );
export const proveWithdrawalWithHandles = (
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
) =>
  defaultClient.proveWithdrawalWithHandles(
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
  );
export const removeSecretHandle = (handle) => defaultClient.removeSecretHandle(handle);
export const clearSecretHandles = () => defaultClient.clearSecretHandles();
export const verifySignedManifest = (payloadJson, signatureHex, publicKeyHex) =>
  defaultClient.verifySignedManifest(payloadJson, signatureHex, publicKeyHex);
export const verifySignedManifestArtifacts = (
  payloadJson,
  signatureHex,
  publicKeyHex,
  artifacts,
) =>
  defaultClient.verifySignedManifestArtifacts(
    payloadJson,
    signatureHex,
    publicKeyHex,
    artifacts,
  );
export const proveAndVerifyCommitmentHandle = (
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
) =>
  defaultClient.proveAndVerifyCommitmentHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
  );
export const proveAndVerifyWithdrawalHandle = (
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
) =>
  defaultClient.proveAndVerifyWithdrawalHandle(
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
  );
export const verifyCommitmentProofForRequestHandle = (
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  proof,
) =>
  defaultClient.verifyCommitmentProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  );
export const verifyRagequitProofForRequestHandle = (
  backendProfile,
  manifestJson,
  artifactsRoot,
  commitmentHandle,
  proof,
) =>
  defaultClient.verifyRagequitProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    commitmentHandle,
    proof,
  );
export const verifyWithdrawalProofForRequestHandle = (
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
) =>
  defaultClient.verifyWithdrawalProofForRequestHandle(
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
export const planVerifiedWithdrawalTransactionWithHandle = (
  chainId,
  poolAddress,
  proofHandle,
) =>
  defaultClient.planVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );
export const planVerifiedRelayTransactionWithHandle = (
  chainId,
  entrypointAddress,
  proofHandle,
) =>
  defaultClient.planVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    proofHandle,
  );
export const planVerifiedRagequitTransactionWithHandle = (
  chainId,
  poolAddress,
  proofHandle,
) =>
  defaultClient.planVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );
export const preflightVerifiedWithdrawalTransactionWithHandle = (
  chainId,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) =>
  defaultClient.preflightVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );
export const preflightVerifiedRelayTransactionWithHandle = (
  chainId,
  entrypointAddress,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) =>
  defaultClient.preflightVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );
export const preflightVerifiedRagequitTransactionWithHandle = (
  chainId,
  poolAddress,
  rpcUrl,
  policy,
  proofHandle,
) =>
  defaultClient.preflightVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );
export const finalizePreflightedTransactionHandle = (
  rpcUrl,
  preflightedHandle,
) =>
  defaultClient.finalizePreflightedTransactionHandle(
    rpcUrl,
    preflightedHandle,
  );
export const submitPreflightedTransactionHandle = (
  rpcUrl,
  preflightedHandle,
) =>
  defaultClient.submitPreflightedTransactionHandle(
    rpcUrl,
    preflightedHandle,
  );
export const submitFinalizedPreflightedTransactionHandle = (
  rpcUrl,
  finalizedHandle,
  signedTransaction,
) =>
  defaultClient.submitFinalizedPreflightedTransactionHandle(
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  );
export const removeExecutionHandle = (handle) =>
  defaultClient.removeExecutionHandle(handle);
export const clearExecutionHandles = () =>
  defaultClient.clearExecutionHandles();
export const removeVerifiedProofHandle = (handle) =>
  defaultClient.removeVerifiedProofHandle(handle);
export const clearVerifiedProofHandles = () =>
  defaultClient.clearVerifiedProofHandles();

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

function encodeArtifactBytes(artifacts) {
  return artifacts.map((artifact) => ({
    kind: artifact.kind,
    bytesBase64: Buffer.from(artifact.bytes).toString("base64"),
  }));
}

function encodeSignedManifestArtifactBytes(artifacts) {
  return artifacts.map((artifact) => ({
    filename: artifact.filename,
    bytesBase64: Buffer.from(artifact.bytes).toString("base64"),
  }));
}

function normalizeExecutionPolicy(policy = {}, chainId) {
  return {
    expectedChainId: Number(policy.expectedChainId ?? policy.expected_chain_id ?? chainId),
    caller: String(policy.caller ?? ""),
    expectedPoolCodeHash:
      policy.expectedPoolCodeHash ?? policy.expected_pool_code_hash ?? null,
    expectedEntrypointCodeHash:
      policy.expectedEntrypointCodeHash ?? policy.expected_entrypoint_code_hash ?? null,
    readConsistency:
      policy.readConsistency ?? policy.read_consistency ?? "latest",
    maxFeeQuoteWei:
      policy.maxFeeQuoteWei ?? policy.max_fee_quote_wei ?? null,
    mode: policy.mode ?? "strict",
  };
}

function normalizeNodeBytes(bytes) {
  if (Buffer.isBuffer(bytes)) {
    return bytes;
  }

  if (bytes instanceof Uint8Array) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  if (bytes instanceof ArrayBuffer) {
    return Buffer.from(bytes);
  }

  if (Array.isArray(bytes)) {
    return Buffer.from(bytes);
  }

  throw new TypeError("mnemonic bytes must be a Buffer, Uint8Array, ArrayBuffer, or number[]");
}

function isPromiseLike(value) {
  return value !== null && typeof value === "object" && typeof value.then === "function";
}

function parseNativeJson(payload) {
  if (isPromiseLike(payload)) {
    return payload.then(parseNativeJson);
  }

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
  if (isPromiseLike(value)) {
    return value.then(unwrapNativeValue);
  }

  if (value instanceof Error) {
    throw value;
  }

  return value;
}
