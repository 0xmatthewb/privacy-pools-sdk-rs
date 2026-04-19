import * as unsafe from "./index.mjs";

function unwrapClient(client) {
  return client?._unsafeClient ?? client;
}

function assertSafeCircuitOptions(options = {}) {
  const usesTestingOnlyArtifacts =
    options.allowUnsignedArtifactsForTesting === true ||
    options.manifestJson != null ||
    options.withdrawalManifestJson != null ||
    options.withdrawManifestJson != null ||
    options.commitmentManifestJson != null;

  if (usesTestingOnlyArtifacts) {
    throw new Error(
      "raw manifest artifact loading is only available from @0xmatthewb/privacy-pools-sdk/testing",
    );
  }
}

export function getRuntimeCapabilities() {
  return unsafe.getRuntimeCapabilities();
}

export function createWorkerClient() {
  return unsafe.createWorkerClient();
}

const SAFE_CLIENT_METHODS = [
  "getRuntimeCapabilities",
  "getVersion",
  "getStableBackendName",
  "deriveMasterKeysHandleBytes",
  "generateDepositSecretsHandle",
  "generateWithdrawalSecretsHandle",
  "getCommitment",
  "getCommitmentFromHandles",
  "removeSecretHandle",
  "clearSecretHandles",
  "removeVerifiedProofHandle",
  "clearVerifiedProofHandles",
  "removeExecutionHandle",
  "clearExecutionHandles",
  "dispose",
  "calculateWithdrawalContext",
  "generateMerkleProof",
  "buildCircuitMerkleWitness",
  "buildWithdrawalCircuitInput",
  "buildCommitmentCircuitInput",
  "verifyArtifactBytes",
  "verifySignedManifest",
  "verifySignedManifestArtifacts",
  "formatGroth16ProofBundle",
  "planWithdrawalTransaction",
  "planRelayTransaction",
  "planRagequitTransaction",
  "planVerifiedWithdrawalTransactionWithHandle",
  "planVerifiedRelayTransactionWithHandle",
  "planVerifiedRagequitTransactionWithHandle",
  "preflightVerifiedWithdrawalTransactionWithHandle",
  "preflightVerifiedRelayTransactionWithHandle",
  "preflightVerifiedRagequitTransactionWithHandle",
  "finalizePreflightedTransactionHandle",
  "submitPreflightedTransactionHandle",
  "submitFinalizedPreflightedTransactionHandle",
  "planPoolStateRootRead",
  "planAspRootRead",
  "isCurrentStateRoot",
  "checkpointRecovery",
  "deriveRecoveryKeyset",
  "recoverAccountState",
  "recoverAccountStateWithKeyset",
];

export class PrivacyPoolsSdkClient {
  constructor(unsafeClient = new unsafe.PrivacyPoolsSdkClient()) {
    this._unsafeClient = unsafeClient;
  }
}

for (const methodName of SAFE_CLIENT_METHODS) {
  Object.defineProperty(PrivacyPoolsSdkClient.prototype, methodName, {
    value(...args) {
      return this._unsafeClient[methodName](...args);
    },
  });
}

export class Circuits extends unsafe.Circuits {
  constructor(options = {}) {
    assertSafeCircuitOptions(options);
    super({
      ...options,
      client: unwrapClient(options.client),
    });
  }
}

export function createPrivacyPoolsSdkClient() {
  return new PrivacyPoolsSdkClient();
}

const defaultClient = createPrivacyPoolsSdkClient();

export const deriveMasterKeysHandleBytes = (mnemonicBytes) =>
  defaultClient.deriveMasterKeysHandleBytes(mnemonicBytes);
export const generateDepositSecretsHandle = (masterKeys, scope, index) =>
  defaultClient.generateDepositSecretsHandle(masterKeys, scope, index);
export const generateWithdrawalSecretsHandle = (masterKeys, label, index) =>
  defaultClient.generateWithdrawalSecretsHandle(masterKeys, label, index);
export const getCommitmentFromHandles = (value, label, secretsHandle) =>
  defaultClient.getCommitmentFromHandles(value, label, secretsHandle);
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
export const finalizePreflightedTransactionHandle = (rpcUrl, preflightedHandle) =>
  defaultClient.finalizePreflightedTransactionHandle(rpcUrl, preflightedHandle);
export const submitPreflightedTransactionHandle = (rpcUrl, preflightedHandle) =>
  defaultClient.submitPreflightedTransactionHandle(rpcUrl, preflightedHandle);
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
export const clearExecutionHandles = () => defaultClient.clearExecutionHandles();
export const removeVerifiedProofHandle = (handle) =>
  defaultClient.removeVerifiedProofHandle(handle);
export const clearVerifiedProofHandles = () =>
  defaultClient.clearVerifiedProofHandles();

export {
  AccountError,
  AccountService,
  BlockchainProvider,
  CircuitInitialization,
  CircuitName,
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
  generateMerkleProof,
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
} from "./index.mjs";
