import { MasterKeys, Secrets, SecretHandle, VerifiedProofHandle, PreflightedTransactionHandle, FinalizedPreflightedTransactionHandle, SubmittedPreflightedTransactionHandle, Commitment, Withdrawal, SnarkJsProof, ProofBundle, ProvingResult, FormattedGroth16Proof, TransactionPlan, ExecutionPolicy, CodeHashCheck, RootCheck, ExecutionPreflightReport, PreflightedTransaction, FinalizedTransactionRequest, FinalizedPreflightedTransaction, TransactionReceiptSummary, SubmittedPreflightedTransaction, RootRead, PoolEvent, ChainConfig, PoolInfo, RecoveryPolicy, RecoveryCheckpoint, RecoveryField, RecoveryKeyset, DepositEvent, WithdrawalEvent, RagequitEvent, PoolRecoveryInput, RecoveredCommitment, RecoveredPoolAccount, RecoveredScope, SpendableScope, RecoveredAccountState, LogFetchConfig, MerkleProof, CircuitMerkleWitness, WithdrawalWitnessRequest, WithdrawalCircuitInput, CommitmentWitnessRequest, CommitmentCircuitInput, ArtifactBytesInput, ByteInput, SignedManifestArtifactBytesInput, SignedArtifactManifestMetadata, SignedArtifactManifestPayload, VerifiedSignedArtifactManifest, ArtifactStatus, ResolvedArtifact, ResolvedArtifactBundle, VerifiedArtifactDescriptor, VerifiedArtifactBundle, WithdrawalCircuitSessionHandle, CommitmentCircuitSessionHandle, RuntimeCapabilities, ExperimentalThreadedInitialization, RuntimeStatusStage, RuntimeStatus, RuntimeStatusHandler, RuntimeStatusOptions, BrowserRuntimeUnavailableError, SDKError, CompatibilityError, ProofError, AccountError, DataError, ContractError, CircuitInitialization, FetchArtifact, PrivacyPoolError, InvalidRpcUrl, Version, CircuitName, circuitToAsset, ErrorCode, DEFAULT_LOG_FETCH_CONFIG, V1Precommitment, V1MasterKeys, V1Secrets, V1Commitment, V1MerkleProof } from './types';
export * from './types';

export class Circuits {
  constructor(options?: {
    baseUrl?: string;
    artifactsRoot?: string;
    signedManifestJson?: string;
    withdrawalSignedManifestJson?: string;
    commitmentSignedManifestJson?: string;
    signedManifestPublicKey?: string;
    client?: PrivacyPoolsSdkClient;
  });
  downloadArtifacts(version?: string): Promise<Record<string, Record<string, Uint8Array>>>;
  initArtifacts(version?: string): Promise<void>;
  getVerificationKey(circuitName: string, version?: string): Promise<Uint8Array>;
  getProvingKey(circuitName: string, version?: string): Promise<Uint8Array>;
  getWasm(circuitName: string, version?: string): Promise<Uint8Array>;
  artifactInputsFor(circuitName: string, version?: string): Promise<ArtifactBytesInput[]>;
}

export class BlockchainProvider {
  constructor(
    rpcUrl: string,
    options?: {
      chain?: unknown;
      client?: { getBalance(args: { address: string }): Promise<bigint> };
    },
  );
  getBalance(address: string): Promise<bigint>;
}

export class CommitmentService {
  constructor(circuits: Circuits);
  proveCommitment(
    value: bigint | string,
    label: bigint | string,
    nullifier: bigint | string,
    secret: bigint | string,
  ): Promise<ProofBundle>;
  verifyCommitment(proof: ProofBundle): Promise<boolean>;
}

export class WithdrawalService {
  constructor(circuits: Circuits);
  proveWithdrawal(commitment: V1Commitment | Commitment, input: unknown): Promise<ProofBundle>;
  verifyWithdrawal(proof: ProofBundle): Promise<boolean>;
}

export class PrivacyPoolSDK {
  constructor(circuits: Circuits);
  proveCommitment(
    value: bigint | string,
    label: bigint | string,
    nullifier: bigint | string,
    secret: bigint | string,
  ): Promise<ProofBundle>;
  verifyCommitment(proof: ProofBundle): Promise<boolean>;
  proveWithdrawal(commitment: V1Commitment | Commitment, input: unknown): Promise<ProofBundle>;
  verifyWithdrawal(proof: ProofBundle): Promise<boolean>;
  createContractInstance(...args: unknown[]): never;
}

export class AccountService {
  constructor(...args: unknown[]);
  getSpendableCommitments(
    state: RecoveredAccountState,
    mode?: "safe" | "legacy",
  ): SpendableScope[];
  sync(): never;
  checkpointRecovery(
    events: PoolEvent[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveryCheckpoint>;
  deriveRecoveryKeyset(
    mnemonic: string,
    policy?: RecoveryPolicy,
  ): Promise<RecoveryKeyset>;
  recoverAccountState(
    mnemonic: string,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
  recoverAccountStateWithKeyset(
    keyset: RecoveryKeyset,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
}

export class DataService {
  constructor(
    chainConfigs?: ChainConfig[],
    logFetchConfig?: Map<number, Partial<LogFetchConfig>> | Record<string, Partial<LogFetchConfig>>,
    options?: { client?: PrivacyPoolsSdkClient },
  );
  getDeposits(pool: PoolInfo): Promise<DepositEvent[]>;
  getWithdrawals(
    pool: PoolInfo,
    fromBlock?: number | bigint | string,
  ): Promise<WithdrawalEvent[]>;
  getRagequits(
    pool: PoolInfo,
    fromBlock?: number | bigint | string,
  ): Promise<RagequitEvent[]>;
  checkpointRecovery(
    events: PoolEvent[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveryCheckpoint>;
  deriveRecoveryKeyset(
    mnemonic: string,
    policy?: RecoveryPolicy,
  ): Promise<RecoveryKeyset>;
  recoverAccountState(
    mnemonic: string,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
  recoverAccountStateWithKeyset(
    keyset: RecoveryKeyset,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
}

export class ContractInteractionsService {
  constructor(...args: unknown[]);
  getStateRoot(poolAddress: string): Promise<RootRead>;
  getScopeData(entrypointAddress: string, poolAddress: string): Promise<RootRead>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planWithdrawalTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planRelayTransaction(
    chainId: number | string | bigint,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string | bigint,
  ): Promise<TransactionPlan>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planRagequitTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  isCurrentStateRoot(
    expectedRoot: string | bigint,
    currentRoot: string | bigint,
  ): Promise<boolean>;
  formatGroth16Proof(proof: ProofBundle): Promise<FormattedGroth16Proof>;
}

export class PrivacyPoolsSdkClient {
  getRuntimeCapabilities(): Promise<RuntimeCapabilities>;
  getVersion(): Promise<string>;
  getStableBackendName(): Promise<string>;
  supportsExperimentalThreadedBrowserProving(): Promise<boolean>;
  deriveMasterKeysHandleBytes(mnemonicBytes: ByteInput): Promise<SecretHandle>;
  generateDepositSecretsHandle(
    masterKeys: MasterKeys | V1MasterKeys | SecretHandle,
    scope: string,
    index: string,
  ): Promise<SecretHandle>;
  generateWithdrawalSecretsHandle(
    masterKeys: MasterKeys | V1MasterKeys | SecretHandle,
    label: string,
    index: string,
  ): Promise<SecretHandle>;
  getCommitment(
    value: string,
    label: string,
    nullifier: string,
    secret: string,
  ): Promise<Commitment>;
  getCommitmentFromHandles(
    value: string,
    label: string,
    secretsHandle: SecretHandle,
  ): Promise<SecretHandle>;
  removeSecretHandle(handle: SecretHandle): Promise<boolean>;
  removeVerifiedProofHandle(handle: VerifiedProofHandle): Promise<boolean>;
  clearSecretHandles(): Promise<boolean>;
  clearVerifiedProofHandles(): Promise<boolean>;
  dispose(options?: { terminate?: boolean }): Promise<unknown>;
  calculateWithdrawalContext(
    withdrawal: Withdrawal,
    scope: string,
  ): Promise<string>;
  generateMerkleProof(leaves: string[], leaf: string): Promise<MerkleProof>;
  buildCircuitMerkleWitness(
    proof: MerkleProof,
    depth: number,
  ): Promise<CircuitMerkleWitness>;
  buildWithdrawalCircuitInput(
    request: WithdrawalWitnessRequest,
  ): Promise<WithdrawalCircuitInput>;
  buildCommitmentCircuitInput(
    request: CommitmentWitnessRequest,
  ): Promise<CommitmentCircuitInput>;
  verifyArtifactBytes(
    manifestJson: string,
    circuit: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<VerifiedArtifactBundle>;
  verifySignedManifest(
    payloadJson: string,
    signatureHex: string,
    publicKeyHex: string,
  ): Promise<VerifiedSignedArtifactManifest>;
  verifySignedManifestArtifacts(
    payloadJson: string,
    signatureHex: string,
    publicKeyHex: string,
    artifacts: SignedManifestArtifactBytesInput[],
  ): Promise<VerifiedSignedArtifactManifest>;
  clearCircuitSessionCache(): Promise<void>;
  formatGroth16ProofBundle(proof: ProofBundle): Promise<FormattedGroth16Proof>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planWithdrawalTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planRelayTransaction(
    chainId: number | string | bigint,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string | bigint,
  ): Promise<TransactionPlan>;
  /**
   * Low-level compatibility/offline formatting API. For execution flows,
   * prefer verified-proof handle planners.
   */
  planRagequitTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  planVerifiedWithdrawalTransactionWithHandle(
    chainId: number | string | bigint,
    poolAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  planVerifiedRelayTransactionWithHandle(
    chainId: number | string | bigint,
    entrypointAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  planVerifiedRagequitTransactionWithHandle(
    chainId: number | string | bigint,
    poolAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  preflightVerifiedWithdrawalTransactionWithHandle(
    chainId: number | string | bigint,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
    proofHandle: VerifiedProofHandle,
  ): Promise<PreflightedTransactionHandle>;
  preflightVerifiedRelayTransactionWithHandle(
    chainId: number | string | bigint,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
    proofHandle: VerifiedProofHandle,
  ): Promise<PreflightedTransactionHandle>;
  preflightVerifiedRagequitTransactionWithHandle(
    chainId: number | string | bigint,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
    proofHandle: VerifiedProofHandle,
  ): Promise<PreflightedTransactionHandle>;
  finalizePreflightedTransactionHandle(
    rpcUrl: string,
    preflightedHandle: PreflightedTransactionHandle,
  ): Promise<FinalizedPreflightedTransactionHandle>;
  submitPreflightedTransactionHandle(
    rpcUrl: string,
    preflightedHandle: PreflightedTransactionHandle,
  ): Promise<SubmittedPreflightedTransactionHandle>;
  submitFinalizedPreflightedTransactionHandle(
    rpcUrl: string,
    finalizedHandle: FinalizedPreflightedTransactionHandle,
    signedTransaction: string,
  ): Promise<SubmittedPreflightedTransactionHandle>;
  removeExecutionHandle(
    handle:
      | PreflightedTransactionHandle
      | FinalizedPreflightedTransactionHandle
      | SubmittedPreflightedTransactionHandle,
  ): Promise<boolean>;
  clearExecutionHandles(): Promise<boolean>;
  planPoolStateRootRead(poolAddress: string): Promise<RootRead>;
  planAspRootRead(entrypointAddress: string, poolAddress: string): Promise<RootRead>;
  isCurrentStateRoot(
    expectedRoot: string | bigint,
    currentRoot: string | bigint,
  ): Promise<boolean>;
  checkpointRecovery(
    events: PoolEvent[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveryCheckpoint>;
  deriveRecoveryKeyset(
    mnemonic: string,
    policy?: RecoveryPolicy,
  ): Promise<RecoveryKeyset>;
  recoverAccountState(
    mnemonic: string,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
  recoverAccountStateWithKeyset(
    keyset: RecoveryKeyset,
    pools: PoolRecoveryInput[],
    policy?: RecoveryPolicy,
  ): Promise<RecoveredAccountState>;
}

export function createPrivacyPoolsSdkClient(): PrivacyPoolsSdkClient;
export function createWorkerClient(worker: Worker): PrivacyPoolsSdkClient;
export function getRuntimeCapabilities(): RuntimeCapabilities;
export function clearBrowserCircuitSessionCache(): Promise<void>;
export function supportsExperimentalThreadedBrowserProving(): boolean;
export function initializeExperimentalThreadedBrowserProving(options?: {
  threadCount?: number;
}): Promise<ExperimentalThreadedInitialization>;
export function deriveMasterKeysHandleBytes(mnemonicBytes: ByteInput): Promise<SecretHandle>;
export function generateDepositSecretsHandle(
  masterKeys: MasterKeys | V1MasterKeys | SecretHandle,
  scope: string | bigint,
  index: string | bigint,
): Promise<SecretHandle>;
export function generateWithdrawalSecretsHandle(
  masterKeys: MasterKeys | V1MasterKeys | SecretHandle,
  label: string | bigint,
  index: string | bigint,
): Promise<SecretHandle>;
export function getCommitmentFromHandles(
  value: string | bigint,
  label: string | bigint,
  secretsHandle: SecretHandle,
): Promise<SecretHandle>;
export function removeSecretHandle(handle: SecretHandle): Promise<boolean>;
export function removeVerifiedProofHandle(handle: VerifiedProofHandle): Promise<boolean>;
export function clearSecretHandles(): Promise<boolean>;
export function clearVerifiedProofHandles(): Promise<boolean>;
export function verifySignedManifest(
  payloadJson: string,
  signatureHex: string,
  publicKeyHex: string,
): Promise<VerifiedSignedArtifactManifest>;
export function verifySignedManifestArtifacts(
  payloadJson: string,
  signatureHex: string,
  publicKeyHex: string,
  artifacts: SignedManifestArtifactBytesInput[],
): Promise<VerifiedSignedArtifactManifest>;
export function getCommitment(
  value: string | bigint,
  label: string | bigint,
  nullifier: string | bigint,
  secret: string | bigint,
): Promise<V1Commitment>;
export function generateMerkleProof(
  leaves: Array<string | bigint>,
  leaf: string | bigint,
): Promise<V1MerkleProof>;
export function calculateContext(
  withdrawal: Withdrawal,
  scope: string | bigint,
): Promise<string>;
export function bigintToHash(value: string | bigint): string;
export function bigintToHex(value?: string | bigint | null): string;
export function checkpointRecovery(
  events: PoolEvent[],
  policy?: RecoveryPolicy,
): Promise<RecoveryCheckpoint>;
export function deriveRecoveryKeyset(
  mnemonic: string,
  policy?: RecoveryPolicy,
): Promise<RecoveryKeyset>;
export function recoverAccountState(
  mnemonic: string,
  pools: PoolRecoveryInput[],
  policy?: RecoveryPolicy,
): Promise<RecoveredAccountState>;
export function recoverAccountStateWithKeyset(
  keyset: RecoveryKeyset,
  pools: PoolRecoveryInput[],
  policy?: RecoveryPolicy,
): Promise<RecoveredAccountState>;
export function formatGroth16ProofBundle(
  proof: ProofBundle,
): Promise<FormattedGroth16Proof>;
export function hashPrecommitment(
  nullifier: string | bigint,
  secret: string | bigint,
): Promise<bigint>;
export function isCurrentStateRoot(
  expectedRoot: string | bigint,
  currentRoot: string | bigint,
): Promise<boolean>;
export function planAspRootRead(
  entrypointAddress: string,
  poolAddress: string,
): Promise<RootRead>;
export function planPoolStateRootRead(poolAddress: string): Promise<RootRead>;
/**
 * Low-level compatibility/offline formatting API. For execution flows,
 * prefer verified-proof handle planners.
 */
export function planRagequitTransaction(
  chainId: number | string | bigint,
  poolAddress: string,
  proof: ProofBundle,
): Promise<TransactionPlan>;
export function planVerifiedRagequitTransactionWithHandle(
  chainId: number | string | bigint,
  poolAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan>;
export function preflightVerifiedRagequitTransactionWithHandle(
  chainId: number | string | bigint,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle>;
/**
 * Low-level compatibility/offline formatting API. For execution flows,
 * prefer verified-proof handle planners.
 */
export function planRelayTransaction(
  chainId: number | string | bigint,
  entrypointAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
  scope: string | bigint,
): Promise<TransactionPlan>;
export function planVerifiedRelayTransactionWithHandle(
  chainId: number | string | bigint,
  entrypointAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan>;
export function preflightVerifiedRelayTransactionWithHandle(
  chainId: number | string | bigint,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle>;
/**
 * Low-level compatibility/offline formatting API. For execution flows,
 * prefer verified-proof handle planners.
 */
export function planWithdrawalTransaction(
  chainId: number | string | bigint,
  poolAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
): Promise<TransactionPlan>;
export function planVerifiedWithdrawalTransactionWithHandle(
  chainId: number | string | bigint,
  poolAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan>;
export function preflightVerifiedWithdrawalTransactionWithHandle(
  chainId: number | string | bigint,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle>;
export function finalizePreflightedTransactionHandle(
  rpcUrl: string,
  preflightedHandle: PreflightedTransactionHandle,
): Promise<FinalizedPreflightedTransactionHandle>;
export function submitPreflightedTransactionHandle(
  rpcUrl: string,
  preflightedHandle: PreflightedTransactionHandle,
): Promise<SubmittedPreflightedTransactionHandle>;
export function submitFinalizedPreflightedTransactionHandle(
  rpcUrl: string,
  finalizedHandle: FinalizedPreflightedTransactionHandle,
  signedTransaction: string,
): Promise<SubmittedPreflightedTransactionHandle>;
export function removeExecutionHandle(
  handle:
    | PreflightedTransactionHandle
    | FinalizedPreflightedTransactionHandle
    | SubmittedPreflightedTransactionHandle,
): Promise<boolean>;
export function clearExecutionHandles(): Promise<boolean>;
