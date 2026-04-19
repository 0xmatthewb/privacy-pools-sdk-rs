export type MasterKeys = {
  masterNullifier: string;
  masterSecret: string;
};

export type Secrets = {
  nullifier: string;
  secret: string;
};

export type SecretHandle = string & {
  readonly __privacyPoolsSecretHandle: unique symbol;
};

export type VerifiedProofHandle = string & {
  readonly __privacyPoolsVerifiedProofHandle: unique symbol;
};

export type PreflightedTransactionHandle = string & {
  readonly __privacyPoolsPreflightedTransactionHandle: unique symbol;
};

export type FinalizedPreflightedTransactionHandle = string & {
  readonly __privacyPoolsFinalizedPreflightedTransactionHandle: unique symbol;
};

export type SubmittedPreflightedTransactionHandle = string & {
  readonly __privacyPoolsSubmittedPreflightedTransactionHandle: unique symbol;
};

export type Commitment = {
  hash: string;
  nullifierHash: string;
  precommitmentHash: string;
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

export type Withdrawal = {
  processooor: string;
  data: string;
};

export type SnarkJsProof = {
  piA: string[];
  piB: string[][];
  piC: string[];
  protocol: string;
  curve: string;
};

export type ProofBundle = {
  proof: SnarkJsProof;
  publicSignals: string[];
};

export type ProvingResult = {
  backend: string;
  proof: ProofBundle;
};

export type FormattedGroth16Proof = {
  pA: string[];
  pB: string[][];
  pC: string[];
  pubSignals: string[];
};

export type TransactionPlan = {
  kind: "withdraw" | "relay" | "ragequit";
  chainId: number;
  target: string;
  calldata: string;
  value: string;
  proof: FormattedGroth16Proof;
};

export type ExecutionPolicy = {
  expectedChainId?: number;
  expected_chain_id?: number;
  caller: string;
  expectedPoolCodeHash?: string | null;
  expected_pool_code_hash?: string | null;
  expectedEntrypointCodeHash?: string | null;
  expected_entrypoint_code_hash?: string | null;
  readConsistency?: "latest" | "finalized" | null;
  read_consistency?: "latest" | "finalized" | null;
  maxFeeQuoteWei?: string | null;
  max_fee_quote_wei?: string | null;
  mode?: "strict" | "insecure_dev" | null;
};

export type CodeHashCheck = {
  address: string;
  expectedCodeHash: string | null;
  actualCodeHash: string;
  matchesExpected: boolean | null;
};

export type RootCheck = {
  kind: "pool_state" | "asp";
  contractAddress: string;
  poolAddress: string;
  expectedRoot: string;
  actualRoot: string;
  matches: boolean;
};

export type ExecutionPreflightReport = {
  kind: "withdraw" | "relay" | "ragequit";
  caller: string;
  target: string;
  expectedChainId: number;
  actualChainId: number;
  chainIdMatches: boolean;
  simulated: boolean;
  estimatedGas: number;
  readConsistency?: "latest" | "finalized" | null;
  maxFeeQuoteWei?: string | null;
  mode?: "strict" | "insecure_dev" | null;
  codeHashChecks: CodeHashCheck[];
  rootChecks: RootCheck[];
};

export type PreflightedTransaction = {
  transaction: TransactionPlan;
  preflight: ExecutionPreflightReport;
};

export type FinalizedTransactionRequest = {
  kind: "withdraw" | "relay" | "ragequit";
  chainId: number;
  from: string;
  to: string;
  nonce: number;
  gasLimit: number;
  value: string;
  data: string;
  gasPrice: string | null;
  maxFeePerGas: string | null;
  maxPriorityFeePerGas: string | null;
};

export type FinalizedPreflightedTransaction = {
  preflighted: PreflightedTransaction;
  request: FinalizedTransactionRequest;
};

export type TransactionReceiptSummary = {
  transactionHash: string;
  blockHash: string | null;
  blockNumber: number | null;
  transactionIndex: number | null;
  success: boolean;
  gasUsed: number;
  effectiveGasPrice: string;
  from: string;
  to: string | null;
};

export type SubmittedPreflightedTransaction = {
  preflighted: PreflightedTransaction;
  receipt: TransactionReceiptSummary;
};

export type RootRead = {
  kind: "pool_state" | "asp";
  contractAddress: string;
  poolAddress: string;
  callData: string;
};

export type PoolEvent = {
  blockNumber: number;
  transactionIndex: number;
  logIndex: number;
  poolAddress: string;
  commitmentHash: string;
};

export type ChainConfig = {
  chainId: number;
  chain_id?: number;
  privacyPoolAddress?: string;
  privacy_pool_address?: string;
  startBlock?: number | bigint | string;
  start_block?: number | bigint | string;
  rpcUrl?: string;
  rpc_url?: string;
  client?: {
    getBlockNumber(): Promise<bigint | number | string>;
    getLogs(args: {
      address: string;
      event: unknown;
      fromBlock: bigint;
      toBlock: bigint;
    }): Promise<unknown[]>;
    getBalance?(args: { address: string }): Promise<bigint>;
  };
};

export type PoolInfo = {
  chainId: number;
  chain_id?: number;
  address?: string;
  poolAddress?: string;
  pool_address?: string;
  privacyPoolAddress?: string;
  deploymentBlock?: number | bigint | string;
  deployment_block?: number | bigint | string;
};

export type RecoveryPolicy = {
  compatibilityMode?: "strict" | "legacy";
  compatibility_mode?: "strict" | "legacy";
  failClosed?: boolean;
  fail_closed?: boolean;
};

export type RecoveryCheckpoint = {
  latestBlock: number;
  commitmentsSeen: number;
};

export type RecoveryField = string | bigint;

export type RecoveryKeyset = {
  safe: MasterKeys | V1MasterKeys;
  legacy?: MasterKeys | V1MasterKeys;
};

export type DepositEvent = {
  depositor?: string;
  commitment?: RecoveryField;
  commitmentHash?: RecoveryField;
  commitment_hash?: RecoveryField;
  label: RecoveryField;
  value: RecoveryField;
  precommitment?: RecoveryField;
  precommitmentHash?: RecoveryField;
  precommitment_hash?: RecoveryField;
  blockNumber: number | bigint;
  block_number?: number;
  transactionHash: string;
  transaction_hash?: string;
};

export type WithdrawalEvent = {
  withdrawn?: RecoveryField;
  withdrawnValue?: RecoveryField;
  withdrawn_value?: RecoveryField;
  spentNullifier?: RecoveryField;
  spentNullifierHash?: RecoveryField;
  spent_nullifier_hash?: RecoveryField;
  newCommitment?: RecoveryField;
  newCommitmentHash?: RecoveryField;
  new_commitment_hash?: RecoveryField;
  blockNumber: number | bigint;
  block_number?: number;
  transactionHash: string;
  transaction_hash?: string;
};

export type RagequitEvent = {
  ragequitter?: string;
  commitment?: RecoveryField;
  commitmentHash?: RecoveryField;
  commitment_hash?: RecoveryField;
  label: RecoveryField;
  value: RecoveryField;
  blockNumber: number | bigint;
  block_number?: number;
  transactionHash: string;
  transaction_hash?: string;
};

export type PoolRecoveryInput = {
  scope: RecoveryField;
  depositEvents?: DepositEvent[];
  deposit_events?: DepositEvent[];
  withdrawalEvents?: WithdrawalEvent[];
  withdrawal_events?: WithdrawalEvent[];
  ragequitEvents?: RagequitEvent[];
  ragequit_events?: RagequitEvent[];
};

export type RecoveredCommitment = {
  hash: string;
  value: string;
  label: string;
  nullifier: string;
  secret: string;
  blockNumber: number;
  transactionHash: string;
  isMigration: boolean;
};

export type RecoveredPoolAccount = {
  label: string;
  deposit: RecoveredCommitment;
  children: RecoveredCommitment[];
  ragequit?: RagequitEvent;
  isMigrated: boolean;
};

export type RecoveredScope = {
  scope: string;
  accounts: RecoveredPoolAccount[];
};

export type SpendableScope = {
  scope: string;
  commitments: RecoveredCommitment[];
};

export type RecoveredAccountState = {
  safeMasterKeys: MasterKeys;
  legacyMasterKeys?: MasterKeys;
  safeScopes: RecoveredScope[];
  legacyScopes: RecoveredScope[];
  safeSpendableCommitments: SpendableScope[];
  legacySpendableCommitments: SpendableScope[];
};

export type LogFetchConfig = {
  blockChunkSize: number;
  concurrency: number;
  chunkDelayMs: number;
  retryOnFailure: boolean;
  maxRetries: number;
  retryBaseDelayMs: number;
};

export type MerkleProof = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
};

export type CircuitMerkleWitness = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
  depth: number;
};

export type WithdrawalWitnessRequest = {
  commitment: Commitment;
  withdrawal: Withdrawal;
  scope: string;
  withdrawalAmount: string;
  stateWitness: CircuitMerkleWitness;
  aspWitness: CircuitMerkleWitness;
  newNullifier: string;
  newSecret: string;
};

export type WithdrawalCircuitInput = {
  withdrawnValue: string;
  stateRoot: string;
  stateTreeDepth: number;
  aspRoot: string;
  aspTreeDepth: number;
  context: string;
  label: string;
  existingValue: string;
  existingNullifier: string;
  existingSecret: string;
  newNullifier: string;
  newSecret: string;
  stateSiblings: string[];
  stateIndex: number;
  aspSiblings: string[];
  aspIndex: number;
};

export type CommitmentWitnessRequest = {
  commitment: Commitment;
};

export type CommitmentCircuitInput = {
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

export type ArtifactBytesInput = {
  kind: "wasm" | "zkey" | "vkey";
  bytes: Uint8Array | ArrayBuffer | number[];
};

export type ByteInput = Uint8Array | ArrayBuffer | number[];

export type SignedManifestArtifactBytesInput = {
  filename: string;
  bytes: Uint8Array | ArrayBuffer | number[];
};

export type SignedArtifactManifestMetadata = {
  ceremony?: string | null;
  build?: string | null;
  repository?: string | null;
  commit?: string | null;
};

export type SignedArtifactManifestPayload = {
  manifest: {
    version: string;
    artifacts: VerifiedArtifactDescriptor[];
  };
  metadata: SignedArtifactManifestMetadata;
};

export type VerifiedSignedArtifactManifest = {
  payload: SignedArtifactManifestPayload;
  artifactCount: number;
};

export type ArtifactStatus = {
  version: string;
  circuit: string;
  kind: string;
  filename: string;
  path: string;
  exists: boolean;
  verified: boolean;
};

export type ResolvedArtifact = {
  circuit: string;
  kind: string;
  filename: string;
  path: string;
};

export type ResolvedArtifactBundle = {
  version: string;
  circuit: string;
  artifacts: ResolvedArtifact[];
};

export type VerifiedArtifactDescriptor = {
  circuit: string;
  kind: string;
  filename: string;
  sha256: string;
};

export type VerifiedArtifactBundle = {
  version: string;
  circuit: string;
  artifacts: VerifiedArtifactDescriptor[];
};

export type WithdrawalCircuitSessionHandle = {
  handle: string;
  circuit: string;
  artifactVersion: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
};

export type CommitmentCircuitSessionHandle = {
  handle: string;
  circuit: string;
  artifactVersion: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
};

export type RuntimeCapabilities = {
  runtime: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
  workerAvailable: boolean;
  reason?: string;
};

export type ExperimentalThreadedInitialization = {
  threadedProvingEnabled: boolean;
  fallback: "stable-single-threaded" | null;
  reason?: string;
  threadCount?: number;
};

export type RuntimeStatusStage =
  | "preload"
  | "witness"
  | "witness-parse"
  | "witness-transfer"
  | "prove"
  | "verify"
  | "done"
  | "error";

export type RuntimeStatus = {
  stage: RuntimeStatusStage;
  circuit?: string;
  witnessSize?: number;
  witnessRuntime?: "probe-reuse" | "fallback";
  message?: string;
};

export type RuntimeStatusHandler = (status: RuntimeStatus) => void;

export type RuntimeStatusOptions =
  | RuntimeStatusHandler
  | {
      onStatus?: RuntimeStatusHandler;
    };

export class BrowserRuntimeUnavailableError extends Error {}
export class SDKError extends Error {
  code: string;
  details?: unknown;
}
export class CompatibilityError extends SDKError {}
export class ProofError extends SDKError {}
export class AccountError extends SDKError {}
export class DataError extends SDKError {}
export class ContractError extends SDKError {}
export class CircuitInitialization extends CompatibilityError {}
export class FetchArtifact extends CompatibilityError {}
export class PrivacyPoolError extends SDKError {}
export class InvalidRpcUrl extends CompatibilityError {}

export const Version: {
  readonly Latest: "latest";
};
export const CircuitName: {
  readonly Commitment: "commitment";
  readonly MerkleTree: "merkleTree";
  readonly Withdraw: "withdraw";
};
export const circuitToAsset: Record<string, {
  wasm: string;
  vkey: string;
  zkey: string;
}>;
export const ErrorCode: Record<string, string>;
export const DEFAULT_LOG_FETCH_CONFIG: Readonly<LogFetchConfig>;

export type V1Precommitment = {
  hash: bigint;
  nullifier: bigint;
  secret: bigint;
};

export type V1MasterKeys = {
  masterNullifier: bigint;
  masterSecret: bigint;
};

export type V1Secrets = {
  nullifier: bigint;
  secret: bigint;
};

export type V1Commitment = {
  hash: bigint;
  nullifierHash: bigint;
  preimage: {
    value: bigint;
    label: bigint;
    precommitment: V1Precommitment;
  };
};

export type V1MerkleProof = {
  root: bigint;
  leaf: bigint;
  index: number;
  siblings: bigint[];
};

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
