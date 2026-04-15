export type MasterKeys = {
  masterNullifier: string;
  masterSecret: string;
};

export type Secrets = {
  nullifier: string;
  secret: string;
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

export type RuntimeStatusStage =
  | "preload"
  | "witness"
  | "prove"
  | "verify"
  | "done"
  | "error";

export type RuntimeStatus = {
  stage: RuntimeStatusStage;
  circuit?: string;
  witnessSize?: number;
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

export type V1Commitment = Commitment & {
  hash: bigint;
  nullifierHash: bigint;
  preimage: {
    value: bigint;
    label: bigint;
    precommitment: V1Precommitment;
  };
};

export class Circuits {
  constructor(options?: {
    baseUrl?: string;
    artifactsRoot?: string;
    manifestJson?: string;
    withdrawalManifestJson?: string;
    withdrawManifestJson?: string;
    commitmentManifestJson?: string;
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
  planWithdrawalTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  planRelayTransaction(
    chainId: number | string | bigint,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string | bigint,
  ): Promise<TransactionPlan>;
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
  fastBackendSupportedOnTarget(): Promise<boolean>;
  deriveMasterKeys(mnemonic: string): Promise<MasterKeys>;
  deriveDepositSecrets(
    masterKeys: MasterKeys,
    scope: string,
    index: string,
  ): Promise<Secrets>;
  deriveWithdrawalSecrets(
    masterKeys: MasterKeys,
    label: string,
    index: string,
  ): Promise<Secrets>;
  getCommitment(
    value: string,
    label: string,
    nullifier: string,
    secret: string,
  ): Promise<Commitment>;
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
  getArtifactStatuses(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<ArtifactStatus[]>;
  getCommitmentArtifactStatuses(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<ArtifactStatus[]>;
  resolveVerifiedArtifactBundle(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<ResolvedArtifactBundle>;
  resolveVerifiedCommitmentArtifactBundle(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<ResolvedArtifactBundle>;
  verifyArtifactBytes(
    manifestJson: string,
    circuit: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<VerifiedArtifactBundle>;
  prepareWithdrawalCircuitSession(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<WithdrawalCircuitSessionHandle>;
  prepareWithdrawalCircuitSessionFromBytes(
    manifestJson: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<WithdrawalCircuitSessionHandle>;
  removeWithdrawalCircuitSession(sessionHandle: string): Promise<boolean>;
  prepareCommitmentCircuitSession(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<CommitmentCircuitSessionHandle>;
  prepareCommitmentCircuitSessionFromBytes(
    manifestJson: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<CommitmentCircuitSessionHandle>;
  removeCommitmentCircuitSession(sessionHandle: string): Promise<boolean>;
  clearCircuitSessionCache(): Promise<void>;
  proveWithdrawal(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    status?: RuntimeStatusOptions,
  ): Promise<ProvingResult>;
  proveWithdrawalWithSession(
    backendProfile: "stable" | "fast",
    sessionHandle: string,
    request: WithdrawalWitnessRequest,
    status?: RuntimeStatusOptions,
  ): Promise<ProvingResult>;
  verifyWithdrawalProof(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  verifyWithdrawalProofWithSession(
    backendProfile: "stable" | "fast",
    sessionHandle: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  proveCommitment(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: CommitmentWitnessRequest,
    status?: RuntimeStatusOptions,
  ): Promise<ProvingResult>;
  proveCommitmentWithSession(
    backendProfile: "stable" | "fast",
    sessionHandle: string,
    request: CommitmentWitnessRequest,
    status?: RuntimeStatusOptions,
  ): Promise<ProvingResult>;
  verifyCommitmentProof(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  verifyCommitmentProofWithSession(
    backendProfile: "stable" | "fast",
    sessionHandle: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  formatGroth16ProofBundle(proof: ProofBundle): Promise<FormattedGroth16Proof>;
  planWithdrawalTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  planRelayTransaction(
    chainId: number | string | bigint,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string | bigint,
  ): Promise<TransactionPlan>;
  planRagequitTransaction(
    chainId: number | string | bigint,
    poolAddress: string,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
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
export function generateMasterKeys(mnemonic: string): Promise<V1MasterKeys>;
export function generateDepositSecrets(
  masterKeys: MasterKeys | V1MasterKeys,
  scope: string | bigint,
  index: string | bigint,
): Promise<V1Secrets>;
export function generateDepositSecrets(
  masterNullifier: string | bigint,
  masterSecret: string | bigint,
  scope: string | bigint,
  index: string | bigint,
): Promise<V1Secrets>;
export function generateWithdrawalSecrets(
  masterKeys: MasterKeys | V1MasterKeys,
  label: string | bigint,
  index: string | bigint,
): Promise<V1Secrets>;
export function generateWithdrawalSecrets(
  masterNullifier: string | bigint,
  masterSecret: string | bigint,
  label: string | bigint,
  index: string | bigint,
): Promise<V1Secrets>;
export function getCommitment(
  value: string | bigint,
  label: string | bigint,
  nullifier: string | bigint,
  secret: string | bigint,
): Promise<V1Commitment>;
export function generateMerkleProof(
  leaves: Array<string | bigint>,
  leaf: string | bigint,
): Promise<MerkleProof>;
export function calculateContext(
  withdrawal: Withdrawal,
  scope: string | bigint,
): Promise<string>;
export function bigintToHash(value: string | bigint): bigint;
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
export function planRagequitTransaction(
  chainId: number | string | bigint,
  poolAddress: string,
  proof: ProofBundle,
): Promise<TransactionPlan>;
export function planRelayTransaction(
  chainId: number | string | bigint,
  entrypointAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
  scope: string | bigint,
): Promise<TransactionPlan>;
export function planWithdrawalTransaction(
  chainId: number | string | bigint,
  poolAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
): Promise<TransactionPlan>;
