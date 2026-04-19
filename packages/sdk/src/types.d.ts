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

export type ProvingBackend = "arkworks";
export type ArtifactKindName = "wasm" | "zkey" | "vkey";
export type CircuitName = "commitment" | "withdraw" | "merkleTree";
export type RuntimeName = "node" | "browser" | "browser-threaded";
export type ErrorCodeValue =
  | "compatibility_unsupported"
  | "missing_manifest"
  | "missing_artifact"
  | "chain-id-mismatch"
  | "invalid-signed-transaction"
  | "signer-requires-external-signing"
  | "unmatched-ragequit"
  | "registry-full"
  | "handle-already-registered"
  | "payload-too-large"
  | "invalid-mnemonic"
  | "invalid-relay-data"
  | "operation-failed";

export type ProvingResult = {
  backend: ProvingBackend;
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
  kind: ArtifactKindName;
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
  circuit: CircuitName;
  kind: ArtifactKindName;
  filename: string;
  path: string;
  exists: boolean;
  verified: boolean;
};

export type ResolvedArtifact = {
  circuit: CircuitName;
  kind: ArtifactKindName;
  filename: string;
  path: string;
};

export type ResolvedArtifactBundle = {
  version: string;
  circuit: CircuitName;
  artifacts: ResolvedArtifact[];
};

export type VerifiedArtifactDescriptor = {
  circuit: CircuitName;
  kind: ArtifactKindName;
  filename: string;
  sha256: string;
};

export type VerifiedArtifactBundle = {
  version: string;
  circuit: CircuitName;
  artifacts: VerifiedArtifactDescriptor[];
};

export type WithdrawalCircuitSessionHandle = {
  handle: string;
  circuit: CircuitName;
  artifactVersion: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
};

export type CommitmentCircuitSessionHandle = {
  handle: string;
  circuit: CircuitName;
  artifactVersion: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
};

export type RuntimeCapabilities = {
  runtime: RuntimeName;
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
  circuit?: CircuitName;
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

export type WebError =
  | { code: "chain-id-mismatch"; expected: number; actual: number }
  | { code: "invalid-signed-transaction"; message: string }
  | { code: "signer-requires-external-signing" }
  | { code: "unmatched-ragequit"; scope: string; label: string }
  | { code: "registry-full"; registry: string; capacity: number }
  | { code: "handle-already-registered"; handle: string }
  | { code: "payload-too-large"; field: string; limit: number; actual: number }
  | { code: "invalid-mnemonic"; message: string }
  | { code: "invalid-relay-data"; message: string }
  | { code: "operation-failed"; message: string };

export class BrowserRuntimeUnavailableError extends Error {}
export class SDKError extends Error {
  code: ErrorCodeValue;
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
export const circuitToAsset: Record<CircuitName, {
  wasm: string;
  vkey: string;
  zkey: string;
}>;
export const ErrorCode: {
  readonly CompatibilityUnsupported: "compatibility_unsupported";
  readonly MissingManifest: "missing_manifest";
  readonly MissingArtifact: "missing_artifact";
  readonly chainIdMismatch: "chain-id-mismatch";
  readonly invalidSignedTransaction: "invalid-signed-transaction";
  readonly signerRequiresExternalSigning: "signer-requires-external-signing";
  readonly unmatchedRagequit: "unmatched-ragequit";
  readonly registryFull: "registry-full";
  readonly handleAlreadyRegistered: "handle-already-registered";
  readonly payloadTooLarge: "payload-too-large";
  readonly invalidMnemonic: "invalid-mnemonic";
  readonly invalidRelayData: "invalid-relay-data";
  readonly operationFailed: "operation-failed";
};
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
