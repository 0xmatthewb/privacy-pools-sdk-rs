import { NativeModules, Platform } from "react-native";

type RootRead = {
  kind: string;
  contract_address: string;
  pool_address: string;
  call_data: string;
};

type MasterKeys = {
  master_nullifier: string;
  master_secret: string;
};

type Secrets = {
  nullifier: string;
  secret: string;
};

type Commitment = {
  hash: string;
  nullifier_hash: string;
  precommitment_hash: string;
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

type Withdrawal = {
  processooor: string;
  data: number[];
};

type SnarkJsProof = {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
};

type ProofBundle = {
  proof: SnarkJsProof;
  public_signals: string[];
};

type ProvingResult = {
  backend: "arkworks" | "rapidsnark";
  proof: ProofBundle;
};

type FormattedGroth16Proof = {
  p_a: string[];
  p_b: string[][];
  p_c: string[];
  pub_signals: string[];
};

type TransactionPlan = {
  kind: "withdraw" | "relay";
  chain_id: number;
  target: string;
  calldata: string;
  value: string;
  proof: FormattedGroth16Proof;
};

type ExecutionPolicy = {
  expected_chain_id: number;
  caller: string;
  expected_pool_code_hash?: string | null;
  expected_entrypoint_code_hash?: string | null;
};

type CodeHashCheck = {
  address: string;
  expected_code_hash?: string | null;
  actual_code_hash: string;
  matches_expected?: boolean | null;
};

type RootCheck = {
  kind: string;
  contract_address: string;
  pool_address: string;
  expected_root: string;
  actual_root: string;
  matches: boolean;
};

type ExecutionPreflightReport = {
  kind: "withdraw" | "relay";
  caller: string;
  target: string;
  expected_chain_id: number;
  actual_chain_id: number;
  chain_id_matches: boolean;
  simulated: boolean;
  estimated_gas: number;
  code_hash_checks: CodeHashCheck[];
  root_checks: RootCheck[];
};

type PreparedTransactionExecution = {
  proving: ProvingResult;
  transaction: TransactionPlan;
  preflight: ExecutionPreflightReport;
};

type FinalizedTransactionRequest = {
  kind: "withdraw" | "relay";
  chain_id: number;
  from: string;
  to: string;
  nonce: number;
  gas_limit: number;
  value: string;
  data: string;
  gas_price?: string | null;
  max_fee_per_gas?: string | null;
  max_priority_fee_per_gas?: string | null;
};

type FinalizedTransactionExecution = {
  prepared: PreparedTransactionExecution;
  request: FinalizedTransactionRequest;
};

type SignerHandle = {
  handle: string;
  address: string;
  kind: "local_dev" | "host_provided" | "mobile_secure_storage";
};

type TransactionReceiptSummary = {
  transaction_hash: string;
  block_hash?: string | null;
  block_number?: number | null;
  transaction_index?: number | null;
  success: boolean;
  gas_used: number;
  effective_gas_price: string;
  from: string;
  to?: string | null;
};

type SubmittedTransactionExecution = {
  prepared: PreparedTransactionExecution;
  receipt: TransactionReceiptSummary;
};

type ArtifactVerification = {
  version: string;
  circuit: string;
  kind: string;
  filename: string;
};

type ArtifactStatus = {
  version: string;
  circuit: string;
  kind: string;
  filename: string;
  path: string;
  exists: boolean;
  verified: boolean;
};

type ResolvedArtifact = {
  circuit: string;
  kind: string;
  filename: string;
  path: string;
};

type ResolvedArtifactBundle = {
  version: string;
  circuit: string;
  artifacts: ResolvedArtifact[];
};

type MerkleProof = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
};

type CircuitMerkleWitness = {
  root: string;
  leaf: string;
  index: number;
  siblings: string[];
  depth: number;
};

type WithdrawalWitnessRequest = {
  commitment: Commitment;
  withdrawal: Withdrawal;
  scope: string;
  withdrawal_amount: string;
  state_witness: CircuitMerkleWitness;
  asp_witness: CircuitMerkleWitness;
  new_nullifier: string;
  new_secret: string;
};

type WithdrawalCircuitInput = {
  withdrawn_value: string;
  state_root: string;
  state_tree_depth: number;
  asp_root: string;
  asp_tree_depth: number;
  context: string;
  label: string;
  existing_value: string;
  existing_nullifier: string;
  existing_secret: string;
  new_nullifier: string;
  new_secret: string;
  state_siblings: string[];
  state_index: number;
  asp_siblings: string[];
  asp_index: number;
};

type RecoveryPolicy = {
  compatibility_mode: "strict" | "legacy";
  fail_closed: boolean;
};

type PoolEvent = {
  block_number: number;
  transaction_index: number;
  log_index: number;
  pool_address: string;
  commitment_hash: string;
};

type RecoveryCheckpoint = {
  latest_block: number;
  commitments_seen: number;
};

type AsyncJobHandle = {
  job_id: string;
  kind: string;
};

type AsyncJobStatus = {
  job_id: string;
  kind: string;
  state: "queued" | "running" | "completed" | "failed" | "cancelled";
  stage?: string | null;
  error?: string | null;
  cancel_requested: boolean;
};

export type NativePrivacyPoolsSdkModule = {
  getVersion(): Promise<string>;
  getStableBackendName(): Promise<string>;
  fastBackendSupportedOnTarget(): Promise<boolean>;
  deriveMasterKeys(mnemonic: string): Promise<MasterKeys>;
  deriveDepositSecrets(
    masterNullifier: string,
    masterSecret: string,
    scope: string,
    index: string,
  ): Promise<Secrets>;
  deriveWithdrawalSecrets(
    masterNullifier: string,
    masterSecret: string,
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
  proveWithdrawal(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
  ): Promise<ProvingResult>;
  startProveWithdrawalJob(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
  ): Promise<AsyncJobHandle>;
  verifyWithdrawalProof(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  pollJobStatus(jobId: string): Promise<AsyncJobStatus>;
  getProveWithdrawalJobResult(jobId: string): Promise<ProvingResult | null>;
  cancelJob(jobId: string): Promise<boolean>;
  removeJob(jobId: string): Promise<boolean>;
  prepareWithdrawalExecution(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<PreparedTransactionExecution>;
  startPrepareWithdrawalExecutionJob(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<AsyncJobHandle>;
  getPrepareWithdrawalExecutionJobResult(
    jobId: string,
  ): Promise<PreparedTransactionExecution | null>;
  prepareRelayExecution(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<PreparedTransactionExecution>;
  startPrepareRelayExecutionJob(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<AsyncJobHandle>;
  getPrepareRelayExecutionJobResult(
    jobId: string,
  ): Promise<PreparedTransactionExecution | null>;
  registerLocalMnemonicSigner(
    handle: string,
    mnemonic: string,
    index: number,
  ): Promise<SignerHandle>;
  registerHostProvidedSigner(
    handle: string,
    address: string,
  ): Promise<SignerHandle>;
  registerMobileSecureStorageSigner(
    handle: string,
    address: string,
  ): Promise<SignerHandle>;
  unregisterSigner(handle: string): Promise<boolean>;
  finalizePreparedTransaction(
    rpcUrl: string,
    prepared: PreparedTransactionExecution,
  ): Promise<FinalizedTransactionExecution>;
  finalizePreparedTransactionForSigner(
    rpcUrl: string,
    signerHandle: string,
    prepared: PreparedTransactionExecution,
  ): Promise<FinalizedTransactionExecution>;
  submitPreparedTransaction(
    rpcUrl: string,
    signerHandle: string,
    prepared: PreparedTransactionExecution,
  ): Promise<SubmittedTransactionExecution>;
  submitSignedTransaction(
    rpcUrl: string,
    finalized: FinalizedTransactionExecution,
    signedTransaction: string,
  ): Promise<SubmittedTransactionExecution>;
  planWithdrawalTransaction(
    chainId: number,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  planRelayTransaction(
    chainId: number,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string,
  ): Promise<TransactionPlan>;
  planPoolStateRootRead(poolAddress: string): Promise<RootRead>;
  planAspRootRead(entrypointAddress: string, poolAddress: string): Promise<RootRead>;
  isCurrentStateRoot(expectedRoot: string, currentRoot: string): Promise<boolean>;
  formatGroth16ProofBundle(
    proof: ProofBundle,
  ): Promise<FormattedGroth16Proof>;
  verifyArtifactBytes(
    manifestJson: string,
    circuit: string,
    kind: string,
    bytes: number[],
  ): Promise<ArtifactVerification>;
  getArtifactStatuses(
    manifestJson: string,
    artifactsRoot: string,
    circuit: string,
  ): Promise<ArtifactStatus[]>;
  resolveVerifiedArtifactBundle(
    manifestJson: string,
    artifactsRoot: string,
    circuit: string,
  ): Promise<ResolvedArtifactBundle>;
  checkpointRecovery(
    events: PoolEvent[],
    policy: RecoveryPolicy,
  ): Promise<RecoveryCheckpoint>;
};

const LINKING_ERROR =
  `The native module 'PrivacyPoolsSdk' is not linked. Make sure the iOS/Android bindings are built, ` +
  Platform.select({
    ios: "run 'pod install' and rebuild the app.",
    default: "rebuild the app after installing the package.",
  });

const nativeModule = NativeModules.PrivacyPoolsSdk as
  | NativePrivacyPoolsSdkModule
  | undefined;

function requireNativeModule(): NativePrivacyPoolsSdkModule {
  if (!nativeModule) {
    throw new Error(LINKING_ERROR);
  }

  return nativeModule;
}

export const getVersion = (): Promise<string> => requireNativeModule().getVersion();

export const getStableBackendName = (): Promise<string> =>
  requireNativeModule().getStableBackendName();

export const fastBackendSupportedOnTarget = (): Promise<boolean> =>
  requireNativeModule().fastBackendSupportedOnTarget();

export const deriveMasterKeys = (mnemonic: string): Promise<MasterKeys> =>
  requireNativeModule().deriveMasterKeys(mnemonic);

export const deriveDepositSecrets = (
  masterNullifier: string,
  masterSecret: string,
  scope: string,
  index: string,
): Promise<Secrets> =>
  requireNativeModule().deriveDepositSecrets(
    masterNullifier,
    masterSecret,
    scope,
    index,
  );

export const deriveWithdrawalSecrets = (
  masterNullifier: string,
  masterSecret: string,
  label: string,
  index: string,
): Promise<Secrets> =>
  requireNativeModule().deriveWithdrawalSecrets(
    masterNullifier,
    masterSecret,
    label,
    index,
  );

export const getCommitment = (
  value: string,
  label: string,
  nullifier: string,
  secret: string,
): Promise<Commitment> =>
  requireNativeModule().getCommitment(value, label, nullifier, secret);

export const calculateWithdrawalContext = (
  withdrawal: Withdrawal,
  scope: string,
): Promise<string> =>
  requireNativeModule().calculateWithdrawalContext(withdrawal, scope);

export const generateMerkleProof = (
  leaves: string[],
  leaf: string,
): Promise<MerkleProof> => requireNativeModule().generateMerkleProof(leaves, leaf);

export const buildCircuitMerkleWitness = (
  proof: MerkleProof,
  depth: number,
): Promise<CircuitMerkleWitness> =>
  requireNativeModule().buildCircuitMerkleWitness(proof, depth);

export const buildWithdrawalCircuitInput = (
  request: WithdrawalWitnessRequest,
): Promise<WithdrawalCircuitInput> =>
  requireNativeModule().buildWithdrawalCircuitInput(request);

export const proveWithdrawal = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
): Promise<ProvingResult> =>
  requireNativeModule().proveWithdrawal(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
  );

export const startProveWithdrawalJob = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
): Promise<AsyncJobHandle> =>
  requireNativeModule().startProveWithdrawalJob(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
  );

export const verifyWithdrawalProof = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  proof: ProofBundle,
): Promise<boolean> =>
  requireNativeModule().verifyWithdrawalProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  );

export const pollJobStatus = (jobId: string): Promise<AsyncJobStatus> =>
  requireNativeModule().pollJobStatus(jobId);

export const getProveWithdrawalJobResult = (
  jobId: string,
): Promise<ProvingResult | null> =>
  requireNativeModule().getProveWithdrawalJobResult(jobId);

export const cancelJob = (jobId: string): Promise<boolean> =>
  requireNativeModule().cancelJob(jobId);

export const removeJob = (jobId: string): Promise<boolean> =>
  requireNativeModule().removeJob(jobId);

export const prepareWithdrawalExecution = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<PreparedTransactionExecution> =>
  requireNativeModule().prepareWithdrawalExecution(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
    chainId,
    poolAddress,
    rpcUrl,
    policy,
  );

export const startPrepareWithdrawalExecutionJob = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<AsyncJobHandle> =>
  requireNativeModule().startPrepareWithdrawalExecutionJob(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
    chainId,
    poolAddress,
    rpcUrl,
    policy,
  );

export const getPrepareWithdrawalExecutionJobResult = (
  jobId: string,
): Promise<PreparedTransactionExecution | null> =>
  requireNativeModule().getPrepareWithdrawalExecutionJobResult(jobId);

export const prepareRelayExecution = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<PreparedTransactionExecution> =>
  requireNativeModule().prepareRelayExecution(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
  );

export const startPrepareRelayExecutionJob = (
  backendProfile: "stable" | "fast",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<AsyncJobHandle> =>
  requireNativeModule().startPrepareRelayExecutionJob(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
  );

export const getPrepareRelayExecutionJobResult = (
  jobId: string,
): Promise<PreparedTransactionExecution | null> =>
  requireNativeModule().getPrepareRelayExecutionJobResult(jobId);

export const registerLocalMnemonicSigner = (
  handle: string,
  mnemonic: string,
  index: number,
): Promise<SignerHandle> =>
  requireNativeModule().registerLocalMnemonicSigner(handle, mnemonic, index);

export const registerHostProvidedSigner = (
  handle: string,
  address: string,
): Promise<SignerHandle> =>
  requireNativeModule().registerHostProvidedSigner(handle, address);

export const registerMobileSecureStorageSigner = (
  handle: string,
  address: string,
): Promise<SignerHandle> =>
  requireNativeModule().registerMobileSecureStorageSigner(handle, address);

export const unregisterSigner = (handle: string): Promise<boolean> =>
  requireNativeModule().unregisterSigner(handle);

export const finalizePreparedTransaction = (
  rpcUrl: string,
  prepared: PreparedTransactionExecution,
): Promise<FinalizedTransactionExecution> =>
  requireNativeModule().finalizePreparedTransaction(rpcUrl, prepared);

export const finalizePreparedTransactionForSigner = (
  rpcUrl: string,
  signerHandle: string,
  prepared: PreparedTransactionExecution,
): Promise<FinalizedTransactionExecution> =>
  requireNativeModule().finalizePreparedTransactionForSigner(
    rpcUrl,
    signerHandle,
    prepared,
  );

export const submitPreparedTransaction = (
  rpcUrl: string,
  signerHandle: string,
  prepared: PreparedTransactionExecution,
): Promise<SubmittedTransactionExecution> =>
  requireNativeModule().submitPreparedTransaction(
    rpcUrl,
    signerHandle,
    prepared,
  );

export const submitSignedTransaction = (
  rpcUrl: string,
  finalized: FinalizedTransactionExecution,
  signedTransaction: string,
): Promise<SubmittedTransactionExecution> =>
  requireNativeModule().submitSignedTransaction(
    rpcUrl,
    finalized,
    signedTransaction,
  );

export const planWithdrawalTransaction = (
  chainId: number,
  poolAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
): Promise<TransactionPlan> =>
  requireNativeModule().planWithdrawalTransaction(
    chainId,
    poolAddress,
    withdrawal,
    proof,
  );

export const planRelayTransaction = (
  chainId: number,
  entrypointAddress: string,
  withdrawal: Withdrawal,
  proof: ProofBundle,
  scope: string,
): Promise<TransactionPlan> =>
  requireNativeModule().planRelayTransaction(
    chainId,
    entrypointAddress,
    withdrawal,
    proof,
    scope,
  );

export const planPoolStateRootRead = (poolAddress: string): Promise<RootRead> =>
  requireNativeModule().planPoolStateRootRead(poolAddress);

export const planAspRootRead = (
  entrypointAddress: string,
  poolAddress: string,
): Promise<RootRead> =>
  requireNativeModule().planAspRootRead(entrypointAddress, poolAddress);

export const isCurrentStateRoot = (
  expectedRoot: string,
  currentRoot: string,
): Promise<boolean> =>
  requireNativeModule().isCurrentStateRoot(expectedRoot, currentRoot);

export const formatGroth16ProofBundle = (
  proof: ProofBundle,
): Promise<FormattedGroth16Proof> =>
  requireNativeModule().formatGroth16ProofBundle(proof);

export const verifyArtifactBytes = (
  manifestJson: string,
  circuit: string,
  kind: string,
  bytes: number[],
): Promise<ArtifactVerification> =>
  requireNativeModule().verifyArtifactBytes(manifestJson, circuit, kind, bytes);

export const getArtifactStatuses = (
  manifestJson: string,
  artifactsRoot: string,
  circuit: string,
): Promise<ArtifactStatus[]> =>
  requireNativeModule().getArtifactStatuses(manifestJson, artifactsRoot, circuit);

export const resolveVerifiedArtifactBundle = (
  manifestJson: string,
  artifactsRoot: string,
  circuit: string,
): Promise<ResolvedArtifactBundle> =>
  requireNativeModule().resolveVerifiedArtifactBundle(
    manifestJson,
    artifactsRoot,
    circuit,
  );

export const checkpointRecovery = (
  events: PoolEvent[],
  policy: RecoveryPolicy,
): Promise<RecoveryCheckpoint> =>
  requireNativeModule().checkpointRecovery(events, policy);
