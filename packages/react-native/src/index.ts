import { NativeModules, Platform } from "react-native";

export type RootRead = {
  kind: string;
  contract_address: string;
  pool_address: string;
  call_data: string;
};

export type MasterKeys = {
  master_nullifier: string;
  master_secret: string;
};

export type SecretHandle = string & { readonly __secretHandle: unique symbol };
export type VerifiedProofHandle = string & {
  readonly __verifiedProofHandle: unique symbol;
};
export type PreflightedTransactionHandle = string & {
  readonly __preflightedTransactionHandle: unique symbol;
};
export type FinalizedPreflightedTransactionHandle = string & {
  readonly __finalizedPreflightedTransactionHandle: unique symbol;
};
export type SubmittedPreflightedTransactionHandle = string & {
  readonly __submittedPreflightedTransactionHandle: unique symbol;
};

export type Secrets = {
  nullifier: string;
  secret: string;
};

export type Commitment = {
  hash: string;
  nullifier_hash: string;
  precommitment_hash: string;
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

export type ByteInput = Uint8Array | ArrayBuffer | number[];

export type Withdrawal = {
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

export type ProofBundle = {
  proof: SnarkJsProof;
  public_signals: string[];
};

export type ProvingResult = {
  backend: "arkworks";
  proof: ProofBundle;
};

export type FormattedGroth16Proof = {
  p_a: string[];
  p_b: string[][];
  p_c: string[];
  pub_signals: string[];
};

export type TransactionPlan = {
  kind: "withdraw" | "relay" | "ragequit";
  chain_id: number;
  target: string;
  calldata: string;
  value: string;
  proof: FormattedGroth16Proof;
};

export type ExecutionPolicy = {
  expected_chain_id: number;
  caller: string;
  expected_pool_code_hash?: string | null;
  expected_entrypoint_code_hash?: string | null;
  read_consistency?: "latest" | "finalized" | null;
  max_fee_quote_wei?: string | null;
  mode?: "strict" | "insecure_dev" | null;
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

type PrepareWithdrawalExecutionPayload = {
  backendProfile: "stable";
  manifestJson: string;
  artifactsRoot: string;
  request: WithdrawalWitnessRequest;
  chainId: number;
  poolAddress: string;
  rpcUrl: string;
  policy: ExecutionPolicy;
};

type PrepareRelayExecutionPayload = {
  backendProfile: "stable";
  manifestJson: string;
  artifactsRoot: string;
  request: WithdrawalWitnessRequest;
  chainId: number;
  entrypointAddress: string;
  poolAddress: string;
  rpcUrl: string;
  policy: ExecutionPolicy;
};

export type ExecutionPreflightReport = {
  kind: "withdraw" | "relay" | "ragequit";
  caller: string;
  target: string;
  expected_chain_id: number;
  actual_chain_id: number;
  chain_id_matches: boolean;
  simulated: boolean;
  estimated_gas: number;
  read_consistency?: "latest" | "finalized" | null;
  max_fee_quote_wei?: string | null;
  mode?: "strict" | "insecure_dev" | null;
  code_hash_checks: CodeHashCheck[];
  root_checks: RootCheck[];
};

export type PreparedTransactionExecution = {
  proving: ProvingResult;
  transaction: TransactionPlan;
  preflight: ExecutionPreflightReport;
};

export type FinalizedTransactionRequest = {
  kind: "withdraw" | "relay" | "ragequit";
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

export type FinalizedTransactionExecution = {
  prepared: PreparedTransactionExecution;
  request: FinalizedTransactionRequest;
};

export type SignerHandle = {
  handle: string;
  address: string;
  kind: "local_dev" | "host_provided" | "mobile_secure_storage";
};

export type TransactionReceiptSummary = {
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

export type SubmittedTransactionExecution = {
  prepared: PreparedTransactionExecution;
  receipt: TransactionReceiptSummary;
};

export type PreflightedTransaction = {
  transaction: TransactionPlan;
  preflight: ExecutionPreflightReport;
};

export type FinalizedPreflightedTransaction = {
  preflighted: PreflightedTransaction;
  request: FinalizedTransactionRequest;
};

export type SubmittedPreflightedTransaction = {
  preflighted: PreflightedTransaction;
  receipt: TransactionReceiptSummary;
};

export type ArtifactVerification = {
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

export type ArtifactBytesInput = {
  kind: string;
  bytes: number[];
};

export type SignedManifestArtifactBytesInput = {
  filename: string;
  bytes: number[];
};

export type VerifiedSignedManifest = {
  version: string;
  artifact_count: number;
  ceremony?: string | null;
  build?: string | null;
  repository?: string | null;
  commit?: string | null;
};

type WithdrawalCircuitSessionHandle = {
  handle: string;
  circuit: string;
  artifact_version: string;
};

type CommitmentCircuitSessionHandle = {
  handle: string;
  circuit: string;
  artifact_version: string;
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
  withdrawal_amount: string;
  state_witness: CircuitMerkleWitness;
  asp_witness: CircuitMerkleWitness;
  new_nullifier: string;
  new_secret: string;
};

export type WithdrawalCircuitInput = {
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

export type CommitmentWitnessRequest = {
  commitment: Commitment;
};

export type CommitmentCircuitInput = {
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

export type RecoveryPolicy = {
  compatibility_mode: "strict" | "legacy";
  fail_closed: boolean;
};

export type PoolEvent = {
  block_number: number;
  transaction_index: number;
  log_index: number;
  pool_address: string;
  commitment_hash: string;
};

export type RecoveryCheckpoint = {
  latest_block: number;
  commitments_seen: number;
};

type AsyncJobHandle = {
  job_id: string;
  kind: string;
};

export type AsyncJobStatus = {
  job_id: string;
  kind: string;
  state: "queued" | "running" | "completed" | "failed" | "cancelled";
  stage?: string | null;
  error?: string | null;
  cancel_requested: boolean;
};

type JobProgressCallback = (status: AsyncJobStatus) => void;

type WaitForJobOptions = {
  intervalMs?: number;
  onProgress?: JobProgressCallback;
  signal?: AbortSignal;
  removeOnComplete?: boolean;
};

export type NativePrivacyPoolsSdkModule = {
  getVersion(): Promise<string>;
  getStableBackendName(): Promise<string>;
  deriveMasterKeysHandle(mnemonic: string): Promise<SecretHandle>;
  deriveMasterKeysHandleBytes(mnemonicBytes: number[]): Promise<SecretHandle>;
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  dangerouslyExportMasterKeys(handle: SecretHandle): Promise<MasterKeys>;
  generateDepositSecretsHandle(
    masterKeysHandle: SecretHandle,
    scope: string,
    index: string,
  ): Promise<SecretHandle>;
  generateWithdrawalSecretsHandle(
    masterKeysHandle: SecretHandle,
    label: string,
    index: string,
  ): Promise<SecretHandle>;
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  dangerouslyExportSecret(handle: SecretHandle): Promise<Secrets>;
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
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  /** Compatibility/testing escape hatch. Avoid in normal integrations. */
  dangerouslyExportCommitmentPreimage(handle: SecretHandle): Promise<Commitment>;
  buildWithdrawalWitnessRequestHandle(
    request: WithdrawalWitnessRequest,
  ): Promise<SecretHandle>;
  removeSecretHandle(handle: SecretHandle): Promise<boolean>;
  clearSecretHandles(): Promise<boolean>;
  removeVerifiedProofHandle(handle: VerifiedProofHandle): Promise<boolean>;
  clearVerifiedProofHandles(): Promise<boolean>;
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
  prepareWithdrawalCircuitSession(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<WithdrawalCircuitSessionHandle>;
  prepareWithdrawalCircuitSessionFromBytes(
    manifestJson: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<WithdrawalCircuitSessionHandle>;
  removeWithdrawalCircuitSession(handle: string): Promise<boolean>;
  prepareCommitmentCircuitSession(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<CommitmentCircuitSessionHandle>;
  prepareCommitmentCircuitSessionFromBytes(
    manifestJson: string,
    artifacts: ArtifactBytesInput[],
  ): Promise<CommitmentCircuitSessionHandle>;
  removeCommitmentCircuitSession(handle: string): Promise<boolean>;
  proveWithdrawal(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
  ): Promise<ProvingResult>;
  proveWithdrawalWithSession(
    backendProfile: "stable",
    sessionHandle: string,
    request: WithdrawalWitnessRequest,
  ): Promise<ProvingResult>;
  proveWithdrawalWithHandles(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
  ): Promise<ProvingResult>;
  startProveWithdrawalJob(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
  ): Promise<AsyncJobHandle>;
  startProveWithdrawalJobWithSession(
    backendProfile: "stable",
    sessionHandle: string,
    request: WithdrawalWitnessRequest,
  ): Promise<AsyncJobHandle>;
  verifyWithdrawalProof(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  verifyWithdrawalProofWithSession(
    backendProfile: "stable",
    sessionHandle: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  proveCommitment(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: CommitmentWitnessRequest,
  ): Promise<ProvingResult>;
  proveCommitmentWithSession(
    backendProfile: "stable",
    sessionHandle: string,
    request: CommitmentWitnessRequest,
  ): Promise<ProvingResult>;
  proveCommitmentWithHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
  ): Promise<ProvingResult>;
  proveAndVerifyCommitmentHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
  ): Promise<VerifiedProofHandle>;
  proveAndVerifyWithdrawalHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
  ): Promise<VerifiedProofHandle>;
  verifyCommitmentProofForRequestHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
    proof: ProofBundle,
  ): Promise<VerifiedProofHandle>;
  verifyRagequitProofForRequestHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
    proof: ProofBundle,
  ): Promise<VerifiedProofHandle>;
  verifyWithdrawalProofForRequestHandle(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    requestHandle: SecretHandle,
    proof: ProofBundle,
  ): Promise<VerifiedProofHandle>;
  verifyCommitmentProof(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  verifyCommitmentProofWithSession(
    backendProfile: "stable",
    sessionHandle: string,
    proof: ProofBundle,
  ): Promise<boolean>;
  pollJobStatus(jobId: string): Promise<AsyncJobStatus>;
  getProveWithdrawalJobResult(jobId: string): Promise<ProvingResult | null>;
  cancelJob(jobId: string): Promise<boolean>;
  removeJob(jobId: string): Promise<boolean>;
  prepareWithdrawalExecution(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<PreparedTransactionExecution>;
  prepareWithdrawalExecutionPayload?(
    payload: PrepareWithdrawalExecutionPayload,
  ): Promise<PreparedTransactionExecution>;
  startPrepareWithdrawalExecutionJob(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<AsyncJobHandle>;
  startPrepareWithdrawalExecutionJobPayload?(
    payload: PrepareWithdrawalExecutionPayload,
  ): Promise<AsyncJobHandle>;
  getPrepareWithdrawalExecutionJobResult(
    jobId: string,
  ): Promise<PreparedTransactionExecution | null>;
  prepareRelayExecution(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<PreparedTransactionExecution>;
  prepareRelayExecutionPayload?(
    payload: PrepareRelayExecutionPayload,
  ): Promise<PreparedTransactionExecution>;
  startPrepareRelayExecutionJob(
    backendProfile: "stable",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
    chainId: number,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
  ): Promise<AsyncJobHandle>;
  startPrepareRelayExecutionJobPayload?(
    payload: PrepareRelayExecutionPayload,
  ): Promise<AsyncJobHandle>;
  getPrepareRelayExecutionJobResult(
    jobId: string,
  ): Promise<PreparedTransactionExecution | null>;
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
  /** Low-level compatibility/offline formatting API. */
  planWithdrawalTransaction(
    chainId: number,
    poolAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  /** Low-level compatibility/offline formatting API. */
  planRelayTransaction(
    chainId: number,
    entrypointAddress: string,
    withdrawal: Withdrawal,
    proof: ProofBundle,
    scope: string,
  ): Promise<TransactionPlan>;
  /** Low-level compatibility/offline formatting API. */
  planRagequitTransaction(
    chainId: number,
    poolAddress: string,
    proof: ProofBundle,
  ): Promise<TransactionPlan>;
  planVerifiedWithdrawalTransactionWithHandle(
    chainId: number,
    poolAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  planVerifiedRelayTransactionWithHandle(
    chainId: number,
    entrypointAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  planVerifiedRagequitTransactionWithHandle(
    chainId: number,
    poolAddress: string,
    proofHandle: VerifiedProofHandle,
  ): Promise<TransactionPlan>;
  preflightVerifiedWithdrawalTransactionWithHandle(
    chainId: number,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
    proofHandle: VerifiedProofHandle,
  ): Promise<PreflightedTransactionHandle>;
  preflightVerifiedRelayTransactionWithHandle(
    chainId: number,
    entrypointAddress: string,
    poolAddress: string,
    rpcUrl: string,
    policy: ExecutionPolicy,
    proofHandle: VerifiedProofHandle,
  ): Promise<PreflightedTransactionHandle>;
  preflightVerifiedRagequitTransactionWithHandle(
    chainId: number,
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
    signerHandle: string,
    preflightedHandle: PreflightedTransactionHandle,
  ): Promise<SubmittedPreflightedTransactionHandle>;
  submitFinalizedPreflightedTransactionHandle(
    rpcUrl: string,
    finalizedHandle: FinalizedPreflightedTransactionHandle,
    signedTransaction: string,
  ): Promise<SubmittedPreflightedTransactionHandle>;
  /** Compatibility/testing escape hatch. Keep execution data in handles for normal integrations. */
  dangerouslyExportPreflightedTransaction(
    handle: PreflightedTransactionHandle,
  ): Promise<PreflightedTransaction>;
  /** Compatibility/testing escape hatch. Keep execution data in handles for normal integrations. */
  dangerouslyExportFinalizedPreflightedTransaction(
    handle: FinalizedPreflightedTransactionHandle,
  ): Promise<FinalizedPreflightedTransaction>;
  /** Compatibility/testing escape hatch. Keep execution data in handles for normal integrations. */
  dangerouslyExportSubmittedPreflightedTransaction(
    handle: SubmittedPreflightedTransactionHandle,
  ): Promise<SubmittedPreflightedTransaction>;
  removeExecutionHandle(
    handle:
      | PreflightedTransactionHandle
      | FinalizedPreflightedTransactionHandle
      | SubmittedPreflightedTransactionHandle,
  ): Promise<boolean>;
  clearExecutionHandles(): Promise<boolean>;
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
  verifySignedManifest(
    payloadJson: string,
    signatureHex: string,
    publicKeyHex: string,
  ): Promise<VerifiedSignedManifest>;
  verifySignedManifestArtifacts(
    payloadJson: string,
    signatureHex: string,
    publicKeyHex: string,
    artifacts: SignedManifestArtifactBytesInput[],
  ): Promise<VerifiedSignedManifest>;
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

const normalizeBackendName = (backend: string): "arkworks" => {
  if (typeof backend !== "string") {
    throw new Error(
      `expected backend string, received ${backend == null ? String(backend) : typeof backend}`,
    );
  }
  return backend.toLowerCase() as "arkworks";
};

const normalizeProvingResult = (result: ProvingResult): ProvingResult => ({
  ...result,
  backend: normalizeBackendName(result.backend),
});

const normalizePreparedTransactionExecution = (
  execution: PreparedTransactionExecution,
): PreparedTransactionExecution => ({
  ...execution,
  proving: normalizeProvingResult(execution.proving),
});

const normalizeFinalizedTransactionExecution = (
  execution: FinalizedTransactionExecution,
): FinalizedTransactionExecution => ({
  ...execution,
  prepared: normalizePreparedTransactionExecution(execution.prepared),
});

const normalizeSubmittedTransactionExecution = (
  execution: SubmittedTransactionExecution,
): SubmittedTransactionExecution => ({
  ...execution,
  prepared: normalizePreparedTransactionExecution(execution.prepared),
});

export const getVersion = (): Promise<string> => requireNativeModule().getVersion();

export const getStableBackendName = (): Promise<string> =>
  coerceAsyncResult(
    "getStableBackendName",
    requireNativeModule().getStableBackendName(),
  ).then(normalizeBackendName);

export const deriveMasterKeysHandle = (
  mnemonic: string,
): Promise<SecretHandle> => requireNativeModule().deriveMasterKeysHandle(mnemonic);

export const deriveMasterKeysHandleBytes = (
  mnemonicBytes: ByteInput,
): Promise<SecretHandle> =>
  requireNativeModule().deriveMasterKeysHandleBytes(normalizeByteInput(mnemonicBytes));

export const generateDepositSecretsHandle = (
  masterKeysHandle: SecretHandle,
  scope: string,
  index: string,
): Promise<SecretHandle> =>
  requireNativeModule().generateDepositSecretsHandle(
    masterKeysHandle,
    scope,
    index,
  );

export const generateWithdrawalSecretsHandle = (
  masterKeysHandle: SecretHandle,
  label: string,
  index: string,
): Promise<SecretHandle> =>
  requireNativeModule().generateWithdrawalSecretsHandle(
    masterKeysHandle,
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

export const getCommitmentFromHandles = (
  value: string,
  label: string,
  secretsHandle: SecretHandle,
): Promise<SecretHandle> =>
  requireNativeModule().getCommitmentFromHandles(value, label, secretsHandle);

export const buildWithdrawalWitnessRequestHandle = (
  request: WithdrawalWitnessRequest,
): Promise<SecretHandle> =>
  requireNativeModule().buildWithdrawalWitnessRequestHandle(request);

export const removeSecretHandle = (
  handle: SecretHandle,
): Promise<boolean> => requireNativeModule().removeSecretHandle(handle);

export const clearSecretHandles = (): Promise<boolean> =>
  requireNativeModule().clearSecretHandles();

export const removeVerifiedProofHandle = (
  handle: VerifiedProofHandle,
): Promise<boolean> => requireNativeModule().removeVerifiedProofHandle(handle);

export const clearVerifiedProofHandles = (): Promise<boolean> =>
  requireNativeModule().clearVerifiedProofHandles();

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

export const buildCommitmentCircuitInput = (
  request: CommitmentWitnessRequest,
): Promise<CommitmentCircuitInput> =>
  requireNativeModule().buildCommitmentCircuitInput(request);

export const prepareWithdrawalCircuitSession = (
  manifestJson: string,
  artifactsRoot: string,
): Promise<WithdrawalCircuitSessionHandle> =>
  requireNativeModule().prepareWithdrawalCircuitSession(
    manifestJson,
    artifactsRoot,
  );

export const prepareWithdrawalCircuitSessionFromBytes = (
  manifestJson: string,
  artifacts: ArtifactBytesInput[],
): Promise<WithdrawalCircuitSessionHandle> =>
  requireNativeModule().prepareWithdrawalCircuitSessionFromBytes(
    manifestJson,
    artifacts,
  );

export const removeWithdrawalCircuitSession = (
  handle: string,
): Promise<boolean> => requireNativeModule().removeWithdrawalCircuitSession(handle);

export const prepareCommitmentCircuitSession = (
  manifestJson: string,
  artifactsRoot: string,
): Promise<CommitmentCircuitSessionHandle> =>
  requireNativeModule().prepareCommitmentCircuitSession(
    manifestJson,
    artifactsRoot,
  );

export const prepareCommitmentCircuitSessionFromBytes = (
  manifestJson: string,
  artifacts: ArtifactBytesInput[],
): Promise<CommitmentCircuitSessionHandle> =>
  requireNativeModule().prepareCommitmentCircuitSessionFromBytes(
    manifestJson,
    artifacts,
  );

export const removeCommitmentCircuitSession = (
  handle: string,
): Promise<boolean> => requireNativeModule().removeCommitmentCircuitSession(handle);

export const proveWithdrawal = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveWithdrawal",
    requireNativeModule().proveWithdrawal(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ),
  ).then(normalizeProvingResult);

export const proveWithdrawalWithSession = (
  backendProfile: "stable",
  sessionHandle: string,
  request: WithdrawalWitnessRequest,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveWithdrawalWithSession",
    requireNativeModule().proveWithdrawalWithSession(
      backendProfile,
      sessionHandle,
      request,
    ),
  ).then(normalizeProvingResult);

export const proveWithdrawalWithHandles = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveWithdrawalWithHandles",
    requireNativeModule().proveWithdrawalWithHandles(
      backendProfile,
      manifestJson,
      artifactsRoot,
      requestHandle,
    ),
  ).then(normalizeProvingResult);

export const startProveWithdrawalJob = (
  backendProfile: "stable",
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

export const startProveWithdrawalJobWithSession = (
  backendProfile: "stable",
  sessionHandle: string,
  request: WithdrawalWitnessRequest,
): Promise<AsyncJobHandle> =>
  requireNativeModule().startProveWithdrawalJobWithSession(
    backendProfile,
    sessionHandle,
    request,
  );

export const verifyWithdrawalProof = (
  backendProfile: "stable",
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

export const verifyWithdrawalProofWithSession = (
  backendProfile: "stable",
  sessionHandle: string,
  proof: ProofBundle,
): Promise<boolean> =>
  requireNativeModule().verifyWithdrawalProofWithSession(
    backendProfile,
    sessionHandle,
    proof,
  );

export const proveCommitment = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: CommitmentWitnessRequest,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveCommitment",
    requireNativeModule().proveCommitment(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
    ),
  ).then(normalizeProvingResult);

export const proveCommitmentWithSession = (
  backendProfile: "stable",
  sessionHandle: string,
  request: CommitmentWitnessRequest,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveCommitmentWithSession",
    requireNativeModule().proveCommitmentWithSession(
      backendProfile,
      sessionHandle,
      request,
    ),
  ).then(normalizeProvingResult);

export const proveCommitmentWithHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
): Promise<ProvingResult> =>
  coerceAsyncResult(
    "proveCommitmentWithHandle",
    requireNativeModule().proveCommitmentWithHandle(
      backendProfile,
      manifestJson,
      artifactsRoot,
      requestHandle,
    ),
  ).then(normalizeProvingResult);

export const proveAndVerifyCommitmentHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
): Promise<VerifiedProofHandle> =>
  requireNativeModule().proveAndVerifyCommitmentHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    requestHandle,
  );

export const proveAndVerifyWithdrawalHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
): Promise<VerifiedProofHandle> =>
  requireNativeModule().proveAndVerifyWithdrawalHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    requestHandle,
  );

export const verifyCommitmentProofForRequestHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
  proof: ProofBundle,
): Promise<VerifiedProofHandle> =>
  requireNativeModule().verifyCommitmentProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    requestHandle,
    proof,
  );

export const verifyRagequitProofForRequestHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
  proof: ProofBundle,
): Promise<VerifiedProofHandle> =>
  requireNativeModule().verifyRagequitProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    requestHandle,
    proof,
  );

export const verifyWithdrawalProofForRequestHandle = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  requestHandle: SecretHandle,
  proof: ProofBundle,
): Promise<VerifiedProofHandle> =>
  requireNativeModule().verifyWithdrawalProofForRequestHandle(
    backendProfile,
    manifestJson,
    artifactsRoot,
    requestHandle,
    proof,
  );

export const verifyCommitmentProof = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  proof: ProofBundle,
): Promise<boolean> =>
  requireNativeModule().verifyCommitmentProof(
    backendProfile,
    manifestJson,
    artifactsRoot,
    proof,
  );

export const verifyCommitmentProofWithSession = (
  backendProfile: "stable",
  sessionHandle: string,
  proof: ProofBundle,
): Promise<boolean> =>
  requireNativeModule().verifyCommitmentProofWithSession(
    backendProfile,
    sessionHandle,
    proof,
  );

export const pollJobStatus = (jobId: string): Promise<AsyncJobStatus> =>
  requireNativeModule().pollJobStatus(jobId);

export const getProveWithdrawalJobResult = (
  jobId: string,
): Promise<ProvingResult | null> =>
  coerceAsyncResult(
    "getProveWithdrawalJobResult",
    requireNativeModule().getProveWithdrawalJobResult(jobId),
  )
    .then((result) => (result == null ? null : normalizeProvingResult(result)));

export const cancelJob = (jobId: string): Promise<boolean> =>
  requireNativeModule().cancelJob(jobId);

export const removeJob = (jobId: string): Promise<boolean> =>
  requireNativeModule().removeJob(jobId);

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const buildPrepareWithdrawalExecutionPayload = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): PrepareWithdrawalExecutionPayload => ({
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  chainId,
  poolAddress,
  rpcUrl,
  policy,
});

const buildPrepareRelayExecutionPayload = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): PrepareRelayExecutionPayload => ({
  backendProfile,
  manifestJson,
  artifactsRoot,
  request,
  chainId,
  entrypointAddress,
  poolAddress,
  rpcUrl,
  policy,
});

const coerceAsyncResult = <T>(
  methodName: string,
  value: PromiseLike<T> | T,
): Promise<T> => {
  if (value === undefined) {
    throw new Error(`${methodName} returned undefined`);
  }
  return Promise.resolve(value);
};

const abortError = (): Error => {
  const error = new Error("job observation aborted");
  error.name = "AbortError";
  return error;
};

const waitForJob = async <T>(
  handle: AsyncJobHandle,
  getResult: (jobId: string) => Promise<T | null>,
  options: WaitForJobOptions = {},
): Promise<T> => {
  const intervalMs = options.intervalMs ?? 250;
  if (intervalMs <= 0) {
    throw new Error("intervalMs must be positive");
  }

  while (true) {
    if (options.signal?.aborted) {
      await cancelJob(handle.job_id);
      throw abortError();
    }

    const status = await pollJobStatus(handle.job_id);
    options.onProgress?.(status);

    if (status.state === "completed") {
      const result = await getResult(handle.job_id);
      if (options.removeOnComplete ?? false) {
        await removeJob(handle.job_id);
      }
      if (result == null) {
        throw new Error(`completed ${handle.kind} job returned no result`);
      }
      return result;
    }

    if (status.state === "failed") {
      throw new Error(status.error ?? `${handle.kind} job failed`);
    }

    if (status.state === "cancelled") {
      throw new Error(`${handle.kind} job was cancelled`);
    }

    await delay(intervalMs);
  }
};

export const waitForProveWithdrawalJob = (
  handle: AsyncJobHandle,
  options?: WaitForJobOptions,
): Promise<ProvingResult> =>
  waitForJob(handle, getProveWithdrawalJobResult, options);

const useAsyncExecutionPreparation = Platform.OS === "android";

export const prepareWithdrawalExecution = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<PreparedTransactionExecution> => {
  if (useAsyncExecutionPreparation) {
    const payload = buildPrepareWithdrawalExecutionPayload(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      chainId,
      poolAddress,
      rpcUrl,
      policy,
    );
    const native = requireNativeModule();
    if (typeof native.prepareWithdrawalExecutionPayload === "function") {
      return coerceAsyncResult<PreparedTransactionExecution>(
        "prepareWithdrawalExecutionPayload",
        native.prepareWithdrawalExecutionPayload(payload),
      )
        .then(normalizePreparedTransactionExecution);
    }
    if (typeof native.startPrepareWithdrawalExecutionJobPayload === "function") {
      return coerceAsyncResult<AsyncJobHandle>(
        "startPrepareWithdrawalExecutionJobPayload",
        native.startPrepareWithdrawalExecutionJobPayload(payload),
      )
        .then((handle) => waitForPrepareWithdrawalExecutionJob(handle));
    }
  }

  return coerceAsyncResult(
    "prepareWithdrawalExecution",
    requireNativeModule().prepareWithdrawalExecution(
      backendProfile,
      manifestJson,
      artifactsRoot,
      request,
      chainId,
      poolAddress,
      rpcUrl,
      policy,
    ),
  )
    .then(normalizePreparedTransactionExecution);
};

export const startPrepareWithdrawalExecutionJob = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<AsyncJobHandle> => {
  if (useAsyncExecutionPreparation) {
    const native = requireNativeModule();
    if (typeof native.startPrepareWithdrawalExecutionJobPayload === "function") {
      return coerceAsyncResult<AsyncJobHandle>(
        "startPrepareWithdrawalExecutionJobPayload",
        native.startPrepareWithdrawalExecutionJobPayload(
          buildPrepareWithdrawalExecutionPayload(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            poolAddress,
            rpcUrl,
            policy,
          ),
        ),
      );
    }
  }

  return requireNativeModule().startPrepareWithdrawalExecutionJob(
    backendProfile,
    manifestJson,
    artifactsRoot,
    request,
    chainId,
    poolAddress,
    rpcUrl,
    policy,
  );
};

export const getPrepareWithdrawalExecutionJobResult = (
  jobId: string,
): Promise<PreparedTransactionExecution | null> =>
  coerceAsyncResult(
    "getPrepareWithdrawalExecutionJobResult",
    requireNativeModule().getPrepareWithdrawalExecutionJobResult(jobId),
  )
    .then((result) =>
      result == null ? null : normalizePreparedTransactionExecution(result),
    );

export const waitForPrepareWithdrawalExecutionJob = (
  handle: AsyncJobHandle,
  options?: WaitForJobOptions,
): Promise<PreparedTransactionExecution> =>
  waitForJob(handle, getPrepareWithdrawalExecutionJobResult, options);

export const prepareRelayExecution = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<PreparedTransactionExecution> => {
  if (useAsyncExecutionPreparation) {
    const payload = buildPrepareRelayExecutionPayload(
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
    const native = requireNativeModule();
    if (typeof native.prepareRelayExecutionPayload === "function") {
      return coerceAsyncResult<PreparedTransactionExecution>(
        "prepareRelayExecutionPayload",
        native.prepareRelayExecutionPayload(payload),
      )
        .then(normalizePreparedTransactionExecution);
    }
    if (typeof native.startPrepareRelayExecutionJobPayload === "function") {
      return coerceAsyncResult<AsyncJobHandle>(
        "startPrepareRelayExecutionJobPayload",
        native.startPrepareRelayExecutionJobPayload(payload),
      )
        .then((handle) => waitForPrepareRelayExecutionJob(handle));
    }
  }

  return coerceAsyncResult(
    "prepareRelayExecution",
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
    ),
  )
    .then(normalizePreparedTransactionExecution);
};

export const startPrepareRelayExecutionJob = (
  backendProfile: "stable",
  manifestJson: string,
  artifactsRoot: string,
  request: WithdrawalWitnessRequest,
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
): Promise<AsyncJobHandle> => {
  if (useAsyncExecutionPreparation) {
    const native = requireNativeModule();
    if (typeof native.startPrepareRelayExecutionJobPayload === "function") {
      return coerceAsyncResult<AsyncJobHandle>(
        "startPrepareRelayExecutionJobPayload",
        native.startPrepareRelayExecutionJobPayload(
          buildPrepareRelayExecutionPayload(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            entrypointAddress,
            poolAddress,
            rpcUrl,
            policy,
          ),
        ),
      );
    }
  }

  return requireNativeModule().startPrepareRelayExecutionJob(
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
};

export const getPrepareRelayExecutionJobResult = (
  jobId: string,
): Promise<PreparedTransactionExecution | null> =>
  coerceAsyncResult(
    "getPrepareRelayExecutionJobResult",
    requireNativeModule().getPrepareRelayExecutionJobResult(jobId),
  )
    .then((result) =>
      result == null ? null : normalizePreparedTransactionExecution(result),
    );

export const waitForPrepareRelayExecutionJob = (
  handle: AsyncJobHandle,
  options?: WaitForJobOptions,
): Promise<PreparedTransactionExecution> =>
  waitForJob(handle, getPrepareRelayExecutionJobResult, options);

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
  coerceAsyncResult(
    "finalizePreparedTransaction",
    requireNativeModule().finalizePreparedTransaction(rpcUrl, prepared),
  )
    .then(normalizeFinalizedTransactionExecution);

export const finalizePreparedTransactionForSigner = (
  rpcUrl: string,
  signerHandle: string,
  prepared: PreparedTransactionExecution,
): Promise<FinalizedTransactionExecution> =>
  coerceAsyncResult(
    "finalizePreparedTransactionForSigner",
    requireNativeModule().finalizePreparedTransactionForSigner(
      rpcUrl,
      signerHandle,
      prepared,
    ),
  ).then(normalizeFinalizedTransactionExecution);

export const submitPreparedTransaction = (
  rpcUrl: string,
  signerHandle: string,
  prepared: PreparedTransactionExecution,
): Promise<SubmittedTransactionExecution> =>
  coerceAsyncResult(
    "submitPreparedTransaction",
    requireNativeModule().submitPreparedTransaction(
      rpcUrl,
      signerHandle,
      prepared,
    ),
  ).then(normalizeSubmittedTransactionExecution);

export const submitSignedTransaction = (
  rpcUrl: string,
  finalized: FinalizedTransactionExecution,
  signedTransaction: string,
): Promise<SubmittedTransactionExecution> =>
  coerceAsyncResult(
    "submitSignedTransaction",
    requireNativeModule().submitSignedTransaction(
      rpcUrl,
      finalized,
      signedTransaction,
    ),
  ).then(normalizeSubmittedTransactionExecution);

/** Low-level compatibility/offline formatting API. */
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

/** Low-level compatibility/offline formatting API. */
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

/** Low-level compatibility/offline formatting API. */
export const planRagequitTransaction = (
  chainId: number,
  poolAddress: string,
  proof: ProofBundle,
): Promise<TransactionPlan> =>
  requireNativeModule().planRagequitTransaction(chainId, poolAddress, proof);

export const planVerifiedWithdrawalTransactionWithHandle = (
  chainId: number,
  poolAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan> =>
  requireNativeModule().planVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );

export const planVerifiedRelayTransactionWithHandle = (
  chainId: number,
  entrypointAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan> =>
  requireNativeModule().planVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    proofHandle,
  );

export const planVerifiedRagequitTransactionWithHandle = (
  chainId: number,
  poolAddress: string,
  proofHandle: VerifiedProofHandle,
): Promise<TransactionPlan> =>
  requireNativeModule().planVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    proofHandle,
  );

export const preflightVerifiedWithdrawalTransactionWithHandle = (
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle> =>
  requireNativeModule().preflightVerifiedWithdrawalTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );

export const preflightVerifiedRelayTransactionWithHandle = (
  chainId: number,
  entrypointAddress: string,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle> =>
  requireNativeModule().preflightVerifiedRelayTransactionWithHandle(
    chainId,
    entrypointAddress,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );

export const preflightVerifiedRagequitTransactionWithHandle = (
  chainId: number,
  poolAddress: string,
  rpcUrl: string,
  policy: ExecutionPolicy,
  proofHandle: VerifiedProofHandle,
): Promise<PreflightedTransactionHandle> =>
  requireNativeModule().preflightVerifiedRagequitTransactionWithHandle(
    chainId,
    poolAddress,
    rpcUrl,
    policy,
    proofHandle,
  );

export const finalizePreflightedTransactionHandle = (
  rpcUrl: string,
  preflightedHandle: PreflightedTransactionHandle,
): Promise<FinalizedPreflightedTransactionHandle> =>
  requireNativeModule().finalizePreflightedTransactionHandle(
    rpcUrl,
    preflightedHandle,
  );

export const submitPreflightedTransactionHandle = (
  rpcUrl: string,
  signerHandle: string,
  preflightedHandle: PreflightedTransactionHandle,
): Promise<SubmittedPreflightedTransactionHandle> =>
  requireNativeModule().submitPreflightedTransactionHandle(
    rpcUrl,
    signerHandle,
    preflightedHandle,
  );

export const submitFinalizedPreflightedTransactionHandle = (
  rpcUrl: string,
  finalizedHandle: FinalizedPreflightedTransactionHandle,
  signedTransaction: string,
): Promise<SubmittedPreflightedTransactionHandle> =>
  requireNativeModule().submitFinalizedPreflightedTransactionHandle(
    rpcUrl,
    finalizedHandle,
    signedTransaction,
  );

export const removeExecutionHandle = (
  handle:
    | PreflightedTransactionHandle
    | FinalizedPreflightedTransactionHandle
    | SubmittedPreflightedTransactionHandle,
): Promise<boolean> => requireNativeModule().removeExecutionHandle(handle);

export const clearExecutionHandles = (): Promise<boolean> =>
  requireNativeModule().clearExecutionHandles();

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

export const verifySignedManifest = (
  payloadJson: string,
  signatureHex: string,
  publicKeyHex: string,
): Promise<VerifiedSignedManifest> =>
  requireNativeModule().verifySignedManifest(
    payloadJson,
    signatureHex,
    publicKeyHex,
  );

export const verifySignedManifestArtifacts = (
  payloadJson: string,
  signatureHex: string,
  publicKeyHex: string,
  artifacts: SignedManifestArtifactBytesInput[],
): Promise<VerifiedSignedManifest> =>
  requireNativeModule().verifySignedManifestArtifacts(
    payloadJson,
    signatureHex,
    publicKeyHex,
    artifacts,
  );

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

function normalizeByteInput(bytes: ByteInput): number[] {
  if (Array.isArray(bytes)) {
    return bytes;
  }

  if (bytes instanceof Uint8Array) {
    return Array.from(bytes);
  }

  if (bytes instanceof ArrayBuffer) {
    return Array.from(new Uint8Array(bytes));
  }

  throw new TypeError("mnemonic bytes must be a Uint8Array, ArrayBuffer, or number[]");
}
