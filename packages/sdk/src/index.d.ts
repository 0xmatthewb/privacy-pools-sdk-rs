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
};

export type RuntimeCapabilities = {
  runtime: string;
  provingAvailable: boolean;
  verificationAvailable: boolean;
  workerAvailable: boolean;
  reason?: string;
};

export class BrowserRuntimeUnavailableError extends Error {}

export class PrivacyPoolsSdkClient {
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
  getArtifactStatuses(
    manifestJson: string,
    artifactsRoot: string,
  ): Promise<ArtifactStatus[]>;
  resolveVerifiedArtifactBundle(
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
  proveWithdrawal(
    backendProfile: "stable" | "fast",
    manifestJson: string,
    artifactsRoot: string,
    request: WithdrawalWitnessRequest,
  ): Promise<ProvingResult>;
  proveWithdrawalWithSession(
    backendProfile: "stable" | "fast",
    sessionHandle: string,
    request: WithdrawalWitnessRequest,
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
}

export function createPrivacyPoolsSdkClient(): PrivacyPoolsSdkClient;
export function createWorkerClient(worker: Worker): PrivacyPoolsSdkClient;
export function getRuntimeCapabilities(): RuntimeCapabilities;
