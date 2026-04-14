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
  generateMerkleProof(leaves: string[], leaf: string): Promise<MerkleProof>;
  buildCircuitMerkleWitness(
    proof: MerkleProof,
    depth: number,
  ): Promise<CircuitMerkleWitness>;
  planPoolStateRootRead(poolAddress: string): Promise<RootRead>;
  planAspRootRead(entrypointAddress: string, poolAddress: string): Promise<RootRead>;
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

export const generateMerkleProof = (
  leaves: string[],
  leaf: string,
): Promise<MerkleProof> => requireNativeModule().generateMerkleProof(leaves, leaf);

export const buildCircuitMerkleWitness = (
  proof: MerkleProof,
  depth: number,
): Promise<CircuitMerkleWitness> =>
  requireNativeModule().buildCircuitMerkleWitness(proof, depth);

export const planPoolStateRootRead = (poolAddress: string): Promise<RootRead> =>
  requireNativeModule().planPoolStateRootRead(poolAddress);

export const planAspRootRead = (
  entrypointAddress: string,
  poolAddress: string,
): Promise<RootRead> =>
  requireNativeModule().planAspRootRead(entrypointAddress, poolAddress);

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

export const checkpointRecovery = (
  events: PoolEvent[],
  policy: RecoveryPolicy,
): Promise<RecoveryCheckpoint> =>
  requireNativeModule().checkpointRecovery(events, policy);
