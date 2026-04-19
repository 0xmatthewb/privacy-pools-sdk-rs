import React from "react";
import { ScrollView, Text, View } from "react-native";
import {
  buildCircuitMerkleWitness,
  buildCommitmentCircuitInput,
  clearExecutionHandles,
  clearSecretHandles,
  clearVerifiedProofHandles,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  cancelJob,
  checkpointRecovery,
  deriveDepositSecrets,
  deriveMasterKeysHandle,
  deriveMasterKeys,
  deriveWithdrawalSecrets,
  finalizePreparedTransaction,
  finalizePreparedTransactionForSigner,
  finalizePreflightedTransactionHandle,
  formatGroth16ProofBundle,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  generateMerkleProof,
  getCommitment,
  getCommitmentFromHandles,
  getStableBackendName,
  getVersion,
  isCurrentStateRoot,
  planAspRootRead,
  planPoolStateRootRead,
  planRagequitTransaction,
  planRelayTransaction,
  planWithdrawalTransaction,
  preflightVerifiedRagequitTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedWithdrawalTransactionWithHandle,
  pollJobStatus,
  registerHostProvidedSigner,
  registerMobileSecureStorageSigner,
  removeJob,
  removeExecutionHandle,
  removeSecretHandle,
  removeVerifiedProofHandle,
  submitPreparedTransaction,
  submitFinalizedPreflightedTransactionHandle,
  submitPreflightedTransactionHandle,
  submitSignedTransaction,
  type FinalizedPreflightedTransactionHandle,
  type PreflightedTransactionHandle,
  type SecretHandle,
  type SubmittedPreflightedTransactionHandle,
  type VerifiedProofHandle,
  unregisterSigner,
  verifyArtifactBytes,
  verifySignedManifest,
  verifySignedManifestArtifacts,
} from "@0xmatthewb/privacy-pools-sdk-react-native";
import {
  getArtifactStatuses,
  getPrepareRelayExecutionJobResult,
  getPrepareWithdrawalExecutionJobResult,
  getProveWithdrawalJobResult,
  prepareCommitmentCircuitSession,
  prepareCommitmentCircuitSessionFromBytes,
  prepareRelayExecution,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  prepareWithdrawalExecution,
  proveAndVerifyCommitmentHandle,
  proveAndVerifyWithdrawalHandle,
  proveCommitment,
  proveCommitmentWithHandle,
  proveCommitmentWithSession,
  proveWithdrawal,
  proveWithdrawalWithHandles,
  proveWithdrawalWithSession,
  removeCommitmentCircuitSession,
  removeWithdrawalCircuitSession,
  resolveVerifiedArtifactBundle,
  startPrepareRelayExecutionJob,
  startPrepareWithdrawalExecutionJob,
  startProveWithdrawalJob,
  startProveWithdrawalJobWithSession,
  verifyCommitmentProof,
  verifyCommitmentProofForRequestHandle,
  verifyCommitmentProofWithSession,
  verifyRagequitProofForRequestHandle,
  verifyWithdrawalProof,
  verifyWithdrawalProofForRequestHandle,
  verifyWithdrawalProofWithSession,
} from "@0xmatthewb/privacy-pools-sdk-react-native/testing";
import {
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportMasterKeys,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportSecret,
  dangerouslyExportSubmittedPreflightedTransaction,
} from "@0xmatthewb/privacy-pools-sdk-react-native/debug";

const address = "0x1111111111111111111111111111111111111111";
const otherAddress = "0x2222222222222222222222222222222222222222";
const scope = "0x" + "33".repeat(32);
const manifestJson = JSON.stringify({
  version: "1.2.0-patched",
  circuits: {},
});
const artifactsRoot = "/tmp/privacy-pools-sdk";
const mnemonic =
  "test test test test test test test test test test test junk";

const proofBundle = {
  proof: {
    pi_a: ["1", "2"],
    pi_b: [
      ["3", "4"],
      ["5", "6"],
    ],
    pi_c: ["7", "8"],
    protocol: "groth16",
    curve: "bn128",
  },
  public_signals: ["9", "10", "11"],
};

const formattedProof = {
  p_a: ["1", "2"],
  p_b: [
    ["3", "4"],
    ["5", "6"],
  ],
  p_c: ["7", "8"],
  pub_signals: ["9", "10"],
};

const commitment = {
  hash: "12",
  precommitment_hash: "14",
  nullifier_hash: "14",
  value: "1000000000000000",
  label: "15",
  nullifier: "16",
  secret: "17",
};

const witness = {
  root: "18",
  leaf: commitment.hash,
  index: 0,
  siblings: ["19", "20", ...Array.from({ length: 30 }, () => "0")],
  depth: 2,
};

const merkleProof = {
  root: witness.root,
  leaf: witness.leaf,
  index: witness.index,
  siblings: witness.siblings,
};

const withdrawal = {
  processooor: otherAddress,
  data: [1, 2, 3, 4],
};

const request = {
  commitment,
  withdrawal,
  scope,
  withdrawal_amount: "1000000000000000",
  state_witness: witness,
  asp_witness: witness,
  new_nullifier: "21",
  new_secret: "22",
};

const commitmentRequest = {
  commitment,
};

const executionPolicy = {
  expected_chain_id: 1,
  caller: address,
  expected_pool_code_hash: null,
  expected_entrypoint_code_hash: null,
};

const preparedExecution = {
  proving: {
    backend: "arkworks" as const,
    proof: proofBundle,
  },
  transaction: {
    kind: "withdraw" as const,
    chain_id: 1,
    target: address,
    calldata: "0x",
    value: "0",
    proof: formattedProof,
  },
  preflight: {
    kind: "withdraw" as const,
    caller: address,
    target: address,
    expected_chain_id: 1,
    actual_chain_id: 1,
    chain_id_matches: true,
    simulated: true,
    estimated_gas: 100000,
    code_hash_checks: [],
    root_checks: [],
  },
};

const finalizedExecution = {
  prepared: preparedExecution,
  request: {
    kind: "withdraw" as const,
    chain_id: 1,
    from: address,
    to: address,
    nonce: 1,
    gas_limit: 100000,
    value: "0",
    data: "0x",
    gas_price: "1",
    max_fee_per_gas: null,
    max_priority_fee_per_gas: null,
  },
};

const strictRecoveryPolicy = {
  compatibility_mode: "strict" as const,
  fail_closed: true,
};

const recoveryEvents = [
  {
    block_number: 1,
    transaction_index: 0,
    log_index: 0,
    pool_address: address,
    commitment_hash: commitment.hash,
  },
];

const smokePromises = [
  getVersion(),
  getStableBackendName(),
  deriveMasterKeys(mnemonic),
  deriveDepositSecrets("1", "2", scope, "0"),
  deriveWithdrawalSecrets("1", "2", commitment.label, "0"),
  getCommitment(
    commitment.value,
    commitment.label,
    commitment.nullifier,
    commitment.secret,
  ),
  calculateWithdrawalContext(withdrawal, scope),
  generateMerkleProof([commitment.hash, "23"], commitment.hash),
  buildCircuitMerkleWitness(merkleProof, witness.depth),
  buildWithdrawalCircuitInput(request),
  buildCommitmentCircuitInput(commitmentRequest),
  prepareWithdrawalCircuitSession(manifestJson, artifactsRoot),
  prepareWithdrawalCircuitSessionFromBytes(manifestJson, [
    { kind: "wasm", bytes: [1, 2, 3] },
  ]),
  removeWithdrawalCircuitSession("withdraw-session-1"),
  prepareCommitmentCircuitSession(manifestJson, artifactsRoot),
  prepareCommitmentCircuitSessionFromBytes(manifestJson, [
    { kind: "wasm", bytes: [1, 2, 3] },
  ]),
  removeCommitmentCircuitSession("commitment-session-1"),
  proveWithdrawal("stable", manifestJson, artifactsRoot, request),
  proveWithdrawalWithSession("stable", "withdraw-session-1", request),
  proveCommitment("stable", manifestJson, artifactsRoot, commitmentRequest),
  proveCommitmentWithSession("stable", "commitment-session-1", commitmentRequest),
  startProveWithdrawalJob("stable", manifestJson, artifactsRoot, request),
  startProveWithdrawalJobWithSession("stable", "withdraw-session-1", request),
  verifyWithdrawalProof("stable", manifestJson, artifactsRoot, proofBundle),
  verifyWithdrawalProofWithSession("stable", "withdraw-session-1", proofBundle),
  verifyCommitmentProof("stable", manifestJson, artifactsRoot, proofBundle),
  verifyCommitmentProofWithSession("stable", "commitment-session-1", proofBundle),
  pollJobStatus("job-1"),
  getProveWithdrawalJobResult("job-1"),
  cancelJob("job-1"),
  removeJob("job-1"),
  prepareWithdrawalExecution(
    "stable",
    manifestJson,
    artifactsRoot,
    request,
    1,
    address,
    "https://rpc.invalid",
    executionPolicy,
  ),
  startPrepareWithdrawalExecutionJob(
    "stable",
    manifestJson,
    artifactsRoot,
    request,
    1,
    address,
    "https://rpc.invalid",
    executionPolicy,
  ),
  getPrepareWithdrawalExecutionJobResult("job-2"),
  prepareRelayExecution(
    "stable",
    manifestJson,
    artifactsRoot,
    request,
    1,
    otherAddress,
    address,
    "https://rpc.invalid",
    executionPolicy,
  ),
  startPrepareRelayExecutionJob(
    "stable",
    manifestJson,
    artifactsRoot,
    request,
    1,
    otherAddress,
    address,
    "https://rpc.invalid",
    executionPolicy,
  ),
  getPrepareRelayExecutionJobResult("job-3"),
  registerHostProvidedSigner("host-signer", address),
  registerMobileSecureStorageSigner("secure-signer", address),
  unregisterSigner("host-signer"),
  finalizePreparedTransaction("https://rpc.invalid", preparedExecution),
  finalizePreparedTransactionForSigner(
    "https://rpc.invalid",
    "host-signer",
    preparedExecution,
  ),
  submitPreparedTransaction("https://rpc.invalid", "host-signer", preparedExecution),
  submitSignedTransaction("https://rpc.invalid", finalizedExecution, "0xdeadbeef"),
  planWithdrawalTransaction(1, address, withdrawal, proofBundle),
  planRelayTransaction(1, otherAddress, withdrawal, proofBundle, scope),
  planRagequitTransaction(1, address, proofBundle),
  planPoolStateRootRead(address),
  planAspRootRead(otherAddress, address),
  isCurrentStateRoot("24", "24"),
  formatGroth16ProofBundle(proofBundle),
  verifyArtifactBytes(manifestJson, "withdraw", "wasm", [1, 2, 3]),
  getArtifactStatuses(manifestJson, artifactsRoot, "withdraw"),
  resolveVerifiedArtifactBundle(manifestJson, artifactsRoot, "withdraw"),
  checkpointRecovery(recoveryEvents, strictRecoveryPolicy),
];

void smokePromises;

const secretHandle = "00000000-0000-4000-8000-000000000001" as SecretHandle;
const verifiedProofHandle =
  "00000000-0000-4000-8000-000000000002" as VerifiedProofHandle;
const preflightedHandle =
  "00000000-0000-4000-8000-000000000003" as PreflightedTransactionHandle;
const finalizedPreflightedHandle =
  "00000000-0000-4000-8000-000000000004" as FinalizedPreflightedTransactionHandle;
const submittedPreflightedHandle =
  "00000000-0000-4000-8000-000000000005" as SubmittedPreflightedTransactionHandle;

const secretHandleSurface = {
  deriveMasterKeysHandle,
  generateDepositSecretsHandle,
  generateWithdrawalSecretsHandle,
  getCommitmentFromHandles,
  dangerouslyExportMasterKeys,
  dangerouslyExportCommitmentPreimage,
  dangerouslyExportSecret,
  removeSecretHandle,
  clearSecretHandles,
} satisfies Record<
  | "deriveMasterKeysHandle"
  | "generateDepositSecretsHandle"
  | "generateWithdrawalSecretsHandle"
  | "getCommitmentFromHandles"
  | "dangerouslyExportMasterKeys"
  | "dangerouslyExportCommitmentPreimage"
  | "dangerouslyExportSecret"
  | "removeSecretHandle"
  | "clearSecretHandles",
  unknown
>;

const verifiedProofHandleSurface = {
  proveCommitmentWithHandle,
  proveWithdrawalWithHandles,
  proveAndVerifyCommitmentHandle,
  proveAndVerifyWithdrawalHandle,
  verifyCommitmentProofForRequestHandle,
  verifyRagequitProofForRequestHandle,
  verifyWithdrawalProofForRequestHandle,
  removeVerifiedProofHandle,
  clearVerifiedProofHandles,
} satisfies Record<
  | "proveCommitmentWithHandle"
  | "proveWithdrawalWithHandles"
  | "proveAndVerifyCommitmentHandle"
  | "proveAndVerifyWithdrawalHandle"
  | "verifyCommitmentProofForRequestHandle"
  | "verifyRagequitProofForRequestHandle"
  | "verifyWithdrawalProofForRequestHandle"
  | "removeVerifiedProofHandle"
  | "clearVerifiedProofHandles",
  unknown
>;

const executionHandleSurface = {
  preflightVerifiedWithdrawalTransactionWithHandle,
  preflightVerifiedRelayTransactionWithHandle,
  preflightVerifiedRagequitTransactionWithHandle,
  finalizePreflightedTransactionHandle,
  submitPreflightedTransactionHandle,
  submitFinalizedPreflightedTransactionHandle,
  dangerouslyExportPreflightedTransaction,
  dangerouslyExportFinalizedPreflightedTransaction,
  dangerouslyExportSubmittedPreflightedTransaction,
  removeExecutionHandle,
  clearExecutionHandles,
} satisfies Record<
  | "preflightVerifiedWithdrawalTransactionWithHandle"
  | "preflightVerifiedRelayTransactionWithHandle"
  | "preflightVerifiedRagequitTransactionWithHandle"
  | "finalizePreflightedTransactionHandle"
  | "submitPreflightedTransactionHandle"
  | "submitFinalizedPreflightedTransactionHandle"
  | "dangerouslyExportPreflightedTransaction"
  | "dangerouslyExportFinalizedPreflightedTransaction"
  | "dangerouslyExportSubmittedPreflightedTransaction"
  | "removeExecutionHandle"
  | "clearExecutionHandles",
  unknown
>;

const signedManifestSurface = {
  verifySignedManifest,
  verifySignedManifestArtifacts,
} satisfies Record<
  "verifySignedManifest" | "verifySignedManifestArtifacts",
  unknown
>;

const handleSurface = {
  secretHandleSurface,
  verifiedProofHandleSurface,
  executionHandleSurface,
  signedManifestSurface,
};

const brandedHandles = {
  secretHandle,
  verifiedProofHandle,
  preflightedHandle,
  finalizedPreflightedHandle,
  submittedPreflightedHandle,
};

void handleSurface;
void brandedHandles;

export default function App() {
  return (
    <ScrollView>
      <View style={{ padding: 24 }}>
        <Text>Privacy Pools SDK React Native smoke app</Text>
      </View>
    </ScrollView>
  );
}
