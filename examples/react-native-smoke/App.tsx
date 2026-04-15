import React from "react";
import { ScrollView, Text, View } from "react-native";
import {
  buildCircuitMerkleWitness,
  buildWithdrawalCircuitInput,
  calculateWithdrawalContext,
  cancelJob,
  checkpointRecovery,
  deriveDepositSecrets,
  deriveMasterKeys,
  deriveWithdrawalSecrets,
  fastBackendSupportedOnTarget,
  finalizePreparedTransaction,
  finalizePreparedTransactionForSigner,
  formatGroth16ProofBundle,
  generateMerkleProof,
  getArtifactStatuses,
  getCommitment,
  getPrepareRelayExecutionJobResult,
  getPrepareWithdrawalExecutionJobResult,
  getProveWithdrawalJobResult,
  getStableBackendName,
  getVersion,
  isCurrentStateRoot,
  planAspRootRead,
  planPoolStateRootRead,
  planRelayTransaction,
  planWithdrawalTransaction,
  pollJobStatus,
  prepareWithdrawalCircuitSession,
  prepareWithdrawalCircuitSessionFromBytes,
  prepareRelayExecution,
  prepareWithdrawalExecution,
  proveWithdrawal,
  proveWithdrawalWithSession,
  registerHostProvidedSigner,
  registerLocalMnemonicSigner,
  registerMobileSecureStorageSigner,
  removeJob,
  removeWithdrawalCircuitSession,
  resolveVerifiedArtifactBundle,
  startPrepareRelayExecutionJob,
  startPrepareWithdrawalExecutionJob,
  startProveWithdrawalJob,
  startProveWithdrawalJobWithSession,
  submitPreparedTransaction,
  submitSignedTransaction,
  unregisterSigner,
  verifyArtifactBytes,
  verifyWithdrawalProof,
  verifyWithdrawalProofWithSession,
} from "@0xmatthewb/privacy-pools-sdk-react-native";

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
  nullifier_hash: "13",
  precommitment_hash: "14",
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
  fastBackendSupportedOnTarget(),
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
  prepareWithdrawalCircuitSession(manifestJson, artifactsRoot),
  prepareWithdrawalCircuitSessionFromBytes(manifestJson, [
    { kind: "wasm", bytes: [1, 2, 3] },
  ]),
  removeWithdrawalCircuitSession("withdraw-session-1"),
  proveWithdrawal("stable", manifestJson, artifactsRoot, request),
  proveWithdrawalWithSession("stable", "withdraw-session-1", request),
  startProveWithdrawalJob("stable", manifestJson, artifactsRoot, request),
  startProveWithdrawalJobWithSession("stable", "withdraw-session-1", request),
  verifyWithdrawalProof("stable", manifestJson, artifactsRoot, proofBundle),
  verifyWithdrawalProofWithSession("stable", "withdraw-session-1", proofBundle),
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
  registerLocalMnemonicSigner("local-dev", mnemonic, 0),
  registerHostProvidedSigner("host-signer", address),
  registerMobileSecureStorageSigner("secure-signer", address),
  unregisterSigner("host-signer"),
  finalizePreparedTransaction("https://rpc.invalid", preparedExecution),
  finalizePreparedTransactionForSigner(
    "https://rpc.invalid",
    "host-signer",
    preparedExecution,
  ),
  submitPreparedTransaction("https://rpc.invalid", "local-dev", preparedExecution),
  submitSignedTransaction("https://rpc.invalid", finalizedExecution, "0xdeadbeef"),
  planWithdrawalTransaction(1, address, withdrawal, proofBundle),
  planRelayTransaction(1, otherAddress, withdrawal, proofBundle, scope),
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

export default function App() {
  return (
    <ScrollView>
      <View style={{ padding: 24 }}>
        <Text>Privacy Pools SDK React Native smoke app</Text>
      </View>
    </ScrollView>
  );
}
