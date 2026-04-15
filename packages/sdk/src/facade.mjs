export const Version = Object.freeze({
  Latest: "latest",
});

export const CircuitName = Object.freeze({
  Commitment: "commitment",
  MerkleTree: "merkleTree",
  Withdraw: "withdraw",
});

export const circuitToAsset = Object.freeze({
  [CircuitName.Commitment]: Object.freeze({
    wasm: "commitment.wasm",
    vkey: "commitment.vkey",
    zkey: "commitment.zkey",
  }),
  [CircuitName.MerkleTree]: Object.freeze({
    wasm: "merkleTree.wasm",
    vkey: "merkleTree.vkey",
    zkey: "merkleTree.zkey",
  }),
  [CircuitName.Withdraw]: Object.freeze({
    wasm: "withdraw.wasm",
    vkey: "withdraw.vkey",
    zkey: "withdraw.zkey",
  }),
});

export const ErrorCode = Object.freeze({
  CompatibilityUnsupported: "compatibility_unsupported",
  MissingManifest: "missing_manifest",
  MissingArtifact: "missing_artifact",
});

export const DEFAULT_LOG_FETCH_CONFIG = Object.freeze({
  blockChunkSize: 10000,
  concurrency: 3,
  chunkDelayMs: 0,
  retryOnFailure: true,
  maxRetries: 3,
  retryBaseDelayMs: 1000,
});

export class SDKError extends Error {
  constructor(message, code = ErrorCode.CompatibilityUnsupported, details = undefined) {
    super(message);
    this.name = "SDKError";
    this.code = code;
    this.details = details;
  }
}

export class CompatibilityError extends SDKError {
  constructor(message, code = ErrorCode.CompatibilityUnsupported, details = undefined) {
    super(message, code, details);
    this.name = "CompatibilityError";
  }
}

export class ProofError extends SDKError {
  constructor(message, details = undefined) {
    super(message, "proof_error", details);
    this.name = "ProofError";
  }
}

export class AccountError extends SDKError {
  constructor(message, details = undefined) {
    super(message, "account_error", details);
    this.name = "AccountError";
  }
}

export class DataError extends SDKError {
  constructor(message, details = undefined) {
    super(message, "data_error", details);
    this.name = "DataError";
  }
}

export class ContractError extends SDKError {
  constructor(message, details = undefined) {
    super(message, "contract_error", details);
    this.name = "ContractError";
  }
}

export class CircuitInitialization extends CompatibilityError {
  constructor(message, details = undefined) {
    super(message, "circuit_initialization", details);
    this.name = "CircuitInitialization";
  }
}

export class FetchArtifact extends CompatibilityError {
  constructor(message, details = undefined) {
    super(message, "fetch_artifact", details);
    this.name = "FetchArtifact";
  }
}

export class PrivacyPoolError extends SDKError {
  constructor(message, details = undefined) {
    super(message, "privacy_pool_error", details);
    this.name = "PrivacyPoolError";
  }
}

export class InvalidRpcUrl extends CompatibilityError {
  constructor(message = "invalid RPC URL", details = undefined) {
    super(message, "invalid_rpc_url", details);
    this.name = "InvalidRpcUrl";
  }
}

export function createRuntimeFacade(PrivacyPoolsSdkClient) {
  class BlockchainProvider {
    constructor(rpcUrl) {
      if (!rpcUrl || !String(rpcUrl).startsWith("http")) {
        throw new InvalidRpcUrl(String(rpcUrl ?? ""));
      }
      this.rpcUrl = String(rpcUrl);
    }

    async getBalance() {
      throw unsupported(
        "BlockchainProvider.getBalance requires app-owned RPC transport; this facade does not bundle viem",
      );
    }
  }

  class Circuits {
    constructor(options = {}) {
      this.client = options.client ?? new PrivacyPoolsSdkClient();
      this.artifactsRoot = options.artifactsRoot ?? options.baseUrl;
      this.manifests = {
        [CircuitName.Withdraw]:
          options.withdrawalManifestJson ?? options.withdrawManifestJson ?? options.manifestJson,
        [CircuitName.Commitment]:
          options.commitmentManifestJson ?? options.manifestJson,
      };
      this.initialized = false;
      this.version = Version.Latest;
      this.binaries = undefined;
    }

    async downloadArtifacts(version = Version.Latest) {
      const [withdraw, commitment] = await Promise.all([
        this.#downloadCircuitArtifacts(CircuitName.Withdraw),
        this.#downloadCircuitArtifacts(CircuitName.Commitment),
      ]);
      this.version = version;
      return { withdraw, commitment };
    }

    async initArtifacts(version = Version.Latest) {
      this.binaries = await this.downloadArtifacts(version);
      this.version = version;
      this.initialized = true;
    }

    async getVerificationKey(circuitName, version = Version.Latest) {
      const artifacts = await this.#artifactsFor(circuitName, version);
      return artifacts.vkey;
    }

    async getProvingKey(circuitName, version = Version.Latest) {
      const artifacts = await this.#artifactsFor(circuitName, version);
      return artifacts.zkey;
    }

    async getWasm(circuitName, version = Version.Latest) {
      const artifacts = await this.#artifactsFor(circuitName, version);
      return artifacts.wasm;
    }

    async artifactInputsFor(circuitName, version = Version.Latest) {
      const artifacts = await this.#artifactsFor(circuitName, version);
      return Object.entries(artifacts).map(([kind, bytes]) => ({ kind, bytes }));
    }

    manifestFor(circuitName) {
      const manifestJson = this.manifests[circuitName];
      if (!manifestJson) {
        throw new CircuitInitialization(
          `manifestJson is required for circuit ${circuitName}`,
          { circuitName },
        );
      }
      return manifestJson;
    }

    rootFor(circuitName) {
      if (!this.artifactsRoot) {
        throw new CircuitInitialization(
          `artifactsRoot or baseUrl is required for circuit ${circuitName}`,
          { circuitName },
        );
      }
      return this.artifactsRoot;
    }

    async #artifactsFor(circuitName, version) {
      if (!this.initialized || this.version !== version) {
        await this.initArtifacts(version);
      }
      const artifacts = this.binaries?.[circuitName];
      if (!artifacts) {
        throw new CircuitInitialization(`Circuit artifacts not found for ${circuitName}`);
      }
      return artifacts;
    }

    async #downloadCircuitArtifacts(circuitName) {
      if (circuitName === CircuitName.MerkleTree) {
        throw new CircuitInitialization("merkleTree artifacts are not shipped by this SDK yet");
      }

      const manifestJson = this.manifestFor(circuitName);
      const manifest = JSON.parse(manifestJson);
      const descriptors = manifest.artifacts?.filter(
        (artifact) => artifact.circuit === circuitName,
      );
      if (!descriptors?.length) {
        throw new CircuitInitialization(`manifest does not declare ${circuitName} artifacts`);
      }

      const baseUrl = normalizeArtifactsRoot(this.rootFor(circuitName));
      const artifacts = await Promise.all(
        descriptors.map(async (descriptor) => {
          const url = new URL(descriptor.filename, baseUrl);
          const response = await fetch(url);
          if (!response.ok) {
            throw new FetchArtifact(`failed to fetch ${url.toString()}`);
          }
          return {
            kind: descriptor.kind,
            bytes: new Uint8Array(await response.arrayBuffer()),
          };
        }),
      );

      await this.client.verifyArtifactBytes(manifestJson, circuitName, artifacts);
      return artifacts.reduce((result, artifact) => {
        result[artifact.kind] = artifact.bytes;
        return result;
      }, {});
    }
  }

  class CommitmentService {
    constructor(circuits) {
      this.circuits = circuits;
      this.client = circuits?.client ?? new PrivacyPoolsSdkClient();
    }

    async proveCommitment(value, label, nullifier, secret) {
      const commitment = await this.client.getCommitment(
        decimalString(value),
        decimalString(label),
        decimalString(nullifier),
        decimalString(secret),
      );
      const session = await this.client.prepareCommitmentCircuitSessionFromBytes(
        this.circuits.manifestFor(CircuitName.Commitment),
        await this.circuits.artifactInputsFor(CircuitName.Commitment),
      );
      try {
        const proving = await this.client.proveCommitmentWithSession(
          "stable",
          session.handle,
          { commitment },
        );
        return proving.proof;
      } finally {
        await this.client.removeCommitmentCircuitSession(session.handle);
      }
    }

    async verifyCommitment(proof) {
      const session = await this.client.prepareCommitmentCircuitSessionFromBytes(
        this.circuits.manifestFor(CircuitName.Commitment),
        await this.circuits.artifactInputsFor(CircuitName.Commitment),
      );
      try {
        return await this.client.verifyCommitmentProofWithSession(
          "stable",
          session.handle,
          normalizeProofBundle(proof),
        );
      } finally {
        await this.client.removeCommitmentCircuitSession(session.handle);
      }
    }
  }

  class WithdrawalService {
    constructor(circuits) {
      this.circuits = circuits;
      this.client = circuits?.client ?? new PrivacyPoolsSdkClient();
    }

    async proveWithdrawal(commitment, input) {
      const request = toWithdrawalRequest(commitment, input);
      const session = await this.client.prepareWithdrawalCircuitSessionFromBytes(
        this.circuits.manifestFor(CircuitName.Withdraw),
        await this.circuits.artifactInputsFor(CircuitName.Withdraw),
      );
      try {
        const proving = await this.client.proveWithdrawalWithSession(
          "stable",
          session.handle,
          request,
        );
        return proving.proof;
      } finally {
        await this.client.removeWithdrawalCircuitSession(session.handle);
      }
    }

    async verifyWithdrawal(proof) {
      const session = await this.client.prepareWithdrawalCircuitSessionFromBytes(
        this.circuits.manifestFor(CircuitName.Withdraw),
        await this.circuits.artifactInputsFor(CircuitName.Withdraw),
      );
      try {
        return await this.client.verifyWithdrawalProofWithSession(
          "stable",
          session.handle,
          normalizeProofBundle(proof),
        );
      } finally {
        await this.client.removeWithdrawalCircuitSession(session.handle);
      }
    }
  }

  class PrivacyPoolSDK {
    constructor(circuits) {
      this.circuits = circuits;
      this.commitmentService = new CommitmentService(circuits);
      this.withdrawalService = new WithdrawalService(circuits);
    }

    createContractInstance() {
      throw unsupported("ContractInteractionsService requires the Rust-backed JS execution facade");
    }

    async proveCommitment(value, label, nullifier, secret) {
      return this.commitmentService.proveCommitment(value, label, nullifier, secret);
    }

    async verifyCommitment(proof) {
      return this.commitmentService.verifyCommitment(proof);
    }

    async proveWithdrawal(commitment, input) {
      return this.withdrawalService.proveWithdrawal(commitment, input);
    }

    async verifyWithdrawal(withdrawalProof) {
      return this.withdrawalService.verifyWithdrawal(withdrawalProof);
    }
  }

  class AccountService {
    constructor(...args) {
      this.args = args;
      this.client = extractClient(args, PrivacyPoolsSdkClient);
    }

    getSpendableCommitments(state, mode = "safe") {
      if (!state) {
        throw unsupported(
          "AccountService.getSpendableCommitments requires an explicit recovered account state",
        );
      }
      return mode === "legacy"
        ? state.legacySpendableCommitments ?? []
        : state.safeSpendableCommitments ?? [];
    }

    sync() {
      throw unsupported("AccountService sync requires app-owned event/RPC transport");
    }

    async checkpointRecovery(events, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "checkpointRecovery",
        normalizePoolEvents(events),
        normalizeRecoveryPolicy(policy),
      );
    }

    async deriveRecoveryKeyset(mnemonic, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "deriveRecoveryKeyset",
        mnemonic,
        normalizeRecoveryPolicy(policy),
      );
    }

    async recoverAccountState(mnemonic, pools, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "recoverAccountState",
        mnemonic,
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      );
    }

    async recoverAccountStateWithKeyset(keyset, pools, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "recoverAccountStateWithKeyset",
        normalizeRecoveryKeyset(keyset),
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      );
    }
  }

  class DataService {
    constructor(...args) {
      this.args = args;
      this.client = extractClient(args, PrivacyPoolsSdkClient);
    }

    async getDeposits() {
      throw unsupported("DataService event fetching is not yet exposed through the JS facade");
    }

    async getWithdrawals() {
      throw unsupported("DataService event fetching is not yet exposed through the JS facade");
    }

    async getRagequits() {
      throw unsupported("DataService event fetching is not yet exposed through the JS facade");
    }

    async checkpointRecovery(events, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "checkpointRecovery",
        normalizePoolEvents(events),
        normalizeRecoveryPolicy(policy),
      );
    }

    async deriveRecoveryKeyset(mnemonic, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "deriveRecoveryKeyset",
        mnemonic,
        normalizeRecoveryPolicy(policy),
      );
    }

    async recoverAccountState(mnemonic, pools, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "recoverAccountState",
        mnemonic,
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      );
    }

    async recoverAccountStateWithKeyset(keyset, pools, policy = defaultRecoveryPolicy()) {
      return callClient(
        this.client,
        "recoverAccountStateWithKeyset",
        normalizeRecoveryKeyset(keyset),
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      );
    }
  }

  class ContractInteractionsService {
    constructor(...args) {
      this.args = args;
      this.client = extractClient(args, PrivacyPoolsSdkClient);
    }

    async getStateRoot(poolAddress) {
      return callClient(this.client, "planPoolStateRootRead", poolAddress);
    }

    async getScopeData(entrypointAddress, poolAddress) {
      return callClient(this.client, "planAspRootRead", entrypointAddress, poolAddress);
    }

    async planWithdrawalTransaction(chainId, poolAddress, withdrawal, proof) {
      return callClient(
        this.client,
        "planWithdrawalTransaction",
        chainId,
        poolAddress,
        withdrawal,
        normalizeProofBundle(proof),
      );
    }

    async planRelayTransaction(chainId, entrypointAddress, withdrawal, proof, scope) {
      return callClient(
        this.client,
        "planRelayTransaction",
        chainId,
        entrypointAddress,
        withdrawal,
        normalizeProofBundle(proof),
        decimalString(scope),
      );
    }

    async planRagequitTransaction(chainId, poolAddress, proof) {
      return callClient(
        this.client,
        "planRagequitTransaction",
        chainId,
        poolAddress,
        normalizeProofBundle(proof),
      );
    }

    async isCurrentStateRoot(expectedRoot, currentRoot) {
      return callClient(
        this.client,
        "isCurrentStateRoot",
        decimalString(expectedRoot),
        decimalString(currentRoot),
      );
    }

    async formatGroth16Proof(proof) {
      return callClient(this.client, "formatGroth16ProofBundle", normalizeProofBundle(proof));
    }
  }

  const createClient = () => new PrivacyPoolsSdkClient();

  return {
    AccountService,
    AccountError,
    BlockchainProvider,
    CircuitInitialization,
    CircuitName,
    Circuits,
    CommitmentService,
    CompatibilityError,
    ContractError,
    ContractInteractionsService,
    DataError,
    DataService,
    DEFAULT_LOG_FETCH_CONFIG,
    ErrorCode,
    FetchArtifact,
    InvalidRpcUrl,
    PrivacyPoolError,
    PrivacyPoolSDK,
    ProofError,
    SDKError,
    Version,
    bigintToHash,
    bigintToHex,
    calculateContext: async (withdrawal, scope) =>
      createClient().calculateWithdrawalContext(withdrawal, decimalString(scope)),
    circuitToAsset,
    generateDepositSecrets: async (...args) => {
      const { masterKeys, scope, index } = normalizeSecretArgs(args, "scope");
      const secrets = await createClient().deriveDepositSecrets(masterKeys, decimalString(scope), decimalString(index));
      return toV1Secrets(secrets);
    },
    generateMasterKeys: async (mnemonic) =>
      toV1MasterKeys(await createClient().deriveMasterKeys(mnemonic)),
    generateMerkleProof: async (leaves, leaf) =>
      createClient().generateMerkleProof(
        leaves.map(decimalString),
        decimalString(leaf),
      ),
    generateWithdrawalSecrets: async (...args) => {
      const { masterKeys, label, index } = normalizeSecretArgs(args, "label");
      const secrets = await createClient().deriveWithdrawalSecrets(masterKeys, decimalString(label), decimalString(index));
      return toV1Secrets(secrets);
    },
    getCommitment: async (value, label, nullifier, secret) => {
      const commitment = await createClient().getCommitment(
        decimalString(value),
        decimalString(label),
        decimalString(nullifier),
        decimalString(secret),
      );
      return toV1Commitment(commitment);
    },
    checkpointRecovery: async (events, policy = defaultRecoveryPolicy()) =>
      callClient(
        createClient(),
        "checkpointRecovery",
        normalizePoolEvents(events),
        normalizeRecoveryPolicy(policy),
      ),
    deriveRecoveryKeyset: async (mnemonic, policy = defaultRecoveryPolicy()) =>
      callClient(
        createClient(),
        "deriveRecoveryKeyset",
        mnemonic,
        normalizeRecoveryPolicy(policy),
      ),
    recoverAccountState: async (mnemonic, pools, policy = defaultRecoveryPolicy()) =>
      callClient(
        createClient(),
        "recoverAccountState",
        mnemonic,
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      ),
    recoverAccountStateWithKeyset: async (
      keyset,
      pools,
      policy = defaultRecoveryPolicy(),
    ) =>
      callClient(
        createClient(),
        "recoverAccountStateWithKeyset",
        normalizeRecoveryKeyset(keyset),
        normalizePoolRecoveryInputs(pools),
        normalizeRecoveryPolicy(policy),
      ),
    formatGroth16ProofBundle: async (proof) =>
      callClient(createClient(), "formatGroth16ProofBundle", normalizeProofBundle(proof)),
    hashPrecommitment: async (nullifier, secret) =>
      hashPrecommitmentWithClient(createClient(), nullifier, secret),
    isCurrentStateRoot: async (expectedRoot, currentRoot) =>
      callClient(
        createClient(),
        "isCurrentStateRoot",
        decimalString(expectedRoot),
        decimalString(currentRoot),
      ),
    planAspRootRead: async (entrypointAddress, poolAddress) =>
      callClient(createClient(), "planAspRootRead", entrypointAddress, poolAddress),
    planPoolStateRootRead: async (poolAddress) =>
      callClient(createClient(), "planPoolStateRootRead", poolAddress),
    planRagequitTransaction: async (chainId, poolAddress, proof) =>
      callClient(
        createClient(),
        "planRagequitTransaction",
        chainId,
        poolAddress,
        normalizeProofBundle(proof),
      ),
    planRelayTransaction: async (chainId, entrypointAddress, withdrawal, proof, scope) =>
      callClient(
        createClient(),
        "planRelayTransaction",
        chainId,
        entrypointAddress,
        withdrawal,
        normalizeProofBundle(proof),
        decimalString(scope),
      ),
    planWithdrawalTransaction: async (chainId, poolAddress, withdrawal, proof) =>
      callClient(
        createClient(),
        "planWithdrawalTransaction",
        chainId,
        poolAddress,
        withdrawal,
        normalizeProofBundle(proof),
      ),
  };
}

function normalizeArtifactsRoot(root) {
  const value = String(root);
  return value.endsWith("/") ? value : `${value}/`;
}

function normalizeSecretArgs(args, scopeName) {
  if (args.length === 3 && typeof args[0] === "object") {
    return {
      masterKeys: normalizeMasterKeys(args[0]),
      [scopeName]: args[1],
      index: args[2],
    };
  }
  if (args.length === 4) {
    return {
      masterKeys: {
        masterNullifier: decimalString(args[0]),
        masterSecret: decimalString(args[1]),
      },
      [scopeName]: args[2],
      index: args[3],
    };
  }
  throw new TypeError("expected master keys plus scope/label and index");
}

function normalizeMasterKeys(masterKeys) {
  return {
    masterNullifier: decimalString(masterKeys.masterNullifier ?? masterKeys.master_nullifier),
    masterSecret: decimalString(masterKeys.masterSecret ?? masterKeys.master_secret),
  };
}

function toV1MasterKeys(masterKeys) {
  return {
    masterNullifier: BigInt(masterKeys.masterNullifier),
    masterSecret: BigInt(masterKeys.masterSecret),
  };
}

function toV1Secrets(secrets) {
  return {
    nullifier: BigInt(secrets.nullifier),
    secret: BigInt(secrets.secret),
  };
}

function toV1Commitment(commitment) {
  return {
    ...commitment,
    hash: BigInt(commitment.hash),
    nullifierHash: BigInt(commitment.nullifierHash),
    preimage: {
      value: BigInt(commitment.value),
      label: BigInt(commitment.label),
      precommitment: {
        hash: BigInt(commitment.precommitmentHash),
        nullifier: BigInt(commitment.nullifier),
        secret: BigInt(commitment.secret),
      },
    },
  };
}

function fromV1Commitment(commitment) {
  if (commitment?.preimage) {
    return {
      hash: decimalString(commitment.hash),
      nullifierHash: decimalString(commitment.nullifierHash),
      precommitmentHash: decimalString(commitment.preimage.precommitment.hash),
      value: decimalString(commitment.preimage.value),
      label: decimalString(commitment.preimage.label),
      nullifier: decimalString(commitment.preimage.precommitment.nullifier),
      secret: decimalString(commitment.preimage.precommitment.secret),
    };
  }
  return commitment;
}

function toWithdrawalRequest(commitment, input) {
  if (input?.commitment && input?.withdrawal) {
    return input;
  }
  if (!input?.withdrawal) {
    throw unsupported(
      "v1 withdrawal facade requires input.withdrawal so Rust can validate context",
    );
  }

  const flatCommitment = fromV1Commitment(commitment);
  return {
    commitment: flatCommitment,
    withdrawal: input.withdrawal,
    scope: decimalString(input.scope),
    withdrawalAmount: decimalString(input.withdrawalAmount),
    stateWitness: toCircuitWitness(
      input.stateMerkleProof,
      input.stateRoot,
      flatCommitment.hash,
      input.stateTreeDepth,
    ),
    aspWitness: toCircuitWitness(
      input.aspMerkleProof,
      input.aspRoot,
      flatCommitment.hash,
      input.aspTreeDepth,
    ),
    newNullifier: decimalString(input.newNullifier),
    newSecret: decimalString(input.newSecret),
  };
}

function toCircuitWitness(proof, root, leaf, depth) {
  return {
    root: decimalString(root ?? proof?.root),
    leaf: decimalString(proof?.leaf ?? leaf),
    index: Number(proof?.index ?? 0),
    siblings: (proof?.siblings ?? []).map(decimalString),
    depth: Number(depth ?? proof?.depth ?? proof?.siblings?.length ?? 0),
  };
}

function normalizeProofBundle(proof) {
  return {
    proof: normalizeSnarkProof(proof.proof),
    publicSignals: proof.publicSignals ?? proof.public_signals,
  };
}

function normalizeSnarkProof(proof) {
  return {
    piA: proof.piA ?? proof.pi_a,
    piB: proof.piB ?? proof.pi_b,
    piC: proof.piC ?? proof.pi_c,
    protocol: proof.protocol,
    curve: proof.curve,
  };
}

function defaultRecoveryPolicy() {
  return {
    compatibilityMode: "legacy",
    failClosed: true,
  };
}

function normalizeRecoveryPolicy(policy) {
  return {
    compatibilityMode:
      policy.compatibilityMode ?? policy.compatibility_mode ?? "legacy",
    failClosed: policy.failClosed ?? policy.fail_closed ?? true,
  };
}

function normalizePoolEvents(events) {
  return events.map((event) => ({
    blockNumber: event.blockNumber ?? event.block_number,
    transactionIndex: event.transactionIndex ?? event.transaction_index,
    logIndex: event.logIndex ?? event.log_index,
    poolAddress: event.poolAddress ?? event.pool_address,
    commitmentHash: event.commitmentHash ?? event.commitment_hash,
  }));
}

function normalizeRecoveryKeyset(keyset) {
  return {
    safe: normalizeMasterKeys(keyset.safe),
    legacy: keyset.legacy ? normalizeMasterKeys(keyset.legacy) : undefined,
  };
}

function normalizePoolRecoveryInputs(pools) {
  return pools.map((pool) => ({
    scope: decimalString(pool.scope),
    depositEvents: (pool.depositEvents ?? pool.deposit_events ?? []).map(
      normalizeDepositEvent,
    ),
    withdrawalEvents: (
      pool.withdrawalEvents ??
      pool.withdrawal_events ??
      []
    ).map(normalizeWithdrawalEvent),
    ragequitEvents: (pool.ragequitEvents ?? pool.ragequit_events ?? []).map(
      normalizeRagequitEvent,
    ),
  }));
}

function normalizeDepositEvent(event) {
  return {
    commitmentHash: decimalString(event.commitmentHash ?? event.commitment_hash),
    label: decimalString(event.label),
    value: decimalString(event.value),
    precommitmentHash: decimalString(
      event.precommitmentHash ?? event.precommitment_hash,
    ),
    blockNumber: Number(event.blockNumber ?? event.block_number),
    transactionHash: normalizeBytes32(event.transactionHash ?? event.transaction_hash),
  };
}

function normalizeWithdrawalEvent(event) {
  return {
    withdrawnValue: decimalString(event.withdrawnValue ?? event.withdrawn_value),
    spentNullifierHash: decimalString(
      event.spentNullifierHash ?? event.spent_nullifier_hash,
    ),
    newCommitmentHash: decimalString(
      event.newCommitmentHash ?? event.new_commitment_hash,
    ),
    blockNumber: Number(event.blockNumber ?? event.block_number),
    transactionHash: normalizeBytes32(event.transactionHash ?? event.transaction_hash),
  };
}

function normalizeRagequitEvent(event) {
  return {
    commitmentHash: decimalString(event.commitmentHash ?? event.commitment_hash),
    label: decimalString(event.label),
    value: decimalString(event.value),
    blockNumber: Number(event.blockNumber ?? event.block_number),
    transactionHash: normalizeBytes32(event.transactionHash ?? event.transaction_hash),
  };
}

function normalizeBytes32(value) {
  const stringValue = String(value);
  if (stringValue.startsWith("0x")) {
    return `0x${stringValue.slice(2).padStart(64, "0")}`;
  }
  return `0x${BigInt(stringValue).toString(16).padStart(64, "0")}`;
}

async function hashPrecommitmentWithClient(client, nullifier, secret) {
  const commitment = await client.getCommitment(
    "1",
    "1",
    decimalString(nullifier),
    decimalString(secret),
  );
  const hash =
    commitment.nullifierHash ??
    commitment.nullifier_hash ??
    commitment.precommitmentHash ??
    commitment.precommitment_hash;
  return BigInt(hash);
}

function extractClient(args, PrivacyPoolsSdkClient) {
  const candidate = args.find((arg) => arg?.client)?.client ?? args.find(
    (arg) => arg?.getRuntimeCapabilities,
  );
  return candidate ?? new PrivacyPoolsSdkClient();
}

async function callClient(client, methodName, ...args) {
  if (typeof client?.[methodName] !== "function") {
    throw unsupported(`${methodName} is not available in this runtime`);
  }
  return client[methodName](...args);
}

function bigintToHash(value) {
  return BigInt(value);
}

function bigintToHex(value) {
  if (value === undefined || value === null) {
    return "0x0";
  }
  return `0x${BigInt(value).toString(16)}`;
}

function decimalString(value) {
  if (value === undefined || value === null) {
    throw new TypeError("value is required");
  }
  return typeof value === "bigint" ? value.toString() : String(value);
}

function unsupported(message) {
  throw new CompatibilityError(message);
}
