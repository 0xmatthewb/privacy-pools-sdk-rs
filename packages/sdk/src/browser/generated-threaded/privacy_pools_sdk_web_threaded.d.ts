/* tslint:disable */
/* eslint-disable */

export function buildCircuitMerkleWitnessJson(proof_json: string, depth: number): string;

export function buildCommitmentCircuitInputJson(request_json: string): string;

export function buildCommitmentWitnessInputFromHandleJson(commitment_handle: string): string;

export function buildCommitmentWitnessInputJson(request_json: string): string;

export function buildWithdrawalCircuitInputJson(request_json: string): string;

export function buildWithdrawalWitnessInputFromHandlesJson(commitment_handle: string, withdrawal_json: string, scope: string, withdrawal_amount: string, state_witness_json: string, asp_witness_json: string, new_secrets_handle: string): string;

export function buildWithdrawalWitnessInputJson(request_json: string): string;

export function calculateWithdrawalContextJson(withdrawal_json: string, scope: string): string;

export function checkpointRecoveryJson(events_json: string, policy_json: string): string;

export function clearExecutionHandles(): boolean;

export function clearSecretHandles(): boolean;

export function clearVerifiedProofHandles(): boolean;

export function deriveMasterKeysHandle(mnemonic: string): string;

export function deriveMasterKeysHandleBytes(mnemonic: Uint8Array): string;

export function deriveRecoveryKeysetJson(mnemonic: string, policy_json: string): string;

export function exportFinalizedPreflightedTransactionInternal(handle: string): string;

export function exportPreflightedTransactionInternal(handle: string): string;

export function exportSubmittedPreflightedTransactionInternal(handle: string): string;

export function formatGroth16ProofBundleJson(proof_json: string): string;

export function generateDepositSecretsHandle(master_keys_handle: string, scope: string, index: string): string;

export function generateMerkleProofJson(leaves_json: string, leaf: string): string;

export function generateWithdrawalSecretsHandle(master_keys_handle: string, label: string, index: string): string;

export function getArtifactStatusesJson(manifest_json: string, artifacts_root: string, circuit: string): string;

export function getBrowserSupportStatusJson(): string;

export function getCommitmentFromHandles(value: string, label: string, secrets_handle: string): string;

export function getCommitmentJson(value: string, label: string, nullifier: string, secret: string): string;

export function getStableBackendName(): string;

export function getVersion(): string;

export function importMasterKeysHandleJson(master_keys_json: string): string;

export function initThreadPool(num_threads: number): Promise<any>;

export function isCurrentStateRoot(expected_root: string, current_root: string): boolean;

export function planAspRootReadJson(entrypoint_address: string, pool_address: string): string;

export function planPoolStateRootReadJson(pool_address: string): string;

export function planRagequitTransactionJson(chain_id: bigint, pool_address: string, proof_json: string): string;

export function planRelayTransactionJson(chain_id: bigint, entrypoint_address: string, withdrawal_json: string, proof_json: string, scope: string): string;

export function planVerifiedRagequitTransactionWithHandleJson(chain_id: bigint, pool_address: string, proof_handle: string): string;

export function planVerifiedRelayTransactionWithHandleJson(chain_id: bigint, entrypoint_address: string, proof_handle: string): string;

export function planVerifiedWithdrawalTransactionWithHandleJson(chain_id: bigint, pool_address: string, proof_handle: string): string;

export function planWithdrawalTransactionJson(chain_id: bigint, pool_address: string, withdrawal_json: string, proof_json: string): string;

export function prepareCommitmentCircuitSessionFromBytes(manifest_json: string, artifacts: Array<any>): string;

export function prepareWithdrawalCircuitSessionFromBytes(manifest_json: string, artifacts: Array<any>): string;

export function proveCommitmentWithSessionWitnessBinary(session_handle: string, witness_binary: Uint32Array): string;

export function proveCommitmentWithSessionWitnessJson(session_handle: string, witness_json: string): string;

export function proveCommitmentWithWitnessJson(manifest_json: string, artifacts_json: string, witness_json: string): string;

export function proveWithdrawalWithSessionWitnessBinary(session_handle: string, witness_binary: Uint32Array): string;

export function proveWithdrawalWithSessionWitnessJson(session_handle: string, witness_json: string): string;

export function proveWithdrawalWithWitnessJson(manifest_json: string, artifacts_json: string, witness_json: string): string;

export function recoverAccountStateJson(mnemonic: string, pools_json: string, policy_json: string): string;

export function recoverAccountStateWithKeysetJson(keyset_json: string, pools_json: string, policy_json: string): string;

export function registerFinalizedPreflightedTransactionJson(preflighted_handle: string, request_json: string): string;

export function registerReconfirmedPreflightedTransactionJson(preflighted_handle: string, preflight_json: string): string;

export function registerSubmittedPreflightedTransactionJson(finalized_handle: string, preflight_json: string, receipt_json: string): string;

export function registerVerifiedRagequitPreflightedTransactionJson(proof_handle: string, pool_address: string, transaction_json: string, preflight_json: string): string;

export function registerVerifiedRelayPreflightedTransactionJson(proof_handle: string, entrypoint_address: string, pool_address: string, transaction_json: string, preflight_json: string): string;

export function registerVerifiedWithdrawalPreflightedTransactionJson(proof_handle: string, pool_address: string, transaction_json: string, preflight_json: string): string;

export function removeCommitmentCircuitSession(session_handle: string): boolean;

export function removeExecutionHandle(handle: string): boolean;

export function removeSecretHandle(handle: string): boolean;

export function removeVerifiedProofHandle(handle: string): boolean;

export function removeWithdrawalCircuitSession(session_handle: string): boolean;

export function resolveVerifiedArtifactBundleJson(manifest_json: string, artifacts_root: string, circuit: string): string;

export function verifyArtifactBytes(manifest_json: string, circuit: string, artifacts: Array<any>): string;

export function verifyArtifactBytesJson(manifest_json: string, circuit: string, artifacts_json: string): string;

export function verifyCommitmentProof(manifest_json: string, artifacts: Array<any>, proof_json: string): boolean;

export function verifyCommitmentProofForHandleJson(proof_json: string, commitment_handle: string): string;

export function verifyCommitmentProofWithSession(session_handle: string, proof_json: string): boolean;

export function verifyRagequitProofForHandleJson(proof_json: string, commitment_handle: string): string;

export function verifySignedManifest(payload_json: string, signature_hex: string, public_key_hex: string): string;

export function verifySignedManifestArtifactsJson(payload_json: string, signature_hex: string, public_key_hex: string, artifacts_json: string): string;

export function verifyWithdrawalProof(manifest_json: string, artifacts: Array<any>, proof_json: string): boolean;

export function verifyWithdrawalProofForHandlesJson(proof_json: string, commitment_handle: string, withdrawal_json: string, scope: string, withdrawal_amount: string, state_witness_json: string, asp_witness_json: string, new_secrets_handle: string): string;

export function verifyWithdrawalProofWithSession(session_handle: string, proof_json: string): boolean;

export class wbg_rayon_PoolBuilder {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    build(): void;
    mainJS(): string;
    numThreads(): number;
    receiver(): number;
}

export function wbg_rayon_start_worker(receiver: number): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly buildCircuitMerkleWitnessJson: (a: number, b: number, c: number, d: number) => void;
    readonly buildCommitmentCircuitInputJson: (a: number, b: number, c: number) => void;
    readonly buildCommitmentWitnessInputFromHandleJson: (a: number, b: number, c: number) => void;
    readonly buildCommitmentWitnessInputJson: (a: number, b: number, c: number) => void;
    readonly buildWithdrawalCircuitInputJson: (a: number, b: number, c: number) => void;
    readonly buildWithdrawalWitnessInputFromHandlesJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => void;
    readonly buildWithdrawalWitnessInputJson: (a: number, b: number, c: number) => void;
    readonly calculateWithdrawalContextJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly checkpointRecoveryJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly clearExecutionHandles: (a: number) => void;
    readonly clearSecretHandles: (a: number) => void;
    readonly clearVerifiedProofHandles: (a: number) => void;
    readonly deriveMasterKeysHandle: (a: number, b: number, c: number) => void;
    readonly deriveMasterKeysHandleBytes: (a: number, b: number) => void;
    readonly deriveRecoveryKeysetJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly exportFinalizedPreflightedTransactionInternal: (a: number, b: number, c: number) => void;
    readonly exportPreflightedTransactionInternal: (a: number, b: number, c: number) => void;
    readonly exportSubmittedPreflightedTransactionInternal: (a: number, b: number, c: number) => void;
    readonly formatGroth16ProofBundleJson: (a: number, b: number, c: number) => void;
    readonly generateDepositSecretsHandle: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly generateMerkleProofJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly generateWithdrawalSecretsHandle: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly getArtifactStatusesJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly getBrowserSupportStatusJson: (a: number) => void;
    readonly getCommitmentFromHandles: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly getCommitmentJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly getStableBackendName: (a: number) => void;
    readonly getVersion: (a: number) => void;
    readonly importMasterKeysHandleJson: (a: number, b: number, c: number) => void;
    readonly isCurrentStateRoot: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly planAspRootReadJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly planPoolStateRootReadJson: (a: number, b: number, c: number) => void;
    readonly planRagequitTransactionJson: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly planRelayTransactionJson: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
    readonly planVerifiedRagequitTransactionWithHandleJson: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly planVerifiedRelayTransactionWithHandleJson: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly planVerifiedWithdrawalTransactionWithHandleJson: (a: number, b: bigint, c: number, d: number, e: number, f: number) => void;
    readonly planWithdrawalTransactionJson: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly prepareCommitmentCircuitSessionFromBytes: (a: number, b: number, c: number, d: number) => void;
    readonly prepareWithdrawalCircuitSessionFromBytes: (a: number, b: number, c: number, d: number) => void;
    readonly proveCommitmentWithSessionWitnessBinary: (a: number, b: number, c: number, d: number) => void;
    readonly proveCommitmentWithSessionWitnessJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly proveCommitmentWithWitnessJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly proveWithdrawalWithSessionWitnessBinary: (a: number, b: number, c: number, d: number) => void;
    readonly proveWithdrawalWithSessionWitnessJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly proveWithdrawalWithWitnessJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly recoverAccountStateJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly registerFinalizedPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly registerReconfirmedPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly registerSubmittedPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly registerVerifiedRagequitPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly registerVerifiedRelayPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly registerVerifiedWithdrawalPreflightedTransactionJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly removeCommitmentCircuitSession: (a: number, b: number, c: number) => void;
    readonly removeExecutionHandle: (a: number, b: number, c: number) => void;
    readonly removeSecretHandle: (a: number, b: number, c: number) => void;
    readonly removeVerifiedProofHandle: (a: number, b: number, c: number) => void;
    readonly removeWithdrawalCircuitSession: (a: number, b: number, c: number) => void;
    readonly resolveVerifiedArtifactBundleJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly verifyArtifactBytes: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly verifyArtifactBytesJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly verifyCommitmentProof: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly verifyCommitmentProofForHandleJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly verifyCommitmentProofWithSession: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly verifyRagequitProofForHandleJson: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly verifySignedManifest: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly verifySignedManifestArtifactsJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyWithdrawalProof: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly verifyWithdrawalProofForHandlesJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => void;
    readonly verifyWithdrawalProofWithSession: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly recoverAccountStateWithKeysetJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly __wbg_wbg_rayon_poolbuilder_free: (a: number, b: number) => void;
    readonly initThreadPool: (a: number) => number;
    readonly wbg_rayon_poolbuilder_build: (a: number) => void;
    readonly wbg_rayon_poolbuilder_mainJS: (a: number) => number;
    readonly wbg_rayon_poolbuilder_numThreads: (a: number) => number;
    readonly wbg_rayon_poolbuilder_receiver: (a: number) => number;
    readonly wbg_rayon_start_worker: (a: number) => void;
    readonly memory: WebAssembly.Memory;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_thread_destroy: (a?: number, b?: number, c?: number) => void;
    readonly __wbindgen_start: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number }} module - Passing `SyncInitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory, thread_stack_size?: number } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number }} module_or_path - Passing `InitInput` directly is deprecated.
 * @param {WebAssembly.Memory} memory - Deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory, thread_stack_size?: number } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;
