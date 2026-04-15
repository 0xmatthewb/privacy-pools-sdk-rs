/* tslint:disable */
/* eslint-disable */

export function buildCircuitMerkleWitnessJson(proof_json: string, depth: number): string;

export function buildCommitmentCircuitInputJson(request_json: string): string;

export function buildCommitmentWitnessInputJson(request_json: string): string;

export function buildWithdrawalCircuitInputJson(request_json: string): string;

export function buildWithdrawalWitnessInputJson(request_json: string): string;

export function calculateWithdrawalContextJson(withdrawal_json: string, scope: string): string;

export function checkpointRecoveryJson(events_json: string, policy_json: string): string;

export function deriveDepositSecretsJson(master_keys_json: string, scope: string, index: string): string;

export function deriveMasterKeysJson(mnemonic: string): string;

export function deriveRecoveryKeysetJson(mnemonic: string, policy_json: string): string;

export function deriveWithdrawalSecretsJson(master_keys_json: string, label: string, index: string): string;

export function fastBackendSupportedOnTarget(): boolean;

export function formatGroth16ProofBundleJson(proof_json: string): string;

export function generateMerkleProofJson(leaves_json: string, leaf: string): string;

export function getArtifactStatusesJson(manifest_json: string, artifacts_root: string, circuit: string): string;

export function getBrowserSupportStatusJson(): string;

export function getCommitmentJson(value: string, label: string, nullifier: string, secret: string): string;

export function getStableBackendName(): string;

export function getVersion(): string;

export function isCurrentStateRoot(expected_root: string, current_root: string): boolean;

export function planAspRootReadJson(entrypoint_address: string, pool_address: string): string;

export function planPoolStateRootReadJson(pool_address: string): string;

export function planRagequitTransactionJson(chain_id: bigint, pool_address: string, proof_json: string): string;

export function planRelayTransactionJson(chain_id: bigint, entrypoint_address: string, withdrawal_json: string, proof_json: string, scope: string): string;

export function planWithdrawalTransactionJson(chain_id: bigint, pool_address: string, withdrawal_json: string, proof_json: string): string;

export function prepareCommitmentCircuitSessionFromBytes(manifest_json: string, artifacts: Array<any>): string;

export function prepareWithdrawalCircuitSessionFromBytes(manifest_json: string, artifacts: Array<any>): string;

export function proveCommitmentWithSessionWitnessJson(session_handle: string, witness_json: string): string;

export function proveCommitmentWithWitnessJson(manifest_json: string, artifacts_json: string, witness_json: string): string;

export function proveWithdrawalWithSessionWitnessJson(session_handle: string, witness_json: string): string;

export function proveWithdrawalWithWitnessJson(manifest_json: string, artifacts_json: string, witness_json: string): string;

export function recoverAccountStateJson(mnemonic: string, pools_json: string, policy_json: string): string;

export function recoverAccountStateWithKeysetJson(keyset_json: string, pools_json: string, policy_json: string): string;

export function removeCommitmentCircuitSession(session_handle: string): boolean;

export function removeWithdrawalCircuitSession(session_handle: string): boolean;

export function resolveVerifiedArtifactBundleJson(manifest_json: string, artifacts_root: string, circuit: string): string;

export function verifyArtifactBytes(manifest_json: string, circuit: string, artifacts: Array<any>): string;

export function verifyArtifactBytesJson(manifest_json: string, circuit: string, artifacts_json: string): string;

export function verifyCommitmentProof(manifest_json: string, artifacts: Array<any>, proof_json: string): boolean;

export function verifyCommitmentProofWithSession(session_handle: string, proof_json: string): boolean;

export function verifyWithdrawalProof(manifest_json: string, artifacts: Array<any>, proof_json: string): boolean;

export function verifyWithdrawalProofWithSession(session_handle: string, proof_json: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly buildCircuitMerkleWitnessJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly buildCommitmentCircuitInputJson: (a: number, b: number) => [number, number, number, number];
    readonly buildCommitmentWitnessInputJson: (a: number, b: number) => [number, number, number, number];
    readonly buildWithdrawalCircuitInputJson: (a: number, b: number) => [number, number, number, number];
    readonly buildWithdrawalWitnessInputJson: (a: number, b: number) => [number, number, number, number];
    readonly calculateWithdrawalContextJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly checkpointRecoveryJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deriveDepositSecretsJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly deriveMasterKeysJson: (a: number, b: number) => [number, number, number, number];
    readonly deriveRecoveryKeysetJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deriveWithdrawalSecretsJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly fastBackendSupportedOnTarget: () => number;
    readonly formatGroth16ProofBundleJson: (a: number, b: number) => [number, number, number, number];
    readonly generateMerkleProofJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly getArtifactStatusesJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly getBrowserSupportStatusJson: () => [number, number];
    readonly getCommitmentJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly getStableBackendName: () => [number, number];
    readonly getVersion: () => [number, number];
    readonly isCurrentStateRoot: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly planAspRootReadJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly planPoolStateRootReadJson: (a: number, b: number) => [number, number, number, number];
    readonly planRagequitTransactionJson: (a: bigint, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly planRelayTransactionJson: (a: bigint, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly planWithdrawalTransactionJson: (a: bigint, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly prepareCommitmentCircuitSessionFromBytes: (a: number, b: number, c: any) => [number, number, number, number];
    readonly prepareWithdrawalCircuitSessionFromBytes: (a: number, b: number, c: any) => [number, number, number, number];
    readonly proveCommitmentWithSessionWitnessJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly proveCommitmentWithWitnessJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly proveWithdrawalWithSessionWitnessJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly proveWithdrawalWithWitnessJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly recoverAccountStateJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly recoverAccountStateWithKeysetJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly removeCommitmentCircuitSession: (a: number, b: number) => [number, number, number];
    readonly removeWithdrawalCircuitSession: (a: number, b: number) => [number, number, number];
    readonly resolveVerifiedArtifactBundleJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verifyArtifactBytes: (a: number, b: number, c: number, d: number, e: any) => [number, number, number, number];
    readonly verifyArtifactBytesJson: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verifyCommitmentProof: (a: number, b: number, c: any, d: number, e: number) => [number, number, number];
    readonly verifyCommitmentProofWithSession: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verifyWithdrawalProof: (a: number, b: number, c: any, d: number, e: number) => [number, number, number];
    readonly verifyWithdrawalProofWithSession: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
