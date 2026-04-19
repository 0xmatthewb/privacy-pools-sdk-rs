import type {
  Commitment,
  FinalizedPreflightedTransaction,
  FinalizedPreflightedTransactionHandle,
  MasterKeys,
  PreflightedTransaction,
  PreflightedTransactionHandle,
  SecretHandle,
  SubmittedPreflightedTransaction,
  SubmittedPreflightedTransactionHandle,
} from "./index.d.ts";

export function dangerouslyExportMasterKeys(handle: SecretHandle): Promise<MasterKeys>;
export function dangerouslyExportCommitmentPreimage(handle: SecretHandle): Promise<Commitment>;
export function dangerouslyExportSecret(handle: SecretHandle): Promise<{
  nullifier: string;
  secret: string;
}>;
export function dangerouslyExportPreflightedTransaction(
  handle: PreflightedTransactionHandle,
): Promise<PreflightedTransaction>;
export function dangerouslyExportFinalizedPreflightedTransaction(
  handle: FinalizedPreflightedTransactionHandle,
): Promise<FinalizedPreflightedTransaction>;
export function dangerouslyExportSubmittedPreflightedTransaction(
  handle: SubmittedPreflightedTransactionHandle,
): Promise<SubmittedPreflightedTransaction>;
export function createWorkerDebugClient(worker: unknown): {
  dangerouslyExportMasterKeys(handle: SecretHandle): Promise<MasterKeys>;
  dangerouslyExportCommitmentPreimage(handle: SecretHandle): Promise<Commitment>;
  dangerouslyExportSecret(handle: SecretHandle): Promise<{
    nullifier: string;
    secret: string;
  }>;
  dangerouslyExportPreflightedTransaction(
    handle: PreflightedTransactionHandle,
  ): Promise<PreflightedTransaction>;
  dangerouslyExportFinalizedPreflightedTransaction(
    handle: FinalizedPreflightedTransactionHandle,
  ): Promise<FinalizedPreflightedTransaction>;
  dangerouslyExportSubmittedPreflightedTransaction(
    handle: SubmittedPreflightedTransactionHandle,
  ): Promise<SubmittedPreflightedTransaction>;
};
