import { NativeModules } from "react-native";
import type {
  Commitment,
  FinalizedPreflightedTransaction,
  FinalizedPreflightedTransactionHandle,
  MasterKeys,
  PreflightedTransaction,
  PreflightedTransactionHandle,
  SecretHandle,
  Secrets,
  SubmittedPreflightedTransaction,
  SubmittedPreflightedTransactionHandle,
} from "./index";

function requireNativeModule() {
  const module = NativeModules.PrivacyPoolsSdk;
  if (!module) {
    throw new Error("PrivacyPoolsSdk native module is not linked");
  }
  return module;
}

export const dangerouslyExportMasterKeys = (
  handle: SecretHandle,
): Promise<MasterKeys> => requireNativeModule().dangerouslyExportMasterKeys(handle);

export const dangerouslyExportSecret = (
  handle: SecretHandle,
): Promise<Secrets> => requireNativeModule().dangerouslyExportSecret(handle);

export const dangerouslyExportCommitmentPreimage = (
  handle: SecretHandle,
): Promise<Commitment> => requireNativeModule().dangerouslyExportCommitmentPreimage(handle);

export const dangerouslyExportPreflightedTransaction = (
  handle: PreflightedTransactionHandle,
): Promise<PreflightedTransaction> =>
  requireNativeModule().dangerouslyExportPreflightedTransaction(handle);

export const dangerouslyExportFinalizedPreflightedTransaction = (
  handle: FinalizedPreflightedTransactionHandle,
): Promise<FinalizedPreflightedTransaction> =>
  requireNativeModule().dangerouslyExportFinalizedPreflightedTransaction(handle);

export const dangerouslyExportSubmittedPreflightedTransaction = (
  handle: SubmittedPreflightedTransactionHandle,
): Promise<SubmittedPreflightedTransaction> =>
  requireNativeModule().dangerouslyExportSubmittedPreflightedTransaction(handle);
