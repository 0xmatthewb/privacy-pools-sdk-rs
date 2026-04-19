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

function requireDangerousMethod(methodName: string) {
  const module = requireNativeModule() as Record<string, unknown>;
  const method = module[methodName];
  if (typeof method !== "function") {
    throw new Error(`${methodName} is unavailable in this React Native build`);
  }
  return method as (...args: unknown[]) => unknown;
}

export const dangerouslyExportMasterKeys = (
  handle: SecretHandle,
): Promise<MasterKeys> => requireDangerousMethod("dangerouslyExportMasterKeys")(handle) as Promise<MasterKeys>;

export const dangerouslyExportSecret = (
  handle: SecretHandle,
): Promise<Secrets> => requireDangerousMethod("dangerouslyExportSecret")(handle) as Promise<Secrets>;

export const dangerouslyExportCommitmentPreimage = (
  handle: SecretHandle,
): Promise<Commitment> => requireDangerousMethod("dangerouslyExportCommitmentPreimage")(handle) as Promise<Commitment>;

export const dangerouslyExportPreflightedTransaction = (
  handle: PreflightedTransactionHandle,
): Promise<PreflightedTransaction> =>
  requireDangerousMethod("dangerouslyExportPreflightedTransaction")(handle) as Promise<PreflightedTransaction>;

export const dangerouslyExportFinalizedPreflightedTransaction = (
  handle: FinalizedPreflightedTransactionHandle,
): Promise<FinalizedPreflightedTransaction> =>
  requireDangerousMethod("dangerouslyExportFinalizedPreflightedTransaction")(handle) as Promise<FinalizedPreflightedTransaction>;

export const dangerouslyExportSubmittedPreflightedTransaction = (
  handle: SubmittedPreflightedTransactionHandle,
): Promise<SubmittedPreflightedTransaction> =>
  requireDangerousMethod("dangerouslyExportSubmittedPreflightedTransaction")(handle) as Promise<SubmittedPreflightedTransaction>;
