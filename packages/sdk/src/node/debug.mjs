import { native } from "../native.mjs";

function unwrapNativeValue(result) {
  if (result instanceof Error) {
    throw result;
  }
  return result;
}

function parseNativeJson(result) {
  const payload = unwrapNativeValue(result);
  try {
    return JSON.parse(payload);
  } catch (error) {
    const message = String(payload);
    if (message.startsWith("Error: ")) {
      throw new Error(message.slice("Error: ".length));
    }
    throw error;
  }
}

export const dangerouslyExportMasterKeys = async (handle) =>
  parseNativeJson(native.dangerouslyExportMasterKeys(handle));

export const dangerouslyExportSecret = async (handle) =>
  parseNativeJson(native.dangerouslyExportSecret(handle));

export const dangerouslyExportCommitmentPreimage = async (handle) =>
  parseNativeJson(native.dangerouslyExportCommitmentPreimage(handle));

export const dangerouslyExportPreflightedTransaction = async (handle) =>
  parseNativeJson(native.dangerouslyExportPreflightedTransaction(handle));

export const dangerouslyExportFinalizedPreflightedTransaction = async (handle) =>
  parseNativeJson(native.dangerouslyExportFinalizedPreflightedTransaction(handle));

export const dangerouslyExportSubmittedPreflightedTransaction = async (handle) =>
  parseNativeJson(native.dangerouslyExportSubmittedPreflightedTransaction(handle));
