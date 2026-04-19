import { native } from "../native.mjs";

function unwrapNativeValue(result) {
  if (result && typeof result.then === "function") {
    return result.then(unwrapNativeValue);
  }
  if (result instanceof Error) {
    throw result;
  }
  return result;
}

function parseNativeJson(result) {
  if (result && typeof result.then === "function") {
    return result.then(parseNativeJson);
  }
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

function requireDangerousNative(methodName) {
  const method = native[methodName];
  if (typeof method !== "function") {
    throw new Error(`${methodName} is unavailable in this Node build`);
  }
  return method;
}

export const dangerouslyExportMasterKeys = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportMasterKeys")(handle));

export const dangerouslyExportSecret = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportSecret")(handle));

export const dangerouslyExportCommitmentPreimage = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportCommitmentPreimage")(handle));

export const dangerouslyExportPreflightedTransaction = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportPreflightedTransaction")(handle));

export const dangerouslyExportFinalizedPreflightedTransaction = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportFinalizedPreflightedTransaction")(handle));

export const dangerouslyExportSubmittedPreflightedTransaction = async (handle) =>
  parseNativeJson(requireDangerousNative("dangerouslyExportSubmittedPreflightedTransaction")(handle));
