export * from "./index.mjs";

import {
  createPrivacyPoolsSdkClient,
  getRuntimeCapabilities,
  initializeExperimentalThreadedBrowserProving,
  supportsExperimentalThreadedBrowserProving,
} from "./index.mjs";

export function getExperimentalThreadedRuntimeCapabilities() {
  return {
    ...getRuntimeCapabilities(),
    experimentalThreadedExport: true,
    threadedProvingAvailable: supportsExperimentalThreadedBrowserProving(),
    threadedProvingEnabled: false,
    fallback: "stable-single-threaded",
  };
}

export async function initializeExperimentalThreadedProving(options = {}) {
  return initializeExperimentalThreadedBrowserProving(options);
}

export async function createExperimentalThreadedBrowserClient(options = {}) {
  await initializeExperimentalThreadedBrowserProving(options);
  return createPrivacyPoolsSdkClient();
}
