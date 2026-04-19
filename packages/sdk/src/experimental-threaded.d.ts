import type { PrivacyPoolsSdkClient, RuntimeCapabilities } from "./index";

export * from "./index";

export type ExperimentalThreadedRuntimeCapabilities = RuntimeCapabilities & {
  experimentalThreadedExport: true;
  threadedProvingAvailable: boolean;
  threadedProvingEnabled: false;
  fallback: "stable-single-threaded";
};

export type ExperimentalThreadedInitialization = {
  threadedProvingEnabled: boolean;
  fallback: "stable-single-threaded" | null;
  reason?: string;
  threadCount?: number;
};

export function getExperimentalThreadedRuntimeCapabilities(): ExperimentalThreadedRuntimeCapabilities;
export function initializeExperimentalThreadedProving(options?: {
  threadCount?: number;
}): Promise<ExperimentalThreadedInitialization>;
export function createExperimentalThreadedBrowserClient(options?: {
  threadCount?: number;
}): Promise<PrivacyPoolsSdkClient>;
