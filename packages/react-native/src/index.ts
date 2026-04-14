import { NativeModules, Platform } from "react-native";

type RootRead = {
  kind: string;
  contract_address: string;
  pool_address: string;
  call_data: string;
};

type MasterKeys = {
  master_nullifier: string;
  master_secret: string;
};

type ArtifactVerification = {
  version: string;
  circuit: string;
  kind: string;
  filename: string;
};

export type NativePrivacyPoolsSdkModule = {
  getVersion(): Promise<string>;
  getStableBackendName(): Promise<string>;
  fastBackendSupportedOnTarget(): Promise<boolean>;
  deriveMasterKeys(mnemonic: string): Promise<MasterKeys>;
  planPoolStateRootRead(poolAddress: string): Promise<RootRead>;
  planAspRootRead(entrypointAddress: string, poolAddress: string): Promise<RootRead>;
  verifyArtifactBytes(
    manifestJson: string,
    circuit: string,
    kind: string,
    bytes: number[],
  ): Promise<ArtifactVerification>;
};

const LINKING_ERROR =
  `The native module 'PrivacyPoolsSdk' is not linked. Make sure the iOS/Android bindings are built, ` +
  Platform.select({
    ios: "run 'pod install' and rebuild the app.",
    default: "rebuild the app after installing the package.",
  });

const nativeModule = NativeModules.PrivacyPoolsSdk as
  | NativePrivacyPoolsSdkModule
  | undefined;

function requireNativeModule(): NativePrivacyPoolsSdkModule {
  if (!nativeModule) {
    throw new Error(LINKING_ERROR);
  }

  return nativeModule;
}

export const getVersion = (): Promise<string> => requireNativeModule().getVersion();

export const getStableBackendName = (): Promise<string> =>
  requireNativeModule().getStableBackendName();

export const fastBackendSupportedOnTarget = (): Promise<boolean> =>
  requireNativeModule().fastBackendSupportedOnTarget();

export const deriveMasterKeys = (mnemonic: string): Promise<MasterKeys> =>
  requireNativeModule().deriveMasterKeys(mnemonic);

export const planPoolStateRootRead = (poolAddress: string): Promise<RootRead> =>
  requireNativeModule().planPoolStateRootRead(poolAddress);

export const planAspRootRead = (
  entrypointAddress: string,
  poolAddress: string,
): Promise<RootRead> =>
  requireNativeModule().planAspRootRead(entrypointAddress, poolAddress);

export const verifyArtifactBytes = (
  manifestJson: string,
  circuit: string,
  kind: string,
  bytes: number[],
): Promise<ArtifactVerification> =>
  requireNativeModule().verifyArtifactBytes(manifestJson, circuit, kind, bytes);
