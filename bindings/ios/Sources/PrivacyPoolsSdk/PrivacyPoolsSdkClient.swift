import Foundation

public enum PrivacyPoolsSdkClient {
    public static func version() -> String {
        getVersion()
    }

    public static func stableBackendName() throws -> String {
        try getStableBackendName()
    }

    public static func supportsFastBackendOnTarget() -> Bool {
        fastBackendSupportedOnTarget()
    }

    public static func masterKeys(forMnemonic mnemonic: String) throws -> FfiMasterKeys {
        try deriveMasterKeys(mnemonic: mnemonic)
    }

    public static func poolStateRootRead(
        poolAddress: String,
    ) throws -> FfiRootRead {
        try planPoolStateRootRead(poolAddress: poolAddress)
    }

    public static func aspRootRead(
        entrypointAddress: String,
        poolAddress: String,
    ) throws -> FfiRootRead {
        try planAspRootRead(
            entrypointAddress: entrypointAddress,
            poolAddress: poolAddress
        )
    }

    public static func verifyArtifactBytes(
        manifestJson: String,
        circuit: String,
        kind: String,
        bytes: Data,
    ) throws -> FfiArtifactVerification {
        try verifyArtifactBytes(
            manifestJson: manifestJson,
            circuit: circuit,
            kind: kind,
            bytes: bytes
        )
    }
}
