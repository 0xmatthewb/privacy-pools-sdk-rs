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

    public static func depositSecrets(
        masterNullifier: String,
        masterSecret: String,
        scope: String,
        index: String,
    ) throws -> FfiSecrets {
        try deriveDepositSecrets(
            masterNullifier: masterNullifier,
            masterSecret: masterSecret,
            scope: scope,
            index: index
        )
    }

    public static func withdrawalSecrets(
        masterNullifier: String,
        masterSecret: String,
        label: String,
        index: String,
    ) throws -> FfiSecrets {
        try deriveWithdrawalSecrets(
            masterNullifier: masterNullifier,
            masterSecret: masterSecret,
            label: label,
            index: index
        )
    }

    public static func commitment(
        value: String,
        label: String,
        nullifier: String,
        secret: String,
    ) throws -> FfiCommitment {
        try getCommitment(
            value: value,
            label: label,
            nullifier: nullifier,
            secret: secret
        )
    }

    public static func merkleProof(
        leaves: [String],
        leaf: String,
    ) throws -> FfiMerkleProof {
        try generateMerkleProof(leaves: leaves, leaf: leaf)
    }

    public static func circuitMerkleWitness(
        proof: FfiMerkleProof,
        depth: UInt64,
    ) throws -> FfiCircuitMerkleWitness {
        try buildCircuitMerkleWitness(proof: proof, depth: depth)
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

    public static func verifyArtifactDescriptorBytes(
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

    public static func artifactStatuses(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
    ) throws -> [FfiArtifactStatus] {
        try getArtifactStatuses(
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            circuit: circuit
        )
    }

    public static func recoveryCheckpoint(
        events: [FfiPoolEvent],
        policy: FfiRecoveryPolicy,
    ) throws -> FfiRecoveryCheckpoint {
        try checkpointRecovery(events: events, policy: policy)
    }
}
