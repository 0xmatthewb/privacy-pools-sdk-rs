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

    public static func withdrawalContext(
        withdrawal: FfiWithdrawal,
        scope: String,
    ) throws -> String {
        try calculateWithdrawalContext(withdrawal: withdrawal, scope: scope)
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

    public static func withdrawalCircuitInput(
        request: FfiWithdrawalWitnessRequest,
    ) throws -> FfiWithdrawalCircuitInput {
        try buildWithdrawalCircuitInput(request: request)
    }

    public static func withdrawalProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
    ) throws -> FfiProvingResult {
        try proveWithdrawal(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            request: request
        )
    }

    public static func verifyWithdrawal(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: FfiProofBundle,
    ) throws -> Bool {
        try verifyWithdrawalProof(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            proof: proof
        )
    }

    public static func prepareWithdrawalExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: UInt64,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ) throws -> FfiPreparedTransactionExecution {
        try PrivacyPoolsSdk.prepareWithdrawalExecution(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            request: request,
            chainId: chainId,
            poolAddress: poolAddress,
            rpcUrl: rpcUrl,
            policy: policy
        )
    }

    public static func prepareRelayExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: UInt64,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ) throws -> FfiPreparedTransactionExecution {
        try PrivacyPoolsSdk.prepareRelayExecution(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            request: request,
            chainId: chainId,
            entrypointAddress: entrypointAddress,
            poolAddress: poolAddress,
            rpcUrl: rpcUrl,
            policy: policy
        )
    }

    public static func registerLocalMnemonicSigner(
        handle: String,
        mnemonic: String,
        index: UInt32
    ) throws -> FfiSignerHandle {
        try PrivacyPoolsSdk.registerLocalMnemonicSigner(
            handle: handle,
            mnemonic: mnemonic,
            index: index
        )
    }

    public static func unregisterSigner(
        handle: String
    ) throws -> Bool {
        try PrivacyPoolsSdk.unregisterSigner(handle: handle)
    }

    public static func finalizePreparedTransaction(
        rpcUrl: String,
        prepared: FfiPreparedTransactionExecution
    ) throws -> FfiFinalizedTransactionExecution {
        try PrivacyPoolsSdk.finalizePreparedTransaction(
            rpcUrl: rpcUrl,
            prepared: prepared
        )
    }

    public static func submitPreparedTransaction(
        rpcUrl: String,
        signerHandle: String,
        prepared: FfiPreparedTransactionExecution
    ) throws -> FfiSubmittedTransactionExecution {
        try PrivacyPoolsSdk.submitPreparedTransaction(
            rpcUrl: rpcUrl,
            signerHandle: signerHandle,
            prepared: prepared
        )
    }

    public static func submitSignedTransaction(
        rpcUrl: String,
        finalized: FfiFinalizedTransactionExecution,
        signedTransaction: String
    ) throws -> FfiSubmittedTransactionExecution {
        try PrivacyPoolsSdk.submitSignedTransaction(
            rpcUrl: rpcUrl,
            finalized: finalized,
            signedTransaction: signedTransaction
        )
    }

    public static func withdrawalTransactionPlan(
        chainId: UInt64,
        poolAddress: String,
        withdrawal: FfiWithdrawal,
        proof: FfiProofBundle,
    ) throws -> FfiTransactionPlan {
        try planWithdrawalTransaction(
            chainId: chainId,
            poolAddress: poolAddress,
            withdrawal: withdrawal,
            proof: proof
        )
    }

    public static func relayTransactionPlan(
        chainId: UInt64,
        entrypointAddress: String,
        withdrawal: FfiWithdrawal,
        proof: FfiProofBundle,
        scope: String,
    ) throws -> FfiTransactionPlan {
        try planRelayTransaction(
            chainId: chainId,
            entrypointAddress: entrypointAddress,
            withdrawal: withdrawal,
            proof: proof,
            scope: scope
        )
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

    public static func isCurrentStateRoot(
        expectedRoot: String,
        currentRoot: String,
    ) throws -> Bool {
        try PrivacyPoolsSdk.isCurrentStateRoot(
            expectedRoot: expectedRoot,
            currentRoot: currentRoot
        )
    }

    public static func formatGroth16Proof(
        proof: FfiProofBundle,
    ) throws -> FfiFormattedGroth16Proof {
        try formatGroth16ProofBundle(proof: proof)
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

    public static func resolvedArtifactBundle(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
    ) throws -> FfiResolvedArtifactBundle {
        try resolveVerifiedArtifactBundle(
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
