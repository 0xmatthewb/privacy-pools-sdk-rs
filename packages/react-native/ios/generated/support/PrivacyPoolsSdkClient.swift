import Foundation

public enum PrivacyPoolsSdkClient {
    public static let defaultJobPollIntervalNanoseconds: UInt64 = 250_000_000

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

    public static func commitmentCircuitInput(
        request: FfiCommitmentWitnessRequest,
    ) throws -> FfiCommitmentCircuitInput {
        try buildCommitmentCircuitInput(request: request)
    }

    public static func prepareWithdrawalCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
    ) throws -> FfiWithdrawalCircuitSessionHandle {
        try PrivacyPoolsSdk.prepareWithdrawalCircuitSession(
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot
        )
    }

    public static func prepareWithdrawalCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: [FfiArtifactBytes],
    ) throws -> FfiWithdrawalCircuitSessionHandle {
        try PrivacyPoolsSdk.prepareWithdrawalCircuitSessionFromBytes(
            manifestJson: manifestJson,
            artifacts: artifacts
        )
    }

    public static func removeWithdrawalCircuitSession(handle: String) throws -> Bool {
        try PrivacyPoolsSdk.removeWithdrawalCircuitSession(handle: handle)
    }

    public static func prepareCommitmentCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
    ) throws -> FfiCommitmentCircuitSessionHandle {
        try PrivacyPoolsSdk.prepareCommitmentCircuitSession(
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot
        )
    }

    public static func prepareCommitmentCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: [FfiArtifactBytes],
    ) throws -> FfiCommitmentCircuitSessionHandle {
        try PrivacyPoolsSdk.prepareCommitmentCircuitSessionFromBytes(
            manifestJson: manifestJson,
            artifacts: artifacts
        )
    }

    public static func removeCommitmentCircuitSession(handle: String) throws -> Bool {
        try PrivacyPoolsSdk.removeCommitmentCircuitSession(handle: handle)
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

    public static func withdrawalProof(
        backendProfile: String,
        sessionHandle: String,
        request: FfiWithdrawalWitnessRequest,
    ) throws -> FfiProvingResult {
        try proveWithdrawalWithSession(
            backendProfile: backendProfile,
            sessionHandle: sessionHandle,
            request: request
        )
    }

    public static func commitmentProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiCommitmentWitnessRequest,
    ) throws -> FfiProvingResult {
        try proveCommitment(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            request: request
        )
    }

    public static func commitmentProof(
        backendProfile: String,
        sessionHandle: String,
        request: FfiCommitmentWitnessRequest,
    ) throws -> FfiProvingResult {
        try proveCommitmentWithSession(
            backendProfile: backendProfile,
            sessionHandle: sessionHandle,
            request: request
        )
    }

    public static func startWithdrawalProofJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
    ) throws -> FfiAsyncJobHandle {
        try startProveWithdrawalJob(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            request: request
        )
    }

    public static func startWithdrawalProofJob(
        backendProfile: String,
        sessionHandle: String,
        request: FfiWithdrawalWitnessRequest,
    ) throws -> FfiAsyncJobHandle {
        try startProveWithdrawalJobWithSession(
            backendProfile: backendProfile,
            sessionHandle: sessionHandle,
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

    public static func verifyWithdrawal(
        backendProfile: String,
        sessionHandle: String,
        proof: FfiProofBundle,
    ) throws -> Bool {
        try verifyWithdrawalProofWithSession(
            backendProfile: backendProfile,
            sessionHandle: sessionHandle,
            proof: proof
        )
    }

    public static func verifyCommitment(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: FfiProofBundle,
    ) throws -> Bool {
        try verifyCommitmentProof(
            backendProfile: backendProfile,
            manifestJson: manifestJson,
            artifactsRoot: artifactsRoot,
            proof: proof
        )
    }

    public static func verifyCommitment(
        backendProfile: String,
        sessionHandle: String,
        proof: FfiProofBundle,
    ) throws -> Bool {
        try verifyCommitmentProofWithSession(
            backendProfile: backendProfile,
            sessionHandle: sessionHandle,
            proof: proof
        )
    }

    public static func jobStatus(jobId: String) throws -> FfiAsyncJobStatus {
        try pollJobStatus(jobId: jobId)
    }

    public static func withdrawalProofJobResult(jobId: String) throws -> FfiProvingResult? {
        try getProveWithdrawalJobResult(jobId: jobId)
    }

    public static func cancelBackgroundJob(jobId: String) throws -> Bool {
        try cancelJob(jobId: jobId)
    }

    public static func removeBackgroundJob(jobId: String) throws -> Bool {
        try removeJob(jobId: jobId)
    }

    public static func awaitWithdrawalProofJob(
        handle: FfiAsyncJobHandle,
        pollIntervalNanoseconds: UInt64 = defaultJobPollIntervalNanoseconds,
        onProgress: ((FfiAsyncJobStatus) -> Void)? = nil
    ) async throws -> FfiProvingResult {
        try await awaitBackgroundJob(
            handle: handle,
            pollIntervalNanoseconds: pollIntervalNanoseconds,
            onProgress: onProgress
        )
        guard let result = try withdrawalProofJobResult(jobId: handle.jobId) else {
            throw NSError(
                domain: "PrivacyPoolsSdkClient",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "completed prove_withdrawal job returned no result"]
            )
        }
        return result
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

    public static func startWithdrawalExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: UInt64,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ) throws -> FfiAsyncJobHandle {
        try PrivacyPoolsSdk.startPrepareWithdrawalExecutionJob(
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

    public static func withdrawalExecutionJobResult(
        jobId: String
    ) throws -> FfiPreparedTransactionExecution? {
        try PrivacyPoolsSdk.getPrepareWithdrawalExecutionJobResult(jobId: jobId)
    }

    public static func awaitWithdrawalExecutionJob(
        handle: FfiAsyncJobHandle,
        pollIntervalNanoseconds: UInt64 = defaultJobPollIntervalNanoseconds,
        onProgress: ((FfiAsyncJobStatus) -> Void)? = nil
    ) async throws -> FfiPreparedTransactionExecution {
        try await awaitBackgroundJob(
            handle: handle,
            pollIntervalNanoseconds: pollIntervalNanoseconds,
            onProgress: onProgress
        )
        guard let result = try withdrawalExecutionJobResult(jobId: handle.jobId) else {
            throw NSError(
                domain: "PrivacyPoolsSdkClient",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "completed prepare_withdrawal_execution job returned no result"]
            )
        }
        return result
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

    public static func startRelayExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: UInt64,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ) throws -> FfiAsyncJobHandle {
        try PrivacyPoolsSdk.startPrepareRelayExecutionJob(
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

    public static func relayExecutionJobResult(
        jobId: String
    ) throws -> FfiPreparedTransactionExecution? {
        try PrivacyPoolsSdk.getPrepareRelayExecutionJobResult(jobId: jobId)
    }

    public static func awaitRelayExecutionJob(
        handle: FfiAsyncJobHandle,
        pollIntervalNanoseconds: UInt64 = defaultJobPollIntervalNanoseconds,
        onProgress: ((FfiAsyncJobStatus) -> Void)? = nil
    ) async throws -> FfiPreparedTransactionExecution {
        try await awaitBackgroundJob(
            handle: handle,
            pollIntervalNanoseconds: pollIntervalNanoseconds,
            onProgress: onProgress
        )
        guard let result = try relayExecutionJobResult(jobId: handle.jobId) else {
            throw NSError(
                domain: "PrivacyPoolsSdkClient",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "completed prepare_relay_execution job returned no result"]
            )
        }
        return result
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

    public static func registerHostProvidedSigner(
        handle: String,
        address: String
    ) throws -> FfiSignerHandle {
        try PrivacyPoolsSdk.registerHostProvidedSigner(
            handle: handle,
            address: address
        )
    }

    public static func registerMobileSecureStorageSigner(
        handle: String,
        address: String
    ) throws -> FfiSignerHandle {
        try PrivacyPoolsSdk.registerMobileSecureStorageSigner(
            handle: handle,
            address: address
        )
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

    public static func finalizePreparedTransactionForSigner(
        rpcUrl: String,
        signerHandle: String,
        prepared: FfiPreparedTransactionExecution
    ) throws -> FfiFinalizedTransactionExecution {
        try PrivacyPoolsSdk.finalizePreparedTransactionForSigner(
            rpcUrl: rpcUrl,
            signerHandle: signerHandle,
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

    public static func ragequitTransactionPlan(
        chainId: UInt64,
        poolAddress: String,
        proof: FfiProofBundle,
    ) throws -> FfiTransactionPlan {
        try planRagequitTransaction(
            chainId: chainId,
            poolAddress: poolAddress,
            proof: proof
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

    private static func awaitBackgroundJob(
        handle: FfiAsyncJobHandle,
        pollIntervalNanoseconds: UInt64,
        onProgress: ((FfiAsyncJobStatus) -> Void)?
    ) async throws -> FfiAsyncJobStatus {
        precondition(pollIntervalNanoseconds > 0, "pollIntervalNanoseconds must be positive")

        while true {
            let status = try jobStatus(jobId: handle.jobId)
            onProgress?(status)

            switch status.state {
            case "completed":
                return status
            case "failed":
                throw NSError(
                    domain: "PrivacyPoolsSdkClient",
                    code: 10,
                    userInfo: [NSLocalizedDescriptionKey: status.error ?? "background job \(handle.jobId) failed"]
                )
            case "cancelled":
                throw NSError(
                    domain: "PrivacyPoolsSdkClient",
                    code: 11,
                    userInfo: [NSLocalizedDescriptionKey: "background job \(handle.jobId) was cancelled"]
                )
            default:
                try await Task.sleep(nanoseconds: pollIntervalNanoseconds)
            }
        }
    }
}
