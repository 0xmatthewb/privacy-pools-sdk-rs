package io.oxbow.privacypoolssdk

import io.oxbow.privacypoolssdk.buildCircuitMerkleWitness as ffiBuildCircuitMerkleWitness
import io.oxbow.privacypoolssdk.buildWithdrawalCircuitInput as ffiBuildWithdrawalCircuitInput
import io.oxbow.privacypoolssdk.calculateWithdrawalContext as ffiCalculateWithdrawalContext
import io.oxbow.privacypoolssdk.cancelJob as ffiCancelJob
import io.oxbow.privacypoolssdk.checkpointRecovery as ffiCheckpointRecovery
import io.oxbow.privacypoolssdk.deriveMasterKeys as ffiDeriveMasterKeys
import io.oxbow.privacypoolssdk.deriveDepositSecrets as ffiDeriveDepositSecrets
import io.oxbow.privacypoolssdk.deriveWithdrawalSecrets as ffiDeriveWithdrawalSecrets
import io.oxbow.privacypoolssdk.fastBackendSupportedOnTarget as ffiFastBackendSupportedOnTarget
import io.oxbow.privacypoolssdk.finalizePreparedTransaction as ffiFinalizePreparedTransaction
import io.oxbow.privacypoolssdk.finalizePreparedTransactionForSigner as ffiFinalizePreparedTransactionForSigner
import io.oxbow.privacypoolssdk.formatGroth16ProofBundle as ffiFormatGroth16ProofBundle
import io.oxbow.privacypoolssdk.generateMerkleProof as ffiGenerateMerkleProof
import io.oxbow.privacypoolssdk.getArtifactStatuses as ffiGetArtifactStatuses
import io.oxbow.privacypoolssdk.getCommitment as ffiGetCommitment
import io.oxbow.privacypoolssdk.getPrepareRelayExecutionJobResult as ffiGetPrepareRelayExecutionJobResult
import io.oxbow.privacypoolssdk.getPrepareWithdrawalExecutionJobResult as ffiGetPrepareWithdrawalExecutionJobResult
import io.oxbow.privacypoolssdk.getProveWithdrawalJobResult as ffiGetProveWithdrawalJobResult
import io.oxbow.privacypoolssdk.getStableBackendName as ffiGetStableBackendName
import io.oxbow.privacypoolssdk.getVersion as ffiGetVersion
import io.oxbow.privacypoolssdk.isCurrentStateRoot as ffiIsCurrentStateRoot
import io.oxbow.privacypoolssdk.planAspRootRead as ffiPlanAspRootRead
import io.oxbow.privacypoolssdk.planPoolStateRootRead as ffiPlanPoolStateRootRead
import io.oxbow.privacypoolssdk.planRelayTransaction as ffiPlanRelayTransaction
import io.oxbow.privacypoolssdk.planWithdrawalTransaction as ffiPlanWithdrawalTransaction
import io.oxbow.privacypoolssdk.pollJobStatus as ffiPollJobStatus
import io.oxbow.privacypoolssdk.prepareWithdrawalCircuitSession as ffiPrepareWithdrawalCircuitSession
import io.oxbow.privacypoolssdk.prepareWithdrawalCircuitSessionFromBytes as ffiPrepareWithdrawalCircuitSessionFromBytes
import io.oxbow.privacypoolssdk.prepareRelayExecution as ffiPrepareRelayExecution
import io.oxbow.privacypoolssdk.prepareWithdrawalExecution as ffiPrepareWithdrawalExecution
import io.oxbow.privacypoolssdk.proveWithdrawal as ffiProveWithdrawal
import io.oxbow.privacypoolssdk.proveWithdrawalWithSession as ffiProveWithdrawalWithSession
import io.oxbow.privacypoolssdk.registerHostProvidedSigner as ffiRegisterHostProvidedSigner
import io.oxbow.privacypoolssdk.registerLocalMnemonicSigner as ffiRegisterLocalMnemonicSigner
import io.oxbow.privacypoolssdk.registerMobileSecureStorageSigner as ffiRegisterMobileSecureStorageSigner
import io.oxbow.privacypoolssdk.resolveVerifiedArtifactBundle as ffiResolveVerifiedArtifactBundle
import io.oxbow.privacypoolssdk.removeJob as ffiRemoveJob
import io.oxbow.privacypoolssdk.removeWithdrawalCircuitSession as ffiRemoveWithdrawalCircuitSession
import io.oxbow.privacypoolssdk.startPrepareRelayExecutionJob as ffiStartPrepareRelayExecutionJob
import io.oxbow.privacypoolssdk.startPrepareWithdrawalExecutionJob as ffiStartPrepareWithdrawalExecutionJob
import io.oxbow.privacypoolssdk.startProveWithdrawalJob as ffiStartProveWithdrawalJob
import io.oxbow.privacypoolssdk.startProveWithdrawalJobWithSession as ffiStartProveWithdrawalJobWithSession
import io.oxbow.privacypoolssdk.submitPreparedTransaction as ffiSubmitPreparedTransaction
import io.oxbow.privacypoolssdk.submitSignedTransaction as ffiSubmitSignedTransaction
import io.oxbow.privacypoolssdk.unregisterSigner as ffiUnregisterSigner
import io.oxbow.privacypoolssdk.verifyArtifactBytes as ffiVerifyArtifactBytes
import io.oxbow.privacypoolssdk.verifyWithdrawalProof as ffiVerifyWithdrawalProof
import io.oxbow.privacypoolssdk.verifyWithdrawalProofWithSession as ffiVerifyWithdrawalProofWithSession

object PrivacyPoolsSdk {
    private const val DefaultJobPollIntervalMs: Long = 250

    fun version(): String = ffiGetVersion()

    @Throws(FfiException::class)
    fun stableBackendName(): String = ffiGetStableBackendName()

    fun supportsFastBackendOnTarget(): Boolean = ffiFastBackendSupportedOnTarget()

    @Throws(FfiException::class)
    fun masterKeys(mnemonic: String): FfiMasterKeys = ffiDeriveMasterKeys(mnemonic)

    @Throws(FfiException::class)
    fun depositSecrets(
        masterNullifier: String,
        masterSecret: String,
        scope: String,
        index: String,
    ): FfiSecrets = ffiDeriveDepositSecrets(masterNullifier, masterSecret, scope, index)

    @Throws(FfiException::class)
    fun withdrawalSecrets(
        masterNullifier: String,
        masterSecret: String,
        label: String,
        index: String,
    ): FfiSecrets = ffiDeriveWithdrawalSecrets(masterNullifier, masterSecret, label, index)

    @Throws(FfiException::class)
    fun commitment(
        value: String,
        label: String,
        nullifier: String,
        secret: String,
    ): FfiCommitment = ffiGetCommitment(value, label, nullifier, secret)

    @Throws(FfiException::class)
    fun withdrawalContext(
        withdrawal: FfiWithdrawal,
        scope: String,
    ): String = ffiCalculateWithdrawalContext(withdrawal, scope)

    @Throws(FfiException::class)
    fun merkleProof(leaves: List<String>, leaf: String): FfiMerkleProof =
        ffiGenerateMerkleProof(leaves, leaf)

    @Throws(FfiException::class)
    fun circuitMerkleWitness(
        proof: FfiMerkleProof,
        depth: Long,
    ): FfiCircuitMerkleWitness = ffiBuildCircuitMerkleWitness(proof, depth.toULong())

    @Throws(FfiException::class)
    fun withdrawalCircuitInput(
        request: FfiWithdrawalWitnessRequest,
    ): FfiWithdrawalCircuitInput = ffiBuildWithdrawalCircuitInput(request)

    @Throws(FfiException::class)
    fun prepareWithdrawalCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
    ): FfiWithdrawalCircuitSessionHandle =
        ffiPrepareWithdrawalCircuitSession(manifestJson, artifactsRoot)

    @Throws(FfiException::class)
    fun prepareWithdrawalCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: List<FfiArtifactBytes>,
    ): FfiWithdrawalCircuitSessionHandle =
        ffiPrepareWithdrawalCircuitSessionFromBytes(manifestJson, artifacts)

    @Throws(FfiException::class)
    fun removeWithdrawalCircuitSession(handle: String): Boolean =
        ffiRemoveWithdrawalCircuitSession(handle)

    @Throws(FfiException::class)
    fun proveWithdrawal(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
    ): FfiProvingResult =
        ffiProveWithdrawal(backendProfile, manifestJson, artifactsRoot, request)

    @Throws(FfiException::class)
    fun proveWithdrawalWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: FfiWithdrawalWitnessRequest,
    ): FfiProvingResult =
        ffiProveWithdrawalWithSession(backendProfile, sessionHandle, request)

    @Throws(FfiException::class)
    fun startProveWithdrawalJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
    ): FfiAsyncJobHandle =
        ffiStartProveWithdrawalJob(backendProfile, manifestJson, artifactsRoot, request)

    @Throws(FfiException::class)
    fun startProveWithdrawalJobWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: FfiWithdrawalWitnessRequest,
    ): FfiAsyncJobHandle =
        ffiStartProveWithdrawalJobWithSession(backendProfile, sessionHandle, request)

    @Throws(FfiException::class)
    fun verifyWithdrawalProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: FfiProofBundle,
    ): Boolean =
        ffiVerifyWithdrawalProof(backendProfile, manifestJson, artifactsRoot, proof)

    @Throws(FfiException::class)
    fun verifyWithdrawalProofWithSession(
        backendProfile: String,
        sessionHandle: String,
        proof: FfiProofBundle,
    ): Boolean =
        ffiVerifyWithdrawalProofWithSession(backendProfile, sessionHandle, proof)

    @Throws(FfiException::class)
    fun pollJobStatus(jobId: String): FfiAsyncJobStatus = ffiPollJobStatus(jobId)

    @Throws(FfiException::class)
    fun getProveWithdrawalJobResult(jobId: String): FfiProvingResult? =
        ffiGetProveWithdrawalJobResult(jobId)

    @Throws(FfiException::class)
    fun cancelJob(jobId: String): Boolean = ffiCancelJob(jobId)

    @Throws(FfiException::class)
    fun removeJob(jobId: String): Boolean = ffiRemoveJob(jobId)

    @Throws(FfiException::class, IllegalStateException::class, InterruptedException::class)
    fun awaitProveWithdrawalJob(
        handle: FfiAsyncJobHandle,
        pollIntervalMs: Long = DefaultJobPollIntervalMs,
        onProgress: ((FfiAsyncJobStatus) -> Unit)? = null,
    ): FfiProvingResult {
        awaitBackgroundJob(handle, pollIntervalMs, onProgress)
        return getProveWithdrawalJobResult(handle.jobId)
            ?: throw IllegalStateException("completed prove_withdrawal job returned no result")
    }

    @Throws(FfiException::class)
    fun prepareWithdrawalExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: ULong,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ): FfiPreparedTransactionExecution =
        ffiPrepareWithdrawalExecution(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            poolAddress,
            rpcUrl,
            policy,
        )

    @Throws(FfiException::class)
    fun startPrepareWithdrawalExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: ULong,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ): FfiAsyncJobHandle =
        ffiStartPrepareWithdrawalExecutionJob(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            poolAddress,
            rpcUrl,
            policy,
        )

    @Throws(FfiException::class)
    fun getPrepareWithdrawalExecutionJobResult(
        jobId: String,
    ): FfiPreparedTransactionExecution? = ffiGetPrepareWithdrawalExecutionJobResult(jobId)

    @Throws(FfiException::class, IllegalStateException::class, InterruptedException::class)
    fun awaitPrepareWithdrawalExecutionJob(
        handle: FfiAsyncJobHandle,
        pollIntervalMs: Long = DefaultJobPollIntervalMs,
        onProgress: ((FfiAsyncJobStatus) -> Unit)? = null,
    ): FfiPreparedTransactionExecution {
        awaitBackgroundJob(handle, pollIntervalMs, onProgress)
        return getPrepareWithdrawalExecutionJobResult(handle.jobId)
            ?: throw IllegalStateException(
                "completed prepare_withdrawal_execution job returned no result",
            )
    }

    @Throws(FfiException::class)
    fun prepareRelayExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: ULong,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ): FfiPreparedTransactionExecution =
        ffiPrepareRelayExecution(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            entrypointAddress,
            poolAddress,
            rpcUrl,
            policy,
        )

    @Throws(FfiException::class)
    fun startPrepareRelayExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
        chainId: ULong,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: FfiExecutionPolicy,
    ): FfiAsyncJobHandle =
        ffiStartPrepareRelayExecutionJob(
            backendProfile,
            manifestJson,
            artifactsRoot,
            request,
            chainId,
            entrypointAddress,
            poolAddress,
            rpcUrl,
            policy,
        )

    @Throws(FfiException::class)
    fun getPrepareRelayExecutionJobResult(
        jobId: String,
    ): FfiPreparedTransactionExecution? = ffiGetPrepareRelayExecutionJobResult(jobId)

    @Throws(FfiException::class, IllegalStateException::class, InterruptedException::class)
    fun awaitPrepareRelayExecutionJob(
        handle: FfiAsyncJobHandle,
        pollIntervalMs: Long = DefaultJobPollIntervalMs,
        onProgress: ((FfiAsyncJobStatus) -> Unit)? = null,
    ): FfiPreparedTransactionExecution {
        awaitBackgroundJob(handle, pollIntervalMs, onProgress)
        return getPrepareRelayExecutionJobResult(handle.jobId)
            ?: throw IllegalStateException(
                "completed prepare_relay_execution job returned no result",
            )
    }

    @Throws(FfiException::class)
    fun registerLocalMnemonicSigner(
        handle: String,
        mnemonic: String,
        index: UInt,
    ): FfiSignerHandle = ffiRegisterLocalMnemonicSigner(handle, mnemonic, index)

    @Throws(FfiException::class)
    fun registerHostProvidedSigner(
        handle: String,
        address: String,
    ): FfiSignerHandle = ffiRegisterHostProvidedSigner(handle, address)

    @Throws(FfiException::class)
    fun registerMobileSecureStorageSigner(
        handle: String,
        address: String,
    ): FfiSignerHandle = ffiRegisterMobileSecureStorageSigner(handle, address)

    @Throws(FfiException::class)
    fun unregisterSigner(handle: String): Boolean = ffiUnregisterSigner(handle)

    @Throws(FfiException::class)
    fun finalizePreparedTransaction(
        rpcUrl: String,
        prepared: FfiPreparedTransactionExecution,
    ): FfiFinalizedTransactionExecution =
        ffiFinalizePreparedTransaction(rpcUrl, prepared)

    @Throws(FfiException::class)
    fun finalizePreparedTransactionForSigner(
        rpcUrl: String,
        signerHandle: String,
        prepared: FfiPreparedTransactionExecution,
    ): FfiFinalizedTransactionExecution =
        ffiFinalizePreparedTransactionForSigner(rpcUrl, signerHandle, prepared)

    @Throws(FfiException::class)
    fun submitPreparedTransaction(
        rpcUrl: String,
        signerHandle: String,
        prepared: FfiPreparedTransactionExecution,
    ): FfiSubmittedTransactionExecution =
        ffiSubmitPreparedTransaction(rpcUrl, signerHandle, prepared)

    @Throws(FfiException::class)
    fun submitSignedTransaction(
        rpcUrl: String,
        finalized: FfiFinalizedTransactionExecution,
        signedTransaction: String,
    ): FfiSubmittedTransactionExecution =
        ffiSubmitSignedTransaction(rpcUrl, finalized, signedTransaction)

    @Throws(FfiException::class)
    fun withdrawalTransactionPlan(
        chainId: ULong,
        poolAddress: String,
        withdrawal: FfiWithdrawal,
        proof: FfiProofBundle,
    ): FfiTransactionPlan = ffiPlanWithdrawalTransaction(chainId, poolAddress, withdrawal, proof)

    @Throws(FfiException::class)
    fun relayTransactionPlan(
        chainId: ULong,
        entrypointAddress: String,
        withdrawal: FfiWithdrawal,
        proof: FfiProofBundle,
        scope: String,
    ): FfiTransactionPlan =
        ffiPlanRelayTransaction(chainId, entrypointAddress, withdrawal, proof, scope)

    @Throws(FfiException::class)
    fun poolStateRootRead(poolAddress: String): FfiRootRead =
        ffiPlanPoolStateRootRead(poolAddress)

    @Throws(FfiException::class)
    fun aspRootRead(entrypointAddress: String, poolAddress: String): FfiRootRead =
        ffiPlanAspRootRead(entrypointAddress, poolAddress)

    @Throws(FfiException::class)
    fun isCurrentStateRoot(expectedRoot: String, currentRoot: String): Boolean =
        ffiIsCurrentStateRoot(expectedRoot, currentRoot)

    @Throws(FfiException::class)
    fun formatGroth16Proof(
        proof: FfiProofBundle,
    ): FfiFormattedGroth16Proof = ffiFormatGroth16ProofBundle(proof)

    @Throws(FfiException::class)
    fun verifyArtifactBytes(
        manifestJson: String,
        circuit: String,
        kind: String,
        bytes: ByteArray,
    ): FfiArtifactVerification =
        ffiVerifyArtifactBytes(manifestJson, circuit, kind, bytes)

    @Throws(FfiException::class)
    fun artifactStatuses(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
    ): List<FfiArtifactStatus> = ffiGetArtifactStatuses(manifestJson, artifactsRoot, circuit)

    @Throws(FfiException::class)
    fun resolvedArtifactBundle(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
    ): FfiResolvedArtifactBundle =
        ffiResolveVerifiedArtifactBundle(manifestJson, artifactsRoot, circuit)

    @Throws(FfiException::class)
    fun recoveryCheckpoint(
        events: List<FfiPoolEvent>,
        policy: FfiRecoveryPolicy,
    ): FfiRecoveryCheckpoint = ffiCheckpointRecovery(events, policy)

    @Throws(FfiException::class, IllegalStateException::class, InterruptedException::class)
    private fun awaitBackgroundJob(
        handle: FfiAsyncJobHandle,
        pollIntervalMs: Long,
        onProgress: ((FfiAsyncJobStatus) -> Unit)?,
    ): FfiAsyncJobStatus {
        require(pollIntervalMs > 0) { "pollIntervalMs must be positive" }

        while (true) {
            val status = pollJobStatus(handle.jobId)
            onProgress?.invoke(status)

            when (status.state) {
                "completed" -> return status
                "failed" -> throw IllegalStateException(
                    status.error ?: "background job ${handle.jobId} failed",
                )
                "cancelled" -> throw IllegalStateException(
                    "background job ${handle.jobId} was cancelled",
                )
            }

            Thread.sleep(pollIntervalMs)
        }
    }
}
