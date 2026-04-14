package io.oxbow.privacypoolssdk

import io.oxbow.privacypoolssdk.buildCircuitMerkleWitness as ffiBuildCircuitMerkleWitness
import io.oxbow.privacypoolssdk.buildWithdrawalCircuitInput as ffiBuildWithdrawalCircuitInput
import io.oxbow.privacypoolssdk.calculateWithdrawalContext as ffiCalculateWithdrawalContext
import io.oxbow.privacypoolssdk.checkpointRecovery as ffiCheckpointRecovery
import io.oxbow.privacypoolssdk.deriveMasterKeys as ffiDeriveMasterKeys
import io.oxbow.privacypoolssdk.deriveDepositSecrets as ffiDeriveDepositSecrets
import io.oxbow.privacypoolssdk.deriveWithdrawalSecrets as ffiDeriveWithdrawalSecrets
import io.oxbow.privacypoolssdk.fastBackendSupportedOnTarget as ffiFastBackendSupportedOnTarget
import io.oxbow.privacypoolssdk.formatGroth16ProofBundle as ffiFormatGroth16ProofBundle
import io.oxbow.privacypoolssdk.generateMerkleProof as ffiGenerateMerkleProof
import io.oxbow.privacypoolssdk.getArtifactStatuses as ffiGetArtifactStatuses
import io.oxbow.privacypoolssdk.getCommitment as ffiGetCommitment
import io.oxbow.privacypoolssdk.getStableBackendName as ffiGetStableBackendName
import io.oxbow.privacypoolssdk.getVersion as ffiGetVersion
import io.oxbow.privacypoolssdk.isCurrentStateRoot as ffiIsCurrentStateRoot
import io.oxbow.privacypoolssdk.planAspRootRead as ffiPlanAspRootRead
import io.oxbow.privacypoolssdk.planPoolStateRootRead as ffiPlanPoolStateRootRead
import io.oxbow.privacypoolssdk.planRelayTransaction as ffiPlanRelayTransaction
import io.oxbow.privacypoolssdk.planWithdrawalTransaction as ffiPlanWithdrawalTransaction
import io.oxbow.privacypoolssdk.prepareRelayExecution as ffiPrepareRelayExecution
import io.oxbow.privacypoolssdk.prepareWithdrawalExecution as ffiPrepareWithdrawalExecution
import io.oxbow.privacypoolssdk.proveWithdrawal as ffiProveWithdrawal
import io.oxbow.privacypoolssdk.resolveVerifiedArtifactBundle as ffiResolveVerifiedArtifactBundle
import io.oxbow.privacypoolssdk.verifyWithdrawalProof as ffiVerifyWithdrawalProof
import io.oxbow.privacypoolssdk.verifyArtifactBytes as ffiVerifyArtifactBytes

object PrivacyPoolsSdk {
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
    fun proveWithdrawal(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: FfiWithdrawalWitnessRequest,
    ): FfiProvingResult =
        ffiProveWithdrawal(backendProfile, manifestJson, artifactsRoot, request)

    @Throws(FfiException::class)
    fun verifyWithdrawalProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: FfiProofBundle,
    ): Boolean =
        ffiVerifyWithdrawalProof(backendProfile, manifestJson, artifactsRoot, proof)

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
}
