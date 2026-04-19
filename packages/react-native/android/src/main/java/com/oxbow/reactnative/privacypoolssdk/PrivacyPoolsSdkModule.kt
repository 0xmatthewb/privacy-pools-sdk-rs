package com.oxbow.reactnative.privacypoolssdk

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import io.oxbow.privacypoolssdk.FfiArtifactVerification
import io.oxbow.privacypoolssdk.FfiArtifactStatus
import io.oxbow.privacypoolssdk.FfiArtifactBytes
import io.oxbow.privacypoolssdk.FfiAsyncJobHandle
import io.oxbow.privacypoolssdk.FfiAsyncJobStatus
import io.oxbow.privacypoolssdk.FfiCircuitMerkleWitness
import io.oxbow.privacypoolssdk.FfiCodeHashCheck
import io.oxbow.privacypoolssdk.FfiCommitment
import io.oxbow.privacypoolssdk.FfiCommitmentCircuitInput
import io.oxbow.privacypoolssdk.FfiCommitmentCircuitSessionHandle
import io.oxbow.privacypoolssdk.FfiCommitmentWitnessRequest
import io.oxbow.privacypoolssdk.FfiExecutionPolicy
import io.oxbow.privacypoolssdk.FfiExecutionPreflightReport
import io.oxbow.privacypoolssdk.FfiException
import io.oxbow.privacypoolssdk.FfiFinalizedTransactionExecution
import io.oxbow.privacypoolssdk.FfiFinalizedTransactionRequest
import io.oxbow.privacypoolssdk.FfiFormattedGroth16Proof
import io.oxbow.privacypoolssdk.FfiMasterKeys
import io.oxbow.privacypoolssdk.FfiMerkleProof
import io.oxbow.privacypoolssdk.FfiPreparedTransactionExecution
import io.oxbow.privacypoolssdk.FfiPoolEvent
import io.oxbow.privacypoolssdk.FfiProofBundle
import io.oxbow.privacypoolssdk.FfiProvingResult
import io.oxbow.privacypoolssdk.FfiRecoveryCheckpoint
import io.oxbow.privacypoolssdk.FfiRecoveryPolicy
import io.oxbow.privacypoolssdk.FfiResolvedArtifact
import io.oxbow.privacypoolssdk.FfiResolvedArtifactBundle
import io.oxbow.privacypoolssdk.FfiRootCheck
import io.oxbow.privacypoolssdk.FfiRootRead
import io.oxbow.privacypoolssdk.FfiSecrets
import io.oxbow.privacypoolssdk.FfiSignedManifestArtifactBytes
import io.oxbow.privacypoolssdk.FfiSignerHandle
import io.oxbow.privacypoolssdk.FfiSnarkJsProof
import io.oxbow.privacypoolssdk.FfiVerifiedSignedManifest
import io.oxbow.privacypoolssdk.FfiTransactionPlan
import io.oxbow.privacypoolssdk.FfiTransactionReceiptSummary
import io.oxbow.privacypoolssdk.FfiWithdrawalCircuitInput
import io.oxbow.privacypoolssdk.FfiWithdrawal
import io.oxbow.privacypoolssdk.FfiWithdrawalCircuitSessionHandle
import io.oxbow.privacypoolssdk.FfiWithdrawalWitnessRequest
import io.oxbow.privacypoolssdk.FfiSubmittedTransactionExecution
import io.oxbow.privacypoolssdk.PrivacyPoolsSdk as NativeSdk

class PrivacyPoolsSdkModule(
    reactContext: ReactApplicationContext,
) : ReactContextBaseJavaModule(reactContext) {
    override fun getName(): String = "PrivacyPoolsSdk"

    @ReactMethod
    fun getVersion(promise: Promise) {
        promise.resolve(NativeSdk.version())
    }

    @ReactMethod
    fun getStableBackendName(promise: Promise) {
        try {
            promise.resolve(NativeSdk.stableBackendName())
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun deriveMasterKeys(mnemonic: String, promise: Promise) {
        try {
            promise.resolve(masterKeysMap(NativeSdk.masterKeys(mnemonic)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun deriveMasterKeysHandle(mnemonic: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.masterKeysHandle(mnemonic))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun dangerouslyExportMasterKeys(handle: String, promise: Promise) {
        try {
            promise.resolve(masterKeysMap(NativeSdk.exportMasterKeys(handle)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun deriveDepositSecrets(
        masterNullifier: String,
        masterSecret: String,
        scope: String,
        index: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                secretsMap(
                    NativeSdk.depositSecrets(masterNullifier, masterSecret, scope, index)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun generateDepositSecretsHandle(
        masterKeysHandle: String,
        scope: String,
        index: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(NativeSdk.depositSecretsHandle(masterKeysHandle, scope, index))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun deriveWithdrawalSecrets(
        masterNullifier: String,
        masterSecret: String,
        label: String,
        index: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                secretsMap(
                    NativeSdk.withdrawalSecrets(masterNullifier, masterSecret, label, index)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun generateWithdrawalSecretsHandle(
        masterKeysHandle: String,
        label: String,
        index: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(NativeSdk.withdrawalSecretsHandle(masterKeysHandle, label, index))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun dangerouslyExportSecret(handle: String, promise: Promise) {
        try {
            promise.resolve(secretsMap(NativeSdk.exportSecret(handle)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getCommitment(
        value: String,
        label: String,
        nullifier: String,
        secret: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                commitmentMap(
                    NativeSdk.commitment(value, label, nullifier, secret)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getCommitmentFromHandles(
        value: String,
        label: String,
        secretsHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(NativeSdk.commitmentFromHandles(value, label, secretsHandle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun dangerouslyExportCommitmentPreimage(handle: String, promise: Promise) {
        try {
            promise.resolve(commitmentMap(NativeSdk.exportCommitmentPreimage(handle)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun buildWithdrawalWitnessRequestHandle(request: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                NativeSdk.withdrawalWitnessRequestHandle(
                    withdrawalWitnessRequestRecord(request)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun removeSecretHandle(handle: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.removeSecretHandle(handle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun clearSecretHandles(promise: Promise) {
        try {
            promise.resolve(NativeSdk.clearSecretHandles())
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun removeVerifiedProofHandle(handle: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.removeVerifiedProofHandle(handle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun clearVerifiedProofHandles(promise: Promise) {
        try {
            promise.resolve(NativeSdk.clearVerifiedProofHandles())
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun calculateWithdrawalContext(withdrawal: ReadableMap, scope: String, promise: Promise) {
        try {
            promise.resolve(
                NativeSdk.withdrawalContext(withdrawalRecord(withdrawal), scope)
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun generateMerkleProof(leaves: ReadableArray, leaf: String, promise: Promise) {
        try {
            promise.resolve(
                merkleProofMap(
                    NativeSdk.merkleProof(readableStringList(leaves), leaf)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun buildCircuitMerkleWitness(proof: ReadableMap, depth: Double, promise: Promise) {
        try {
            promise.resolve(
                circuitMerkleWitnessMap(
                    NativeSdk.circuitMerkleWitness(
                        merkleProofRecord(proof),
                        depth.toLong(),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun buildWithdrawalCircuitInput(request: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                withdrawalCircuitInputMap(
                    NativeSdk.withdrawalCircuitInput(withdrawalWitnessRequestRecord(request))
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun buildCommitmentCircuitInput(request: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                commitmentCircuitInputMap(
                    NativeSdk.commitmentCircuitInput(commitmentWitnessRequestRecord(request))
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareWithdrawalCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                withdrawalCircuitSessionHandleMap(
                    NativeSdk.prepareWithdrawalCircuitSession(manifestJson, artifactsRoot)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareWithdrawalCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: ReadableArray,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                withdrawalCircuitSessionHandleMap(
                    NativeSdk.prepareWithdrawalCircuitSessionFromBytes(
                        manifestJson,
                        readableMapList(artifacts).map(::artifactBytesRecord),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun removeWithdrawalCircuitSession(handle: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.removeWithdrawalCircuitSession(handle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareCommitmentCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                commitmentCircuitSessionHandleMap(
                    NativeSdk.prepareCommitmentCircuitSession(manifestJson, artifactsRoot)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareCommitmentCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: ReadableArray,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                commitmentCircuitSessionHandleMap(
                    NativeSdk.prepareCommitmentCircuitSessionFromBytes(
                        manifestJson,
                        readableMapList(artifacts).map(::artifactBytesRecord),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun removeCommitmentCircuitSession(handle: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.removeCommitmentCircuitSession(handle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveWithdrawal(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveWithdrawal(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveWithdrawalWithHandles(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveWithdrawalWithHandles(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        requestHandle,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveWithdrawalWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveWithdrawalWithSession(
                        backendProfile,
                        sessionHandle,
                        withdrawalWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveCommitment(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveCommitment(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        commitmentWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveCommitmentWithHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveCommitmentWithHandle(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        requestHandle,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveCommitmentWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                provingResultMap(
                    NativeSdk.proveCommitmentWithSession(
                        backendProfile,
                        sessionHandle,
                        commitmentWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun startProveWithdrawalJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startProveWithdrawalJob(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun startProveWithdrawalJobWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startProveWithdrawalJobWithSession(
                        backendProfile,
                        sessionHandle,
                        withdrawalWitnessRequestRecord(request),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyWithdrawalProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyWithdrawalProof(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyWithdrawalProofWithSession(
        backendProfile: String,
        sessionHandle: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyWithdrawalProofWithSession(
                    backendProfile,
                    sessionHandle,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyCommitmentProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyCommitmentProof(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyCommitmentProofWithSession(
        backendProfile: String,
        sessionHandle: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyCommitmentProofWithSession(
                    backendProfile,
                    sessionHandle,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveAndVerifyCommitmentHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.proveAndVerifyCommitmentHandle(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    requestHandle,
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun proveAndVerifyWithdrawalHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.proveAndVerifyWithdrawalHandle(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    requestHandle,
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyCommitmentProofForRequestHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyCommitmentProofForRequestHandle(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    requestHandle,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyRagequitProofForRequestHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyRagequitProofForRequestHandle(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    requestHandle,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyWithdrawalProofForRequestHandle(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        requestHandle: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                NativeSdk.verifyWithdrawalProofForRequestHandle(
                    backendProfile,
                    manifestJson,
                    artifactsRoot,
                    requestHandle,
                    proofBundleRecord(proof),
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun pollJobStatus(jobId: String, promise: Promise) {
        try {
            promise.resolve(asyncJobStatusMap(NativeSdk.pollJobStatus(jobId)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getProveWithdrawalJobResult(jobId: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.getProveWithdrawalJobResult(jobId)?.let(::provingResultMap))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun cancelJob(jobId: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.cancelJob(jobId))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun removeJob(jobId: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.removeJob(jobId))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareWithdrawalExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        chainId: Double,
        poolAddress: String,
        rpcUrl: String,
        policy: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                preparedExecutionMap(
                    NativeSdk.prepareWithdrawalExecution(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                        chainId.toLong().toULong(),
                        poolAddress,
                        rpcUrl,
                        executionPolicyRecord(policy),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareWithdrawalExecutionPayload(payload: ReadableMap, promise: Promise) {
        runPreparedExecutionPayloadAsync(promise) {
            NativeSdk.prepareWithdrawalExecution(
                payload.requireString("backendProfile"),
                payload.requireString("manifestJson"),
                payload.requireString("artifactsRoot"),
                withdrawalWitnessRequestRecord(payload.requireMap("request")),
                payload.requireDouble("chainId").toLong().toULong(),
                payload.requireString("poolAddress"),
                payload.requireString("rpcUrl"),
                executionPolicyRecord(payload.requireMap("policy")),
            )
        }
    }

    @ReactMethod
    fun startPrepareWithdrawalExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        chainId: Double,
        poolAddress: String,
        rpcUrl: String,
        policy: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startPrepareWithdrawalExecutionJob(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                        chainId.toLong().toULong(),
                        poolAddress,
                        rpcUrl,
                        executionPolicyRecord(policy),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun startPrepareWithdrawalExecutionJobPayload(payload: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startPrepareWithdrawalExecutionJob(
                        payload.requireString("backendProfile"),
                        payload.requireString("manifestJson"),
                        payload.requireString("artifactsRoot"),
                        withdrawalWitnessRequestRecord(payload.requireMap("request")),
                        payload.requireDouble("chainId").toLong().toULong(),
                        payload.requireString("poolAddress"),
                        payload.requireString("rpcUrl"),
                        executionPolicyRecord(payload.requireMap("policy")),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getPrepareWithdrawalExecutionJobResult(jobId: String, promise: Promise) {
        try {
            promise.resolve(
                NativeSdk.getPrepareWithdrawalExecutionJobResult(jobId)?.let(::preparedExecutionMap)
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareRelayExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        chainId: Double,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                preparedExecutionMap(
                    NativeSdk.prepareRelayExecution(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                        chainId.toLong().toULong(),
                        entrypointAddress,
                        poolAddress,
                        rpcUrl,
                        executionPolicyRecord(policy),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun prepareRelayExecutionPayload(payload: ReadableMap, promise: Promise) {
        runPreparedExecutionPayloadAsync(promise) {
            NativeSdk.prepareRelayExecution(
                payload.requireString("backendProfile"),
                payload.requireString("manifestJson"),
                payload.requireString("artifactsRoot"),
                withdrawalWitnessRequestRecord(payload.requireMap("request")),
                payload.requireDouble("chainId").toLong().toULong(),
                payload.requireString("entrypointAddress"),
                payload.requireString("poolAddress"),
                payload.requireString("rpcUrl"),
                executionPolicyRecord(payload.requireMap("policy")),
            )
        }
    }

    @ReactMethod
    fun startPrepareRelayExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: ReadableMap,
        chainId: Double,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startPrepareRelayExecutionJob(
                        backendProfile,
                        manifestJson,
                        artifactsRoot,
                        withdrawalWitnessRequestRecord(request),
                        chainId.toLong().toULong(),
                        entrypointAddress,
                        poolAddress,
                        rpcUrl,
                        executionPolicyRecord(policy),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun startPrepareRelayExecutionJobPayload(payload: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                asyncJobHandleMap(
                    NativeSdk.startPrepareRelayExecutionJob(
                        payload.requireString("backendProfile"),
                        payload.requireString("manifestJson"),
                        payload.requireString("artifactsRoot"),
                        withdrawalWitnessRequestRecord(payload.requireMap("request")),
                        payload.requireDouble("chainId").toLong().toULong(),
                        payload.requireString("entrypointAddress"),
                        payload.requireString("poolAddress"),
                        payload.requireString("rpcUrl"),
                        executionPolicyRecord(payload.requireMap("policy")),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getPrepareRelayExecutionJobResult(jobId: String, promise: Promise) {
        try {
            promise.resolve(
                NativeSdk.getPrepareRelayExecutionJobResult(jobId)?.let(::preparedExecutionMap)
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun registerHostProvidedSigner(handle: String, address: String, promise: Promise) {
        try {
            promise.resolve(
                signerHandleMap(
                    NativeSdk.registerHostProvidedSigner(
                        handle,
                        address,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun registerMobileSecureStorageSigner(handle: String, address: String, promise: Promise) {
        try {
            promise.resolve(
                signerHandleMap(
                    NativeSdk.registerMobileSecureStorageSigner(
                        handle,
                        address,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun unregisterSigner(handle: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.unregisterSigner(handle))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun finalizePreparedTransaction(
        rpcUrl: String,
        prepared: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                finalizedExecutionMap(
                    NativeSdk.finalizePreparedTransaction(
                        rpcUrl,
                        preparedExecutionRecord(prepared),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun finalizePreparedTransactionForSigner(
        rpcUrl: String,
        signerHandle: String,
        prepared: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                finalizedExecutionMap(
                    NativeSdk.finalizePreparedTransactionForSigner(
                        rpcUrl,
                        signerHandle,
                        preparedExecutionRecord(prepared),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun submitPreparedTransaction(
        rpcUrl: String,
        signerHandle: String,
        prepared: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                submittedExecutionMap(
                    NativeSdk.submitPreparedTransaction(
                        rpcUrl,
                        signerHandle,
                        preparedExecutionRecord(prepared),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun submitSignedTransaction(
        rpcUrl: String,
        finalized: ReadableMap,
        signedTransaction: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                submittedExecutionMap(
                    NativeSdk.submitSignedTransaction(
                        rpcUrl,
                        finalizedExecutionRecord(finalized),
                        signedTransaction,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planWithdrawalTransaction(
        chainId: Double,
        poolAddress: String,
        withdrawal: ReadableMap,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.withdrawalTransactionPlan(
                        chainId.toLong().toULong(),
                        poolAddress,
                        withdrawalRecord(withdrawal),
                        proofBundleRecord(proof),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planRelayTransaction(
        chainId: Double,
        entrypointAddress: String,
        withdrawal: ReadableMap,
        proof: ReadableMap,
        scope: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.relayTransactionPlan(
                        chainId.toLong().toULong(),
                        entrypointAddress,
                        withdrawalRecord(withdrawal),
                        proofBundleRecord(proof),
                        scope,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planRagequitTransaction(
        chainId: Double,
        poolAddress: String,
        proof: ReadableMap,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.ragequitTransactionPlan(
                        chainId.toLong().toULong(),
                        poolAddress,
                        proofBundleRecord(proof),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planVerifiedWithdrawalTransactionWithHandle(
        chainId: Double,
        poolAddress: String,
        proofHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.verifiedWithdrawalTransactionPlan(
                        chainId.toLong().toULong(),
                        poolAddress,
                        proofHandle,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planVerifiedRelayTransactionWithHandle(
        chainId: Double,
        entrypointAddress: String,
        proofHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.verifiedRelayTransactionPlan(
                        chainId.toLong().toULong(),
                        entrypointAddress,
                        proofHandle,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planVerifiedRagequitTransactionWithHandle(
        chainId: Double,
        poolAddress: String,
        proofHandle: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                transactionPlanMap(
                    NativeSdk.verifiedRagequitTransactionPlan(
                        chainId.toLong().toULong(),
                        poolAddress,
                        proofHandle,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planPoolStateRootRead(poolAddress: String, promise: Promise) {
        try {
            promise.resolve(rootReadMap(NativeSdk.poolStateRootRead(poolAddress)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun planAspRootRead(entrypointAddress: String, poolAddress: String, promise: Promise) {
        try {
            promise.resolve(rootReadMap(NativeSdk.aspRootRead(entrypointAddress, poolAddress)))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun isCurrentStateRoot(expectedRoot: String, currentRoot: String, promise: Promise) {
        try {
            promise.resolve(NativeSdk.isCurrentStateRoot(expectedRoot, currentRoot))
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun formatGroth16ProofBundle(proof: ReadableMap, promise: Promise) {
        try {
            promise.resolve(
                formattedGroth16ProofMap(
                    NativeSdk.formatGroth16Proof(proofBundleRecord(proof))
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifyArtifactBytes(
        manifestJson: String,
        circuit: String,
        kind: String,
        bytes: ReadableArray,
        promise: Promise,
    ) {
        try {
            val byteArray = ByteArray(bytes.size())
            for (index in 0 until bytes.size()) {
                byteArray[index] = bytes.getInt(index).toByte()
            }

            promise.resolve(
                artifactVerificationMap(
                    NativeSdk.verifyArtifactBytes(
                        manifestJson = manifestJson,
                        circuit = circuit,
                        kind = kind,
                        bytes = byteArray,
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifySignedManifest(
        payloadJson: String,
        signatureHex: String,
        publicKeyHex: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                verifiedSignedManifestMap(
                    NativeSdk.verifySignedManifest(payloadJson, signatureHex, publicKeyHex)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun verifySignedManifestArtifacts(
        payloadJson: String,
        signatureHex: String,
        publicKeyHex: String,
        artifacts: ReadableArray,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                verifiedSignedManifestMap(
                    NativeSdk.verifySignedManifestArtifacts(
                        payloadJson,
                        signatureHex,
                        publicKeyHex,
                        readableMapList(artifacts).map(::signedManifestArtifactBytesRecord),
                    )
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun getArtifactStatuses(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
        promise: Promise,
    ) {
        try {
            val result = Arguments.createArray()
            NativeSdk.artifactStatuses(manifestJson, artifactsRoot, circuit)
                .forEach { status -> result.pushMap(artifactStatusMap(status)) }
            promise.resolve(result)
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun resolveVerifiedArtifactBundle(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
        promise: Promise,
    ) {
        try {
            promise.resolve(
                resolvedArtifactBundleMap(
                    NativeSdk.resolvedArtifactBundle(manifestJson, artifactsRoot, circuit)
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    @ReactMethod
    fun checkpointRecovery(events: ReadableArray, policy: ReadableMap, promise: Promise) {
        try {
            val eventRecords = List(events.size()) { index ->
                poolEventRecord(events.getMap(index) ?: error("missing recovery event at index $index"))
            }

            promise.resolve(
                recoveryCheckpointMap(
                    NativeSdk.recoveryCheckpoint(eventRecords, recoveryPolicyRecord(policy))
                )
            )
        } catch (error: FfiException) {
            promise.reject("ffi_error", error.message, error)
        } catch (error: Exception) {
            promise.reject("ffi_error", error.message, error)
        }
    }

    private fun masterKeysMap(keys: FfiMasterKeys) = Arguments.createMap().apply {
        putString("master_nullifier", keys.masterNullifier)
        putString("master_secret", keys.masterSecret)
    }

    private fun secretsMap(secrets: FfiSecrets) = Arguments.createMap().apply {
        putString("nullifier", secrets.nullifier)
        putString("secret", secrets.secret)
    }

    private fun commitmentMap(commitment: FfiCommitment) = Arguments.createMap().apply {
        putString("hash", commitment.hash)
        putString("nullifier_hash", commitment.nullifierHash)
        putString("precommitment_hash", commitment.precommitmentHash)
        putString("value", commitment.value)
        putString("label", commitment.label)
        putString("nullifier", commitment.nullifier)
        putString("secret", commitment.secret)
    }

    private fun commitmentRecord(commitment: ReadableMap): FfiCommitment =
        FfiCommitment(
            hash = commitment.getString("hash") ?: error("missing hash in commitment"),
            nullifierHash =
                commitment.getString("nullifier_hash")
                    ?: error("missing nullifier_hash in commitment"),
            precommitmentHash =
                commitment.getString("precommitment_hash")
                    ?: error("missing precommitment_hash in commitment"),
            value = commitment.getString("value") ?: error("missing value in commitment"),
            label = commitment.getString("label") ?: error("missing label in commitment"),
            nullifier =
                commitment.getString("nullifier") ?: error("missing nullifier in commitment"),
            secret = commitment.getString("secret") ?: error("missing secret in commitment"),
        )

    private fun ReadableMap.requireString(key: String): String =
        getString(key) ?: error("missing string field $key")

    private fun ReadableMap.requireDouble(key: String): Double =
        if (hasKey(key)) getDouble(key) else error("missing numeric field $key")

    private fun ReadableMap.requireMap(key: String): ReadableMap =
        getMap(key) ?: error("missing map field $key")

    private fun withdrawalRecord(withdrawal: ReadableMap): FfiWithdrawal {
        val processooor =
            withdrawal.getString("processooor") ?: error("missing processooor in withdrawal")
        val data = withdrawal.getArray("data") ?: error("missing data in withdrawal")

        return FfiWithdrawal(
            processooor = processooor,
            data = readableByteArray(data),
        )
    }

    private fun merkleProofMap(proof: FfiMerkleProof) = Arguments.createMap().apply {
        putString("root", proof.root)
        putString("leaf", proof.leaf)
        putDouble("index", proof.index.toDouble())
        putArray("siblings", Arguments.fromList(proof.siblings))
    }

    private fun merkleProofRecord(proof: ReadableMap): FfiMerkleProof {
        val root = proof.getString("root") ?: error("missing root in merkle proof")
        val leaf = proof.getString("leaf") ?: error("missing leaf in merkle proof")
        val index = proof.getDouble("index").toLong()
        val siblingsArray = proof.getArray("siblings") ?: error("missing siblings in merkle proof")

        return FfiMerkleProof(
            root = root,
            leaf = leaf,
            index = index.toULong(),
            siblings = readableStringList(siblingsArray),
        )
    }

    private fun circuitMerkleWitnessMap(witness: FfiCircuitMerkleWitness) =
        Arguments.createMap().apply {
            putString("root", witness.root)
            putString("leaf", witness.leaf)
            putDouble("index", witness.index.toDouble())
            putArray("siblings", Arguments.fromList(witness.siblings))
            putDouble("depth", witness.depth.toDouble())
        }

    private fun circuitMerkleWitnessRecord(witness: ReadableMap): FfiCircuitMerkleWitness {
        val root = witness.getString("root") ?: error("missing root in merkle witness")
        val leaf = witness.getString("leaf") ?: error("missing leaf in merkle witness")
        val index = witness.getDouble("index").toLong()
        val siblingsArray =
            witness.getArray("siblings") ?: error("missing siblings in merkle witness")
        val depth = witness.getDouble("depth").toLong()

        return FfiCircuitMerkleWitness(
            root = root,
            leaf = leaf,
            index = index.toULong(),
            siblings = readableStringList(siblingsArray),
            depth = depth.toULong(),
        )
    }

    private fun withdrawalWitnessRequestRecord(request: ReadableMap): FfiWithdrawalWitnessRequest {
        val commitment =
            request.getMap("commitment") ?: error("missing commitment in withdrawal request")
        val withdrawal =
            request.getMap("withdrawal") ?: error("missing withdrawal in withdrawal request")
        val stateWitness =
            request.getMap("state_witness") ?: error("missing state_witness in withdrawal request")
        val aspWitness =
            request.getMap("asp_witness") ?: error("missing asp_witness in withdrawal request")

        return FfiWithdrawalWitnessRequest(
            commitment = commitmentRecord(commitment),
            withdrawal = withdrawalRecord(withdrawal),
            scope = request.getString("scope") ?: error("missing scope in withdrawal request"),
            withdrawalAmount =
                request.getString("withdrawal_amount")
                    ?: error("missing withdrawal_amount in withdrawal request"),
            stateWitness = circuitMerkleWitnessRecord(stateWitness),
            aspWitness = circuitMerkleWitnessRecord(aspWitness),
            newNullifier =
                request.getString("new_nullifier")
                    ?: error("missing new_nullifier in withdrawal request"),
            newSecret =
                request.getString("new_secret") ?: error("missing new_secret in withdrawal request"),
        )
    }

    private fun commitmentWitnessRequestRecord(request: ReadableMap): FfiCommitmentWitnessRequest {
        val commitment =
            request.getMap("commitment") ?: error("missing commitment in commitment request")

        return FfiCommitmentWitnessRequest(commitment = commitmentRecord(commitment))
    }

    private fun withdrawalCircuitInputMap(input: FfiWithdrawalCircuitInput) =
        Arguments.createMap().apply {
            putString("withdrawn_value", input.withdrawnValue)
            putString("state_root", input.stateRoot)
            putDouble("state_tree_depth", input.stateTreeDepth.toDouble())
            putString("asp_root", input.aspRoot)
            putDouble("asp_tree_depth", input.aspTreeDepth.toDouble())
            putString("context", input.context)
            putString("label", input.label)
            putString("existing_value", input.existingValue)
            putString("existing_nullifier", input.existingNullifier)
            putString("existing_secret", input.existingSecret)
            putString("new_nullifier", input.newNullifier)
            putString("new_secret", input.newSecret)
            putArray("state_siblings", Arguments.fromList(input.stateSiblings))
            putDouble("state_index", input.stateIndex.toDouble())
            putArray("asp_siblings", Arguments.fromList(input.aspSiblings))
            putDouble("asp_index", input.aspIndex.toDouble())
        }

    private fun commitmentCircuitInputMap(input: FfiCommitmentCircuitInput) =
        Arguments.createMap().apply {
            putString("value", input.value)
            putString("label", input.label)
            putString("nullifier", input.nullifier)
            putString("secret", input.secret)
        }

    private fun provingResultMap(result: FfiProvingResult) = Arguments.createMap().apply {
        putString("backend", result.backend)
        putMap("proof", proofBundleMap(result.proof))
    }

    private fun asyncJobHandleMap(handle: FfiAsyncJobHandle) = Arguments.createMap().apply {
        putString("job_id", handle.jobId)
        putString("kind", handle.kind)
    }

    private fun withdrawalCircuitSessionHandleMap(
        handle: FfiWithdrawalCircuitSessionHandle,
    ) = Arguments.createMap().apply {
        putString("handle", handle.handle)
        putString("circuit", handle.circuit)
        putString("artifact_version", handle.artifactVersion)
    }

    private fun commitmentCircuitSessionHandleMap(
        handle: FfiCommitmentCircuitSessionHandle,
    ) = Arguments.createMap().apply {
        putString("handle", handle.handle)
        putString("circuit", handle.circuit)
        putString("artifact_version", handle.artifactVersion)
    }

    private fun asyncJobStatusMap(status: FfiAsyncJobStatus) = Arguments.createMap().apply {
        putString("job_id", status.jobId)
        putString("kind", status.kind)
        putString("state", status.state)
        status.stage?.let { putString("stage", it) }
        status.error?.let { putString("error", it) }
        putBoolean("cancel_requested", status.cancelRequested)
    }

    private fun runPreparedExecutionPayloadAsync(
        promise: Promise,
        block: () -> FfiPreparedTransactionExecution,
    ) {
        Thread {
            try {
                val prepared = block()
                promise.resolve(preparedExecutionMap(prepared))
            } catch (error: FfiException) {
                promise.reject("ffi_error", error.message, error)
            } catch (error: Exception) {
                promise.reject("ffi_error", error.message, error)
            }
        }.start()
    }

    private fun preparedExecutionMap(prepared: FfiPreparedTransactionExecution) =
        Arguments.createMap().apply {
            putMap("proving", provingResultMap(prepared.proving))
            putMap("transaction", transactionPlanMap(prepared.transaction))
            putMap("preflight", executionPreflightMap(prepared.preflight))
        }

    private fun finalizedExecutionMap(finalized: FfiFinalizedTransactionExecution) =
        Arguments.createMap().apply {
            putMap("prepared", preparedExecutionMap(finalized.prepared))
            putMap("request", finalizedRequestMap(finalized.request))
        }

    private fun finalizedRequestMap(request: FfiFinalizedTransactionRequest) =
        Arguments.createMap().apply {
            putString("kind", request.kind)
            putDouble("chain_id", request.chainId.toDouble())
            putString("from", request.from)
            putString("to", request.to)
            putDouble("nonce", request.nonce.toDouble())
            putDouble("gas_limit", request.gasLimit.toDouble())
            putString("value", request.value)
            putString("data", request.data)
            request.gasPrice?.let { putString("gas_price", it) }
            request.maxFeePerGas?.let { putString("max_fee_per_gas", it) }
            request.maxPriorityFeePerGas?.let { putString("max_priority_fee_per_gas", it) }
        }

    private fun submittedExecutionMap(submitted: FfiSubmittedTransactionExecution) =
        Arguments.createMap().apply {
            putMap("prepared", preparedExecutionMap(submitted.prepared))
            putMap("receipt", transactionReceiptMap(submitted.receipt))
        }

    private fun signerHandleMap(handle: FfiSignerHandle) = Arguments.createMap().apply {
        putString("handle", handle.handle)
        putString("address", handle.address)
        putString("kind", handle.kind)
    }

    private fun transactionReceiptMap(receipt: FfiTransactionReceiptSummary) =
        Arguments.createMap().apply {
            putString("transaction_hash", receipt.transactionHash)
            receipt.blockHash?.let { putString("block_hash", it) }
            receipt.blockNumber?.let { putDouble("block_number", it.toDouble()) }
            receipt.transactionIndex?.let { putDouble("transaction_index", it.toDouble()) }
            putBoolean("success", receipt.success)
            putDouble("gas_used", receipt.gasUsed.toDouble())
            putString("effective_gas_price", receipt.effectiveGasPrice)
            putString("from", receipt.from)
            receipt.to?.let { putString("to", it) }
        }

    private fun executionPreflightMap(report: FfiExecutionPreflightReport) =
        Arguments.createMap().apply {
            putString("kind", report.kind)
            putString("caller", report.caller)
            putString("target", report.target)
            putDouble("expected_chain_id", report.expectedChainId.toDouble())
            putDouble("actual_chain_id", report.actualChainId.toDouble())
            putBoolean("chain_id_matches", report.chainIdMatches)
            putBoolean("simulated", report.simulated)
            putDouble("estimated_gas", report.estimatedGas.toDouble())
            report.mode?.let { putString("mode", it) }
            putArray("code_hash_checks", mapArray(report.codeHashChecks, ::codeHashCheckMap))
            putArray("root_checks", mapArray(report.rootChecks, ::rootCheckMap))
        }

    private fun codeHashCheckMap(check: FfiCodeHashCheck) = Arguments.createMap().apply {
        putString("address", check.address)
        check.expectedCodeHash?.let { putString("expected_code_hash", it) }
        putString("actual_code_hash", check.actualCodeHash)
        check.matchesExpected?.let { putBoolean("matches_expected", it) }
    }

    private fun rootCheckMap(check: FfiRootCheck) = Arguments.createMap().apply {
        putString("kind", check.kind)
        putString("contract_address", check.contractAddress)
        putString("pool_address", check.poolAddress)
        putString("expected_root", check.expectedRoot)
        putString("actual_root", check.actualRoot)
        putBoolean("matches", check.matches)
    }

    private fun <T> mapArray(
        values: List<T>,
        transform: (T) -> WritableMap,
    ) = Arguments.createArray().apply {
        values.forEach { value -> pushMap(transform(value)) }
    }

    private fun proofBundleMap(bundle: FfiProofBundle) = Arguments.createMap().apply {
        putMap("proof", snarkJsProofMap(bundle.proof))
        putArray("public_signals", Arguments.fromList(bundle.publicSignals))
    }

    private fun snarkJsProofMap(proof: FfiSnarkJsProof) = Arguments.createMap().apply {
        putArray("pi_a", Arguments.fromList(proof.piA))
        putArray("pi_b", stringMatrixArray(proof.piB))
        putArray("pi_c", Arguments.fromList(proof.piC))
        putString("protocol", proof.protocol)
        putString("curve", proof.curve)
    }

    private fun transactionPlanMap(plan: FfiTransactionPlan) = Arguments.createMap().apply {
        putString("kind", plan.kind)
        putDouble("chain_id", plan.chainId.toDouble())
        putString("target", plan.target)
        putString("calldata", plan.calldata)
        putString("value", plan.value)
        putMap("proof", formattedGroth16ProofMap(plan.proof))
    }

    private fun transactionPlanRecord(plan: ReadableMap): FfiTransactionPlan {
        val proof = plan.getMap("proof") ?: error("missing proof in transaction plan")
        return FfiTransactionPlan(
            kind = plan.getString("kind") ?: error("missing kind in transaction plan"),
            chainId = plan.getDouble("chain_id").toLong().toULong(),
            target = plan.getString("target") ?: error("missing target in transaction plan"),
            calldata = plan.getString("calldata") ?: error("missing calldata in transaction plan"),
            value = plan.getString("value") ?: error("missing value in transaction plan"),
            proof = formattedGroth16ProofRecord(proof),
        )
    }

    private fun formattedGroth16ProofMap(proof: FfiFormattedGroth16Proof) =
        Arguments.createMap().apply {
            putArray("p_a", Arguments.fromList(proof.pA))
            putArray("p_b", stringMatrixArray(proof.pB))
            putArray("p_c", Arguments.fromList(proof.pC))
            putArray("pub_signals", Arguments.fromList(proof.pubSignals))
        }

    private fun formattedGroth16ProofRecord(proof: ReadableMap): FfiFormattedGroth16Proof {
        val pA = proof.getArray("p_a") ?: error("missing p_a in formatted proof")
        val pB = proof.getArray("p_b") ?: error("missing p_b in formatted proof")
        val pC = proof.getArray("p_c") ?: error("missing p_c in formatted proof")
        val pubSignals =
            proof.getArray("pub_signals") ?: error("missing pub_signals in formatted proof")

        return FfiFormattedGroth16Proof(
            pA = readableStringList(pA),
            pB = readableStringMatrix(pB),
            pC = readableStringList(pC),
            pubSignals = readableStringList(pubSignals),
        )
    }

    private fun proofBundleRecord(proof: ReadableMap): FfiProofBundle {
        val snarkProof = proof.getMap("proof") ?: error("missing proof in proof bundle")
        val publicSignals =
            proof.getArray("public_signals") ?: error("missing public_signals in proof bundle")

        return FfiProofBundle(
            proof = snarkJsProofRecord(snarkProof),
            publicSignals = readableStringList(publicSignals),
        )
    }

    private fun snarkJsProofRecord(proof: ReadableMap): FfiSnarkJsProof {
        val piA = proof.getArray("pi_a") ?: error("missing pi_a in proof")
        val piB = proof.getArray("pi_b") ?: error("missing pi_b in proof")
        val piC = proof.getArray("pi_c") ?: error("missing pi_c in proof")
        val protocol = proof.getString("protocol") ?: error("missing protocol in proof")
        val curve = proof.getString("curve") ?: error("missing curve in proof")

        return FfiSnarkJsProof(
            piA = readableStringList(piA),
            piB = readableStringMatrix(piB),
            piC = readableStringList(piC),
            protocol = protocol,
            curve = curve,
        )
    }

    private fun preparedExecutionRecord(prepared: ReadableMap): FfiPreparedTransactionExecution {
        val proving = prepared.getMap("proving") ?: error("missing proving in prepared execution")
        val transaction =
            prepared.getMap("transaction") ?: error("missing transaction in prepared execution")
        val preflight =
            prepared.getMap("preflight") ?: error("missing preflight in prepared execution")

        return FfiPreparedTransactionExecution(
            proving = provingResultRecord(proving),
            transaction = transactionPlanRecord(transaction),
            preflight = executionPreflightRecord(preflight),
        )
    }

    private fun finalizedExecutionRecord(finalized: ReadableMap): FfiFinalizedTransactionExecution {
        val prepared =
            finalized.getMap("prepared") ?: error("missing prepared in finalized execution")
        val request =
            finalized.getMap("request") ?: error("missing request in finalized execution")

        return FfiFinalizedTransactionExecution(
            prepared = preparedExecutionRecord(prepared),
            request = finalizedRequestRecord(request),
        )
    }

    private fun finalizedRequestRecord(request: ReadableMap): FfiFinalizedTransactionRequest =
        FfiFinalizedTransactionRequest(
            kind = request.getString("kind") ?: error("missing kind in finalized request"),
            chainId = request.getDouble("chain_id").toLong().toULong(),
            from = request.getString("from") ?: error("missing from in finalized request"),
            to = request.getString("to") ?: error("missing to in finalized request"),
            nonce = request.getDouble("nonce").toLong().toULong(),
            gasLimit = request.getDouble("gas_limit").toLong().toULong(),
            value = request.getString("value") ?: error("missing value in finalized request"),
            data = request.getString("data") ?: error("missing data in finalized request"),
            gasPrice = request.getString("gas_price"),
            maxFeePerGas = request.getString("max_fee_per_gas"),
            maxPriorityFeePerGas = request.getString("max_priority_fee_per_gas"),
        )

    private fun provingResultRecord(result: ReadableMap): FfiProvingResult {
        val proof = result.getMap("proof") ?: error("missing proof in proving result")
        return FfiProvingResult(
            backend = result.getString("backend") ?: error("missing backend in proving result"),
            proof = proofBundleRecord(proof),
        )
    }

    private fun executionPreflightRecord(report: ReadableMap): FfiExecutionPreflightReport {
        val codeHashChecks =
            report.getArray("code_hash_checks") ?: error("missing code_hash_checks in preflight")
        val rootChecks =
            report.getArray("root_checks") ?: error("missing root_checks in preflight")

        return FfiExecutionPreflightReport(
            kind = report.getString("kind") ?: error("missing kind in preflight"),
            caller = report.getString("caller") ?: error("missing caller in preflight"),
            target = report.getString("target") ?: error("missing target in preflight"),
            expectedChainId = report.getDouble("expected_chain_id").toLong().toULong(),
            actualChainId = report.getDouble("actual_chain_id").toLong().toULong(),
            chainIdMatches = report.getBoolean("chain_id_matches"),
            simulated = report.getBoolean("simulated"),
            estimatedGas = report.getDouble("estimated_gas").toLong().toULong(),
            mode =
                if (report.hasKey("mode") && !report.isNull("mode")) {
                    report.getString("mode")
                } else {
                    null
                },
            codeHashChecks = readableMapList(codeHashChecks).map(::codeHashCheckRecord),
            rootChecks = readableMapList(rootChecks).map(::rootCheckRecord),
        )
    }

    private fun codeHashCheckRecord(check: ReadableMap): FfiCodeHashCheck =
        FfiCodeHashCheck(
            address = check.getString("address") ?: error("missing address in code hash check"),
            expectedCodeHash = check.getString("expected_code_hash"),
            actualCodeHash =
                check.getString("actual_code_hash")
                    ?: error("missing actual_code_hash in code hash check"),
            matchesExpected =
                if (check.hasKey("matches_expected")) check.getBoolean("matches_expected") else null,
        )

    private fun rootCheckRecord(check: ReadableMap): FfiRootCheck =
        FfiRootCheck(
            kind = check.getString("kind") ?: error("missing kind in root check"),
            contractAddress =
                check.getString("contract_address")
                    ?: error("missing contract_address in root check"),
            poolAddress =
                check.getString("pool_address") ?: error("missing pool_address in root check"),
            expectedRoot =
                check.getString("expected_root") ?: error("missing expected_root in root check"),
            actualRoot =
                check.getString("actual_root") ?: error("missing actual_root in root check"),
            matches = check.getBoolean("matches"),
        )

    private fun rootReadMap(read: FfiRootRead) = Arguments.createMap().apply {
        putString("kind", read.kind)
        putString("contract_address", read.contractAddress)
        putString("pool_address", read.poolAddress)
        putString("call_data", read.callData)
    }

    private fun artifactVerificationMap(
        verification: FfiArtifactVerification,
    ) = Arguments.createMap().apply {
        putString("version", verification.version)
        putString("circuit", verification.circuit)
        putString("kind", verification.kind)
        putString("filename", verification.filename)
    }

    private fun verifiedSignedManifestMap(
        manifest: FfiVerifiedSignedManifest,
    ) = Arguments.createMap().apply {
        putString("version", manifest.version)
        putDouble("artifact_count", manifest.artifactCount.toDouble())
        putString("ceremony", manifest.ceremony)
        putString("build", manifest.build)
        putString("repository", manifest.repository)
        putString("commit", manifest.commit)
    }

    private fun artifactStatusMap(status: FfiArtifactStatus) = Arguments.createMap().apply {
        putString("version", status.version)
        putString("circuit", status.circuit)
        putString("kind", status.kind)
        putString("filename", status.filename)
        putString("path", status.path)
        putBoolean("exists", status.exists)
        putBoolean("verified", status.verified)
    }

    private fun resolvedArtifactBundleMap(bundle: FfiResolvedArtifactBundle) =
        Arguments.createMap().apply {
            putString("version", bundle.version)
            putString("circuit", bundle.circuit)
            val artifacts = Arguments.createArray()
            bundle.artifacts.forEach { artifact -> artifacts.pushMap(resolvedArtifactMap(artifact)) }
            putArray("artifacts", artifacts)
        }

    private fun resolvedArtifactMap(artifact: FfiResolvedArtifact) = Arguments.createMap().apply {
        putString("circuit", artifact.circuit)
        putString("kind", artifact.kind)
        putString("filename", artifact.filename)
        putString("path", artifact.path)
    }

    private fun recoveryCheckpointMap(checkpoint: FfiRecoveryCheckpoint) =
        Arguments.createMap().apply {
            putDouble("latest_block", checkpoint.latestBlock.toDouble())
            putDouble("commitments_seen", checkpoint.commitmentsSeen.toDouble())
        }

    private fun executionPolicyRecord(policy: ReadableMap): FfiExecutionPolicy =
        FfiExecutionPolicy(
            expectedChainId = policy.getDouble("expected_chain_id").toLong().toULong(),
            caller = policy.getString("caller") ?: error("missing caller"),
            expectedPoolCodeHash =
                if (policy.hasKey("expected_pool_code_hash") && !policy.isNull("expected_pool_code_hash")) {
                    policy.getString("expected_pool_code_hash")
                } else {
                    null
                },
            expectedEntrypointCodeHash =
                if (policy.hasKey("expected_entrypoint_code_hash") && !policy.isNull("expected_entrypoint_code_hash")) {
                    policy.getString("expected_entrypoint_code_hash")
                } else {
                    null
                },
            mode =
                if (policy.hasKey("mode") && !policy.isNull("mode")) {
                    policy.getString("mode")
                } else {
                    null
                },
        )

    private fun recoveryPolicyRecord(policy: ReadableMap): FfiRecoveryPolicy {
        val compatibilityMode =
            policy.getString("compatibility_mode") ?: error("missing compatibility_mode")
        return FfiRecoveryPolicy(
            compatibilityMode = compatibilityMode,
            failClosed = policy.getBoolean("fail_closed"),
        )
    }

    private fun poolEventRecord(event: ReadableMap): FfiPoolEvent {
        val poolAddress = event.getString("pool_address") ?: error("missing pool_address")
        val commitmentHash = event.getString("commitment_hash") ?: error("missing commitment_hash")

        return FfiPoolEvent(
            blockNumber = event.getDouble("block_number").toLong().toULong(),
            transactionIndex = event.getDouble("transaction_index").toLong().toULong(),
            logIndex = event.getDouble("log_index").toLong().toULong(),
            poolAddress = poolAddress,
            commitmentHash = commitmentHash,
        )
    }

    private fun artifactBytesRecord(artifact: ReadableMap): FfiArtifactBytes {
        val kind = artifact.getString("kind") ?: error("missing artifact kind")
        val bytes = artifact.getArray("bytes") ?: error("missing artifact bytes")

        return FfiArtifactBytes(kind = kind, bytes = readableByteArray(bytes))
    }

    private fun signedManifestArtifactBytesRecord(
        artifact: ReadableMap,
    ): FfiSignedManifestArtifactBytes {
        val filename = artifact.getString("filename") ?: error("missing artifact filename")
        val bytes = artifact.getArray("bytes") ?: error("missing artifact bytes")

        return FfiSignedManifestArtifactBytes(
            filename = filename,
            bytes = readableByteArray(bytes),
        )
    }

    private fun readableStringList(values: ReadableArray): List<String> =
        List(values.size()) { index ->
            values.getString(index) ?: error("expected string at index $index")
        }

    private fun readableStringMatrix(values: ReadableArray): List<List<String>> =
        List(values.size()) { index ->
            readableStringList(values.getArray(index) ?: error("expected string array at index $index"))
        }

    private fun readableMapList(values: ReadableArray): List<ReadableMap> =
        List(values.size()) { index ->
            values.getMap(index) ?: error("expected map at index $index")
        }

    private fun readableByteArray(values: ReadableArray): ByteArray =
        ByteArray(values.size()) { index ->
            values.getInt(index).toByte()
        }

    private fun stringMatrixArray(values: List<List<String>>) = Arguments.createArray().apply {
        values.forEach { row -> pushArray(Arguments.fromList(row)) }
    }
}
