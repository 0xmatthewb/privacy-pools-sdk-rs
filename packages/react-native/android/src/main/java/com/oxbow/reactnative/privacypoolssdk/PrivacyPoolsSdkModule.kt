package com.oxbow.reactnative.privacypoolssdk

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import io.oxbow.privacypoolssdk.FfiArtifactVerification
import io.oxbow.privacypoolssdk.FfiCircuitMerkleWitness
import io.oxbow.privacypoolssdk.FfiCommitment
import io.oxbow.privacypoolssdk.FfiException
import io.oxbow.privacypoolssdk.FfiMasterKeys
import io.oxbow.privacypoolssdk.FfiMerkleProof
import io.oxbow.privacypoolssdk.FfiPoolEvent
import io.oxbow.privacypoolssdk.FfiRecoveryCheckpoint
import io.oxbow.privacypoolssdk.FfiRecoveryPolicy
import io.oxbow.privacypoolssdk.FfiRootRead
import io.oxbow.privacypoolssdk.FfiSecrets
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
    fun fastBackendSupportedOnTarget(promise: Promise) {
        promise.resolve(NativeSdk.supportsFastBackendOnTarget())
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

    private fun recoveryCheckpointMap(checkpoint: FfiRecoveryCheckpoint) =
        Arguments.createMap().apply {
            putDouble("latest_block", checkpoint.latestBlock.toDouble())
            putDouble("commitments_seen", checkpoint.commitmentsSeen.toDouble())
        }

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

    private fun readableStringList(values: ReadableArray): List<String> =
        List(values.size()) { index ->
            values.getString(index) ?: error("expected string at index $index")
        }
}
