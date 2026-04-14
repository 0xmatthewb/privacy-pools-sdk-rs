package com.oxbow.reactnative.privacypoolssdk

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import io.oxbow.privacypoolssdk.FfiArtifactVerification
import io.oxbow.privacypoolssdk.FfiArtifactStatus
import io.oxbow.privacypoolssdk.FfiCircuitMerkleWitness
import io.oxbow.privacypoolssdk.FfiCommitment
import io.oxbow.privacypoolssdk.FfiException
import io.oxbow.privacypoolssdk.FfiFormattedGroth16Proof
import io.oxbow.privacypoolssdk.FfiMasterKeys
import io.oxbow.privacypoolssdk.FfiMerkleProof
import io.oxbow.privacypoolssdk.FfiPoolEvent
import io.oxbow.privacypoolssdk.FfiProofBundle
import io.oxbow.privacypoolssdk.FfiRecoveryCheckpoint
import io.oxbow.privacypoolssdk.FfiRecoveryPolicy
import io.oxbow.privacypoolssdk.FfiResolvedArtifact
import io.oxbow.privacypoolssdk.FfiResolvedArtifactBundle
import io.oxbow.privacypoolssdk.FfiRootRead
import io.oxbow.privacypoolssdk.FfiSecrets
import io.oxbow.privacypoolssdk.FfiSnarkJsProof
import io.oxbow.privacypoolssdk.FfiWithdrawal
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

    private fun formattedGroth16ProofMap(proof: FfiFormattedGroth16Proof) =
        Arguments.createMap().apply {
            putArray("p_a", Arguments.fromList(proof.pA))
            putArray("p_b", stringMatrixArray(proof.pB))
            putArray("p_c", Arguments.fromList(proof.pC))
            putArray("pub_signals", Arguments.fromList(proof.pubSignals))
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

    private fun readableStringMatrix(values: ReadableArray): List<List<String>> =
        List(values.size()) { index ->
            readableStringList(values.getArray(index) ?: error("expected string array at index $index"))
        }

    private fun readableByteArray(values: ReadableArray): ByteArray =
        ByteArray(values.size()) { index ->
            values.getInt(index).toByte()
        }

    private fun stringMatrixArray(values: List<List<String>>) = Arguments.createArray().apply {
        values.forEach { row -> pushArray(Arguments.fromList(row)) }
    }
}
