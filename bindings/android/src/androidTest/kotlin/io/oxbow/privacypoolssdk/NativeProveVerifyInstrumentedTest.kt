package io.oxbow.privacypoolssdk

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.math.BigDecimal
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeProveVerifyInstrumentedTest {
    companion object {
        private const val REPORT_TAG = "PrivacyPoolsNativeSmoke"
        private const val REPORT_MARKER = "PRIVACY_POOLS_ANDROID_NATIVE_REPORT"
        private const val SMOKE_READ_CONSISTENCY = "finalized"
        private const val SMOKE_MAX_FEE_QUOTE_WEI = "2000000000"
    }

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun emitsStructuredMobileEvidence() {
        val smoke = defaultSmoke()
        var parity = defaultParity()

        try {
            runSmokeFlow(smoke)
            parity = runParityChecks()
            if (parity.getInt("failed") != 0) {
                throw AssertionError("android native parity checks failed")
            }
        } catch (error: Throwable) {
            parity = if (parity.optInt("totalChecks", 0) == 0) {
                failureParity("android native smoke failed: ${error.message ?: error}")
            } else {
                appendParityFailure(parity, "android native smoke failed: ${error.message ?: error}")
            }
            writeReport(smoke, parity)
            throw error
        }

        writeReport(smoke, parity)
    }

    private fun runSmokeFlow(smoke: JSONObject) {
        val fixturesRoot = copyFixtureAssets()
        val artifactsRoot = File(fixturesRoot, "artifacts").absolutePath
        val crypto = readJson("vectors/crypto-compatibility.json")
        val withdrawalFixture = readJson("vectors/withdrawal-circuit-input.json")
        val withdrawalManifest = readText("artifacts/withdrawal-proving-manifest.json")
        val commitmentManifest = readText("artifacts/commitment-proving-manifest.json")
        val signedManifestPayload = readText("artifacts/signed-manifest/payload.json")
        val signedManifestSignature = readText("artifacts/signed-manifest/signature").trim()
        val signedManifestPublicKey = readText("artifacts/signed-manifest/public-key.hex").trim()
        val executionFixture = readJson("vectors/mobile-execution-fixture.json")
        val depositSecrets = crypto.getJSONObject("depositSecrets")

        smoke.put("backend", PrivacyPoolsSdk.stableBackendName())

        val commitment = PrivacyPoolsSdk.commitment(
            withdrawalFixture.getString("existingValue"),
            withdrawalFixture.getString("label"),
            depositSecrets.getString("nullifier"),
            depositSecrets.getString("secret"),
        )

        val commitmentSession = PrivacyPoolsSdk.prepareCommitmentCircuitSession(
            commitmentManifest,
            artifactsRoot,
        )
        val commitmentProof = PrivacyPoolsSdk.proveCommitmentWithSession(
            "stable",
            commitmentSession.handle,
            FfiCommitmentWitnessRequest(commitment),
        )
        smoke.put(
            "commitmentVerified",
            PrivacyPoolsSdk.verifyCommitmentProofWithSession(
                "stable",
                commitmentSession.handle,
                commitmentProof.proof,
            ),
        )
        val tamperedCommitmentProof = commitmentProof.proof.copy(
            publicSignals = commitmentProof.proof.publicSignals.toMutableList().also {
                it[0] = "9"
            },
        )
        smoke.put(
            "tamperedProofRejected",
            rejectsOrFalse {
                PrivacyPoolsSdk.verifyCommitmentProofWithSession(
                    "stable",
                    commitmentSession.handle,
                    tamperedCommitmentProof,
                )
            },
        )
        PrivacyPoolsSdk.removeCommitmentCircuitSession(commitmentSession.handle)
        smoke.put(
            "staleCommitmentSessionRejected",
            failsClosed {
                PrivacyPoolsSdk.verifyCommitmentProofWithSession(
                    "stable",
                    commitmentSession.handle,
                    commitmentProof.proof,
                )
            },
        )

        val withdrawalRequest = withdrawalRequest(
            commitment,
            crypto,
            withdrawalFixture,
            executionFixture.getString("entrypointAddress"),
        )
        val withdrawalSession = PrivacyPoolsSdk.prepareWithdrawalCircuitSession(
            withdrawalManifest,
            artifactsRoot,
        )
        val withdrawalProof = PrivacyPoolsSdk.proveWithdrawalWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalRequest,
        )
        smoke.put(
            "withdrawalVerified",
            PrivacyPoolsSdk.verifyWithdrawalProofWithSession(
                "stable",
                withdrawalSession.handle,
                withdrawalProof.proof,
            ),
        )
        PrivacyPoolsSdk.removeWithdrawalCircuitSession(withdrawalSession.handle)
        smoke.put(
            "staleWithdrawalSessionRejected",
            failsClosed {
                PrivacyPoolsSdk.verifyWithdrawalProofWithSession(
                    "stable",
                    withdrawalSession.handle,
                    withdrawalProof.proof,
                )
            },
        )

        smoke.put(
            "signedManifestVerified",
            PrivacyPoolsSdk.verifySignedManifest(
                signedManifestPayload,
                signedManifestSignature,
                signedManifestPublicKey,
            ).version.isNotEmpty(),
        )
        smoke.put(
            "wrongSignedManifestPublicKeyRejected",
            failsClosed {
                PrivacyPoolsSdk.verifySignedManifest(
                    signedManifestPayload,
                    signedManifestSignature,
                    mutateHex(signedManifestPublicKey),
                )
            },
        )
        smoke.put(
            "tamperedSignedManifestArtifactsRejected",
            failsClosed {
                PrivacyPoolsSdk.verifySignedManifestArtifacts(
                    signedManifestPayload,
                    signedManifestSignature,
                    signedManifestPublicKey,
                    listOf(
                        FfiSignedManifestArtifactBytes(
                            "withdraw-fixture.wasm",
                            byteArrayOf(1, 2, 3),
                        ),
                    ),
                )
            },
        )

        val masterKeysHandle = PrivacyPoolsSdk.masterKeysHandle(
            crypto.getString("mnemonic").toByteArray(Charsets.UTF_8),
        )
        val depositSecretsHandle = PrivacyPoolsSdk.depositSecretsHandle(
            masterKeysHandle,
            crypto.getString("scope"),
            "0",
        )
        val commitmentHandle = PrivacyPoolsSdk.commitmentFromHandles(
            withdrawalFixture.getString("existingValue"),
            withdrawalFixture.getString("label"),
            depositSecretsHandle,
        )
        val verifiedCommitmentHandle = PrivacyPoolsSdk.proveAndVerifyCommitmentHandle(
            "stable",
            commitmentManifest,
            artifactsRoot,
            commitmentHandle,
        )
        smoke.put(
            "handleKindMismatchRejected",
            failsClosed {
                PrivacyPoolsSdk.verifiedWithdrawalTransactionPlan(
                    executionFixture.getLong("expectedChainId").toULong(),
                    executionFixture.getString("poolAddress"),
                    verifiedCommitmentHandle,
                )
            },
        )
        PrivacyPoolsSdk.removeVerifiedProofHandle(verifiedCommitmentHandle)
        smoke.put(
            "staleVerifiedProofHandleRejected",
            failsClosed {
                PrivacyPoolsSdk.verifiedRagequitTransactionPlan(
                    executionFixture.getLong("expectedChainId").toULong(),
                    executionFixture.getString("poolAddress"),
                    verifiedCommitmentHandle,
                )
            },
        )

        val prepared = PrivacyPoolsSdk.prepareWithdrawalExecution(
            "stable",
            withdrawalManifest,
            artifactsRoot,
            withdrawalRequest,
            executionFixture.getLong("expectedChainId").toULong(),
            executionFixture.getString("poolAddress"),
            executionFixture.getString("validRpcUrl"),
            executionPolicy(executionFixture),
        )
        require(prepared.preflight.readConsistency == SMOKE_READ_CONSISTENCY) {
            "execution policy read_consistency did not round-trip"
        }
        require(prepared.preflight.maxFeeQuoteWei == SMOKE_MAX_FEE_QUOTE_WEI) {
            "execution policy max_fee_quote_wei did not round-trip"
        }
        val nullablePrepared = PrivacyPoolsSdk.prepareWithdrawalExecution(
            "stable",
            withdrawalManifest,
            artifactsRoot,
            withdrawalRequest,
            executionFixture.getLong("expectedChainId").toULong(),
            executionFixture.getString("poolAddress"),
            executionFixture.getString("validRpcUrl"),
            executionPolicy(executionFixture).copy(
                readConsistency = null,
                maxFeeQuoteWei = null,
            ),
        )
        require(nullablePrepared.preflight.readConsistency == null) {
            "null read_consistency did not round-trip"
        }
        require(nullablePrepared.preflight.maxFeeQuoteWei == null) {
            "null max_fee_quote_wei did not round-trip"
        }
        val signerHandle = "host-signer-collision"
        PrivacyPoolsSdk.registerHostProvidedSigner(
            signerHandle,
            executionFixture.getString("caller"),
        )
        val handleCollisionRejected = try {
            PrivacyPoolsSdk.registerHostProvidedSigner(
                signerHandle,
                executionFixture.getString("caller"),
            )
            false
        } catch (_: FfiException.HandleAlreadyRegistered) {
            true
        } finally {
            PrivacyPoolsSdk.unregisterSigner(signerHandle)
        }
        require(handleCollisionRejected) { "duplicate signer handles must fail closed" }
        val finalized = PrivacyPoolsSdk.finalizePreparedTransaction(
            executionFixture.getString("validRpcUrl"),
            prepared,
        )
        val signedTransaction = signRequest(
            executionFixture.getString("signerUrl"),
            finalized.request,
        )
        val submitted = PrivacyPoolsSdk.submitSignedTransaction(
            executionFixture.getString("validRpcUrl"),
            finalized,
            signedTransaction,
        )
        smoke.put("executionSubmitted", submitted.receipt.transactionHash.isNotEmpty())

        smoke.put(
            "wrongChainIdRejected",
            failsClosed {
                PrivacyPoolsSdk.prepareWithdrawalExecution(
                    "stable",
                    withdrawalManifest,
                    artifactsRoot,
                    withdrawalRequest,
                    executionFixture.getLong("expectedChainId").toULong() + 1UL,
                    executionFixture.getString("poolAddress"),
                    executionFixture.getString("validRpcUrl"),
                    executionPolicy(executionFixture),
                )
            },
        )
        smoke.put(
            "wrongCodeHashRejected",
            failsClosed {
                PrivacyPoolsSdk.prepareWithdrawalExecution(
                    "stable",
                    withdrawalManifest,
                    artifactsRoot,
                    withdrawalRequest,
                    executionFixture.getLong("expectedChainId").toULong(),
                    executionFixture.getString("poolAddress"),
                    executionFixture.getString("validRpcUrl"),
                    executionPolicy(executionFixture).copy(
                        expectedPoolCodeHash = mutateHex(executionFixture.getString("expectedPoolCodeHash")),
                    ),
                )
            },
        )
        smoke.put(
            "wrongRootRejected",
            failsClosed {
                PrivacyPoolsSdk.prepareWithdrawalExecution(
                    "stable",
                    withdrawalManifest,
                    artifactsRoot,
                    withdrawalRequest,
                    executionFixture.getLong("expectedChainId").toULong(),
                    executionFixture.getString("poolAddress"),
                    executionFixture.getString("wrongRootRpcUrl"),
                    executionPolicy(executionFixture),
                )
            },
        )
        smoke.put(
            "wrongSignerRejected",
            failsClosed {
                val wrongSignedTransaction = signRequest(
                    executionFixture.getString("wrongSignerUrl"),
                    finalized.request,
                )
                PrivacyPoolsSdk.submitSignedTransaction(
                    executionFixture.getString("validRpcUrl"),
                    finalized,
                    wrongSignedTransaction,
                )
            },
        )

        for (field in listOf(
            "commitmentVerified",
            "withdrawalVerified",
            "executionSubmitted",
            "signedManifestVerified",
            "wrongSignedManifestPublicKeyRejected",
            "tamperedSignedManifestArtifactsRejected",
            "tamperedProofRejected",
            "handleKindMismatchRejected",
            "staleVerifiedProofHandleRejected",
            "staleCommitmentSessionRejected",
            "staleWithdrawalSessionRejected",
            "wrongRootRejected",
            "wrongChainIdRejected",
            "wrongCodeHashRejected",
            "wrongSignerRejected",
        )) {
            require(smoke.getBoolean(field)) { "$field did not pass" }
        }
    }

    private fun runParityChecks(): JSONObject {
        val goldens = readJson("vectors/assurance-goldens.json")
        val auditCases = readJson("vectors/audit-parity-cases.json")
        val checks = mutableListOf<Pair<String, Boolean>>()

        val goldenCases = goldens.getJSONArray("cases")
        val goldenMerkleCases = goldens.getJSONArray("merkleCases")
        val comparisonCases = auditCases.getJSONArray("comparisonCases")
        val merkleCases = auditCases.getJSONArray("merkleCases")

        for (index in 0 until comparisonCases.length()) {
            val fixture = comparisonCases.getJSONObject(index)
            val expected = findByName(goldenCases, fixture.getString("name"))
            if (expected == null) {
                checks += "${fixture.getString("name")}: fixture" to false
                continue
            }

            val masterKeysHandle = PrivacyPoolsSdk.masterKeysHandle(
                fixture.getString("mnemonic").toByteArray(Charsets.UTF_8),
            )
            checks += "${fixture.getString("name")}: masterKeysHandle" to masterKeysHandle.isNotEmpty()

            val depositSecretsHandle = PrivacyPoolsSdk.depositSecretsHandle(
                masterKeysHandle,
                fixture.getString("scope"),
                fixture.getString("depositIndex"),
            )
            checks += "${fixture.getString("name")}: depositSecretsHandle" to depositSecretsHandle.isNotEmpty()

            val withdrawalSecretsHandle = PrivacyPoolsSdk.withdrawalSecretsHandle(
                masterKeysHandle,
                fixture.getString("label"),
                fixture.getString("withdrawalIndex"),
            )
            checks += "${fixture.getString("name")}: withdrawalSecretsHandle" to withdrawalSecretsHandle.isNotEmpty()

            val expectedDepositSecrets = expected.getJSONObject("depositSecrets")

            val commitment = PrivacyPoolsSdk.commitment(
                fixture.getString("value"),
                fixture.getString("label"),
                expectedDepositSecrets.getString("nullifier"),
                expectedDepositSecrets.getString("secret"),
            )
            checks += "${fixture.getString("name")}: precommitmentHash" to (
                commitment.precommitmentHash == expected.getString("precommitmentHash")
            )
            checks += "${fixture.getString("name")}: commitment" to jsonEquals(
                JSONObject().apply {
                    put("hash", commitment.hash)
                    put("nullifierHash", commitment.nullifierHash)
                    put("precommitmentHash", commitment.precommitmentHash)
                    put("value", commitment.value)
                    put("label", commitment.label)
                    put("nullifier", commitment.nullifier)
                    put("secret", commitment.secret)
                },
                expected.getJSONObject("commitment"),
            )

            val withdrawal = fixture.getJSONObject("withdrawal")
            val withdrawalContext = PrivacyPoolsSdk.withdrawalContext(
                FfiWithdrawal(withdrawal.getString("processooor"), hexToBytes(withdrawal.getString("data"))),
                fixture.getString("scope"),
            )
            checks += "${fixture.getString("name")}: withdrawalContextHex" to (
                withdrawalContext == expected.getString("withdrawalContextHex")
            )
        }

        for (index in 0 until merkleCases.length()) {
            val fixture = merkleCases.getJSONObject(index)
            val expected = findByName(goldenMerkleCases, fixture.getString("name"))
            if (expected == null) {
                checks += "${fixture.getString("name")}: merkleFixture" to false
                continue
            }

            val leaves = List(fixture.getJSONArray("leaves").length()) { fixture.getJSONArray("leaves").getString(it) }
            val proof = PrivacyPoolsSdk.merkleProof(leaves, fixture.getString("leaf"))
            checks += "${fixture.getString("name")}: merkleProof" to jsonEquals(
                JSONObject().apply {
                    put("root", proof.root)
                    put("leaf", proof.leaf)
                    put("index", proof.index.toLong())
                    put("siblings", JSONArray(proof.siblings))
                },
                expected.getJSONObject("proof"),
            )
        }

        val failedChecks = checks.filterNot { it.second }.map { it.first }
        return JSONObject().apply {
            put("totalChecks", checks.size)
            put("passed", checks.size - failedChecks.size)
            put("failed", failedChecks.size)
            put("failedChecks", JSONArray(failedChecks))
        }
    }

    private fun copyFixtureAssets(): File {
        val destination = File(context.filesDir, "privacy-pools-sdk-fixtures")
        destination.deleteRecursively()
        copyAssetTree("artifacts", destination)
        copyAssetTree("circuits", destination)
        copyAssetTree("vectors", destination)
        return destination
    }

    private fun writeReport(smoke: JSONObject, parity: JSONObject) {
        val report = JSONObject().apply {
            put("generatedAt", java.time.Instant.now().toString())
            put("runtime", "native")
            put("platform", "android")
            put("surface", "native")
            put("smoke", smoke)
            put("parity", parity)
            put("benchmark", defaultBenchmark())
        }
        reportFile().apply {
            parentFile?.mkdirs()
            writeText(report.toString(2))
        }
        val compactReport = report.toString()
        Log.i(REPORT_TAG, "$REPORT_MARKER $compactReport")
        println("$REPORT_MARKER $compactReport")
    }

    private fun defaultSmoke() = JSONObject().apply {
        put("backend", "unknown")
        put("commitmentVerified", false)
        put("withdrawalVerified", false)
        put("executionSubmitted", false)
        put("signedManifestVerified", false)
        put("wrongSignedManifestPublicKeyRejected", false)
        put("tamperedSignedManifestArtifactsRejected", false)
        put("tamperedProofRejected", false)
        put("handleKindMismatchRejected", false)
        put("staleVerifiedProofHandleRejected", false)
        put("staleCommitmentSessionRejected", false)
        put("staleWithdrawalSessionRejected", false)
        put("wrongRootRejected", false)
        put("wrongChainIdRejected", false)
        put("wrongCodeHashRejected", false)
        put("wrongSignerRejected", false)
    }

    private fun defaultParity() = JSONObject().apply {
        put("totalChecks", 0)
        put("passed", 0)
        put("failed", 0)
        put("failedChecks", JSONArray())
    }

    private fun failureParity(message: String) = JSONObject().apply {
        put("totalChecks", 1)
        put("passed", 0)
        put("failed", 1)
        put("failedChecks", JSONArray().put(message))
    }

    private fun appendParityFailure(parity: JSONObject, message: String): JSONObject {
        val failedChecks = parity.optJSONArray("failedChecks") ?: JSONArray()
        failedChecks.put(message)
        return JSONObject().apply {
            put("totalChecks", parity.optInt("totalChecks", 0))
            put("passed", maxOf(0, parity.optInt("totalChecks", 0) - failedChecks.length()))
            put("failed", failedChecks.length())
            put("failedChecks", failedChecks)
        }
    }

    private fun defaultBenchmark() = JSONObject().apply {
        put("artifactResolutionMs", 0.0)
        put("bundleVerificationMs", 0.0)
        put("sessionPreloadMs", 0.0)
        put("firstInputPreparationMs", 0.0)
        put("firstWitnessGenerationMs", 0.0)
        put("firstProofGenerationMs", 0.0)
        put("firstVerificationMs", 0.0)
        put("firstProveAndVerifyMs", 0.0)
        put("iterations", 1)
        put("warmup", 0)
        put("peakResidentMemoryBytes", JSONObject.NULL)
        put(
            "samples",
            JSONArray().put(
                JSONObject().apply {
                    put("inputPreparationMs", 0.0)
                    put("witnessGenerationMs", 0.0)
                    put("proofGenerationMs", 0.0)
                    put("verificationMs", 0.0)
                    put("proveAndVerifyMs", 0.0)
                },
            ),
        )
    }

    private fun executionPolicy(fixture: JSONObject) = FfiExecutionPolicy(
        fixture.getLong("expectedChainId").toULong(),
        fixture.getString("caller"),
        fixture.getString("expectedPoolCodeHash"),
        fixture.getString("expectedEntrypointCodeHash"),
        SMOKE_READ_CONSISTENCY,
        SMOKE_MAX_FEE_QUOTE_WEI,
        "strict",
    )

    private fun withdrawalRequest(
        commitment: FfiCommitment,
        crypto: JSONObject,
        fixture: JSONObject,
        processooor: String,
    ): FfiWithdrawalWitnessRequest =
        FfiWithdrawalWitnessRequest(
            commitment,
            FfiWithdrawal(processooor, byteArrayOf(0x12, 0x34)),
            crypto.getString("scope"),
            fixture.getString("withdrawalAmount"),
            circuitWitness(fixture.getJSONObject("stateWitness")),
            circuitWitness(fixture.getJSONObject("aspWitness")),
            fixture.getString("newNullifier"),
            fixture.getString("newSecret"),
        )

    private fun circuitWitness(value: JSONObject): FfiCircuitMerkleWitness =
        FfiCircuitMerkleWitness(
            value.getString("root"),
            value.getString("leaf"),
            value.getLong("index").toULong(),
            stringList(value.getJSONArray("siblings")),
            value.getLong("depth").toULong(),
        )

    private fun signRequest(url: String, request: FfiFinalizedTransactionRequest): String {
        val payload = JSONObject().apply {
            put("kind", request.kind)
            put("chainId", request.chainId.toLong())
            put("from", request.from)
            put("to", request.to)
            put("nonce", request.nonce.toLong())
            put("gasLimit", request.gasLimit.toLong())
            put("value", request.value)
            put("data", request.data)
            put("gasPrice", request.gasPrice)
            put("maxFeePerGas", request.maxFeePerGas)
            put("maxPriorityFeePerGas", request.maxPriorityFeePerGas)
        }
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("content-type", "application/json")
        connection.outputStream.use { output ->
            output.write(payload.toString().toByteArray())
        }
        val body = connection.inputStream.bufferedReader().use { it.readText() }
        return JSONObject(body).getString("signedTransaction")
    }

    private fun failsClosed(block: () -> Any): Boolean = try {
        block()
        false
    } catch (_: Throwable) {
        true
    }

    private fun rejectsOrFalse(block: () -> Boolean): Boolean = try {
        !block()
    } catch (_: Throwable) {
        true
    }

    private fun findByName(values: JSONArray, name: String): JSONObject? =
        (0 until values.length())
            .map { values.getJSONObject(it) }
            .firstOrNull { it.optString("name") == name }

    private fun jsonEquals(left: JSONObject, right: JSONObject): Boolean = jsonValueEquals(left, right)

    private fun jsonValueEquals(left: Any?, right: Any?): Boolean {
        if (left === right) {
            return true
        }
        if (left == null || right == null) {
            return false
        }
        if (left is Number && right is Number) {
            return canonicalNumber(left) == canonicalNumber(right)
        }
        if (left is JSONObject && right is JSONObject) {
            if (left.length() != right.length()) {
                return false
            }
            val keys = left.keys().asSequence().toList()
            if (keys.any { !right.has(it) }) {
                return false
            }
            return keys.all { key ->
                jsonValueEquals(left.opt(key), right.opt(key))
            }
        }
        if (left is JSONArray && right is JSONArray) {
            if (left.length() != right.length()) {
                return false
            }
            return (0 until left.length()).all { index ->
                jsonValueEquals(left.opt(index), right.opt(index))
            }
        }
        return left == right
    }

    private fun canonicalNumber(value: Number): BigDecimal =
        try {
            BigDecimal(value.toString()).stripTrailingZeros()
        } catch (_: NumberFormatException) {
            BigDecimal(value.toDouble()).stripTrailingZeros()
        }

    private fun mutateHex(value: String): String =
        if (value.isEmpty()) "00" else value.dropLast(1) + if (value.last() == '0') "1" else "0"

    private fun hexToBytes(value: String): ByteArray {
        val normalized = value.removePrefix("0x")
        if (normalized.isEmpty()) {
            return byteArrayOf()
        }
        val padded = if (normalized.length % 2 == 0) normalized else "0$normalized"
        return ByteArray(padded.length / 2) { index ->
            padded.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun stringList(values: JSONArray): List<String> =
        List(values.length()) { index -> values.getString(index) }

    private fun readText(path: String): String =
        context.assets.open(path).bufferedReader().use { it.readText() }

    private fun readJson(path: String): JSONObject = JSONObject(readText(path))

    private fun copyAssetTree(assetPath: String, destinationRoot: File) {
        val children = context.assets.list(assetPath)?.toList().orEmpty()
        val destination = File(destinationRoot, assetPath)
        if (children.isEmpty()) {
            destination.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                destination.outputStream().use { output -> input.copyTo(output) }
            }
            return
        }

        destination.mkdirs()
        for (child in children) {
            copyAssetTree("$assetPath/$child", destinationRoot)
        }
    }

    private fun reportFile(): File =
        File(context.getExternalFilesDir(null) ?: context.filesDir, "native-smoke-report.json")
}
