package io.oxbow.privacypoolssdk

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeProveVerifyInstrumentedTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun provesAndVerifiesCommitmentAndWithdrawalInAppProcess() {
        val fixturesRoot = copyFixtureAssets()
        val artifactsRoot = File(fixturesRoot, "artifacts").absolutePath
        val crypto = readJson("vectors/crypto-compatibility.json")
        val withdrawalFixture = readJson("vectors/withdrawal-circuit-input.json")
        val withdrawalManifest = readText("artifacts/withdrawal-proving-manifest.json")
        val commitmentManifest = readText("artifacts/commitment-proving-manifest.json")
        val depositSecrets = crypto.getJSONObject("depositSecrets")

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
        assertEquals("arkworks", commitmentProof.backend)
        assertTrue(
            PrivacyPoolsSdk.verifyCommitmentProofWithSession(
                "stable",
                commitmentSession.handle,
                commitmentProof.proof,
            ),
        )
        assertTrue(PrivacyPoolsSdk.removeCommitmentCircuitSession(commitmentSession.handle))
        assertSessionFailsClosed {
            PrivacyPoolsSdk.verifyCommitmentProofWithSession(
                "stable",
                commitmentSession.handle,
                commitmentProof.proof,
            )
        }

        val withdrawalSession = PrivacyPoolsSdk.prepareWithdrawalCircuitSession(
            withdrawalManifest,
            artifactsRoot,
        )
        val withdrawalProof = PrivacyPoolsSdk.proveWithdrawalWithSession(
            "stable",
            withdrawalSession.handle,
            withdrawalRequest(commitment, crypto, withdrawalFixture),
        )
        assertEquals("arkworks", withdrawalProof.backend)
        assertTrue(
            PrivacyPoolsSdk.verifyWithdrawalProofWithSession(
                "stable",
                withdrawalSession.handle,
                withdrawalProof.proof,
            ),
        )
        assertTrue(PrivacyPoolsSdk.removeWithdrawalCircuitSession(withdrawalSession.handle))
        assertSessionFailsClosed {
            PrivacyPoolsSdk.verifyWithdrawalProofWithSession(
                "stable",
                withdrawalSession.handle,
                withdrawalProof.proof,
            )
        }
    }

    private fun withdrawalRequest(
        commitment: FfiCommitment,
        crypto: JSONObject,
        fixture: JSONObject,
    ): FfiWithdrawalWitnessRequest =
        FfiWithdrawalWitnessRequest(
            commitment,
            FfiWithdrawal(
                "0x1111111111111111111111111111111111111111",
                byteArrayOf(0x12, 0x34),
            ),
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

    private fun stringList(values: JSONArray): List<String> =
        List(values.length()) { index -> values.getString(index) }

    private fun assertSessionFailsClosed(block: () -> Unit) {
        try {
            block()
            fail("expected stale session call to fail")
        } catch (_: FfiException) {
        }
    }

    private fun readText(path: String): String =
        context.assets.open(path).bufferedReader().use { it.readText() }

    private fun readJson(path: String): JSONObject = JSONObject(readText(path))

    private fun copyFixtureAssets(): File {
        val destination = File(context.filesDir, "privacy-pools-sdk-fixtures")
        destination.deleteRecursively()
        copyAssetTree("artifacts", destination)
        copyAssetTree("circuits", destination)
        return destination
    }

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
}
