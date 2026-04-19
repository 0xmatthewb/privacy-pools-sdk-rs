package com.privacypoolsrnappsmoke

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.io.File
import org.json.JSONObject

class PrivacyPoolsSmokeFixturesModule(
    private val reactContext: ReactApplicationContext,
) : ReactContextBaseJavaModule(reactContext) {
    override fun getName(): String = "PrivacyPoolsSmokeFixtures"

    @ReactMethod
    fun copyFixtures(promise: Promise) {
        try {
            val destination = File(reactContext.filesDir, FIXTURE_ASSET_ROOT)
            destination.deleteRecursively()
            copyAssetTree(FIXTURE_ASSET_ROOT, reactContext.filesDir)
            resetReportFiles()
            writeStatus("running")

            promise.resolve(
                Arguments.createMap().apply {
                    putString("root", destination.absolutePath)
                    putString("artifactsRoot", File(destination, "artifacts").absolutePath)
                    putString("reportPath", reportFile().absolutePath)
                    putString("statusPath", statusFile().absolutePath)
                    putString(
                        "withdrawalManifestJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/withdrawal-proving-manifest.json"),
                    )
                    putString(
                        "commitmentManifestJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/commitment-proving-manifest.json"),
                    )
                    putString(
                        "signedManifestPayloadJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/signed-manifest/payload.json"),
                    )
                    putString(
                        "signedManifestSignatureHex",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/signed-manifest/signature").trim(),
                    )
                    putString(
                        "signedManifestPublicKeyHex",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/signed-manifest/public-key.hex").trim(),
                    )
                    putString(
                        "cryptoCompatibilityJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/crypto-compatibility.json"),
                    )
                    putString(
                        "withdrawalCircuitInputJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/withdrawal-circuit-input.json"),
                    )
                    putString(
                        "assuranceGoldensJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/assurance-goldens.json"),
                    )
                    putString(
                        "auditParityCasesJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/audit-parity-cases.json"),
                    )
                    putString(
                        "executionFixtureJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/mobile-execution-fixture.json"),
                    )
                }
            )
        } catch (error: Exception) {
            promise.reject("fixture_error", error.message, error)
        }
    }

    @ReactMethod
    fun markSuccess(marker: String, promise: Promise) {
        try {
            writeStatus("success")
            promise.resolve(true)
        } catch (error: Exception) {
            promise.reject("report_error", error.message, error)
        }
    }

    @ReactMethod
    fun markFailure(marker: String, message: String, promise: Promise) {
        try {
            writeStatus("error", message)
            promise.resolve(true)
        } catch (error: Exception) {
            promise.reject("report_error", error.message, error)
        }
    }

    @ReactMethod
    fun markProgress(marker: String, message: String, promise: Promise) {
        try {
            writeStatus("running", message)
            promise.resolve(true)
        } catch (error: Exception) {
            promise.reject("report_error", error.message, error)
        }
    }

    @ReactMethod
    fun markReport(marker: String, reportJson: String, promise: Promise) {
        try {
            reportFile().apply {
                parentFile?.mkdirs()
                writeText(reportJson)
            }
            promise.resolve(true)
        } catch (error: Exception) {
            promise.reject("report_error", error.message, error)
        }
    }

    private fun readAssetText(path: String): String =
        reactContext.assets.open(path).bufferedReader().use { it.readText() }

    private fun copyAssetTree(assetPath: String, destinationRoot: File) {
        val children = reactContext.assets.list(assetPath)?.toList().orEmpty()
        val destination = File(destinationRoot, assetPath)
        if (children.isEmpty()) {
            destination.parentFile?.mkdirs()
            reactContext.assets.open(assetPath).use { input ->
                destination.outputStream().use { output -> input.copyTo(output) }
            }
            return
        }

        destination.mkdirs()
        for (child in children) {
            copyAssetTree("$assetPath/$child", destinationRoot)
        }
    }

    private fun reportRoot(): File =
        File(reactContext.getExternalFilesDir(null) ?: reactContext.filesDir, REPORT_DIRECTORY)
            .apply { mkdirs() }

    private fun reportFile(): File = File(reportRoot(), REPORT_FILE_NAME)

    private fun statusFile(): File = File(reportRoot(), STATUS_FILE_NAME)

    private fun resetReportFiles() {
        reportFile().delete()
        statusFile().delete()
    }

    private fun writeStatus(status: String, message: String? = null) {
        val payload = JSONObject().apply {
            put("status", status)
            put("updatedAt", System.currentTimeMillis())
            if (message != null) {
                put("message", message)
            }
        }
        statusFile().apply {
            parentFile?.mkdirs()
            writeText(payload.toString())
        }
    }

    private companion object {
        const val FIXTURE_ASSET_ROOT = "privacy-pools-fixtures"
        const val REPORT_DIRECTORY = "privacy-pools-smoke"
        const val REPORT_FILE_NAME = "report.json"
        const val STATUS_FILE_NAME = "report-status.json"
    }
}
