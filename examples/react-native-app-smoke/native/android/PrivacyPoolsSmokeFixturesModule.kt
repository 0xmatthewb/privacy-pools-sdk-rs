package {{PACKAGE}}

import android.util.Log
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.io.File

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

            promise.resolve(
                Arguments.createMap().apply {
                    putString("root", destination.absolutePath)
                    putString("artifactsRoot", File(destination, "artifacts").absolutePath)
                    putString(
                        "withdrawalManifestJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/withdrawal-proving-manifest.json"),
                    )
                    putString(
                        "commitmentManifestJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/artifacts/commitment-proving-manifest.json"),
                    )
                    putString(
                        "cryptoCompatibilityJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/crypto-compatibility.json"),
                    )
                    putString(
                        "withdrawalCircuitInputJson",
                        readAssetText("$FIXTURE_ASSET_ROOT/vectors/withdrawal-circuit-input.json"),
                    )
                }
            )
        } catch (error: Exception) {
            promise.reject("fixture_error", error.message, error)
        }
    }

    @ReactMethod
    fun markSuccess(marker: String, promise: Promise) {
        Log.i(LOG_TAG, marker)
        promise.resolve(true)
    }

    @ReactMethod
    fun markFailure(marker: String, message: String, promise: Promise) {
        Log.e(LOG_TAG, "$marker $message")
        promise.resolve(true)
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

    private companion object {
        const val FIXTURE_ASSET_ROOT = "privacy-pools-fixtures"
        const val LOG_TAG = "PrivacyPoolsRnAppSmoke"
    }
}
