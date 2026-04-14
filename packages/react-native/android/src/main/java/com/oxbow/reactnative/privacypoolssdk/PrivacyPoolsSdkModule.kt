package com.oxbow.reactnative.privacypoolssdk

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import io.oxbow.privacypoolssdk.FfiArtifactVerification
import io.oxbow.privacypoolssdk.FfiException
import io.oxbow.privacypoolssdk.FfiMasterKeys
import io.oxbow.privacypoolssdk.FfiRootRead
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

    private fun masterKeysMap(keys: FfiMasterKeys) = Arguments.createMap().apply {
        putString("master_nullifier", keys.masterNullifier)
        putString("master_secret", keys.masterSecret)
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
}
