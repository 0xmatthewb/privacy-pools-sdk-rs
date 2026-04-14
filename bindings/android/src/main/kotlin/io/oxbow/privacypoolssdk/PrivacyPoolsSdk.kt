package io.oxbow.privacypoolssdk

import io.oxbow.privacypoolssdk.deriveMasterKeys as ffiDeriveMasterKeys
import io.oxbow.privacypoolssdk.fastBackendSupportedOnTarget as ffiFastBackendSupportedOnTarget
import io.oxbow.privacypoolssdk.getStableBackendName as ffiGetStableBackendName
import io.oxbow.privacypoolssdk.getVersion as ffiGetVersion
import io.oxbow.privacypoolssdk.planAspRootRead as ffiPlanAspRootRead
import io.oxbow.privacypoolssdk.planPoolStateRootRead as ffiPlanPoolStateRootRead
import io.oxbow.privacypoolssdk.verifyArtifactBytes as ffiVerifyArtifactBytes

object PrivacyPoolsSdk {
    fun version(): String = ffiGetVersion()

    @Throws(FfiException::class)
    fun stableBackendName(): String = ffiGetStableBackendName()

    fun supportsFastBackendOnTarget(): Boolean = ffiFastBackendSupportedOnTarget()

    @Throws(FfiException::class)
    fun masterKeys(mnemonic: String): FfiMasterKeys = ffiDeriveMasterKeys(mnemonic)

    @Throws(FfiException::class)
    fun poolStateRootRead(poolAddress: String): FfiRootRead =
        ffiPlanPoolStateRootRead(poolAddress)

    @Throws(FfiException::class)
    fun aspRootRead(entrypointAddress: String, poolAddress: String): FfiRootRead =
        ffiPlanAspRootRead(entrypointAddress, poolAddress)

    @Throws(FfiException::class)
    fun verifyArtifactBytes(
        manifestJson: String,
        circuit: String,
        kind: String,
        bytes: ByteArray,
    ): FfiArtifactVerification =
        ffiVerifyArtifactBytes(manifestJson, circuit, kind, bytes)
}
