import Foundation
import React

@objc(PrivacyPoolsSdk)
final class PrivacyPoolsSdk: NSObject {
    @objc
    static func requiresMainQueueSetup() -> Bool {
        false
    }

    @objc(getVersion:rejecter:)
    func getVersion(
        resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        resolve(PrivacyPoolsSdkClient.version())
    }

    @objc(getStableBackendName:rejecter:)
    func getStableBackendName(
        resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.stableBackendName())
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(fastBackendSupportedOnTarget:rejecter:)
    func fastBackendSupportedOnTarget(
        resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        resolve(PrivacyPoolsSdkClient.supportsFastBackendOnTarget())
    }

    @objc(deriveMasterKeys:resolver:rejecter:)
    func deriveMasterKeys(
        mnemonic: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let keys = try PrivacyPoolsSdkClient.masterKeys(forMnemonic: mnemonic)
            resolve([
                "master_nullifier": keys.masterNullifier,
                "master_secret": keys.masterSecret,
            ])
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(planPoolStateRootRead:resolver:rejecter:)
    func planPoolStateRootRead(
        poolAddress: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let read = try PrivacyPoolsSdkClient.poolStateRootRead(poolAddress: poolAddress)
            resolve(rootReadMap(read))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(planAspRootRead:poolAddress:resolver:rejecter:)
    func planAspRootRead(
        entrypointAddress: String,
        poolAddress: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let read = try PrivacyPoolsSdkClient.aspRootRead(
                entrypointAddress: entrypointAddress,
                poolAddress: poolAddress
            )
            resolve(rootReadMap(read))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(verifyArtifactBytes:circuit:kind:bytes:resolver:rejecter:)
    func verifyArtifactBytes(
        manifestJson: String,
        circuit: String,
        kind: String,
        bytes: [NSNumber],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let data = Data(bytes.map(\.uint8Value))
            let verification = try PrivacyPoolsSdkClient.verifyArtifactBytes(
                manifestJson: manifestJson,
                circuit: circuit,
                kind: kind,
                bytes: data
            )

            resolve([
                "version": verification.version,
                "circuit": verification.circuit,
                "kind": verification.kind,
                "filename": verification.filename,
            ])
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    private func rootReadMap(_ read: FfiRootRead) -> [String: String] {
        [
            "kind": read.kind,
            "contract_address": read.contractAddress,
            "pool_address": read.poolAddress,
            "call_data": read.callData,
        ]
    }
}
