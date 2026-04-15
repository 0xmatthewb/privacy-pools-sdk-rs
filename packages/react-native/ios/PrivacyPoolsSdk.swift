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

    @objc(deriveDepositSecrets:masterSecret:scope:index:resolver:rejecter:)
    func deriveDepositSecrets(
        masterNullifier: String,
        masterSecret: String,
        scope: String,
        index: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let secrets = try PrivacyPoolsSdkClient.depositSecrets(
                masterNullifier: masterNullifier,
                masterSecret: masterSecret,
                scope: scope,
                index: index
            )
            resolve(secretsMap(secrets))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(deriveWithdrawalSecrets:masterSecret:label:index:resolver:rejecter:)
    func deriveWithdrawalSecrets(
        masterNullifier: String,
        masterSecret: String,
        label: String,
        index: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let secrets = try PrivacyPoolsSdkClient.withdrawalSecrets(
                masterNullifier: masterNullifier,
                masterSecret: masterSecret,
                label: label,
                index: index
            )
            resolve(secretsMap(secrets))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(getCommitment:label:nullifier:secret:resolver:rejecter:)
    func getCommitment(
        value: String,
        label: String,
        nullifier: String,
        secret: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let commitment = try PrivacyPoolsSdkClient.commitment(
                value: value,
                label: label,
                nullifier: nullifier,
                secret: secret
            )
            resolve(commitmentMap(commitment))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(calculateWithdrawalContext:scope:resolver:rejecter:)
    func calculateWithdrawalContext(
        withdrawal: [String: Any],
        scope: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let ffiWithdrawal = try withdrawalRecord(from: withdrawal)
            resolve(try PrivacyPoolsSdkClient.withdrawalContext(withdrawal: ffiWithdrawal, scope: scope))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(generateMerkleProof:leaf:resolver:rejecter:)
    func generateMerkleProof(
        leaves: [String],
        leaf: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let proof = try PrivacyPoolsSdkClient.merkleProof(leaves: leaves, leaf: leaf)
            resolve(merkleProofMap(proof))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(buildCircuitMerkleWitness:depth:resolver:rejecter:)
    func buildCircuitMerkleWitness(
        proof: [String: Any],
        depth: NSNumber,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let ffiProof = try merkleProofRecord(from: proof)
            let witness = try PrivacyPoolsSdkClient.circuitMerkleWitness(
                proof: ffiProof,
                depth: depth.uint64Value
            )
            resolve(circuitMerkleWitnessMap(witness))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(buildWithdrawalCircuitInput:resolver:rejecter:)
    func buildWithdrawalCircuitInput(
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let input = try PrivacyPoolsSdkClient.withdrawalCircuitInput(
                request: try withdrawalWitnessRequestRecord(from: request)
            )
            resolve(withdrawalCircuitInputMap(input))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(buildCommitmentCircuitInput:resolver:rejecter:)
    func buildCommitmentCircuitInput(
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let input = try PrivacyPoolsSdkClient.commitmentCircuitInput(
                request: try commitmentWitnessRequestRecord(from: request)
            )
            resolve(commitmentCircuitInputMap(input))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareWithdrawalCircuitSession:artifactsRoot:resolver:rejecter:)
    func prepareWithdrawalCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.prepareWithdrawalCircuitSession(
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot
            )
            resolve(withdrawalCircuitSessionHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareWithdrawalCircuitSessionFromBytes:artifacts:resolver:rejecter:)
    func prepareWithdrawalCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: [[String: Any]],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.prepareWithdrawalCircuitSessionFromBytes(
                manifestJson: manifestJson,
                artifacts: try artifacts.map(artifactBytesRecord(from:))
            )
            resolve(withdrawalCircuitSessionHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(removeWithdrawalCircuitSession:resolver:rejecter:)
    func removeWithdrawalCircuitSession(
        handle: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.removeWithdrawalCircuitSession(handle: handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareCommitmentCircuitSession:artifactsRoot:resolver:rejecter:)
    func prepareCommitmentCircuitSession(
        manifestJson: String,
        artifactsRoot: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.prepareCommitmentCircuitSession(
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot
            )
            resolve(commitmentCircuitSessionHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareCommitmentCircuitSessionFromBytes:artifacts:resolver:rejecter:)
    func prepareCommitmentCircuitSessionFromBytes(
        manifestJson: String,
        artifacts: [[String: Any]],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.prepareCommitmentCircuitSessionFromBytes(
                manifestJson: manifestJson,
                artifacts: try artifacts.map(artifactBytesRecord(from:))
            )
            resolve(commitmentCircuitSessionHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(removeCommitmentCircuitSession:resolver:rejecter:)
    func removeCommitmentCircuitSession(
        handle: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.removeCommitmentCircuitSession(handle: handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(proveWithdrawal:manifestJson:artifactsRoot:request:resolver:rejecter:)
    func proveWithdrawal(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let result = try PrivacyPoolsSdkClient.withdrawalProof(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request)
            )
            resolve(provingResultMap(result))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(proveWithdrawalWithSession:sessionHandle:request:resolver:rejecter:)
    func proveWithdrawalWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let result = try PrivacyPoolsSdkClient.withdrawalProof(
                backendProfile: backendProfile,
                sessionHandle: sessionHandle,
                request: try withdrawalWitnessRequestRecord(from: request)
            )
            resolve(provingResultMap(result))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(proveCommitment:manifestJson:artifactsRoot:request:resolver:rejecter:)
    func proveCommitment(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let result = try PrivacyPoolsSdkClient.commitmentProof(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try commitmentWitnessRequestRecord(from: request)
            )
            resolve(provingResultMap(result))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(proveCommitmentWithSession:sessionHandle:request:resolver:rejecter:)
    func proveCommitmentWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let result = try PrivacyPoolsSdkClient.commitmentProof(
                backendProfile: backendProfile,
                sessionHandle: sessionHandle,
                request: try commitmentWitnessRequestRecord(from: request)
            )
            resolve(provingResultMap(result))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(startProveWithdrawalJob:manifestJson:artifactsRoot:request:resolver:rejecter:)
    func startProveWithdrawalJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.startWithdrawalProofJob(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request)
            )
            resolve(asyncJobHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(startProveWithdrawalJobWithSession:sessionHandle:request:resolver:rejecter:)
    func startProveWithdrawalJobWithSession(
        backendProfile: String,
        sessionHandle: String,
        request: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.startWithdrawalProofJob(
                backendProfile: backendProfile,
                sessionHandle: sessionHandle,
                request: try withdrawalWitnessRequestRecord(from: request)
            )
            resolve(asyncJobHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(verifyWithdrawalProof:manifestJson:artifactsRoot:proof:resolver:rejecter:)
    func verifyWithdrawalProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.verifyWithdrawal(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                proof: try proofBundleRecord(from: proof)
            ))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(verifyWithdrawalProofWithSession:sessionHandle:proof:resolver:rejecter:)
    func verifyWithdrawalProofWithSession(
        backendProfile: String,
        sessionHandle: String,
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.verifyWithdrawal(
                backendProfile: backendProfile,
                sessionHandle: sessionHandle,
                proof: try proofBundleRecord(from: proof)
            ))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(verifyCommitmentProof:manifestJson:artifactsRoot:proof:resolver:rejecter:)
    func verifyCommitmentProof(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.verifyCommitment(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                proof: try proofBundleRecord(from: proof)
            ))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(verifyCommitmentProofWithSession:sessionHandle:proof:resolver:rejecter:)
    func verifyCommitmentProofWithSession(
        backendProfile: String,
        sessionHandle: String,
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.verifyCommitment(
                backendProfile: backendProfile,
                sessionHandle: sessionHandle,
                proof: try proofBundleRecord(from: proof)
            ))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(pollJobStatus:resolver:rejecter:)
    func pollJobStatus(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(asyncJobStatusMap(try PrivacyPoolsSdkClient.jobStatus(jobId: jobId)))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(getProveWithdrawalJobResult:resolver:rejecter:)
    func getProveWithdrawalJobResult(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.withdrawalProofJobResult(jobId: jobId).map(provingResultMap))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(cancelJob:resolver:rejecter:)
    func cancelJob(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.cancelBackgroundJob(jobId: jobId))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(removeJob:resolver:rejecter:)
    func removeJob(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.removeBackgroundJob(jobId: jobId))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareWithdrawalExecution:manifestJson:artifactsRoot:request:chainId:poolAddress:rpcUrl:policy:resolver:rejecter:)
    func prepareWithdrawalExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        chainId: NSNumber,
        poolAddress: String,
        rpcUrl: String,
        policy: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let prepared = try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request),
                chainId: chainId.uint64Value,
                poolAddress: poolAddress,
                rpcUrl: rpcUrl,
                policy: try executionPolicyRecord(from: policy)
            )
            resolve(preparedExecutionMap(prepared))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(startPrepareWithdrawalExecutionJob:manifestJson:artifactsRoot:request:chainId:poolAddress:rpcUrl:policy:resolver:rejecter:)
    func startPrepareWithdrawalExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        chainId: NSNumber,
        poolAddress: String,
        rpcUrl: String,
        policy: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.startWithdrawalExecutionJob(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request),
                chainId: chainId.uint64Value,
                poolAddress: poolAddress,
                rpcUrl: rpcUrl,
                policy: try executionPolicyRecord(from: policy)
            )
            resolve(asyncJobHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(getPrepareWithdrawalExecutionJobResult:resolver:rejecter:)
    func getPrepareWithdrawalExecutionJobResult(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.withdrawalExecutionJobResult(jobId: jobId).map(preparedExecutionMap))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(prepareRelayExecution:manifestJson:artifactsRoot:request:chainId:entrypointAddress:poolAddress:rpcUrl:policy:resolver:rejecter:)
    func prepareRelayExecution(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        chainId: NSNumber,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let prepared = try PrivacyPoolsSdkClient.prepareRelayExecution(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request),
                chainId: chainId.uint64Value,
                entrypointAddress: entrypointAddress,
                poolAddress: poolAddress,
                rpcUrl: rpcUrl,
                policy: try executionPolicyRecord(from: policy)
            )
            resolve(preparedExecutionMap(prepared))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(startPrepareRelayExecutionJob:manifestJson:artifactsRoot:request:chainId:entrypointAddress:poolAddress:rpcUrl:policy:resolver:rejecter:)
    func startPrepareRelayExecutionJob(
        backendProfile: String,
        manifestJson: String,
        artifactsRoot: String,
        request: [String: Any],
        chainId: NSNumber,
        entrypointAddress: String,
        poolAddress: String,
        rpcUrl: String,
        policy: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let handle = try PrivacyPoolsSdkClient.startRelayExecutionJob(
                backendProfile: backendProfile,
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                request: try withdrawalWitnessRequestRecord(from: request),
                chainId: chainId.uint64Value,
                entrypointAddress: entrypointAddress,
                poolAddress: poolAddress,
                rpcUrl: rpcUrl,
                policy: try executionPolicyRecord(from: policy)
            )
            resolve(asyncJobHandleMap(handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(getPrepareRelayExecutionJobResult:resolver:rejecter:)
    func getPrepareRelayExecutionJobResult(
        jobId: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.relayExecutionJobResult(jobId: jobId).map(preparedExecutionMap))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(registerLocalMnemonicSigner:mnemonic:index:resolver:rejecter:)
    func registerLocalMnemonicSigner(
        handle: String,
        mnemonic: String,
        index: NSNumber,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let signer = try PrivacyPoolsSdkClient.registerLocalMnemonicSigner(
                handle: handle,
                mnemonic: mnemonic,
                index: index.uint32Value
            )
            resolve(signerHandleMap(signer))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(registerHostProvidedSigner:address:resolver:rejecter:)
    func registerHostProvidedSigner(
        handle: String,
        address: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let signer = try PrivacyPoolsSdkClient.registerHostProvidedSigner(
                handle: handle,
                address: address
            )
            resolve(signerHandleMap(signer))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(registerMobileSecureStorageSigner:address:resolver:rejecter:)
    func registerMobileSecureStorageSigner(
        handle: String,
        address: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let signer = try PrivacyPoolsSdkClient.registerMobileSecureStorageSigner(
                handle: handle,
                address: address
            )
            resolve(signerHandleMap(signer))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(unregisterSigner:resolver:rejecter:)
    func unregisterSigner(
        handle: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.unregisterSigner(handle: handle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(finalizePreparedTransaction:prepared:resolver:rejecter:)
    func finalizePreparedTransaction(
        rpcUrl: String,
        prepared: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let finalized = try PrivacyPoolsSdkClient.finalizePreparedTransaction(
                rpcUrl: rpcUrl,
                prepared: try preparedExecutionRecord(from: prepared)
            )
            resolve(finalizedExecutionMap(finalized))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(finalizePreparedTransactionForSigner:signerHandle:prepared:resolver:rejecter:)
    func finalizePreparedTransactionForSigner(
        rpcUrl: String,
        signerHandle: String,
        prepared: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let finalized = try PrivacyPoolsSdkClient.finalizePreparedTransactionForSigner(
                rpcUrl: rpcUrl,
                signerHandle: signerHandle,
                prepared: try preparedExecutionRecord(from: prepared)
            )
            resolve(finalizedExecutionMap(finalized))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(submitPreparedTransaction:signerHandle:prepared:resolver:rejecter:)
    func submitPreparedTransaction(
        rpcUrl: String,
        signerHandle: String,
        prepared: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let submitted = try PrivacyPoolsSdkClient.submitPreparedTransaction(
                rpcUrl: rpcUrl,
                signerHandle: signerHandle,
                prepared: try preparedExecutionRecord(from: prepared)
            )
            resolve(submittedExecutionMap(submitted))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(submitSignedTransaction:finalized:signedTransaction:resolver:rejecter:)
    func submitSignedTransaction(
        rpcUrl: String,
        finalized: [String: Any],
        signedTransaction: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let submitted = try PrivacyPoolsSdkClient.submitSignedTransaction(
                rpcUrl: rpcUrl,
                finalized: try finalizedExecutionRecord(from: finalized),
                signedTransaction: signedTransaction
            )
            resolve(submittedExecutionMap(submitted))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(planWithdrawalTransaction:poolAddress:withdrawal:proof:resolver:rejecter:)
    func planWithdrawalTransaction(
        chainId: NSNumber,
        poolAddress: String,
        withdrawal: [String: Any],
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let plan = try PrivacyPoolsSdkClient.withdrawalTransactionPlan(
                chainId: chainId.uint64Value,
                poolAddress: poolAddress,
                withdrawal: try withdrawalRecord(from: withdrawal),
                proof: try proofBundleRecord(from: proof)
            )
            resolve(transactionPlanMap(plan))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(planRelayTransaction:entrypointAddress:withdrawal:proof:scope:resolver:rejecter:)
    func planRelayTransaction(
        chainId: NSNumber,
        entrypointAddress: String,
        withdrawal: [String: Any],
        proof: [String: Any],
        scope: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let plan = try PrivacyPoolsSdkClient.relayTransactionPlan(
                chainId: chainId.uint64Value,
                entrypointAddress: entrypointAddress,
                withdrawal: try withdrawalRecord(from: withdrawal),
                proof: try proofBundleRecord(from: proof),
                scope: scope
            )
            resolve(transactionPlanMap(plan))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(planRagequitTransaction:poolAddress:proof:resolver:rejecter:)
    func planRagequitTransaction(
        chainId: NSNumber,
        poolAddress: String,
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let plan = try PrivacyPoolsSdkClient.ragequitTransactionPlan(
                chainId: chainId.uint64Value,
                poolAddress: poolAddress,
                proof: try proofBundleRecord(from: proof)
            )
            resolve(transactionPlanMap(plan))
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

    @objc(isCurrentStateRoot:currentRoot:resolver:rejecter:)
    func isCurrentStateRoot(
        expectedRoot: String,
        currentRoot: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            resolve(try PrivacyPoolsSdkClient.isCurrentStateRoot(
                expectedRoot: expectedRoot,
                currentRoot: currentRoot
            ))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(formatGroth16ProofBundle:resolver:rejecter:)
    func formatGroth16ProofBundle(
        proof: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let formatted = try PrivacyPoolsSdkClient.formatGroth16Proof(
                proof: try proofBundleRecord(from: proof)
            )
            resolve(formattedGroth16ProofMap(formatted))
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
            let verification = try PrivacyPoolsSdkClient.verifyArtifactDescriptorBytes(
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

    @objc(getArtifactStatuses:artifactsRoot:circuit:resolver:rejecter:)
    func getArtifactStatuses(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let statuses = try PrivacyPoolsSdkClient.artifactStatuses(
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                circuit: circuit
            )
            resolve(statuses.map(artifactStatusMap))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(resolveVerifiedArtifactBundle:artifactsRoot:circuit:resolver:rejecter:)
    func resolveVerifiedArtifactBundle(
        manifestJson: String,
        artifactsRoot: String,
        circuit: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let bundle = try PrivacyPoolsSdkClient.resolvedArtifactBundle(
                manifestJson: manifestJson,
                artifactsRoot: artifactsRoot,
                circuit: circuit
            )
            resolve(resolvedArtifactBundleMap(bundle))
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    @objc(checkpointRecovery:policy:resolver:rejecter:)
    func checkpointRecovery(
        events: [[String: Any]],
        policy: [String: Any],
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock,
    ) {
        do {
            let ffiEvents = try events.map(poolEventRecord(from:))
            let ffiPolicy = try recoveryPolicyRecord(from: policy)
            let checkpoint = try PrivacyPoolsSdkClient.recoveryCheckpoint(
                events: ffiEvents,
                policy: ffiPolicy
            )
            resolve([
                "latest_block": NSNumber(value: checkpoint.latestBlock),
                "commitments_seen": NSNumber(value: checkpoint.commitmentsSeen),
            ])
        } catch {
            reject("ffi_error", error.localizedDescription, error)
        }
    }

    private func secretsMap(_ secrets: FfiSecrets) -> [String: String] {
        [
            "nullifier": secrets.nullifier,
            "secret": secrets.secret,
        ]
    }

    private func commitmentMap(_ commitment: FfiCommitment) -> [String: String] {
        [
            "hash": commitment.hash,
            "nullifier_hash": commitment.nullifierHash,
            "precommitment_hash": commitment.precommitmentHash,
            "value": commitment.value,
            "label": commitment.label,
            "nullifier": commitment.nullifier,
            "secret": commitment.secret,
        ]
    }

    private func commitmentRecord(from value: [String: Any]) throws -> FfiCommitment {
        guard
            let hash = value["hash"] as? String,
            let nullifierHash = value["nullifier_hash"] as? String,
            let precommitmentHash = value["precommitment_hash"] as? String,
            let amount = value["value"] as? String,
            let label = value["label"] as? String,
            let nullifier = value["nullifier"] as? String,
            let secret = value["secret"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid commitment payload"]
            )
        }

        return FfiCommitment(
            hash: hash,
            nullifierHash: nullifierHash,
            precommitmentHash: precommitmentHash,
            value: amount,
            label: label,
            nullifier: nullifier,
            secret: secret
        )
    }

    private func withdrawalRecord(from value: [String: Any]) throws -> FfiWithdrawal {
        guard let processooor = value["processooor"] as? String else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid withdrawal payload"]
            )
        }

        return FfiWithdrawal(
            processooor: processooor,
            data: try byteData(from: value["data"], field: "data")
        )
    }

    private func merkleProofMap(_ proof: FfiMerkleProof) -> [String: Any] {
        [
            "root": proof.root,
            "leaf": proof.leaf,
            "index": NSNumber(value: proof.index),
            "siblings": proof.siblings,
        ]
    }

    private func merkleProofRecord(from value: [String: Any]) throws -> FfiMerkleProof {
        guard
            let root = value["root"] as? String,
            let leaf = value["leaf"] as? String,
            let index = value["index"] as? NSNumber,
            let siblings = value["siblings"] as? [String]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid merkle proof payload"]
            )
        }

        return FfiMerkleProof(root: root, leaf: leaf, index: index.uint64Value, siblings: siblings)
    }

    private func circuitMerkleWitnessMap(_ witness: FfiCircuitMerkleWitness) -> [String: Any] {
        [
            "root": witness.root,
            "leaf": witness.leaf,
            "index": NSNumber(value: witness.index),
            "siblings": witness.siblings,
            "depth": NSNumber(value: witness.depth),
        ]
    }

    private func circuitMerkleWitnessRecord(from value: [String: Any]) throws -> FfiCircuitMerkleWitness {
        guard
            let root = value["root"] as? String,
            let leaf = value["leaf"] as? String,
            let index = value["index"] as? NSNumber,
            let siblings = value["siblings"] as? [String],
            let depth = value["depth"] as? NSNumber
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid merkle witness payload"]
            )
        }

        return FfiCircuitMerkleWitness(
            root: root,
            leaf: leaf,
            index: index.uint64Value,
            siblings: siblings,
            depth: depth.uint64Value
        )
    }

    private func withdrawalWitnessRequestRecord(
        from value: [String: Any]
    ) throws -> FfiWithdrawalWitnessRequest {
        guard
            let commitment = value["commitment"] as? [String: Any],
            let withdrawal = value["withdrawal"] as? [String: Any],
            let scope = value["scope"] as? String,
            let withdrawalAmount = value["withdrawal_amount"] as? String,
            let stateWitness = value["state_witness"] as? [String: Any],
            let aspWitness = value["asp_witness"] as? [String: Any],
            let newNullifier = value["new_nullifier"] as? String,
            let newSecret = value["new_secret"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid withdrawal witness payload"]
            )
        }

        return FfiWithdrawalWitnessRequest(
            commitment: try commitmentRecord(from: commitment),
            withdrawal: try withdrawalRecord(from: withdrawal),
            scope: scope,
            withdrawalAmount: withdrawalAmount,
            stateWitness: try circuitMerkleWitnessRecord(from: stateWitness),
            aspWitness: try circuitMerkleWitnessRecord(from: aspWitness),
            newNullifier: newNullifier,
            newSecret: newSecret
        )
    }

    private func commitmentWitnessRequestRecord(
        from value: [String: Any]
    ) throws -> FfiCommitmentWitnessRequest {
        guard let commitment = value["commitment"] as? [String: Any] else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid commitment witness payload"]
            )
        }

        return FfiCommitmentWitnessRequest(commitment: try commitmentRecord(from: commitment))
    }

    private func withdrawalCircuitInputMap(_ input: FfiWithdrawalCircuitInput) -> [String: Any] {
        [
            "withdrawn_value": input.withdrawnValue,
            "state_root": input.stateRoot,
            "state_tree_depth": NSNumber(value: input.stateTreeDepth),
            "asp_root": input.aspRoot,
            "asp_tree_depth": NSNumber(value: input.aspTreeDepth),
            "context": input.context,
            "label": input.label,
            "existing_value": input.existingValue,
            "existing_nullifier": input.existingNullifier,
            "existing_secret": input.existingSecret,
            "new_nullifier": input.newNullifier,
            "new_secret": input.newSecret,
            "state_siblings": input.stateSiblings,
            "state_index": NSNumber(value: input.stateIndex),
            "asp_siblings": input.aspSiblings,
            "asp_index": NSNumber(value: input.aspIndex),
        ]
    }

    private func commitmentCircuitInputMap(_ input: FfiCommitmentCircuitInput) -> [String: Any] {
        [
            "value": input.value,
            "label": input.label,
            "nullifier": input.nullifier,
            "secret": input.secret,
        ]
    }

    private func provingResultMap(_ result: FfiProvingResult) -> [String: Any] {
        [
            "backend": result.backend,
            "proof": proofBundleMap(result.proof),
        ]
    }

    private func asyncJobHandleMap(_ handle: FfiAsyncJobHandle) -> [String: Any] {
        [
            "job_id": handle.jobId,
            "kind": handle.kind,
        ]
    }

    private func withdrawalCircuitSessionHandleMap(
        _ handle: FfiWithdrawalCircuitSessionHandle
    ) -> [String: Any] {
        [
            "handle": handle.handle,
            "circuit": handle.circuit,
            "artifact_version": handle.artifactVersion,
        ]
    }

    private func commitmentCircuitSessionHandleMap(
        _ handle: FfiCommitmentCircuitSessionHandle
    ) -> [String: Any] {
        [
            "handle": handle.handle,
            "circuit": handle.circuit,
            "artifact_version": handle.artifactVersion,
        ]
    }

    private func asyncJobStatusMap(_ status: FfiAsyncJobStatus) -> [String: Any] {
        var map: [String: Any] = [
            "job_id": status.jobId,
            "kind": status.kind,
            "state": status.state,
            "cancel_requested": status.cancelRequested,
        ]
        if let stage = status.stage {
            map["stage"] = stage
        }
        if let error = status.error {
            map["error"] = error
        }
        return map
    }

    private func preparedExecutionMap(_ prepared: FfiPreparedTransactionExecution) -> [String: Any] {
        [
            "proving": provingResultMap(prepared.proving),
            "transaction": transactionPlanMap(prepared.transaction),
            "preflight": executionPreflightMap(prepared.preflight),
        ]
    }

    private func finalizedExecutionMap(_ finalized: FfiFinalizedTransactionExecution) -> [String: Any] {
        [
            "prepared": preparedExecutionMap(finalized.prepared),
            "request": finalizedRequestMap(finalized.request),
        ]
    }

    private func finalizedRequestMap(_ request: FfiFinalizedTransactionRequest) -> [String: Any] {
        var map: [String: Any] = [
            "kind": request.kind,
            "chain_id": NSNumber(value: request.chainId),
            "from": request.from,
            "to": request.to,
            "nonce": NSNumber(value: request.nonce),
            "gas_limit": NSNumber(value: request.gasLimit),
            "value": request.value,
            "data": request.data,
        ]
        if let gasPrice = request.gasPrice {
            map["gas_price"] = gasPrice
        }
        if let maxFeePerGas = request.maxFeePerGas {
            map["max_fee_per_gas"] = maxFeePerGas
        }
        if let maxPriorityFeePerGas = request.maxPriorityFeePerGas {
            map["max_priority_fee_per_gas"] = maxPriorityFeePerGas
        }
        return map
    }

    private func submittedExecutionMap(_ submitted: FfiSubmittedTransactionExecution) -> [String: Any] {
        [
            "prepared": preparedExecutionMap(submitted.prepared),
            "receipt": transactionReceiptMap(submitted.receipt),
        ]
    }

    private func signerHandleMap(_ handle: FfiSignerHandle) -> [String: Any] {
        [
            "handle": handle.handle,
            "address": handle.address,
            "kind": handle.kind,
        ]
    }

    private func transactionReceiptMap(_ receipt: FfiTransactionReceiptSummary) -> [String: Any] {
        var map: [String: Any] = [
            "transaction_hash": receipt.transactionHash,
            "success": receipt.success,
            "gas_used": NSNumber(value: receipt.gasUsed),
            "effective_gas_price": receipt.effectiveGasPrice,
            "from": receipt.from,
        ]
        if let blockHash = receipt.blockHash {
            map["block_hash"] = blockHash
        }
        if let blockNumber = receipt.blockNumber {
            map["block_number"] = NSNumber(value: blockNumber)
        }
        if let transactionIndex = receipt.transactionIndex {
            map["transaction_index"] = NSNumber(value: transactionIndex)
        }
        if let to = receipt.to {
            map["to"] = to
        }
        return map
    }

    private func executionPreflightMap(_ report: FfiExecutionPreflightReport) -> [String: Any] {
        [
            "kind": report.kind,
            "caller": report.caller,
            "target": report.target,
            "expected_chain_id": NSNumber(value: report.expectedChainId),
            "actual_chain_id": NSNumber(value: report.actualChainId),
            "chain_id_matches": report.chainIdMatches,
            "simulated": report.simulated,
            "estimated_gas": NSNumber(value: report.estimatedGas),
            "code_hash_checks": report.codeHashChecks.map(codeHashCheckMap),
            "root_checks": report.rootChecks.map(rootCheckMap),
        ]
    }

    private func codeHashCheckMap(_ check: FfiCodeHashCheck) -> [String: Any] {
        var map: [String: Any] = [
            "address": check.address,
            "actual_code_hash": check.actualCodeHash,
        ]
        if let expected = check.expectedCodeHash {
            map["expected_code_hash"] = expected
        }
        if let matchesExpected = check.matchesExpected {
            map["matches_expected"] = matchesExpected
        }
        return map
    }

    private func rootCheckMap(_ check: FfiRootCheck) -> [String: Any] {
        [
            "kind": check.kind,
            "contract_address": check.contractAddress,
            "pool_address": check.poolAddress,
            "expected_root": check.expectedRoot,
            "actual_root": check.actualRoot,
            "matches": check.matches,
        ]
    }

    private func formattedGroth16ProofMap(_ proof: FfiFormattedGroth16Proof) -> [String: Any] {
        [
            "p_a": proof.pA,
            "p_b": proof.pB,
            "p_c": proof.pC,
            "pub_signals": proof.pubSignals,
        ]
    }

    private func proofBundleMap(_ bundle: FfiProofBundle) -> [String: Any] {
        [
            "proof": snarkJsProofMap(bundle.proof),
            "public_signals": bundle.publicSignals,
        ]
    }

    private func transactionPlanMap(_ plan: FfiTransactionPlan) -> [String: Any] {
        [
            "kind": plan.kind,
            "chain_id": NSNumber(value: plan.chainId),
            "target": plan.target,
            "calldata": plan.calldata,
            "value": plan.value,
            "proof": formattedGroth16ProofMap(plan.proof),
        ]
    }

    private func transactionPlanRecord(from value: [String: Any]) throws -> FfiTransactionPlan {
        guard
            let kind = value["kind"] as? String,
            let chainId = value["chain_id"] as? NSNumber,
            let target = value["target"] as? String,
            let calldata = value["calldata"] as? String,
            let valueString = value["value"] as? String,
            let proof = value["proof"] as? [String: Any]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid transaction plan payload"]
            )
        }

        return FfiTransactionPlan(
            kind: kind,
            chainId: chainId.uint64Value,
            target: target,
            calldata: calldata,
            value: valueString,
            proof: try formattedGroth16ProofRecord(from: proof)
        )
    }

    private func formattedGroth16ProofRecord(
        from value: [String: Any]
    ) throws -> FfiFormattedGroth16Proof {
        FfiFormattedGroth16Proof(
            pA: try stringArray(from: value["p_a"], field: "p_a"),
            pB: try stringMatrix(from: value["p_b"], field: "p_b"),
            pC: try stringArray(from: value["p_c"], field: "p_c"),
            pubSignals: try stringArray(from: value["pub_signals"], field: "pub_signals")
        )
    }

    private func proofBundleRecord(from value: [String: Any]) throws -> FfiProofBundle {
        guard let proof = value["proof"] as? [String: Any] else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid proof bundle payload"]
            )
        }

        return FfiProofBundle(
            proof: try snarkJsProofRecord(from: proof),
            publicSignals: try stringArray(from: value["public_signals"], field: "public_signals")
        )
    }

    private func preparedExecutionRecord(
        from value: [String: Any]
    ) throws -> FfiPreparedTransactionExecution {
        guard
            let proving = value["proving"] as? [String: Any],
            let transaction = value["transaction"] as? [String: Any],
            let preflight = value["preflight"] as? [String: Any]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid prepared execution payload"]
            )
        }

        return FfiPreparedTransactionExecution(
            proving: try provingResultRecord(from: proving),
            transaction: try transactionPlanRecord(from: transaction),
            preflight: try executionPreflightRecord(from: preflight)
        )
    }

    private func finalizedExecutionRecord(
        from value: [String: Any]
    ) throws -> FfiFinalizedTransactionExecution {
        guard
            let prepared = value["prepared"] as? [String: Any],
            let request = value["request"] as? [String: Any]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid finalized execution payload"]
            )
        }

        return FfiFinalizedTransactionExecution(
            prepared: try preparedExecutionRecord(from: prepared),
            request: try finalizedRequestRecord(from: request)
        )
    }

    private func finalizedRequestRecord(
        from value: [String: Any]
    ) throws -> FfiFinalizedTransactionRequest {
        guard
            let kind = value["kind"] as? String,
            let chainId = value["chain_id"] as? NSNumber,
            let from = value["from"] as? String,
            let to = value["to"] as? String,
            let nonce = value["nonce"] as? NSNumber,
            let gasLimit = value["gas_limit"] as? NSNumber,
            let valueString = value["value"] as? String,
            let data = value["data"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid finalized request payload"]
            )
        }

        return FfiFinalizedTransactionRequest(
            kind: kind,
            chainId: chainId.uint64Value,
            from: from,
            to: to,
            nonce: nonce.uint64Value,
            gasLimit: gasLimit.uint64Value,
            value: valueString,
            data: data,
            gasPrice: value["gas_price"] as? String,
            maxFeePerGas: value["max_fee_per_gas"] as? String,
            maxPriorityFeePerGas: value["max_priority_fee_per_gas"] as? String
        )
    }

    private func provingResultRecord(from value: [String: Any]) throws -> FfiProvingResult {
        guard
            let backend = value["backend"] as? String,
            let proof = value["proof"] as? [String: Any]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid proving result payload"]
            )
        }

        return FfiProvingResult(
            backend: backend,
            proof: try proofBundleRecord(from: proof)
        )
    }

    private func executionPreflightRecord(
        from value: [String: Any]
    ) throws -> FfiExecutionPreflightReport {
        guard
            let kind = value["kind"] as? String,
            let caller = value["caller"] as? String,
            let target = value["target"] as? String,
            let expectedChainId = value["expected_chain_id"] as? NSNumber,
            let actualChainId = value["actual_chain_id"] as? NSNumber,
            let chainIdMatches = value["chain_id_matches"] as? Bool,
            let simulated = value["simulated"] as? Bool,
            let estimatedGas = value["estimated_gas"] as? NSNumber,
            let codeHashChecks = value["code_hash_checks"] as? [[String: Any]],
            let rootChecks = value["root_checks"] as? [[String: Any]]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid preflight payload"]
            )
        }

        return FfiExecutionPreflightReport(
            kind: kind,
            caller: caller,
            target: target,
            expectedChainId: expectedChainId.uint64Value,
            actualChainId: actualChainId.uint64Value,
            chainIdMatches: chainIdMatches,
            simulated: simulated,
            estimatedGas: estimatedGas.uint64Value,
            codeHashChecks: try codeHashChecks.map(codeHashCheckRecord),
            rootChecks: try rootChecks.map(rootCheckRecord)
        )
    }

    private func codeHashCheckRecord(from value: [String: Any]) throws -> FfiCodeHashCheck {
        guard
            let address = value["address"] as? String,
            let actualCodeHash = value["actual_code_hash"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid code hash check payload"]
            )
        }

        return FfiCodeHashCheck(
            address: address,
            expectedCodeHash: value["expected_code_hash"] as? String,
            actualCodeHash: actualCodeHash,
            matchesExpected: value["matches_expected"] as? Bool
        )
    }

    private func rootCheckRecord(from value: [String: Any]) throws -> FfiRootCheck {
        guard
            let kind = value["kind"] as? String,
            let contractAddress = value["contract_address"] as? String,
            let poolAddress = value["pool_address"] as? String,
            let expectedRoot = value["expected_root"] as? String,
            let actualRoot = value["actual_root"] as? String,
            let matches = value["matches"] as? Bool
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid root check payload"]
            )
        }

        return FfiRootCheck(
            kind: kind,
            contractAddress: contractAddress,
            poolAddress: poolAddress,
            expectedRoot: expectedRoot,
            actualRoot: actualRoot,
            matches: matches
        )
    }

    private func snarkJsProofMap(_ proof: FfiSnarkJsProof) -> [String: Any] {
        [
            "pi_a": proof.piA,
            "pi_b": proof.piB,
            "pi_c": proof.piC,
            "protocol": proof.protocol,
            "curve": proof.curve,
        ]
    }

    private func snarkJsProofRecord(from value: [String: Any]) throws -> FfiSnarkJsProof {
        guard
            let protocolName = value["protocol"] as? String,
            let curve = value["curve"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid proof payload"]
            )
        }

        return FfiSnarkJsProof(
            piA: try stringArray(from: value["pi_a"], field: "pi_a"),
            piB: try stringMatrix(from: value["pi_b"], field: "pi_b"),
            piC: try stringArray(from: value["pi_c"], field: "pi_c"),
            protocol: protocolName,
            curve: curve
        )
    }

    private func artifactStatusMap(_ status: FfiArtifactStatus) -> [String: Any] {
        [
            "version": status.version,
            "circuit": status.circuit,
            "kind": status.kind,
            "filename": status.filename,
            "path": status.path,
            "exists": status.exists,
            "verified": status.verified,
        ]
    }

    private func resolvedArtifactBundleMap(_ bundle: FfiResolvedArtifactBundle) -> [String: Any] {
        [
            "version": bundle.version,
            "circuit": bundle.circuit,
            "artifacts": bundle.artifacts.map(resolvedArtifactMap),
        ]
    }

    private func resolvedArtifactMap(_ artifact: FfiResolvedArtifact) -> [String: String] {
        [
            "circuit": artifact.circuit,
            "kind": artifact.kind,
            "filename": artifact.filename,
            "path": artifact.path,
        ]
    }

    private func artifactBytesRecord(from value: [String: Any]) throws -> FfiArtifactBytes {
        guard
            let kind = value["kind"] as? String,
            let bytes = value["bytes"] as? [NSNumber]
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid artifact bytes payload"]
            )
        }

        return FfiArtifactBytes(
            kind: kind,
            bytes: bytes.map(\.uint8Value)
        )
    }

    private func poolEventRecord(from value: [String: Any]) throws -> FfiPoolEvent {
        guard
            let blockNumber = value["block_number"] as? NSNumber,
            let transactionIndex = value["transaction_index"] as? NSNumber,
            let logIndex = value["log_index"] as? NSNumber,
            let poolAddress = value["pool_address"] as? String,
            let commitmentHash = value["commitment_hash"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid recovery event payload"]
            )
        }

        return FfiPoolEvent(
            blockNumber: blockNumber.uint64Value,
            transactionIndex: transactionIndex.uint64Value,
            logIndex: logIndex.uint64Value,
            poolAddress: poolAddress,
            commitmentHash: commitmentHash
        )
    }

    private func recoveryPolicyRecord(from value: [String: Any]) throws -> FfiRecoveryPolicy {
        guard
            let compatibilityMode = value["compatibility_mode"] as? String,
            let failClosed = value["fail_closed"] as? Bool
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid recovery policy payload"]
            )
        }

        return FfiRecoveryPolicy(
            compatibilityMode: compatibilityMode,
            failClosed: failClosed
        )
    }

    private func executionPolicyRecord(from value: [String: Any]) throws -> FfiExecutionPolicy {
        guard
            let expectedChainId = value["expected_chain_id"] as? NSNumber,
            let caller = value["caller"] as? String
        else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid execution policy payload"]
            )
        }

        return FfiExecutionPolicy(
            expectedChainId: expectedChainId.uint64Value,
            caller: caller,
            expectedPoolCodeHash: value["expected_pool_code_hash"] as? String,
            expectedEntrypointCodeHash: value["expected_entrypoint_code_hash"] as? String,
            mode: value["mode"] as? String
        )
    }

    private func stringArray(from value: Any?, field: String) throws -> [String] {
        guard let values = value as? [String] else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid \(field) payload"]
            )
        }

        return values
    }

    private func stringMatrix(from value: Any?, field: String) throws -> [[String]] {
        guard let values = value as? [[String]] else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid \(field) payload"]
            )
        }

        return values
    }

    private func byteData(from value: Any?, field: String) throws -> Data {
        guard let values = value as? [NSNumber] else {
            throw NSError(
                domain: "PrivacyPoolsSdk",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "invalid \(field) payload"]
            )
        }

        return Data(values.map(\.uint8Value))
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
