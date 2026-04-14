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

    private func rootReadMap(_ read: FfiRootRead) -> [String: String] {
        [
            "kind": read.kind,
            "contract_address": read.contractAddress,
            "pool_address": read.poolAddress,
            "call_data": read.callData,
        ]
    }
}
