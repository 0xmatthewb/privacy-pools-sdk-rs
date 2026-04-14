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

    private func provingResultMap(_ result: FfiProvingResult) -> [String: Any] {
        [
            "backend": result.backend,
            "proof": proofBundleMap(result.proof),
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
