import Foundation
import PrivacyPoolsSdk
import XCTest

private let reportMarker = "PRIVACY_POOLS_IOS_NATIVE_REPORT="
private let smokeReadConsistency = "finalized"
private let smokeMaxFeeQuoteWei = "2000000000"

final class PrivacyPoolsSdkSmokeTests: XCTestCase {
    func testNativeMobileParitySurface() throws {
        let fixturesRoot = try copyFixturesToAppStorage()
        let artifactsRoot = fixturesRoot.appendingPathComponent("artifacts").path
        let crypto = try readJSONObject("vectors/crypto-compatibility.json")
        let withdrawalFixture = try readJSONObject("vectors/withdrawal-circuit-input.json")
        let withdrawalManifest = try readText("artifacts/withdrawal-proving-manifest.json")
        let commitmentManifest = try readText("artifacts/commitment-proving-manifest.json")
        let signedManifestPayload = try readText("artifacts/signed-manifest/payload.json")
        let signedManifestSignature = try readText("artifacts/signed-manifest/signature")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let signedManifestPublicKey = try readText("artifacts/signed-manifest/public-key.hex")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let goldens = try readJSONObject("vectors/assurance-goldens.json")
        let auditCases = try readJSONObject("vectors/audit-parity-cases.json")
        let executionFixture = try readJSONObject("vectors/mobile-execution-fixture.json")
        var smoke = defaultSmoke()
        var parity = defaultParity()

        do {
            try runSmokeFlow(
                smoke: &smoke,
                artifactsRoot: artifactsRoot,
                crypto: crypto,
                withdrawalFixture: withdrawalFixture,
                withdrawalManifest: withdrawalManifest,
                commitmentManifest: commitmentManifest,
                signedManifestPayload: signedManifestPayload,
                signedManifestSignature: signedManifestSignature,
                signedManifestPublicKey: signedManifestPublicKey,
                executionFixture: executionFixture
            )
            parity = try runParityChecks(goldens: goldens, auditCases: auditCases)
            if failedCount(parity) > 0 {
                throw NSError(
                    domain: "PrivacyPoolsSdkSmoke",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "native parity checks failed"]
                )
            }
        } catch {
            if totalChecks(parity) == 0 {
                parity = failureParity("native smoke failed: \(error.localizedDescription)")
            } else {
                parity = appendParityFailure(parity, failure: "native smoke failed: \(error.localizedDescription)")
            }
            printReport(smoke: smoke, parity: parity)
            throw error
        }

        printReport(smoke: smoke, parity: parity)
    }

    private func runSmokeFlow(
        smoke: inout [String: Any],
        artifactsRoot: String,
        crypto: [String: Any],
        withdrawalFixture: [String: Any],
        withdrawalManifest: String,
        commitmentManifest: String,
        signedManifestPayload: String,
        signedManifestSignature: String,
        signedManifestPublicKey: String,
        executionFixture: [String: Any]
    ) throws {
        let backend = try PrivacyPoolsSdkClient.stableBackendName()
        smoke["backend"] = backend
        XCTAssertEqual(backend.lowercased(), "arkworks")

        let depositSecrets = try dictionary(crypto, "depositSecrets")
        let commitment = try PrivacyPoolsSdkClient.commitment(
            value: try string(withdrawalFixture, "existingValue"),
            label: try string(withdrawalFixture, "label"),
            nullifier: try string(depositSecrets, "nullifier"),
            secret: try string(depositSecrets, "secret")
        )

        let commitmentSession = try PrivacyPoolsSdkClient.prepareCommitmentCircuitSession(
            manifestJson: commitmentManifest,
            artifactsRoot: artifactsRoot
        )
        let commitmentProof = try PrivacyPoolsSdkClient.commitmentProof(
            backendProfile: "stable",
            sessionHandle: commitmentSession.handle,
            request: FfiCommitmentWitnessRequest(commitment: commitment)
        )
        if try PrivacyPoolsSdkClient.verifyCommitment(
            backendProfile: "stable",
            sessionHandle: commitmentSession.handle,
            proof: commitmentProof.proof
        ) {
            smoke["commitmentVerified"] = true
        }
        var tamperedCommitmentProof = commitmentProof.proof
        tamperedCommitmentProof.publicSignals[0] = "9"
        smoke["tamperedProofRejected"] = rejectsOrFalse {
            return try PrivacyPoolsSdkClient.verifyCommitment(
                backendProfile: "stable",
                sessionHandle: commitmentSession.handle,
                proof: tamperedCommitmentProof
            )
        }
        _ = try PrivacyPoolsSdkClient.removeCommitmentCircuitSession(handle: commitmentSession.handle)
        smoke["staleCommitmentSessionRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifyCommitment(
                backendProfile: "stable",
                sessionHandle: commitmentSession.handle,
                proof: commitmentProof.proof
            )
        }

        let withdrawalRequest = try buildWithdrawalRequest(
            commitment: commitment,
            crypto: crypto,
            fixture: withdrawalFixture,
            processooor: try string(executionFixture, "entrypointAddress")
        )
        let withdrawalSession = try PrivacyPoolsSdkClient.prepareWithdrawalCircuitSession(
            manifestJson: withdrawalManifest,
            artifactsRoot: artifactsRoot
        )
        let withdrawalProof = try PrivacyPoolsSdkClient.withdrawalProof(
            backendProfile: "stable",
            sessionHandle: withdrawalSession.handle,
            request: withdrawalRequest
        )
        if try PrivacyPoolsSdkClient.verifyWithdrawal(
            backendProfile: "stable",
            sessionHandle: withdrawalSession.handle,
            proof: withdrawalProof.proof
        ) {
            smoke["withdrawalVerified"] = true
        }
        _ = try PrivacyPoolsSdkClient.removeWithdrawalCircuitSession(handle: withdrawalSession.handle)
        smoke["staleWithdrawalSessionRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifyWithdrawal(
                backendProfile: "stable",
                sessionHandle: withdrawalSession.handle,
                proof: withdrawalProof.proof
            )
        }

        _ = try PrivacyPoolsSdkClient.verifySignedManifestPayload(
            payloadJson: signedManifestPayload,
            signatureHex: signedManifestSignature,
            publicKeyHex: signedManifestPublicKey
        )
        smoke["signedManifestVerified"] = true
        smoke["wrongSignedManifestPublicKeyRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifySignedManifestPayload(
                payloadJson: signedManifestPayload,
                signatureHex: signedManifestSignature,
                publicKeyHex: mutateHex(signedManifestPublicKey)
            )
        }
        smoke["tamperedSignedManifestArtifactsRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifySignedManifestArtifactBytes(
                payloadJson: signedManifestPayload,
                signatureHex: signedManifestSignature,
                publicKeyHex: signedManifestPublicKey,
                artifacts: [FfiSignedManifestArtifactBytes(
                    filename: "withdraw-fixture.wasm",
                    bytes: Data([1, 2, 3])
                )]
            )
        }

        let masterKeysHandle = try PrivacyPoolsSdkClient.masterKeysHandle(
            forMnemonicBytes: Data(try string(crypto, "mnemonic").utf8)
        )
        let commitmentHandle = try PrivacyPoolsSdkClient.commitmentFromHandles(
            value: try string(withdrawalFixture, "existingValue"),
            label: try string(withdrawalFixture, "label"),
            secretsHandle: try PrivacyPoolsSdkClient.depositSecretsHandle(
                masterKeysHandle: masterKeysHandle,
                scope: try string(crypto, "scope"),
                index: "0"
            )
        )
        let verifiedCommitmentHandle = try PrivacyPoolsSdkClient.proveAndVerifyCommitmentHandle(
            backendProfile: "stable",
            manifestJson: commitmentManifest,
            artifactsRoot: artifactsRoot,
            requestHandle: commitmentHandle
        )
        smoke["handleKindMismatchRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifiedWithdrawalTransactionPlan(
                chainId: UInt64(try integer(executionFixture, "expectedChainId")),
                poolAddress: try string(executionFixture, "poolAddress"),
                proofHandle: verifiedCommitmentHandle
            )
        }
        _ = try PrivacyPoolsSdkClient.removeVerifiedProofHandle(handle: verifiedCommitmentHandle)
        smoke["staleVerifiedProofHandleRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.verifiedRagequitTransactionPlan(
                chainId: UInt64(try integer(executionFixture, "expectedChainId")),
                poolAddress: try string(executionFixture, "poolAddress"),
                proofHandle: verifiedCommitmentHandle
            )
        }

        let prepared = try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
            backendProfile: "stable",
            manifestJson: withdrawalManifest,
            artifactsRoot: artifactsRoot,
            request: withdrawalRequest,
            chainId: UInt64(try integer(executionFixture, "expectedChainId")),
            poolAddress: try string(executionFixture, "poolAddress"),
            rpcUrl: try string(executionFixture, "validRpcUrl"),
            policy: executionPolicy(executionFixture)
        )
        guard prepared.preflight.readConsistency == smokeReadConsistency else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "execution policy read_consistency did not round-trip"]
            )
        }
        guard prepared.preflight.maxFeeQuoteWei == smokeMaxFeeQuoteWei else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 5,
                userInfo: [NSLocalizedDescriptionKey: "execution policy max_fee_quote_wei did not round-trip"]
            )
        }
        let nullablePrepared = try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
            backendProfile: "stable",
            manifestJson: withdrawalManifest,
            artifactsRoot: artifactsRoot,
            request: withdrawalRequest,
            chainId: UInt64(try integer(executionFixture, "expectedChainId")),
            poolAddress: try string(executionFixture, "poolAddress"),
            rpcUrl: try string(executionFixture, "validRpcUrl"),
            policy: FfiExecutionPolicy(
                expectedChainId: UInt64(try integer(executionFixture, "expectedChainId")),
                caller: try string(executionFixture, "caller"),
                expectedPoolCodeHash: try string(executionFixture, "expectedPoolCodeHash"),
                expectedEntrypointCodeHash: try string(executionFixture, "expectedEntrypointCodeHash"),
                readConsistency: nil,
                maxFeeQuoteWei: nil,
                mode: "strict"
            )
        )
        guard nullablePrepared.preflight.readConsistency == nil else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 6,
                userInfo: [NSLocalizedDescriptionKey: "null read_consistency did not round-trip"]
            )
        }
        guard nullablePrepared.preflight.maxFeeQuoteWei == nil else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 7,
                userInfo: [NSLocalizedDescriptionKey: "null max_fee_quote_wei did not round-trip"]
            )
        }
        let signerHandle = "host-signer-collision"
        _ = try PrivacyPoolsSdkClient.registerHostProvidedSigner(
            handle: signerHandle,
            address: try string(executionFixture, "caller")
        )
        let handleCollisionRejected: Bool
        do {
            _ = try PrivacyPoolsSdkClient.registerHostProvidedSigner(
                handle: signerHandle,
                address: try string(executionFixture, "caller")
            )
            handleCollisionRejected = false
        } catch let error as FfiError {
            if case .HandleAlreadyRegistered = error {
                handleCollisionRejected = true
            } else {
                throw error
            }
        }
        _ = try PrivacyPoolsSdkClient.unregisterSigner(handle: signerHandle)
        guard handleCollisionRejected else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 8,
                userInfo: [NSLocalizedDescriptionKey: "duplicate signer handles must fail closed"]
            )
        }
        let finalized = try PrivacyPoolsSdkClient.finalizePreparedTransaction(
            rpcUrl: try string(executionFixture, "validRpcUrl"),
            prepared: prepared
        )
        let signedTransaction = try signRequest(
            urlString: try string(executionFixture, "signerUrl"),
            request: finalized.request
        )
        let submitted = try PrivacyPoolsSdkClient.submitSignedTransaction(
            rpcUrl: try string(executionFixture, "validRpcUrl"),
            finalized: finalized,
            signedTransaction: signedTransaction
        )
        smoke["executionSubmitted"] = !submitted.receipt.transactionHash.isEmpty

        smoke["wrongChainIdRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
                backendProfile: "stable",
                manifestJson: withdrawalManifest,
                artifactsRoot: artifactsRoot,
                request: withdrawalRequest,
                chainId: UInt64(try integer(executionFixture, "expectedChainId") + 1),
                poolAddress: try string(executionFixture, "poolAddress"),
                rpcUrl: try string(executionFixture, "validRpcUrl"),
                policy: executionPolicy(executionFixture)
            )
        }
        smoke["wrongCodeHashRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
                backendProfile: "stable",
                manifestJson: withdrawalManifest,
                artifactsRoot: artifactsRoot,
                request: withdrawalRequest,
                chainId: UInt64(try integer(executionFixture, "expectedChainId")),
                poolAddress: try string(executionFixture, "poolAddress"),
                rpcUrl: try string(executionFixture, "validRpcUrl"),
                policy: FfiExecutionPolicy(
                    expectedChainId: UInt64(try integer(executionFixture, "expectedChainId")),
                    caller: try string(executionFixture, "caller"),
                    expectedPoolCodeHash: mutateHex(try string(executionFixture, "expectedPoolCodeHash")),
                    expectedEntrypointCodeHash: try string(executionFixture, "expectedEntrypointCodeHash"),
                    readConsistency: smokeReadConsistency,
                    maxFeeQuoteWei: smokeMaxFeeQuoteWei,
                    mode: "strict"
                )
            )
        }
        smoke["wrongRootRejected"] = failsClosed {
            return try PrivacyPoolsSdkClient.prepareWithdrawalExecution(
                backendProfile: "stable",
                manifestJson: withdrawalManifest,
                artifactsRoot: artifactsRoot,
                request: withdrawalRequest,
                chainId: UInt64(try integer(executionFixture, "expectedChainId")),
                poolAddress: try string(executionFixture, "poolAddress"),
                rpcUrl: try string(executionFixture, "wrongRootRpcUrl"),
                policy: executionPolicy(executionFixture)
            )
        }
        smoke["wrongSignerRejected"] = failsClosed {
            let wrongSigned = try signRequest(
                urlString: try string(executionFixture, "wrongSignerUrl"),
                request: finalized.request
            )
            return try PrivacyPoolsSdkClient.submitSignedTransaction(
                rpcUrl: try string(executionFixture, "validRpcUrl"),
                finalized: finalized,
                signedTransaction: wrongSigned
            )
        }

        for key in [
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
        ] {
            guard smoke[key] as? Bool == true else {
                throw NSError(
                    domain: "PrivacyPoolsSdkSmoke",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "\(key) did not pass"]
                )
            }
        }
    }

    private func runParityChecks(
        goldens: [String: Any],
        auditCases: [String: Any]
    ) throws -> [String: Any] {
        var checks: [(String, Bool)] = []
        let goldenCases = try array(goldens, "cases")
        let goldenMerkleCases = try array(goldens, "merkleCases")
        let comparisonCases = try array(auditCases, "comparisonCases")
        let merkleCases = try array(auditCases, "merkleCases")

        for comparisonCase in comparisonCases {
            let fixture = try unwrapObject(comparisonCase)
            let fixtureName = try string(fixture, "name")
            guard let expected = goldenCases
                .compactMap({ try? unwrapObject($0) })
                .first(where: { (try? string($0, "name")) == fixtureName }) else {
                checks.append(("\(fixtureName): fixture", false))
                continue
            }

            let masterKeysHandle = try PrivacyPoolsSdkClient.masterKeysHandle(
                forMnemonicBytes: Data(try string(fixture, "mnemonic").utf8)
            )
            checks.append(("\(fixtureName): masterKeysHandle", !masterKeysHandle.isEmpty))

            let depositSecretsHandle = try PrivacyPoolsSdkClient.depositSecretsHandle(
                masterKeysHandle: masterKeysHandle,
                scope: try string(fixture, "scope"),
                index: try string(fixture, "depositIndex")
            )
            checks.append(("\(fixtureName): depositSecretsHandle", !depositSecretsHandle.isEmpty))

            let withdrawalSecretsHandle = try PrivacyPoolsSdkClient.withdrawalSecretsHandle(
                masterKeysHandle: masterKeysHandle,
                label: try string(fixture, "label"),
                index: try string(fixture, "withdrawalIndex")
            )
            checks.append(("\(fixtureName): withdrawalSecretsHandle", !withdrawalSecretsHandle.isEmpty))

            let expectedDepositSecrets = try dictionary(expected, "depositSecrets")

            let commitment = try PrivacyPoolsSdkClient.commitment(
                value: try string(fixture, "value"),
                label: try string(fixture, "label"),
                nullifier: try string(expectedDepositSecrets, "nullifier"),
                secret: try string(expectedDepositSecrets, "secret")
            )
            let expectedPrecommitmentHash = try string(expected, "precommitmentHash")
            checks.append(("\(fixtureName): precommitmentHash", commitment.precommitmentHash == expectedPrecommitmentHash))
            checks.append(("\(fixtureName): commitment", dictionariesEqual([
                "hash": commitment.hash,
                "nullifierHash": commitment.nullifierHash,
                "precommitmentHash": commitment.precommitmentHash,
                "value": commitment.value,
                "label": commitment.label,
                "nullifier": commitment.nullifier,
                "secret": commitment.secret,
            ], try dictionary(expected, "commitment"))))

            let withdrawal = try dictionary(fixture, "withdrawal")
            let withdrawalContext = try PrivacyPoolsSdkClient.withdrawalContext(
                withdrawal: FfiWithdrawal(
                    processooor: try string(withdrawal, "processooor"),
                    data: hexToData(try string(withdrawal, "data"))
                ),
                scope: try string(fixture, "scope")
            )
            let expectedWithdrawalContext = try string(expected, "withdrawalContextHex")
            checks.append(("\(fixtureName): withdrawalContextHex", withdrawalContext == expectedWithdrawalContext))
        }

        for merkleCaseValue in merkleCases {
            let fixture = try unwrapObject(merkleCaseValue)
            let fixtureName = try string(fixture, "name")
            guard let expected = goldenMerkleCases
                .compactMap({ try? unwrapObject($0) })
                .first(where: { (try? string($0, "name")) == fixtureName }) else {
                checks.append(("\(fixtureName): merkleFixture", false))
                continue
            }
            let proof = try PrivacyPoolsSdkClient.merkleProof(
                leaves: try stringArray(fixture, "leaves"),
                leaf: try string(fixture, "leaf")
            )
            checks.append(("\(fixtureName): merkleProof", dictionariesEqual([
                "root": proof.root,
                "leaf": proof.leaf,
                "index": Int(proof.index),
                "siblings": proof.siblings,
            ], try dictionary(expected, "proof"))))
        }

        let failedChecks = checks.filter { !$0.1 }.map(\.0)
        return [
            "totalChecks": checks.count,
            "passed": checks.count - failedChecks.count,
            "failed": failedChecks.count,
            "failedChecks": failedChecks,
        ]
    }

    private func copyFixturesToAppStorage() throws -> URL {
        let source = try XCTUnwrap(Bundle.module.resourceURL)
            .appendingPathComponent("Fixtures", isDirectory: true)
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("privacy-pools-sdk-fixtures", isDirectory: true)
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.copyItem(at: source, to: destination)
        return destination
    }

    private func printReport(smoke: [String: Any], parity: [String: Any]) {
        let report: [String: Any] = [
            "generatedAt": ISO8601DateFormatter().string(from: Date()),
            "runtime": "native",
            "platform": "ios",
            "surface": "native",
            "smoke": smoke,
            "parity": parity,
            "benchmark": defaultBenchmark(),
        ]
        let data = try! JSONSerialization.data(withJSONObject: report)
        print("\(reportMarker)\(String(decoding: data, as: UTF8.self))")
    }

    private func defaultSmoke() -> [String: Any] {
        [
            "backend": "unknown",
            "commitmentVerified": false,
            "withdrawalVerified": false,
            "executionSubmitted": false,
            "signedManifestVerified": false,
            "wrongSignedManifestPublicKeyRejected": false,
            "tamperedSignedManifestArtifactsRejected": false,
            "tamperedProofRejected": false,
            "handleKindMismatchRejected": false,
            "staleVerifiedProofHandleRejected": false,
            "staleCommitmentSessionRejected": false,
            "staleWithdrawalSessionRejected": false,
            "wrongRootRejected": false,
            "wrongChainIdRejected": false,
            "wrongCodeHashRejected": false,
            "wrongSignerRejected": false,
        ]
    }

    private func defaultParity() -> [String: Any] {
        ["totalChecks": 0, "passed": 0, "failed": 0, "failedChecks": []]
    }

    private func failureParity(_ failure: String) -> [String: Any] {
        ["totalChecks": 1, "passed": 0, "failed": 1, "failedChecks": [failure]]
    }

    private func appendParityFailure(_ parity: [String: Any], failure: String) -> [String: Any] {
        var failedChecks = (parity["failedChecks"] as? [String]) ?? []
        failedChecks.append(failure)
        return [
            "totalChecks": totalChecks(parity),
            "passed": max(0, totalChecks(parity) - failedChecks.count),
            "failed": failedChecks.count,
            "failedChecks": failedChecks,
        ]
    }

    private func totalChecks(_ parity: [String: Any]) -> Int {
        parity["totalChecks"] as? Int ?? 0
    }

    private func failedCount(_ parity: [String: Any]) -> Int {
        parity["failed"] as? Int ?? 0
    }

    private func defaultBenchmark() -> [String: Any] {
        [
            "artifactResolutionMs": 0.0,
            "bundleVerificationMs": 0.0,
            "sessionPreloadMs": 0.0,
            "firstInputPreparationMs": 0.0,
            "firstWitnessGenerationMs": 0.0,
            "firstProofGenerationMs": 0.0,
            "firstVerificationMs": 0.0,
            "firstProveAndVerifyMs": 0.0,
            "iterations": 1,
            "warmup": 0,
            "peakResidentMemoryBytes": NSNull(),
            "samples": [[
                "inputPreparationMs": 0.0,
                "witnessGenerationMs": 0.0,
                "proofGenerationMs": 0.0,
                "verificationMs": 0.0,
                "proveAndVerifyMs": 0.0,
            ]],
        ]
    }

    private func executionPolicy(_ fixture: [String: Any]) throws -> FfiExecutionPolicy {
        FfiExecutionPolicy(
            expectedChainId: UInt64(try integer(fixture, "expectedChainId")),
            caller: try string(fixture, "caller"),
            expectedPoolCodeHash: try string(fixture, "expectedPoolCodeHash"),
            expectedEntrypointCodeHash: try string(fixture, "expectedEntrypointCodeHash"),
            readConsistency: smokeReadConsistency,
            maxFeeQuoteWei: smokeMaxFeeQuoteWei,
            mode: "strict"
        )
    }

    private func buildWithdrawalRequest(
        commitment: FfiCommitment,
        crypto: [String: Any],
        fixture: [String: Any],
        processooor: String
    ) throws -> FfiWithdrawalWitnessRequest {
        FfiWithdrawalWitnessRequest(
            commitment: commitment,
            withdrawal: FfiWithdrawal(
                processooor: processooor,
                data: Data([0x12, 0x34])
            ),
            scope: try string(crypto, "scope"),
            withdrawalAmount: try string(fixture, "withdrawalAmount"),
            stateWitness: try circuitWitness(try dictionary(fixture, "stateWitness")),
            aspWitness: try circuitWitness(try dictionary(fixture, "aspWitness")),
            newNullifier: try string(fixture, "newNullifier"),
            newSecret: try string(fixture, "newSecret")
        )
    }

    private func circuitWitness(_ value: [String: Any]) throws -> FfiCircuitMerkleWitness {
        FfiCircuitMerkleWitness(
            root: try string(value, "root"),
            leaf: try string(value, "leaf"),
            index: UInt64(try int(value, "index")),
            siblings: try stringArray(value, "siblings"),
            depth: UInt64(try int(value, "depth"))
        )
    }

    private func signRequest(urlString: String, request: FfiFinalizedTransactionRequest) throws -> String {
        let payload: [String: Any] = [
            "kind": request.kind,
            "chainId": request.chainId,
            "from": request.from,
            "to": request.to,
            "nonce": request.nonce,
            "gasLimit": request.gasLimit,
            "value": request.value,
            "data": request.data,
            "gasPrice": request.gasPrice as Any,
            "maxFeePerGas": request.maxFeePerGas as Any,
            "maxPriorityFeePerGas": request.maxPriorityFeePerGas as Any,
        ]
        var httpRequest = URLRequest(url: try url(urlString))
        httpRequest.httpMethod = "POST"
        httpRequest.setValue("application/json", forHTTPHeaderField: "content-type")
        httpRequest.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let semaphore = DispatchSemaphore(value: 0)
        var signedTransaction: String?
        var capturedError: Error?
        URLSession.shared.dataTask(with: httpRequest) { data, _, error in
            defer { semaphore.signal() }
            if let error {
                capturedError = error
                return
            }
            guard let data else {
                capturedError = NSError(
                    domain: "PrivacyPoolsSdkSmoke",
                    code: 5,
                    userInfo: [NSLocalizedDescriptionKey: "missing signer fixture response body"]
                )
                return
            }
            do {
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                signedTransaction = json?["signedTransaction"] as? String
            } catch {
                capturedError = error
            }
        }.resume()
        semaphore.wait()

        if let capturedError {
            throw capturedError
        }
        guard let signedTransaction, !signedTransaction.isEmpty else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 6,
                userInfo: [NSLocalizedDescriptionKey: "missing signer fixture signedTransaction"]
            )
        }
        return signedTransaction
    }

    private func failsClosed(_ operation: () throws -> Any) -> Bool {
        do {
            _ = try operation()
            return false
        } catch {
            return true
        }
    }

    private func rejectsOrFalse(_ operation: () throws -> Bool) -> Bool {
        do {
            return try !operation()
        } catch {
            return true
        }
    }

    private func dictionariesEqual(_ left: [String: Any], _ right: [String: Any]) -> Bool {
        let leftData = try! JSONSerialization.data(withJSONObject: left, options: [.sortedKeys])
        let rightData = try! JSONSerialization.data(withJSONObject: right, options: [.sortedKeys])
        return leftData == rightData
    }

    private func mutateHex(_ value: String) -> String {
        guard !value.isEmpty else { return "00" }
        let last = value.suffix(1)
        let replacement = last == "0" ? "1" : "0"
        return "\(value.dropLast())\(replacement)"
    }

    private func hexToData(_ value: String) -> Data {
        let normalized = value.hasPrefix("0x") ? String(value.dropFirst(2)) : value
        if normalized.isEmpty {
            return Data()
        }
        let padded = normalized.count.isMultiple(of: 2) ? normalized : "0\(normalized)"
        var bytes = [UInt8]()
        var index = padded.startIndex
        while index < padded.endIndex {
            let next = padded.index(index, offsetBy: 2)
            bytes.append(UInt8(padded[index..<next], radix: 16) ?? 0)
            index = next
        }
        return Data(bytes)
    }

    private func url(_ value: String) throws -> URL {
        guard let url = URL(string: value) else {
            throw NSError(
                domain: "PrivacyPoolsSdkSmoke",
                code: 7,
                userInfo: [NSLocalizedDescriptionKey: "invalid URL: \(value)"]
            )
        }
        return url
    }

    private func readText(_ path: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.resourceURL)
            .appendingPathComponent("Fixtures", isDirectory: true)
            .appendingPathComponent(path)
        return try String(contentsOf: url, encoding: .utf8)
    }

    private func readJSONObject(_ path: String) throws -> [String: Any] {
        let data = try Data(readText(path).utf8)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func unwrapObject(_ value: Any) throws -> [String: Any] {
        guard let object = value as? [String: Any] else {
            throw NSError(domain: "PrivacyPoolsSdkSmoke", code: 8)
        }
        return object
    }

    private func array(_ object: [String: Any], _ key: String) throws -> [Any] {
        try XCTUnwrap(object[key] as? [Any])
    }

    private func dictionary(_ object: [String: Any], _ key: String) throws -> [String: Any] {
        try XCTUnwrap(object[key] as? [String: Any])
    }

    private func string(_ object: [String: Any], _ key: String) throws -> String {
        try XCTUnwrap(object[key] as? String)
    }

    private func int(_ object: [String: Any], _ key: String) throws -> Int {
        try XCTUnwrap(object[key] as? Int)
    }

    private func integer(_ object: [String: Any], _ key: String) throws -> Int {
        if let value = object[key] as? Int {
            return value
        }
        if let value = object[key] as? Double {
            return Int(value)
        }
        throw NSError(domain: "PrivacyPoolsSdkSmoke", code: 9)
    }

    private func stringArray(_ object: [String: Any], _ key: String) throws -> [String] {
        try XCTUnwrap(object[key] as? [String])
    }
}
