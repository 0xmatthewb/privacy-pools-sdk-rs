import Foundation
import React

@objc(PrivacyPoolsSmokeFixtures)
final class PrivacyPoolsSmokeFixtures: NSObject {
    @objc
    static func requiresMainQueueSetup() -> Bool {
        false
    }

    @objc(copyFixtures:rejecter:)
    func copyFixtures(
        resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        do {
            let source = try fixtureSourceURL()
            let destination = FileManager.default.temporaryDirectory
                .appendingPathComponent("privacy-pools-fixtures", isDirectory: true)
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.copyItem(at: source, to: destination)
            try resetReportFiles()
            try writeStatus(status: "running")

            resolve([
                "root": destination.path,
                "artifactsRoot": destination.appendingPathComponent("artifacts").path,
                "reportPath": try reportURL().path,
                "statusPath": try statusURL().path,
                "withdrawalManifestJson": try readFixtureText(
                    "artifacts/withdrawal-proving-manifest.json"
                ),
                "commitmentManifestJson": try readFixtureText(
                    "artifacts/commitment-proving-manifest.json"
                ),
                "signedManifestPayloadJson": try readFixtureText(
                    "artifacts/signed-manifest/payload.json"
                ),
                "signedManifestSignatureHex": try readFixtureText(
                    "artifacts/signed-manifest/signature"
                ).trimmingCharacters(in: .whitespacesAndNewlines),
                "signedManifestPublicKeyHex": try readFixtureText(
                    "artifacts/signed-manifest/public-key.hex"
                ).trimmingCharacters(in: .whitespacesAndNewlines),
                "cryptoCompatibilityJson": try readFixtureText(
                    "vectors/crypto-compatibility.json"
                ),
                "withdrawalCircuitInputJson": try readFixtureText(
                    "vectors/withdrawal-circuit-input.json"
                ),
                "assuranceGoldensJson": try readFixtureText(
                    "vectors/assurance-goldens.json"
                ),
                "auditParityCasesJson": try readFixtureText(
                    "vectors/audit-parity-cases.json"
                ),
                "executionFixtureJson": try readFixtureText(
                    "vectors/mobile-execution-fixture.json"
                ),
            ])
        } catch {
            reject("fixture_error", error.localizedDescription, error)
        }
    }

    @objc(markSuccess:resolver:rejecter:)
    func markSuccess(
        marker: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        do {
            try writeStatus(status: "success")
            resolve(true)
        } catch {
            reject("report_error", error.localizedDescription, error)
        }
    }

    @objc(markFailure:message:resolver:rejecter:)
    func markFailure(
        marker: String,
        message: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        do {
            try writeStatus(status: "error", message: message)
            resolve(true)
        } catch {
            reject("report_error", error.localizedDescription, error)
        }
    }

    @objc(markProgress:message:resolver:rejecter:)
    func markProgress(
        marker: String,
        message: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        do {
            try writeStatus(status: "running", message: message)
            resolve(true)
        } catch {
            reject("report_error", error.localizedDescription, error)
        }
    }

    @objc(markReport:reportJson:resolver:rejecter:)
    func markReport(
        marker: String,
        reportJson: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        do {
            try reportJson.write(to: reportURL(), atomically: true, encoding: .utf8)
            resolve(true)
        } catch {
            reject("report_error", error.localizedDescription, error)
        }
    }

    private func fixtureSourceURL() throws -> URL {
        guard let resourceURL = Bundle.main.resourceURL else {
            throw NSError(
                domain: "PrivacyPoolsRnAppSmoke",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing app resource URL"]
            )
        }

        let source = resourceURL.appendingPathComponent(
            "privacy-pools-fixtures",
            isDirectory: true
        )
        guard FileManager.default.fileExists(atPath: source.path) else {
            throw NSError(
                domain: "PrivacyPoolsRnAppSmoke",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing bundled fixtures"]
            )
        }

        return source
    }

    private func readFixtureText(_ path: String) throws -> String {
        let url = try fixtureSourceURL().appendingPathComponent(path)
        return try String(contentsOf: url, encoding: .utf8)
    }

    private func reportRootURL() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = base.appendingPathComponent("privacy-pools-smoke", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }

    private func reportURL() throws -> URL {
        try reportRootURL().appendingPathComponent("report.json")
    }

    private func statusURL() throws -> URL {
        try reportRootURL().appendingPathComponent("report-status.json")
    }

    private func resetReportFiles() throws {
        let fileManager = FileManager.default
        try? fileManager.removeItem(at: reportURL())
        try? fileManager.removeItem(at: statusURL())
    }

    private func writeStatus(status: String, message: String? = nil) throws {
        var payload: [String: Any] = [
            "status": status,
            "updatedAt": Int(Date().timeIntervalSince1970 * 1000),
        ]
        if let message {
            payload["message"] = message
        }
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted])
        try data.write(to: statusURL(), options: [.atomic])
    }
}
