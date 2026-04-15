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

            resolve([
                "root": destination.path,
                "artifactsRoot": destination.appendingPathComponent("artifacts").path,
                "withdrawalManifestJson": try readFixtureText(
                    "artifacts/withdrawal-proving-manifest.json"
                ),
                "commitmentManifestJson": try readFixtureText(
                    "artifacts/commitment-proving-manifest.json"
                ),
                "cryptoCompatibilityJson": try readFixtureText(
                    "vectors/crypto-compatibility.json"
                ),
                "withdrawalCircuitInputJson": try readFixtureText(
                    "vectors/withdrawal-circuit-input.json"
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
        NSLog("%@", marker)
        resolve(true)
    }

    @objc(markFailure:message:resolver:rejecter:)
    func markFailure(
        marker: String,
        message: String,
        resolver resolve: RCTPromiseResolveBlock,
        rejecter reject: RCTPromiseRejectBlock
    ) {
        NSLog("%@ %@", marker, message)
        resolve(true)
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
}
