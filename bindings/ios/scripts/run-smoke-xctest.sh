#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
IOS_DIR="$ROOT_DIR/bindings/ios"
SMOKE_DIR="$ROOT_DIR/target/ios-native-smoke"
PACKAGE_SOURCES="$SMOKE_DIR/Sources/PrivacyPoolsSdk"
PACKAGE_FFI="$SMOKE_DIR/Sources/PrivacyPoolsSdkFFI"
PACKAGE_LIB="$SMOKE_DIR/lib"
PACKAGE_TESTS="$SMOKE_DIR/Tests/PrivacyPoolsSdkSmokeTests"
FIXTURES_DIR="$PACKAGE_TESTS/Fixtures"
XCFRAMEWORK="$IOS_DIR/build/PrivacyPoolsSdkFFI.xcframework"
SIMULATOR_LIB="$XCFRAMEWORK/ios-arm64-simulator/libprivacy_pools_sdk_ffi.a"

if [[ ! -d "$XCFRAMEWORK" ]]; then
  "$IOS_DIR/scripts/build-xcframework.sh"
fi

rm -rf "$SMOKE_DIR"
mkdir -p "$PACKAGE_SOURCES" "$PACKAGE_FFI/include" "$PACKAGE_LIB" "$PACKAGE_TESTS" "$FIXTURES_DIR"

cp "$IOS_DIR/generated/PrivacyPoolsSdk.swift" "$PACKAGE_SOURCES/PrivacyPoolsSdk.swift"
cp "$IOS_DIR/Sources/PrivacyPoolsSdk/PrivacyPoolsSdkClient.swift" \
  "$PACKAGE_SOURCES/PrivacyPoolsSdkClient.swift"
cp "$IOS_DIR/generated/PrivacyPoolsSdkFFI.h" "$PACKAGE_FFI/include/PrivacyPoolsSdkFFI.h"
cp "$SIMULATOR_LIB" "$PACKAGE_LIB/libprivacy_pools_sdk_ffi.a"
touch "$PACKAGE_FFI/empty.c"
cat > "$PACKAGE_FFI/include/module.modulemap" <<'MODULEMAP'
module PrivacyPoolsSdkFFI {
    header "PrivacyPoolsSdkFFI.h"
    export *
}
MODULEMAP
cp -R "$ROOT_DIR/fixtures/artifacts" "$FIXTURES_DIR/artifacts"
cp -R "$ROOT_DIR/fixtures/circuits" "$FIXTURES_DIR/circuits"
cp -R "$ROOT_DIR/fixtures/vectors" "$FIXTURES_DIR/vectors"

if [[ -z "${IOS_SMOKE_DESTINATION:-}" ]]; then
  IOS_SMOKE_DEVICE="$(
    xcrun simctl list devices available |
      sed -nE 's/^[[:space:]]*(iPhone[^()]*) .*/\1/p' |
      head -n 1 |
      sed 's/[[:space:]]*$//'
  )"
  if [[ -z "$IOS_SMOKE_DEVICE" ]]; then
    echo "failed to find an available iPhone simulator"
    exit 1
  fi
  IOS_SMOKE_DESTINATION="platform=iOS Simulator,name=$IOS_SMOKE_DEVICE"
fi

cat > "$SMOKE_DIR/Package.swift" <<SWIFT
// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "PrivacyPoolsSdkIOSSmoke",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "PrivacyPoolsSdk", targets: ["PrivacyPoolsSdk"]),
    ],
    targets: [
        .target(
            name: "PrivacyPoolsSdkFFI",
            path: "Sources/PrivacyPoolsSdkFFI",
            publicHeadersPath: "include",
            linkerSettings: [
                .unsafeFlags(["-L$PACKAGE_LIB", "-lprivacy_pools_sdk_ffi"])
            ]
        ),
        .target(
            name: "PrivacyPoolsSdk",
            dependencies: ["PrivacyPoolsSdkFFI"],
            path: "Sources/PrivacyPoolsSdk"
        ),
        .testTarget(
            name: "PrivacyPoolsSdkSmokeTests",
            dependencies: ["PrivacyPoolsSdk"],
            path: "Tests/PrivacyPoolsSdkSmokeTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
SWIFT

cat > "$PACKAGE_TESTS/PrivacyPoolsSdkSmokeTests.swift" <<'SWIFT'
import Foundation
import PrivacyPoolsSdk
import XCTest

final class PrivacyPoolsSdkSmokeTests: XCTestCase {
    func testProvesAndVerifiesCommitmentAndWithdrawalInAppProcess() throws {
        let fixturesRoot = try copyFixturesToAppStorage()
        let artifactsRoot = fixturesRoot.appendingPathComponent("artifacts").path
        let crypto = try readJSONObject("vectors/crypto-compatibility.json")
        let withdrawalFixture = try readJSONObject("vectors/withdrawal-circuit-input.json")
        let withdrawalManifest = try readText("artifacts/withdrawal-proving-manifest.json")
        let commitmentManifest = try readText("artifacts/commitment-proving-manifest.json")
        let depositSecrets = try XCTUnwrap(crypto["depositSecrets"] as? [String: Any])

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
        XCTAssertEqual(commitmentProof.backend, "arkworks")
        XCTAssertTrue(try PrivacyPoolsSdkClient.verifyCommitment(
            backendProfile: "stable",
            sessionHandle: commitmentSession.handle,
            proof: commitmentProof.proof
        ))
        XCTAssertTrue(try PrivacyPoolsSdkClient.removeCommitmentCircuitSession(
            handle: commitmentSession.handle
        ))
        XCTAssertThrowsError(try PrivacyPoolsSdkClient.verifyCommitment(
            backendProfile: "stable",
            sessionHandle: commitmentSession.handle,
            proof: commitmentProof.proof
        ))

        let withdrawalSession = try PrivacyPoolsSdkClient.prepareWithdrawalCircuitSession(
            manifestJson: withdrawalManifest,
            artifactsRoot: artifactsRoot
        )
        let withdrawalProof = try PrivacyPoolsSdkClient.withdrawalProof(
            backendProfile: "stable",
            sessionHandle: withdrawalSession.handle,
            request: try withdrawalRequest(
                commitment: commitment,
                crypto: crypto,
                fixture: withdrawalFixture
            )
        )
        XCTAssertEqual(withdrawalProof.backend, "arkworks")
        XCTAssertTrue(try PrivacyPoolsSdkClient.verifyWithdrawal(
            backendProfile: "stable",
            sessionHandle: withdrawalSession.handle,
            proof: withdrawalProof.proof
        ))
        XCTAssertTrue(try PrivacyPoolsSdkClient.removeWithdrawalCircuitSession(
            handle: withdrawalSession.handle
        ))
        XCTAssertThrowsError(try PrivacyPoolsSdkClient.verifyWithdrawal(
            backendProfile: "stable",
            sessionHandle: withdrawalSession.handle,
            proof: withdrawalProof.proof
        ))
    }

    private func withdrawalRequest(
        commitment: FfiCommitment,
        crypto: [String: Any],
        fixture: [String: Any]
    ) throws -> FfiWithdrawalWitnessRequest {
        FfiWithdrawalWitnessRequest(
            commitment: commitment,
            withdrawal: FfiWithdrawal(
                processooor: "0x1111111111111111111111111111111111111111",
                data: Data([0x12, 0x34])
            ),
            scope: try string(crypto, "scope"),
            withdrawalAmount: try string(fixture, "withdrawalAmount"),
            stateWitness: try circuitWitness(fixture, "stateWitness"),
            aspWitness: try circuitWitness(fixture, "aspWitness"),
            newNullifier: try string(fixture, "newNullifier"),
            newSecret: try string(fixture, "newSecret")
        )
    }

    private func circuitWitness(
        _ fixture: [String: Any],
        _ key: String
    ) throws -> FfiCircuitMerkleWitness {
        let value = try XCTUnwrap(fixture[key] as? [String: Any])
        return FfiCircuitMerkleWitness(
            root: try string(value, "root"),
            leaf: try string(value, "leaf"),
            index: UInt64(try int(value, "index")),
            siblings: try XCTUnwrap(value["siblings"] as? [String]),
            depth: UInt64(try int(value, "depth"))
        )
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

    private func string(_ object: [String: Any], _ key: String) throws -> String {
        try XCTUnwrap(object[key] as? String)
    }

    private func int(_ object: [String: Any], _ key: String) throws -> Int {
        try XCTUnwrap(object[key] as? Int)
    }
}
SWIFT

(cd "$SMOKE_DIR" && xcodebuild test \
  -scheme PrivacyPoolsSdkIOSSmoke \
  -destination "$IOS_SMOKE_DESTINATION" \
  -skipPackagePluginValidation)
