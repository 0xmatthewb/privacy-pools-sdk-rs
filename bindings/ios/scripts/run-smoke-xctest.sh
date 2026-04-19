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
LIB_NAME="libprivacy_pools_sdk_ffi.a"
IOS_REPORT_PATH="$SMOKE_DIR/report.json"
IOS_XCODEBUILD_LOG="$SMOKE_DIR/xcodebuild.log"
EXECUTION_FIXTURE_PATH="$FIXTURES_DIR/vectors/mobile-execution-fixture.json"

"$IOS_DIR/scripts/build-xcframework.sh"

if [[ -f "$XCFRAMEWORK/ios-arm64_x86_64-simulator/$LIB_NAME" ]]; then
  SIMULATOR_LIB="$XCFRAMEWORK/ios-arm64_x86_64-simulator/$LIB_NAME"
elif [[ -f "$XCFRAMEWORK/ios-arm64-simulator/$LIB_NAME" ]]; then
  SIMULATOR_LIB="$XCFRAMEWORK/ios-arm64-simulator/$LIB_NAME"
else
  echo "failed to locate simulator library in $XCFRAMEWORK"
  exit 1
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

STATE_ROOT="$(
  node - <<'EOF'
const fs = require("node:fs");
const fixture = JSON.parse(fs.readFileSync("fixtures/vectors/withdrawal-circuit-input.json", "utf8"));
process.stdout.write(String(fixture.stateWitness.root));
EOF
)"
ASP_ROOT="$(
  node - <<'EOF'
const fs = require("node:fs");
const fixture = JSON.parse(fs.readFileSync("fixtures/vectors/withdrawal-circuit-input.json", "utf8"));
process.stdout.write(String(fixture.aspWitness.root));
EOF
)"
node "$ROOT_DIR/packages/sdk/scripts/start-mobile-execution-fixture-servers.mjs" \
  --platform ios \
  --bind-host 127.0.0.1 \
  --public-host 127.0.0.1 \
  --state-root "$STATE_ROOT" \
  --asp-root "$ASP_ROOT" \
  > "$EXECUTION_FIXTURE_PATH" &
EXECUTION_FIXTURE_PID=$!
cleanup() {
  kill "$EXECUTION_FIXTURE_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
for _ in $(seq 1 50); do
  if [[ -s "$EXECUTION_FIXTURE_PATH" ]]; then
    break
  fi
  sleep 0.2
done
if [[ ! -s "$EXECUTION_FIXTURE_PATH" ]]; then
  echo "failed to start iOS mobile execution fixture servers"
  exit 1
fi

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
                .unsafeFlags([
                    "-Xlinker", "-force_load",
                    "-Xlinker", "$PACKAGE_LIB/$LIB_NAME"
                ])
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

cp "$IOS_DIR/scripts/PrivacyPoolsSdkSmokeTests.swift" \
  "$PACKAGE_TESTS/PrivacyPoolsSdkSmokeTests.swift"

set +e
(cd "$SMOKE_DIR" && xcodebuild test \
  -scheme PrivacyPoolsSdkIOSSmoke \
  -destination "$IOS_SMOKE_DESTINATION" \
  -skipPackagePluginValidation | tee "$IOS_XCODEBUILD_LOG")
XCODEBUILD_STATUS=$?
set -e

REPORT_LINE="$(grep '^PRIVACY_POOLS_IOS_NATIVE_REPORT=' "$IOS_XCODEBUILD_LOG" | tail -n 1 || true)"
if [[ -n "$REPORT_LINE" ]]; then
  printf '%s\n' "${REPORT_LINE#PRIVACY_POOLS_IOS_NATIVE_REPORT=}" > "$IOS_REPORT_PATH"
elif [[ ! -f "$IOS_REPORT_PATH" ]]; then
  node - "$IOS_REPORT_PATH" "$XCODEBUILD_STATUS" <<'EOF'
const fs = require("node:fs");
const path = process.argv[2];
const status = Number(process.argv[3] ?? "1");
fs.writeFileSync(
  path,
  `${JSON.stringify({
    generatedAt: new Date().toISOString(),
    runtime: "native",
    platform: "ios",
    surface: "native",
    smoke: {
      backend: "unknown",
      commitmentVerified: false,
      withdrawalVerified: false,
      executionSubmitted: false,
      signedManifestVerified: false,
      wrongSignedManifestPublicKeyRejected: false,
      tamperedSignedManifestArtifactsRejected: false,
      tamperedProofRejected: false,
      handleKindMismatchRejected: false,
      staleVerifiedProofHandleRejected: false,
      staleCommitmentSessionRejected: false,
      staleWithdrawalSessionRejected: false,
      wrongRootRejected: false,
      wrongChainIdRejected: false,
      wrongCodeHashRejected: false,
      wrongSignerRejected: false
    },
    parity: {
      totalChecks: 1,
      passed: 0,
      failed: 1,
      failedChecks: [`missing ios native smoke report marker (xcodebuild exit ${status})`]
    },
    benchmark: {
      artifactResolutionMs: 0,
      bundleVerificationMs: 0,
      sessionPreloadMs: 0,
      firstInputPreparationMs: 0,
      firstWitnessGenerationMs: 0,
      firstProofGenerationMs: 0,
      firstVerificationMs: 0,
      firstProveAndVerifyMs: 0,
      iterations: 1,
      warmup: 0,
      peakResidentMemoryBytes: null,
      samples: [{
        inputPreparationMs: 0,
        witnessGenerationMs: 0,
        proofGenerationMs: 0,
        verificationMs: 0,
        proveAndVerifyMs: 0
      }]
    }
  }, null, 2)}\n`,
);
EOF
fi

if [[ "$XCODEBUILD_STATUS" -ne 0 ]]; then
  exit "$XCODEBUILD_STATUS"
fi
