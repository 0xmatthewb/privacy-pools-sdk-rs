#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
IOS_DIR="$ROOT_DIR/bindings/ios"
BUILD_DIR="$IOS_DIR/build"
HEADERS_DIR="$BUILD_DIR/headers"
GEN_DIR="$IOS_DIR/generated"
IOS_HEADERS_FILE="$GEN_DIR/PrivacyPoolsSdkFFI.h"

DEVICE_TARGET="aarch64-apple-ios"
SIMULATOR_TARGET="aarch64-apple-ios-sim"
SIMULATOR_X86_TARGET="x86_64-apple-ios"
LIB_NAME="libprivacy_pools_sdk_ffi.a"
XCFRAMEWORK_PATH="$BUILD_DIR/PrivacyPoolsSdkFFI.xcframework"
UNIVERSAL_SIMULATOR_DIR="$BUILD_DIR/universal-simulator"
UNIVERSAL_SIMULATOR_LIB="$UNIVERSAL_SIMULATOR_DIR/$LIB_NAME"

rm -rf "$BUILD_DIR"
mkdir -p "$HEADERS_DIR"

pushd "$ROOT_DIR" >/dev/null

cargo run -p xtask -- bindings-release
cargo build -p privacy-pools-sdk-ffi --release --target "$DEVICE_TARGET" --lib
cargo build -p privacy-pools-sdk-ffi --release --target "$SIMULATOR_TARGET" --lib
cargo build -p privacy-pools-sdk-ffi --release --target "$SIMULATOR_X86_TARGET" --lib

popd >/dev/null

cp "$IOS_HEADERS_FILE" "$HEADERS_DIR/PrivacyPoolsSdkFFI.h"
cat > "$HEADERS_DIR/module.modulemap" <<'MODULEMAP'
module PrivacyPoolsSdkFFI {
    header "PrivacyPoolsSdkFFI.h"
    export *
}
MODULEMAP

mkdir -p "$UNIVERSAL_SIMULATOR_DIR"
lipo -create \
  "$ROOT_DIR/target/$SIMULATOR_TARGET/release/$LIB_NAME" \
  "$ROOT_DIR/target/$SIMULATOR_X86_TARGET/release/$LIB_NAME" \
  -output "$UNIVERSAL_SIMULATOR_LIB"

xcodebuild -create-xcframework \
  -library "$ROOT_DIR/target/$DEVICE_TARGET/release/$LIB_NAME" -headers "$HEADERS_DIR" \
  -library "$UNIVERSAL_SIMULATOR_LIB" -headers "$HEADERS_DIR" \
  -output "$XCFRAMEWORK_PATH"

echo "created $XCFRAMEWORK_PATH"
