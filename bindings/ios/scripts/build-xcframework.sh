#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
IOS_DIR="$ROOT_DIR/bindings/ios"
BUILD_DIR="$IOS_DIR/build"
HEADERS_DIR="$BUILD_DIR/headers"
GEN_DIR="$IOS_DIR/generated"

DEVICE_TARGET="aarch64-apple-ios"
SIMULATOR_TARGET="aarch64-apple-ios-sim"
LIB_NAME="libprivacy_pools_sdk_ffi.a"
XCFRAMEWORK_PATH="$BUILD_DIR/PrivacyPoolsSdkFFI.xcframework"

rm -rf "$BUILD_DIR"
mkdir -p "$HEADERS_DIR"

pushd "$ROOT_DIR" >/dev/null

cargo run -p xtask -- bindings-release
cargo build -p privacy-pools-sdk-ffi --release --target "$DEVICE_TARGET" --lib
cargo build -p privacy-pools-sdk-ffi --release --target "$SIMULATOR_TARGET" --lib

popd >/dev/null

cp "$GEN_DIR/PrivacyPoolsSdkFFI.h" "$HEADERS_DIR/PrivacyPoolsSdkFFI.h"
cp "$GEN_DIR/PrivacyPoolsSdkFFI.modulemap" "$HEADERS_DIR/module.modulemap"

xcodebuild -create-xcframework \
  -library "$ROOT_DIR/target/$DEVICE_TARGET/release/$LIB_NAME" -headers "$HEADERS_DIR" \
  -library "$ROOT_DIR/target/$SIMULATOR_TARGET/release/$LIB_NAME" -headers "$HEADERS_DIR" \
  -output "$XCFRAMEWORK_PATH"

echo "created $XCFRAMEWORK_PATH"
