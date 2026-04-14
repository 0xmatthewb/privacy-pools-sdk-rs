#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
ANDROID_DIR="$ROOT_DIR/bindings/android"
JNI_DIR="$ANDROID_DIR/src/main/jniLibs"
ANDROID_BINDINGS_FILE="$ROOT_DIR/bindings/android/generated/src/main/java/io/oxbow/privacypoolssdk/privacy_pools_sdk_ffi.kt"
IOS_HEADERS_FILE="$ROOT_DIR/bindings/ios/generated/PrivacyPoolsSdkFFI.h"

if [[ ! -f "$ANDROID_BINDINGS_FILE" || ! -f "$IOS_HEADERS_FILE" ]]; then
  pushd "$ROOT_DIR" >/dev/null
  cargo run -p xtask -- bindings-release
  popd >/dev/null
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "cargo-ndk is required to build Android native libraries"
  exit 1
fi

rm -rf "$JNI_DIR"
mkdir -p "$JNI_DIR"

pushd "$ROOT_DIR" >/dev/null
cargo ndk \
  -t armeabi-v7a \
  -t arm64-v8a \
  -t x86_64 \
  -o "$JNI_DIR" \
  build -p privacy-pools-sdk-ffi --release --lib
popd >/dev/null

if command -v gradle >/dev/null 2>&1; then
  pushd "$ANDROID_DIR" >/dev/null
  gradle assembleRelease
  popd >/dev/null
else
  echo "gradle not found; native libraries were built into $JNI_DIR"
fi
