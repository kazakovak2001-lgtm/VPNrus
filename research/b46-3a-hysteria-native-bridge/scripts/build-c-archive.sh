#!/usr/bin/env bash
# B46-3A: build the Nova tun2socks native bridge as a Go c-archive for
# android/arm64. Research-only; do not commit the resulting artifacts
# (.h/.a are gitignored - see research/b46-3a-hysteria-native-bridge/.gitignore).
set -euo pipefail

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an installed NDK, e.g. .../Sdk/ndk/27.0.12077973}"
ANDROID_API="${ANDROID_API:-26}"

HOST_TAG="windows-x86_64"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
CC="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang.cmd"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="$SCRIPT_DIR/../native"
OUT_DIR="$SCRIPT_DIR/../out/arm64-v8a"
mkdir -p "$OUT_DIR"

echo "== go version =="
go version

echo "== building libnovatun2socks (c-archive, android/arm64, api $ANDROID_API) =="
(
  cd "$NATIVE_DIR"
  CGO_ENABLED=1 \
  GOOS=android \
  GOARCH=arm64 \
  CC="$CC" \
  go build -buildmode=c-archive -trimpath \
    -o "$OUT_DIR/libnovatun2socks.a" .
)

echo "== artifacts =="
ls -la "$OUT_DIR"
echo "== sha256 =="
sha256sum "$OUT_DIR/libnovatun2socks.a" "$OUT_DIR/libnovatun2socks.h"
