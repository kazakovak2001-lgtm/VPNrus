#!/usr/bin/env bash
# B46-3A: compile the JNI shim (../jni/nova_tun2socks_jni.c) and link it
# against the Go c-shared artifact (libnovatun2socks.so), producing
# libnovatun2socks_jni.so - the ONLY library the JVM ever dlopen()s.
# Requires ../out/arm64-v8a/libnovatun2socks.{so,h} to already exist
# (run build-c-shared.sh first).
set -euo pipefail

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an installed NDK}"
ANDROID_API="${ANDROID_API:-26}"

HOST_TAG="windows-x86_64"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
CC="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang.cmd"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNI_DIR="$SCRIPT_DIR/../jni"
OUT_DIR="$SCRIPT_DIR/../out/arm64-v8a"

if [ ! -f "$OUT_DIR/libnovatun2socks.so" ]; then
  echo "missing $OUT_DIR/libnovatun2socks.so - run build-c-shared.sh first" >&2
  exit 1
fi

echo "== compiling + linking libnovatun2socks_jni.so =="
"$CC" -shared -fPIC -O2 \
  -I"$OUT_DIR" \
  -o "$OUT_DIR/libnovatun2socks_jni.so" \
  "$JNI_DIR/nova_tun2socks_jni.c" \
  -L"$OUT_DIR" -lnovatun2socks \
  -Wl,-soname,libnovatun2socks_jni.so

echo "== artifacts =="
ls -la "$OUT_DIR"/*.so
echo "== sha256 =="
sha256sum "$OUT_DIR"/*.so
