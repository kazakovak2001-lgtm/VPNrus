#!/usr/bin/env bash
# B46-3B: build the tun2socks-child PLAIN Go executable for android/arm64.
# No cgo, no NDK, no gomobile - a real ELF PIE executable dynamically
# linked only against /system/bin/linker64 (confirmed via readelf: no
# NEEDED entries), exec()'d as a separate OS process, never dlopen()'d.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHILD_DIR="$SCRIPT_DIR/../tun2socks-child"
OUT_DIR="$SCRIPT_DIR/../out/arm64-v8a"
mkdir -p "$OUT_DIR"

echo "== go version =="
go version

echo "== building tun2socks-child (plain executable, android/arm64, CGO_ENABLED=0) =="
(
  cd "$CHILD_DIR"
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
    go build -trimpath -o "$OUT_DIR/libnovatun2sockschild.so" .
)

echo "== artifact =="
ls -la "$OUT_DIR/libnovatun2sockschild.so"
echo "== sha256 =="
sha256sum "$OUT_DIR/libnovatun2sockschild.so"
