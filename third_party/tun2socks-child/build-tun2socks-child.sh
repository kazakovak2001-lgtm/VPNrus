#!/usr/bin/env bash
# B46-4A: reproducibly build the Hysteria2 tun2socks Android child
# (libnovatun2sockschild.so) from third_party/tun2socks-child/src, a standalone
# Go module pinned to xjasonlyu/tun2socks/v2 v2.0.0-20260913205830-5d9fac67bb10
# (go.sum). See README.md for the provenance record.
#
# Usage: build-tun2socks-child.sh [output-dir]
#   default output-dir: android/app/src/main/jniLibs/arm64-v8a
set -euo pipefail

PINNED_TUN2SOCKS="github.com/xjasonlyu/tun2socks/v2 v2.0.0-20260913205830-5d9fac67bb10"
GO_TOOLCHAIN=go1.26.5

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
OUT_DIR="${1:-$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a}"
mkdir -p "$OUT_DIR"

# CRLF sources produce a different ELF - refuse them (see .gitattributes).
# Byte-exact: strip CR (0x0D) and compare. Not `grep $'\r'`, which MSYS/Git
# Bash grep does not match reliably because it strips CR in text mode.
for f in "$SRC_DIR"/*.go "$SRC_DIR"/go.mod "$SRC_DIR"/go.sum; do
  if ! tr -d '\r' < "$f" | cmp -s - "$f"; then
    echo "ERROR: CRLF line endings in $f - check out with LF" >&2
    exit 1
  fi
done

if ! grep -q "require $PINNED_TUN2SOCKS" "$SRC_DIR/go.mod"; then
  echo "ERROR: go.mod does not pin $PINNED_TUN2SOCKS" >&2
  exit 1
fi

export GOTOOLCHAIN="$GO_TOOLCHAIN"
echo "== go version =="
(cd "$SRC_DIR" && go version)

echo "== building libnovatun2sockschild.so (android/arm64, CGO_ENABLED=0) =="
(
  cd "$SRC_DIR"
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false -o "$OUT_DIR/libnovatun2sockschild.so" .
)

echo "== artifact =="
ls -l "$OUT_DIR/libnovatun2sockschild.so"
sha256sum "$OUT_DIR/libnovatun2sockschild.so"
