#!/usr/bin/env bash
# B46-4A: reproducibly build the Hysteria2 Android child (libnovahysteriachild.so)
# from third_party/hysteria2-child/src against the pinned upstream commit.
#
# The wrapper imports packages of the upstream `app` module, so it is built
# from inside a checkout of the pinned commit (copied to app/novaminimal/).
# No upstream file is modified. See README.md for the provenance record.
#
# Usage: build-hysteria2-child.sh [output-dir]
#   default output-dir: android/app/src/main/jniLibs/arm64-v8a
set -euo pipefail

PINNED_COMMIT=e1366b173ccf5706e1e4630fe8aa654a4b574085
GO_TOOLCHAIN=go1.26.5

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
OUT_DIR="${1:-$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a}"
WORK="${TMPDIR:-/tmp}/nova-hysteria2-child-build"
mkdir -p "$OUT_DIR"

# CRLF sources produce a different ELF - refuse them (see .gitattributes).
# Byte-exact: strip CR (0x0D) and compare. Not `grep $'\r'`, which MSYS/Git
# Bash grep does not match reliably because it strips CR in text mode.
for f in "$SRC_DIR"/*.go; do
  if ! tr -d '\r' < "$f" | cmp -s - "$f"; then
    echo "ERROR: CRLF line endings in $f - check out with LF" >&2
    exit 1
  fi
done

if [ ! -d "$WORK/.git" ]; then
  git -c core.autocrlf=false clone -q https://github.com/apernet/hysteria.git "$WORK"
fi
cd "$WORK"
git -c core.autocrlf=false fetch -q
git -c core.autocrlf=false checkout -q "$PINNED_COMMIT"
git -c core.autocrlf=false reset --hard -q "$PINNED_COMMIT"
git clean -fdq
actual_sha=$(git rev-parse HEAD)
if [ "$actual_sha" != "$PINNED_COMMIT" ]; then
  echo "ERROR: hysteria resolved to $actual_sha, expected $PINNED_COMMIT" >&2
  exit 1
fi

mkdir -p app/novaminimal
cp "$SRC_DIR"/*.go app/novaminimal/

export GOTOOLCHAIN="$GO_TOOLCHAIN"
echo "== go version =="
(cd app && go version)

echo "== building libnovahysteriachild.so (android/arm64, CGO_ENABLED=0) =="
(
  cd app
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
    go build -trimpath -buildvcs=false -o "$OUT_DIR/libnovahysteriachild.so" ./novaminimal
)

echo "== dependency check: no sing-tun / internal/tun / internal/socks5 =="
if (cd app && GOOS=android GOARCH=arm64 go list -deps ./novaminimal | grep -E 'sing-tun|app/v2/internal/(tun|socks5)$'); then
  echo "ERROR: forbidden dependency found" >&2
  exit 1
fi
echo "OK"

echo "== artifact =="
ls -l "$OUT_DIR/libnovahysteriachild.so"
sha256sum "$OUT_DIR/libnovahysteriachild.so"
