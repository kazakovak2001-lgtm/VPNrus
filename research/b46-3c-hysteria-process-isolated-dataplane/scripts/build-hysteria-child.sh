#!/usr/bin/env bash
# B46-3C: build the minimal Hysteria2 Android child for android/arm64.
# Reuses the exact B46-2P/B46-2C source (hysteria-child/main.go, a copy of
# research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go,
# unmodified) against the same pinned upstream commit. No upstream Hysteria
# file is modified - this cannot be a standalone Go module (imports the
# `app/internal/socks5` internal package), so it must be built from inside
# a real checkout of the pinned commit, same as B46-2P's own documented
# recipe.
set -euo pipefail

PINNED_COMMIT=e1366b173ccf5706e1e4630fe8aa654a4b574085
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${TMPDIR:-/tmp}/b46-3c-hysteria-build"
OUT_DIR="$SCRIPT_DIR/../out/arm64-v8a"
mkdir -p "$OUT_DIR"

if [ ! -d "$WORK/.git" ]; then
  git clone -q https://github.com/apernet/hysteria.git "$WORK"
fi
cd "$WORK"
git fetch -q
git checkout -q "$PINNED_COMMIT"
git reset --hard -q "$PINNED_COMMIT"

actual_sha=$(git rev-parse HEAD)
if [ "$actual_sha" != "$PINNED_COMMIT" ]; then
  echo "ERROR: hysteria resolved to $actual_sha, expected $PINNED_COMMIT" >&2
  exit 1
fi

mkdir -p app/novaminimal
cp "$SCRIPT_DIR/../hysteria-child/main.go" app/novaminimal/main.go

echo "== go version =="
go version

echo "== building novaminimal-android-arm64 =="
(
  cd app
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath -o "$OUT_DIR/libnovahysteriachild.so" ./novaminimal
)

echo "== verification (per B46-2P's own required checks) =="
(cd app && go list -deps ./novaminimal | grep -i 'sing-tun\|internal/tun') && {
  echo "ERROR: found sing-tun/internal-tun in deps" >&2
  exit 1
} || echo "OK: zero sing-tun/internal-tun in deps"

echo "== artifact =="
ls -la "$OUT_DIR/libnovahysteriachild.so"
sha256sum "$OUT_DIR/libnovahysteriachild.so"
