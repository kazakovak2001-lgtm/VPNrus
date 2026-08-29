#!/bin/bash
# Builds the pinned AndroidLibXrayLite (VLESS/REALITY-capable Xray-core)
# Android library (.aar) inside WSL2 Ubuntu.
# Run from Windows: wsl -d Ubuntu -- bash /mnt/c/.../third_party/xray/build-xray-wsl.sh
#
# Why WSL: same reason as third_party/build-tunnel-wsl.sh - gomobile's
# Android/NDK cross-compile toolchain wants a POSIX host, not plain Windows.
#
# Pinned revision: see VERSION in this directory. Do not float to main -
# always pin to an exact commit until deliberately re-audited (B8K0).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=VERSION
source "$HERE/VERSION"

WORK=~/build/androidlibxraylite
ANDROID_HOME=~/android-sdk

if [ ! -d "$WORK" ]; then
    mkdir -p ~/build
    git clone "$WRAPPER_REPO" "$WORK"
fi

cd "$WORK"
git fetch -q
git checkout -q "$WRAPPER_COMMIT"

actual_sha=$(git rev-parse HEAD)
if [ "$actual_sha" != "$WRAPPER_COMMIT" ]; then
    echo "ERROR: pinned commit resolved to $actual_sha, expected $WRAPPER_COMMIT" >&2
    exit 1
fi

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME="$ANDROID_HOME"
export PATH="$(go env GOPATH)/bin:$PATH"

go version | grep -q "go${GO_VERSION_REQUIRED%%.*}\." || {
    echo "WARNING: expected a go${GO_VERSION_REQUIRED} toolchain, found: $(go version)" >&2
}

# gomobile init/build resolve dependencies via go.sum, which cryptographically
# pins the exact xray-core content this commit's go.mod references (see
# VERSION's own "Checksum/provenance strategy" note) - no separate manual
# xray-core clone/checkout is needed or performed here.
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init

go mod tidy -v

gomobile bind -v -androidapi "$ANDROID_API_LEVEL" -trimpath \
    -ldflags='-s -w -buildid= -checklinkname=0' \
    ./

OUT="$WORK/libv2ray.aar"
echo "Built: $OUT"
echo "Copy this file into android/app/libs/ for the app module to consume it (once a real Kotlin adapter exists - see docs/B8K0_RUNTIME_AUDIT.md)."
