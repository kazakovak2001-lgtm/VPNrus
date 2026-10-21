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
#
# Optional overrides (used by .github/workflows/android-ci.yml; unset = the WSL defaults below):
#   NOVA_BUILD_ROOT    disposable clone root      (default: ~/build)
#   NOVA_ANDROID_HOME  Android SDK                (default: ~/android-sdk)
#   NOVA_JAVA_HOME     JDK 17                     (default: /usr/lib/jvm/java-17-openjdk-amd64)
# gomobile takes the NDK from ANDROID_NDK_HOME when set, else the newest one under the SDK.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=VERSION
source "$HERE/VERSION"

BUILD_ROOT="${NOVA_BUILD_ROOT:-$HOME/build}"
WORK="$BUILD_ROOT/androidlibxraylite"
CORE_WORK="$BUILD_ROOT/xray-core-nova"
ANDROID_HOME="${NOVA_ANDROID_HOME:-$HOME/android-sdk}"
PATCH_FILE="$HERE/$XRAY_CORE_PATCH_0001"

mkdir -p "$BUILD_ROOT"

if [ ! -d "$CORE_WORK/.git" ]; then
    git clone "$XRAY_CORE_REPO" "$CORE_WORK"
fi

cd "$CORE_WORK"
git fetch -q
git checkout -q "$XRAY_CORE_COMMIT"
git reset --hard -q "$XRAY_CORE_COMMIT"
git clean -fdx -q

actual_core_sha=$(git rev-parse HEAD)
if [ "$actual_core_sha" != "$XRAY_CORE_COMMIT" ]; then
    echo "ERROR: xray-core resolved to $actual_core_sha, expected $XRAY_CORE_COMMIT" >&2
    exit 1
fi

echo "$XRAY_CORE_PATCH_0001_SHA256  $PATCH_FILE" | sha256sum -c -
git apply --check "$PATCH_FILE"
git apply "$PATCH_FILE"

go test ./transport/internet/splithttp \
    -run '^TestNovaXhttpDialTimeout' \
    -count=1

if [ ! -d "$WORK/.git" ]; then
    git clone "$WRAPPER_REPO" "$WORK"
fi

cd "$WORK"
git fetch -q
git checkout -q "$WRAPPER_COMMIT"
git reset --hard -q "$WRAPPER_COMMIT"
git clean -fdx -q

actual_sha=$(git rev-parse HEAD)
if [ "$actual_sha" != "$WRAPPER_COMMIT" ]; then
    echo "ERROR: pinned commit resolved to $actual_sha, expected $WRAPPER_COMMIT" >&2
    exit 1
fi

export JAVA_HOME="${NOVA_JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_HOME="$ANDROID_HOME"
export PATH="$(go env GOPATH)/bin:$PATH"

go version | grep -q "go${GO_VERSION_REQUIRED%%.*}\." || {
    echo "WARNING: expected a go${GO_VERSION_REQUIRED} toolchain, found: $(go version)" >&2
}

# Build the pinned wrapper against the separately verified/patched copy of
# the exact pinned xray-core commit. This modifies only the disposable build
# checkout; VERSION + the tracked patch remain the repository authority.
go mod edit -replace="github.com/xtls/xray-core=$CORE_WORK"

go install golang.org/x/mobile/cmd/gomobile@"$GOMOBILE_VERSION"
go install golang.org/x/mobile/cmd/gobind@"$GOMOBILE_VERSION"

gomobile init

go mod tidy -v
go mod verify

gomobile bind -v \
    -androidapi "$ANDROID_API_LEVEL" \
    -trimpath \
    -ldflags='-s -w -buildid= -checklinkname=0' \
    ./

OUT="$WORK/libv2ray.aar"

echo "Built: $OUT"
echo "Patchset: $XRAY_CORE_PATCHSET"
echo "Copy this file into android/app/libs/libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar"
