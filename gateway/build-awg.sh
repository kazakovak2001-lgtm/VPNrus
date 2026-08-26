#!/usr/bin/env bash
# Builds and installs amneziawg-go + amneziawg-tools pinned to the exact
# commits verified compatible with the pinned Android client (B5A / B2.6).
# Never floats to master/latest - refuses to proceed if the resolved tag
# does not match the pinned commit SHA below.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config

# Pinned upstream sources. Update both TAG and SHA together, deliberately,
# and re-run B5A-style compatibility verification before changing these.
AWG_GO_REPO="https://github.com/amnezia-vpn/amneziawg-go.git"
AWG_GO_TAG="v3.1.20260814"
AWG_GO_SHA="1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1"

AWG_TOOLS_REPO="https://github.com/amnezia-vpn/amneziawg-tools.git"
AWG_TOOLS_TAG="v3.1.20260812"
AWG_TOOLS_SHA="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"

clone_and_pin() {
    local repo_url=$1 dir=$2 tag=$3 expected_sha=$4
    if [ ! -d "$dir/.git" ]; then
        log "cloning $repo_url"
        git clone -q "$repo_url" "$dir"
    fi
    ( cd "$dir" && git fetch -q --tags origin )
    ( cd "$dir" && git checkout -q "$tag" )
    local actual_sha
    actual_sha=$(cd "$dir" && git rev-parse HEAD)
    if [ "$actual_sha" != "$expected_sha" ]; then
        die "$dir: tag $tag resolved to $actual_sha, expected $expected_sha - refusing to build an unverified revision"
    fi
    log "$dir pinned at $tag ($actual_sha)"
}

mkdir -p "$BUILD_DIR"

clone_and_pin "$AWG_GO_REPO" "$BUILD_DIR/amneziawg-go" "$AWG_GO_TAG" "$AWG_GO_SHA"
clone_and_pin "$AWG_TOOLS_REPO" "$BUILD_DIR/amneziawg-tools" "$AWG_TOOLS_TAG" "$AWG_TOOLS_SHA"

command -v go >/dev/null || die "Go toolchain not found (amneziawg-go requires Go >= 1.25). Install golang-go first."
command -v cc >/dev/null || command -v gcc >/dev/null || die "C compiler not found (amneziawg-tools requires one)."

log "building amneziawg-go"
( cd "$BUILD_DIR/amneziawg-go" && make )

log "building amneziawg-tools"
( cd "$BUILD_DIR/amneziawg-tools/src" && make )

log "installing binaries to /usr/local/bin"
install -v -m 0755 "$BUILD_DIR/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go
install -v -m 0755 "$BUILD_DIR/amneziawg-tools/src/wg" /usr/local/bin/awg
install -v -m 0755 "$BUILD_DIR/amneziawg-tools/src/wg-quick/linux.bash" /usr/local/bin/awg-quick
install -v -m 0700 -d "$CONFIG_DIR"

log "installed: $(awg --version 2>&1 || echo 'version string unavailable')"
