#!/usr/bin/env bash
# B8K2 - reproducible fetch of the pinned SERVER-side Xray-core release
# binary. Downloads the exact asset pinned in VERSION, verifies its
# sha256 before extracting anything, and installs it to a version-named,
# immutable directory - never overwrites a previous install, never
# "latest"-symlinks without an explicit, separate activation step.
#
# This is NOT run against Oracle in this slice (see gateway/xray/README.md -
# no deployment yet). It is a real, runnable script, reproducible from a
# clean host.
#
#   sudo bash gateway/xray/fetch-xray-server.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=VERSION
source "$HERE/VERSION"

INSTALL_ROOT="${XRAY_INSTALL_ROOT:-/opt/pocvpn/xray}"
VERSIONED_DIR="$INSTALL_ROOT/$XRAY_CORE_TAG"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -d "$VERSIONED_DIR" ]; then
    echo "already installed: $VERSIONED_DIR (remove it explicitly to re-fetch)" >&2
    exit 0
fi

echo "Downloading $XRAY_RELEASE_ASSET_URL ..."
curl -fsSL -o "$WORK/$XRAY_RELEASE_ASSET" "$XRAY_RELEASE_ASSET_URL"

actual_sha256="$(sha256sum "$WORK/$XRAY_RELEASE_ASSET" | awk '{print $1}')"
if [ "$actual_sha256" != "$XRAY_RELEASE_ASSET_SHA256" ]; then
    echo "ERROR: checksum mismatch for $XRAY_RELEASE_ASSET" >&2
    echo "  expected: $XRAY_RELEASE_ASSET_SHA256" >&2
    echo "  actual:   $actual_sha256" >&2
    exit 1
fi

mkdir -p "$WORK/extract"
unzip -q "$WORK/$XRAY_RELEASE_ASSET" -d "$WORK/extract"

actual_version="$("$WORK/extract/xray" version | head -1)"
if [[ "$actual_version" != *"$XRAY_CORE_COMMIT"* ]]; then
    echo "ERROR: extracted binary's own 'version' output does not mention the pinned commit $XRAY_CORE_COMMIT" >&2
    echo "  got: $actual_version" >&2
    exit 1
fi

mkdir -p "$INSTALL_ROOT"
mv "$WORK/extract" "$VERSIONED_DIR"
chmod 755 "$VERSIONED_DIR/xray"
# geoip.dat/geosite.dat are only needed if a future config's routing rules
# reference them - this slice's minimal single-outbound VLESS+REALITY
# config does not, but they are kept installed for that future case.

echo "Installed: $VERSIONED_DIR"
echo "Binary:    $VERSIONED_DIR/xray"
echo "Next: point nova-xray.service's ExecStart at this exact path (see"
echo "gateway/systemd/nova-xray.service), generate REALITY keys with"
echo "gateway/xray/scripts/generate-reality-keys.sh, then render a config"
echo "with gateway/api/xray_config_renderer.py before ever starting the unit."
