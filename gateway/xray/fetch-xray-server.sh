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

# B31B - the canonical pinned fact stays the FULL 40-char commit
# (XRAY_CORE_COMMIT, unchanged by this fix) - `xray version`'s own output
# only ever reports the SHORT (7-char) git commit, never the full one (a
# real fetch of the genuinely-pinned v26.7.28 asset - SHA256-verified -
# reported "... 5ca6f4b ..." for pinned commit
# "5ca6f4b7d4dc20a881d4330e498892697627ec0c", found live). This derives
# the short form ONCE, from the canonical full value, rather than
# hardcoding a second pinned constant that could drift from VERSION.
if ! [[ "$XRAY_CORE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: XRAY_CORE_COMMIT in $HERE/VERSION is not a well-formed 40-char lowercase hex commit: ${XRAY_CORE_COMMIT:-<unset>}" >&2
    exit 1
fi
EXPECTED_SHORT_COMMIT="${XRAY_CORE_COMMIT:0:7}"

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
# B31B - token-aware match (an exact whitespace-delimited word equals the
# EXPECTED SHORT commit), never a loose substring check against the full
# 40-char value - see this file's own docs above for why the full value
# can never appear in this output at all, and why a bare substring test
# would also risk a false-positive match against an unrelated longer hex
# run that merely happens to contain this short token.
commit_matched=0
for token in $actual_version; do
    if [ "$token" = "$EXPECTED_SHORT_COMMIT" ]; then
        commit_matched=1
        break
    fi
done
if [ "$commit_matched" -ne 1 ]; then
    echo "ERROR: extracted binary's own 'version' output does not report the pinned commit's short form ($EXPECTED_SHORT_COMMIT, derived from the full pinned $XRAY_CORE_COMMIT)" >&2
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
