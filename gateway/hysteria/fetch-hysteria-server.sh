#!/usr/bin/env bash
# B46-4P.3 - reproducible fetch of the pinned SERVER-side Hysteria2 release
# binary (same model as gateway/xray/fetch-xray-server.sh). Downloads the
# exact asset pinned in VERSION, verifies its sha256 BEFORE executing it,
# checks the binary's own reported commit, and installs it to a
# version-named directory - never overwrites an existing install.
#
# Not run against any host by B46-4P.3 (deployment preparation only).
#
#   sudo bash gateway/hysteria/fetch-hysteria-server.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=VERSION
source "$HERE/VERSION"

if ! [[ "$HYSTERIA_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: HYSTERIA_COMMIT in $HERE/VERSION is not a 40-char lowercase hex commit: ${HYSTERIA_COMMIT:-<unset>}" >&2
    exit 1
fi

INSTALL_ROOT="${HYSTERIA_INSTALL_ROOT:-/opt/pocvpn/hysteria}"
VERSIONED_DIR="$INSTALL_ROOT/$HYSTERIA_VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -d "$VERSIONED_DIR" ]; then
    echo "already installed: $VERSIONED_DIR (remove it explicitly to re-fetch)" >&2
    exit 0
fi

echo "Downloading $HYSTERIA_RELEASE_ASSET_URL ..."
curl -fsSL -o "$WORK/hysteria" "$HYSTERIA_RELEASE_ASSET_URL"

actual_sha256="$(sha256sum "$WORK/hysteria" | awk '{print $1}')"
if [ "$actual_sha256" != "$HYSTERIA_RELEASE_ASSET_SHA256" ]; then
    echo "ERROR: checksum mismatch for $HYSTERIA_RELEASE_ASSET" >&2
    echo "  expected: $HYSTERIA_RELEASE_ASSET_SHA256" >&2
    echo "  actual:   $actual_sha256" >&2
    exit 1
fi
chmod 755 "$WORK/hysteria"

# `hysteria version` prints "CommitHash:<TAB><full 40-char commit>".
reported_commit="$("$WORK/hysteria" version --disable-update-check | awk '$1 == "CommitHash:" {print $2}')"
if [ "$reported_commit" != "$HYSTERIA_COMMIT" ]; then
    echo "ERROR: binary reports commit '${reported_commit:-<none>}', pinned $HYSTERIA_COMMIT" >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$VERSIONED_DIR"
install -o root -g root -m 0755 "$WORK/hysteria" "$VERSIONED_DIR/hysteria"

echo "Installed: $VERSIONED_DIR/hysteria"
echo "Next: see gateway/DEPLOYMENT.md 'Hysteria2 on Stockholm (B46-4P.3)'."
