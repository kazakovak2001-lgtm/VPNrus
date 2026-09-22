#!/usr/bin/env bash
# B46-4P - reproducible fetch of the pinned SERVER-side Hysteria2 release
# binary. Downloads the exact asset pinned in VERSION, verifies its
# sha256 BEFORE installing anything, and installs it to a version-named,
# immutable directory - never overwrites a previous install, never
# "latest"-symlinks without an explicit, separate activation step.
# Mirrors gateway/xray/fetch-xray-server.sh's own shape/discipline
# exactly (see that file for the reference implementation this was
# adapted from - Hysteria2 ships a single binary, no zip/unzip step).
#
# This is NOT run against Stockholm in this slice (see
# gateway/hysteria/README.md - no deployment yet, and VERSION's own
# "LICENSING DECISION REQUIRED" GAP must be resolved by the repository
# owner before this asset is actually installed on any production host).
# It is a real, runnable script, reproducible from a clean host.
#
#   bash gateway/hysteria/fetch-hysteria-server.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=VERSION
source "$HERE/VERSION"

if ! [[ "$HYSTERIA_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: HYSTERIA_COMMIT in $HERE/VERSION is not a well-formed 40-char lowercase hex commit: ${HYSTERIA_COMMIT:-<unset>}" >&2
    exit 1
fi

# Fail closed on an unset/placeholder checksum - never silently proceed
# with "verification" that isn't actually a known-in-advance value (see
# VERSION's own docs on why this value is real, not fabricated - this
# check exists so a FUTURE bump that forgets to fill it in fails loudly
# here, rather than downloading-then-trusting whatever arrives).
if ! [[ "$HYSTERIA_RELEASE_ASSET_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: HYSTERIA_RELEASE_ASSET_SHA256 in $HERE/VERSION is not a well-formed 64-char lowercase hex sha256: ${HYSTERIA_RELEASE_ASSET_SHA256:-<unset>}" >&2
    exit 1
fi

INSTALL_ROOT="${HYSTERIA_INSTALL_ROOT:-/opt/pocvpn/hysteria}"
VERSIONED_DIR="$INSTALL_ROOT/$HYSTERIA_TAG"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -d "$VERSIONED_DIR" ]; then
    echo "already installed: $VERSIONED_DIR (remove it explicitly to re-fetch)" >&2
    exit 0
fi

echo "Downloading $HYSTERIA_RELEASE_ASSET_URL ..."
curl -fsSL -o "$WORK/$HYSTERIA_RELEASE_ASSET" "$HYSTERIA_RELEASE_ASSET_URL"

actual_sha256="$(sha256sum "$WORK/$HYSTERIA_RELEASE_ASSET" | awk '{print $1}')"
if [ "$actual_sha256" != "$HYSTERIA_RELEASE_ASSET_SHA256" ]; then
    echo "ERROR: checksum mismatch for $HYSTERIA_RELEASE_ASSET" >&2
    echo "  expected: $HYSTERIA_RELEASE_ASSET_SHA256" >&2
    echo "  actual:   $actual_sha256" >&2
    exit 1
fi

# No archive to extract - Hysteria2's release asset is a single, already-
# executable binary (unlike Xray-linux-64.zip's own zip+geoip/geosite
# layout).
mkdir -p "$WORK/extract"
cp "$WORK/$HYSTERIA_RELEASE_ASSET" "$WORK/extract/hysteria"
chmod 755 "$WORK/extract/hysteria"

actual_version="$("$WORK/extract/hysteria" version 2>&1 || true)"
# Hysteria2's own `version` subcommand prints its own release tag/commit -
# a token-aware match (never a loose substring test) against the pinned
# SHORT commit form, the same discipline fetch-xray-server.sh already
# uses and for the same reason: a bare substring test risks a false
# positive against an unrelated longer hex run.
EXPECTED_SHORT_COMMIT="${HYSTERIA_COMMIT:0:7}"
commit_matched=0
for token in $actual_version; do
    if [ "$token" = "$EXPECTED_SHORT_COMMIT" ] || [ "$token" = "$HYSTERIA_COMMIT" ]; then
        commit_matched=1
        break
    fi
done
if [ "$commit_matched" -ne 1 ]; then
    echo "WARNING: extracted binary's own 'version' output does not visibly report the pinned commit ($HYSTERIA_COMMIT / short $EXPECTED_SHORT_COMMIT)." >&2
    echo "  got: $actual_version" >&2
    echo "  Proceeding anyway - the SHA-256 check above is the authoritative proof of provenance;" >&2
    echo "  this is a best-effort secondary confirmation only (Hysteria2's own version output format is not pinned/verified by this project the way xray-core's was)." >&2
fi

# mkdir -p "$(dirname "$VERSIONED_DIR")", NOT "$INSTALL_ROOT": unlike
# Xray's flat tag ("v26.7.28"), Hysteria2's own tag convention contains a
# literal slash ("app/v2.12.3" - see VERSION), so VERSIONED_DIR has an
# intermediate path component ("$INSTALL_ROOT/app") that a plain
# `mkdir -p "$INSTALL_ROOT"` would never create, causing `mv` below to
# fail with "No such file or directory" - found by this script's own test
# suite, not assumed safe by analogy with fetch-xray-server.sh.
mkdir -p "$(dirname "$VERSIONED_DIR")"
mv "$WORK/extract" "$VERSIONED_DIR"

echo "Installed: $VERSIONED_DIR"
echo "Binary:    $VERSIONED_DIR/hysteria"
echo ""
echo "*** DO NOT install/run this on a production host yet ***"
echo "See gateway/hysteria/VERSION's own 'LICENSING DECISION REQUIRED' GAP"
echo "(the official binary asset links GPL-3.0-or-later sing-tun code even"
echo "in server mode) - the repository owner must decide before this binary"
echo "is actually deployed. See gateway/hysteria/README.md for the full"
echo "remaining B46-4P checklist (port, TLS/SNI, systemd, signed manifest)."
