#!/usr/bin/env bash
# B8K2A - the real activation logic behind gateway/privileged/nova-xray-reload.
# Root-run in production (via the thin wrapper's fixed exec chain - see that
# file); directly testable without root against an isolated fixture tree,
# same convention as gateway/scripts/provision-peer.sh's own split from
# gateway/privileged/pocvpn-provision-peer.
#
#   xray-activate.sh
#
# Takes NO arguments - every path is fixed, sourced from an env file
# (mirrors gateway/lib/common.sh's load_config for the AWG side). This is
# deliberate: nothing about which files this script touches is ever
# influenced by a caller-supplied ARGUMENT.
#
# B26 (task F) - which env file is sourced IS configurable, but only via
# XRAY_ACTIVATE_ENV_FILE, an ENVIRONMENT VARIABLE the privileged wrapper
# sets explicitly (never a CLI argument, never inherited from an arbitrary
# caller - gateway/privileged/nova-xray-reload and its ingress-role
# counterpart nova-xray-ingress-reload each `env -i` a fixed, hardcoded
# value before exec'ing this script - see each wrapper's own docstring).
# Defaults to config/xray.env - the ORIGINAL fixed path - so every
# pre-B26 gateway deployment is byte-for-byte unaffected; an ingress
# deployment's wrapper points this at config/xray-ingress.env instead,
# letting the two roles share this ONE validate/stage/publish/rollback
# implementation rather than maintaining a near-duplicate copy.
#
# --- IMPORTANT, VERIFIED FINDING (not assumed) ---
# `xray run -test -c <file>` was tested against the actual pinned v26.7.28
# binary this slice: it exits 0 in EVERY case tried (valid config, invalid
# privateKey, malformed JSON, missing file) - the exit code is NOT a
# validation signal for this binary. The only reliable signal is textual:
# stdout+stderr contain the literal line "Configuration OK." on success, or
# "Failed to start: ..." on failure. This script greps for "Configuration OK."
# specifically - do not "simplify" this back to checking $? without
# re-verifying against the pinned binary first.
#
# --- stdout contract (mirrors provision-peer.sh's style) ---
# Success: exactly one line, tab-separated:
#   activated<TAB><sha256 of the newly-published live config>
# Failure: stdout is empty; the exit code distinguishes which failure:
#   20 = usage error (unexpected arguments)
#   21 = staging config missing/empty
#   22 = candidate config failed `xray run -test` validation - live config
#        and running service are UNTOUCHED
#   23 = candidate validated, but publish+restart did not converge to
#        active - the PREVIOUS known-good config was restored and the
#        service was restarted with it (best-effort); overall result is
#        still failure
#   24 = candidate validated, publish+restart did not converge, AND
#        restoring the previous config also failed to bring the service
#        back to active - the most severe case, needs operator attention
# All logs/diagnostics go to stderr only (log()/die() from lib/common.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck disable=SC1090
source "${XRAY_ACTIVATE_ENV_FILE:-$SCRIPT_DIR/config/xray.env}"

[ $# -eq 0 ] || { echo "usage: xray-activate.sh (no arguments)" >&2; exit 20; }

[ -s "$XRAY_STAGING_CONFIG" ] || { log "staging config missing or empty: $XRAY_STAGING_CONFIG"; exit 21; }

# --- validate (see this file's own header for why textual, not exit-code) ---
validation_output="$("$XRAY_BIN_PATH" run -test -c "$XRAY_STAGING_CONFIG" 2>&1 || true)"
if ! grep -q "Configuration OK\." <<< "$validation_output"; then
    log "candidate config failed validation - live config and service untouched"
    log "xray output: $validation_output"
    exit 22
fi

mkdir -p "$XRAY_LIVE_CONFIG_DIR"

# --- back up the current live config (if any) before touching it ---
had_previous=0
if [ -f "$XRAY_LIVE_CONFIG" ]; then
    cp -p "$XRAY_LIVE_CONFIG" "$XRAY_BACKUP_CONFIG"
    had_previous=1
fi

# --- atomic publish: write to a tmp file in the SAME directory as the live
# path, set final ownership/mode, then rename - rename within one
# directory is atomic, so nova-xray.service never observes a partially
# written config file. ---
tmp_path="$(mktemp "$XRAY_LIVE_CONFIG_DIR/.config.XXXXXX")"
cp "$XRAY_STAGING_CONFIG" "$tmp_path"
chown "$XRAY_LIVE_CONFIG_OWNER:$XRAY_LIVE_CONFIG_GROUP" "$tmp_path"
chmod "$XRAY_LIVE_CONFIG_MODE" "$tmp_path"
mv -f "$tmp_path" "$XRAY_LIVE_CONFIG"

log "restarting $XRAY_SERVICE_NAME.service with the newly published config"
systemctl restart "$XRAY_SERVICE_NAME.service" || true

if systemctl is-active --quiet "$XRAY_SERVICE_NAME.service"; then
    published_sha256="$(sha256sum "$XRAY_LIVE_CONFIG" | awk '{print $1}')"
    printf 'activated\t%s\n' "$published_sha256"
    exit 0
fi

log "$XRAY_SERVICE_NAME.service did not become active with the new config - attempting rollback"

if [ "$had_previous" -ne 1 ]; then
    log "no previous config to roll back to - service left in its current (inactive) state"
    exit 23
fi

mv -f "$XRAY_BACKUP_CONFIG" "$XRAY_LIVE_CONFIG"
chown "$XRAY_LIVE_CONFIG_OWNER:$XRAY_LIVE_CONFIG_GROUP" "$XRAY_LIVE_CONFIG"
chmod "$XRAY_LIVE_CONFIG_MODE" "$XRAY_LIVE_CONFIG"
systemctl restart "$XRAY_SERVICE_NAME.service" || true

if systemctl is-active --quiet "$XRAY_SERVICE_NAME.service"; then
    log "rolled back to the previous known-good config; service is active again"
    exit 23
fi

log "rollback restart ALSO failed to bring $XRAY_SERVICE_NAME.service to active - operator attention required"
exit 24
