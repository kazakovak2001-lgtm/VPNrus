#!/usr/bin/env bash
# B47 T1: AWG entitlement desired-state reconcile - removes AWG peers whose
# entitlement (activation or legacy enrollment token) is revoked or expired.
# Run as root by pocvpn-awg-reconcile.service (timer + revoke trigger) -
# never through pocvpn-api's sudoers (the API gains no removal privilege).
#
#   reconcile-peers.sh --env-file /etc/pocvpn/api.env [--dry-run]
#
# Sequence (entirely under ONE exclusive .provision.lock acquisition, the
# same single serialization authority provision-peer.sh/add-peer.sh/
# remove-peer.sh use):
#   1. list the peers currently in awg0.conf
#   2. ask tools/awg_reconcile.py (read-only planner) which of them belong
#      to a revoked/expired entitlement - the planner reads the stores
#      WHILE this lock is held, so a concurrent /v1/activate either bound
#      its key before the snapshot (-> kept) or its provision-peer.sh is
#      still blocked on this lock and re-adds the peer afterwards
#   3. remove exactly those peers (idempotent), then confirm live state
#
# Safety rules:
#   - the planner failing for ANY reason (store missing/unreadable/malformed,
#     naive expiry, odd awg0.conf) aborts BEFORE any mutation - an
#     incomplete view of entitlement never drives deletions
#   - peers unknown to every store are reported by the planner, never removed
#   - a malformed durable entry for a planned key is skipped (reported,
#     non-zero exit), never "repaired" by deletion
#
# Lock order: .provision.lock -> (activation/token store shared locks,
# momentary, inside the planner). The API never waits on .provision.lock
# while holding a store lock (it holds only its per-activation lock), and
# this script never takes a per-activation lock - no cycle.
#
# Exit codes: 0 = converged (or dry run); 1 = mutation/convergence failure
# or at least one planned key skipped as malformed; 2 = usage;
# 3 = planner refused (fail closed, nothing changed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
load_config

usage() { echo "usage: $0 --env-file <PATH> [--dry-run]" >&2; exit 2; }

ENV_FILE=""
DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --env-file) [ $# -ge 2 ] || usage; ENV_FILE=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) usage ;;
    esac
done
[ -n "$ENV_FILE" ] || usage

PLANNER="$SCRIPT_DIR/tools/awg_reconcile.py"
# Test-harness overrides only (run_tests.sh); the systemd unit sets neither.
PYTHON_BIN="${POCVPN_RECONCILE_PYTHON:-python3}"
CONFIG_PATH="$CONFIG_DIR/$CONFIG_FILE"

LOCK_FILE="$CONFIG_DIR/.provision.lock"
exec 9>"$LOCK_FILE"
flock -x 9

[ -f "$CONFIG_PATH" ] || die "gateway config not found at $CONFIG_PATH - nothing reconciled"

# Everything below runs with the exclusive lock held.
planner_rc=0
# awk (not grep): zero peers is a normal, successful empty list, while an
# unreadable file is still a hard error under pipefail.
PLAN=$(awk '/^PublicKey = / { sub(/^PublicKey = /, ""); print }' "$CONFIG_PATH" \
    | "$PYTHON_BIN" "$PLANNER" --env-file "$ENV_FILE" ${POCVPN_RECONCILE_NOW:+--now "$POCVPN_RECONCILE_NOW"}) || planner_rc=$?
if [ "$planner_rc" -ne 0 ]; then
    log "reconcile aborted: planner refused (rc=$planner_rc) - FAIL CLOSED, no peer removed"
    exit 3
fi

mapfile -t TO_REMOVE < <(printf '%s\n' "$PLAN" | sed '/^$/d')
for key in "${TO_REMOVE[@]}"; do
    is_valid_wg_key "$key" || die "planner produced a malformed key - refusing to act on its output"
done

if [ "${#TO_REMOVE[@]}" -eq 0 ]; then
    log "reconcile: no revoked/expired peer present - already converged"
    exit 0
fi

if [ "$DRY_RUN" -eq 1 ]; then
    for key in "${TO_REMOVE[@]}"; do
        log "dry-run: would remove peer ${key:0:8}... (revoked/expired entitlement)"
    done
    exit 0
fi

skipped=0
removed=()
for key in "${TO_REMOVE[@]}"; do
    rc=0
    mutate_remove_peer_if_present "$key" || rc=$?
    if [ "$rc" -eq 0 ]; then
        removed+=("$key")
        log "removed peer ${key:0:8}... (revoked/expired entitlement)"
    else
        skipped=$((skipped + 1))
        log "skipped peer ${key:0:8}...: malformed durable entry - investigate manually"
    fi
done

# Durable state is final above; now make the live interface reflect it.
# The first converge reloads (awg syncconf applies every removal at once);
# the remaining calls find the live state already matching.
for key in "${removed[@]}"; do
    converge_live_state absent "$key"
done

if [ "$skipped" -ne 0 ]; then
    die "reconcile finished with $skipped planned peer(s) skipped as malformed"
fi
log "reconcile: removed ${#removed[@]} peer(s)"
