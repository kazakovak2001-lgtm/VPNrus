#!/usr/bin/env bash
# Automatic tunnel-IP allocation on top of the existing manual add-peer.sh.
#
#   sudo ./allocate-and-add-peer.sh <CLIENT_PUBLIC_KEY> [label]
#
# Prints the allocated tunnel IP (and nothing else) to stdout on success.
# The manual `add-peer.sh <PUBLIC_KEY> <TUNNEL_IP> [label]` path is
# unmodified and remains the supported fallback for a caller-chosen IP.
#
# This CLI contract is unchanged by B8B1A: a public key that already has a
# peer is still REJECTED (via mutate_add_peer's own "already exists"
# check), not treated as idempotent - that idempotent behavior lives only
# in the new machine-facing scripts/provision-peer.sh, which is the sole
# entry point future automated callers (B8B1's HTTP API) are expected to
# use. This script remains the manual/human "always allocate a fresh IP,
# reject if the key is already provisioned" tool.
#
# Allocation is derived entirely from the live gateway config (the same
# file add-peer.sh writes to, via the shared lib/peer_mutations.sh core) -
# there is no separate ledger that could drift from it. The whole
# read-choose-add-converge sequence happens under one exclusive flock so
# two concurrent callers can never receive the same IP; the lock is
# released only after the peer write AND live-state convergence have
# actually succeeded (or the whole allocation is abandoned and nothing is
# reported allocated).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY> [label]" >&2; exit 2; }
[ $# -ge 1 ] || usage
PUBLIC_KEY=$1
LABEL=${2:-peer-$(date +%s 2>/dev/null || echo unlabeled)}

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"

LOCK_FILE="$CONFIG_DIR/.provision.lock"

exec 9>"$LOCK_FILE"
flock -x 9

# --- everything below runs with the exclusive lock held ---

# allocate_lowest_free_ip (lib/peer_mutations.sh, shared with
# scripts/provision-peer.sh - see B8B1A) returns 3 specifically for
# subnet exhaustion; any other internal failure has already die()'d with
# its own message before returning here. Only the exhaustion case gets
# this script's own die() message, so the CLI's existing wording for
# operators is unchanged.
alloc_rc=0
CHOSEN_IP=$(allocate_lowest_free_ip) || alloc_rc=$?
if [ "$alloc_rc" -eq 3 ]; then
    die "subnet $AWG_SUBNET_CIDR is exhausted - no free tunnel address available"
elif [ "$alloc_rc" -ne 0 ]; then
    exit "$alloc_rc"
fi

log "allocated $CHOSEN_IP for '$LABEL' - applying"
# In-process calls, not a subprocess exec of add-peer.sh: both mutate_add_peer
# and converge_live_state assume the caller already holds .provision.lock
# (acquired above) and must never re-acquire it themselves - a subprocess
# that tried to `flock` its own fresh fd on this same lock file, while this
# script synchronously waited for it, would deadlock (see peer_mutations.sh).
mutate_add_peer "$PUBLIC_KEY" "$CHOSEN_IP" "$LABEL"
converge_live_state present "$PUBLIC_KEY"

# mutate_add_peer/converge_live_state (set -e, common.sh's `die`) would have
# already exited non-zero on any failure, so reaching here means the peer
# write AND live convergence genuinely succeeded - only now is it safe to
# report the IP as allocated.
echo "$CHOSEN_IP"
