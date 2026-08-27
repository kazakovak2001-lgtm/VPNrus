#!/usr/bin/env bash
# B8B1A: idempotent, machine-facing peer provisioning. This is the ONLY
# gateway entry point future automated callers (the B8B1 localhost HTTP
# API) are expected to invoke - it owns the entire transaction itself and
# acquires .provision.lock exactly once. It must NEVER be invoked while
# something else already holds that same lock, and it must NEVER shell out
# to another locking script (add-peer.sh / remove-peer.sh /
# allocate-and-add-peer.sh) while holding it - doing so would either
# deadlock (a subprocess trying to flock the same already-held lock file)
# or, if the lock were somehow re-entrant, defeat the whole point of one
# lock acquisition per transaction. Only the unlocked lib/peer_mutations.sh
# functions are called, in-process, exactly like allocate-and-add-peer.sh
# and add-peer.sh/remove-peer.sh already do.
#
#   provision-peer.sh <CLIENT_PUBLIC_KEY>
#
# Exactly one caller-controlled argument - deliberately no label parameter.
# A future HTTP caller's request body must never be able to inject
# free-form text into a config file comment; the diagnostic label used
# here is generated internally from fixed, safe data only.
#
# --- stdout contract ---
# On success, stdout is EXACTLY one line, tab-separated, and nothing else:
#   created<TAB><ip>      a new peer was allocated and durably persisted
#   existing<TAB><ip>     a peer for this public key already existed
#     (this is the idempotency path: a caller that retries after a lost
#     HTTP response, or sends the same request twice, lands here on the
#     second attempt and gets back the SAME ip - no second IP is ever
#     allocated for an already-provisioned key)
# All logs/diagnostics go to stderr only, via log()/die() (lib/common.sh) -
# never to stdout, so a caller can safely treat stdout as machine-readable.
#
# --- exit code contract ---
#   0  = success - see stdout (created/existing) to distinguish which
#   20 = subnet exhausted (no free tunnel address available) - a dedicated
#        code so a future HTTP layer can map this straight to 503 without
#        parsing English stderr text
#   2  = usage error (wrong argument count)
#   1  = any other failure: invalid public key, missing/malformed gateway
#        config, malformed or ambiguous existing peer state for this key
#        (fails closed - see find_existing_peer in lib/peer_mutations.sh),
#        or a mutation/convergence failure. Generic for this smallest
#        slice, per the B8B1A design - the specific reason is always on
#        stderr via die()/log().
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY>" >&2; exit 2; }
[ $# -eq 1 ] || usage
PUBLIC_KEY=$1

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"

LOCK_FILE="$CONFIG_DIR/.provision.lock"
exec 9>"$LOCK_FILE"
flock -x 9

# --- everything below runs with the exclusive lock held, exactly once,
#     across the entire lookup -> allocate/mutate -> converge sequence ---

# find_existing_peer's three-valued return (0 found / 1 absent / 2
# malformed) is deliberately checked in full, not just "did it succeed" -
# see lib/peer_mutations.sh for why collapsing "absent" and "malformed"
# into one signal would be unsafe here.
find_rc=0
EXISTING_IP=$(find_existing_peer "$PUBLIC_KEY") || find_rc=$?

if [ "$find_rc" -eq 0 ]; then
    # Idempotency path: do NOT mutate, do NOT allocate another IP. Still
    # verify/repair live convergence - the durable config could already
    # have this peer while the live AWG interface is stale (e.g. this is a
    # retry after a prior convergence failure), and that must still be
    # detected and repaired here, not silently skipped just because the
    # peer already existed.
    converge_live_state present "$PUBLIC_KEY"
    printf 'existing\t%s\n' "$EXISTING_IP"
    exit 0
fi

if [ "$find_rc" -eq 2 ]; then
    die "durable peer state for this public key is malformed or ambiguous - refusing to provision (fail closed)"
fi

# find_rc == 1: no peer for this key exists yet - allocate one. (A missing
# gateway config file would also have already die()'d inside
# find_existing_peer itself, before reaching here.)
alloc_rc=0
CHOSEN_IP=$(allocate_lowest_free_ip) || alloc_rc=$?
if [ "$alloc_rc" -eq 3 ]; then
    exit 20
elif [ "$alloc_rc" -ne 0 ]; then
    exit "$alloc_rc"
fi

LABEL="provision-peer-$(date +%s 2>/dev/null || echo unlabeled)"
mutate_add_peer "$PUBLIC_KEY" "$CHOSEN_IP" "$LABEL"
converge_live_state present "$PUBLIC_KEY"
printf 'created\t%s\n' "$CHOSEN_IP"
