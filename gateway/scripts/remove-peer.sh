#!/usr/bin/env bash
# Removes a peer by public key.
#
#   sudo ./remove-peer.sh <CLIENT_PUBLIC_KEY>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY>" >&2; exit 2; }
[ $# -ge 1 ] || usage
PUBLIC_KEY=$1

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"

LOCK_FILE="$CONFIG_DIR/.provision.lock"
exec 9>"$LOCK_FILE"
flock -x 9

mutate_remove_peer "$PUBLIC_KEY"
converge_live_state absent "$PUBLIC_KEY"
