#!/usr/bin/env bash
# Manual POC-01 peer provisioning.
#
#   sudo ./add-peer.sh <CLIENT_PUBLIC_KEY> <CLIENT_TUNNEL_IP> [label]
#
# Input is the client's PUBLIC key only. This script has no parameter for a
# private key - there is nothing to paste one into. Note: AmneziaWG/WireGuard
# public and private keys are both 32-byte base64 blobs and are NOT
# distinguishable by format alone, so this is a procedural safeguard, not a
# cryptographic one - never paste a private key on this command line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY> <CLIENT_TUNNEL_IP> [label]" >&2; exit 2; }

[ $# -ge 2 ] || usage
PUBLIC_KEY=$1
TUNNEL_IP=$2
LABEL=${3:-peer-$(date +%s 2>/dev/null || echo unlabeled)}

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"
ip_in_cidr "$TUNNEL_IP" "$AWG_SUBNET_CIDR" || die "$TUNNEL_IP is not inside the POC subnet $AWG_SUBNET_CIDR"
[ "$TUNNEL_IP" != "$GATEWAY_TUNNEL_IP" ] || die "$TUNNEL_IP is the gateway's own tunnel address, cannot also be a peer"

# Existing-peer/existing-IP lookups happen inside mutate_add_peer, under
# this lock - never before it, so two concurrent manual invocations can
# never both decide "not a duplicate" and race each other.
LOCK_FILE="$CONFIG_DIR/.provision.lock"
exec 9>"$LOCK_FILE"
flock -x 9

mutate_add_peer "$PUBLIC_KEY" "$TUNNEL_IP" "$LABEL"
converge_live_state present "$PUBLIC_KEY"
