#!/usr/bin/env bash
# Automatic tunnel-IP allocation on top of the existing manual add-peer.sh.
#
#   sudo ./allocate-and-add-peer.sh <CLIENT_PUBLIC_KEY> [label]
#
# Prints the allocated tunnel IP (and nothing else) to stdout on success.
# The manual `add-peer.sh <PUBLIC_KEY> <TUNNEL_IP> [label]` path is
# unmodified and remains the supported fallback for a caller-chosen IP.
#
# Allocation is derived entirely from the live gateway config (the same
# file add-peer.sh writes to) - there is no separate ledger that could
# drift from it. The whole read-choose-add-verify sequence happens under
# one exclusive flock so two concurrent callers can never receive the same
# IP; the lock is released only after add-peer.sh has actually succeeded
# (or the whole allocation is abandoned and nothing is reported allocated).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY> [label]" >&2; exit 2; }
[ $# -ge 1 ] || usage
PUBLIC_KEY=$1
LABEL=${2:-peer-$(date +%s 2>/dev/null || echo unlabeled)}

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"

CONFIG_PATH="$CONFIG_DIR/$CONFIG_FILE"
[ -f "$CONFIG_PATH" ] || die "gateway config not found at $CONFIG_PATH - run provision.sh first"

NET_ADDR=${AWG_SUBNET_CIDR%/*}
PREFIX=${AWG_SUBNET_CIDR#*/}
is_valid_ipv4 "$NET_ADDR" || die "AWG_SUBNET_CIDR network address is not valid IPv4: $AWG_SUBNET_CIDR"
[[ "$PREFIX" =~ ^[0-9]+$ ]] && (( PREFIX >= 0 && PREFIX <= 32 )) || die "AWG_SUBNET_CIDR prefix is invalid: $AWG_SUBNET_CIDR"
(( PREFIX <= 30 )) || die "AWG_SUBNET_CIDR $AWG_SUBNET_CIDR has no usable host addresses (prefix must be <= 30)"

NET_INT=$(ipv4_to_int "$NET_ADDR")
MASK=$(( (0xFFFFFFFF << (32 - PREFIX)) & 0xFFFFFFFF ))
BROADCAST_INT=$(( (NET_INT | (~MASK & 0xFFFFFFFF)) & 0xFFFFFFFF ))
GATEWAY_INT=$(ipv4_to_int "$GATEWAY_TUNNEL_IP")

LOCK_FILE="$CONFIG_DIR/.provision.lock"

exec 9>"$LOCK_FILE"
flock -x 9

# --- everything below runs with the exclusive lock held ---

is_used() {
    local candidate=$1
    (( candidate == NET_INT )) && return 0
    (( candidate == BROADCAST_INT )) && return 0
    (( candidate == GATEWAY_INT )) && return 0
    local existing_ip existing_int
    while IFS= read -r existing_ip; do
        [ -n "$existing_ip" ] || continue
        is_valid_ipv4 "$existing_ip" || continue
        existing_int=$(ipv4_to_int "$existing_ip")
        (( candidate == existing_int )) && return 0
    done < <(grep -E '^AllowedIPs = ' "$CONFIG_PATH" | sed -E 's#^AllowedIPs = ([0-9.]+)/32.*#\1#')
    return 1
}

CHOSEN_INT=""
for (( candidate = NET_INT + 1; candidate < BROADCAST_INT; candidate++ )); do
    if ! is_used "$candidate"; then
        CHOSEN_INT=$candidate
        break
    fi
done

[ -n "$CHOSEN_INT" ] || die "subnet $AWG_SUBNET_CIDR is exhausted - no free tunnel address available"

CHOSEN_IP=$(int_to_ipv4 "$CHOSEN_INT")

log "allocated $CHOSEN_IP for '$LABEL' - handing off to add-peer.sh"
"$SCRIPT_DIR/scripts/add-peer.sh" "$PUBLIC_KEY" "$CHOSEN_IP" "$LABEL"

# add-peer.sh (set -e, sourced common.sh's `die`) would have already exited
# non-zero on any failure, so reaching here means the peer write genuinely
# succeeded - only now is it safe to report the IP as allocated.
echo "$CHOSEN_IP"
