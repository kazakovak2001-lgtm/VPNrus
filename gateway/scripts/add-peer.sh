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
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY> <CLIENT_TUNNEL_IP> [label]" >&2; exit 2; }

[ $# -ge 2 ] || usage
PUBLIC_KEY=$1
TUNNEL_IP=$2
LABEL=${3:-peer-$(date +%s 2>/dev/null || echo unlabeled)}

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"
ip_in_cidr "$TUNNEL_IP" "$AWG_SUBNET_CIDR" || die "$TUNNEL_IP is not inside the POC subnet $AWG_SUBNET_CIDR"
[ "$TUNNEL_IP" != "$GATEWAY_TUNNEL_IP" ] || die "$TUNNEL_IP is the gateway's own tunnel address, cannot also be a peer"

CONFIG_PATH="$CONFIG_DIR/$CONFIG_FILE"
[ -f "$CONFIG_PATH" ] || die "gateway config not found at $CONFIG_PATH - run provision.sh first"

if grep -qF "PublicKey = $PUBLIC_KEY" "$CONFIG_PATH"; then
    die "a peer with this public key already exists"
fi
if grep -qE "AllowedIPs = ${TUNNEL_IP//./\\.}/32" "$CONFIG_PATH"; then
    die "tunnel IP $TUNNEL_IP is already assigned to another peer"
fi

PEER_BLOCK=$(cat <<EOF
[Peer]
# label: $LABEL
PublicKey = $PUBLIC_KEY
AllowedIPs = $TUNNEL_IP/32
EOF
)

TMP_FILE=$(mktemp)
awk -v block="$PEER_BLOCK" '
    /^# --- PEERS END ---/ { print block; print "" }
    { print }
' "$CONFIG_PATH" > "$TMP_FILE"
chmod 600 "$TMP_FILE"
mv "$TMP_FILE" "$CONFIG_PATH"

log "peer added: $LABEL -> $TUNNEL_IP"

if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    log "reloading $SERVICE_NAME.service to apply the new peer without dropping the tunnel"
    systemctl reload "$SERVICE_NAME.service"
else
    log "$SERVICE_NAME.service is not currently active - peer will apply the next time it starts"
fi
