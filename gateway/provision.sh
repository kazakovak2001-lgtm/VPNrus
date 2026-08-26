#!/usr/bin/env bash
# Idempotent POC-01 AmneziaWG gateway provisioner. Run as root on a fresh
# (or already-provisioned) Ubuntu/Debian VPS.
#
#   sudo ./provision.sh
#
# Running this twice must not: duplicate firewall rules, create conflicting
# services, silently replace the server's identity, or corrupt a working
# config. See README.md for the exact idempotence guarantees per step.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config

[ "$(id -u)" -eq 0 ] || die "must be run as root"

log "step 1/6: installing build dependencies"
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq git build-essential golang-go nftables >/dev/null
else
    die "this provisioner only supports apt-based (Debian/Ubuntu) hosts"
fi

log "step 2/6: building and installing pinned amneziawg-go + amneziawg-tools"
"$SCRIPT_DIR/build-awg.sh"

log "step 3/6: enabling IPv4 forwarding"
install -d -m 0755 /etc/sysctl.d
cat > /etc/sysctl.d/99-pocvpn-forwarding.conf <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

log "step 4/6: server identity + interface config"
install -d -m 0700 "$CONFIG_DIR"
CONFIG_PATH="$CONFIG_DIR/$CONFIG_FILE"
if [ -f "$CONFIG_PATH" ]; then
    log "existing config found at $CONFIG_PATH - leaving server identity untouched"
else
    log "no existing config - generating a new server keypair"
    SERVER_PRIVATE_KEY=$(awg genkey)
    SERVER_PUBLIC_KEY=$(printf '%s' "$SERVER_PRIVATE_KEY" | awg pubkey)

    render_template "$SCRIPT_DIR/config/awg0.conf.example" \
        "SERVER_PRIVATE_KEY=$SERVER_PRIVATE_KEY" \
        "GATEWAY_TUNNEL_IP=$GATEWAY_TUNNEL_IP" \
        "GATEWAY_TUNNEL_PREFIX=$GATEWAY_TUNNEL_PREFIX" \
        "LISTEN_PORT=$LISTEN_PORT" \
        "AWG_JC=$AWG_JC" "AWG_JMIN=$AWG_JMIN" "AWG_JMAX=$AWG_JMAX" \
        "AWG_S1=$AWG_S1" "AWG_S2=$AWG_S2" "AWG_S3=$AWG_S3" "AWG_S4=$AWG_S4" \
        "AWG_H1=$AWG_H1" "AWG_H2=$AWG_H2" "AWG_H3=$AWG_H3" "AWG_H4=$AWG_H4" \
        "AWG_RANDOM_TRAILERS=$AWG_RANDOM_TRAILERS" "AWG_DISABLE_COOKIES=$AWG_DISABLE_COOKIES" \
        > "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    chown root:root "$CONFIG_PATH"

    unset SERVER_PRIVATE_KEY
    log "server public key (safe to share, provision into B6 client peer list): $SERVER_PUBLIC_KEY"
fi

log "step 5/6: nftables (forward + NAT for the tunnel only)"
EGRESS_IFACE=$(detect_egress_interface)
[ -n "$EGRESS_IFACE" ] || die "could not detect a default-route egress interface"
log "detected egress interface: $EGRESS_IFACE"

render_template "$SCRIPT_DIR/nftables/pocvpn.nft.template" \
    "NFT_TABLE=$NFT_TABLE" \
    "AWG_IFACE=$INTERFACE_NAME" \
    "EGRESS_IFACE=$EGRESS_IFACE" \
    "AWG_SUBNET=$AWG_SUBNET_CIDR" \
    > /etc/nftables.pocvpn.conf
chmod 644 /etc/nftables.pocvpn.conf
nft -f /etc/nftables.pocvpn.conf

log "step 6/6: systemd service"
install -m 0644 "$SCRIPT_DIR/systemd/awg-poc.service" /etc/systemd/system/awg-poc.service
systemctl daemon-reload
systemctl enable --now awg-poc.service

log "done. status:"
systemctl --no-pager status awg-poc.service || true
