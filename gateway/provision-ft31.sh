#!/usr/bin/env bash
# B37 - provisions the ISOLATED AmneziaWG 3.1 field-test interface
# (awg-ft31) alongside an already-provisioned production awg0 gateway.
# Never touches awg0.conf, awg-poc.service, /etc/nftables.pocvpn.conf, or
# any existing peer - only adds new, separate files/units scoped to
# awg-ft31. Requires provision.sh (production awg0) to have already been
# run on this host (amneziawg-go/amneziawg-tools already installed, IPv4
# forwarding already enabled) - this script does not build or install
# those again.
#
# Required environment (never committed - see the B37 task report for the
# exact, not-yet-applied values):
#   FT31_SERVER_PRIVATE_KEY      - this gateway's own awg-ft31 private key
#   FT31_HEADER_PROTECTION_KEY   - shared HeaderProtectionKey (both ends)
#   FT31_CLIENT_PUBLIC_KEY       - the field-test Android build's public key
#   FT31_CLIENT_TUNNEL_IP        - the field-test peer's tunnel IP (e.g. 10.77.31.2)
#
#   sudo FT31_SERVER_PRIVATE_KEY=... FT31_HEADER_PROTECTION_KEY=... \
#        FT31_CLIENT_PUBLIC_KEY=... FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
#        ./provision-ft31.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/config/awg-ft31-profile.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

: "${FT31_SERVER_PRIVATE_KEY:?FT31_SERVER_PRIVATE_KEY is required - see the header of gateway/provision-ft31.sh}"
: "${FT31_HEADER_PROTECTION_KEY:?FT31_HEADER_PROTECTION_KEY is required}"
: "${FT31_CLIENT_PUBLIC_KEY:?FT31_CLIENT_PUBLIC_KEY is required}"
: "${FT31_CLIENT_TUNNEL_IP:?FT31_CLIENT_TUNNEL_IP is required (e.g. 10.77.31.2)}"

is_valid_wg_key "$FT31_CLIENT_PUBLIC_KEY" || die "FT31_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard public key"

# Isolated interface facts - deliberately NOT read from config/poc.env
# (that file's INTERFACE_NAME/CONFIG_FILE/LISTEN_PORT/AWG_SUBNET_CIDR are
# awg0's own, production values; reusing them here would be exactly the
# bug this isolation is meant to prevent).
FT31_INTERFACE_NAME=awg-ft31
FT31_CONFIG_FILE=awg-ft31.conf
FT31_LISTEN_PORT=51821
FT31_SUBNET_CIDR=10.77.31.0/24
FT31_GATEWAY_TUNNEL_IP=10.77.31.1
FT31_GATEWAY_TUNNEL_PREFIX=24
FT31_NFT_TABLE=pocvpn-ft31

command -v awg >/dev/null && command -v awg-quick >/dev/null || \
    die "amneziawg-tools not found - run provision.sh (production awg0) on this host first"
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || \
    die "IPv4 forwarding is not enabled - run provision.sh (production awg0) on this host first"

log "step 1/4: isolated awg-ft31 interface config"
CONFIG_DIR=/etc/amnezia/amneziawg
FT31_CONFIG_PATH="$CONFIG_DIR/$FT31_CONFIG_FILE"
install -d -m 0700 "$CONFIG_DIR"
if [ -f "$FT31_CONFIG_PATH" ]; then
    log "existing config found at $FT31_CONFIG_PATH - leaving server identity untouched"
else
    render_template "$SCRIPT_DIR/config/awg-ft31.conf.example" \
        "SERVER_PRIVATE_KEY=$FT31_SERVER_PRIVATE_KEY" \
        "HEADER_PROTECTION_KEY=$FT31_HEADER_PROTECTION_KEY" \
        "GATEWAY_TUNNEL_IP=$FT31_GATEWAY_TUNNEL_IP" \
        "GATEWAY_TUNNEL_PREFIX=$FT31_GATEWAY_TUNNEL_PREFIX" \
        "LISTEN_PORT=$FT31_LISTEN_PORT" \
        "AWG_FT31_JC=$AWG_FT31_JC" "AWG_FT31_JMIN=$AWG_FT31_JMIN" "AWG_FT31_JMAX=$AWG_FT31_JMAX" \
        "AWG_FT31_S1=$AWG_FT31_S1" "AWG_FT31_S2=$AWG_FT31_S2" "AWG_FT31_S3=$AWG_FT31_S3" "AWG_FT31_S4=$AWG_FT31_S4" \
        "AWG_FT31_H1=$AWG_FT31_H1" "AWG_FT31_H2=$AWG_FT31_H2" "AWG_FT31_H3=$AWG_FT31_H3" "AWG_FT31_H4=$AWG_FT31_H4" \
        "AWG_FT31_I1=$AWG_FT31_I1" "AWG_FT31_I2=$AWG_FT31_I2" "AWG_FT31_I3=$AWG_FT31_I3" \
        "AWG_FT31_I4=$AWG_FT31_I4" "AWG_FT31_I5=$AWG_FT31_I5" \
        "AWG_FT31_CONTENT_PADDING_ADDITION=$AWG_FT31_CONTENT_PADDING_ADDITION" \
        "AWG_FT31_RANDOM_TRAILERS=$AWG_FT31_RANDOM_TRAILERS" "AWG_FT31_DISABLE_COOKIES=$AWG_FT31_DISABLE_COOKIES" \
        > "$FT31_CONFIG_PATH"
    chmod 600 "$FT31_CONFIG_PATH"
    chown root:root "$FT31_CONFIG_PATH"
fi

log "step 2/4: field-test peer"
CONFIG_FILE=$FT31_CONFIG_FILE
INTERFACE_NAME=$FT31_INTERFACE_NAME
AWG_SUBNET_CIDR=$FT31_SUBNET_CIDR
GATEWAY_TUNNEL_IP=$FT31_GATEWAY_TUNNEL_IP
ip_in_cidr "$FT31_CLIENT_TUNNEL_IP" "$AWG_SUBNET_CIDR" || die "$FT31_CLIENT_TUNNEL_IP is not inside $AWG_SUBNET_CIDR"
LOCK_FILE="$CONFIG_DIR/.provision-ft31.lock"
exec 9>"$LOCK_FILE"
flock -x 9
if grep -qF "PublicKey = $FT31_CLIENT_PUBLIC_KEY" "$FT31_CONFIG_PATH" 2>/dev/null; then
    log "field-test peer already present - leaving it untouched"
else
    mutate_add_peer "$FT31_CLIENT_PUBLIC_KEY" "$FT31_CLIENT_TUNNEL_IP" "field-test-awg31"
fi

log "step 3/4: nftables (isolated table, forward + NAT for awg-ft31 only)"
EGRESS_IFACE=$(detect_egress_interface)
[ -n "$EGRESS_IFACE" ] || die "could not detect a default-route egress interface"
render_template "$SCRIPT_DIR/nftables/pocvpn-ft31.nft.template" \
    "AWG_FT31_IFACE=$FT31_INTERFACE_NAME" \
    "EGRESS_IFACE=$EGRESS_IFACE" \
    "AWG_FT31_SUBNET=$FT31_SUBNET_CIDR" \
    > /etc/nftables.pocvpn-ft31.conf
chmod 644 /etc/nftables.pocvpn-ft31.conf
nft -f /etc/nftables.pocvpn-ft31.conf

log "step 4/4: systemd service"
install -m 0644 "$SCRIPT_DIR/systemd/awg-poc-ft31.service" /etc/systemd/system/awg-poc-ft31.service
systemctl daemon-reload
systemctl enable --now awg-poc-ft31.service

log "done. status:"
systemctl --no-pager status awg-poc-ft31.service || true
log "verify: sudo awg show $FT31_INTERFACE_NAME"
