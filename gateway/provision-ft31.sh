#!/usr/bin/env bash
# B37 (senior-review correction) - provisions the ISOLATED AmneziaWG 3.1
# field-test interface (awg-ft31) alongside an already-provisioned
# production awg0 gateway. Never touches awg0.conf, awg-poc.service, or any
# existing peer - only adds new, separate files/units scoped to awg-ft31,
# plus exactly two narrowly-scoped, tagged ACCEPT rules inserted into each
# host's OWN real production forwarding path (see lib/ft31_forward_rules.sh
# for why a second, competing nftables base chain is unsafe and was removed).
#
# Usage:
#   sudo FT31_CLIENT_PUBLIC_KEY=... FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
#        ./provision-ft31.sh <frankfurt|stockholm>
#
# Secret handling (senior-review requirement):
# - The server's own awg-ft31 private key and the shared HeaderProtectionKey
#   are generated HERE, ON THIS HOST, via `awg genkey` - never accepted as
#   an input, never echoed to stdout, never written to shell history or
#   passed as a literal command-line argument. Only the resulting PUBLIC
#   key is printed (non-secret, safe to relay/report) - see step 1's own
#   output for the exact, one-time instructions to retrieve
#   HeaderProtectionKey yourself, directly from this server's own config
#   file, for pasting into the Android build (never through this script,
#   never through a chat/ticket/log).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
# shellcheck source=lib/ft31_forward_rules.sh
source "$SCRIPT_DIR/lib/ft31_forward_rules.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/config/awg-ft31-profile.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

FT31_HOST=${1:-}
case "$FT31_HOST" in
    frankfurt|stockholm) ;;
    *) die "usage: $0 <frankfurt|stockholm> - unknown/missing host, refusing to mutate any firewall rule" ;;
esac

: "${FT31_CLIENT_PUBLIC_KEY:?FT31_CLIENT_PUBLIC_KEY is required (non-secret - the field-test build own public key)}"
: "${FT31_CLIENT_TUNNEL_IP:?FT31_CLIENT_TUNNEL_IP is required (e.g. 10.77.31.2, non-secret)}"
is_valid_wg_key "$FT31_CLIENT_PUBLIC_KEY" || die "FT31_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard public key"

# Isolated interface facts - deliberately NOT read from config/poc.env (see
# gateway/config/awg-ft31-profile.env's own docs for why).
FT31_INTERFACE_NAME=awg-ft31
FT31_CONFIG_FILE=awg-ft31.conf
FT31_LISTEN_PORT=51821
FT31_SUBNET_CIDR=10.77.31.0/24
FT31_GATEWAY_TUNNEL_IP=10.77.31.1
FT31_GATEWAY_TUNNEL_PREFIX=24

command -v awg >/dev/null && command -v awg-quick >/dev/null || \
    die "amneziawg-tools not found - run provision.sh (production awg0) on this host first"
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || \
    die "IPv4 forwarding is not enabled - run provision.sh (production awg0) on this host first"

EGRESS_IFACE=$(detect_egress_interface)
[ -n "$EGRESS_IFACE" ] || die "could not detect a default-route egress interface"

log "step 0/5: preflight - verifying $FT31_HOST's live firewall runtime matches its expected production facts"
ft31_verify_runtime "$FT31_HOST" "$EGRESS_IFACE"

PRE_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$PRE_SNAPSHOT"
log "captured pre-mutation firewall snapshot ($PRE_SNAPSHOT) for the post-deploy no-unrelated-change proof"

log "step 1/5: isolated awg-ft31 interface config"
CONFIG_DIR=/etc/amnezia/amneziawg
FT31_CONFIG_PATH="$CONFIG_DIR/$FT31_CONFIG_FILE"
install -d -m 0700 "$CONFIG_DIR"
if [ -f "$FT31_CONFIG_PATH" ]; then
    log "existing config found at $FT31_CONFIG_PATH - leaving server identity/HeaderProtectionKey untouched"
else
    # Generated HERE, on this host, via `awg genkey` - held only in shell
    # variables for the remainder of this script, never echoed, never
    # passed as a literal CLI argument, never written anywhere but directly
    # into the 0600 config file below. Explicitly unset afterwards so no
    # subshell/trap/core-dump can retain them longer than necessary.
    FT31_SERVER_PRIVATE_KEY=$(awg genkey)
    FT31_SERVER_PUBLIC_KEY=$(printf '%s' "$FT31_SERVER_PRIVATE_KEY" | awg pubkey)
    FT31_HEADER_PROTECTION_KEY=$(awg genkey)

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

    log "server public key (safe to share/paste into FieldTestAwg31GatewayCatalog.kt): $FT31_SERVER_PUBLIC_KEY"
    log "HeaderProtectionKey is NOT printed here (secret, shared-key material)."
    log "Retrieve it YOURSELF, directly from this server, when you are ready to build the field-test APK:"
    log "    sudo grep '^HeaderProtectionKey' $FT31_CONFIG_PATH"
    log "Paste it directly into FieldTestAwg31GatewayCatalog.kt's headerProtectionKeyBase64 for this gateway."
    log "Never paste it into chat, a ticket, a commit message, or any log."
    unset FT31_SERVER_PRIVATE_KEY FT31_HEADER_PROTECTION_KEY
fi

log "step 2/5: field-test peer"
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

log "step 3/5: isolated NAT (inet pocvpn-ft31, no forward/filter chain - see this table's own docs)"
render_template "$SCRIPT_DIR/nftables/pocvpn-ft31.nft.template" \
    "EGRESS_IFACE=$EGRESS_IFACE" \
    "AWG_FT31_SUBNET=$FT31_SUBNET_CIDR" \
    > /etc/nftables.pocvpn-ft31.conf
chmod 644 /etc/nftables.pocvpn-ft31.conf
nft -f /etc/nftables.pocvpn-ft31.conf

log "step 4/5: systemd service"
install -m 0644 "$SCRIPT_DIR/systemd/awg-poc-ft31.service" /etc/systemd/system/awg-poc-ft31.service
systemctl daemon-reload
systemctl enable --now awg-poc-ft31.service

log "step 5/5: FORWARD accept rules in the REAL production forwarding path ($FT31_HOST)"
ft31_add_forward_rules "$FT31_HOST" "$EGRESS_IFACE"

POST_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$POST_SNAPSHOT"
ft31_verify_no_unrelated_change "$PRE_SNAPSHOT" "$POST_SNAPSHOT"
rm -f "$PRE_SNAPSHOT" "$POST_SNAPSHOT"

log "post-deploy verification:"
ft31_verify_runtime "$FT31_HOST" "$EGRESS_IFACE" && log "  [ok] existing production awg0/FORWARD facts for $FT31_HOST are still intact"
ft31_forward_rules_present "$FT31_HOST" "$EGRESS_IFACE" && log "  [ok] b37-ft31 FORWARD accept rules are present"
FT31_NAT_OUTPUT=$(nft list table inet pocvpn-ft31 2>/dev/null || true)
printf '%s' "$FT31_NAT_OUTPUT" | grep -q masquerade && log "  [ok] b37-ft31 NAT (masquerade) is present"

log "done. verify: sudo awg show $FT31_INTERFACE_NAME"
