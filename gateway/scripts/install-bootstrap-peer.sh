#!/usr/bin/env bash
# B36 - installs the ONE shared, PUBLIC bootstrap peer plus the additive
# nftables restriction, on WHICHEVER gateway runtime this host is confirmed
# to be running:
#   - Frankfurt: iptables-nft (`ip filter`/`ip nat`), owned by a host-local
#     awg-firewall.service (not tracked in this repository) - left
#     completely untouched.
#   - Stockholm: this repository's own native nftables `inet pocvpn` table
#     (gateway/nftables/pocvpn.nft.template) - also left completely
#     untouched.
# See gateway/lib/bootstrap_runtime.sh for the exact detection/priority-
# verification this relies on, and docs/B36_SERVER_DEPLOYMENT_PLAN.md for
# the full per-host design.
#
# Usage:
#   sudo ./install-bootstrap-peer.sh                      # autodetect
#   sudo ./install-bootstrap-peer.sh --runtime frankfurt   # explicit override
#   sudo ./install-bootstrap-peer.sh --runtime stockholm
#
# Fails closed - refuses to proceed - if the runtime cannot be confirmed
# unambiguously and no --runtime override is given, or if the live
# FORWARD-hook priority ordering cannot be confirmed safe. NEVER silently
# applies a firewall model that does not match the live host, and NEVER
# assumes hook ordering without reading the real, live ruleset first.
#
# Reuses add-peer.sh (peer lifecycle: durable config write, lock, live
# convergence check) UNCHANGED on BOTH runtimes - this script never
# re-implements or branches peer mutation itself, only the firewall
# restriction and its own pre-flight verification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/bootstrap_runtime.sh
source "$SCRIPT_DIR/lib/bootstrap_runtime.sh"
load_config
# shellcheck source=../config/bootstrap.env
source "$SCRIPT_DIR/config/bootstrap.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"
is_valid_wg_key "$BOOTSTRAP_CLIENT_PUBLIC_KEY" || die "config/bootstrap.env: BOOTSTRAP_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard key"

RUNTIME=""
if [ "${1:-}" = "--runtime" ]; then
    case "${2:-}" in
        frankfurt) RUNTIME=frankfurt-iptables-nft ;;
        stockholm) RUNTIME=stockholm-native-nftables ;;
        *) die "usage: $0 [--runtime frankfurt|stockholm]" ;;
    esac
    log "runtime explicitly selected: $RUNTIME (skipping autodetection)"
else
    RUNTIME=$(detect_bootstrap_firewall_runtime) || die "could not confirm a known firewall runtime (neither Frankfurt's iptables-nft+awg-firewall.service nor Stockholm's native 'inet pocvpn' table matched unambiguously) - refusing to guess. Re-run with --runtime frankfurt|stockholm only after manually confirming which shape this host actually runs."
    log "detected runtime: $RUNTIME"
fi

case "$RUNTIME" in
    frankfurt-iptables-nft)
        PRODUCTION_NFT_FAMILY=ip
        PRODUCTION_NFT_TABLE=filter
        ;;
    stockholm-native-nftables)
        PRODUCTION_NFT_FAMILY=inet
        PRODUCTION_NFT_TABLE="$NFT_TABLE"   # poc.env - "pocvpn"
        ;;
    *) die "internal error: unrecognized runtime '$RUNTIME'" ;;
esac

log "step 1/4: verifying live FORWARD-hook ordering ($PRODUCTION_NFT_FAMILY $PRODUCTION_NFT_TABLE vs bootstrap priority $BOOTSTRAP_FORWARD_PRIORITY) before applying anything"
verify_bootstrap_priority_precedes_production "$PRODUCTION_NFT_FAMILY" "$PRODUCTION_NFT_TABLE" "$BOOTSTRAP_FORWARD_PRIORITY"

log "step 2/4: adding the shared bootstrap peer (label: bootstrap, tunnel IP: $BOOTSTRAP_CLIENT_TUNNEL_IP)"
"$SCRIPT_DIR/scripts/add-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY" "$BOOTSTRAP_CLIENT_TUNNEL_IP" bootstrap

log "step 3/4: applying the restricted bootstrap nftables table ($BOOTSTRAP_NFT_TABLE) - identical template on both runtimes, additive only"
render_template "$SCRIPT_DIR/nftables/pocvpn-bootstrap.nft.template" \
    "NFT_TABLE_BOOTSTRAP=$BOOTSTRAP_NFT_TABLE" \
    "BOOTSTRAP_CLIENT_IP=$BOOTSTRAP_CLIENT_TUNNEL_IP" \
    "BOOTSTRAP_FORWARD_PRIORITY=$BOOTSTRAP_FORWARD_PRIORITY" \
    > /etc/nftables.pocvpn-bootstrap.conf
chmod 644 /etc/nftables.pocvpn-bootstrap.conf
nft -f /etc/nftables.pocvpn-bootstrap.conf

log "step 4/4: enabling boot-persistence for the bootstrap nftables table (its own dedicated systemd unit, independent of either runtime's own persistence mechanism)"
install -m 0644 "$SCRIPT_DIR/systemd/nftables-pocvpn-bootstrap.service" /etc/systemd/system/nftables-pocvpn-bootstrap.service
systemctl daemon-reload
systemctl enable --now nftables-pocvpn-bootstrap.service

log "re-verifying the existing PRODUCTION ruleset is untouched:"
case "$RUNTIME" in
    frankfurt-iptables-nft)
        nft list table ip filter >/dev/null 2>&1 || die "POST-CHECK FAILED: ip filter table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        nft list table ip nat >/dev/null 2>&1 || die "POST-CHECK FAILED: ip nat table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        systemctl is-active --quiet awg-firewall.service || log "WARNING: awg-firewall.service is not reported active after this change - verify manually; this script never starts/stops/reloads it"
        log "REQUIRED manual read-only check on Frankfurt specifically: run 'iptables -L INPUT -n' / 'nft list ruleset' and confirm no existing rule already ACCEPTs traffic from $BOOTSTRAP_CLIENT_TUNNEL_IP ahead of this table's own input chain - see gateway/lib/bootstrap_runtime.sh's own 'KNOWN, DISCLOSED LIMITATION (INPUT, Frankfurt only)' docs. The FORWARD (Internet-access) restriction above is unaffected either way."
        ;;
    stockholm-native-nftables)
        nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "POST-CHECK FAILED: inet $NFT_TABLE table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        ;;
esac

log "done. verify with:"
log "  awg show $INTERFACE_NAME peers               # bootstrap public key should be listed"
log "  nft list table inet $BOOTSTRAP_NFT_TABLE      # the two restriction rules should be present, priority $BOOTSTRAP_FORWARD_PRIORITY on forward"
log "  from a second host through the bootstrap tunnel: only tcp/443 to this box's own public IP should succeed; every other destination/port should time out or be refused"
