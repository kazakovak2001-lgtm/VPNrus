#!/usr/bin/env bash
# B36 rollback - removes the shared bootstrap peer and its restricted
# nftables table/systemd unit. Symmetric with install-bootstrap-peer.sh,
# including its runtime autodetection/override - never assumes which
# firewall runtime this host runs.
#
# Never touches: Frankfurt's `ip filter`/`ip nat` (iptables-nft) or
# Stockholm's `inet pocvpn` (native nftables), any other peer, or any
# production key/activation store.
#
# Usage:
#   sudo ./uninstall-bootstrap-peer.sh                      # autodetect
#   sudo ./uninstall-bootstrap-peer.sh --runtime frankfurt   # explicit override
#   sudo ./uninstall-bootstrap-peer.sh --runtime stockholm
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

RUNTIME=""
if [ "${1:-}" = "--runtime" ]; then
    case "${2:-}" in
        frankfurt) RUNTIME=frankfurt-iptables-nft ;;
        stockholm) RUNTIME=stockholm-native-nftables ;;
        *) die "usage: $0 [--runtime frankfurt|stockholm]" ;;
    esac
    log "runtime explicitly selected: $RUNTIME (skipping autodetection)"
else
    RUNTIME=$(detect_bootstrap_firewall_runtime) || die "could not confirm a known firewall runtime - refusing to guess which production ruleset to protect during rollback. Re-run with --runtime frankfurt|stockholm after manual verification."
    log "detected runtime: $RUNTIME"
fi

log "step 1/3: disabling boot-persistence for the bootstrap nftables table"
systemctl disable --now nftables-pocvpn-bootstrap.service 2>/dev/null || true
rm -f /etc/systemd/system/nftables-pocvpn-bootstrap.service
systemctl daemon-reload

log "step 2/3: deleting the bootstrap nftables table ($BOOTSTRAP_NFT_TABLE)"
nft delete table inet "$BOOTSTRAP_NFT_TABLE" 2>/dev/null || true
rm -f /etc/nftables.pocvpn-bootstrap.conf

log "step 3/3: removing the shared bootstrap peer"
"$SCRIPT_DIR/scripts/remove-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY"

log "re-verifying the existing PRODUCTION ruleset is untouched:"
case "$RUNTIME" in
    frankfurt-iptables-nft)
        nft list table ip filter >/dev/null 2>&1 || die "POST-CHECK FAILED: ip filter table no longer present after rollback - investigate immediately, this must never happen"
        nft list table ip nat >/dev/null 2>&1 || die "POST-CHECK FAILED: ip nat table no longer present after rollback - investigate immediately, this must never happen"
        ;;
    stockholm-native-nftables)
        nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "POST-CHECK FAILED: inet $NFT_TABLE table no longer present after rollback - investigate immediately, this must never happen"
        ;;
esac

log "done. verify with: awg show $INTERFACE_NAME peers   (bootstrap public key must be absent)"
