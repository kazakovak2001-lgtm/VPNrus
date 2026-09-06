#!/usr/bin/env bash
# B37 (senior-review correction) - full rollback of the isolated AWG 3.1
# field-test interface (awg-ft31), including the two b37-ft31-tagged
# FORWARD accept rules provision-ft31.sh added to the host's REAL
# production forwarding path. Removes ONLY B37 state - never touches
# awg0, awg-poc.service, the production `inet pocvpn` forward chain's
# other rules/policy, or any other pre-existing rule.
#
#   sudo ./rollback-ft31.sh <frankfurt|stockholm>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/ft31_forward_rules.sh
source "$SCRIPT_DIR/lib/ft31_forward_rules.sh"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

FT31_HOST=${1:-}
case "$FT31_HOST" in
    frankfurt|stockholm) ;;
    *) die "usage: $0 <frankfurt|stockholm> - unknown/missing host, refusing to mutate any firewall rule" ;;
esac

EGRESS_IFACE=$(detect_egress_interface)
[ -n "$EGRESS_IFACE" ] || die "could not detect a default-route egress interface"

PRE_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$PRE_SNAPSHOT"

log "removing b37-ft31 FORWARD accept rules from the production forwarding path (if present)"
ft31_remove_forward_rules "$FT31_HOST" "$EGRESS_IFACE"

log "stopping/disabling awg-poc-ft31.service"
systemctl disable --now awg-poc-ft31.service 2>/dev/null || true
rm -f /etc/systemd/system/awg-poc-ft31.service
systemctl daemon-reload

log "removing isolated NAT table (inet pocvpn-ft31)"
nft delete table inet pocvpn-ft31 2>/dev/null || true
rm -f /etc/nftables.pocvpn-ft31.conf

CONFIG_PATH=/etc/amnezia/amneziawg/awg-ft31.conf
if [ -f "$CONFIG_PATH" ]; then
    BACKUP_PATH="/etc/amnezia/amneziawg/awg-ft31.conf.rolled-back.$(date +%Y%m%dT%H%M%S)"
    log "archiving $CONFIG_PATH -> $BACKUP_PATH (not deleted outright, in case rollback needs to be undone) - still contains the server private key/HeaderProtectionKey, mode stays 0600"
    mv "$CONFIG_PATH" "$BACKUP_PATH"
    chmod 600 "$BACKUP_PATH"
fi
rm -f /etc/amnezia/amneziawg/.provision-ft31.lock

POST_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$POST_SNAPSHOT"
# Rollback direction: POST must be a SUBSET of PRE (things were removed, not
# added) with every remaining line in its original relative order - i.e.
# PRE filtered down to POST's own lines must equal POST verbatim.
FILTERED=$(mktemp)
grep -Fxf "$POST_SNAPSHOT" "$PRE_SNAPSHOT" > "$FILTERED" || true
if ! diff -q "$FILTERED" "$POST_SNAPSHOT" >/dev/null 2>&1; then
    die "rollback verification FAILED: a rule remains that was not in the pre-rollback ruleset, or ordering changed unexpectedly - see $PRE_SNAPSHOT vs $POST_SNAPSHOT"
fi
log "rollback verification: every remaining rule already existed before rollback, in the same relative order - only b37-ft31 state was removed"
rm -f "$PRE_SNAPSHOT" "$POST_SNAPSHOT" "$FILTERED"

log "done. production awg0/awg-poc.service and every other production firewall rule were never touched by this script."
