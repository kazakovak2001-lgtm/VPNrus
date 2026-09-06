#!/usr/bin/env bash
# B37 - full rollback of the isolated AWG 3.1 field-test interface
# (awg-ft31). Never touches awg0, awg-poc.service, or the production
# `inet pocvpn` nftables table - only removes the awg-ft31-scoped
# unit/config/table this task's provision-ft31.sh added.
#
#   sudo ./rollback-ft31.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

log "stopping/disabling awg-poc-ft31.service"
systemctl disable --now awg-poc-ft31.service 2>/dev/null || true
rm -f /etc/systemd/system/awg-poc-ft31.service
systemctl daemon-reload

log "removing isolated nftables table (inet pocvpn-ft31)"
nft delete table inet pocvpn-ft31 2>/dev/null || true
rm -f /etc/nftables.pocvpn-ft31.conf

CONFIG_PATH=/etc/amnezia/amneziawg/awg-ft31.conf
if [ -f "$CONFIG_PATH" ]; then
    BACKUP_PATH="/etc/amnezia/amneziawg/awg-ft31.conf.rolled-back.$(date +%Y%m%dT%H%M%S)"
    log "archiving $CONFIG_PATH -> $BACKUP_PATH (not deleted outright, in case rollback needs to be undone)"
    mv "$CONFIG_PATH" "$BACKUP_PATH"
    chmod 600 "$BACKUP_PATH"
fi
rm -f /etc/amnezia/amneziawg/.provision-ft31.lock

log "done. production awg0/awg-poc.service/inet pocvpn were never touched by this script."
