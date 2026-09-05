#!/usr/bin/env bash
# B36 rollback - removes the shared bootstrap peer and its restricted
# nftables table/systemd unit. Symmetric with install-bootstrap-peer.sh.
# Never touches any other peer, the existing `pocvpn` nftables table, or
# any production key/activation store.
#
#   sudo ./uninstall-bootstrap-peer.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config
# shellcheck source=../config/bootstrap.env
source "$SCRIPT_DIR/config/bootstrap.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

log "step 1/3: disabling boot-persistence for the bootstrap nftables table"
systemctl disable --now nftables-pocvpn-bootstrap.service 2>/dev/null || true
rm -f /etc/systemd/system/nftables-pocvpn-bootstrap.service
systemctl daemon-reload

log "step 2/3: deleting the bootstrap nftables table ($BOOTSTRAP_NFT_TABLE)"
nft delete table inet "$BOOTSTRAP_NFT_TABLE" 2>/dev/null || true
rm -f /etc/nftables.pocvpn-bootstrap.conf

log "step 3/3: removing the shared bootstrap peer"
"$SCRIPT_DIR/scripts/remove-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY"

log "done. verify with: awg show $INTERFACE_NAME peers   (bootstrap public key must be absent)"
