#!/usr/bin/env bash
# B36 - installs the ONE shared, PUBLIC bootstrap peer on this gateway's
# existing AWG interface and applies the restricted, additive
# pocvpn_bootstrap nftables table that denies it general forwarding/NAT.
#
# Reuses the existing add-peer.sh peer-mutation tool verbatim (same lock,
# same durable-config validation, same live-convergence check) - this
# script adds NOTHING new to how a peer is registered, only WHICH peer
# (the fixed bootstrap identity from config/bootstrap.env) and the
# additional nftables restriction step.
#
# Never touches: the existing `pocvpn` nftables table, any other peer, any
# production key, any activation store, port 8443/8444 (loopback-only,
# untouched).
#
#   sudo ./install-bootstrap-peer.sh
#
# Safe to re-run: add-peer.sh already fails closed (not silently) if this
# exact public key or tunnel IP is already assigned; the nftables template
# is idempotent (delete + redeclare, see that file's own docs).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config
# shellcheck source=../config/bootstrap.env
source "$SCRIPT_DIR/config/bootstrap.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"
is_valid_wg_key "$BOOTSTRAP_CLIENT_PUBLIC_KEY" || die "config/bootstrap.env: BOOTSTRAP_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard key"

log "step 1/3: adding the shared bootstrap peer (label: bootstrap, tunnel IP: $BOOTSTRAP_CLIENT_TUNNEL_IP)"
"$SCRIPT_DIR/scripts/add-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY" "$BOOTSTRAP_CLIENT_TUNNEL_IP" bootstrap

log "step 2/3: applying the restricted bootstrap nftables table ($BOOTSTRAP_NFT_TABLE)"
render_template "$SCRIPT_DIR/nftables/pocvpn-bootstrap.nft.template" \
    "NFT_TABLE_BOOTSTRAP=$BOOTSTRAP_NFT_TABLE" \
    "BOOTSTRAP_CLIENT_IP=$BOOTSTRAP_CLIENT_TUNNEL_IP" \
    > /etc/nftables.pocvpn-bootstrap.conf
chmod 644 /etc/nftables.pocvpn-bootstrap.conf
nft -f /etc/nftables.pocvpn-bootstrap.conf

log "step 3/3: enabling boot-persistence for the bootstrap nftables table"
install -m 0644 "$SCRIPT_DIR/systemd/nftables-pocvpn-bootstrap.service" /etc/systemd/system/nftables-pocvpn-bootstrap.service
systemctl daemon-reload
systemctl enable --now nftables-pocvpn-bootstrap.service

log "done. verify with:"
log "  awg show $INTERFACE_NAME peers          # bootstrap public key should be listed"
log "  nft list table inet $BOOTSTRAP_NFT_TABLE # the two restriction rules should be present"
log "  from a second host through the bootstrap tunnel: only tcp/443 to this box's own public IP should succeed; every other destination/port should time out or be refused"
