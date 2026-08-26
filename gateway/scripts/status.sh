#!/usr/bin/env bash
# Read-only status check. Never prints the private key or full config dump.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config

echo "== systemd =="
systemctl --no-pager status "$SERVICE_NAME.service" || true

echo
echo "== interface (awg show never prints the private key) =="
awg show "$INTERFACE_NAME" 2>&1 || echo "(interface not up)"

echo
echo "== listening UDP port =="
ss -uln "sport = :$LISTEN_PORT" 2>&1 || true

echo
echo "== nftables (our table only) =="
nft list table inet "$NFT_TABLE" 2>&1 || echo "(table not loaded)"

echo
echo "== peer count =="
grep -c '^\[Peer\]' "$CONFIG_DIR/$CONFIG_FILE" 2>/dev/null || echo 0
