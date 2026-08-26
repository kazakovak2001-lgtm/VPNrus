#!/usr/bin/env bash
# Removes a peer by public key.
#
#   sudo ./remove-peer.sh <CLIENT_PUBLIC_KEY>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_config

usage() { echo "usage: $0 <CLIENT_PUBLIC_KEY>" >&2; exit 2; }
[ $# -ge 1 ] || usage
PUBLIC_KEY=$1

is_valid_wg_key "$PUBLIC_KEY" || die "not a valid AmneziaWG/WireGuard key: $PUBLIC_KEY"

CONFIG_PATH="$CONFIG_DIR/$CONFIG_FILE"
[ -f "$CONFIG_PATH" ] || die "gateway config not found at $CONFIG_PATH"

grep -qF "PublicKey = $PUBLIC_KEY" "$CONFIG_PATH" || die "no peer with this public key exists"

# Peer blocks are delimited by a leading "[Peer]" line and a trailing blank
# line (guaranteed by add-peer.sh). A block is dropped in full if it contains
# our target PublicKey line, otherwise it is reprinted unchanged.
TMP_FILE=$(mktemp)
awk -v key="PublicKey = $PUBLIC_KEY" '
    function flush() {
        if (in_block && !matched) { for (i = 0; i < n; i++) print hold[i] }
        in_block = 0; n = 0; matched = 0
    }
    /^\[Peer\]/ {
        flush()
        in_block = 1
        hold[n++] = $0
        next
    }
    in_block && $0 == "" {
        hold[n++] = $0
        flush()
        next
    }
    in_block {
        hold[n++] = $0
        if ($0 == key) matched = 1
        next
    }
    { print }
    END { flush() }
' "$CONFIG_PATH" > "$TMP_FILE"
chmod 600 "$TMP_FILE"
mv "$TMP_FILE" "$CONFIG_PATH"

log "peer removed"

if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    log "reloading $SERVICE_NAME.service to apply removal without dropping the tunnel"
    systemctl reload "$SERVICE_NAME.service"
fi
