#!/usr/bin/env bash
# Field test - server-side correlation capture for ONE scheduled tester
# window (owner-approved per session, see docs/FIELD_TEST_RUNBOOK.md).
#
#   sudo field_test_capture.sh --minutes 30 [--client-net 203.0.113.0/24] [--out /var/tmp/nova-fieldtest] [--dry-run]
#
# Read-only towards the service: no reload, restart, config or firewall
# change. It only
#   1. records packet HEADERS (snaplen 96: no payload content) on Nova's
#      client-facing ports for --minutes, optionally limited to the
#      tester's network (--client-net - strongly preferred: nobody else's
#      traffic is recorded),
#   2. snapshots `awg show` handshakes (peer public keys only) before/after,
#   3. exports the journal of the Nova units for exactly that window,
#   4. writes a per-port packet/direction summary next to the capture.
# Output: <out>/<UTC timestamp>/ (root, 0700). Delete it after analysis -
# it contains the tester's IP addresses.
set -euo pipefail

MINUTES=""
CLIENT_NET=""
OUT_BASE="/var/tmp/nova-fieldtest"
DRY_RUN=0
SNAPLEN=96
# Client-facing ports in the signed manifest (AWG, REALITY, TLS, XHTTP/relay
# ingress, Hysteria2/HTTPS, Shadowsocks, B37 field-test AWG).
PORTS=(51820 51821 2053 2083 2093 443 28388)
UNITS=(nova-xray nova-xray-ingress nova-xray-xhttp-ingress pocvpn-api pocvpn-api-ingress pocvpn-api-xhttp-ingress
       nova-hysteria pocvpn-hysteria-auth nginx awg-poc awg-quick@awg0 awg-poc-ft31 b45a-ssserver cloudflared)

usage() { echo "usage: $0 --minutes N [--client-net CIDR] [--out DIR] [--dry-run]" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --minutes) [ $# -ge 2 ] || usage; MINUTES=$2; shift 2 ;;
        --client-net) [ $# -ge 2 ] || usage; CLIENT_NET=$2; shift 2 ;;
        --out) [ $# -ge 2 ] || usage; OUT_BASE=$2; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) usage ;;
    esac
done
[[ "$MINUTES" =~ ^[0-9]+$ ]] && [ "$MINUTES" -ge 1 ] && [ "$MINUTES" -le 240 ] || { echo "--minutes must be 1..240" >&2; exit 2; }
if [ -n "$CLIENT_NET" ] && ! [[ "$CLIENT_NET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
    echo "--client-net must be an IPv4 address or CIDR" >&2; exit 2
fi

build_filter() {
    local f="" p
    for p in "${PORTS[@]}"; do f+="${f:+ or }port $p"; done
    f="($f)"
    [ -n "$CLIENT_NET" ] && f+=" and net $CLIENT_NET"
    printf '%s' "$f"
}

FILTER=$(build_filter)
IFACE=$(ip route show default 2>/dev/null | awk '/^default/ { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }')
IFACE=${IFACE:-any}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_BASE/$STAMP"

run() {
    if [ "$DRY_RUN" -eq 1 ]; then printf 'DRY-RUN: %s\n' "$*"; else "$@"; fi
}

echo "capture: iface=$IFACE minutes=$MINUTES snaplen=$SNAPLEN filter='$FILTER' out=$OUT"
if [ "$DRY_RUN" -eq 0 ]; then
    [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
    command -v tcpdump >/dev/null || { echo "tcpdump not installed" >&2; exit 1; }
    install -d -m 700 "$OUT"
fi
SINCE=$(date -u '+%Y-%m-%d %H:%M:%S')

snapshot_awg() {
    local label=$1 iface
    for iface in awg0 awg-ft31; do
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "DRY-RUN: awg show $iface latest-handshakes > $OUT/awg-$iface-$label.txt"
        elif command -v awg >/dev/null && awg show "$iface" >/dev/null 2>&1; then
            awg show "$iface" latest-handshakes > "$OUT/awg-$iface-$label.txt" || true
        fi
    done
}

snapshot_awg before
run timeout --signal=INT "${MINUTES}m" tcpdump -i "$IFACE" -n -s "$SNAPLEN" -w "$OUT/headers.pcap" "$FILTER" || true
snapshot_awg after
UNTIL=$(date -u '+%Y-%m-%d %H:%M:%S')

for unit in "${UNITS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY-RUN: journalctl -u $unit --since '$SINCE' --until '$UNTIL' > $OUT/journal-$unit.txt"
    elif systemctl cat "$unit" >/dev/null 2>&1; then
        journalctl -u "$unit" --since "$SINCE" --until "$UNTIL" --no-pager -o short-iso-precise > "$OUT/journal-$unit.txt" 2>&1 || true
    fi
done

if [ "$DRY_RUN" -eq 0 ] && [ -s "$OUT/headers.pcap" ]; then
    # Per local port: packets in / out (direction from the server's view).
    tcpdump -n -r "$OUT/headers.pcap" 2>/dev/null | awk -v ports="${PORTS[*]}" '
        BEGIN { n = split(ports, p, " "); for (i = 1; i <= n; i++) watch[p[i]] = 1 }
        {
            src = $3; dst = $5; sub(/:$/, "", dst)
            sp = src; sub(/.*\./, "", sp); dp = dst; sub(/.*\./, "", dp)
            proto = ($0 ~ / UDP,/ || $0 ~ /: UDP/) ? "udp" : "tcp"
            if (dp in watch) in_[proto "/" dp]++
            else if (sp in watch) out_[proto "/" sp]++
        }
        END {
            for (k in in_) keys[k] = 1
            for (k in out_) keys[k] = 1
            for (k in keys) printf "%-10s in=%d out=%d\n", k, in_[k], out_[k]
        }' | sort > "$OUT/summary.txt"
fi
echo "done: $OUT (window $SINCE .. $UNTIL UTC) - delete after analysis"
