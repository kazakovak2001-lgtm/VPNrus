#!/usr/bin/env bash
# B37 Russia field-test diagnostic pass - run this ON a gateway (Frankfurt or
# Stockholm), over SSH, WHILE the tester in Russia presses Connect (ask them
# to do it right after you start this). It answers the exact question a
# client-side FieldTestReport alone cannot: did any client data actually
# reach this gateway after the handshake, and did the health-probe's own
# targets (this gateway itself on :443, then 1.1.1.1:443, 8.8.8.8:443) see
# any return traffic leave it - see docs/FIELD_TEST_RUSSIA_AWG31.md's own
# "Distinguishing a REAL AWG 3.1 block from a mundane reachability/config
# problem" section for how to read the result.
#
# Read-only. Captures headers/counters only - never payload (-A is never
# passed to tcpdump). Makes zero changes to any firewall/interface/service.
#
# Usage (on the gateway itself, as a user who can sudo):
#   bash gateway/tools/ft31-capture-diagnostics.sh [duration_seconds]
# duration_seconds defaults to 30 - keep it just long enough to cover one
# tester attempt (handshake + health-probe window), not left running.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

DURATION=${1:-30}
IFACE=$(detect_egress_interface)
[ -n "$IFACE" ] || { echo "could not detect egress interface" >&2; exit 1; }

echo "=== before: awg-ft31 transfer (peer bytes: tx rx, cumulative since interface came up) ==="
sudo awg show awg-ft31 transfer 2>&1
echo "=== before: awg-ft31 latest handshake ==="
sudo awg show awg-ft31 latest-handshakes 2>&1

echo
echo "=== capturing udp/51821 (awg-ft31 tunnel packets, headers only) on $IFACE for ${DURATION}s ==="
echo "    -> ask the tester to press Connect NOW"
sudo timeout "$DURATION" tcpdump -ni "$IFACE" udp port 51821 -c 200 2>&1 || true

echo
echo "=== after: awg-ft31 transfer (compare tx/rx deltas against 'before' above) ==="
sudo awg show awg-ft31 transfer 2>&1
echo "=== after: awg-ft31 latest handshake ==="
sudo awg show awg-ft31 latest-handshakes 2>&1

cat <<'EOF'

=== how to read this ===
- Zero packets captured at all -> reachability/provider/port-filtering
  problem (re-check the PREDEPLOY GATE in docs/FIELD_TEST_RUSSIA_AWG31.md),
  not a data-plane/MTU/DPI issue.
- Packets captured, but rx bytes barely increase (a few hundred bytes only,
  matching a handshake, then nothing more) -> consistent with a black hole
  AFTER the handshake (MTU drop or DPI flow throttling) - matches the
  reported HEALTH_CHECK_FAILED pattern exactly.
- rx bytes climb substantially (multiple KB) during the window -> the
  client's data IS reaching this gateway; if the health probe still failed
  client-side, the problem is more likely on the return path (egress from
  this gateway to 1.1.1.1/8.8.8.8, or back to the client) - check this
  gateway's own outbound connectivity to those two IPs separately
  (e.g. `curl -sS -m 5 -o /dev/null -w '%{http_code}\n' https://1.1.1.1/`
  run directly on the gateway, outside the tunnel).
EOF
