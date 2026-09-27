#!/usr/bin/env bash
# Exit Target ACL - functional test of gateway/nftables/pocvpn.nft.template
# inside DISPOSABLE network namespaces only. Never loads a rule into the
# caller's own namespace, never touches a real gateway. Requires root, ip,
# nft, python3, ping.
#
#   sudo bash gateway/nftables/tests/run_exit_acl_netns_tests.sh [template]
#
# Topology (mirrors AWS: the gateway's egress next hop is a PRIVATE VPC router):
#   client(10.77.0.2) --awg0-- gw(10.77.0.1 | egress0 172.31.36.199/20)
#     --- vpc router(172.31.32.1, also hosts the "internal" targets)
#     --- far(1.1.1.1, link MTU 1280)
# [template] defaults to the repository template; pass an older one as a
# control run (its "blocked" checks are expected to FAIL - proof the test
# really reaches those targets without the ACL).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "$HERE/../.." && pwd)"
TEMPLATE="${1:-$GATEWAY_DIR/nftables/pocvpn.nft.template}"
# shellcheck source=../../lib/common.sh
source "$GATEWAY_DIR/lib/common.sh"

[ "$(id -u)" -eq 0 ] || { echo "must run as root (disposable netns only)" >&2; exit 2; }

SUFFIX="exitacl$$"
C="c-$SUFFIX" G="g-$SUFFIX" V="v-$SUFFIX" F="f-$SUFFIX"
PASSES=0 FAILURES=0
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

cleanup() {
    for ns in "$C" "$G" "$V" "$F"; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

for ns in "$C" "$G" "$V" "$F"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

ip -n "$G" link add awg0 type veth peer name tun0 netns "$C"
ip -n "$G" link add egress0 type veth peer name vpc0 netns "$V"
ip -n "$V" link add far0 mtu 1280 type veth peer name up0 netns "$F" mtu 1280

ip -n "$C" addr add 10.77.0.2/24 dev tun0 && ip -n "$C" link set tun0 up
ip -n "$C" route add default via 10.77.0.1
ip -n "$G" addr add 10.77.0.1/24 dev awg0 && ip -n "$G" link set awg0 up
ip -n "$G" addr add 172.31.36.199/20 dev egress0 && ip -n "$G" link set egress0 up
ip -n "$G" route add default via 172.31.32.1
ip netns exec "$G" sysctl -qw net.ipv4.ip_forward=1
ip -n "$V" addr add 172.31.32.1/20 dev vpc0 && ip -n "$V" link set vpc0 up
ip -n "$V" addr add 10.99.0.1/30 dev far0 && ip -n "$V" link set far0 up
ip -n "$V" route add 1.1.1.1/32 via 10.99.0.2
ip netns exec "$V" sysctl -qw net.ipv4.ip_forward=1
for internal in 169.254.169.254 10.0.0.5 192.168.1.1 100.64.0.1 172.16.5.5 198.18.0.1 203.0.113.9 127.0.0.2; do
    ip -n "$V" addr add "$internal/32" dev lo 2>/dev/null
done
ip -n "$F" addr add 10.99.0.2/30 dev up0 && ip -n "$F" link set up0 up
ip -n "$F" addr add 1.1.1.1/32 dev lo
ip -n "$F" route add default via 10.99.0.1

render_template "$TEMPLATE" "NFT_TABLE=pocvpn" "AWG_IFACE=awg0" "EGRESS_IFACE=egress0" "AWG_SUBNET=10.77.0.0/24" \
    > "/tmp/$SUFFIX.nft"
grep -q "^table inet pocvpn {" "/tmp/$SUFFIX.nft" || { fail "template did not render"; exit 1; }
if ip netns exec "$G" nft -f "/tmp/$SUFFIX.nft"; then pass "template loads (nft -f)"; else fail "template loads"; exit 1; fi
# Idempotent re-apply, exactly as provision.sh re-runs.
if ip netns exec "$G" nft -f "/tmp/$SUFFIX.nft"; then pass "template re-applies idempotently"; else fail "re-apply"; fi
rm -f "/tmp/$SUFFIX.nft"
[ "$(ip netns exec "$G" nft list tables | grep -c 'table inet pocvpn')" -eq 1 ] && pass "exactly one pocvpn table" || fail "table count"

# TCP echo-peer servers: reply with the source address they saw.
SERVER='import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",8080)); s.listen(16)
while True:
    c,a=s.accept(); c.sendall(a[0].encode()); c.close()'
ip netns exec "$V" python3 -c "$SERVER" & VPID=$!
ip netns exec "$F" python3 -c "$SERVER" & FPID=$!
trap 'kill $VPID $FPID 2>/dev/null; cleanup' EXIT
sleep 1

probe() {  # probe <ip> -> prints "OK <peer-seen>" or "ERR <errno name>"
    ip netns exec "$C" python3 -c '
import socket,sys,errno
s=socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1],8080)); print("OK", s.recv(64).decode())
except OSError as e:
    print("ERR", errno.errorcode.get(e.errno, "timeout"))' "$1"
}

out="$(probe 1.1.1.1)"
[ "$out" = "OK 172.31.36.199" ] && pass "public TCP allowed and masqueraded ($out)" || fail "public TCP ($out)"
ip netns exec "$C" ping -c1 -W2 1.1.1.1 >/dev/null && pass "public ICMP echo allowed" || fail "public ICMP echo"

for target in 169.254.169.254 172.31.32.1 10.0.0.5 192.168.1.1 100.64.0.1 172.16.5.5 198.18.0.1 203.0.113.9; do
    out="$(probe "$target")"
    case "$out" in
        "ERR EHOSTUNREACH"|"ERR ECONNREFUSED") pass "blocked $target ($out)" ;;
        *) fail "blocked $target ($out)" ;;
    esac
done
if ip netns exec "$C" ping -c1 -W2 169.254.169.254 >/dev/null 2>&1; then fail "metadata ICMP blocked"; else pass "metadata ICMP blocked"; fi
# (127/8 is not probed: a client's own loopback is local to the client, and
# 127/8 arriving on awg0 is a martian the gateway kernel drops before the
# forward hook. It is still in the set as defense in depth.)
# UDP to the metadata endpoint is rejected too (ICMP admin-prohibited).
udp="$(ip netns exec "$C" python3 -c '
import socket,errno
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect(("169.254.169.254",53))
s.send(b"x")
try: s.recv(10); print("OK")
except OSError as e: print("ERR", errno.errorcode.get(e.errno,"timeout"))')"
[ "$udp" = "ERR EHOSTUNREACH" ] && pass "UDP to metadata rejected ($udp)" || fail "UDP to metadata ($udp)"

# PMTUD: a DF packet larger than the far link's MTU must produce ICMP
# "fragmentation needed" from the PRIVATE-addressed router back to the client.
pmtu="$(ip netns exec "$C" ping -c1 -W3 -M do -s 1400 1.1.1.1 2>&1)"
if echo "$pmtu" | grep -Eqi "frag needed|mtu = 1280|mtu=1280|message too long"; then
    pass "PMTUD: frag-needed from private router reaches client"
else
    fail "PMTUD ($pmtu)"
fi

# Established/related: a flow opened before the ACL keeps working is not
# testable after load; assert the rule order instead.
chain="$(ip netns exec "$G" nft list chain inet pocvpn forward)"
est=$(echo "$chain" | grep -n "ct state established,related accept" | cut -d: -f1)
acl=$(echo "$chain" | grep -n "@exit_blocked_v4" | cut -d: -f1)
acc=$(echo "$chain" | grep -n 'iifname "awg0" oifname "egress0" accept' | cut -d: -f1)
[ -n "$est" ] && [ -n "$acl" ] && [ -n "$acc" ] && [ "$est" -lt "$acl" ] && [ "$acl" -lt "$acc" ] \
    && pass "order: established,related -> ACL -> tunnel accept" || fail "rule order"
ip netns exec "$G" nft list chain inet pocvpn postrouting | grep -q 'ip saddr 10.77.0.0/24 oifname "egress0" masquerade' \
    && pass "masquerade rule intact" || fail "masquerade rule"

echo "RESULT: pass=$PASSES fail=$FAILURES"
[ "$FAILURES" -eq 0 ]
