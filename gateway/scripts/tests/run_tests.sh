#!/usr/bin/env bash
# Test harness for gateway/scripts/allocate-and-add-peer.sh, plus a
# regression check that the existing manual add-peer.sh path is unchanged.
#
# Runs entirely against isolated temp copies of the real
# gateway/{lib,scripts,config} tree - never touches a real gateway (local
# WSL2 dev gateway or the live Oracle box). No network, no systemd, no
# root privilege required for most tests (see test_add_peer_failure for the
# one that needs to actually deny a filesystem write).
#
#   bash gateway/scripts/tests/run_tests.sh
set -uo pipefail

REPO_GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILURES=0
PASSES=0

fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }

# Arbitrary 44-char base64-shaped strings matching the real WG/AWG key format
# (32 raw bytes -> 44 base64 chars, trailing '=') - NOT real keys, fixture-only.
KEY1="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
KEY2="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
KEY3="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
KEY4="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="

# make_fixture <subnet_cidr> <gateway_ip> <prefix> -> prints the fixture root dir
make_fixture() {
    local subnet_cidr=$1 gateway_ip=$2 prefix=$3
    local root
    root=$(mktemp -d)
    cp -r "$REPO_GATEWAY_DIR/lib" "$root/lib"
    mkdir -p "$root/scripts" "$root/config" "$root/etc" "$root/build"
    cp "$REPO_GATEWAY_DIR/scripts/add-peer.sh" "$root/scripts/add-peer.sh"
    cp "$REPO_GATEWAY_DIR/scripts/allocate-and-add-peer.sh" "$root/scripts/allocate-and-add-peer.sh"
    chmod +x "$root/scripts/"*.sh
    cat > "$root/config/poc.env" <<EOF
AWG_SUBNET_CIDR=$subnet_cidr
GATEWAY_TUNNEL_IP=$gateway_ip
GATEWAY_TUNNEL_PREFIX=$prefix
LISTEN_PORT=51820
INTERFACE_NAME=awg0
CONFIG_DIR=$root/etc
CONFIG_FILE=awg0.conf
SERVICE_NAME=pocvpn-test-nonexistent-$RANDOM
NFT_TABLE=pocvpn
BUILD_DIR=$root/build
EOF
    cp "$REPO_GATEWAY_DIR/config/awg-profile.env" "$root/config/awg-profile.env"
    cat > "$root/etc/awg0.conf" <<EOF
[Interface]
PrivateKey = test-fixture-not-a-real-key
Address = $gateway_ip/$prefix
ListenPort = 51820

# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)
# --- PEERS END ---
EOF
    chmod 600 "$root/etc/awg0.conf"
    echo "$root"
}

allocate() { local root=$1; shift; "$root/scripts/allocate-and-add-peer.sh" "$@" 2>/dev/null; }
add_manual() { local root=$1; shift; "$root/scripts/add-peer.sh" "$@" 2>/dev/null; }
peer_count() { local n; n=$(grep -c '^\[Peer\]' "$1/etc/awg0.conf" 2>/dev/null); echo "${n:-0}"; }
allowed_ips_of() { local root=$1 key=$2; grep -A2 "PublicKey = $key\$" "$root/etc/awg0.conf" | grep '^AllowedIPs' | sed -E 's#^AllowedIPs = ([0-9.]+)/32.*#\1#'; }

# --- 1. Empty peer set -> first valid client IP ---
test_first_allocation() {
    local root; root=$(make_fixture "10.90.0.0/29" "10.90.0.1" 29)
    local ip; ip=$(allocate "$root" "$KEY1" "peer1")
    if [ "$ip" = "10.90.0.2" ] && [ "$(peer_count "$root")" = "1" ]; then
        pass "empty peer set allocates the lowest usable address (10.90.0.2), not .0/.1"
    else
        fail "expected 10.90.0.2 with 1 peer, got ip='$ip' peers=$(peer_count "$root")"
    fi
    rm -rf "$root"
}

# --- 2. Sequential allocations -> distinct deterministic IPs ---
test_sequential_allocations() {
    local root; root=$(make_fixture "10.90.0.0/29" "10.90.0.1" 29)
    local ip1 ip2 ip3
    ip1=$(allocate "$root" "$KEY1" "peer1")
    ip2=$(allocate "$root" "$KEY2" "peer2")
    ip3=$(allocate "$root" "$KEY3" "peer3")
    if [ "$ip1" = "10.90.0.2" ] && [ "$ip2" = "10.90.0.3" ] && [ "$ip3" = "10.90.0.4" ]; then
        pass "sequential allocations are distinct and deterministic (.2, .3, .4)"
    else
        fail "expected .2/.3/.4, got $ip1/$ip2/$ip3"
    fi
    rm -rf "$root"
}

# --- 3. Existing holes -> lowest free IP is reused safely ---
test_hole_reuse() {
    local root; root=$(make_fixture "10.90.0.0/29" "10.90.0.1" 29)
    allocate "$root" "$KEY1" "peer1" >/dev/null   # .2
    allocate "$root" "$KEY2" "peer2" >/dev/null   # .3
    allocate "$root" "$KEY3" "peer3" >/dev/null   # .4
    # Remove the middle peer (.3) to create a hole, using the real remove-peer.sh.
    cp "$REPO_GATEWAY_DIR/scripts/remove-peer.sh" "$root/scripts/remove-peer.sh"
    chmod +x "$root/scripts/remove-peer.sh"
    "$root/scripts/remove-peer.sh" "$KEY2" >/dev/null 2>/dev/null
    local ip4; ip4=$(allocate "$root" "$KEY4" "peer4")
    if [ "$ip4" = "10.90.0.3" ] && [ "$(peer_count "$root")" = "3" ]; then
        pass "a freed hole (.3) is reused as the lowest free address, not appended past .4"
    else
        fail "expected hole reuse at .3 with 3 peers, got ip=$ip4 peers=$(peer_count "$root")"
    fi
    rm -rf "$root"
}

# --- 4. Duplicate public key -> rejected ---
test_duplicate_key_rejected() {
    local root; root=$(make_fixture "10.90.0.0/29" "10.90.0.1" 29)
    allocate "$root" "$KEY1" "peer1" >/dev/null
    if allocate "$root" "$KEY1" "peer1-again" >/dev/null 2>&1; then
        fail "duplicate public key was accepted, must be rejected"
    elif [ "$(peer_count "$root")" = "1" ]; then
        pass "duplicate public key is rejected, peer count stays at 1"
    else
        fail "duplicate public key rejected but peer count changed to $(peer_count "$root")"
    fi
    rm -rf "$root"
}

# --- 5. Exhausted subnet -> rejected without mutation ---
test_exhausted_subnet() {
    # /30 with the gateway at .1 leaves exactly one usable host address (.2).
    local root; root=$(make_fixture "10.91.0.0/30" "10.91.0.1" 30)
    allocate "$root" "$KEY1" "peer1" >/dev/null   # takes the only usable address, .2
    local before_hash; before_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
    if allocate "$root" "$KEY2" "peer2" >/dev/null 2>&1; then
        fail "allocation succeeded on an exhausted subnet, must fail closed"
    else
        local after_hash; after_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
        if [ "$before_hash" = "$after_hash" ] && [ "$(peer_count "$root")" = "1" ]; then
            pass "exhausted subnet is rejected without mutating the config"
        else
            fail "exhausted subnet rejected but config was mutated"
        fi
    fi
    rm -rf "$root"
}

# --- 6. Two genuinely concurrent invocations -> distinct IPs ---
test_concurrent_allocations() {
    local root; root=$(make_fixture "10.92.0.0/24" "10.92.0.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    allocate "$root" "$KEY1" "concurrent-a" > "$out1" 2>/dev/null &
    pid1=$!
    allocate "$root" "$KEY2" "concurrent-b" > "$out2" 2>/dev/null &
    pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    local ip1 ip2; ip1=$(cat "$out1"); ip2=$(cat "$out2")
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ -n "$ip1" ] && [ -n "$ip2" ] && [ "$ip1" != "$ip2" ] && [ "$(peer_count "$root")" = "2" ]; then
        pass "two concurrent allocations receive distinct IPs ($ip1, $ip2), no lost update"
    else
        fail "concurrent allocation collision or failure: rc1=$rc1 rc2=$rc2 ip1='$ip1' ip2='$ip2' peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"
    rm -rf "$root"
}

# --- 7. add-peer.sh failure -> allocation is not reported successful ---
test_add_peer_failure_not_reported_successful() {
    local root; root=$(make_fixture "10.93.0.0/29" "10.93.0.1" 29)
    # Make the config file immutable so add-peer.sh's own `mv` write step
    # fails (chmod alone doesn't stop a root-owned process; chattr +i does,
    # and this harness always runs as root) - independent of any
    # allocate-and-add-peer.sh precondition check.
    local have_chattr=1
    chattr +i "$root/etc/awg0.conf" 2>/dev/null || have_chattr=0
    if [ "$have_chattr" = "0" ]; then
        fail "chattr +i unsupported on this filesystem - cannot exercise a real add-peer.sh write failure"
        rm -rf "$root"
        return
    fi
    local out; out=$(mktemp)
    if allocate "$root" "$KEY1" "peer1" > "$out" 2>/dev/null; then
        chattr -i "$root/etc/awg0.conf" 2>/dev/null
        fail "allocate succeeded despite add-peer.sh being unable to write the config"
    else
        chattr -i "$root/etc/awg0.conf" 2>/dev/null
        if [ -z "$(cat "$out")" ] && [ "$(peer_count "$root")" = "0" ]; then
            pass "add-peer.sh write failure propagates - no IP printed, no peer recorded"
        else
            fail "add-peer.sh write failure but stdout='$(cat "$out")' peers=$(peer_count "$root")"
        fi
    fi
    rm -f "$out"
    rm -rf "$root"
}

# --- 8. Existing manual add-peer.sh path still behaves unchanged ---
test_manual_path_unchanged() {
    local root; root=$(make_fixture "10.94.0.0/29" "10.94.0.1" 29)
    add_manual "$root" "$KEY1" "10.94.0.5" "manual-peer" >/dev/null
    local ok=1
    [ "$(peer_count "$root")" = "1" ] || ok=0
    grep -q "PublicKey = $KEY1" "$root/etc/awg0.conf" || ok=0
    grep -q "AllowedIPs = 10.94.0.5/32" "$root/etc/awg0.conf" || ok=0
    # duplicate public key still rejected
    if add_manual "$root" "$KEY1" "10.94.0.6" "manual-peer-2" >/dev/null 2>&1; then ok=0; fi
    # duplicate tunnel IP still rejected
    if add_manual "$root" "$KEY2" "10.94.0.5" "manual-peer-3" >/dev/null 2>&1; then ok=0; fi
    if [ "$ok" = "1" ] && [ "$(peer_count "$root")" = "1" ]; then
        pass "manual add-peer.sh <key> <ip> [label] path is unchanged"
    else
        fail "manual add-peer.sh path regressed"
    fi
    rm -rf "$root"
}

# --- 9. Re-running with the same public key cannot create duplicate peer state ---
test_rerun_same_key_no_duplicate() {
    local root; root=$(make_fixture "10.95.0.0/29" "10.95.0.1" 29)
    local ip1; ip1=$(allocate "$root" "$KEY1" "peer1")
    if allocate "$root" "$KEY1" "peer1-retry" >/dev/null 2>&1; then
        fail "re-running allocate with the same public key was accepted"
    elif [ "$(peer_count "$root")" = "1" ] && [ "$(allowed_ips_of "$root" "$KEY1")" = "$ip1" ]; then
        pass "re-running with the same public key is rejected, no duplicate peer state"
    else
        fail "re-run rejected but peer state changed: peers=$(peer_count "$root") ip=$(allowed_ips_of "$root" "$KEY1")"
    fi
    rm -rf "$root"
}

# --- Bonus: gateway address (.1) is never allocated, even as the very first call ---
test_gateway_address_never_allocated() {
    local root; root=$(make_fixture "10.96.0.0/29" "10.96.0.1" 29)
    local ip; ip=$(allocate "$root" "$KEY1" "peer1")
    if [ "$ip" != "10.96.0.1" ] && [ "$ip" != "10.96.0.0" ] && [ "$ip" != "10.96.0.7" ]; then
        pass "gateway/network/broadcast addresses are never allocated (.0, .1, .7 for a /29)"
    else
        fail "reserved address was allocated: $ip"
    fi
    rm -rf "$root"
}

echo "== gateway allocation test suite =="
test_first_allocation
test_sequential_allocations
test_hole_reuse
test_duplicate_key_rejected
test_exhausted_subnet
test_concurrent_allocations
test_add_peer_failure_not_reported_successful
test_manual_path_unchanged
test_rerun_same_key_no_duplicate
test_gateway_address_never_allocated

echo
echo "== results: $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
