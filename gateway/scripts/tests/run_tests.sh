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
    cp "$REPO_GATEWAY_DIR/scripts/remove-peer.sh" "$root/scripts/remove-peer.sh"
    cp "$REPO_GATEWAY_DIR/scripts/allocate-and-add-peer.sh" "$root/scripts/allocate-and-add-peer.sh"
    cp "$REPO_GATEWAY_DIR/scripts/provision-peer.sh" "$root/scripts/provision-peer.sh"
    chmod +x "$root/scripts/"*.sh

    # Fake systemctl/awg so converge_live_state's behavior is deterministic
    # and controllable, without needing a real systemd unit or AWG
    # interface. Controlled via marker files in $root/etc (see the
    # set_service_*/set_reload_*/set_live_peers helpers below). Neither
    # stub ever touches the real host's systemctl/awg/gateway.
    mkdir -p "$root/bin"
    cat > "$root/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
# Fake systemctl for gateway allocation tests - see run_tests.sh.
case "$1" in
    is-active)
        [ -f "$POCVPN_TEST_ETC/.fake_active" ] && exit 0
        exit 1
        ;;
    reload)
        echo x >> "$POCVPN_TEST_ETC/.reload_count"
        if [ -f "$POCVPN_TEST_ETC/.fake_reload_fail" ]; then
            exit 1
        fi
        if [ -f "$POCVPN_TEST_ETC/.fake_reload_converges" ]; then
            grep '^PublicKey = ' "$POCVPN_TEST_ETC/awg0.conf" 2>/dev/null | sed 's/^PublicKey = //' > "$POCVPN_TEST_ETC/live_peers.txt"
        fi
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
STUB
    cat > "$root/bin/awg" <<'STUB'
#!/usr/bin/env bash
# Fake awg for gateway allocation tests - see run_tests.sh.
if [ "$1" = "show" ] && [ "${3:-}" = "peers" ]; then
    if [ -f "$POCVPN_TEST_ETC/.fake_awg_query_fail" ]; then
        echo "fake: unable to access interface" >&2
        exit 1
    fi
    cat "$POCVPN_TEST_ETC/live_peers.txt" 2>/dev/null
    exit 0
fi
exit 0
STUB
    # Passthrough mktemp that also records its own arguments, so a test can
    # dynamically prove the real code calls `mktemp -p "$CONFIG_DIR"` (same
    # filesystem as awg0.conf) rather than the system tmp dir - not just a
    # static source-grep assertion.
    cat > "$root/bin/mktemp" <<'STUB'
#!/usr/bin/env bash
echo "$@" >> "$POCVPN_TEST_ETC/.mktemp_calls"
exec /usr/bin/mktemp "$@"
STUB
    chmod +x "$root/bin/systemctl" "$root/bin/awg" "$root/bin/mktemp"

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

allocate() { local root=$1; shift; PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" "$root/scripts/allocate-and-add-peer.sh" "$@" 2>/dev/null; }
add_manual() { local root=$1; shift; PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" "$root/scripts/add-peer.sh" "$@" 2>/dev/null; }
remove_manual() { local root=$1; shift; PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" "$root/scripts/remove-peer.sh" "$@" 2>/dev/null; }
provision() { local root=$1; shift; PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" "$root/scripts/provision-peer.sh" "$@" 2>/dev/null; }
provision_stderr() { local root=$1; shift; PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" "$root/scripts/provision-peer.sh" "$@" 2>&1 >/dev/null; }
peer_count() { local n; n=$(grep -c '^\[Peer\]' "$1/etc/awg0.conf" 2>/dev/null); echo "${n:-0}"; }
allowed_ips_of() { local root=$1 key=$2; grep -A2 "PublicKey = $key\$" "$root/etc/awg0.conf" | grep '^AllowedIPs' | sed -E 's#^AllowedIPs = ([0-9.]+)/32.*#\1#'; }
has_peer() { grep -qF "PublicKey = $2" "$1/etc/awg0.conf"; }

# --- fake systemctl/awg control helpers ---
set_service_active() { touch "$1/etc/.fake_active"; }
set_reload_fails() { touch "$1/etc/.fake_reload_fail"; }
set_reload_succeeds() { rm -f "$1/etc/.fake_reload_fail"; }
set_reload_converges() { touch "$1/etc/.fake_reload_converges"; }
set_reload_does_not_converge() { rm -f "$1/etc/.fake_reload_converges"; }
set_live_peers() { local root=$1; shift; printf '%s\n' "$@" > "$root/etc/live_peers.txt"; }
set_no_live_peers() { : > "$1/etc/live_peers.txt"; }
live_peers_of() { cat "$1/etc/live_peers.txt" 2>/dev/null; }
reload_count() { cat "$1/etc/.reload_count" 2>/dev/null | wc -l | tr -d ' '; }
set_awg_query_fails() { touch "$1/etc/.fake_awg_query_fail"; }
set_awg_query_succeeds() { rm -f "$1/etc/.fake_awg_query_fail"; }

# --- peer-marker corruption helpers (for _validate_peer_markers tests) ---
corrupt_remove_begin_marker() { sed -i '/^# --- PEERS BEGIN ---/d' "$1/etc/awg0.conf"; }
corrupt_remove_end_marker() { sed -i '/^# --- PEERS END ---/d' "$1/etc/awg0.conf"; }
corrupt_duplicate_begin_marker() { sed -i '/^# --- PEERS BEGIN ---/p' "$1/etc/awg0.conf"; }
corrupt_duplicate_end_marker() { sed -i '/^# --- PEERS END ---/p' "$1/etc/awg0.conf"; }
corrupt_reverse_markers() {
    local root=$1
    cat > "$root/etc/awg0.conf" <<'EOF'
[Interface]
PrivateKey = test-fixture-not-a-real-key
Address = 10.0.0.1/29
ListenPort = 51820

# --- PEERS END ---
# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)
EOF
    chmod 600 "$root/etc/awg0.conf"
}

# --- raw peer-block injection helpers (for find_existing_peer fail-closed
# tests below) - these write directly to awg0.conf, bypassing add-peer.sh's
# own validation entirely, because that validation is exactly what would
# normally prevent this state from ever being created. The point of these
# tests is: if it somehow got there anyway (hand-edit, an older bug, a
# race outside this codebase's control), provision-peer.sh must still
# detect it and fail closed rather than trust it. ---
insert_before_end_marker() {
    local root=$1 block=$2
    local tmp; tmp=$(mktemp)
    awk -v block="$block" '
        /^# --- PEERS END ---/ { print block; print "" }
        { print }
    ' "$root/etc/awg0.conf" > "$tmp"
    mv "$tmp" "$root/etc/awg0.conf"
    chmod 600 "$root/etc/awg0.conf"
}
corrupt_add_duplicate_key_peer() {
    local root=$1 key=$2
    insert_before_end_marker "$root" "$(printf '[Peer]\n# label: dup1\nPublicKey = %s\nAllowedIPs = 10.250.0.9/32' "$key")"
    insert_before_end_marker "$root" "$(printf '[Peer]\n# label: dup2\nPublicKey = %s\nAllowedIPs = 10.250.0.10/32' "$key")"
}
corrupt_add_malformed_allowedips_peer() {
    local root=$1 key=$2 raw_allowedips=$3
    insert_before_end_marker "$root" "$(printf '[Peer]\n# label: malformed\nPublicKey = %s\nAllowedIPs = %s' "$key" "$raw_allowedips")"
}
corrupt_add_peer_with_ip() {
    local root=$1 key=$2 ip=$3
    insert_before_end_marker "$root" "$(printf '[Peer]\n# label: raw\nPublicKey = %s\nAllowedIPs = %s/32' "$key" "$ip")"
}

# converge_only <root> <present|absent> <key> -> runs ONLY converge_live_state
# (never mutate_add_peer/mutate_remove_peer), under the same lock discipline,
# to model an operator/retry repair action against an already-persisted
# config - never a duplicate mutation.
converge_only() {
    local root=$1 expected=$2 key=$3
    PATH="$root/bin:$PATH" POCVPN_TEST_ETC="$root/etc" bash -c '
        set -euo pipefail
        source "'"$root"'/lib/common.sh"
        source "'"$root"'/lib/peer_mutations.sh"
        load_config
        exec 9>"$CONFIG_DIR/.provision.lock"
        flock -x 9
        converge_live_state "$1" "$2"
    ' _ "$expected" "$key" 2>/dev/null
}
export -f allocate add_manual remove_manual provision provision_stderr

# Bounded-background convention used by every concurrency test below:
#   timeout 15 bash -c '<fn> "$@"' _ <args...> > "$out" 2>/dev/null &
#   pidN=$!
# run directly inline in each test (NOT via a helper function called
# through command substitution: `$(...)` runs in a subshell, so a `&` job
# started inside it is a child of that subshell, not of this script - a
# later `wait "$pid"` in the caller would fail with "not a child of this
# shell". Backgrounding must happen directly in the test function's own
# shell for `$!`/`wait` to refer to the same process tree.
#
# A hung/deadlocked call is killed by `timeout` (exit 124) and therefore
# still completes and is reported as a FAILED test, never a silently-hung
# test run.

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
    remove_manual "$root" "$KEY2" >/dev/null
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

# ============================================================
# B8B0: common locking + live-state convergence tests
# ============================================================

# --- Concurrency pairings (each bounded, deadlock == FAIL) ---

test_concurrent_allocator_vs_allocator() {
    local root; root=$(make_fixture "10.97.0.0/24" "10.97.0.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'allocate "$@"' _ "$root" "$KEY1" "a" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'allocate "$@"' _ "$root" "$KEY2" "b" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    local ip1 ip2; ip1=$(cat "$out1"); ip2=$(cat "$out2")
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ -n "$ip1" ] && [ "$ip1" != "$ip2" ] && [ "$(peer_count "$root")" = "2" ]; then
        pass "allocator vs allocator: distinct IPs, no lost update, no deadlock"
    else
        fail "allocator vs allocator: rc1=$rc1 rc2=$rc2 ip1='$ip1' ip2='$ip2' peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_concurrent_allocator_vs_manual_add() {
    local root; root=$(make_fixture "10.97.1.0/24" "10.97.1.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'allocate "$@"' _ "$root" "$KEY1" "alloc" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'add_manual "$@"' _ "$root" "$KEY2" "10.97.1.50" "manual" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY1" && has_peer "$root" "$KEY2" && [ "$(peer_count "$root")" = "2" ]; then
        pass "allocator vs manual add: both persisted, no lost update, no deadlock"
    else
        fail "allocator vs manual add: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_concurrent_allocator_vs_remove() {
    local root; root=$(make_fixture "10.97.2.0/24" "10.97.2.1" 24)
    add_manual "$root" "$KEY1" "10.97.2.50" "pre-existing" >/dev/null
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'allocate "$@"' _ "$root" "$KEY2" "alloc" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'remove_manual "$@"' _ "$root" "$KEY1" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY2" && ! has_peer "$root" "$KEY1" && [ "$(peer_count "$root")" = "1" ]; then
        pass "allocator vs remove: net state correct, no lost update, no deadlock"
    else
        fail "allocator vs remove: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_concurrent_manual_add_vs_remove() {
    local root; root=$(make_fixture "10.97.3.0/24" "10.97.3.1" 24)
    add_manual "$root" "$KEY1" "10.97.3.50" "pre-existing" >/dev/null
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'add_manual "$@"' _ "$root" "$KEY2" "10.97.3.51" "new" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'remove_manual "$@"' _ "$root" "$KEY1" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY2" && ! has_peer "$root" "$KEY1" && [ "$(peer_count "$root")" = "1" ]; then
        pass "manual add vs remove: net state correct, no lost update, no deadlock"
    else
        fail "manual add vs remove: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_concurrent_manual_add_vs_manual_add() {
    local root; root=$(make_fixture "10.97.4.0/24" "10.97.4.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'add_manual "$@"' _ "$root" "$KEY1" "10.97.4.50" "a" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'add_manual "$@"' _ "$root" "$KEY2" "10.97.4.51" "b" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY1" && has_peer "$root" "$KEY2" && [ "$(peer_count "$root")" = "2" ]; then
        pass "manual add vs manual add: both persisted, no lost update, no deadlock"
    else
        fail "manual add vs manual add: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_concurrent_remove_vs_remove() {
    local root; root=$(make_fixture "10.97.5.0/24" "10.97.5.1" 24)
    add_manual "$root" "$KEY1" "10.97.5.50" "a" >/dev/null
    add_manual "$root" "$KEY2" "10.97.5.51" "b" >/dev/null
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'remove_manual "$@"' _ "$root" "$KEY1" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'remove_manual "$@"' _ "$root" "$KEY2" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$(peer_count "$root")" = "0" ]; then
        pass "remove vs remove: both removed, no lost update, no deadlock"
    else
        fail "remove vs remove: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

# --- Convergence behavior ---

test_converged_already_no_unnecessary_reload() {
    local root; root=$(make_fixture "10.98.0.0/29" "10.98.0.1" 29)
    set_service_active "$root"
    set_live_peers "$root" "$KEY1"   # live already has KEY1 before we even add it
    add_manual "$root" "$KEY1" "10.98.0.2" "peer1" >/dev/null
    if [ "$(reload_count "$root")" = "0" ] && has_peer "$root" "$KEY1"; then
        pass "already-converged live state triggers no reload"
    else
        fail "expected 0 reloads, got $(reload_count "$root") (peers=$(peer_count "$root"))"
    fi
    rm -rf "$root"
}

test_persisted_peer_live_missing_triggers_reload() {
    local root; root=$(make_fixture "10.98.1.0/29" "10.98.1.1" 29)
    set_service_active "$root"
    set_reload_converges "$root"
    add_manual "$root" "$KEY1" "10.98.1.2" "peer1" >/dev/null
    if [ "$(reload_count "$root")" -ge "1" ] && [ "$(live_peers_of "$root")" = "$KEY1" ]; then
        pass "persisted peer + live missing triggers a reload that converges"
    else
        fail "expected >=1 reload and live convergence, got reloads=$(reload_count "$root") live='$(live_peers_of "$root")'"
    fi
    rm -rf "$root"
}

test_persisted_removal_live_present_triggers_reload() {
    local root; root=$(make_fixture "10.98.2.0/29" "10.98.2.1" 29)
    set_service_active "$root"
    set_reload_converges "$root"
    add_manual "$root" "$KEY1" "10.98.2.2" "peer1" >/dev/null   # converges, live now has KEY1
    remove_manual "$root" "$KEY1" >/dev/null
    if ! live_peers_of "$root" | grep -qF "$KEY1"; then
        pass "persisted removal + live still present triggers a reload that converges"
    else
        fail "expected live state to no longer contain the removed key, got '$(live_peers_of "$root")'"
    fi
    rm -rf "$root"
}

test_reload_failure_after_durable_write_is_nonzero_config_retained() {
    local root; root=$(make_fixture "10.98.3.0/29" "10.98.3.1" 29)
    set_service_active "$root"
    set_reload_does_not_converge "$root"   # reload command "succeeds" but live state never updates
    if add_manual "$root" "$KEY1" "10.98.3.2" "peer1" >/dev/null; then
        fail "expected non-zero exit when live state cannot be made to converge"
    elif has_peer "$root" "$KEY1"; then
        pass "convergence failure is non-zero, durable config is retained (not rolled back)"
    else
        fail "convergence failed as expected but durable config was NOT retained"
    fi
    rm -rf "$root"
}

test_retry_after_convergence_failure_converges_without_duplicate_mutation() {
    local root; root=$(make_fixture "10.98.4.0/29" "10.98.4.1" 29)
    set_service_active "$root"
    set_reload_does_not_converge "$root"
    add_manual "$root" "$KEY1" "10.98.4.2" "peer1" >/dev/null || true   # fails to converge; peer IS persisted
    local peers_before; peers_before=$(peer_count "$root")

    set_reload_converges "$root"
    if converge_only "$root" present "$KEY1" && [ "$(peer_count "$root")" = "$peers_before" ] && echo "$(live_peers_of "$root")" | grep -qF "$KEY1"; then
        pass "retry converges the already-persisted peer without a duplicate mutation"
    else
        fail "retry-convergence did not succeed cleanly (peers before=$peers_before after=$(peer_count "$root"), live='$(live_peers_of "$root")')"
    fi
    rm -rf "$root"
}

# --- AWG query-failure safety (must never be mistaken for "absent") ---

test_awg_query_failure_present_is_nonzero() {
    local root; root=$(make_fixture "10.99.0.0/29" "10.99.0.1" 29)
    set_service_active "$root"
    set_awg_query_fails "$root"
    if converge_only "$root" present "$KEY1"; then
        fail "expected non-zero when the awg query fails and expected=present"
    else
        pass "AWG query failure + expected=present is non-zero"
    fi
    rm -rf "$root"
}

test_awg_query_failure_absent_is_nonzero() {
    local root; root=$(make_fixture "10.99.1.0/29" "10.99.1.1" 29)
    set_service_active "$root"
    set_awg_query_fails "$root"
    if converge_only "$root" absent "$KEY1"; then
        fail "expected non-zero when the awg query fails, even for expected=absent - a failed query must never be treated as successful absence"
    else
        pass "AWG query failure + expected=absent is non-zero (not falsely treated as absence)"
    fi
    rm -rf "$root"
}

test_zero_peers_successful_query_absent_succeeds() {
    local root; root=$(make_fixture "10.99.2.0/29" "10.99.2.1" 29)
    set_service_active "$root"
    set_no_live_peers "$root"
    if converge_only "$root" absent "$KEY1"; then
        pass "zero live peers + successful awg query: absent converges immediately"
    else
        fail "expected absent to succeed with zero live peers and a successful query"
    fi
    rm -rf "$root"
}

test_zero_peers_successful_query_present_fails() {
    local root; root=$(make_fixture "10.99.3.0/29" "10.99.3.1" 29)
    set_service_active "$root"
    set_no_live_peers "$root"
    set_reload_does_not_converge "$root"
    if converge_only "$root" present "$KEY1"; then
        fail "expected present to fail with zero live peers even after a reload attempt"
    else
        pass "zero live peers + successful awg query: present fails (attempts reload, then fails)"
    fi
    rm -rf "$root"
}

# --- Same-filesystem atomic publish (temp file under CONFIG_DIR) ---

test_mktemp_source_uses_config_dir() {
    if grep -q 'mktemp -p "\$CONFIG_DIR"' "$REPO_GATEWAY_DIR/lib/peer_mutations.sh"; then
        pass "peer_mutations.sh source creates its temp file via mktemp -p \"\$CONFIG_DIR\" (static check)"
    else
        fail "peer_mutations.sh does not appear to create its temp file under CONFIG_DIR"
    fi
}

test_tmp_file_created_under_config_dir() {
    local root; root=$(make_fixture "10.99.4.0/29" "10.99.4.1" 29)
    add_manual "$root" "$KEY1" "10.99.4.2" "peer1" >/dev/null
    if grep -qF -- "-p $root/etc" "$root/etc/.mktemp_calls" 2>/dev/null; then
        pass "mktemp is dynamically invoked with -p CONFIG_DIR - temp file shares awg0.conf's filesystem"
    else
        fail "mktemp was not invoked with -p CONFIG_DIR: $(cat "$root/etc/.mktemp_calls" 2>/dev/null)"
    fi
    rm -rf "$root"
}

# --- Peer-marker structural validation (fail-closed) + postcondition checks ---

# A. missing PEERS BEGIN
test_marker_missing_begin_rejected() {
    local root; root=$(make_fixture "10.99.5.0/29" "10.99.5.1" 29)
    corrupt_remove_begin_marker "$root"
    if add_manual "$root" "$KEY1" "10.99.5.2" "peer1" >/dev/null; then
        fail "expected rejection when the PEERS BEGIN marker is missing"
    else
        pass "missing PEERS BEGIN marker is rejected"
    fi
    rm -rf "$root"
}

# B. missing PEERS END
test_marker_missing_end_rejected() {
    local root; root=$(make_fixture "10.99.6.0/29" "10.99.6.1" 29)
    corrupt_remove_end_marker "$root"
    if add_manual "$root" "$KEY1" "10.99.6.2" "peer1" >/dev/null; then
        fail "expected rejection when the PEERS END marker is missing"
    else
        pass "missing PEERS END marker is rejected"
    fi
    rm -rf "$root"
}

# C. duplicate PEERS BEGIN
test_marker_duplicate_begin_rejected() {
    local root; root=$(make_fixture "10.99.7.0/29" "10.99.7.1" 29)
    corrupt_duplicate_begin_marker "$root"
    if add_manual "$root" "$KEY1" "10.99.7.2" "peer1" >/dev/null; then
        fail "expected rejection when the PEERS BEGIN marker is duplicated"
    else
        pass "duplicate PEERS BEGIN marker is rejected"
    fi
    rm -rf "$root"
}

# D. duplicate PEERS END
test_marker_duplicate_end_rejected() {
    local root; root=$(make_fixture "10.99.8.0/29" "10.99.8.1" 29)
    corrupt_duplicate_end_marker "$root"
    if add_manual "$root" "$KEY1" "10.99.8.2" "peer1" >/dev/null; then
        fail "expected rejection when the PEERS END marker is duplicated"
    else
        pass "duplicate PEERS END marker is rejected"
    fi
    rm -rf "$root"
}

# E. BEGIN after END (reversed)
test_marker_reversed_order_rejected() {
    local root; root=$(make_fixture "10.99.9.0/29" "10.99.9.1" 29)
    corrupt_reverse_markers "$root"
    if add_manual "$root" "$KEY1" "10.99.9.2" "peer1" >/dev/null; then
        fail "expected rejection when PEERS BEGIN occurs after PEERS END"
    else
        pass "reversed PEERS BEGIN/END order is rejected"
    fi
    rm -rf "$root"
}

# F. malformed marker config causes zero mutation
test_marker_malformed_causes_zero_mutation() {
    local root; root=$(make_fixture "10.99.10.0/29" "10.99.10.1" 29)
    corrupt_remove_end_marker "$root"
    add_manual "$root" "$KEY1" "10.99.10.2" "peer1" >/dev/null || true
    if [ "$(peer_count "$root")" = "0" ] && ! has_peer "$root" "$KEY1"; then
        pass "malformed marker structure causes zero mutation to the config"
    else
        fail "expected zero mutation, got peer_count=$(peer_count "$root")"
    fi
    rm -rf "$root"
}

# G. failed structural validation causes zero reload
test_marker_malformed_causes_zero_reload() {
    local root; root=$(make_fixture "10.99.11.0/29" "10.99.11.1" 29)
    set_service_active "$root"
    corrupt_remove_begin_marker "$root"
    add_manual "$root" "$KEY1" "10.99.11.2" "peer1" >/dev/null || true
    if [ "$(reload_count "$root")" = "0" ]; then
        pass "failed structural validation triggers zero reload attempts"
    else
        fail "expected 0 reloads, got $(reload_count "$root")"
    fi
    rm -rf "$root"
}

# H. successful add verifies key + requested /32 after mv
test_postcondition_verifies_key_and_ip_after_add() {
    local root; root=$(make_fixture "10.99.12.0/29" "10.99.12.1" 29)
    if add_manual "$root" "$KEY1" "10.99.12.2" "peer1" >/dev/null \
        && [ "$(grep -cF "PublicKey = $KEY1" "$root/etc/awg0.conf")" = "1" ] \
        && grep -A1 -F "PublicKey = $KEY1" "$root/etc/awg0.conf" | grep -qF "AllowedIPs = 10.99.12.2/32"; then
        pass "successful add: postcondition confirms exactly one peer entry with the requested /32"
    else
        fail "postcondition check did not confirm the expected published state"
    fi
    rm -rf "$root"
}

# I. successful remove verifies key is absent after mv
test_postcondition_verifies_key_absent_after_remove() {
    local root; root=$(make_fixture "10.99.13.0/29" "10.99.13.1" 29)
    add_manual "$root" "$KEY1" "10.99.13.2" "peer1" >/dev/null
    if remove_manual "$root" "$KEY1" >/dev/null && ! has_peer "$root" "$KEY1"; then
        pass "successful remove: postcondition confirms the key is absent"
    else
        fail "postcondition check did not confirm removal"
    fi
    rm -rf "$root"
}

# J. service inactive + malformed markers still fails - the key regression:
# durable-config-is-enough (inactive service) must never let a malformed,
# never-actually-mutated config be reported as success.
test_marker_malformed_fails_even_when_service_inactive() {
    local root; root=$(make_fixture "10.99.14.0/29" "10.99.14.1" 29)
    # service intentionally left INACTIVE (no set_service_active call) -
    # this is exactly the scenario the original bug report described.
    corrupt_remove_end_marker "$root"
    if add_manual "$root" "$KEY1" "10.99.14.2" "peer1" >/dev/null; then
        fail "malformed markers + inactive service must still fail, not report false success"
    elif [ "$(peer_count "$root")" = "0" ]; then
        pass "malformed markers fail closed even when the service is inactive (no false success)"
    else
        fail "command failed as expected but config was mutated anyway"
    fi
    rm -rf "$root"
}

# --- Unchanged CLI contracts (spot check alongside B8A's own test_manual_path_unchanged) ---

test_cli_usage_unchanged() {
    local root; root=$(make_fixture "10.98.5.0/29" "10.98.5.1" 29)
    local usage_add usage_remove
    usage_add=$("$root/scripts/add-peer.sh" 2>&1 || true)
    usage_remove=$("$root/scripts/remove-peer.sh" 2>&1 || true)
    if echo "$usage_add" | grep -q "usage:.*add-peer.sh <CLIENT_PUBLIC_KEY> <CLIENT_TUNNEL_IP> \[label\]" \
        && echo "$usage_remove" | grep -q "usage:.*remove-peer.sh <CLIENT_PUBLIC_KEY>"; then
        pass "add-peer.sh/remove-peer.sh usage text is unchanged"
    else
        fail "usage text changed: add='$usage_add' remove='$usage_remove'"
    fi
    rm -rf "$root"
}

# ============================================================
# B8B1A: idempotent machine-facing provision-peer.sh
# ============================================================

test_provision_first_creates_lowest_free_ip() {
    local root; root=$(make_fixture "10.151.0.0/29" "10.151.0.1" 29)
    local out; out=$(provision "$root" "$KEY1")
    local kind ip; kind=$(printf '%s' "$out" | cut -f1); ip=$(printf '%s' "$out" | cut -f2)
    if [ "$kind" = "created" ] && [ "$ip" = "10.151.0.2" ] && [ "$(peer_count "$root")" = "1" ]; then
        pass "provision-peer.sh: first provision creates the lowest free IP"
    else
        fail "expected created/10.151.0.2 with 1 peer, got kind='$kind' ip='$ip' peers=$(peer_count "$root")"
    fi
    rm -rf "$root"
}

test_provision_retry_same_key_returns_existing_same_ip() {
    local root; root=$(make_fixture "10.151.1.0/29" "10.151.1.1" 29)
    local out1; out1=$(provision "$root" "$KEY1")
    local ip1; ip1=$(printf '%s' "$out1" | cut -f2)
    local out2; out2=$(provision "$root" "$KEY1")
    local kind2 ip2; kind2=$(printf '%s' "$out2" | cut -f1); ip2=$(printf '%s' "$out2" | cut -f2)
    if [ "$kind2" = "existing" ] && [ "$ip2" = "$ip1" ]; then
        pass "provision-peer.sh: retry with the same key returns existing + the exact same IP"
    else
        fail "expected existing/$ip1, got kind='$kind2' ip='$ip2'"
    fi
    rm -rf "$root"
}

test_provision_retry_no_duplicate_peer() {
    local root; root=$(make_fixture "10.151.2.0/29" "10.151.2.1" 29)
    provision "$root" "$KEY1" >/dev/null
    provision "$root" "$KEY1" >/dev/null
    provision "$root" "$KEY1" >/dev/null
    if [ "$(peer_count "$root")" = "1" ]; then
        pass "provision-peer.sh: repeated retries (simulated lost-response) never create a duplicate peer"
    else
        fail "expected 1 peer after repeated retries, got $(peer_count "$root")"
    fi
    rm -rf "$root"
}

test_provision_concurrent_same_key() {
    local root; root=$(make_fixture "10.151.3.0/24" "10.151.3.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY1" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY1" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    local kind1 ip1 kind2 ip2
    kind1=$(cut -f1 "$out1"); ip1=$(cut -f2 "$out1")
    kind2=$(cut -f1 "$out2"); ip2=$(cut -f2 "$out2")
    local kinds_sorted; kinds_sorted=$(printf '%s\n%s\n' "$kind1" "$kind2" | sort | tr '\n' ',')
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$kinds_sorted" = "created,existing," ] \
        && [ -n "$ip1" ] && [ "$ip1" = "$ip2" ] && [ "$(peer_count "$root")" = "1" ]; then
        pass "concurrent same-key provision: one created, one existing, same IP, exactly one durable peer, no deadlock"
    else
        fail "concurrent same-key: rc1=$rc1 rc2=$rc2 kinds=$kinds_sorted ip1='$ip1' ip2='$ip2' peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_provision_concurrent_different_keys() {
    local root; root=$(make_fixture "10.151.4.0/24" "10.151.4.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY1" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY2" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    local ip1 ip2; ip1=$(cut -f2 "$out1"); ip2=$(cut -f2 "$out2")
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ -n "$ip1" ] && [ "$ip1" != "$ip2" ] && [ "$(peer_count "$root")" = "2" ]; then
        pass "concurrent different-key provisions: distinct IPs, no lost update, no deadlock"
    else
        fail "concurrent different keys: rc1=$rc1 rc2=$rc2 ip1='$ip1' ip2='$ip2' peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_provision_vs_manual_add() {
    local root; root=$(make_fixture "10.151.5.0/24" "10.151.5.1" 24)
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY1" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'add_manual "$@"' _ "$root" "$KEY2" "10.151.5.50" "manual" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY1" && has_peer "$root" "$KEY2" && [ "$(peer_count "$root")" = "2" ]; then
        pass "provision-peer.sh vs manual add-peer.sh: both persisted, no lost update, no deadlock"
    else
        fail "provision vs manual add: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_provision_vs_remove() {
    local root; root=$(make_fixture "10.151.6.0/24" "10.151.6.1" 24)
    add_manual "$root" "$KEY1" "10.151.6.50" "pre-existing" >/dev/null
    local out1 out2 pid1 pid2
    out1=$(mktemp); out2=$(mktemp)
    timeout 15 bash -c 'provision "$@"' _ "$root" "$KEY2" > "$out1" 2>/dev/null & pid1=$!
    timeout 15 bash -c 'remove_manual "$@"' _ "$root" "$KEY1" > "$out2" 2>/dev/null & pid2=$!
    wait "$pid1"; local rc1=$?
    wait "$pid2"; local rc2=$?
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && has_peer "$root" "$KEY2" && ! has_peer "$root" "$KEY1" && [ "$(peer_count "$root")" = "1" ]; then
        pass "provision-peer.sh vs remove-peer.sh: net state correct, no lost update, no deadlock"
    else
        fail "provision vs remove: rc1=$rc1 rc2=$rc2 peers=$(peer_count "$root")"
    fi
    rm -f "$out1" "$out2"; rm -rf "$root"
}

test_provision_existing_peer_live_stale_triggers_convergence() {
    local root; root=$(make_fixture "10.151.9.0/29" "10.151.9.1" 29)
    local out1; out1=$(provision "$root" "$KEY1")   # service inactive: durable only, no live push
    local ip1; ip1=$(printf '%s' "$out1" | cut -f2)
    set_service_active "$root"
    set_reload_converges "$root"
    local out2; out2=$(provision "$root" "$KEY1")
    local kind2 ip2; kind2=$(printf '%s' "$out2" | cut -f1); ip2=$(printf '%s' "$out2" | cut -f2)
    if [ "$kind2" = "existing" ] && [ "$ip2" = "$ip1" ] && [ "$(reload_count "$root")" -ge "1" ] \
        && live_peers_of "$root" | grep -qF "$KEY1" && [ "$(peer_count "$root")" = "1" ]; then
        pass "existing durable peer + stale live state: convergence is attempted and repairs it, no duplicate mutation"
    else
        fail "expected existing/$ip1 with >=1 reload and live convergence, got kind='$kind2' ip='$ip2' reloads=$(reload_count "$root") live='$(live_peers_of "$root")' peers=$(peer_count "$root")"
    fi
    rm -rf "$root"
}

test_provision_existing_peer_live_already_correct_no_reload() {
    local root; root=$(make_fixture "10.151.10.0/29" "10.151.10.1" 29)
    set_service_active "$root"
    set_reload_converges "$root"
    provision "$root" "$KEY1" >/dev/null   # created; converges live via one reload
    local before; before=$(reload_count "$root")
    local out2; out2=$(provision "$root" "$KEY1")
    local kind2; kind2=$(printf '%s' "$out2" | cut -f1)
    if [ "$kind2" = "existing" ] && [ "$(reload_count "$root")" = "$before" ]; then
        pass "existing durable peer + live already correct: no unnecessary reload"
    else
        fail "expected no additional reload, before=$before after=$(reload_count "$root") kind='$kind2'"
    fi
    rm -rf "$root"
}

test_provision_awg_query_failure_is_nonzero() {
    local root; root=$(make_fixture "10.151.11.0/29" "10.151.11.1" 29)
    provision "$root" "$KEY1" >/dev/null   # service inactive: durable only
    set_service_active "$root"
    set_awg_query_fails "$root"
    if provision "$root" "$KEY1" >/dev/null; then
        fail "expected non-zero when the awg query fails during existing-peer convergence"
    else
        pass "AWG query failure during existing-peer convergence is non-zero (never false success)"
    fi
    rm -rf "$root"
}

test_provision_ambiguous_duplicate_key_fails_closed() {
    local root; root=$(make_fixture "10.151.12.0/29" "10.151.12.1" 29)
    corrupt_add_duplicate_key_peer "$root" "$KEY1"
    local before_hash; before_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
    if provision "$root" "$KEY1" >/dev/null; then
        fail "expected rejection when durable state has multiple entries for the same public key"
    else
        local after_hash; after_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
        if [ "$before_hash" = "$after_hash" ]; then
            pass "ambiguous (duplicate-PublicKey) durable state fails closed, no mutation"
        else
            fail "ambiguous state rejected but config was mutated"
        fi
    fi
    rm -rf "$root"
}

test_provision_malformed_allowedips_fails_closed() {
    local root; root=$(make_fixture "10.151.13.0/29" "10.151.13.1" 29)
    corrupt_add_malformed_allowedips_peer "$root" "$KEY1" "not-an-ip"
    if provision "$root" "$KEY1" >/dev/null; then
        fail "expected rejection when the existing peer's AllowedIPs is not a valid /32"
    else
        pass "malformed/ambiguous AllowedIPs for an existing peer fails closed"
    fi
    rm -rf "$root"
}

test_provision_existing_ip_outside_subnet_fails_closed() {
    local root; root=$(make_fixture "10.151.14.0/29" "10.151.14.1" 29)
    corrupt_add_peer_with_ip "$root" "$KEY1" "10.200.200.200"
    if provision "$root" "$KEY1" >/dev/null; then
        fail "expected rejection when the existing peer's IP is outside AWG_SUBNET_CIDR"
    else
        pass "existing peer IP outside the subnet fails closed"
    fi
    rm -rf "$root"
}

test_provision_existing_ip_equals_gateway_fails_closed() {
    local root; root=$(make_fixture "10.151.15.0/29" "10.151.15.1" 29)
    corrupt_add_peer_with_ip "$root" "$KEY1" "10.151.15.1"
    if provision "$root" "$KEY1" >/dev/null; then
        fail "expected rejection when the existing peer's IP equals the gateway's own tunnel IP"
    else
        pass "existing peer IP equal to the gateway's tunnel IP fails closed"
    fi
    rm -rf "$root"
}

test_provision_subnet_exhaustion_dedicated_exit_code() {
    local root; root=$(make_fixture "10.151.16.0/30" "10.151.16.1" 30)   # only .2 usable
    provision "$root" "$KEY1" >/dev/null   # takes the only usable address
    local before_hash; before_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
    local rc=0
    provision "$root" "$KEY2" >/dev/null || rc=$?
    local after_hash; after_hash=$(md5sum "$root/etc/awg0.conf" | awk '{print $1}')
    if [ "$rc" -eq 20 ] && [ "$before_hash" = "$after_hash" ]; then
        pass "subnet exhaustion returns the dedicated exit code 20, no mutation"
    else
        fail "expected exit code 20 and no mutation, got rc=$rc before=$before_hash after=$after_hash"
    fi
    rm -rf "$root"
}

test_provision_stdout_contract_created_and_existing() {
    local root; root=$(make_fixture "10.151.17.0/29" "10.151.17.1" 29)
    local out1; out1=$(provision "$root" "$KEY1")
    local out2; out2=$(provision "$root" "$KEY1")
    if [ "$out1" = "$(printf 'created\t10.151.17.2')" ] && [ "$out2" = "$(printf 'existing\t10.151.17.2')" ] \
        && [ "$(printf '%s' "$out1" | wc -l)" = "0" ] && [ "$(printf '%s' "$out2" | wc -l)" = "0" ]; then
        pass "stdout is exactly one tab-separated created/existing line, nothing else"
    else
        fail "unexpected stdout: out1='$out1' out2='$out2'"
    fi
    rm -rf "$root"
}

test_provision_usage_requires_exactly_one_arg() {
    local root; root=$(make_fixture "10.151.18.0/29" "10.151.18.1" 29)
    local usage_none usage_two
    usage_none=$("$root/scripts/provision-peer.sh" 2>&1 || true)
    usage_two=$("$root/scripts/provision-peer.sh" "$KEY1" "extra-arg" 2>&1 || true)
    if echo "$usage_none" | grep -q "usage:.*provision-peer.sh <CLIENT_PUBLIC_KEY>" \
        && echo "$usage_two" | grep -q "usage:.*provision-peer.sh <CLIENT_PUBLIC_KEY>"; then
        pass "provision-peer.sh requires exactly one argument - no caller-controlled label accepted"
    else
        fail "provision-peer.sh usage/argcount check failed: none='$usage_none' two='$usage_two'"
    fi
    rm -rf "$root"
}

test_allocate_and_add_peer_usage_and_duplicate_unchanged() {
    local root; root=$(make_fixture "10.151.19.0/29" "10.151.19.1" 29)
    local usage; usage=$("$root/scripts/allocate-and-add-peer.sh" 2>&1 || true)
    allocate "$root" "$KEY1" "peer1" >/dev/null
    local dup_rejected=1
    if allocate "$root" "$KEY1" "peer1-again" >/dev/null 2>&1; then dup_rejected=0; fi
    if echo "$usage" | grep -q "usage:.*allocate-and-add-peer.sh <CLIENT_PUBLIC_KEY> \[label\]" \
        && [ "$dup_rejected" = "1" ] && [ "$(peer_count "$root")" = "1" ]; then
        pass "allocate-and-add-peer.sh usage text and duplicate-key rejection are unchanged after extraction to shared lib functions"
    else
        fail "allocate-and-add-peer.sh regressed after extraction: usage='$usage' dup_rejected=$dup_rejected peers=$(peer_count "$root")"
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

test_concurrent_allocator_vs_allocator
test_concurrent_allocator_vs_manual_add
test_concurrent_allocator_vs_remove
test_concurrent_manual_add_vs_remove
test_concurrent_manual_add_vs_manual_add
test_concurrent_remove_vs_remove
test_converged_already_no_unnecessary_reload
test_persisted_peer_live_missing_triggers_reload
test_persisted_removal_live_present_triggers_reload
test_reload_failure_after_durable_write_is_nonzero_config_retained
test_retry_after_convergence_failure_converges_without_duplicate_mutation
test_awg_query_failure_present_is_nonzero
test_awg_query_failure_absent_is_nonzero
test_zero_peers_successful_query_absent_succeeds
test_zero_peers_successful_query_present_fails
test_mktemp_source_uses_config_dir
test_tmp_file_created_under_config_dir
test_marker_missing_begin_rejected
test_marker_missing_end_rejected
test_marker_duplicate_begin_rejected
test_marker_duplicate_end_rejected
test_marker_reversed_order_rejected
test_marker_malformed_causes_zero_mutation
test_marker_malformed_causes_zero_reload
test_postcondition_verifies_key_and_ip_after_add
test_postcondition_verifies_key_absent_after_remove
test_marker_malformed_fails_even_when_service_inactive
test_cli_usage_unchanged

test_provision_first_creates_lowest_free_ip
test_provision_retry_same_key_returns_existing_same_ip
test_provision_retry_no_duplicate_peer
test_provision_concurrent_same_key
test_provision_concurrent_different_keys
test_provision_vs_manual_add
test_provision_vs_remove
test_provision_existing_peer_live_stale_triggers_convergence
test_provision_existing_peer_live_already_correct_no_reload
test_provision_awg_query_failure_is_nonzero
test_provision_ambiguous_duplicate_key_fails_closed
test_provision_malformed_allowedips_fails_closed
test_provision_existing_ip_outside_subnet_fails_closed
test_provision_existing_ip_equals_gateway_fails_closed
test_provision_subnet_exhaustion_dedicated_exit_code
test_provision_stdout_contract_created_and_existing
test_provision_usage_requires_exactly_one_arg
test_allocate_and_add_peer_usage_and_duplicate_unchanged

echo
echo "== results: $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
