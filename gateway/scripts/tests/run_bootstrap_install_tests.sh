#!/usr/bin/env bash
# PR #60: transactional-behavior tests for install-bootstrap-peer.sh.
#
# Proves the corrected install order (restriction verified live BEFORE the
# shared/public bootstrap peer is ever added) and the fail-closed rollback
# trap, entirely against isolated temp copies of the real
# gateway/{lib,scripts,config,nftables,systemd} tree - never a real
# gateway, never real nft/systemctl/awg, never root.
#
#   bash gateway/scripts/tests/run_bootstrap_install_tests.sh
#
# `nft`, `systemctl`, `awg`, `id` are faked (PATH-shadowed, see
# make_fixture below) so this suite runs on any host, with or without
# nftables/systemd/AmneziaWG actually installed - the real add-peer.sh/
# remove-peer.sh and the real install-bootstrap-peer.sh transaction logic
# run unmodified against those fakes.
set -uo pipefail

REPO_GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILURES=0
PASSES=0

fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }

# Arbitrary 44-char base64-shaped strings matching the real WG/AWG key
# format (32 raw bytes -> 44 base64 chars, trailing '=') - NOT real keys.
BOOTSTRAP_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
BOOTSTRAP_IP="10.77.0.250"
BOOTSTRAP_TABLE="pocvpn_bootstrap_test"
FWD_PRIORITY="-5"
INPUT_PRIORITY="-5"

# make_fixture -> prints the fixture root dir. Every test gets its own,
# disposable, isolated tree.
make_fixture() {
    local root
    root=$(mktemp -d)
    cp -r "$REPO_GATEWAY_DIR/lib" "$root/lib"
    mkdir -p "$root/scripts" "$root/config" "$root/etc" "$root/nftables" "$root/systemd" "$root/build"
    cp "$REPO_GATEWAY_DIR/scripts/add-peer.sh" "$root/scripts/add-peer.sh"
    cp "$REPO_GATEWAY_DIR/scripts/remove-peer.sh" "$root/scripts/remove-peer.sh"
    cp "$REPO_GATEWAY_DIR/scripts/install-bootstrap-peer.sh" "$root/scripts/install-bootstrap-peer.sh"
    cp "$REPO_GATEWAY_DIR/nftables/pocvpn-bootstrap.nft.template" "$root/nftables/pocvpn-bootstrap.nft.template"
    cp "$REPO_GATEWAY_DIR/systemd/nftables-pocvpn-bootstrap.service" "$root/systemd/nftables-pocvpn-bootstrap.service"
    chmod +x "$root/scripts/"*.sh

    mkdir -p "$root/bin"

    # Fake nft: -c -f <file> (syntax check), -f <file> (apply), list table
    # <family> <table>, delete table <family> <table>. Applying copies the
    # rendered file verbatim into a "live table" state file - the rendered
    # file already contains the real `hook forward/input priority ...;`
    # and `ip saddr ... drop`/`accept` lines the caller's verification
    # greps for, so this doubles as a faithful enough live-state stand-in
    # without reimplementing nft. Controlled via marker files in $root/etc.
    cat > "$root/bin/nft" <<STUB
#!/usr/bin/env bash
BOOT_STATE="\$POCVPN_TEST_ETC/.bootstrap_table_live.conf"
case "\$1" in
    -c)
        if [ -f "\$POCVPN_TEST_ETC/.fake_nft_check_fail" ]; then
            echo "Error: fake syntax error (test-injected)" >&2
            exit 1
        fi
        exit 0
        ;;
    -f)
        if [ -f "\$POCVPN_TEST_ETC/.fake_nft_apply_fail" ]; then
            echo "Error: fake apply failure (test-injected)" >&2
            exit 1
        fi
        cp "\$2" "\$BOOT_STATE"
        exit 0
        ;;
    list)
        # list table <family> <table>
        family=\$3
        table=\$4
        if [ "\$family" = "inet" ] && [ "\$table" = "$BOOTSTRAP_TABLE" ]; then
            [ -f "\$BOOT_STATE" ] || exit 1
            cat "\$BOOT_STATE"
            exit 0
        fi
        if [ "\$family" = "inet" ] && [ "\$table" = "pocvpn" ]; then
            cat <<'PROD'
table inet pocvpn {
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
}
PROD
            exit 0
        fi
        exit 1
        ;;
    delete)
        rm -f "\$BOOT_STATE"
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
STUB

    # Fake systemctl: tracks the bootstrap unit's active/inactive state
    # (controllable enable failure) separately from the pre-existing
    # awg-service reload/is-active simulation add-peer.sh's own
    # converge_live_state relies on (see gateway/scripts/tests/run_tests.sh
    # for the original of that half - unchanged here).
    cat > "$root/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    is-active)
        unit="$3"
        if [ "$unit" = "nftables-pocvpn-bootstrap.service" ]; then
            grep -qxF "$unit" "$POCVPN_TEST_ETC/.active_units" 2>/dev/null && exit 0 || exit 1
        fi
        [ -f "$POCVPN_TEST_ETC/.fake_active" ] && exit 0 || exit 1
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
    enable)
        unit="$3"
        if [ -f "$POCVPN_TEST_ETC/.fake_enable_fail" ]; then
            echo "fake: enable failed (test-injected)" >&2
            exit 1
        fi
        echo "$unit" >> "$POCVPN_TEST_ETC/.active_units"
        exit 0
        ;;
    disable)
        unit="$3"
        touch "$POCVPN_TEST_ETC/.active_units"
        grep -vxF "$unit" "$POCVPN_TEST_ETC/.active_units" > "$POCVPN_TEST_ETC/.active_units.tmp" 2>/dev/null || true
        mv "$POCVPN_TEST_ETC/.active_units.tmp" "$POCVPN_TEST_ETC/.active_units"
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
STUB

    cat > "$root/bin/awg" <<'STUB'
#!/usr/bin/env bash
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

    # Fake `id -u` -> 0: install-bootstrap-peer.sh's root check must pass
    # without actually running this suite as root.
    cat > "$root/bin/id" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "-u" ]; then
    echo 0
    exit 0
fi
exit 0
STUB
    chmod +x "$root/bin/nft" "$root/bin/systemctl" "$root/bin/awg" "$root/bin/id"

    cat > "$root/config/poc.env" <<EOF
AWG_SUBNET_CIDR=10.77.0.0/24
GATEWAY_TUNNEL_IP=10.77.0.1
GATEWAY_TUNNEL_PREFIX=24
LISTEN_PORT=51820
INTERFACE_NAME=awg0
CONFIG_DIR=$root/etc
CONFIG_FILE=awg0.conf
SERVICE_NAME=pocvpn-test-nonexistent-$RANDOM
NFT_TABLE=pocvpn
BUILD_DIR=$root/build
EOF
    cp "$REPO_GATEWAY_DIR/config/awg-profile.env" "$root/config/awg-profile.env"

    cat > "$root/config/bootstrap.env" <<EOF
BOOTSTRAP_CLIENT_PUBLIC_KEY=$BOOTSTRAP_KEY
BOOTSTRAP_CLIENT_TUNNEL_IP=$BOOTSTRAP_IP
BOOTSTRAP_NFT_TABLE=$BOOTSTRAP_TABLE
BOOTSTRAP_FORWARD_PRIORITY=$FWD_PRIORITY
BOOTSTRAP_INPUT_PRIORITY=$INPUT_PRIORITY
EOF

    cat > "$root/etc/awg0.conf" <<EOF
[Interface]
PrivateKey = test-fixture-not-a-real-key
Address = 10.77.0.1/24
ListenPort = 51820

# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)
# --- PEERS END ---
EOF
    chmod 600 "$root/etc/awg0.conf"
    echo "$root"
}

# install <root> [args...] -> runs install-bootstrap-peer.sh --runtime
# stockholm against the fixture (its production table is faked as
# `inet pocvpn` with a FORWARD-only hook, matching Stockholm's real,
# verified shape - see docs/B36_SERVER_DEPLOYMENT_PLAN.md).
run_install() {
    local root=$1; shift
    PATH="$root/bin:$PATH" \
    POCVPN_TEST_ETC="$root/etc" \
    BOOTSTRAP_NFT_CONF_PATH="$root/etc/nftables.pocvpn-bootstrap.conf" \
    BOOTSTRAP_SYSTEMD_UNIT_PATH="$root/etc/nftables-pocvpn-bootstrap.service" \
        "$root/scripts/install-bootstrap-peer.sh" --runtime stockholm "$@"
}
run_install_no_runtime() {
    local root=$1; shift
    PATH="$root/bin:$PATH" \
    POCVPN_TEST_ETC="$root/etc" \
    BOOTSTRAP_NFT_CONF_PATH="$root/etc/nftables.pocvpn-bootstrap.conf" \
    BOOTSTRAP_SYSTEMD_UNIT_PATH="$root/etc/nftables-pocvpn-bootstrap.service" \
        "$root/scripts/install-bootstrap-peer.sh" "$@"
}
export -f run_install run_install_no_runtime

set_service_active() { touch "$1/etc/.fake_active"; }
set_reload_converges() { touch "$1/etc/.fake_reload_converges"; }
set_nft_check_fails() { touch "$1/etc/.fake_nft_check_fail"; }
set_nft_apply_fails() { touch "$1/etc/.fake_nft_apply_fail"; }
set_enable_fails() { touch "$1/etc/.fake_enable_fail"; }
set_awg_query_fails() { touch "$1/etc/.fake_awg_query_fail"; }

peer_count() { local n; n=$(grep -c '^\[Peer\]' "$1/etc/awg0.conf" 2>/dev/null); echo "${n:-0}"; }
has_durable_peer() { grep -qF "PublicKey = $BOOTSTRAP_KEY" "$1/etc/awg0.conf" 2>/dev/null; }
has_live_peer() { grep -qF "$BOOTSTRAP_KEY" "$1/etc/live_peers.txt" 2>/dev/null; }
table_live() { [ -f "$1/etc/.bootstrap_table_live.conf" ]; }
unit_active() { grep -qxF "nftables-pocvpn-bootstrap.service" "$1/etc/.active_units" 2>/dev/null; }
conf_file_exists() { [ -f "$1/etc/nftables.pocvpn-bootstrap.conf" ]; }

# --- 1. nft apply failure -> add-peer.sh is NEVER called ---------------
test_nft_apply_failure_never_calls_add_peer() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    set_nft_apply_fails "$root"
    if run_install "$root" >/dev/null 2>&1; then
        fail "nft apply failure: install reported success"
    elif has_durable_peer "$root" || [ "$(peer_count "$root")" != "0" ]; then
        fail "nft apply failure: bootstrap peer was durably added despite the apply failing"
    else
        pass "nft apply failure: add-peer.sh is never reached, no peer state created"
    fi
    rm -rf "$root"
}

# --- 2. persistence failure -> add-peer.sh never called + state cleaned
test_persistence_failure_cleans_up_and_never_calls_add_peer() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    set_enable_fails "$root"
    if run_install "$root" >/dev/null 2>&1; then
        fail "persistence failure: install reported success"
    elif has_durable_peer "$root" || [ "$(peer_count "$root")" != "0" ]; then
        fail "persistence failure: bootstrap peer was durably added despite persistence failing"
    elif table_live "$root"; then
        fail "persistence failure: dedicated bootstrap table was not rolled back"
    elif conf_file_exists "$root"; then
        fail "persistence failure: rendered bootstrap conf file was not cleaned up"
    else
        pass "persistence failure: add-peer.sh never reached, dedicated firewall state rolled back"
    fi
    rm -rf "$root"
}

# --- 3. add-peer failure -> dedicated bootstrap firewall state rolled back
test_add_peer_failure_rolls_back_firewall_state() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    local have_chattr=1
    chattr +i "$root/etc/awg0.conf" 2>/dev/null || have_chattr=0
    if [ "$have_chattr" = "0" ]; then
        fail "chattr +i unsupported on this filesystem - cannot exercise a real add-peer.sh write failure"
        rm -rf "$root"
        return
    fi
    local rc=0
    run_install "$root" >/dev/null 2>&1 || rc=$?
    chattr -i "$root/etc/awg0.conf" 2>/dev/null
    if [ "$rc" -eq 0 ]; then
        fail "add-peer failure: install reported success"
    elif table_live "$root" || unit_active "$root" || conf_file_exists "$root"; then
        fail "add-peer failure: dedicated firewall state (table/unit/conf) was not fully rolled back"
    else
        pass "add-peer failure: dedicated bootstrap firewall state is rolled back"
    fi
    rm -rf "$root"
}

# --- 4. post-peer verification failure -> peer + firewall both rolled back
test_post_peer_verification_failure_rolls_back_both() {
    local root; root=$(make_fixture)
    # Service left INACTIVE: add-peer.sh's own converge_live_state
    # succeeds durably-only (matches its documented "will apply on next
    # start" contract) WITHOUT ever pushing live state - so the durable
    # config gets the peer, but live_peers.txt never does. This is exactly
    # the scenario verify_bootstrap_peer_live's own live-state check must
    # catch and fail closed on.
    if run_install "$root" >/dev/null 2>&1; then
        fail "post-peer verification failure: install reported success despite the peer never reaching live state"
    elif has_durable_peer "$root"; then
        fail "post-peer verification failure: bootstrap peer was left in durable config after rollback"
    elif table_live "$root" || unit_active "$root" || conf_file_exists "$root"; then
        fail "post-peer verification failure: dedicated firewall state was not fully rolled back"
    else
        pass "post-peer verification failure: both the bootstrap peer and the dedicated firewall state are rolled back"
    fi
    rm -rf "$root"
}

# --- 5. successful install -> restriction exists before peer-add -------
test_successful_install_restriction_before_peer_add() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    # Fake add-peer.sh wrapper that snapshots whether the bootstrap table
    # was already live at the moment it is invoked - the real add-peer.sh
    # is still exec'd immediately after, unmodified.
    mv "$root/scripts/add-peer.sh" "$root/scripts/add-peer.sh.real"
    cat > "$root/scripts/add-peer.sh" <<STUB
#!/usr/bin/env bash
if [ -f "\$POCVPN_TEST_ETC/.bootstrap_table_live.conf" ]; then
    echo present > "\$POCVPN_TEST_ETC/.table_state_at_peer_add"
else
    echo absent > "\$POCVPN_TEST_ETC/.table_state_at_peer_add"
fi
exec "\$(dirname "\$0")/add-peer.sh.real" "\$@"
STUB
    chmod +x "$root/scripts/add-peer.sh"

    if ! run_install "$root" >/dev/null 2>&1; then
        fail "successful install: expected success, install failed"
    elif [ "$(cat "$root/etc/.table_state_at_peer_add" 2>/dev/null)" != "present" ]; then
        fail "successful install: bootstrap table was not yet live when add-peer.sh was invoked"
    elif ! has_durable_peer "$root" || ! has_live_peer "$root"; then
        fail "successful install: bootstrap peer not fully present after a reported success"
    elif ! table_live "$root" || ! unit_active "$root"; then
        fail "successful install: bootstrap table/persistence unit not live after a reported success"
    else
        pass "successful install: restriction table is live before add-peer.sh is ever invoked, peer ends up present in both durable config and live state"
    fi
    rm -rf "$root"
}

# --- 6. unknown runtime -> zero state mutation --------------------------
test_unknown_runtime_zero_mutation() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    if run_install_no_runtime "$root" >/dev/null 2>&1; then
        fail "unknown runtime: install reported success despite no matching runtime signal and no --runtime override"
    elif has_durable_peer "$root" || table_live "$root" || unit_active "$root" || conf_file_exists "$root"; then
        fail "unknown runtime: some state was mutated despite failing runtime detection"
    else
        pass "unknown runtime: fails closed before any state mutation"
    fi
    rm -rf "$root"
}

# --- 7. repeated rollback remains safe (idempotent) ---------------------
test_repeated_rollback_is_safe() {
    local root; root=$(make_fixture)
    set_service_active "$root"; set_reload_converges "$root"
    set_enable_fails "$root"
    run_install "$root" >/dev/null 2>&1 || true
    local first_rc=0
    run_install "$root" >/dev/null 2>&1 || first_rc=$?
    local second_rc=0
    run_install "$root" >/dev/null 2>&1 || second_rc=$?
    if [ "$first_rc" -eq 0 ] || [ "$second_rc" -eq 0 ]; then
        fail "repeated rollback: a run unexpectedly reported success while persistence is still forced to fail"
    elif table_live "$root" || unit_active "$root" || conf_file_exists "$root" || has_durable_peer "$root"; then
        fail "repeated rollback: state leaked across repeated failing runs"
    else
        pass "repeated rollback: running the failing install repeatedly stays safe and leaves zero state each time"
    fi
    rm -rf "$root"
}

echo "== bootstrap install transactional test suite (PR #60) =="
test_nft_apply_failure_never_calls_add_peer
test_persistence_failure_cleans_up_and_never_calls_add_peer
test_add_peer_failure_rolls_back_firewall_state
test_post_peer_verification_failure_rolls_back_both
test_successful_install_restriction_before_peer_add
test_unknown_runtime_zero_mutation
test_repeated_rollback_is_safe

echo
echo "== results: $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
