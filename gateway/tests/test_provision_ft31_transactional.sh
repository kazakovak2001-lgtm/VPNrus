#!/usr/bin/env bash
# B37 (senior-review correction) - failure-injection integration tests for
# gateway/provision-ft31.sh ITSELF (not a reimplementation of its logic).
# Runs the real script against an isolated temp root (via its FT31_TEST_*
# path overrides - see provision-ft31.sh's own docs) with fake
# awg/awg-quick/systemctl/nft/iptables/ip/flock/chmod/chown binaries on
# PATH. Never touches a real gateway, never needs real root privilege
# (EUID is faked via a stub `id`).
#
#   bash gateway/tests/test_provision_ft31_transactional.sh
set -uo pipefail

GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0
PASSES=0
fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }

CLIENT_PUBKEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# make_env [--pre-existing] -> prints the isolated root dir. With
# --pre-existing, seeds a fully-deployed B37 state first (as if an earlier
# successful run already happened) so failure-injection tests can prove
# that state survives a LATER run's failure untouched (requirement F).
make_env() {
    local root
    root=$(mktemp -d)
    mkdir -p "$root/bin" "$root/etc/amnezia" "$root/systemd" "$root/state"
    echo 1 > "$root/ip_forward"
    touch "$root/state/calls.log"

    cat > "$root/bin/id" <<'STUB'
#!/usr/bin/env bash
[ "$1" = "-u" ] && echo 0 || echo root
STUB
    cat > "$root/bin/ip" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "default" ]; then
    echo "default via 10.0.0.1 dev ens3 proto dhcp"
    exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ]; then
    # No pre-existing route for the B37 subnet in this hermetic fixture.
    exit 0
fi
if [ "$1" = "link" ] && [ "$2" = "show" ]; then
    # No pre-existing interface by this name - real `ip link show <iface>`
    # exits non-zero (with stderr) when the interface does not exist.
    exit 1
fi
exit 0
STUB
    cat > "$root/bin/ss" <<'STUB'
#!/usr/bin/env bash
# No listeners in this hermetic fixture - header line only, same shape as
# real `ss -uln` with nothing bound.
echo "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port"
exit 0
STUB
    cat > "$root/bin/flock" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    cat > "$root/bin/awg" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "genkey" ]; then
    echo "FAKEKEY$$RANDOM$RANDOM=================================="| cut -c1-44
    exit 0
fi
if [ "$1" = "pubkey" ]; then
    cat >/dev/null
    echo "FAKEPUBKEY00000000000000000000000000000000="
    exit 0
fi
exit 0
STUB
    cat > "$root/bin/awg-quick" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    cat > "$root/bin/chmod" <<STUB
#!/usr/bin/env bash
[ -f "$root/state/.fail_chmod" ] && exit 1
exec /bin/chmod "\$@"
STUB
    cat > "$root/bin/chown" <<STUB
#!/usr/bin/env bash
exit 0
STUB
    # Real `install -m MODE ...` fails to set POSIX permission bits on this
    # Windows/NTFS dev sandbox (`install: cannot change permissions ...`) -
    # a sandbox/filesystem limitation, not something this test suite is
    # meant to exercise (real Linux gateways have no such issue). Stub only
    # the two forms provision-ft31.sh actually uses: `-d -m MODE DIR`
    # (mkdir) and `-m MODE SRC DEST` (copy).
    cat > "$root/bin/install" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "-d" ]; then
    shift 2
    mkdir -p "$@"
    exit 0
fi
if [ "$1" = "-m" ]; then
    shift 2
    cp "$1" "$2"
    exit 0
fi
exit 0
STUB
    cat > "$root/bin/iptables" <<STUB
#!/usr/bin/env bash
ETC="$root/etc"
STATE="$root/state"
echo "iptables \$*" >> "\$STATE/calls.log"
if [ "\$1" = "--version" ]; then echo "iptables v1.8.9 (nf_tables)"; exit 0; fi
_ft31_chain_file() { [ "\$1" = "INPUT" ] && echo "\$ETC/input_rules" || echo "\$ETC/forward_rules"; }
if [ "\$1" = "-S" ]; then
    cat "\$(_ft31_chain_file "\$2")" 2>/dev/null
    exit 0
fi
if [ "\$1" = "-C" ]; then
    chain=\$2; shift 2
    grep -qF -- "\$*" "\$(_ft31_chain_file "\$chain")" 2>/dev/null && exit 0
    exit 1
fi
if [ "\$1" = "-I" ]; then
    n=\$(( \$(cat "\$STATE/.iptables_i_count" 2>/dev/null || echo 0) + 1 ))
    echo "\$n" > "\$STATE/.iptables_i_count"
    fail_at=\$(cat "\$STATE/.fail_iptables_i_at" 2>/dev/null || echo 0)
    if [ "\$n" = "\$fail_at" ]; then
        echo "iptables: simulated failure on -I call #\$n" >&2
        exit 1
    fi
    chain=\$2; pos=\$3; shift 3
    file=\$(_ft31_chain_file "\$chain")
    fail_input_at=\$(cat "\$STATE/.fail_iptables_input_insert" 2>/dev/null || echo 0)
    if [ "\$chain" = "INPUT" ] && [ "\$fail_input_at" = "1" ]; then
        echo "iptables: simulated failure inserting into INPUT" >&2
        exit 1
    fi
    awk -v pos="\$pos" -v newline="-A \$chain \$*" '
        NR == pos { print newline }
        { print }
        END { if (pos > NR) print newline }
    ' "\$file" > "\$file.tmp"
    mv "\$file.tmp" "\$file"
    exit 0
fi
if [ "\$1" = "-D" ]; then
    chain=\$2; shift 2
    file=\$(_ft31_chain_file "\$chain")
    grep -vF -- "-A \$chain \$*" "\$file" 2>/dev/null > "\$file.tmp" || true
    mv "\$file.tmp" "\$file"
    exit 0
fi
exit 0
STUB
    cat > "$root/etc/forward_rules" <<'FIXTURE'
-A FORWARD -i awg0 -o ens3 -j ACCEPT
-A FORWARD -i ens3 -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -j REJECT --reject-with icmp-port-unreachable
FIXTURE
    # Real verified Frankfurt INPUT facts (senior-review pass): UDP 51820
    # ACCEPT (production awg0), terminal REJECT - no UDP 51821 rule yet.
    cat > "$root/etc/input_rules" <<'FIXTURE'
-A INPUT -p udp --dport 51820 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-port-unreachable
FIXTURE
    cat > "$root/bin/iptables-save" <<STUB
#!/usr/bin/env bash
cat "$root/etc/input_rules" 2>/dev/null
cat "$root/etc/forward_rules" 2>/dev/null
STUB
    cat > "$root/bin/nft" <<STUB
#!/usr/bin/env bash
STATE="$root/state"
echo "nft \$*" >> "\$STATE/calls.log"
if [ "\$1" = "list" ] && [ "\$2" = "table" ]; then
    tbl="\${@: -1}"
    if [ "\$tbl" = "pocvpn-ft31" ]; then
        [ -f "\$STATE/.nat_exists" ] && exit 0 || exit 1
    fi
    exit 0
fi
if [ "\$1" = "-f" ]; then
    touch "\$STATE/.nat_exists"
    if [ -f "\$STATE/.fail_nft_f" ]; then
        echo "nft: simulated failure applying ruleset" >&2
        exit 1
    fi
    exit 0
fi
if [ "\$1" = "delete" ] && [ "\$2" = "table" ]; then
    rm -f "\$STATE/.nat_exists"
    exit 0
fi
exit 0
STUB
    cat > "$root/bin/systemctl" <<STUB
#!/usr/bin/env bash
STATE="$root/state"
echo "systemctl \$*" >> "\$STATE/calls.log"
case "\$1" in
    daemon-reload) exit 0 ;;
    is-enabled) [ -f "\$STATE/.enabled" ] && exit 0 || exit 1 ;;
    is-active) [ -f "\$STATE/.active" ] && exit 0 || exit 1 ;;
    enable)
        if [ "\$2" = "--now" ]; then
            touch "\$STATE/.enabled"
            if [ -f "\$STATE/.fail_start" ]; then
                echo "systemctl: simulated failure starting service" >&2
                exit 1
            fi
            touch "\$STATE/.active"
            exit 0
        fi
        touch "\$STATE/.enabled"; exit 0 ;;
    disable)
        if [ "\$2" = "--now" ]; then rm -f "\$STATE/.enabled" "\$STATE/.active"; exit 0; fi
        rm -f "\$STATE/.enabled"; exit 0 ;;
    start)
        if [ -f "\$STATE/.fail_start" ]; then
            echo "systemctl: simulated failure starting service" >&2
            exit 1
        fi
        touch "\$STATE/.active"; exit 0 ;;
    stop) rm -f "\$STATE/.active"; exit 0 ;;
esac
exit 0
STUB
    chmod +x "$root/bin/"*

    if [ "${1:-}" = "--pre-existing" ]; then
        FT31_TEST_HARNESS_MODE=1 \
        FT31_TEST_CONFIG_DIR="$root/etc/amnezia" \
        FT31_TEST_IP_FORWARD_PROC="$root/ip_forward" \
        FT31_TEST_SYSTEMD_UNIT_DIR="$root/systemd" \
        FT31_TEST_NFTABLES_CONF_PATH="$root/nftables.pocvpn-ft31.conf" \
        PATH="$root/bin:$PATH" \
        FT31_CLIENT_PUBLIC_KEY="$CLIENT_PUBKEY" FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
        bash "$GATEWAY_DIR/provision-ft31.sh" frankfurt >/dev/null 2>&1
    fi

    echo "$root"
}

run_provision() {
    local root=$1; shift
    FT31_TEST_HARNESS_MODE=1 \
    FT31_TEST_CONFIG_DIR="$root/etc/amnezia" \
    FT31_TEST_IP_FORWARD_PROC="$root/ip_forward" \
    FT31_TEST_SYSTEMD_UNIT_DIR="$root/systemd" \
    FT31_TEST_NFTABLES_CONF_PATH="$root/nftables.pocvpn-ft31.conf" \
    PATH="$root/bin:$PATH" \
    FT31_CLIENT_PUBLIC_KEY="$CLIENT_PUBKEY" FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
    "$@" \
    bash "$GATEWAY_DIR/provision-ft31.sh" frankfurt
}

# --- A: first FORWARD insert succeeds, second fails -> first rolled back --
ROOT=$(make_env)
echo 2 > "$ROOT/state/.fail_iptables_i_at"
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "A: expected provision-ft31.sh to fail when the 2nd -I call fails"
else
    pass "A: provision-ft31.sh correctly failed (2nd FORWARD insert failed)"
fi
if ! grep -q "awg-ft31" "$ROOT/etc/forward_rules"; then
    pass "A: the first (already-applied) FORWARD rule was rolled back"
else
    fail "A: expected the first FORWARD rule to be rolled back after the second failed"
fi
if [ "$(wc -l < "$ROOT/etc/forward_rules")" -eq 3 ]; then
    pass "A: only the 3 original production FORWARD rules remain"
else
    fail "A: production FORWARD rules must be untouched"
fi
rm -rf "$ROOT"

# --- B: nft table appears but `nft -f` itself returns failure -> rolled back
ROOT=$(make_env)
touch "$ROOT/state/.fail_nft_f"
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "B: expected provision-ft31.sh to fail when nft -f reports failure"
else
    pass "B: provision-ft31.sh correctly failed (nft -f reported failure)"
fi
if [ ! -f "$ROOT/state/.nat_exists" ]; then
    pass "B: the NAT table (created by nft -f despite its own failure exit) was rolled back regardless of nft's exit status"
else
    fail "B: the isolated NAT table must be rolled back even though nft -f returned failure after applying it"
fi
rm -rf "$ROOT"

# --- C: systemd unit becomes enabled but start fails -> exact pre-state restored (first-time deploy: pre-state is "absent")
ROOT=$(make_env)
touch "$ROOT/state/.fail_start"
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "C: expected provision-ft31.sh to fail when the service fails to start"
else
    pass "C: provision-ft31.sh correctly failed (service enabled but failed to start)"
fi
if [ ! -f "$ROOT/state/.enabled" ] && [ ! -f "$ROOT/state/.active" ] && [ ! -f "$ROOT/systemd/awg-poc-ft31.service" ]; then
    pass "C: exact pre-run state restored (unit file/enabled/active all absent, as before this run)"
else
    fail "C: expected a full teardown back to 'absent' (no prior B37 service existed)"
fi
rm -rf "$ROOT"

# --- D: config file created but chmod fails -> new config removed ---------
ROOT=$(make_env)
touch "$ROOT/state/.fail_chmod"
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "D: expected provision-ft31.sh to fail when chmod on the new config fails"
else
    pass "D: provision-ft31.sh correctly failed (chmod on the new config failed)"
fi
if [ ! -f "$ROOT/etc/amnezia/awg-ft31.conf" ]; then
    pass "D: the freshly-rendered config file (chmod failed right after) was rolled back"
else
    fail "D: a config file created by this run must be rolled back even if a later command in the same step failed"
fi
rm -rf "$ROOT"

# --- E: peer mutation succeeds but the step is failed right after -> new peer removed
ROOT=$(make_env)
if FT31_TEST_FAIL_AFTER_PEER=1 run_provision "$ROOT" >/dev/null 2>&1; then
    fail "E: expected provision-ft31.sh to fail via the post-peer-add test hook"
else
    pass "E: provision-ft31.sh correctly failed (post-peer-add hook)"
fi
if [ -f "$ROOT/etc/amnezia/awg-ft31.conf" ] && grep -qF "$CLIENT_PUBKEY" "$ROOT/etc/amnezia/awg-ft31.conf"; then
    fail "E: the peer added by this run must be rolled back"
else
    pass "E: the peer added by this run was rolled back (config's own peer markers empty again)"
fi
# Config itself was ALSO created fresh by this same run, so it too must be gone -
# rollback is invocation-wide, not "only the step that happened to fail".
if [ ! -f "$ROOT/etc/amnezia/awg-ft31.conf" ]; then
    pass "E: the config file this same run created is also rolled back (invocation-wide rollback)"
else
    fail "E: this invocation's own freshly-created config must be rolled back too"
fi
rm -rf "$ROOT"

# --- F: pre-existing, UNCHANGED B37 state survives a later idempotent rerun,
# and that rerun now SUCCEEDS without re-mutating anything (senior-review
# requirement A2: exact-match pre-existing state is left untouched, not
# blindly re-applied - so a rerun no longer even calls `nft -f`/`install` for
# NAT/systemd when the on-disk state already matches byte-for-byte; forcing
# nft -f to fail on such a rerun must have NO EFFECT, because the fail-closed
# match check means nft -f is never invoked at all this time).
ROOT=$(make_env --pre-existing)
if [ ! -f "$ROOT/etc/amnezia/awg-ft31.conf" ]; then
    fail "F setup: pre-existing deploy did not actually create a config - test setup is broken"
else
    PRE_CONFIG_CONTENT=$(cat "$ROOT/etc/amnezia/awg-ft31.conf")
    PRE_ENABLED=$([ -f "$ROOT/state/.enabled" ] && echo yes || echo no)
    PRE_ACTIVE=$([ -f "$ROOT/state/.active" ] && echo yes || echo no)
    PRE_FORWARD_COUNT=$(grep -c "awg-ft31" "$ROOT/etc/forward_rules")

    touch "$ROOT/state/.fail_nft_f"
    if run_provision "$ROOT" >/dev/null 2>&1; then
        pass "F: idempotent rerun of unchanged pre-existing B37 state succeeds (nft -f is never invoked, so its forced failure has no effect)"
    else
        fail "F: expected an idempotent rerun of exactly-matching pre-existing state to succeed"
    fi

    if [ -f "$ROOT/etc/amnezia/awg-ft31.conf" ] && [ "$(cat "$ROOT/etc/amnezia/awg-ft31.conf")" = "$PRE_CONFIG_CONTENT" ]; then
        pass "F: pre-existing config from the earlier successful run is untouched"
    else
        fail "F: a later idempotent rerun must never remove/alter an earlier successful run's config"
    fi
    if [ "$([ -f "$ROOT/state/.enabled" ] && echo yes || echo no)" = "$PRE_ENABLED" ] && [ "$([ -f "$ROOT/state/.active" ] && echo yes || echo no)" = "$PRE_ACTIVE" ]; then
        pass "F: pre-existing service enabled/active state is untouched"
    else
        fail "F: a later idempotent rerun must never change an earlier run's already-correct service state"
    fi
    if [ -f "$ROOT/state/.nat_exists" ]; then
        pass "F: pre-existing NAT table is untouched"
    else
        fail "F: a later idempotent rerun must never remove a pre-existing NAT table"
    fi
    if [ "$(grep -c "awg-ft31" "$ROOT/etc/forward_rules")" -eq "$PRE_FORWARD_COUNT" ]; then
        pass "F: pre-existing FORWARD rules are untouched"
    else
        fail "F: a later idempotent rerun must never remove pre-existing FORWARD rules"
    fi
fi
rm -rf "$ROOT"

# --- G: DIFFERING pre-existing NAT config fails closed, zero mutation -----
# (senior-review requirement A2: unexpected/unowned or changed pre-existing
# B37 state must never be silently overwritten).
ROOT=$(make_env --pre-existing)
echo "# unexpected drifted content, not what this run would render" >> "$ROOT/nftables.pocvpn-ft31.conf"
DRIFTED_CONTENT=$(cat "$ROOT/nftables.pocvpn-ft31.conf")
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "G: expected provision-ft31.sh to fail closed when the existing NAT config differs from the desired render"
else
    pass "G: provision-ft31.sh correctly failed closed (differing pre-existing NAT config)"
fi
if [ "$(cat "$ROOT/nftables.pocvpn-ft31.conf")" = "$DRIFTED_CONTENT" ]; then
    pass "G: the differing pre-existing NAT config was left completely untouched (zero mutation)"
else
    fail "G: a differing pre-existing NAT config must never be mutated by a fail-closed check"
fi
rm -rf "$ROOT"

# --- H: DIFFERING pre-existing systemd unit fails closed, zero mutation ---
ROOT=$(make_env --pre-existing)
echo "# unexpected hand-edited unit content" >> "$ROOT/systemd/awg-poc-ft31.service"
DRIFTED_UNIT=$(cat "$ROOT/systemd/awg-poc-ft31.service")
if run_provision "$ROOT" >/dev/null 2>&1; then
    fail "H: expected provision-ft31.sh to fail closed when the existing systemd unit differs from the repo's own unit file"
else
    pass "H: provision-ft31.sh correctly failed closed (differing pre-existing systemd unit)"
fi
if [ "$(cat "$ROOT/systemd/awg-poc-ft31.service")" = "$DRIFTED_UNIT" ]; then
    pass "H: the differing pre-existing systemd unit was left completely untouched (zero mutation)"
else
    fail "H: a differing pre-existing systemd unit must never be mutated by a fail-closed check"
fi
rm -rf "$ROOT"

# --- I: FT31_TEST_* overrides are refused without FT31_TEST_HARNESS_MODE=1
# (senior-review requirement F2: a real deploy environment leaking a stale
# FT31_TEST_* var must never silently redirect a real run).
ROOT=$(make_env)
if FT31_TEST_CONFIG_DIR="$ROOT/etc/amnezia" \
   FT31_TEST_IP_FORWARD_PROC="$ROOT/ip_forward" \
   FT31_TEST_SYSTEMD_UNIT_DIR="$ROOT/systemd" \
   FT31_TEST_NFTABLES_CONF_PATH="$ROOT/nftables.pocvpn-ft31.conf" \
   PATH="$ROOT/bin:$PATH" \
   FT31_CLIENT_PUBLIC_KEY="$CLIENT_PUBKEY" FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
   bash "$GATEWAY_DIR/provision-ft31.sh" frankfurt >/dev/null 2>&1; then
    fail "I: expected provision-ft31.sh to refuse FT31_TEST_* overrides without FT31_TEST_HARNESS_MODE=1"
else
    pass "I: provision-ft31.sh correctly refused FT31_TEST_* overrides without FT31_TEST_HARNESS_MODE=1"
fi
rm -rf "$ROOT"

# --- J: real binary-path resolution (senior-review pass: real Frankfurt
# preflight evidence) - the rendered systemd unit must use THIS host's own
# resolved `command -v awg`/`command -v awg-quick` absolute paths (here:
# under the fixture's $ROOT/bin, standing in for the verified real
# Frankfurt facts of /usr/bin, NOT the previously-hardcoded /usr/local/bin)
# -----------------------------------------------------------------------
ROOT=$(make_env)
run_provision "$ROOT" >/dev/null 2>&1
UNIT_CONTENT=$(cat "$ROOT/systemd/awg-poc-ft31.service")
if printf '%s' "$UNIT_CONTENT" | grep -qF "$ROOT/bin/awg-quick up awg-ft31" && \
   printf '%s' "$UNIT_CONTENT" | grep -qF "$ROOT/bin/awg-quick down awg-ft31" && \
   printf '%s' "$UNIT_CONTENT" | grep -qF "$ROOT/bin/awg syncconf"; then
    pass "J: the rendered B37 unit uses this host's own resolved (non-/usr/local) AWG binary paths"
else
    fail "J: expected the rendered unit to reference $ROOT/bin/awg{,-quick} - got: $UNIT_CONTENT"
fi
# Only the [Service] Exec* directives matter here - the template's own
# comments legitimately mention the OLD /usr/local/bin assumption (to
# explain why this is now a template at all), so checking the whole file
# would false-positive on that prose, not on any actual directive.
if ! printf '%s' "$UNIT_CONTENT" | grep '^Exec' | grep -q "/usr/local/bin"; then
    pass "J: the rendered unit's Exec* directives never fall back to the old hardcoded /usr/local/bin path"
else
    fail "J: the rendered unit's Exec* directives must never contain a hardcoded /usr/local/bin path"
fi
rm -rf "$ROOT"

# --- K: /usr/local/bin absence does not break deployment - every fixture in
# this entire test file only ever provides awg/awg-quick under $ROOT/bin
# (standing in for the verified real Frankfurt /usr/bin, never /usr/local/bin
# at all) and provisioning still succeeds end-to-end via real `command -v`
# resolution, never a blind hardcoded assumption.
ROOT=$(make_env)
if run_provision "$ROOT" >/dev/null 2>&1; then
    pass "K: provisioning succeeds with AWG binaries resolved from PATH, with no /usr/local/bin present anywhere in this fixture"
else
    fail "K: provisioning must not depend on a hardcoded /usr/local/bin path existing"
fi
rm -rf "$ROOT"

# --- L: the b37-ft31 host INPUT rule is inserted before the terminal
# REJECT during a real end-to-end run, and the pre-existing production UDP
# 51820 ACCEPT rule is untouched -----------------------------------------
ROOT=$(make_env)
run_provision "$ROOT" >/dev/null 2>&1
INPUT_RULES=$(cat "$ROOT/etc/input_rules")
if [ "$(printf '%s\n' "$INPUT_RULES" | wc -l)" -eq 3 ] && \
   printf '%s\n' "$INPUT_RULES" | sed -n '1p' | grep -q -- "--dport 51820" && \
   printf '%s\n' "$INPUT_RULES" | sed -n '2p' | grep -q -- "--dport 51821.*b37-ft31" && \
   printf '%s\n' "$INPUT_RULES" | sed -n '3p' | grep -q -- "-j REJECT"; then
    pass "L: a real end-to-end run inserts the b37-ft31 INPUT rule immediately before the terminal REJECT"
else
    fail "L: expected [51820 ACCEPT, b37-ft31 51821 ACCEPT, REJECT] in that order after a full run, got: $INPUT_RULES"
fi
rm -rf "$ROOT"

# --- M: repeated end-to-end runs never duplicate the INPUT rule -----------
ROOT=$(make_env)
run_provision "$ROOT" >/dev/null 2>&1
run_provision "$ROOT" >/dev/null 2>&1
COUNT=$(grep -c -- "b37-ft31" "$ROOT/etc/input_rules")
[ "$COUNT" -eq 1 ] && pass "M: a repeated end-to-end run never duplicates the INPUT rule" || fail "M: expected exactly 1 b37-ft31 INPUT rule after two runs, found $COUNT"
rm -rf "$ROOT"

# --- N: a failure AFTER the INPUT rule is inserted (the new, final step)
# rolls the INPUT rule back too, restoring the exact pre-run INPUT state -
# proves the INPUT rule participates in the SAME transactional model as the
# FORWARD rules, not a bolted-on afterthought.
ROOT=$(make_env)
PRE_INPUT=$(cat "$ROOT/etc/input_rules")
if FT31_TEST_FAIL_AFTER_INPUT_RULE=1 run_provision "$ROOT" >/dev/null 2>&1; then
    fail "N: expected provision-ft31.sh to fail when the post-INPUT-rule hook fires"
else
    pass "N: provision-ft31.sh correctly failed (post-INPUT-rule hook)"
fi
if [ "$(cat "$ROOT/etc/input_rules")" = "$PRE_INPUT" ]; then
    pass "N: a failure after INPUT-rule insertion restores the exact pre-run INPUT state (rule rolled back)"
else
    fail "N: the INPUT rule must be rolled back on a failure occurring after it was inserted - got: $(cat "$ROOT/etc/input_rules")"
fi
rm -rf "$ROOT"

# --- O: a full successful run leaves every OTHER production INPUT rule
# byte-for-byte intact (only the b37-ft31 rule is new) --------------------
ROOT=$(make_env)
PRE_INPUT=$(cat "$ROOT/etc/input_rules")
run_provision "$ROOT" >/dev/null 2>&1
POST_INPUT_NON_B37=$(grep -v "b37-ft31" "$ROOT/etc/input_rules")
if [ "$POST_INPUT_NON_B37" = "$PRE_INPUT" ]; then
    pass "O: every pre-existing production INPUT rule remains byte-for-byte intact after a full successful run"
else
    fail "O: production INPUT rules must remain byte-for-byte intact - expected: $PRE_INPUT - got (minus b37-ft31): $POST_INPUT_NON_B37"
fi
rm -rf "$ROOT"

echo
echo "== $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
