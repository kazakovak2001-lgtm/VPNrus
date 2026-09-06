#!/usr/bin/env bash
# B37 (senior-review correction) - test harness for
# gateway/lib/ft31_forward_rules.sh. Runs entirely against fake
# iptables/nft stub binaries on PATH - never touches a real gateway, never
# needs root. Proves:
#   - existing awg0 forwarding is recognized as unaffected (runtime
#     verification passes on a matching fixture, and never mutates)
#   - awg-ft31 forward rules get added correctly, idempotently, per host
#   - rollback removes ONLY the b37-ft31 rules, nothing else
#   - an unknown/mismatched runtime causes ZERO mutation (fails closed
#     before any iptables/nft mutating call is ever made)
#
#   bash gateway/tests/test_ft31_forward_rules.sh
set -uo pipefail

GATEWAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0
PASSES=0
fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }

# make_fixture <profile: frankfurt|stockholm> -> prints fixture root dir.
# Builds fake iptables/nft/ip stubs reflecting that host's OWN real,
# already-verified production forwarding facts (per docs/FIELD_TEST_RUSSIA_AWG31.md).
make_fixture() {
    local profile=$1
    local root
    root=$(mktemp -d)
    mkdir -p "$root/bin" "$root/etc"
    touch "$root/etc/calls.log"

    cat > "$root/bin/ip" <<STUB
#!/usr/bin/env bash
if [ "\$1" = "route" ] && [ "\$2" = "show" ] && [ "\$3" = "default" ]; then
    if [ "$profile" = "frankfurt" ]; then
        echo "default via 10.0.0.1 dev ens3 proto dhcp"
    else
        echo "default via 10.0.0.1 dev ens5 proto dhcp"
    fi
fi
STUB
    chmod +x "$root/bin/ip"

    # --- iptables (Frankfurt fixture) ---
    cat > "$root/bin/iptables" <<STUB
#!/usr/bin/env bash
ETC="$root/etc"
echo "iptables \$*" >> "\$ETC/calls.log"
if [ "\$1" = "--version" ]; then
    echo "iptables v1.8.9 (nf_tables)"
    exit 0
fi
if [ "\$1" = "-S" ] && [ "\$2" = "FORWARD" ]; then
    cat "\$ETC/forward_rules" 2>/dev/null
    exit 0
fi
if [ "\$1" = "-C" ]; then
    shift 2
    spec="\$*"
    grep -qF -- "\$spec" "\$ETC/forward_rules" 2>/dev/null && exit 0
    exit 1
fi
if [ "\$1" = "-I" ]; then
    chain=\$2; pos=\$3; shift 3
    { echo "-A \$chain \$*"; cat "\$ETC/forward_rules" 2>/dev/null; } > "\$ETC/forward_rules.tmp"
    mv "\$ETC/forward_rules.tmp" "\$ETC/forward_rules"
    exit 0
fi
if [ "\$1" = "-D" ]; then
    chain=\$2; shift 2
    grep -vF -- "-A \$chain \$*" "\$ETC/forward_rules" 2>/dev/null > "\$ETC/forward_rules.tmp" || true
    mv "\$ETC/forward_rules.tmp" "\$ETC/forward_rules"
    exit 0
fi
exit 0
STUB
    chmod +x "$root/bin/iptables"
    cat > "$root/etc/forward_rules" <<'FIXTURE'
-A FORWARD -i awg0 -o ens3 -j ACCEPT
-A FORWARD -i ens3 -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -j REJECT --reject-with icmp-port-unreachable
FIXTURE

    # --- nft (Stockholm fixture) ---
    cat > "$root/bin/nft" <<STUB
#!/usr/bin/env bash
ETC="$root/etc"
echo "nft \$*" >> "\$ETC/calls.log"
if [ "\$1" = "list" ] && [ "\$2" = "table" ] && [ "\$3" = "inet" ] && [ "\$4" = "pocvpn" ]; then
    [ "$profile" = "stockholm" ] && exit 0 || exit 1
fi
if [ "\$1" = "-a" ] && [ "\$2" = "list" ] && [ "\$3" = "table" ]; then
    echo "table inet pocvpn {"
    echo "    chain forward {"
    echo "        type filter hook forward priority filter; policy drop;"
    cat "\$ETC/ft31_forward_rules" 2>/dev/null
    echo "    }"
    echo "}"
    exit 0
fi
if [ "\$1" = "-a" ] && [ "\$2" = "list" ] && [ "\$3" = "chain" ]; then
    cat "\$ETC/ft31_forward_rules" 2>/dev/null
    exit 0
fi
if [ "\$1" = "insert" ] && [ "\$2" = "rule" ]; then
    n=\$(( \$(wc -l < "\$ETC/ft31_forward_rules" 2>/dev/null || echo 0) + 1 ))
    echo "        ... comment \"b37-ft31\" # handle \$n" >> "\$ETC/ft31_forward_rules"
    exit 0
fi
if [ "\$1" = "delete" ] && [ "\$2" = "rule" ]; then
    handle="\${*: -1}"
    grep -v -- "# handle \$handle\$" "\$ETC/ft31_forward_rules" 2>/dev/null > "\$ETC/ft31_forward_rules.tmp" || true
    mv "\$ETC/ft31_forward_rules.tmp" "\$ETC/ft31_forward_rules"
    exit 0
fi
if [ "\$1" = "list" ] && [ "\$2" = "ruleset" ]; then
    echo "table inet pocvpn { chain forward { policy drop; } }"
    cat "\$ETC/ft31_forward_rules" 2>/dev/null
    exit 0
fi
exit 0
STUB
    chmod +x "$root/bin/nft"
    touch "$root/etc/ft31_forward_rules"

    echo "$root"
}

run_lib() {
    local root=$1; shift
    PATH="$root/bin:$PATH" bash -c '
        set -euo pipefail
        source "'"$GATEWAY_DIR"'/lib/common.sh"
        source "'"$GATEWAY_DIR"'/lib/ft31_forward_rules.sh"
        '"$*"'
    '
}

# --- Test: Frankfurt runtime verification passes on the real fixture -------
ROOT=$(make_fixture frankfurt)
if run_lib "$ROOT" 'ft31_verify_runtime frankfurt ens3' >/dev/null 2>&1; then
    pass "Frankfurt runtime verification passes when live facts match"
else
    fail "Frankfurt runtime verification should pass on a matching fixture"
fi
if [ "$(wc -l < "$ROOT/etc/forward_rules")" -eq 3 ]; then
    pass "Frankfurt verification alone made zero FORWARD mutation (still 3 pre-existing rules)"
else
    fail "Frankfurt verification must never mutate FORWARD"
fi
rm -rf "$ROOT"

# --- Test: awg-ft31 forward rules get added correctly (Frankfurt) ---------
ROOT=$(make_fixture frankfurt)
run_lib "$ROOT" 'ft31_add_forward_rules frankfurt ens3' >/dev/null 2>&1
if grep -q -- "-A FORWARD -i awg-ft31 -o ens3" "$ROOT/etc/forward_rules" && \
   grep -q -- "-A FORWARD -i ens3 -o awg-ft31" "$ROOT/etc/forward_rules"; then
    pass "Frankfurt: both b37-ft31 FORWARD accept rules were added"
else
    fail "Frankfurt: expected both b37-ft31 FORWARD accept rules to be present"
fi
if grep -qc -- "-A FORWARD -i awg0 -o ens3" "$ROOT/etc/forward_rules" && \
   grep -qc -- "-A FORWARD -j REJECT" "$ROOT/etc/forward_rules"; then
    pass "Frankfurt: pre-existing awg0 accept + terminal REJECT are still present"
else
    fail "Frankfurt: pre-existing awg0/REJECT rules must survive unchanged"
fi
# Idempotency: re-running must not duplicate.
run_lib "$ROOT" 'ft31_add_forward_rules frankfurt ens3' >/dev/null 2>&1
COUNT=$(grep -c -- "-i awg-ft31 -o ens3" "$ROOT/etc/forward_rules")
[ "$COUNT" -eq 1 ] && pass "Frankfurt: re-running add is idempotent (no duplicate rule)" || fail "Frankfurt: expected exactly 1 awg-ft31->ens3 rule, found $COUNT"
rm -rf "$ROOT"

# --- Test: rollback removes ONLY the b37-ft31 rules (Frankfurt) -----------
ROOT=$(make_fixture frankfurt)
run_lib "$ROOT" 'ft31_add_forward_rules frankfurt ens3'
run_lib "$ROOT" 'ft31_remove_forward_rules frankfurt ens3'
if ! grep -q -- "awg-ft31" "$ROOT/etc/forward_rules"; then
    pass "Frankfurt rollback: b37-ft31 rules fully removed"
else
    fail "Frankfurt rollback: b37-ft31 rules should be gone"
fi
if grep -q -- "-A FORWARD -i awg0 -o ens3" "$ROOT/etc/forward_rules" && \
   grep -q -- "-A FORWARD -j REJECT" "$ROOT/etc/forward_rules" && \
   [ "$(wc -l < "$ROOT/etc/forward_rules")" -eq 3 ]; then
    pass "Frankfurt rollback: only B37 state removed, all 3 original production rules intact"
else
    fail "Frankfurt rollback must leave exactly the original 3 production rules untouched"
fi
rm -rf "$ROOT"

# --- Test: Stockholm runtime verification + rule insertion into the -------
# EXISTING production chain (never a second base chain) -------------------
ROOT=$(make_fixture stockholm)
if run_lib "$ROOT" 'ft31_verify_runtime stockholm ens5' >/dev/null 2>&1; then
    pass "Stockholm runtime verification passes when live facts match"
else
    fail "Stockholm runtime verification should pass on a matching fixture"
fi
run_lib "$ROOT" 'ft31_add_forward_rules stockholm ens5' >/dev/null 2>&1
if [ "$(grep -c 'b37-ft31' "$ROOT/etc/ft31_forward_rules")" -eq 2 ]; then
    pass "Stockholm: both b37-ft31 rules inserted into the existing inet pocvpn forward chain"
else
    fail "Stockholm: expected exactly 2 b37-ft31 rules inserted"
fi
run_lib "$ROOT" 'ft31_remove_forward_rules stockholm ens5' >/dev/null 2>&1
if [ ! -s "$ROOT/etc/ft31_forward_rules" ]; then
    pass "Stockholm rollback: b37-ft31 rules fully removed from the production chain"
else
    fail "Stockholm rollback: b37-ft31 rules should be gone"
fi
rm -rf "$ROOT"

# --- Test: unknown/mismatched runtime causes ZERO mutation ----------------
ROOT=$(make_fixture frankfurt)
if run_lib "$ROOT" 'ft31_verify_runtime paris ens3' >/dev/null 2>&1; then
    fail "an unknown host string must be refused"
else
    pass "unknown host string ('paris') is refused"
fi
if run_lib "$ROOT" 'ft31_verify_runtime frankfurt ens5' >/dev/null 2>&1; then
    fail "a wrong egress interface for the declared host must be refused"
else
    pass "wrong egress interface for --host frankfurt is refused"
fi
if [ "$(wc -l < "$ROOT/etc/forward_rules")" -eq 3 ] && ! grep -q '\-I \|\-D ' "$ROOT/etc/calls.log"; then
    pass "unknown/mismatched runtime made ZERO FORWARD mutation (no -I/-D ever called)"
else
    fail "an unknown/mismatched runtime must never call any mutating iptables command"
fi
rm -rf "$ROOT"

# --- Test: Frankfurt with a wrong firewall backend (legacy, not nf_tables) -
ROOT=$(make_fixture frankfurt)
sed -i 's/nf_tables/legacy/' "$ROOT/bin/iptables"
if run_lib "$ROOT" 'ft31_verify_runtime frankfurt ens3' >/dev/null 2>&1; then
    fail "a non-nf_tables iptables backend must be refused for --host frankfurt"
else
    pass "non-nf_tables iptables backend is refused for --host frankfurt"
fi
rm -rf "$ROOT"

# --- Test: ft31_verify_no_unrelated_change catches a removed/reordered rule
PRE=$(mktemp); POST=$(mktemp)
printf 'a\nb\nc\n' > "$PRE"
printf 'a\nb\nc\nd\n' > "$POST"
if run_lib "$(make_fixture frankfurt)" "ft31_verify_no_unrelated_change $PRE $POST" >/dev/null 2>&1; then
    pass "no-unrelated-change check passes when every pre-existing line survives, in order, plus an addition"
else
    fail "an addition-only change must still pass the no-unrelated-change check"
fi
printf 'a\nc\n' > "$POST"
if run_lib "$(make_fixture frankfurt)" "ft31_verify_no_unrelated_change $PRE $POST" >/dev/null 2>&1; then
    fail "a removed pre-existing rule (b missing) must be caught"
else
    pass "no-unrelated-change check catches a removed pre-existing rule"
fi
printf 'b\na\nc\n' > "$POST"
if run_lib "$(make_fixture frankfurt)" "ft31_verify_no_unrelated_change $PRE $POST" >/dev/null 2>&1; then
    fail "a reordered set of pre-existing rules must be caught"
else
    pass "no-unrelated-change check catches reordered pre-existing rules"
fi
rm -f "$PRE" "$POST"

echo
echo "== $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
