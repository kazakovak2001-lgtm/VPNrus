#!/usr/bin/env bash
# B37 (senior-review correction) - per-host FORWARD accept rules for the
# isolated awg-ft31 interface, added DIRECTLY into each host's own REAL,
# already-verified production forwarding path - never a second, competing
# nftables base chain (see pocvpn-ft31.nft.template's own docs for why that
# was the critical bug in the original version of this file).
#
# Frankfurt and Stockholm run TWO DIFFERENT firewall backends (task's own
# "Known current runtime" facts, cross-checked against docs/ROADMAP.md's
# 2026-09-01 read-only SSH diagnosis of Frankfurt's real FORWARD chain):
#   - Frankfurt: iptables-nft (legacy iptables syntax, nft_tables backend),
#     FORWARD chain contains awg0/ens3 accepts + a final REJECT/DROP.
#   - Stockholm: native nftables, `inet pocvpn` table, `forward` chain,
#     policy drop (see gateway/nftables/pocvpn.nft.template).
#
# Every function here is PREFLIGHT-GATED: it verifies the live runtime
# actually matches what is expected for the declared --host BEFORE making
# any change, and dies (zero mutation) if it does not. Every added rule is
# tagged with the literal marker "b37-ft31" so rollback can find and remove
# EXACTLY those rules, never anything else.
#
# Requires lib/common.sh already sourced (log/die).

FT31_FW_MARKER="b37-ft31"

# ft31_snapshot_ruleset <host> <out_file>
# Captures the CURRENT, full forwarding ruleset for the given host's real
# backend, verbatim - used both as the preflight evidence and as the
# "before" half of the post-deploy no-unrelated-rule-changed proof.
ft31_snapshot_ruleset() {
    local host=$1 out_file=$2
    case "$host" in
        frankfurt) iptables-save -t filter > "$out_file" ;;
        stockholm) nft list ruleset > "$out_file" ;;
        *) die "ft31_snapshot_ruleset: unknown host '$host'" ;;
    esac
}

# ft31_verify_runtime <host> <egress_iface>
# Fails closed (die, zero mutation) unless the LIVE runtime matches every
# expected fact for that host - never trusts the --host flag alone.
ft31_verify_runtime() {
    local host=$1 egress_iface=$2
    # Every check below captures command output into a variable FIRST, then
    # inspects it with grep on that captured string (never `cmd | grep -q`
    # directly) - a pipe into a short-circuiting consumer like `grep -q`
    # can SIGPIPE the upstream writer, and this codebase runs under `set -e
    # -o pipefail` (see lib/common.sh callers) where that signal has been
    # observed to surface as a false pipeline failure on this toolchain,
    # even though the match itself would have succeeded.
    local version_output forward_rules last_action nft_table_output nft_forward_output
    case "$host" in
        frankfurt)
            [ "$egress_iface" = "ens3" ] || die "runtime mismatch: --host frankfurt expects egress ens3, detected '$egress_iface' - refusing to mutate any firewall rule"
            version_output=$(iptables --version 2>/dev/null || true)
            printf '%s' "$version_output" | grep -qi 'nf_tables' || die "runtime mismatch: --host frankfurt expects an iptables-nft backend - refusing to mutate any firewall rule"
            forward_rules=$(iptables -S FORWARD 2>/dev/null || true)
            printf '%s' "$forward_rules" | grep -q -- '-o ens3' || die "runtime mismatch: --host frankfurt expects an existing FORWARD rule on ens3 (production awg0 egress) - refusing to mutate any firewall rule"
            last_action=$(printf '%s\n' "$forward_rules" | tail -1)
            printf '%s' "$last_action" | grep -qE -- '-j (REJECT|DROP)' || die "runtime mismatch: --host frankfurt expects a terminal REJECT/DROP in FORWARD - refusing to mutate any firewall rule"
            ;;
        stockholm)
            [ "$egress_iface" = "ens5" ] || die "runtime mismatch: --host stockholm expects egress ens5, detected '$egress_iface' - refusing to mutate any firewall rule"
            command -v nft >/dev/null || die "runtime mismatch: --host stockholm expects native nftables ('nft' not found) - refusing to mutate any firewall rule"
            nft list table inet pocvpn >/dev/null 2>&1 || die "runtime mismatch: --host stockholm expects an existing 'inet pocvpn' table - refusing to mutate any firewall rule"
            nft_table_output=$(nft -a list table inet pocvpn 2>/dev/null || true)
            printf '%s' "$nft_table_output" | grep -q 'chain forward' || die "runtime mismatch: --host stockholm expects a 'forward' chain in 'inet pocvpn' - refusing to mutate any firewall rule"
            nft_forward_output=$(printf '%s' "$nft_table_output" | grep -A2 'chain forward' || true)
            printf '%s' "$nft_forward_output" | grep -q 'policy drop' || die "runtime mismatch: --host stockholm expects 'forward' chain policy drop - refusing to mutate any firewall rule"
            ;;
        *)
            die "unknown --host '$host' (must be exactly 'frankfurt' or 'stockholm') - refusing to mutate any firewall rule"
            ;;
    esac
    log "runtime verified: --host $host matches its expected, already-live production firewall facts"
}

# ft31_forward_rules_present <host> <egress_iface>
# Idempotency probe - true (0) only when BOTH b37-ft31 rules already exist.
ft31_forward_rules_present() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -C FORWARD -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null &&
            iptables -C FORWARD -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null
            ;;
        stockholm)
            local chain_output marker_count
            chain_output=$(nft -a list chain inet pocvpn forward 2>/dev/null || true)
            marker_count=$(printf '%s' "$chain_output" | grep -c "comment \"$FT31_FW_MARKER\"" || true)
            [ "$marker_count" -eq 2 ]
            ;;
        *) return 1 ;;
    esac
}

# ft31_add_forward_rules <host> <egress_iface>
# Adds EXACTLY two narrowly-scoped accept rules (awg-ft31 -> egress, and
# egress -> awg-ft31 established/related) into the host's REAL production
# forwarding path. Idempotent - a rerun with the rules already present is
# a no-op, never a duplicate insert.
ft31_add_forward_rules() {
    local host=$1 egress_iface=$2
    if ft31_forward_rules_present "$host" "$egress_iface"; then
        log "b37-ft31 forward rules already present on $host - leaving them untouched"
        return 0
    fi
    case "$host" in
        frankfurt)
            iptables -I FORWARD 1 -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT
            iptables -I FORWARD 1 -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT
            log "inserted 2 b37-ft31 ACCEPT rules at the top of FORWARD (iptables-nft) - every existing rule, including the final REJECT/DROP, is otherwise unchanged and unmoved in relative order"
            ;;
        stockholm)
            nft insert rule inet pocvpn forward iifname "awg-ft31" oifname "$egress_iface" accept comment "$FT31_FW_MARKER"
            nft insert rule inet pocvpn forward iifname "$egress_iface" oifname "awg-ft31" ct state established,related accept comment "$FT31_FW_MARKER"
            log "inserted 2 b37-ft31 ACCEPT rules into the existing 'inet pocvpn forward' chain - policy remains drop, every other rule is otherwise unchanged"
            ;;
    esac
}

# ft31_remove_forward_rules <host> <egress_iface>
# Removes ONLY the two b37-ft31-tagged rules this task added - never
# anything else in the production forwarding path. Safe to call even if
# the rules are already absent (no-op).
ft31_remove_forward_rules() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -D FORWARD -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null || true
            log "removed b37-ft31 FORWARD rules (if present) - every other FORWARD rule is untouched"
            ;;
        stockholm)
            local handle chain_output handles
            chain_output=$(nft -a list chain inet pocvpn forward 2>/dev/null || true)
            handles=$(printf '%s' "$chain_output" | grep -F "comment \"$FT31_FW_MARKER\"" | sed -n 's/.*# handle \([0-9]\+\).*/\1/p')
            for handle in $handles; do
                nft delete rule inet pocvpn forward handle "$handle" 2>/dev/null || true
            done
            log "removed b37-ft31 FORWARD rules (if present) - the 'inet pocvpn forward' chain and every other rule in it are otherwise untouched"
            ;;
    esac
}

# ft31_verify_no_unrelated_change <pre_snapshot_file> <post_snapshot_file>
# Proves every line present before mutation is STILL present, in the same
# relative order, after mutation (i.e. nothing removed or reordered - only
# additions are possible). Dies loudly if that does not hold.
ft31_verify_no_unrelated_change() {
    local pre_file=$1 post_file=$2
    local filtered
    filtered=$(mktemp)
    # Keep only the POST lines that also occur in PRE, in POST's own order -
    # this is the subsequence PRE must appear as, unchanged, for "nothing
    # removed or reordered" to hold.
    grep -Fxf "$pre_file" "$post_file" > "$filtered" || true
    if ! diff -q "$pre_file" "$filtered" >/dev/null 2>&1; then
        die "post-deploy verification FAILED: at least one pre-existing firewall rule was removed or reordered relative to the others - see $pre_file vs $post_file (no further B37 action taken; investigate before retrying)"
    fi
    rm -f "$filtered"
    log "post-deploy verification: every pre-existing rule is still present, in the same relative order - nothing unrelated was removed or reordered"
}
