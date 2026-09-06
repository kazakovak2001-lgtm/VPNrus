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
# "before"/"after" halves of the post-deploy no-unrelated-rule-changed
# proof (ft31_verify_no_unrelated_change).
#
# Volatile-field audit (senior-review requirement): neither invocation used
# here includes any field that mutates on its own between two snapshots
# taken moments apart with no intervening rule change:
#   - `iptables-save` NEVER includes packet/byte counters in its output
#     (those only appear with `iptables -L -v`/`-c`, neither used here) -
#     `iptables-save -t filter` output is pure, deterministic rule-spec
#     text, byte-for-byte stable across repeated calls when nothing changed.
#   - `nft list ruleset` (WITHOUT the `-a`/`--handle` flag - deliberately
#     never passed here, unlike ft31_verify_runtime's own `-a` calls, which
#     are used only for one-shot inspection, never for a snapshot that gets
#     diffed) omits rule handles; and none of this repo's own nftables
#     rules/templates (pocvpn.nft.template, pocvpn-ft31.nft.template, or
#     the rules ft31_add_forward_rules inserts) declare an explicit
#     `counter` statement, so no packet/byte counter output appears either.
# Both snapshots are therefore stable and safe to compare byte-for-byte
# (via the ordered-subsequence check below) with no canonicalization step
# needed - and this function must keep NOT passing `-a`/`-c`/`-v` if that
# stays true; revisit this audit note first if either invocation ever
# changes.
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
# Proves PRE occurs as an ORDERED SUBSEQUENCE of POST - i.e. every PRE line,
# in the same relative order, including duplicates by exact multiplicity and
# position, still occurs somewhere in POST (insertions anywhere are fine;
# a removal, a reorder, or a changed line is not). Dies loudly if that does
# not hold.
#
# senior-review correction: the original version of this function used
# `grep -Fxf pre post | diff pre -` - that is a LINE-MEMBERSHIP filter, not
# an ordered-subsequence check, and is wrong wherever PRE contains a line
# whose exact text also appears among the NEW lines POST-only introduces
# (e.g. a bare `}` closing brace, or "policy accept;" - both common,
# expected text in an nftables ruleset dump). `grep -Fxf` would keep EVERY
# such POST occurrence (old and new alike), not just the one that
# corresponds to the original PRE line, so a purely-additive, perfectly
# safe change could produce more matching lines than PRE has, making the
# `diff` fail and reporting a false "unrelated rule removed/reordered"
# AFTER real mutations (config/peer/NAT/systemd/FORWARD-rule insertion)
# had already happened - see provision-ft31.sh's own failure/rollback
# handling for how that specific failure mode is now made safe regardless.
#
# This implementation instead does a real sequential single-pass scan:
# walk POST top to bottom, and whenever the current POST line exactly
# equals the NEXT still-unconsumed PRE line, advance the PRE pointer.
# Success requires every PRE line to have been consumed, in order, by the
# time POST is exhausted - this is the standard subsequence-matching
# algorithm and handles duplicate lines correctly by construction (each
# PRE line, duplicate or not, is only ever matched against the POST
# occurrence reached by the scan at that point, never any other).
ft31_verify_no_unrelated_change() {
    local pre_file=$1 post_file=$2
    if ! awk '
        NR == FNR { pre[FNR] = $0; pre_count = FNR; next }
        { if (idx < pre_count && $0 == pre[idx + 1]) idx++ }
        END { exit (idx == pre_count) ? 0 : 1 }
    ' "$pre_file" "$post_file"; then
        die "post-deploy verification FAILED: at least one pre-existing firewall rule was removed, reordered, or changed relative to the others - see $pre_file vs $post_file (investigate before retrying - see provision-ft31.sh's own failure/rollback handling for what state this invocation itself may have left behind)"
    fi
    log "post-deploy verification: every pre-existing rule still occurs, in the same relative order (an exact ordered subsequence of the new ruleset) - nothing unrelated was removed, reordered, or changed"
}
