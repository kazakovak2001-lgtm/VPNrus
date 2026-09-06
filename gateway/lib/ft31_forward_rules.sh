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

# The isolated field-test UDP port - kept as a lib-local constant (same
# convention as FT31_FW_MARKER above and the hardcoded "awg-ft31" interface
# name used throughout this file) rather than threaded in from
# provision-ft31.sh's own FT31_LISTEN_PORT, since this file already hardcodes
# every other B37-specific fact. MUST stay in sync with provision-ft31.sh's
# FT31_LISTEN_PORT=51821 if that ever changes.
FT31_INPUT_PORT=51821

# --- Host INPUT rule (senior-review pass: real Frankfurt preflight evidence)
#
# Real, verified Frankfurt facts (read-only SSH diagnosis, not assumed):
# INPUT already ACCEPTs UDP 51820 (production awg0) and ends in a terminal
# REJECT - there is NO existing UDP 51821 ACCEPT, so inbound B37 traffic
# would be silently rejected by INPUT regardless of anything this file's
# FORWARD-rule functions do (FORWARD only decides whether an already-
# INPUT-accepted/locally-destined packet gets forwarded onward - it has no
# say over whether the packet reaches this host's own listening socket in
# the first place).
#
# Stockholm's own live INPUT model has NOT been read-only-diagnosed the same
# way (see docs/FIELD_TEST_RUSSIA_AWG31.md's PREDEPLOY GATE) - every function
# below is Frankfurt-only BY DESIGN, and deliberately refuses (fails closed,
# zero mutation) rather than guessing for any other host, exactly the same
# discipline as ft31_verify_runtime's own per-host case statement.

# ft31_input_rule_present <host> - true (0) only if the exact b37-ft31 INPUT
# ACCEPT rule already exists. Always false for a host with no audited INPUT
# model (never dies - "not present" is the correct, safe answer for a
# presence CHECK; ft31_add_input_rule is the one that fails closed on an
# unaudited host, since only an ADD needs to refuse to guess).
ft31_input_rule_present() {
    local host=$1
    case "$host" in
        frankfurt)
            iptables -C INPUT -p udp --dport "$FT31_INPUT_PORT" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null
            ;;
        *) return 1 ;;
    esac
}

# _ft31_frankfurt_input_reject_line_number - internal helper. Returns (on
# stdout) the 1-indexed position, AMONG "-A INPUT ..." rules only (i.e. the
# same numbering `iptables -I INPUT <N>` expects - the chain's own `-P INPUT
# ...` policy line is not itself a numbered rule and is excluded), of the
# chain's terminal REJECT/DROP rule. Fails closed (die) unless there is
# EXACTLY ONE REJECT/DROP rule in INPUT and it is the LAST rule - this file
# must never guess an insertion point in an unexpected/drifted chain shape.
_ft31_frankfurt_input_reject_line_number() {
    local rules line idx=0 reject_count=0 reject_line=0
    rules=$(iptables -S INPUT 2>/dev/null | grep '^-A INPUT ' || true)
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        idx=$((idx + 1))
        if printf '%s' "$line" | grep -qE -- '-j (REJECT|DROP)'; then
            reject_count=$((reject_count + 1))
            reject_line=$idx
        fi
    done <<< "$rules"
    [ "$reject_count" -eq 1 ] || die "runtime mismatch: frankfurt INPUT chain does not have exactly one terminal REJECT/DROP rule (found $reject_count) - refusing to guess where to insert the b37-ft31 INPUT rule"
    [ "$reject_line" -eq "$idx" ] || die "runtime mismatch: frankfurt INPUT chain's REJECT/DROP rule is not the LAST rule (found at position $reject_line of $idx) - refusing to insert before an unexpected chain shape"
    printf '%s' "$reject_line"
}

# ft31_add_input_rule <host> - idempotent; inserts the b37-ft31 INPUT ACCEPT
# rule immediately before the chain's terminal REJECT/DROP (so it stays
# ahead of the final verdict, without disturbing the relative order or
# position of any other existing rule, including the pre-existing UDP 51820
# ACCEPT). Fails closed (die, zero mutation) for any host with no audited
# INPUT model - never a blind guess for Stockholm or any future host.
ft31_add_input_rule() {
    local host=$1
    ft31_input_rule_present "$host" && return 0
    case "$host" in
        frankfurt)
            local reject_line
            reject_line=$(_ft31_frankfurt_input_reject_line_number)
            iptables -I INPUT "$reject_line" -p udp --dport "$FT31_INPUT_PORT" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT
            ;;
        *)
            die "ft31_add_input_rule: no audited host INPUT model for '$host' - refusing to guess an INPUT rule (see docs/FIELD_TEST_RUSSIA_AWG31.md's PREDEPLOY GATE)"
            ;;
    esac
}

# ft31_remove_input_rule <host> - removes exactly the b37-ft31 INPUT ACCEPT
# rule (no-op, exit 0, if already absent or the host has no INPUT model at
# all - there is nothing of ours to remove either way).
ft31_remove_input_rule() {
    local host=$1
    case "$host" in
        frankfurt)
            iptables -D INPUT -p udp --dport "$FT31_INPUT_PORT" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null || true
            ;;
        *) : ;;
    esac
}

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
            # Real Frankfurt preflight evidence (senior-review pass): INPUT
            # must also have a single terminal REJECT/DROP as its LAST rule -
            # _ft31_frankfurt_input_reject_line_number (used by
            # ft31_add_input_rule below) relies on exactly this shape to know
            # where "immediately before the terminal REJECT" actually is;
            # checked here too so a malformed/unexpected INPUT chain is
            # reported at preflight, before any mutation, not only when the
            # INPUT-rule step itself is reached.
            _ft31_frankfurt_input_reject_line_number >/dev/null
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

# --- Per-rule granular presence/add/remove (senior-review requirement:
# transactional ownership must be based on OBSERVED pre-state vs OBSERVED
# current state per RULE, not on whether a two-command function returned
# success - `ft31_add_forward_rules` issues TWO separate mutating commands;
# if the first succeeds and the second fails, the combined function exits
# non-zero having still changed live state, and a caller that only sets an
# ownership flag after the WHOLE function returns would wrongly believe
# nothing was added. Every caller that needs correct rollback ownership
# (provision-ft31.sh) must observe each rule's presence independently,
# both before mutating and again on failure, and act only on the
# per-rule delta - never on the combined function's own exit status.

# ft31_rule_to_ft31_present <host> <egress_iface> - the awg-ft31 -> egress rule.
ft31_rule_to_ft31_present() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -C FORWARD -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null
            ;;
        stockholm)
            local chain_output
            chain_output=$(nft -a list chain inet pocvpn forward 2>/dev/null || true)
            printf '%s' "$chain_output" | grep -qF "iifname \"awg-ft31\" oifname \"$egress_iface\""
            ;;
        *) return 1 ;;
    esac
}

# ft31_rule_from_ft31_present <host> <egress_iface> - the egress -> awg-ft31 established/related rule.
ft31_rule_from_ft31_present() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -C FORWARD -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null
            ;;
        stockholm)
            local chain_output
            chain_output=$(nft -a list chain inet pocvpn forward 2>/dev/null || true)
            printf '%s' "$chain_output" | grep -qF "iifname \"$egress_iface\" oifname \"awg-ft31\""
            ;;
        *) return 1 ;;
    esac
}

# ft31_add_rule_to_ft31 / ft31_add_rule_from_ft31 <host> <egress_iface>
# Each inserts exactly ONE rule, idempotently. Kept as single-command-per-
# call operations deliberately, so a caller tracking per-rule ownership
# never has to guess which half of a combined function actually landed.
ft31_add_rule_to_ft31() {
    local host=$1 egress_iface=$2
    ft31_rule_to_ft31_present "$host" "$egress_iface" && return 0
    case "$host" in
        frankfurt) iptables -I FORWARD 1 -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT ;;
        stockholm) nft insert rule inet pocvpn forward iifname "awg-ft31" oifname "$egress_iface" accept comment "$FT31_FW_MARKER" ;;
    esac
}
ft31_add_rule_from_ft31() {
    local host=$1 egress_iface=$2
    ft31_rule_from_ft31_present "$host" "$egress_iface" && return 0
    case "$host" in
        frankfurt) iptables -I FORWARD 1 -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT ;;
        stockholm) nft insert rule inet pocvpn forward iifname "$egress_iface" oifname "awg-ft31" ct state established,related accept comment "$FT31_FW_MARKER" ;;
    esac
}

# ft31_remove_rule_to_ft31 / ft31_remove_rule_from_ft31 <host> <egress_iface>
# Removes exactly ONE rule (no-op, exit 0, if already absent).
ft31_remove_rule_to_ft31() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -D FORWARD -i awg-ft31 -o "$egress_iface" -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null || true
            ;;
        stockholm)
            local h
            h=$(_ft31_handle_for_rule "$egress_iface" "\"awg-ft31\" oifname \"$egress_iface\"")
            [ -n "$h" ] && nft delete rule inet pocvpn forward handle "$h" 2>/dev/null || true
            ;;
    esac
}
ft31_remove_rule_from_ft31() {
    local host=$1 egress_iface=$2
    case "$host" in
        frankfurt)
            iptables -D FORWARD -i "$egress_iface" -o awg-ft31 -m state --state ESTABLISHED,RELATED -m comment --comment "$FT31_FW_MARKER" -j ACCEPT 2>/dev/null || true
            ;;
        stockholm)
            local h
            h=$(_ft31_handle_for_rule "$egress_iface" "\"$egress_iface\" oifname \"awg-ft31\"")
            [ -n "$h" ] && nft delete rule inet pocvpn forward handle "$h" 2>/dev/null || true
            ;;
    esac
}

# _ft31_handle_for_rule <egress_iface> <iifname/oifname substring> - internal,
# Stockholm-only helper: finds the nft rule handle for the b37-ft31 rule
# whose iifname/oifname text matches, without assuming it is the only
# b37-ft31-tagged rule present (a partial-failure state may have only one
# of the two rules, or the other rule from an unrelated direction).
_ft31_handle_for_rule() {
    local egress_iface=$1 iface_pattern=$2
    local chain_output
    chain_output=$(nft -a list chain inet pocvpn forward 2>/dev/null || true)
    printf '%s' "$chain_output" | grep -F "iifname $iface_pattern" | grep -F "comment \"$FT31_FW_MARKER\"" | sed -n 's/.*# handle \([0-9]\+\).*/\1/p' | head -1
}

# ft31_forward_rules_present <host> <egress_iface>
# Idempotency probe - true (0) only when BOTH b37-ft31 rules already exist.
# Kept for rollback-ft31.sh's own full-teardown use (that script's job is
# unconditional removal regardless of provenance, not partial-failure
# reconciliation) - provision-ft31.sh's own trap uses the per-rule
# functions above instead, precisely so a partial two-rule failure is
# tracked correctly (see this file's own top-level docs on that point).
ft31_forward_rules_present() {
    local host=$1 egress_iface=$2
    ft31_rule_to_ft31_present "$host" "$egress_iface" && ft31_rule_from_ft31_present "$host" "$egress_iface"
}

# ft31_add_forward_rules <host> <egress_iface>
# Adds EXACTLY two narrowly-scoped accept rules (awg-ft31 -> egress, and
# egress -> awg-ft31 established/related) into the host's REAL production
# forwarding path. Idempotent - a rerun with the rules already present is
# a no-op, never a duplicate insert. Kept as a convenience wrapper for
# rollback-ft31.sh/tests that want "both rules" as one call - see the
# per-rule functions above for callers that need correct partial-failure
# rollback ownership.
ft31_add_forward_rules() {
    local host=$1 egress_iface=$2
    ft31_add_rule_to_ft31 "$host" "$egress_iface"
    ft31_add_rule_from_ft31 "$host" "$egress_iface"
    log "b37-ft31 FORWARD accept rules present on $host (production egress: $egress_iface) - every pre-existing rule is otherwise unchanged"
}

# ft31_remove_forward_rules <host> <egress_iface>
# Removes ONLY the two b37-ft31-tagged rules this task added - never
# anything else in the production forwarding path. Safe to call even if
# the rules are already absent (no-op).
ft31_remove_forward_rules() {
    local host=$1 egress_iface=$2
    ft31_remove_rule_to_ft31 "$host" "$egress_iface"
    ft31_remove_rule_from_ft31 "$host" "$egress_iface"
    log "removed b37-ft31 FORWARD rules (if present) - every other FORWARD rule is untouched"
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

# ft31_verify_rollback_exact <pre_snapshot_file> <post_snapshot_file>
#
# senior-review correction (A3): rollback-ft31.sh previously reused
# ft31_verify_no_unrelated_change in the "reverse" direction (checking that
# POST is an ordered subsequence of PRE) as its own safety net. That check is
# MATHEMATICALLY VACUOUS for a removal-only operation: since rollback only
# ever DELETES lines from PRE, the resulting POST is *by construction*
# always an ordered subsequence of PRE, no matter WHICH lines were deleted -
# deleting an unrelated production rule instead of (or in addition to) the
# intended b37-ft31 rule(s) would still pass that check every single time.
# Concretely: PRE = [A, B, C] (B = an unrelated production rule), a buggy
# rollback that removes B instead of the intended C-only target produces
# POST = [A, C] - still a valid ordered subsequence of [A, B, C] - so the old
# check could never have caught this class of bug.
#
# This check instead proves the actual, sufficient property: POST must equal
# PRE with ONLY the exact b37-ft31-tagged line(s) removed - nothing else
# added, removed, or reordered. Every rule this task ever adds carries the
# literal "$FT31_FW_MARKER" comment/marker (see ft31_add_rule_to_ft31/
# ft31_add_rule_from_ft31 - both the frankfurt `-m comment --comment
# b37-ft31` and stockholm `comment "b37-ft31"` forms embed this exact
# string), and nothing else in either host's real ruleset dump is expected
# to ever contain it, so filtering PRE for lines NOT containing that marker
# computes the exact expected POST-rollback state deterministically, without
# needing to reconstruct either backend's exact rule-dump syntax by hand.
ft31_verify_rollback_exact() {
    local pre_file=$1 post_file=$2
    local expected_file
    expected_file=$(mktemp)
    grep -vF "$FT31_FW_MARKER" "$pre_file" > "$expected_file"
    if ! diff -q "$expected_file" "$post_file" >/dev/null 2>&1; then
        local diff_output
        diff_output=$(diff -u "$expected_file" "$post_file" 2>&1 || true)
        rm -f "$expected_file"
        die "rollback verification FAILED: post-rollback ruleset is NOT exactly pre-rollback minus only the $FT31_FW_MARKER-tagged rule(s) - at least one unrelated rule was also removed, reordered, or changed (or a b37-ft31 rule was NOT actually removed). Diff (expected vs actual):
$diff_output"
    fi
    rm -f "$expected_file"
    log "rollback verification: post-rollback ruleset is EXACTLY pre-rollback minus only the $FT31_FW_MARKER-tagged rule(s) - no unrelated rule was removed, reordered, or changed"
}
