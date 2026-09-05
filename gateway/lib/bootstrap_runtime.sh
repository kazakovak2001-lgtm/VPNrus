#!/usr/bin/env bash
# B36 - runtime-variant detection + netfilter hook-priority verification for
# the additive bootstrap-peer firewall restriction. Not meant to be run
# directly - sourced by install-bootstrap-peer.sh/uninstall-bootstrap-peer.sh.
# Requires lib/common.sh to already be sourced (for log/die).
#
# Frankfurt and Stockholm run DIFFERENT firewall implementations for the
# EXISTING production AWG forwarding/NAT - verified directly against each
# host, not assumed (see docs/B36_SERVER_DEPLOYMENT_PLAN.md's own per-host
# sections for the full verified-fact table):
#   - Frankfurt: iptables-nft compatibility tables (`ip filter`/`ip nat`),
#     applied/owned by a host-local `awg-firewall.service` - NOT tracked in
#     this repository (host-specific, predates this repo's own
#     provision.sh/nftables convention).
#   - Stockholm: this repository's own native nftables table (`inet
#     pocvpn`, gateway/nftables/pocvpn.nft.template), applied directly by
#     provision.sh - no separate firewall-apply service.
#
# The additive bootstrap-restriction table itself
# (gateway/nftables/pocvpn-bootstrap.nft.template) is IDENTICAL on both -
# it declares its own separately-named `inet pocvpn_bootstrap` table, which
# coexists with EITHER underlying production implementation unmodified.
# Detection below exists so install-bootstrap-peer.sh never applies a
# verification step meant for one runtime against the other, and never
# silently proceeds when the live host does not match either known shape.
#
# ---------------------------------------------------------------------
# Netfilter hook-priority reasoning (task requirement 4 - documented, not
# assumed):
#
# A nftables base chain's dispatch order at a given hook (e.g. `forward`)
# for a given packet is determined SOLELY by the registered chains'
# priority values for that packet's L3 protocol - this ordering is
# enforced by the kernel's netfilter core hook infrastructure itself,
# independent of which userspace tool (native `nft`, or the `iptables-nft`
# compatibility layer that backs plain `iptables` on modern Debian/Ubuntu)
# registered the chain, and independent of nftables "family" declaration
# (`ip` vs `inet`) beyond which L3 protocols that family's hooks cover
# (`inet` covers both IPv4 and IPv6; `ip` covers IPv4 only - for an actual
# IPv4 packet, an `inet`-family chain and an `ip`-family chain hooked into
# the SAME point are dispatched together, in one strict priority order).
# This is standard, documented netfilter/nftables architecture - the exact
# mechanism Debian/RHEL rely on for their own default "iptables-nft
# coexists with native nftables" backend - not a guess.
#
# This is why a NEW `inet pocvpn_bootstrap` table with
# `hook forward priority -5` (config/bootstrap.env's
# BOOTSTRAP_FORWARD_PRIORITY) runs BEFORE Frankfurt's `ip filter` FORWARD
# chain (legacy/iptables-nft default priority 0, the exact numeric value
# nftables' own named priority "filter" resolves to) AND BEFORE Stockholm's
# `inet pocvpn` FORWARD chain (this repository's own
# `type filter hook forward priority filter;`, also 0) - in BOTH cases,
# -5 < 0. [read_forward_hook_priority]/[verify_bootstrap_priority_precedes_production]
# below still VERIFY the real live value on the actual host rather than
# trusting this reasoning blindly, so an unexpected non-default priority on
# either host fails closed instead of silently applying an unsafe ordering.
#
# Table-coexistence note (FORWARD): `iptables-nft`/`iptables-restore`
# (Frankfurt's `awg-firewall.service`) only ever touches the specific
# tables it owns (`ip filter`, `ip nat`, ...) - it does not issue a global
# `nft flush ruleset`, so a separately-named `inet pocvpn_bootstrap` table
# is never affected by that service reloading/restarting. This is standard
# iptables-nft behavior, but has NOT been physically read against
# Frankfurt's actual `awg-firewall.service` unit file (not tracked in this
# repository) - install-bootstrap-peer.sh re-checks the bootstrap table's
# presence immediately after every apply as a defensive measure.
#
# KNOWN, DISCLOSED LIMITATION (INPUT, Frankfurt only): the verified
# Frankfurt facts this plan is built from name a FORWARD/NAT ruleset only -
# no INPUT-hook rule is documented for Frankfurt's `awg-firewall.service`.
# If that service's real (untracked) ruleset already ACCEPTs
# awg0-sourced/bootstrap-sourced traffic in its own INPUT chain ahead of
# this table's `input` chain, this table's own "tcp/443 only" DROP for
# every other locally-delivered port from the bootstrap source may not
# execute for already-accepted packets - a no-op in that case, never a
# WORSENING of what the host already allowed (this table only ever adds a
# DROP, never an ACCEPT, for traffic other than tcp/443). The FORWARD
# restriction above (the actual "no general Internet access" boundary) is
# unaffected by this either way. install-bootstrap-peer.sh prints an
# explicit reminder to read Frankfurt's real INPUT ruleset
# (`iptables -L INPUT -n` / `nft list ruleset`) as a manual, read-only
# verification step before treating the tcp/443-only restriction as a hard
# guarantee on that host specifically.

# detect_bootstrap_firewall_runtime
# Prints exactly one of "frankfurt-iptables-nft" / "stockholm-native-nftables"
# on stdout and returns 0, or returns 1 (nothing printed) if the signals are
# ambiguous or match neither known shape - callers MUST treat return 1 as
# "fail closed", never guess a default.
detect_bootstrap_firewall_runtime() {
    local is_frankfurt=0 is_stockholm=0

    if systemctl list-unit-files 2>/dev/null | grep -q '^awg-firewall\.service' \
        && nft list table ip filter >/dev/null 2>&1; then
        is_frankfurt=1
    fi

    if [ -f /etc/nftables.pocvpn.conf ] && nft list table inet pocvpn >/dev/null 2>&1; then
        is_stockholm=1
    fi

    if [ "$is_frankfurt" -eq 1 ] && [ "$is_stockholm" -eq 0 ]; then
        printf 'frankfurt-iptables-nft\n'
        return 0
    fi
    if [ "$is_stockholm" -eq 1 ] && [ "$is_frankfurt" -eq 0 ]; then
        printf 'stockholm-native-nftables\n'
        return 0
    fi
    return 1
}

# read_forward_hook_priority <family> <table>
# Prints the live numeric FORWARD-hook priority of <family> <table>'s own
# base chain hooked at `forward` (there must be exactly one), or returns 1
# if it cannot be determined unambiguously (table/hook missing, more than
# one forward hook in the table, or an unparseable priority token) - never
# guesses a default.
read_forward_hook_priority() {
    local family=$1 table=$2
    local listing
    listing=$(nft list table "$family" "$table" 2>/dev/null) || return 1

    local hook_lines
    hook_lines=$(printf '%s\n' "$listing" | grep -c 'hook forward priority')
    [ "$hook_lines" -eq 1 ] || return 1

    local priority_token
    priority_token=$(printf '%s\n' "$listing" | grep 'hook forward priority' | sed -E 's/.*hook forward priority ([^;]+);.*/\1/' | tr -d ' ')

    if [ "$priority_token" = "filter" ]; then
        printf '0\n'
        return 0
    fi
    [[ "$priority_token" =~ ^-?[0-9]+$ ]] || return 1
    printf '%s\n' "$priority_token"
    return 0
}

# verify_bootstrap_priority_precedes_production <family> <table> <bootstrap_priority>
# Dies (fail closed) unless <family> <table>'s live FORWARD-hook priority is
# confirmed strictly greater than <bootstrap_priority> - i.e. the bootstrap
# table's DROP genuinely runs first for every real packet. Never assumes;
# always reads the live ruleset via read_forward_hook_priority above.
verify_bootstrap_priority_precedes_production() {
    local family=$1 table=$2 bootstrap_priority=$3
    local production_priority
    production_priority=$(read_forward_hook_priority "$family" "$table") \
        || die "could not determine the live FORWARD-hook priority of $family $table - refusing to apply the bootstrap restriction without confirming ordering"

    if [ "$production_priority" -le "$bootstrap_priority" ]; then
        die "unsafe ordering: $family $table's own FORWARD-hook priority ($production_priority) is not greater than the bootstrap table's priority ($bootstrap_priority) - the bootstrap DROP would not reliably run first. Refusing to apply. Investigate manually before retrying."
    fi

    log "verified live: $family $table FORWARD-hook priority is $production_priority (> bootstrap priority $bootstrap_priority) - bootstrap DROP is confirmed to execute first"
}
