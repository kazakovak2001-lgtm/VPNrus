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
# RESOLVED (previously a disclosed limitation, INPUT, Frankfurt only): an
# earlier version of this table hooked `input` at nftables' named priority
# "filter" (0) - the SAME priority as either production runtime's own
# INPUT chain, if one exists. At equal priority, dispatch order between
# base chains falls back to base-chain registration order, which is not
# something this repository controls or can verify for Frankfurt's
# untracked `awg-firewall.service` - so this table's own DROP was not
# guaranteed to run before a same-priority production ACCEPT.
#
# This table's `input` chain now hooks at BOOTSTRAP_INPUT_PRIORITY
# (config/bootstrap.env, default -5 - the same safe earlier value as
# BOOTSTRAP_FORWARD_PRIORITY), and
# verify_bootstrap_input_priority_precedes_production below verifies, on
# the LIVE ruleset, that this priority is strictly earlier than any
# production INPUT hook that exists on the host before ever applying the
# bootstrap table. Since a lower/earlier priority is unconditionally
# dispatched first regardless of registration order, this table's DROP is
# now guaranteed to execute before any production INPUT chain (existing or
# not) ever sees the bootstrap source's non-443 traffic - no limitation
# genuinely remains here. (If a host has some OTHER, non-nftables-visible
# mechanism intercepting the packet before the netfilter input hook at all
# - e.g. a raw socket - no nftables-priority ordering could ever address
# that; nothing in either verified host's facts suggests this applies.)

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

# read_hook_priority <family> <table> <hook>
# Prints the live numeric <hook>-hook priority of <family> <table>'s own
# base chain hooked at <hook> on stdout and returns 0, if there is exactly
# one such hook. Returns 2 (nothing printed) if <family> <table> declares
# NO base chain at that hook at all - a legitimate, distinguishable
# outcome (e.g. Stockholm's `inet pocvpn` has no `input` hook), never
# treated as an error by callers. Returns 1 (nothing printed) if it cannot
# be determined unambiguously (table missing entirely, more than one such
# hook in the table, or an unparseable priority token) - callers MUST treat
# 1 as fail-closed. Never guesses a default.
read_hook_priority() {
    local family=$1 table=$2 hook=$3
    local listing
    listing=$(nft list table "$family" "$table" 2>/dev/null) || return 1

    local hook_lines
    hook_lines=$(printf '%s\n' "$listing" | grep -c "hook $hook priority")
    if [ "$hook_lines" -eq 0 ]; then
        return 2
    fi
    [ "$hook_lines" -eq 1 ] || return 1

    local priority_token
    priority_token=$(printf '%s\n' "$listing" | grep "hook $hook priority" | sed -E "s/.*hook $hook priority ([^;]+);.*/\1/" | tr -d ' ')

    if [ "$priority_token" = "filter" ]; then
        printf '0\n'
        return 0
    fi
    [[ "$priority_token" =~ ^-?[0-9]+$ ]] || return 1
    printf '%s\n' "$priority_token"
    return 0
}

# read_forward_hook_priority <family> <table>
# Back-compat thin wrapper around read_hook_priority for the `forward`
# hook - see that function for the exact contract.
read_forward_hook_priority() {
    read_hook_priority "$1" "$2" forward
}

# verify_bootstrap_priority_precedes_production <family> <table> <bootstrap_priority>
# Dies (fail closed) unless <family> <table>'s live FORWARD-hook priority is
# confirmed strictly greater than <bootstrap_priority> - i.e. the bootstrap
# table's DROP genuinely runs first for every real packet. A production
# FORWARD hook is expected to exist on both known runtimes (this is the
# entire boundary this table exists to race against), so an absent hook
# (return 2) is treated the same as an unparseable one - fail closed. Never
# assumes; always reads the live ruleset via read_hook_priority above.
verify_bootstrap_priority_precedes_production() {
    local family=$1 table=$2 bootstrap_priority=$3
    local production_priority rc
    # set +e/-e around the substitution: under `set -e` (this function is
    # always sourced into a script running with it), `var=$(cmd)` aborts
    # the WHOLE script immediately if cmd fails, before `rc=$?` is ever
    # reached - unlike `cmd1 || cmd2`, a bare assignment is not exempted.
    set +e
    production_priority=$(read_hook_priority "$family" "$table" forward)
    rc=$?
    set -e

    if [ "$rc" -ne 0 ]; then
        die "could not determine the live FORWARD-hook priority of $family $table - refusing to apply the bootstrap restriction without confirming ordering"
    fi

    if [ "$production_priority" -le "$bootstrap_priority" ]; then
        die "unsafe ordering: $family $table's own FORWARD-hook priority ($production_priority) is not greater than the bootstrap table's priority ($bootstrap_priority) - the bootstrap DROP would not reliably run first. Refusing to apply. Investigate manually before retrying."
    fi

    log "verified live: $family $table FORWARD-hook priority is $production_priority (> bootstrap priority $bootstrap_priority) - bootstrap DROP is confirmed to execute first"
}

# verify_bootstrap_input_priority_precedes_production <family> <table> <bootstrap_priority>
# Dies (fail closed) unless <family> <table>'s live INPUT-hook priority
# (when one exists at all) is confirmed strictly greater than
# <bootstrap_priority>. Unlike FORWARD, a production INPUT hook is NOT
# guaranteed to exist on every known runtime (Stockholm's `inet pocvpn` has
# none) - a genuinely absent hook (return 2) is not a race at all and is
# logged, not treated as an error. An ambiguous/unparseable result (return
# 1) still fails closed exactly like the FORWARD check.
verify_bootstrap_input_priority_precedes_production() {
    local family=$1 table=$2 bootstrap_priority=$3
    local production_priority rc
    # See verify_bootstrap_priority_precedes_production above for why
    # set +e/-e is required around this substitution under `set -e`.
    set +e
    production_priority=$(read_hook_priority "$family" "$table" input)
    rc=$?
    set -e

    if [ "$rc" -eq 2 ]; then
        log "verified live: $family $table declares no INPUT hook at all - nothing to race the bootstrap table's INPUT priority $bootstrap_priority against"
        return 0
    fi
    if [ "$rc" -ne 0 ]; then
        die "could not determine the live INPUT-hook priority of $family $table - refusing to apply the bootstrap restriction without confirming ordering"
    fi

    if [ "$production_priority" -le "$bootstrap_priority" ]; then
        die "unsafe ordering: $family $table's own INPUT-hook priority ($production_priority) is not greater than the bootstrap table's INPUT priority ($bootstrap_priority) - the bootstrap INPUT restriction would not reliably run first. Refusing to apply. Investigate manually before retrying."
    fi

    log "verified live: $family $table INPUT-hook priority is $production_priority (> bootstrap INPUT priority $bootstrap_priority) - bootstrap INPUT restriction is confirmed to execute first"
}

# verify_bootstrap_table_live <table> <client_ip> <forward_priority> <input_priority>
# Fail-closed post-apply check that the just-applied dedicated bootstrap
# table is genuinely live with the exact expected hook priorities and both
# restriction rules this table exists to enforce - never trusts `nft -f`'s
# own exit code alone.
verify_bootstrap_table_live() {
    local table=$1 client_ip=$2 forward_priority=$3 input_priority=$4
    local listing
    listing=$(nft list table inet "$table" 2>/dev/null) \
        || die "post-apply verification failed: inet $table table is not present immediately after applying it"

    printf '%s\n' "$listing" | grep -qE "hook forward priority ${forward_priority};" \
        || die "post-apply verification failed: inet $table forward chain does not show the expected priority $forward_priority"
    printf '%s\n' "$listing" | grep -qE "hook input priority ${input_priority};" \
        || die "post-apply verification failed: inet $table input chain does not show the expected priority $input_priority"
    printf '%s\n' "$listing" | grep -qF "ip saddr $client_ip drop" \
        || die "post-apply verification failed: inet $table forward chain is missing its 'ip saddr $client_ip drop' rule"
    printf '%s\n' "$listing" | grep -qF "ip saddr $client_ip tcp dport 443 accept" \
        || die "post-apply verification failed: inet $table input chain is missing its 'ip saddr $client_ip tcp dport 443 accept' rule"

    log "verified live: inet $table forward(priority $forward_priority)/input(priority $input_priority) restriction rules for $client_ip are present"
}

# verify_bootstrap_peer_live <public_key> <tunnel_ip> <config_path> <interface>
# Fail-closed post-add check that the bootstrap peer is genuinely present
# in BOTH the durable config and the live AWG interface - never trusts
# add-peer.sh's own exit code alone.
verify_bootstrap_peer_live() {
    local public_key=$1 tunnel_ip=$2 config_path=$3 interface=$4

    grep -qF "PublicKey = $public_key" "$config_path" \
        || die "post-add verification failed: bootstrap peer public key not found in durable config $config_path"
    grep -A1 -F "PublicKey = $public_key" "$config_path" | grep -qF "AllowedIPs = $tunnel_ip/32" \
        || die "post-add verification failed: durable config's bootstrap peer entry does not show AllowedIPs = $tunnel_ip/32"
    awg show "$interface" peers 2>/dev/null | grep -qF "$public_key" \
        || die "post-add verification failed: bootstrap public key not present in live 'awg show $interface peers'"

    log "verified: bootstrap peer $public_key/$tunnel_ip present in both durable config ($config_path) and live $interface"
}
