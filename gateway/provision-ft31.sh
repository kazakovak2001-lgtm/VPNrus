#!/usr/bin/env bash
# B37 (senior-review correction) - provisions the ISOLATED AmneziaWG 3.1
# field-test interface (awg-ft31) alongside an already-provisioned
# production awg0 gateway. Never touches awg0.conf, awg-poc.service, or any
# existing peer - only adds new, separate files/units scoped to awg-ft31,
# plus exactly two narrowly-scoped, tagged ACCEPT rules inserted into each
# host's OWN real production forwarding path (see lib/ft31_forward_rules.sh
# for why a second, competing nftables base chain is unsafe and was removed).
#
# Usage:
#   sudo FT31_CLIENT_PUBLIC_KEY=... FT31_CLIENT_TUNNEL_IP=10.77.31.2 \
#        ./provision-ft31.sh <frankfurt|stockholm>
#
# Secret handling (senior-review requirement):
# - The server's own awg-ft31 private key and the shared HeaderProtectionKey
#   are generated HERE, ON THIS HOST, via `awg genkey` - never accepted as
#   an input, never echoed to stdout, never written to shell history or
#   passed as a literal command-line argument. Only the resulting PUBLIC
#   key is printed (non-secret, safe to relay/report) - see step 1's own
#   output for the exact, one-time instructions to retrieve
#   HeaderProtectionKey yourself, directly from this server's own config
#   file, for pasting into the Android build (never through this script,
#   never through a chat/ticket/log).
#
# Transactional ownership model (senior-review requirement - read before
# touching the trap below): ownership of what to roll back on failure is
# decided by OBSERVING live state, twice - once BEFORE any mutation begins
# (captured into the FT31_PRE_* variables below), and again INSIDE the trap
# if something fails (the FT31_PRE_* variables are compared against
# freshly re-observed CURRENT state at that moment). This is deliberately
# NOT "set a flag to true after each mutating command returns success" -
# several of the steps below issue MORE THAN ONE mutating command (most
# notably the two separate FORWARD-rule inserts), so a command can partially
# succeed and then the overall step can still fail; a flag set only after
# the WHOLE step returns would then wrongly believe nothing happened and
# leave the first, already-applied half behind. Observing actual state
# before and (again) after is correct regardless of exactly which command
# inside a step failed, or how many of them ran.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/peer_mutations.sh
source "$SCRIPT_DIR/lib/peer_mutations.sh"
# shellcheck source=lib/ft31_forward_rules.sh
source "$SCRIPT_DIR/lib/ft31_forward_rules.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/config/awg-ft31-profile.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"

FT31_HOST=${1:-}
case "$FT31_HOST" in
    frankfurt|stockholm) ;;
    *) die "usage: $0 <frankfurt|stockholm> - unknown/missing host, refusing to mutate any firewall rule" ;;
esac

: "${FT31_CLIENT_PUBLIC_KEY:?FT31_CLIENT_PUBLIC_KEY is required (non-secret - the field-test build own public key)}"
: "${FT31_CLIENT_TUNNEL_IP:?FT31_CLIENT_TUNNEL_IP is required (e.g. 10.77.31.2, non-secret)}"
is_valid_wg_key "$FT31_CLIENT_PUBLIC_KEY" || die "FT31_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard public key"

# Isolated interface facts - deliberately NOT read from config/poc.env (see
# gateway/config/awg-ft31-profile.env's own docs for why).
FT31_INTERFACE_NAME=awg-ft31
FT31_CONFIG_FILE=awg-ft31.conf
FT31_LISTEN_PORT=51821
FT31_SUBNET_CIDR=10.77.31.0/24
FT31_GATEWAY_TUNNEL_IP=10.77.31.1
FT31_GATEWAY_TUNNEL_PREFIX=24

# Test-only path overrides (senior-review requirement: failure-injection
# tests must exercise THIS actual script, not a reimplementation of its
# logic - these absolute system paths are the only thing standing in the
# way of running it against an isolated temp root). Every var defaults to
# the exact real production path when unset, so normal/real invocations are
# completely unaffected - `FT31_TEST_*` is deliberately named to make clear
# these are never meant to be set outside a test harness.
#
# Fail-closed gate (senior-review requirement F2): a real deploy's own shell/
# CI/inherited environment could accidentally carry a stale FT31_TEST_* var
# from an unrelated prior test run. Rather than silently ignoring that (which
# could mask a genuine test-harness misconfiguration) or silently honoring it
# (which could redirect a real production deploy at a throwaway temp root),
# any FT31_TEST_* var being set at all is refused UNLESS the harness also
# sets FT31_TEST_HARNESS_MODE=1 - a real invocation never sets either.
if [ -n "${FT31_TEST_CONFIG_DIR:-}${FT31_TEST_IP_FORWARD_PROC:-}${FT31_TEST_SYSTEMD_UNIT_DIR:-}${FT31_TEST_NFTABLES_CONF_PATH:-}" ] \
    && [ "${FT31_TEST_HARNESS_MODE:-}" != "1" ]; then
    die "FT31_TEST_* path override(s) are set but FT31_TEST_HARNESS_MODE=1 is not - refusing to run against a possibly-redirected path. This is either a real deploy with a stale test var leaked into its environment (unset it), or a test harness that forgot to also set FT31_TEST_HARNESS_MODE=1."
fi
CONFIG_DIR="${FT31_TEST_CONFIG_DIR:-/etc/amnezia/amneziawg}"
IP_FORWARD_PROC="${FT31_TEST_IP_FORWARD_PROC:-/proc/sys/net/ipv4/ip_forward}"
SYSTEMD_UNIT_DIR="${FT31_TEST_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
NFTABLES_CONF_PATH="${FT31_TEST_NFTABLES_CONF_PATH:-/etc/nftables.pocvpn-ft31.conf}"
FT31_SERVICE_UNIT_PATH="$SYSTEMD_UNIT_DIR/awg-poc-ft31.service"
FT31_CONFIG_PATH="$CONFIG_DIR/$FT31_CONFIG_FILE"

command -v awg >/dev/null && command -v awg-quick >/dev/null || \
    die "amneziawg-tools not found - run provision.sh (production awg0) on this host first"
[ "$(cat "$IP_FORWARD_PROC" 2>/dev/null || echo 0)" = "1" ] || \
    die "IPv4 forwarding is not enabled - run provision.sh (production awg0) on this host first"

EGRESS_IFACE=$(detect_egress_interface)
[ -n "$EGRESS_IFACE" ] || die "could not detect a default-route egress interface"

# Test-only failure-injection hooks (senior-review requirement: prove the
# trap's rollback ownership is based on OBSERVED state, not on whether a
# step's own command happened to return success - each hook below fires
# ONLY when its named env var is explicitly set, which a real invocation
# never does; every hook is a no-op by default). Each is placed right
# after the state-changing action it names, simulating "this step's own
# mutation actually landed, but something failed before the step as a
# whole would have returned success" - exactly the class of partial
# failure a plain "set a flag after the command returns" model gets wrong.
_ft31_test_fail_if() {
    local var_name=$1
    local value="${!var_name:-}"
    if [ -n "$value" ] && [ "${FT31_TEST_HARNESS_MODE:-}" != "1" ]; then
        die "$var_name is set but FT31_TEST_HARNESS_MODE=1 is not - refusing to honor a failure-injection hook outside a test harness"
    fi
    [ -z "$value" ] || die "test-injected failure via $var_name (failure-injection test only - never set outside a test harness)"
}

log "step 0/5: preflight - verifying $FT31_HOST's live firewall runtime matches its expected production facts"
ft31_verify_runtime "$FT31_HOST" "$EGRESS_IFACE"

# --- Preflight collision checks (senior-review requirement A6) -----------
# Only meaningful on a genuinely FRESH deploy (no existing awg-ft31 config on
# this host yet) - if a config already exists, any port/interface/subnet
# usage found below is expected to BE this host's own prior B37 state, which
# the fail-closed exact-content checks in steps 1/3/4 already reconcile
# idempotently. Checked here, before ANY mutation, so an unrelated
# collision is reported before this run touches anything.
if [ ! -f "$CONFIG_DIR/$FT31_CONFIG_FILE" ]; then
    if command -v ss >/dev/null 2>&1; then
        if ss -uln 2>/dev/null | awk '{print $5}' | grep -qE "[:.]$FT31_LISTEN_PORT\$"; then
            die "preflight collision: UDP $FT31_LISTEN_PORT already has a listener and no prior awg-ft31 config exists on this host - refusing to provision on top of an unexplained port owner. Investigate manually before retrying."
        fi
    else
        log "  [warn] 'ss' not found - could not verify UDP $FT31_LISTEN_PORT is free before provisioning; proceeding on the strength of the interface/subnet checks below only"
    fi
    if ip link show "$FT31_INTERFACE_NAME" >/dev/null 2>&1; then
        die "preflight collision: interface $FT31_INTERFACE_NAME already exists but no awg-ft31 config was found for it - refusing to provision on top of unexplained existing interface state. Investigate manually before retrying."
    fi
    if ip route show 2>/dev/null | grep -qE "^${FT31_SUBNET_CIDR//./\\.}([[:space:]]|\$)"; then
        die "preflight collision: a route for $FT31_SUBNET_CIDR already exists and no prior awg-ft31 config was found - refusing to provision on top of an unexplained existing route. Investigate manually before retrying."
    fi
    log "  [ok] no pre-existing owner of UDP $FT31_LISTEN_PORT / interface $FT31_INTERFACE_NAME / subnet $FT31_SUBNET_CIDR"
fi

PRE_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$PRE_SNAPSHOT"
log "captured pre-mutation firewall snapshot ($PRE_SNAPSHOT) for the post-deploy no-unrelated-change proof"

# --- Observe EVERY B37-relevant pre-state, BEFORE any mutation below ------
# (senior-review requirement 1-5: ownership of what the trap rolls back is
# decided from these observations vs a second observation taken again
# inside the trap, never from "did the mutating command return success").
FT31_PRE_CONFIG_EXISTS=false
[ -f "$FT31_CONFIG_PATH" ] && FT31_PRE_CONFIG_EXISTS=true

FT31_PRE_PEER_EXISTS=false
if [ "$FT31_PRE_CONFIG_EXISTS" = true ] && grep -qF "PublicKey = $FT31_CLIENT_PUBLIC_KEY" "$FT31_CONFIG_PATH" 2>/dev/null; then
    FT31_PRE_PEER_EXISTS=true
fi

FT31_PRE_NAT_EXISTS=false
nft list table inet pocvpn-ft31 >/dev/null 2>&1 && FT31_PRE_NAT_EXISTS=true

FT31_PRE_SERVICE_FILE_EXISTS=false
[ -f "$FT31_SERVICE_UNIT_PATH" ] && FT31_PRE_SERVICE_FILE_EXISTS=true
FT31_PRE_SERVICE_ENABLED=false
systemctl is-enabled awg-poc-ft31.service >/dev/null 2>&1 && FT31_PRE_SERVICE_ENABLED=true
FT31_PRE_SERVICE_ACTIVE=false
systemctl is-active awg-poc-ft31.service >/dev/null 2>&1 && FT31_PRE_SERVICE_ACTIVE=true

FT31_PRE_RULE_TO_FT31_EXISTS=false
ft31_rule_to_ft31_present "$FT31_HOST" "$EGRESS_IFACE" && FT31_PRE_RULE_TO_FT31_EXISTS=true
FT31_PRE_RULE_FROM_FT31_EXISTS=false
ft31_rule_from_ft31_present "$FT31_HOST" "$EGRESS_IFACE" && FT31_PRE_RULE_FROM_FT31_EXISTS=true

log "pre-mutation B37 state observed: config=$FT31_PRE_CONFIG_EXISTS peer=$FT31_PRE_PEER_EXISTS nat=$FT31_PRE_NAT_EXISTS service_file=$FT31_PRE_SERVICE_FILE_EXISTS service_enabled=$FT31_PRE_SERVICE_ENABLED service_active=$FT31_PRE_SERVICE_ACTIVE rule_to=$FT31_PRE_RULE_TO_FT31_EXISTS rule_from=$FT31_PRE_RULE_FROM_FT31_EXISTS"

# --- Failure trap: re-observes CURRENT state and reconciles it back to ----
# the pre-mutation observations above - never removes anything that was
# already there before this invocation started, regardless of which
# individual command inside a step actually failed.
#
# Residual limitation, reported rather than hidden: this trap runs on any
# normal bash error exit (`set -e`, or an explicit `die`), but cannot run
# if the process is killed uncatchably (`kill -9`, a host power loss, an
# OOM-kill) mid-script - such an event can still leave partial B37 state.
# Re-running this same script afterwards is safe (every step is
# idempotent/pre-existence-checked) and will either complete the deploy or
# report the same failure again; `rollback-ft31.sh` remains the manual,
# always-safe way to fully remove all B37 state regardless of how it was
# left.
ft31_rollback_this_invocation() {
    local exit_code=$?
    if [ "$exit_code" -eq 0 ]; then return 0; fi
    log "provision-ft31.sh FAILED (exit $exit_code) - reconciling live state back to what existed before this invocation (never touching state that already existed, never touching awg0)"

    # FORWARD rules - each of the two rules is reconciled INDEPENDENTLY, so
    # a partial failure (one inserted, the other not) is handled correctly.
    if [ "$FT31_PRE_RULE_TO_FT31_EXISTS" = false ] && ft31_rule_to_ft31_present "$FT31_HOST" "$EGRESS_IFACE"; then
        ft31_remove_rule_to_ft31 "$FT31_HOST" "$EGRESS_IFACE"
        log "  rolled back: awg-ft31 -> egress FORWARD rule (did not exist before this run)"
    fi
    if [ "$FT31_PRE_RULE_FROM_FT31_EXISTS" = false ] && ft31_rule_from_ft31_present "$FT31_HOST" "$EGRESS_IFACE"; then
        ft31_remove_rule_from_ft31 "$FT31_HOST" "$EGRESS_IFACE"
        log "  rolled back: egress -> awg-ft31 FORWARD rule (did not exist before this run)"
    fi

    # systemd - reconcile file existence, enabled, and active state
    # independently; `systemctl enable --now` is not assumed atomic.
    local now_service_active=false now_service_enabled=false now_service_file_exists=false
    [ -f "$FT31_SERVICE_UNIT_PATH" ] && now_service_file_exists=true
    systemctl is-enabled awg-poc-ft31.service >/dev/null 2>&1 && now_service_enabled=true
    systemctl is-active awg-poc-ft31.service >/dev/null 2>&1 && now_service_active=true

    if [ "$FT31_PRE_SERVICE_FILE_EXISTS" = false ]; then
        # Did not exist before -> fully tear down whatever exists now.
        if [ "$now_service_active" = true ] || [ "$now_service_enabled" = true ] || [ "$now_service_file_exists" = true ]; then
            systemctl disable --now awg-poc-ft31.service 2>/dev/null || true
            rm -f "$FT31_SERVICE_UNIT_PATH"
            systemctl daemon-reload 2>/dev/null || true
            log "  rolled back: awg-poc-ft31.service (unit file did not exist before this run)"
        fi
    else
        # Existed before - restore the EXACT enabled/active combination it
        # had, never remove the unit file itself.
        if [ "$FT31_PRE_SERVICE_ACTIVE" = true ] && [ "$now_service_active" = false ]; then
            systemctl start awg-poc-ft31.service 2>/dev/null || true
            log "  restored: awg-poc-ft31.service active state (was active before this run)"
        elif [ "$FT31_PRE_SERVICE_ACTIVE" = false ] && [ "$now_service_active" = true ]; then
            systemctl stop awg-poc-ft31.service 2>/dev/null || true
            log "  restored: awg-poc-ft31.service inactive state (was inactive before this run)"
        fi
        if [ "$FT31_PRE_SERVICE_ENABLED" = true ] && [ "$now_service_enabled" = false ]; then
            systemctl enable awg-poc-ft31.service 2>/dev/null || true
            log "  restored: awg-poc-ft31.service enabled state (was enabled before this run)"
        elif [ "$FT31_PRE_SERVICE_ENABLED" = false ] && [ "$now_service_enabled" = true ]; then
            systemctl disable awg-poc-ft31.service 2>/dev/null || true
            log "  restored: awg-poc-ft31.service disabled state (was disabled before this run)"
        fi
    fi

    # NAT - remove the live table if it did not exist before AND exists
    # now, regardless of whether `nft -f` itself reported success or
    # failure; ALSO remove the on-disk config file whenever this run is the
    # one that wrote it (FT31_PRE_NAT_EXISTS=false), independently of
    # whether the live table ended up applied - covers the partial-failure
    # case where the rendered file was written but `nft -f` itself failed,
    # which would otherwise leave an orphan config file with no
    # corresponding live table.
    if [ "$FT31_PRE_NAT_EXISTS" = false ]; then
        if nft list table inet pocvpn-ft31 >/dev/null 2>&1; then
            nft delete table inet pocvpn-ft31 2>/dev/null || true
            log "  rolled back: isolated NAT table (did not exist before this run)"
        fi
        if [ -f "$NFTABLES_CONF_PATH" ]; then
            rm -f "$NFTABLES_CONF_PATH"
            log "  rolled back: this run's rendered $NFTABLES_CONF_PATH (did not exist before this run)"
        fi
    fi

    # Peer - remove only if it did not exist before AND exists now. Must
    # happen BEFORE the config-file removal below (removing a peer requires
    # the config file it lives in to still exist).
    if [ "$FT31_PRE_PEER_EXISTS" = false ] && [ -f "$FT31_CONFIG_PATH" ] && grep -qF "PublicKey = $FT31_CLIENT_PUBLIC_KEY" "$FT31_CONFIG_PATH" 2>/dev/null; then
        CONFIG_FILE=$FT31_CONFIG_FILE
        INTERFACE_NAME=$FT31_INTERFACE_NAME
        # Subshell-isolated for the same reason as the mutate_add_peer call
        # above - we are already inside the EXIT trap here, so a trap
        # clobbered by mutate_remove_peer would not matter for THIS
        # invocation, but isolating it is still correct: it keeps this
        # trap's own behavior independent of peer_mutations.sh internals
        # regardless of call site, and costs nothing.
        ( mutate_remove_peer "$FT31_CLIENT_PUBLIC_KEY" ) 2>/dev/null || true
        log "  rolled back: this run's field-test peer entry (did not exist before this run)"
    fi

    # Config file - remove only if it did not exist before AND exists now
    # (covers a render/chmod/chown failure partway through creating it,
    # not merely "the whole step returned non-zero").
    if [ "$FT31_PRE_CONFIG_EXISTS" = false ] && [ -f "$FT31_CONFIG_PATH" ]; then
        rm -f "$FT31_CONFIG_PATH"
        log "  rolled back: this run's freshly-generated awg-ft31.conf (did not exist before this run; server private key/HeaderProtectionKey discarded, never persisted elsewhere)"
    fi

    log "rollback of this invocation's own state complete - no half-deployed B37 state left behind by this run, no pre-existing B37 state touched"
}
trap ft31_rollback_this_invocation EXIT

log "step 1/5: isolated awg-ft31 interface config"
install -d -m 0700 "$CONFIG_DIR"
if [ "$FT31_PRE_CONFIG_EXISTS" = true ]; then
    log "existing config found at $FT31_CONFIG_PATH - leaving server identity/HeaderProtectionKey untouched"
else
    # Generated HERE, on this host, via `awg genkey` - held only in shell
    # variables for the remainder of this script, never echoed, never
    # passed as a literal CLI argument, never written anywhere but directly
    # into the 0600 config file below. Explicitly unset afterwards so no
    # subshell/trap/core-dump can retain them longer than necessary.
    FT31_SERVER_PRIVATE_KEY=$(awg genkey)
    FT31_SERVER_PUBLIC_KEY=$(printf '%s' "$FT31_SERVER_PRIVATE_KEY" | awg pubkey)
    FT31_HEADER_PROTECTION_KEY=$(awg genkey)

    render_template "$SCRIPT_DIR/config/awg-ft31.conf.example" \
        "SERVER_PRIVATE_KEY=$FT31_SERVER_PRIVATE_KEY" \
        "HEADER_PROTECTION_KEY=$FT31_HEADER_PROTECTION_KEY" \
        "GATEWAY_TUNNEL_IP=$FT31_GATEWAY_TUNNEL_IP" \
        "GATEWAY_TUNNEL_PREFIX=$FT31_GATEWAY_TUNNEL_PREFIX" \
        "LISTEN_PORT=$FT31_LISTEN_PORT" \
        "AWG_FT31_JC=$AWG_FT31_JC" "AWG_FT31_JMIN=$AWG_FT31_JMIN" "AWG_FT31_JMAX=$AWG_FT31_JMAX" \
        "AWG_FT31_S1=$AWG_FT31_S1" "AWG_FT31_S2=$AWG_FT31_S2" "AWG_FT31_S3=$AWG_FT31_S3" "AWG_FT31_S4=$AWG_FT31_S4" \
        "AWG_FT31_H1=$AWG_FT31_H1" "AWG_FT31_H2=$AWG_FT31_H2" "AWG_FT31_H3=$AWG_FT31_H3" "AWG_FT31_H4=$AWG_FT31_H4" \
        "AWG_FT31_I1=$AWG_FT31_I1" "AWG_FT31_I2=$AWG_FT31_I2" "AWG_FT31_I3=$AWG_FT31_I3" \
        "AWG_FT31_I4=$AWG_FT31_I4" "AWG_FT31_I5=$AWG_FT31_I5" \
        "AWG_FT31_CONTENT_PADDING_ADDITION=$AWG_FT31_CONTENT_PADDING_ADDITION" \
        "AWG_FT31_RANDOM_TRAILERS=$AWG_FT31_RANDOM_TRAILERS" "AWG_FT31_DISABLE_COOKIES=$AWG_FT31_DISABLE_COOKIES" \
        > "$FT31_CONFIG_PATH"
    chmod 600 "$FT31_CONFIG_PATH"
    chown root:root "$FT31_CONFIG_PATH"
    _ft31_test_fail_if FT31_TEST_FAIL_AFTER_CONFIG

    log "server public key (safe to share/paste into FieldTestAwg31GatewayCatalog.kt): $FT31_SERVER_PUBLIC_KEY"
    log "HeaderProtectionKey is NOT printed here (secret, shared-key material)."
    log "Retrieve it YOURSELF, directly from this server, when you are ready to build the field-test APK:"
    log "    sudo grep '^HeaderProtectionKey' $FT31_CONFIG_PATH"
    log "Paste it directly into FieldTestAwg31GatewayCatalog.kt's headerProtectionKeyBase64 for this gateway."
    log "Never paste it into chat, a ticket, a commit message, or any log."
    unset FT31_SERVER_PRIVATE_KEY FT31_HEADER_PROTECTION_KEY
fi

log "step 2/5: field-test peer"
CONFIG_FILE=$FT31_CONFIG_FILE
INTERFACE_NAME=$FT31_INTERFACE_NAME
AWG_SUBNET_CIDR=$FT31_SUBNET_CIDR
GATEWAY_TUNNEL_IP=$FT31_GATEWAY_TUNNEL_IP
ip_in_cidr "$FT31_CLIENT_TUNNEL_IP" "$AWG_SUBNET_CIDR" || die "$FT31_CLIENT_TUNNEL_IP is not inside $AWG_SUBNET_CIDR"
LOCK_FILE="$CONFIG_DIR/.provision-ft31.lock"
exec 9>"$LOCK_FILE"
flock -x 9
if [ "$FT31_PRE_PEER_EXISTS" = true ]; then
    log "field-test peer already present - leaving it untouched"
else
    # CRITICAL: mutate_add_peer (lib/peer_mutations.sh) sets its own
    # `trap ... EXIT` internally for its own tmp-file cleanup, then clears
    # it with `trap - EXIT` once it succeeds - bash traps are GLOBAL to the
    # shell, not scoped to the function that set them, so calling it
    # directly in THIS shell would silently wipe out
    # ft31_rollback_this_invocation's own registration, AND a failure
    # occurring INSIDE mutate_add_peer itself (before its own `trap - EXIT`
    # ever runs) would fire mutate_add_peer's tmp-file-cleanup trap instead
    # of ours - meaning our rollback would never run at all for that case,
    # not merely be at risk of being overwritten after the fact. Isolating
    # the call in its own subshell fixes both: the subshell has its own,
    # completely separate trap table, so anything mutate_add_peer does to
    # `trap ... EXIT` inside it can never touch this (parent) shell's own
    # ft31_rollback_this_invocation registration, regardless of whether
    # mutate_add_peer succeeds, fails internally, or fails partway through.
    # The subshell's own exit status still propagates normally to `set -e`
    # here, and every filesystem side effect it makes (the config file
    # write) is real, not lost - only shell-local state (traps, variables)
    # is subshell-local.
    ( mutate_add_peer "$FT31_CLIENT_PUBLIC_KEY" "$FT31_CLIENT_TUNNEL_IP" "field-test-awg31" )
fi
_ft31_test_fail_if FT31_TEST_FAIL_AFTER_PEER

log "step 3/5: isolated NAT (inet pocvpn-ft31, no forward/filter chain - see this table's own docs)"
# Fail-closed on pre-existing, differing B37 state (senior-review requirement
# A2): render the desired config to a TEMP file first, never straight over
# the real path, so an already-live table (FT31_PRE_NAT_EXISTS) is never
# blindly overwritten. If the on-disk config already matches byte-for-byte,
# leave it untouched (idempotent rerun). If it exists but differs, this is
# unexpected/unowned B37 state (or a profile change) - die BEFORE any
# mutation rather than silently replacing it.
FT31_NAT_RENDERED=$(mktemp)
render_template "$SCRIPT_DIR/nftables/pocvpn-ft31.nft.template" \
    "EGRESS_IFACE=$EGRESS_IFACE" \
    "AWG_FT31_SUBNET=$FT31_SUBNET_CIDR" \
    > "$FT31_NAT_RENDERED"
if [ "$FT31_PRE_NAT_EXISTS" = true ]; then
    if [ -f "$NFTABLES_CONF_PATH" ] && cmp -s "$FT31_NAT_RENDERED" "$NFTABLES_CONF_PATH"; then
        log "existing $NFTABLES_CONF_PATH already matches the desired B37 NAT config exactly - leaving untouched"
    else
        rm -f "$FT31_NAT_RENDERED"
        die "runtime mismatch: inet pocvpn-ft31 (or $NFTABLES_CONF_PATH) already exists but does not exactly match the desired B37 NAT config - refusing to overwrite unrecognized/differing pre-existing B37 state. Investigate manually (compare against gateway/nftables/pocvpn-ft31.nft.template) before retrying."
    fi
else
    mv "$FT31_NAT_RENDERED" "$NFTABLES_CONF_PATH"
    chmod 644 "$NFTABLES_CONF_PATH"
    nft -f "$NFTABLES_CONF_PATH"
fi
rm -f "$FT31_NAT_RENDERED"
_ft31_test_fail_if FT31_TEST_FAIL_AFTER_NAT

log "step 4/5: systemd service"
# Same fail-closed policy as NAT above (senior-review requirement A2): a
# pre-existing unit file is compared byte-for-byte against the source unit
# in this repo before any install - matching state is left untouched,
# differing state fails closed rather than being silently replaced.
if [ "$FT31_PRE_SERVICE_FILE_EXISTS" = true ]; then
    if cmp -s "$SCRIPT_DIR/systemd/awg-poc-ft31.service" "$FT31_SERVICE_UNIT_PATH"; then
        log "existing $FT31_SERVICE_UNIT_PATH already matches the desired B37 unit exactly - leaving untouched"
    else
        die "runtime mismatch: $FT31_SERVICE_UNIT_PATH already exists but does not exactly match the desired B37 unit (gateway/systemd/awg-poc-ft31.service) - refusing to overwrite unrecognized/differing pre-existing B37 state. Investigate manually before retrying."
    fi
else
    install -m 0644 "$SCRIPT_DIR/systemd/awg-poc-ft31.service" "$FT31_SERVICE_UNIT_PATH"
fi
systemctl daemon-reload
# B37 disposable-field-test policy (senior-review requirement B3): this unit
# is deliberately only STARTED, never enabled across reboot. The two
# required FORWARD accept rules this script adds directly into each host's
# real production forwarding path (step 5/5) are NOT reapplied at boot by
# anything - if the service auto-started after a reboot with those firewall
# rules gone, the field-test interface would come up with no route out,
# a confusing half-working state for a supposedly-disposable test. Requiring
# an explicit reprovision/start after any reboot is the smaller, safer of
# the two options (vs. building new boot-time firewall-reapplication
# machinery for a throwaway interface) - see rollback-ft31.sh for full
# teardown and this script for how to bring it back up again.
systemctl start awg-poc-ft31.service
_ft31_test_fail_if FT31_TEST_FAIL_AFTER_SERVICE

log "step 5/5: FORWARD accept rules in the REAL production forwarding path ($FT31_HOST)"
ft31_add_rule_to_ft31 "$FT31_HOST" "$EGRESS_IFACE"
_ft31_test_fail_if FT31_TEST_FAIL_AFTER_FIRST_FORWARD_RULE
ft31_add_rule_from_ft31 "$FT31_HOST" "$EGRESS_IFACE"
log "b37-ft31 FORWARD accept rules present on $FT31_HOST"

POST_SNAPSHOT=$(mktemp)
ft31_snapshot_ruleset "$FT31_HOST" "$POST_SNAPSHOT"
ft31_verify_no_unrelated_change "$PRE_SNAPSHOT" "$POST_SNAPSHOT"
rm -f "$PRE_SNAPSHOT" "$POST_SNAPSHOT"

log "post-deploy verification:"
ft31_verify_runtime "$FT31_HOST" "$EGRESS_IFACE" && log "  [ok] existing production awg0/FORWARD facts for $FT31_HOST are still intact"
ft31_forward_rules_present "$FT31_HOST" "$EGRESS_IFACE" && log "  [ok] b37-ft31 FORWARD accept rules are present"
FT31_NAT_OUTPUT=$(nft list table inet pocvpn-ft31 2>/dev/null || true)
printf '%s' "$FT31_NAT_OUTPUT" | grep -q masquerade && log "  [ok] b37-ft31 NAT (masquerade) is present"

log "done. verify: sudo awg show $FT31_INTERFACE_NAME"
