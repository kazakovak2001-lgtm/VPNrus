#!/usr/bin/env bash
# B36 - installs the ONE shared, PUBLIC bootstrap peer plus the additive
# nftables restriction, on WHICHEVER gateway runtime this host is confirmed
# to be running:
#   - Frankfurt: iptables-nft (`ip filter`/`ip nat`), owned by a host-local
#     awg-firewall.service (not tracked in this repository) - left
#     completely untouched.
#   - Stockholm: this repository's own native nftables `inet pocvpn` table
#     (gateway/nftables/pocvpn.nft.template) - also left completely
#     untouched.
# See gateway/lib/bootstrap_runtime.sh for the exact detection/priority-
# verification this relies on, and docs/B36_SERVER_DEPLOYMENT_PLAN.md for
# the full per-host design.
#
# Usage:
#   sudo ./install-bootstrap-peer.sh                      # autodetect
#   sudo ./install-bootstrap-peer.sh --runtime frankfurt   # explicit override
#   sudo ./install-bootstrap-peer.sh --runtime stockholm
#
# Fails closed - refuses to proceed - if the runtime cannot be confirmed
# unambiguously and no --runtime override is given, or if the live
# FORWARD/INPUT-hook priority ordering cannot be confirmed safe. NEVER
# silently applies a firewall model that does not match the live host, and
# NEVER assumes hook ordering without reading the real, live ruleset first.
#
# Reuses add-peer.sh (peer lifecycle: durable config write, lock, live
# convergence check) UNCHANGED on BOTH runtimes - this script never
# re-implements or branches peer mutation itself, only the firewall
# restriction and its own pre-flight verification.
#
# Installation order is deliberately fail-closed: the restriction must
# exist (and be verified live) BEFORE the shared/public bootstrap peer is
# ever added, never the other way around. If any step after the first
# state mutation fails, the EXIT trap below rolls back only the dedicated
# state THIS script itself created in THIS run (the bootstrap peer, the
# pocvpn_bootstrap table/config file, and its systemd unit) - it never
# touches production firewall/NAT or any other peer, and the rollback is
# idempotent (safe to run again against partially-rolled-back state).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/bootstrap_runtime.sh
source "$SCRIPT_DIR/lib/bootstrap_runtime.sh"
load_config
# shellcheck source=../config/bootstrap.env
source "$SCRIPT_DIR/config/bootstrap.env"

[ "$(id -u)" -eq 0 ] || die "must be run as root"
is_valid_wg_key "$BOOTSTRAP_CLIENT_PUBLIC_KEY" || die "config/bootstrap.env: BOOTSTRAP_CLIENT_PUBLIC_KEY is not a valid AmneziaWG/WireGuard key"

# Overridable only for the isolated test harness (gateway/scripts/tests/) -
# unset in production, so these always resolve to the real system paths.
: "${BOOTSTRAP_NFT_CONF_PATH:=/etc/nftables.pocvpn-bootstrap.conf}"
: "${BOOTSTRAP_SYSTEMD_UNIT_PATH:=/etc/systemd/system/nftables-pocvpn-bootstrap.service}"

# --- rollback state tracking + trap -----------------------------------
# Set to 1 only immediately AFTER the corresponding mutation is confirmed
# to have actually happened - so a failure at step N only ever rolls back
# steps 1..N-1 that genuinely ran, never anything past this run's own
# dedicated state, and never anything production-owned.
NFT_TABLE_APPLIED=0
PERSISTENCE_INSTALLED=0
PEER_ADDED=0

rollback_bootstrap_install() {
    local exit_code=$?
    if [ "$exit_code" -eq 0 ]; then
        return
    fi
    log "install failed (exit $exit_code) - rolling back ONLY this run's own dedicated bootstrap state (never production firewall/NAT, never any other peer)"

    if [ "$PEER_ADDED" -eq 1 ]; then
        log "rollback: removing the bootstrap peer ($BOOTSTRAP_CLIENT_PUBLIC_KEY)"
        "$SCRIPT_DIR/scripts/remove-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY" 2>/dev/null \
            || log "rollback WARNING: remove-peer.sh for the bootstrap peer did not report success - verify manually with 'awg show $INTERFACE_NAME peers'"
    fi

    if [ "$PERSISTENCE_INSTALLED" -eq 1 ]; then
        log "rollback: disabling the bootstrap nftables persistence unit"
        systemctl disable --now nftables-pocvpn-bootstrap.service 2>/dev/null || true
        rm -f "$BOOTSTRAP_SYSTEMD_UNIT_PATH"
        systemctl daemon-reload 2>/dev/null || true
    fi

    if [ "$NFT_TABLE_APPLIED" -eq 1 ]; then
        log "rollback: deleting the dedicated $BOOTSTRAP_NFT_TABLE table"
        nft delete table inet "$BOOTSTRAP_NFT_TABLE" 2>/dev/null || true
    fi
    # The rendered conf file is this script's own dedicated artifact
    # regardless of whether `nft -f` ever succeeded - always safe to
    # remove, and removing it is itself idempotent.
    rm -f "$BOOTSTRAP_NFT_CONF_PATH"

    log "rollback complete - production firewall/NAT and all other peers were never touched by this script"
}
trap rollback_bootstrap_install EXIT

RUNTIME=""
if [ "${1:-}" = "--runtime" ]; then
    case "${2:-}" in
        frankfurt) RUNTIME=frankfurt-iptables-nft ;;
        stockholm) RUNTIME=stockholm-native-nftables ;;
        *) die "usage: $0 [--runtime frankfurt|stockholm]" ;;
    esac
    log "runtime explicitly selected: $RUNTIME (skipping autodetection)"
else
    RUNTIME=$(detect_bootstrap_firewall_runtime) || die "could not confirm a known firewall runtime (neither Frankfurt's iptables-nft+awg-firewall.service nor Stockholm's native 'inet pocvpn' table matched unambiguously) - refusing to guess. Re-run with --runtime frankfurt|stockholm only after manually confirming which shape this host actually runs."
    log "detected runtime: $RUNTIME"
fi

case "$RUNTIME" in
    frankfurt-iptables-nft)
        PRODUCTION_NFT_FAMILY=ip
        PRODUCTION_NFT_TABLE=filter
        ;;
    stockholm-native-nftables)
        PRODUCTION_NFT_FAMILY=inet
        PRODUCTION_NFT_TABLE="$NFT_TABLE"   # poc.env - "pocvpn"
        ;;
    *) die "internal error: unrecognized runtime '$RUNTIME'" ;;
esac

# --- A. verify runtime + production hook priorities (no mutation yet) --
log "step A/I: verifying live FORWARD-hook ordering ($PRODUCTION_NFT_FAMILY $PRODUCTION_NFT_TABLE vs bootstrap priority $BOOTSTRAP_FORWARD_PRIORITY) before applying anything"
verify_bootstrap_priority_precedes_production "$PRODUCTION_NFT_FAMILY" "$PRODUCTION_NFT_TABLE" "$BOOTSTRAP_FORWARD_PRIORITY"
log "step A/I: verifying live INPUT-hook ordering ($PRODUCTION_NFT_FAMILY $PRODUCTION_NFT_TABLE vs bootstrap priority $BOOTSTRAP_INPUT_PRIORITY), where a production INPUT hook exists at all, before applying anything"
verify_bootstrap_input_priority_precedes_production "$PRODUCTION_NFT_FAMILY" "$PRODUCTION_NFT_TABLE" "$BOOTSTRAP_INPUT_PRIORITY"

# --- B. render the bootstrap nftables config (no live mutation yet) ----
log "step B/I: rendering the bootstrap nftables table ($BOOTSTRAP_NFT_TABLE)"
render_template "$SCRIPT_DIR/nftables/pocvpn-bootstrap.nft.template" \
    "NFT_TABLE_BOOTSTRAP=$BOOTSTRAP_NFT_TABLE" \
    "BOOTSTRAP_CLIENT_IP=$BOOTSTRAP_CLIENT_TUNNEL_IP" \
    "BOOTSTRAP_FORWARD_PRIORITY=$BOOTSTRAP_FORWARD_PRIORITY" \
    "BOOTSTRAP_INPUT_PRIORITY=$BOOTSTRAP_INPUT_PRIORITY" \
    > "$BOOTSTRAP_NFT_CONF_PATH"
chmod 644 "$BOOTSTRAP_NFT_CONF_PATH"

# --- C. syntax/validation check, if the installed nft supports it ------
log "step C/I: syntax-checking the rendered config before applying it"
NFT_CHECK_OUTPUT=$(nft -c -f "$BOOTSTRAP_NFT_CONF_PATH" 2>&1) && NFT_CHECK_RC=0 || NFT_CHECK_RC=$?
if [ "$NFT_CHECK_RC" -ne 0 ]; then
    if printf '%s' "$NFT_CHECK_OUTPUT" | grep -qiE 'unknown option|unrecognized option|invalid option|-c'; then
        log "installed nft does not support '-c' syntax checking - skipping this step, proceeding to a real apply (which itself fails closed on any syntax error)"
    else
        die "syntax check failed for the rendered bootstrap nftables config: $NFT_CHECK_OUTPUT"
    fi
else
    log "syntax check passed"
fi

# --- D. install/apply the bootstrap nftables table ----------------------
log "step D/I: applying the bootstrap nftables table"
nft -f "$BOOTSTRAP_NFT_CONF_PATH"
NFT_TABLE_APPLIED=1

# --- E. verify the live table, FORWARD drop and INPUT restriction exist
log "step E/I: verifying the live bootstrap table matches the expected shape and priorities"
verify_bootstrap_table_live "$BOOTSTRAP_NFT_TABLE" "$BOOTSTRAP_CLIENT_TUNNEL_IP" "$BOOTSTRAP_FORWARD_PRIORITY" "$BOOTSTRAP_INPUT_PRIORITY"

# --- F. install/enable persistence --------------------------------------
log "step F/I: enabling boot-persistence for the bootstrap nftables table (its own dedicated systemd unit, independent of either runtime's own persistence mechanism)"
install -m 0644 "$SCRIPT_DIR/systemd/nftables-pocvpn-bootstrap.service" "$BOOTSTRAP_SYSTEMD_UNIT_PATH"
systemctl daemon-reload
systemctl enable --now nftables-pocvpn-bootstrap.service
PERSISTENCE_INSTALLED=1

# --- G. verify the persistence unit is active and the table still exists
log "step G/I: verifying the persistence unit is active and the bootstrap table is still live"
systemctl is-active --quiet nftables-pocvpn-bootstrap.service \
    || die "post-persistence verification failed: nftables-pocvpn-bootstrap.service is not active"
nft list table inet "$BOOTSTRAP_NFT_TABLE" >/dev/null 2>&1 \
    || die "post-persistence verification failed: inet $BOOTSTRAP_NFT_TABLE is no longer present after enabling persistence"

# --- H. ONLY THEN add the shared bootstrap peer -------------------------
log "step H/I: the bootstrap restriction is confirmed live - now adding the shared bootstrap peer (label: bootstrap, tunnel IP: $BOOTSTRAP_CLIENT_TUNNEL_IP)"
"$SCRIPT_DIR/scripts/add-peer.sh" "$BOOTSTRAP_CLIENT_PUBLIC_KEY" "$BOOTSTRAP_CLIENT_TUNNEL_IP" bootstrap
PEER_ADDED=1

# --- I. verify the bootstrap peer exists in durable config and live awg0
log "step I/I: verifying the bootstrap peer is present in durable config and live $INTERFACE_NAME"
verify_bootstrap_peer_live "$BOOTSTRAP_CLIENT_PUBLIC_KEY" "$BOOTSTRAP_CLIENT_TUNNEL_IP" "$CONFIG_DIR/$CONFIG_FILE" "$INTERFACE_NAME"

log "re-verifying the existing PRODUCTION ruleset is untouched:"
case "$RUNTIME" in
    frankfurt-iptables-nft)
        nft list table ip filter >/dev/null 2>&1 || die "POST-CHECK FAILED: ip filter table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        nft list table ip nat >/dev/null 2>&1 || die "POST-CHECK FAILED: ip nat table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        systemctl is-active --quiet awg-firewall.service || log "WARNING: awg-firewall.service is not reported active after this change - verify manually; this script never starts/stops/reloads it"
        ;;
    stockholm-native-nftables)
        nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "POST-CHECK FAILED: inet $NFT_TABLE table no longer present after applying the bootstrap restriction - investigate immediately, this must never happen"
        ;;
esac

log "done. verify with:"
log "  awg show $INTERFACE_NAME peers               # bootstrap public key should be listed"
log "  nft list table inet $BOOTSTRAP_NFT_TABLE      # both restriction rules should be present, priority $BOOTSTRAP_FORWARD_PRIORITY on forward, $BOOTSTRAP_INPUT_PRIORITY on input"
log "  from a second host through the bootstrap tunnel: only tcp/443 to this box's own public IP should succeed; every other destination/port should time out or be refused"
