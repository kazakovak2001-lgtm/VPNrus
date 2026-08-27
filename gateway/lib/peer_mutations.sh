#!/usr/bin/env bash
# Shared, UNLOCKED peer-mutation core for add-peer.sh / remove-peer.sh /
# allocate-and-add-peer.sh. Not meant to be run directly.
#
# Every function here assumes the caller has ALREADY acquired the
# .provision.lock exclusive flock before calling it, and holds it for the
# entire mutate_* + converge_live_state sequence. Nothing in this file
# touches flock itself - that is the entry-point scripts' job, exactly
# once each, so a second in-process call (e.g. allocate-and-add-peer.sh
# calling mutate_add_peer directly rather than exec'ing add-peer.sh as a
# subprocess) never attempts to re-acquire an already-held lock.
#
# Requires lib/common.sh to already be sourced (for log/die) and
# load_config to have already run (for CONFIG_DIR/CONFIG_FILE/SERVICE_NAME/
# INTERFACE_NAME) - this file does not source common.sh itself, matching
# the existing pattern of scripts sourcing common.sh directly.

# _validate_peer_markers <CONFIG_PATH>
# mutate_add_peer inserts a new peer immediately before the
# "# --- PEERS END ---" marker line. If that marker is missing, duplicated,
# or precedes "# --- PEERS BEGIN ---", the awk insertion below would
# silently no-op (or insert into the wrong place) and copy an
# unchanged/malformed config through to `mv` - which chmod/mv would still
# "succeed" at, letting the caller wrongly believe a peer was added. Fail
# closed here, before any tmp file or mv is attempted.
_validate_peer_markers() {
    local config_path=$1
    local begin_count end_count begin_line end_line

    begin_count=$(grep -c '^# --- PEERS BEGIN ---' "$config_path" || true)
    end_count=$(grep -c '^# --- PEERS END ---' "$config_path" || true)

    if [ "$begin_count" -ne 1 ]; then
        die "malformed gateway config: expected exactly one '# --- PEERS BEGIN ---' marker, found $begin_count"
    fi
    if [ "$end_count" -ne 1 ]; then
        die "malformed gateway config: expected exactly one '# --- PEERS END ---' marker, found $end_count"
    fi

    begin_line=$(grep -n '^# --- PEERS BEGIN ---' "$config_path" | cut -d: -f1)
    end_line=$(grep -n '^# --- PEERS END ---' "$config_path" | cut -d: -f1)

    if [ "$begin_line" -ge "$end_line" ]; then
        die "malformed gateway config: '# --- PEERS BEGIN ---' must occur before '# --- PEERS END ---'"
    fi
}

# _verify_peer_present_with_ip <CONFIG_PATH> <PUBLIC_KEY> <TUNNEL_IP>
# Durable postcondition check for mutate_add_peer, run AFTER the atomic mv
# has already published the new config - never trust that the awk/mv
# sequence did what it was supposed to without re-reading the actual
# published result.
_verify_peer_present_with_ip() {
    local config_path=$1 public_key=$2 tunnel_ip=$3
    local key_count
    key_count=$(grep -cF "PublicKey = $public_key" "$config_path" || true)
    if [ "$key_count" -ne 1 ]; then
        die "durable config validation failed: expected exactly one peer entry for this public key after write, found $key_count"
    fi
    if ! grep -A1 -F "PublicKey = $public_key" "$config_path" | grep -qF "AllowedIPs = $tunnel_ip/32"; then
        die "durable config validation failed: peer entry does not contain the expected AllowedIPs = $tunnel_ip/32 after write"
    fi
}

# mutate_add_peer <PUBLIC_KEY> <TUNNEL_IP> <LABEL>
# Existing-peer/existing-IP lookups happen HERE, under the caller's held
# lock - never rely on a lookup performed before the lock is acquired.
mutate_add_peer() {
    local public_key=$1 tunnel_ip=$2 label=$3
    local config_path="$CONFIG_DIR/$CONFIG_FILE"

    [ -f "$config_path" ] || die "gateway config not found at $config_path - run provision.sh first"

    if grep -qF "PublicKey = $public_key" "$config_path"; then
        die "a peer with this public key already exists"
    fi
    if grep -qE "AllowedIPs = ${tunnel_ip//./\\.}/32" "$config_path"; then
        die "tunnel IP $tunnel_ip is already assigned to another peer"
    fi

    # Fail closed before creating/publishing anything if the insertion
    # marker structure is missing, duplicated, or reversed - never
    # silently repair it.
    _validate_peer_markers "$config_path"

    local peer_block
    peer_block=$(cat <<EOF
[Peer]
# label: $label
PublicKey = $public_key
AllowedIPs = $tunnel_ip/32
EOF
    )

    # Created in CONFIG_DIR (not the system tmp dir) so the final `mv` is a
    # same-filesystem, atomic rename - a cross-filesystem `mv` would fall
    # back to a non-atomic copy+delete, which could leave a torn/partial
    # config visible mid-write. Cleaned up via the EXIT trap below if
    # anything fails before the rename; the trap is a no-op once the file
    # no longer exists (i.e. after a successful `mv`).
    local tmp_file
    tmp_file=$(mktemp -p "$CONFIG_DIR")
    trap 'rm -f "$tmp_file"' EXIT
    awk -v block="$peer_block" '
        /^# --- PEERS END ---/ { print block; print "" }
        { print }
    ' "$config_path" > "$tmp_file"
    chmod 600 "$tmp_file"
    mv "$tmp_file" "$config_path"
    trap - EXIT

    # Postcondition check against the actually-published file - never
    # claim success on the strength of the awk/mv sequence alone.
    _verify_peer_present_with_ip "$config_path" "$public_key" "$tunnel_ip"

    log "peer added: $label -> $tunnel_ip"
}

# mutate_remove_peer <PUBLIC_KEY>
mutate_remove_peer() {
    local public_key=$1
    local config_path="$CONFIG_DIR/$CONFIG_FILE"

    [ -f "$config_path" ] || die "gateway config not found at $config_path"
    grep -qF "PublicKey = $public_key" "$config_path" || die "no peer with this public key exists"

    # Peer blocks are delimited by a leading "[Peer]" line and a trailing
    # blank line (guaranteed by mutate_add_peer). A block is dropped in
    # full if it contains our target PublicKey line, otherwise it is
    # reprinted unchanged.
    # See mutate_add_peer's comment: created in CONFIG_DIR for a same-
    # filesystem atomic `mv`, cleaned up on failure via the EXIT trap.
    local tmp_file
    tmp_file=$(mktemp -p "$CONFIG_DIR")
    trap 'rm -f "$tmp_file"' EXIT
    awk -v key="PublicKey = $public_key" '
        function flush() {
            if (in_block && !matched) { for (i = 0; i < n; i++) print hold[i] }
            in_block = 0; n = 0; matched = 0
        }
        /^\[Peer\]/ {
            flush()
            in_block = 1
            hold[n++] = $0
            next
        }
        in_block && $0 == "" {
            hold[n++] = $0
            flush()
            next
        }
        in_block {
            hold[n++] = $0
            if ($0 == key) matched = 1
            next
        }
        { print }
        END { flush() }
    ' "$config_path" > "$tmp_file"
    chmod 600 "$tmp_file"
    mv "$tmp_file" "$config_path"
    trap - EXIT

    # Postcondition check against the actually-published file.
    if grep -qF "PublicKey = $public_key" "$config_path"; then
        die "durable config validation failed: peer entry still present after removal"
    fi

    log "peer removed"
}

# _live_peer_state_matches <present|absent> <PUBLIC_KEY>
# `awg show <iface> peers` lists only peer PUBLIC keys, one per line -
# never the interface's own private key (same invariant status.sh already
# relies on). Internal helper - not called directly by entry-point scripts.
#
# Return codes are deliberately three-valued, not a boolean - a failed
# query must never be mistaken for a successful "absent" (or "present"):
#   0 = query succeeded, live state matches `expected`
#   1 = query succeeded, live state does NOT match `expected`
#   2 = the `awg show` query itself failed - state is UNKNOWN, not absent
# The awg command's own exit status is captured directly from the command
# substitution (not through a pipe into grep), so pipefail/grep's exit
# status can never mask an awg failure as a successful empty result.
_live_peer_state_matches() {
    local expected=$1 public_key=$2
    local awg_output
    local awg_rc=0
    awg_output=$(awg show "$INTERFACE_NAME" peers 2>/dev/null) || awg_rc=$?

    if [ "$awg_rc" -ne 0 ]; then
        return 2
    fi

    local is_present=1
    if printf '%s\n' "$awg_output" | grep -qxF "$public_key"; then
        is_present=0
    fi

    case "$expected" in
        present) [ "$is_present" -eq 0 ]; return $? ;;
        absent)  [ "$is_present" -ne 0 ]; return $? ;;
        *) die "converge_live_state: invalid expected state '$expected' (must be 'present' or 'absent')" ;;
    esac
}

# converge_live_state <present|absent> <PUBLIC_KEY>
#
# Call only AFTER the corresponding mutate_add_peer/mutate_remove_peer has
# already durably persisted the change, still holding the same lock.
#
# - Service inactive: durable config is sufficient: it applies on next
#   start. Returns success (0) without attempting a reload - matches the
#   existing CLI behavior of "peer will apply the next time it starts".
# - Service active: success requires the live interface to actually
#   reflect the expected peer state. If it doesn't yet (or the live query
#   itself fails - see _live_peer_state_matches), one reload is attempted
#   and the live state is re-checked. Only the FINAL re-check decides the
#   outcome: a query failure is never treated as successful convergence
#   for either `present` or `absent`, and a persistent query failure after
#   the reload attempt is itself a command failure, not false success.
#   Either way this exits non-zero (via `die`) WITHOUT rolling back the
#   already-persisted durable config - the config change is real and
#   retained; only live convergence could not be confirmed. A later retry
#   (of the same request, or a manual `systemctl reload`) can converge (or
#   re-confirm) the already-correct config.
converge_live_state() {
    local expected=$1 public_key=$2
    local match_rc

    if ! systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
        log "$SERVICE_NAME.service is not currently active - durable config will apply next start"
        return 0
    fi

    match_rc=0
    _live_peer_state_matches "$expected" "$public_key" || match_rc=$?
    if [ "$match_rc" -eq 0 ]; then
        return 0
    fi

    if [ "$match_rc" -eq 2 ]; then
        log "unable to query live AWG state for $INTERFACE_NAME (awg show failed) - attempting a reload before failing"
    else
        log "live AWG state does not yet reflect the durable config - reloading $SERVICE_NAME.service"
    fi
    # Deliberately not a bare `systemctl reload ...` statement: under this
    # script's `set -e`, a non-zero reload exit would abort immediately
    # here and skip the re-check below entirely. The re-check against
    # actual live state is the real authority on success, not the
    # reload command's own exit code - so its failure is captured, not
    # fatal by itself.
    systemctl reload "$SERVICE_NAME.service" || true

    match_rc=0
    _live_peer_state_matches "$expected" "$public_key" || match_rc=$?
    if [ "$match_rc" -eq 0 ]; then
        return 0
    fi

    if [ "$match_rc" -eq 2 ]; then
        die "durable config was updated but live AWG state for $INTERFACE_NAME could not be queried after reload - convergence to '$expected' cannot be confirmed; config change is retained, retry or investigate $SERVICE_NAME.service manually"
    fi

    die "durable config was updated but live AWG state did not converge to '$expected' for this peer after reload - config change is retained; retry or investigate $SERVICE_NAME.service manually"
}

# find_existing_peer <PUBLIC_KEY>
# Unlocked - caller must already hold .provision.lock (added for B8B1A's
# provision-peer.sh, the future machine-facing entry point's idempotency
# check: it needs to know, under the lock, whether this key already has a
# durable peer BEFORE deciding whether to allocate a new IP - never after).
#
# Deliberately does NOT grep an arbitrary "AllowedIPs = " line anywhere in
# the file - only the one immediately following THIS key's own "PublicKey ="
# line, matching the exact block shape mutate_add_peer itself writes
# ([Peer] / # label / PublicKey / AllowedIPs, see above) and the same
# lookup style _verify_peer_present_with_ip already uses.
#
# On stdout: the peer's tunnel IP (only on return 0).
# Return codes (three-valued - "not found" and "found but broken" must
# never collapse into the same signal, or a caller would either silently
# skip the fail-closed checks below or silently treat malformed state as
# absent and allocate a second IP on top of it):
#   0 = exactly one peer for this key exists, with a single valid /32
#       AllowedIPs inside AWG_SUBNET_CIDR, not equal to the gateway's own
#       tunnel IP
#   1 = no peer for this key exists
#   2 = a peer for this key exists but its durable state is malformed or
#       ambiguous (multiple entries, missing/invalid/multi AllowedIPs, IP
#       outside the subnet, or IP == GATEWAY_TUNNEL_IP) - fail closed,
#       reason logged to stderr via log()
# A missing config file is treated as a harder failure than any of the
# above (die, i.e. exit 1 from the caller's perspective) since there is
# nothing to look anything up in - not folded into "not found" (which
# would wrongly invite an allocation attempt against a nonexistent file)
# nor "malformed" (which describes a file that exists but is broken).
find_existing_peer() {
    local public_key=$1
    local config_path="$CONFIG_DIR/$CONFIG_FILE"

    [ -f "$config_path" ] || die "gateway config not found at $config_path - run provision.sh first"

    local key_count
    key_count=$(grep -cF "PublicKey = $public_key" "$config_path" || true)

    if [ "$key_count" -eq 0 ]; then
        return 1
    fi
    if [ "$key_count" -gt 1 ]; then
        log "durable config is ambiguous: found $key_count PublicKey entries for this public key"
        return 2
    fi

    local allowed_ips_line
    allowed_ips_line=$(grep -A1 -F "PublicKey = $public_key" "$config_path" | tail -n1)

    local ip
    if [[ "$allowed_ips_line" =~ ^AllowedIPs\ =\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/32[[:space:]]*$ ]]; then
        ip="${BASH_REMATCH[1]}"
    else
        log "durable config is malformed: peer entry for this public key has no single valid /32 AllowedIPs line"
        return 2
    fi

    if ! is_valid_ipv4 "$ip"; then
        log "durable config is malformed: existing peer IP '$ip' is not valid IPv4"
        return 2
    fi
    if ! ip_in_cidr "$ip" "$AWG_SUBNET_CIDR"; then
        log "durable config is malformed: existing peer IP $ip is outside $AWG_SUBNET_CIDR"
        return 2
    fi
    if [ "$ip" = "$GATEWAY_TUNNEL_IP" ]; then
        log "durable config is malformed: existing peer IP equals the gateway's own tunnel IP"
        return 2
    fi

    printf '%s\n' "$ip"
    return 0
}

# allocate_lowest_free_ip
# Unlocked - caller must already hold .provision.lock. Extracted out of
# allocate-and-add-peer.sh (B8A) so B8B1A's provision-peer.sh can reuse the
# exact same lowest-free-IP algorithm instead of maintaining a second,
# independent implementation that could drift from it. allocate-and-add-
# peer.sh's own CLI behavior (exit 1 + a die() message on exhaustion) is
# unchanged - it is unaffected by this call's own error signaling: see
# below.
#
# The durable config remains the sole IP ledger: this scans awg0.conf's
# existing AllowedIPs entries (same as before extraction), skipping the
# network/broadcast/gateway addresses.
#
# On stdout: the chosen IP (only on return 0).
# Return codes: 0 = found a free address (on stdout); 3 = subnet
# exhausted, no free address - a value distinct from 1 (a plain die()'s
# exit code) so a caller can tell "genuinely exhausted" apart from "some
# other internal/config error already died with its own stderr message"
# without parsing stderr text, per B8B1A's exit-code requirement. Any
# other function-internal failure (missing config, invalid
# AWG_SUBNET_CIDR) still goes through die() as before extraction.
allocate_lowest_free_ip() {
    local config_path="$CONFIG_DIR/$CONFIG_FILE"
    [ -f "$config_path" ] || die "gateway config not found at $config_path - run provision.sh first"

    local net_addr=${AWG_SUBNET_CIDR%/*} prefix=${AWG_SUBNET_CIDR#*/}
    is_valid_ipv4 "$net_addr" || die "AWG_SUBNET_CIDR network address is not valid IPv4: $AWG_SUBNET_CIDR"
    [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 )) || die "AWG_SUBNET_CIDR prefix is invalid: $AWG_SUBNET_CIDR"
    (( prefix <= 30 )) || die "AWG_SUBNET_CIDR $AWG_SUBNET_CIDR has no usable host addresses (prefix must be <= 30)"

    local net_int mask broadcast_int gateway_int
    net_int=$(ipv4_to_int "$net_addr")
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    broadcast_int=$(( (net_int | (~mask & 0xFFFFFFFF)) & 0xFFFFFFFF ))
    gateway_int=$(ipv4_to_int "$GATEWAY_TUNNEL_IP")

    local candidate
    for (( candidate = net_int + 1; candidate < broadcast_int; candidate++ )); do
        if ! _allocate_candidate_is_used "$candidate" "$net_int" "$broadcast_int" "$gateway_int" "$config_path"; then
            printf '%s\n' "$(int_to_ipv4 "$candidate")"
            return 0
        fi
    done
    return 3
}

# _allocate_candidate_is_used <candidate_int> <net_int> <broadcast_int> <gateway_int> <config_path>
# Internal helper for allocate_lowest_free_ip - not called directly by
# entry-point scripts.
_allocate_candidate_is_used() {
    local candidate=$1 net_int=$2 broadcast_int=$3 gateway_int=$4 config_path=$5
    (( candidate == net_int )) && return 0
    (( candidate == broadcast_int )) && return 0
    (( candidate == gateway_int )) && return 0
    local existing_ip existing_int
    while IFS= read -r existing_ip; do
        [ -n "$existing_ip" ] || continue
        is_valid_ipv4 "$existing_ip" || continue
        existing_int=$(ipv4_to_int "$existing_ip")
        (( candidate == existing_int )) && return 0
    done < <(grep -E '^AllowedIPs = ' "$config_path" | sed -E 's#^AllowedIPs = ([0-9.]+)/32.*#\1#')
    return 1
}
