#!/usr/bin/env bash
# Shared helpers sourced by provision.sh and scripts/*.sh. Not meant to be run directly.

GATEWAY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo "[pocvpn] $*" >&2; }
die()  { echo "[pocvpn] ERROR: $*" >&2; exit 1; }

load_config() {
    # shellcheck disable=SC1090
    source "$GATEWAY_ROOT/config/poc.env"
    # shellcheck disable=SC1090
    source "$GATEWAY_ROOT/config/awg-profile.env"
    load_host_overrides "${POCVPN_AWG_HOST_ENV_FILE:-/etc/pocvpn/awg-host.env}"
}

# load_host_overrides <PATH>
# B47 Frankfurt: per-host facts the tracked config/poc.env cannot carry.
# Stockholm's AWG unit is awg-poc.service (poc.env default); Frankfurt's is
# awg-quick@awg0.service, and a wrong SERVICE_NAME makes converge_live_state
# skip every live reload. The file lives outside the deployed tree, so a
# redeploy of config/ never reverts it. Absent file = no override.
#
# PARSED, never sourced: exactly SERVICE_NAME is accepted, any other key or
# a malformed value fails closed - this runs as root for provisioning and
# reconcile, so a host file must not be able to inject shell or silently
# change addressing (CONFIG_DIR/INTERFACE_NAME stay repo-defined).
# POCVPN_AWG_HOST_ENV_FILE exists for the test harness only; the sudo
# wrapper's `env -i` and the systemd units never set it.
load_host_overrides() {
    local path=$1 line key value
    [ -e "$path" ] || return 0
    [ -f "$path" ] && [ -r "$path" ] || die "host override $path is not a readable regular file"
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]] || die "host override $path: malformed line"
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        case "$key" in
            SERVICE_NAME)
                [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9@._-]{0,99}$ ]] \
                    || die "host override $path: invalid SERVICE_NAME value"
                SERVICE_NAME=$value
                ;;
            *) die "host override $path: unsupported key $key (only SERVICE_NAME may be overridden)" ;;
        esac
    done < "$path"
}

# A WireGuard/AmneziaWG key is 32 raw bytes, base64-encoded -> 44 chars, last char '='.
is_valid_wg_key() {
    [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

ipv4_to_int() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

int_to_ipv4() {
    local i=$1
    echo "$(( (i >> 24) & 255 )).$(( (i >> 16) & 255 )).$(( (i >> 8) & 255 )).$(( i & 255 ))"
}

is_valid_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}

# ip_in_cidr <ip> <cidr, e.g. 10.77.0.0/24>
ip_in_cidr() {
    local ip=$1 cidr=$2
    local net_addr=${cidr%/*} prefix=${cidr#*/}
    is_valid_ipv4 "$ip" || return 1
    is_valid_ipv4 "$net_addr" || return 1
    local ip_int net_int mask
    ip_int=$(ipv4_to_int "$ip")
    net_int=$(ipv4_to_int "$net_addr")
    mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    (( (ip_int & mask) == (net_int & mask) ))
}

detect_egress_interface() {
    ip route show default 2>/dev/null | awk '/^default/ { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }'
}

render_template() {
    # render_template <template-file> <VAR1=val1> <VAR2=val2> ...
    local template=$1; shift
    local content
    content=$(cat "$template")
    local pair key val
    for pair in "$@"; do
        key=${pair%%=*}
        val=${pair#*=}
        content=${content//__${key}__/${val}}
    done
    printf '%s\n' "$content"
}
