#!/bin/bash
# B8B1C3: LOCAL/WSL-ONLY production-like composition E2E harness.
#
# Proves the full chain, under real systemd, as a real non-root user:
#
#   HTTP -> bearer token auth -> non-root pocvpn-api -> sudo -n boundary
#        -> root-owned wrapper -> root fixture provisioning helper
#        -> HTTP 201/200
#
# using a genuinely disposable OS user, systemd unit, sudoers drop-in,
# env file, token store, and root-owned fixture tree - never the real
# gateway, never /opt/pocvpn, never /etc/amnezia/amneziawg, never
# /usr/local/libexec/pocvpn-provision-peer, never /etc/sudoers.d/pocvpn-api,
# never the real pocvpn-api.service. See gateway/privileged/README.md and
# gateway/DEPLOYMENT.md for the production shapes this harness mirrors.
#
# The systemd unit installed here (pocvpn-c3-test.service) carries the
# EXACT SAME hardening directive set as the tracked production template
# (gateway/systemd/pocvpn-api.service) - only User/Group/WorkingDirectory/
# EnvironmentFile/ReadWritePaths differ, all pointed at disposable test
# paths. Proving the chain survives THIS set is what justifies shipping it
# in the tracked template.
#
# The final privileged mutation target is an ISOLATED FIXTURE helper
# implementing the B8B1A created/existing contract against its own
# disposable state file - NOT provision-peer.sh, NOT awg0.conf, and NOT
# systemctl-reloading the real awg-poc.service. B8B1A/B8B0 already prove
# real AWG mutation semantics; re-proving them here would just be testing
# the same thing twice while risking the one thing this file must never
# risk - see the constraint below.
#
# MUST be run as root (creates/removes a system user, a systemd unit, a
# sudoers.d drop-in). If it is not, or if any required tool is missing, or
# if any disposable path is already occupied by something that isn't
# obviously this harness's own leftover, every check is marked SKIPPED
# with an explicit reason and the script exits 0 - never silently reported
# as passing.
#
# Every artifact this script creates is removed by the EXIT trap, on
# success or failure, including `systemctl daemon-reload` after the unit
# file is removed.
#
#   sudo bash gateway/systemd/tests/run_c3_e2e_tests.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GATEWAY_SRC="$REPO_ROOT/gateway"
WRAPPER_SRC="$GATEWAY_SRC/privileged/pocvpn-provision-peer"
SERVICE_TEMPLATE="$GATEWAY_SRC/systemd/pocvpn-api.service"

TEST_ID="pocvpn-c3-test"
TEST_USER="$TEST_ID"
APP_PARENT="/opt/${TEST_ID}"
APP_DIR="$APP_PARENT/gateway"
ENV_DIR="/etc/${TEST_ID}"
ENV_FILE="$ENV_DIR/api.env"
STATE_DIR="/var/lib/${TEST_ID}-provision"
TOKEN_STORE="$STATE_DIR/enrollment-tokens.json"
TOKEN_LOCK="$STATE_DIR/.tokens.lock"
WRAPPER_PATH="/usr/local/libexec/${TEST_ID}-wrapper"
FIXTURE_AWG_DIR="/var/lib/${TEST_ID}-awg"
FIXTURE_HELPER="/usr/local/libexec/${TEST_ID}-fixture-helper"
FIXTURE_STATE="$FIXTURE_AWG_DIR/state.tsv"
FIXTURE_SECRET="$FIXTURE_AWG_DIR/server-private-key"
SUDOERS_FILE="/etc/sudoers.d/${TEST_ID}"
UNIT_NAME="${TEST_ID}.service"
UNIT_FILE="/etc/systemd/system/$UNIT_NAME"
API_PORT=18143

VALID_KEY_1="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
VALID_KEY_2="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="

FAILURES=0
PASSES=0
SKIPPED=0
fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }
skip() { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

run_as_test_user() { timeout 10 runuser -u "$TEST_USER" -- "$@"; }
bounded_sudo() { timeout 10 runuser -u "$TEST_USER" -- sudo -n "$@"; }

http_get_status_body() {
    # http_request <method-irrelevant, always POST> <token-or-empty> <body>
    # Prints "<status>\n<body>" - curl only, bounded, localhost only.
    local token=$1 body=$2
    if [ -n "$token" ]; then
        curl -sS --max-time 10 -o /tmp/${TEST_ID}-resp.$$ -w '%{http_code}' \
            -X POST "http://127.0.0.1:${API_PORT}/v1/peers" \
            -H "Authorization: Bearer ${token}" \
            -H "Content-Type: application/json" \
            --data "$body"
    else
        curl -sS --max-time 10 -o /tmp/${TEST_ID}-resp.$$ -w '%{http_code}' \
            -X POST "http://127.0.0.1:${API_PORT}/v1/peers" \
            -H "Content-Type: application/json" \
            --data "$body"
    fi
    echo
    cat /tmp/${TEST_ID}-resp.$$ 2>/dev/null
    rm -f /tmp/${TEST_ID}-resp.$$
}

# ============================================================
# Preconditions
# ============================================================
_preflight_reason=""
preflight_ok() {
    if [ "$(id -u)" -ne 0 ]; then
        _preflight_reason="this harness must run as root (system user, systemd unit, sudoers.d drop-in)"
        return 1
    fi
    for bin in sudo visudo useradd userdel runuser systemctl curl python3 flock; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            _preflight_reason="required tool '$bin' is not available in this environment"
            return 1
        fi
    done
    if ! (ps -p 1 -o comm= | grep -q systemd); then
        _preflight_reason="PID 1 is not systemd in this environment - cannot run a real systemd E2E"
        return 1
    fi
    if id "$TEST_USER" >/dev/null 2>&1; then
        _preflight_reason="test user $TEST_USER already exists - not clearly this harness's own leftover"
        return 1
    fi
    for p in "$APP_PARENT" "$ENV_DIR" "$STATE_DIR" "$WRAPPER_PATH" "$FIXTURE_AWG_DIR" \
             "$FIXTURE_HELPER" "$SUDOERS_FILE" "$UNIT_FILE"; do
        if [ -e "$p" ]; then
            _preflight_reason="$p already exists - refusing to overwrite; investigate and remove manually first"
            return 1
        fi
    done
    return 0
}

# ============================================================
# Cleanup - ALWAYS runs
# ============================================================
cleanup() {
    systemctl stop "$UNIT_NAME" >/dev/null 2>&1
    systemctl disable "$UNIT_NAME" >/dev/null 2>&1
    rm -f "$UNIT_FILE"
    systemctl daemon-reload >/dev/null 2>&1
    rm -f "$SUDOERS_FILE"
    rm -f "$WRAPPER_PATH" "$FIXTURE_HELPER"
    chmod -R u+rwx "$FIXTURE_AWG_DIR" "$STATE_DIR" "$ENV_DIR" "$APP_PARENT" 2>/dev/null
    rm -rf "$FIXTURE_AWG_DIR" "$STATE_DIR" "$ENV_DIR" "$APP_PARENT"
    if id "$TEST_USER" >/dev/null 2>&1; then
        userdel "$TEST_USER" >/dev/null 2>&1
    fi
    rm -f /tmp/${TEST_ID}-*.$$  2>/dev/null
}
trap cleanup EXIT

# ============================================================
# Setup
# ============================================================
setup() {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$TEST_USER"

    # --- app code: root:root, not writable by the service user ---
    mkdir -p "$APP_DIR"
    cp -r "$GATEWAY_SRC"/. "$APP_DIR/"
    # Throwaway CRLF normalization for this disposable copy only - see
    # gateway repo-wide CRLF note; never touches the tracked source tree.
    find "$APP_DIR" -type f -print0 | xargs -0 file | grep -F 'CRLF' | cut -d: -f1 \
        | while read -r f; do sed -i 's/\r$//' "$f"; done
    chown -R root:root "$APP_PARENT"
    find "$APP_DIR" -type d -exec chmod 755 {} +
    find "$APP_DIR" -type f -exec chmod 644 {} +

    # --- env file: root:pocvpn-c3-test, 0640 - readable by the service
    # user's own systemd-loaded environment, never writable by it ---
    mkdir -p "$ENV_DIR"
    chown root:root "$ENV_DIR"
    chmod 755 "$ENV_DIR"
    cat > "$ENV_FILE" <<EOF
POCVPN_API_ENDPOINT_HOST=vpn.c3test.invalid
POCVPN_API_ENDPOINT_PORT=51820
POCVPN_API_GATEWAY_PUBLIC_KEY=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
POCVPN_API_GATEWAY_TUNNEL_IP=10.250.0.1
POCVPN_API_API_PORT=${API_PORT}
POCVPN_API_TOKEN_STORE_PATH=${TOKEN_STORE}
POCVPN_API_TOKEN_LOCK_PATH=${TOKEN_LOCK}
POCVPN_API_PROVISION_SCRIPT_PATH=${WRAPPER_PATH}
POCVPN_API_SUDO_PATH=/usr/bin/sudo
POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS=3
EOF
    chown root:"$TEST_USER" "$ENV_FILE"
    chmod 640 "$ENV_FILE"

    # --- durable token store: initialized via the real B8B1C1 operator
    # tool, then re-owned to the production-documented root:pocvpn-api
    # 0750/0640 shape ---
    PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" init >/dev/null
    ISSUED_TOKEN=$(PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" issue "$VALID_KEY_1" 2>/tmp/${TEST_ID}-issue-stderr.$$)
    ISSUED_TOKEN_ID=$(grep -oE 'token_id=[0-9a-f]{32}' /tmp/${TEST_ID}-issue-stderr.$$ | cut -d= -f2)
    rm -f /tmp/${TEST_ID}-issue-stderr.$$
    chown -R root:"$TEST_USER" "$STATE_DIR"
    chmod 750 "$STATE_DIR"
    chmod 640 "$TOKEN_STORE" "$TOKEN_LOCK"

    # --- fixture "AWG" root-only tree: pocvpn-c3-test has ZERO access,
    # matching the production invariant for /etc/amnezia/amneziawg ---
    mkdir -p "$FIXTURE_AWG_DIR"
    chown root:root "$FIXTURE_AWG_DIR"
    chmod 700 "$FIXTURE_AWG_DIR"
    : > "$FIXTURE_STATE"
    chown root:root "$FIXTURE_STATE"
    chmod 600 "$FIXTURE_STATE"
    cat > "$FIXTURE_SECRET" <<'EOF'
[Interface]
PrivateKey = c3-test-fixture-not-a-real-key
EOF
    chown root:root "$FIXTURE_SECRET"
    chmod 600 "$FIXTURE_SECRET"

    # --- fixture privileged helper: B8B1A created/existing contract
    # against $FIXTURE_STATE only - never provision-peer.sh, never
    # awg0.conf. root:root 0700 - the wrapper (root, via sudo) is the
    # only thing that ever invokes it. ---
    cat > "$FIXTURE_HELPER" <<HELPER
#!/bin/bash
set -euo pipefail
[ "\$#" -eq 1 ] || { echo "usage: \$0 <PUBLIC_KEY>" >&2; exit 2; }
KEY="\$1"
[[ "\$KEY" =~ ^[A-Za-z0-9+/]{43}=\$ ]] || { echo "invalid key" >&2; exit 1; }
if [ "\$KEY" = "TIMEOUT_TRIGGER_KEY" ]; then
    sleep 30
fi
if [ "\$KEY" = "FAIL_TRIGGER_KEY" ]; then
    echo "synthetic forced failure" >&2
    exit 1
fi
exec 8>"${FIXTURE_STATE}.lock"
flock -x 8
EXISTING_IP=\$(awk -F'\t' -v k="\$KEY" '\$1==k{print \$2}' "$FIXTURE_STATE" | head -n1)
if [ -n "\$EXISTING_IP" ]; then
    printf 'existing\t%s\n' "\$EXISTING_IP"
    exit 0
fi
COUNT=\$(wc -l < "$FIXTURE_STATE" | tr -d ' ')
NEXT_OCTET=\$(( COUNT + 2 ))
NEW_IP="10.250.0.\${NEXT_OCTET}"
printf '%s\t%s\n' "\$KEY" "\$NEW_IP" >> "$FIXTURE_STATE"
printf 'created\t%s\n' "\$NEW_IP"
HELPER
    chown root:root "$FIXTURE_HELPER"
    chmod 700 "$FIXTURE_HELPER"

    # --- test copy of the tracked wrapper - PROVISION_SCRIPT is the only
    # substituted line, exactly matching gateway/privileged/tests/
    # run_sudo_tests.sh's own established pattern (see that file / README's
    # "Testing approach") ---
    sed "s#^readonly PROVISION_SCRIPT=.*#readonly PROVISION_SCRIPT=\"$FIXTURE_HELPER\"#" \
        "$WRAPPER_SRC" | sed 's/\r$//' > "$WRAPPER_PATH"
    chown root:root "$WRAPPER_PATH"
    chmod 750 "$WRAPPER_PATH"

    # --- sudoers drop-in: identical shape to pocvpn-api.sudoers, scoped
    # to the disposable user/wrapper ---
    cat > "$SUDOERS_FILE" <<EOF
Cmnd_Alias POCVPN_C3_TEST_PROVISION = $WRAPPER_PATH
Defaults!POCVPN_C3_TEST_PROVISION env_reset
Defaults!POCVPN_C3_TEST_PROVISION !env_keep
Defaults!POCVPN_C3_TEST_PROVISION secure_path="/usr/local/bin:/usr/bin:/bin"
$TEST_USER ALL=(root) NOPASSWD: POCVPN_C3_TEST_PROVISION
EOF
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE" >/dev/null || { echo "sudoers template failed visudo -cf" >&2; exit 1; }

    # --- systemd unit: byte-identical hardening block to the tracked
    # production template, only identity/paths substituted ---
    sed \
        -e "s#^User=.*#User=$TEST_USER#" \
        -e "s#^Group=.*#Group=$TEST_USER#" \
        -e "s#^WorkingDirectory=.*#WorkingDirectory=$APP_DIR#" \
        -e "s#^EnvironmentFile=.*#EnvironmentFile=$ENV_FILE#" \
        -e "s#^ReadWritePaths=.*#ReadWritePaths=$FIXTURE_AWG_DIR#" \
        "$SERVICE_TEMPLATE" > "$UNIT_FILE"
    chmod 644 "$UNIT_FILE"
    systemctl daemon-reload
    systemctl start "$UNIT_NAME"
}

wait_for_active() {
    local tries=0
    while [ "$tries" -lt 30 ]; do
        systemctl is-active --quiet "$UNIT_NAME" && return 0
        sleep 0.5
        tries=$((tries + 1))
    done
    return 1
}

wait_for_listen() {
    local tries=0
    while [ "$tries" -lt 30 ]; do
        ss -ltn "sport = :${API_PORT}" 2>/dev/null | grep -q "$API_PORT" && return 0
        sleep 0.5
        tries=$((tries + 1))
    done
    return 1
}

# ============================================================
# H/I: real HTTP E2E through the full chain, then revoke live
# ============================================================
test_e2e_first_request_created() {
    local out status body
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    body=$(echo "$out" | tail -n1)
    if [ "$status" = "201" ] && echo "$body" | grep -q '"client_tunnel_ip": "10.250.0.2"'; then
        pass "H1: first request -> HTTP 201, created, client_tunnel_ip=10.250.0.2"
    else
        fail "H1: first request expected 201/10.250.0.2, got status=$status body=$body"
    fi
}

test_e2e_second_request_existing() {
    local out status body
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    body=$(echo "$out" | tail -n1)
    if [ "$status" = "200" ] && echo "$body" | grep -q '"client_tunnel_ip": "10.250.0.2"'; then
        pass "H2: second (retry) request -> HTTP 200, same IP, existing"
    else
        fail "H2: second request expected 200/same IP, got status=$status body=$body"
    fi
}

test_e2e_revoke_then_401_no_restart() {
    local before_active out status
    before_active=$(systemctl is-active "$UNIT_NAME")
    PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" revoke "$ISSUED_TOKEN_ID" >/dev/null
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    local after_active
    after_active=$(systemctl is-active "$UNIT_NAME")
    if [ "$status" = "401" ] && [ "$before_active" = "active" ] && [ "$after_active" = "active" ]; then
        pass "I: revoke via operator tool while service runs -> next request 401, no restart, reader re-read durable state"
    else
        fail "I: revoke/reload expected 401 with no restart, got status=$status before=$before_active after=$after_active"
    fi
}

# ============================================================
# J: filesystem/DAC proofs, as the running service's own OS user
# ============================================================
_hash() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

test_dac_must_succeed() {
    local ok=1
    run_as_test_user cat "$TOKEN_STORE" >/dev/null 2>&1 || ok=0
    run_as_test_user flock -s "$TOKEN_LOCK" -c true >/dev/null 2>&1 || ok=0
    run_as_test_user python3 -c "print(1)" >/dev/null 2>&1 || ok=0
    if [ "$ok" = "1" ]; then
        pass "J-succeed: pocvpn-c3-test can read token store, take LOCK_SH, execute python3"
    else
        fail "J-succeed: one of the required-success DAC operations failed"
    fi
}

test_dac_must_fail() {
    local before_store after_store before_wrapper after_wrapper before_helper after_helper rc
    before_store=$(_hash "$TOKEN_STORE"); before_wrapper=$(_hash "$WRAPPER_PATH"); before_helper=$(_hash "$FIXTURE_HELPER")

    local all_denied=1

    rc=0; run_as_test_user tee -a "$TOKEN_STORE" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user chmod 666 "$TOKEN_STORE" >/dev/null 2>&1 || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user rm -f "$TOKEN_STORE" >/dev/null 2>&1 || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user sh -c "echo x > '$STATE_DIR/newfile'" >/dev/null 2>&1 || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user tee -a "$ENV_FILE" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user tee -a "$APP_DIR/api/server.py" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user tee -a "$WRAPPER_PATH" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user tee -a "$FIXTURE_HELPER" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user cat "$FIXTURE_SECRET" >/dev/null 2>&1 || rc=$?; [ "$rc" -ne 0 ] || all_denied=0
    rc=0; run_as_test_user tee -a "$FIXTURE_STATE" >/dev/null 2>&1 <<< "x" || rc=$?; [ "$rc" -ne 0 ] || all_denied=0

    after_store=$(_hash "$TOKEN_STORE"); after_wrapper=$(_hash "$WRAPPER_PATH"); after_helper=$(_hash "$FIXTURE_HELPER")

    if [ "$all_denied" = "1" ] && [ "$before_store" = "$after_store" ] \
        && [ "$before_wrapper" = "$after_wrapper" ] && [ "$before_helper" = "$after_helper" ]; then
        pass "J-fail: every write/chmod/delete/create attempt by pocvpn-c3-test was denied; hashes unchanged"
    else
        fail "J-fail: at least one denied-operation or hash-stability check did not hold (all_denied=$all_denied)"
    fi
}

# ============================================================
# F: ProtectSystem=strict + DAC proof, BOTH simultaneously
# ============================================================
test_protectsystem_and_dac_together() {
    local direct_rc=0
    run_as_test_user sh -c "echo x > '$FIXTURE_AWG_DIR/direct-write-attempt'" >/dev/null 2>&1 || direct_rc=$?

    # Trigger a real provisioning request for a fresh key (its own token,
    # bound to VALID_KEY_2) so the sudo root child (inside the unit's mount
    # namespace) writes into $FIXTURE_AWG_DIR via the ReadWritePaths
    # exception.
    local token2
    token2=$(PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" issue "$VALID_KEY_2" 2>/dev/null)
    local out status
    out=$(http_get_status_body "$token2" "{\"public_key\": \"$VALID_KEY_2\"}")
    status=$(echo "$out" | head -n1)

    if [ "$direct_rc" -ne 0 ] && [ ! -e "$FIXTURE_AWG_DIR/direct-write-attempt" ] && [ "$status" = "201" ] \
        && grep -qF "$VALID_KEY_2" "$FIXTURE_STATE"; then
        pass "F: pocvpn-c3-test's own process cannot write into the ReadWritePaths-exempted fixture dir (DAC), while the sudo root child launched from inside the SAME unit successfully wrote to it (ProtectSystem=strict mount exception) - both hold at once"
    else
        fail "F: direct_rc=$direct_rc fixture_leaked=$([ -e "$FIXTURE_AWG_DIR/direct-write-attempt" ] && echo yes || echo no) status=$status state_has_key2=$(grep -qF "$VALID_KEY_2" "$FIXTURE_STATE" && echo yes || echo no)"
    fi
}

# ============================================================
# K: sudo boundary from inside the running unit's identity
# ============================================================
test_sudo_boundary_under_systemd() {
    local out rc=0
    out=$(bounded_sudo "$WRAPPER_PATH" "$VALID_KEY_1" 2>/dev/null) || rc=$?
    local approved_ok=0
    [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'existing\t10.250.0.2')" ] && approved_ok=1

    rc=0
    bounded_sudo /bin/true >/dev/null 2>&1 || rc=$?
    local unrelated_denied=0
    [ "$rc" -ne 0 ] && unrelated_denied=1

    local marker="/tmp/${TEST_ID}-env-marker.$$"
    rm -f "$marker"
    rc=0
    out=$(timeout 10 runuser -u "$TEST_USER" -- \
        env BASH_ENV="/tmp/nonexistent-${TEST_ID}.sh" ENV="/tmp/nonexistent-${TEST_ID}.sh" \
            PATH="/tmp:$PATH" PROVISION_SCRIPT="/tmp/should-not-be-used" \
        sudo -n "$WRAPPER_PATH" "$VALID_KEY_1" 2>/dev/null) || rc=$?
    local env_injection_neutralized=0
    [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'existing\t10.250.0.2')" ] && env_injection_neutralized=1

    rc=0
    bounded_sudo "$WRAPPER_PATH" "not-a-valid-key" >/dev/null 2>&1 || rc=$?
    local malformed_denied=0
    [ "$rc" -ne 0 ] && malformed_denied=1

    if [ "$approved_ok" = "1" ] && [ "$unrelated_denied" = "1" ] \
        && [ "$env_injection_neutralized" = "1" ] && [ "$malformed_denied" = "1" ]; then
        pass "K: sudo boundary holds from the running unit's own user - approved wrapper ok, unrelated command denied, PATH/BASH_ENV/ENV/PROVISION_SCRIPT injection neutralized, malformed key denied"
    else
        fail "K: approved=$approved_ok unrelated_denied=$unrelated_denied env_neutralized=$env_injection_neutralized malformed_denied=$malformed_denied"
    fi
}

# ============================================================
# L (partial): localhost-only listener
# ============================================================
test_listener_localhost_only() {
    local listing
    listing=$(ss -ltn 2>/dev/null | grep ":${API_PORT}" || true)
    local has_loopback has_wildcard
    has_loopback=$(echo "$listing" | grep -c "^LISTEN.*127\.0\.0\.1:${API_PORT}" || true)
    has_wildcard=$(echo "$listing" | grep -cE "^LISTEN.*(0\.0\.0\.0|\*|\[::\]):${API_PORT}" || true)

    local wsl_iface_ip
    wsl_iface_ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
    local external_connect_rc=1
    if [ -n "$wsl_iface_ip" ]; then
        timeout 2 bash -c "exec 3<>/dev/tcp/${wsl_iface_ip}/${API_PORT}" >/dev/null 2>&1 && external_connect_rc=0
    fi

    if [ "$has_loopback" -ge 1 ] && [ "$has_wildcard" -eq 0 ] && [ "$external_connect_rc" -ne 0 ]; then
        pass "K/17: listens only on 127.0.0.1:${API_PORT} - not 0.0.0.0/[::]/the WSL external interface ($wsl_iface_ip refused a connect)"
    else
        fail "listener check: loopback_matches=$has_loopback wildcard_matches=$has_wildcard external_connect_rc=$external_connect_rc listing='$listing'"
    fi
}

# ============================================================
# L: service restart
# ============================================================
test_service_restart() {
    local before_hash after_hash
    before_hash=$(_hash "$TOKEN_STORE")
    systemctl restart "$UNIT_NAME"
    if ! wait_for_active || ! wait_for_listen; then
        fail "L: service did not become active+listening after restart"
        return
    fi
    after_hash=$(_hash "$TOKEN_STORE")

    local out status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    local revoked_status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    # ISSUED_TOKEN was revoked earlier (test_e2e_revoke_then_401_no_restart)
    # so BOTH calls above must be 401 - re-confirms revocation survived restart.
    revoked_status=$(echo "$out" | head -n1)

    if [ "$before_hash" = "$after_hash" ] && [ "$status" = "401" ] && [ "$revoked_status" = "401" ] \
        && [ "$(systemctl is-active "$UNIT_NAME")" = "active" ]; then
        pass "L: restart -> active, token store byte-identical, revoked token still rejected (no state lived only in memory), listener re-confirmed"
    else
        fail "L: before_hash=$before_hash after_hash=$after_hash status=$status revoked_status=$revoked_status"
    fi
    test_listener_localhost_only
}

# ============================================================
# M: failure paths - each fails closed, each restores state after
# ============================================================
test_failure_missing_env() {
    systemctl stop "$UNIT_NAME" >/dev/null 2>&1
    mv "$ENV_FILE" "${ENV_FILE}.bak"
    systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1
    local rc=0
    timeout 10 systemctl start "$UNIT_NAME" >/dev/null 2>&1 || rc=$?
    local active
    active=$(systemctl is-active "$UNIT_NAME" 2>/dev/null)
    mv "${ENV_FILE}.bak" "$ENV_FILE"
    systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1
    systemctl start "$UNIT_NAME" >/dev/null 2>&1
    wait_for_active && wait_for_listen
    if [ "$active" != "active" ]; then
        pass "M: missing EnvironmentFile -> service fails to become active (fail closed)"
    else
        fail "M: service became active despite missing env file"
    fi
}

test_failure_malformed_config() {
    # Type=simple marks a unit "active" the instant ExecStart forks - not
    # once it is actually serving - so a process that forks and then
    # quickly exit(1)s on ConfigError can race a same-instant `is-active`
    # check into a false "active" reading. The real invariant this test
    # must prove is stronger and race-free: the port never actually opens.
    systemctl stop "$UNIT_NAME" >/dev/null 2>&1
    cp "$ENV_FILE" "${ENV_FILE}.bak"
    sed -i 's/POCVPN_API_API_PORT=.*/POCVPN_API_API_PORT=not-a-number/' "$ENV_FILE"
    systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1
    timeout 10 systemctl start "$UNIT_NAME" >/dev/null 2>&1
    local never_listened=1
    local tries=0
    while [ "$tries" -lt 6 ]; do
        ss -ltn "sport = :${API_PORT}" 2>/dev/null | grep -q "$API_PORT" && never_listened=0 && break
        sleep 0.5
        tries=$((tries + 1))
    done
    systemctl stop "$UNIT_NAME" >/dev/null 2>&1
    mv "${ENV_FILE}.bak" "$ENV_FILE"
    systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1
    systemctl start "$UNIT_NAME" >/dev/null 2>&1
    wait_for_active && wait_for_listen
    if [ "$never_listened" = "1" ]; then
        pass "M: malformed config value -> service never opens its listener (fail closed, ConfigError -> SystemExit(1) before serving)"
    else
        fail "M: service actually started listening despite malformed config"
    fi
}

test_failure_missing_token_lock() {
    mv "$TOKEN_LOCK" "${TOKEN_LOCK}.bak"
    local out status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    mv "${TOKEN_LOCK}.bak" "$TOKEN_LOCK"
    if [ "$status" = "500" ]; then
        pass "M: missing token lock -> request fails closed (500), never mistaken for 401"
    else
        fail "M: missing token lock expected 500, got $status"
    fi
}

test_failure_unreadable_token_store() {
    chmod 000 "$TOKEN_STORE"
    local out status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    chmod 640 "$TOKEN_STORE"
    if [ "$status" = "500" ]; then
        pass "M: unreadable token store -> request fails closed (500)"
    else
        fail "M: unreadable token store expected 500, got $status"
    fi
}

test_failure_missing_wrapper() {
    mv "$WRAPPER_PATH" "${WRAPPER_PATH}.bak"
    local out status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    mv "${WRAPPER_PATH}.bak" "$WRAPPER_PATH"
    if [ "$status" = "500" ]; then
        pass "M: missing privileged wrapper -> provisioning request fails closed (500), never a false success"
    else
        fail "M: missing wrapper expected 500, got $status"
    fi
}

test_failure_sudo_denied() {
    mv "$SUDOERS_FILE" "${SUDOERS_FILE}.bak"
    local out status
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status=$(echo "$out" | head -n1)
    mv "${SUDOERS_FILE}.bak" "$SUDOERS_FILE"
    if [ "$status" = "500" ]; then
        pass "M: sudo denied (no sudoers grant) -> provisioning request fails closed (500)"
    else
        fail "M: sudo-denied expected 500, got $status"
    fi
}

test_failure_helper_failure_and_timeout() {
    local out status1 status2
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"FAIL_TRIGGER_KEY_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}")
    # FAIL_TRIGGER_KEY isn't itself a valid 44-char key, so use a real one
    # and drive the failure via the fixture helper's own key match instead.
    :
    out=$(http_get_status_body "$ISSUED_TOKEN" "{\"public_key\": \"$VALID_KEY_1\"}")
    status1=$(echo "$out" | head -n1)
    # (VALID_KEY_1 already exists -> 200 existing; this call is just to
    # confirm the happy path still works before/after the fault injections
    # below, isolating any regression they might cause.)

    # --- forced non-zero exit inside the root fixture helper ---
    cp "$FIXTURE_HELPER" "${FIXTURE_HELPER}.bak"
    cat > "$FIXTURE_HELPER" <<'EOF'
#!/bin/bash
echo "synthetic forced failure" >&2
exit 1
EOF
    chmod 700 "$FIXTURE_HELPER"
    local key3="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA="
    PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" issue "$key3" >/tmp/${TEST_ID}-tok3.$$ 2>/dev/null
    local token3
    token3=$(cat /tmp/${TEST_ID}-tok3.$$); rm -f /tmp/${TEST_ID}-tok3.$$
    out=$(http_get_status_body "$token3" "{\"public_key\": \"$key3\"}")
    status2=$(echo "$out" | head -n1)
    local no_state_written_on_failure
    grep -qF "$key3" "$FIXTURE_STATE" && no_state_written_on_failure=0 || no_state_written_on_failure=1
    cp "${FIXTURE_HELPER}.bak" "$FIXTURE_HELPER"
    chmod 700 "$FIXTURE_HELPER"
    rm -f "${FIXTURE_HELPER}.bak"

    # --- timeout: helper sleeps longer than SUBPROCESS_TIMEOUT_SECONDS=3 ---
    cp "$FIXTURE_HELPER" "${FIXTURE_HELPER}.bak2"
    cat > "$FIXTURE_HELPER" <<'EOF'
#!/bin/bash
sleep 30
EOF
    chmod 700 "$FIXTURE_HELPER"
    local key4="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA="
    PYTHONPATH="$APP_DIR" python3 "$APP_DIR/tools/enrollment_tokens.py" \
        --store "$TOKEN_STORE" --lock "$TOKEN_LOCK" issue "$key4" >/tmp/${TEST_ID}-tok4.$$ 2>/dev/null
    local token4
    token4=$(cat /tmp/${TEST_ID}-tok4.$$); rm -f /tmp/${TEST_ID}-tok4.$$
    local status3
    out=$(http_get_status_body "$token4" "{\"public_key\": \"$key4\"}")
    status3=$(echo "$out" | head -n1)
    cp "${FIXTURE_HELPER}.bak2" "$FIXTURE_HELPER"
    chmod 700 "$FIXTURE_HELPER"
    rm -f "${FIXTURE_HELPER}.bak2"

    if [ "$status1" = "200" ] && [ "$status2" = "500" ] && [ "$no_state_written_on_failure" = "1" ] && [ "$status3" = "504" ]; then
        pass "M: root fixture helper failure -> 500 no false success (no state written); helper timeout -> 504"
    else
        fail "M: happy_path=$status1 helper_failure=$status2 (state_written=$([ "$no_state_written_on_failure" = "1" ] && echo no || echo yes)) timeout=$status3"
    fi
}

# ============================================================
# N: journal must never contain secrets
# ============================================================
test_journal_no_secrets() {
    local journal app_journal
    journal=$(journalctl -u "$UNIT_NAME" --no-pager -o cat 2>/dev/null)
    # sudo emits its OWN accountability line for every invocation
    # (`<user> : PWD=... ; USER=root ; COMMAND=<wrapper> <argv>`), by
    # design, as its audit trail of what was run as root - see
    # gateway/DEPLOYMENT.md "Journal secret/redaction proof" for the
    # confirmed diagnosis. It is emitted by `sudo` itself (SYSLOG_IDENTIFIER
    # sudo, not this application), lands under `journalctl -u <unit>` only
    # because the wrapper runs inside this unit's cgroup, and necessarily
    # carries the full argv - including the public key - because that IS
    # the audit record. Suppressing it would be a worse outcome (no root-
    # action audit trail), and a WireGuard/AmneziaWG public key is not
    # confidential the way a bearer token or private key is (see
    # gateway/api/handler.py's own pubkey_prefix[:8]-only logging for what
    # THIS application controls). This check therefore excludes sudo's own
    # accountability lines when scanning for the full public key
    # specifically - every other secret class is still checked against the
    # FULL, unfiltered journal, including those lines.
    app_journal=$(echo "$journal" | grep -vE '^[^ ]+ *: *PWD=.*; *USER=root *; *COMMAND=')

    local reasons=""
    echo "$journal" | grep -qF "$ISSUED_TOKEN" && reasons="$reasons plaintext-bearer-token"
    echo "$journal" | grep -qiF "Authorization: Bearer" && reasons="$reasons authorization-header"
    echo "$app_journal" | grep -qF "$VALID_KEY_1" && reasons="$reasons full-public-key-outside-sudo-audit-line"
    echo "$journal" | grep -qiF "PrivateKey" && reasons="$reasons private-key-marker"
    echo "$journal" | grep -qF '"public_key"' && reasons="$reasons raw-request-body"
    local store_contents
    store_contents=$(cat "$TOKEN_STORE" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$store_contents" ] && echo "$journal" | tr -d '[:space:]' | grep -qF "$store_contents"; then
        reasons="$reasons full-store-contents"
    fi
    if [ -z "$reasons" ]; then
        pass "N: journal contains no plaintext bearer token, Authorization header, private key marker, raw request body, or full store contents; the only place the full public key appears is sudo's own root-accountability audit line, which is expected and desirable (see comment above)"
    else
        fail "N: journal leak check matched:$reasons -- see journalctl -u $UNIT_NAME"
    fi
}

# ============================================================
# Run
# ============================================================
echo "== gateway/systemd B8B1C3 production-composition E2E harness =="
if ! preflight_ok; then
    for n in \
        "H1: first request creates a peer (201)" \
        "H2: second request is idempotent (200, same IP)" \
        "I: revoke token live, no restart, next request 401" \
        "J-succeed: required-success DAC operations" \
        "J-fail: required-failure DAC operations, hashes unchanged" \
        "F: ProtectSystem=strict writable exception + DAC both hold" \
        "K: sudo boundary under systemd (approved/unrelated/env-injection/malformed)" \
        "listener: 127.0.0.1 only" \
        "L: service restart preserves durable state" \
        "M: missing env file fails closed" \
        "M: malformed config fails closed" \
        "M: missing token lock fails closed (500)" \
        "M: unreadable token store fails closed (500)" \
        "M: missing wrapper fails closed (500)" \
        "M: sudo denied fails closed (500)" \
        "M: helper failure (500, no false success) and timeout (504)" \
        "N: journal contains no secrets" \
        ; do
        skip "$n" "$_preflight_reason"
    done
else
    setup
    if ! wait_for_active || ! wait_for_listen; then
        echo "FATAL: $UNIT_NAME did not become active+listening after setup" >&2
        systemctl status "$UNIT_NAME" --no-pager >&2 || true
        journalctl -u "$UNIT_NAME" --no-pager -n 50 >&2 || true
        FAILURES=$((FAILURES + 1))
    else
        test_e2e_first_request_created
        test_e2e_second_request_existing
        test_dac_must_succeed
        test_dac_must_fail
        test_protectsystem_and_dac_together
        test_sudo_boundary_under_systemd
        test_listener_localhost_only
        # M-tests that still need ISSUED_TOKEN ACTIVE run before it is
        # revoked below - revoking it earlier would make missing_wrapper/
        # sudo_denied/helper_failure_and_timeout's "happy path" calls
        # observe 401 (unauthorized) before ever reaching the code path
        # each of those tests actually means to exercise.
        test_failure_missing_env
        test_failure_malformed_config
        test_failure_missing_token_lock
        test_failure_unreadable_token_store
        test_failure_missing_wrapper
        test_failure_sudo_denied
        test_failure_helper_failure_and_timeout
        test_e2e_revoke_then_401_no_restart
        test_service_restart
        test_journal_no_secrets
    fi
fi

echo
echo "== results: $PASSES passed, $FAILURES failed, $SKIPPED skipped =="
[ "$FAILURES" -eq 0 ]
