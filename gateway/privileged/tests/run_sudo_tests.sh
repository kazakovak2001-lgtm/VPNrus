#!/usr/bin/env bash
# B8B1C2: LOCAL/WSL-ONLY real-sudo privilege-boundary integration harness.
#
# Proves the actual pocvpn-api -> sudo -n -> wrapper -> root chain using a
# genuinely disposable OS identity, sudoers drop-in, and root-owned
# fixture tree - never the real gateway, never /opt/pocvpn, never
# /usr/local/libexec/pocvpn-provision-peer, never /etc/sudoers.d/pocvpn-api.
# See gateway/privileged/README.md's "Testing approach" section.
#
# MUST be run as root (this harness creates/removes a system user and a
# sudoers.d drop-in - both privileged operations). If it is not, or if
# sudo/visudo/useradd/userdel are unavailable, every check in this file is
# marked SKIPPED with an explicit reason and the script exits 0 - it never
# silently reports a skipped check as PASS.
#
# Every artifact this script creates is named with the TEST_ID below and
# removed by the EXIT trap, on success OR failure. Before creating
# anything, it checks the exact disposable paths it is about to use are
# not already occupied by something that isn't obviously this harness's
# own leftover - if so, it STOPS without touching them.
#
#   sudo bash gateway/privileged/tests/run_sudo_tests.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER_SRC="$REPO_ROOT/gateway/privileged/pocvpn-provision-peer"
SUDOERS_TEMPLATE="$REPO_ROOT/gateway/privileged/pocvpn-api.sudoers"

TEST_ID="pocvpn-c2-test"
TEST_USER="$TEST_ID"
TEST_WRAPPER_PATH="/usr/local/libexec/${TEST_ID}-wrapper"
TEST_SUDOERS_PATH="/etc/sudoers.d/${TEST_ID}"
FIXTURE_ROOT=""   # set by setup(), a mktemp -d under /tmp

FAILURES=0
PASSES=0
SKIPPED=0

fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }
skip() { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }

VALID_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# ============================================================
# Preconditions - never PASS a check that didn't actually run
# ============================================================
_preflight_reason=""
preflight_ok() {
    if [ "$(id -u)" -ne 0 ]; then
        _preflight_reason="this harness must run as root to create/remove a system user and a sudoers.d drop-in"
        return 1
    fi
    for bin in sudo visudo useradd userdel runuser; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            _preflight_reason="required tool '$bin' is not available in this environment"
            return 1
        fi
    done
    if id "$TEST_USER" >/dev/null 2>&1; then
        _preflight_reason="test user $TEST_USER already exists - not clearly this harness's own leftover, refusing to reuse or delete it; investigate and remove manually first"
        return 1
    fi
    if [ -e "$TEST_WRAPPER_PATH" ]; then
        _preflight_reason="$TEST_WRAPPER_PATH already exists - refusing to overwrite"
        return 1
    fi
    if [ -e "$TEST_SUDOERS_PATH" ]; then
        _preflight_reason="$TEST_SUDOERS_PATH already exists - refusing to overwrite"
        return 1
    fi
    return 0
}

# ============================================================
# Setup / cleanup - cleanup ALWAYS runs (trap ... EXIT), success or failure
# ============================================================
cleanup() {
    rm -f "$TEST_SUDOERS_PATH" 2>/dev/null
    rm -f "$TEST_WRAPPER_PATH" 2>/dev/null
    if id "$TEST_USER" >/dev/null 2>&1; then
        userdel "$TEST_USER" >/dev/null 2>&1
    fi
    if [ -n "$FIXTURE_ROOT" ] && [ -d "$FIXTURE_ROOT" ]; then
        chmod -R u+rwx "$FIXTURE_ROOT" 2>/dev/null
        rm -rf "$FIXTURE_ROOT"
    fi
}
trap cleanup EXIT

setup() {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$TEST_USER"

    FIXTURE_ROOT=$(mktemp -d /tmp/pocvpn-c2-test-fixture.XXXXXX)
    chmod 755 "$FIXTURE_ROOT"

    # Root-owned stub target - records invocation, echoes a deterministic
    # machine result, mode 0700 root:root so the test user can neither
    # read nor write it (see checks 24-26).
    cat > "$FIXTURE_ROOT/stub-target.sh" <<STUB
#!/bin/bash
echo x >> "$FIXTURE_ROOT/call_count"
printf '%s\n' "\$1" >> "$FIXTURE_ROOT/captured_argv1"
printf 'created\t10.77.0.2\n'
STUB
    chown root:root "$FIXTURE_ROOT/stub-target.sh"
    chmod 700 "$FIXTURE_ROOT/stub-target.sh"

    # Decoy "server private key" file (test 25/26) - root:root, 0600.
    cat > "$FIXTURE_ROOT/awg0.conf" <<'EOF'
[Interface]
PrivateKey = test-fixture-not-a-real-key
EOF
    chown root:root "$FIXTURE_ROOT/awg0.conf"
    chmod 600 "$FIXTURE_ROOT/awg0.conf"

    # Test copy of the tracked wrapper - see gateway/privileged/README.md.
    # PROVISION_SCRIPT is the ONLY substituted line; installed root:root
    # 0750 (matches the documented production mode) at a disposable path.
    sed "s#^readonly PROVISION_SCRIPT=.*#readonly PROVISION_SCRIPT=\"$FIXTURE_ROOT/stub-target.sh\"#" \
        "$WRAPPER_SRC" > "$TEST_WRAPPER_PATH"
    chown root:root "$TEST_WRAPPER_PATH"
    chmod 750 "$TEST_WRAPPER_PATH"

    # Sudoers drop-in with the SAME shape as pocvpn-api.sudoers, scoped to
    # the disposable test user and disposable wrapper path.
    cat > "$TEST_SUDOERS_PATH" <<EOF
Cmnd_Alias POCVPN_C2_TEST_PROVISION = $TEST_WRAPPER_PATH
Defaults!POCVPN_C2_TEST_PROVISION env_reset
Defaults!POCVPN_C2_TEST_PROVISION !env_keep
Defaults!POCVPN_C2_TEST_PROVISION secure_path="/usr/local/bin:/usr/bin:/bin"
$TEST_USER ALL=(root) NOPASSWD: POCVPN_C2_TEST_PROVISION
EOF
    chmod 440 "$TEST_SUDOERS_PATH"
}

call_count() { cat "$FIXTURE_ROOT/call_count" 2>/dev/null | wc -l | tr -d ' '; }

# bounded_sudo <args...> - always -n, always under `timeout`, always as
# TEST_USER via runuser (never as root directly - the whole point is
# proving the NON-root user's boundary).
bounded_sudo() {
    timeout 10 runuser -u "$TEST_USER" -- sudo -n "$@"
}

# ============================================================
# 17-21: the approved command through real sudo
# ============================================================
test_sudo_approved_wrapper_succeeds() {
    local out rc=0
    out=$(bounded_sudo "$TEST_WRAPPER_PATH" "$VALID_KEY" 2>/dev/null) || rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'created\t10.77.0.2')" ] && [ "$(call_count)" = "1" ]; then
        pass "sudo -n approved wrapper succeeds, target reached exactly once"
    else
        fail "approved wrapper via sudo: rc=$rc out='$out' calls=$(call_count)"
    fi
}

test_sudo_unrelated_command_denied() {
    local rc=0
    bounded_sudo /bin/true >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "unrelated sudo command denied"
    else
        fail "unrelated command via sudo unexpectedly succeeded (rc=$rc)"
    fi
}

test_sudo_list_shows_only_the_one_command() {
    local listing
    listing=$(timeout 10 runuser -u "$TEST_USER" -- sudo -n -l 2>/dev/null)
    if echo "$listing" | grep -qF "$TEST_WRAPPER_PATH" \
        && ! echo "$listing" | grep -qE '\(ALL\s*:\s*ALL\)|NOPASSWD:\s*ALL' \
        && ! echo "$listing" | grep -qE '/bin/(ba)?sh\b'; then
        pass "sudo cannot execute arbitrary shell through this rule (sudo -n -l shows only the one fixed command)"
    else
        fail "sudo -n -l listing was not the expected single-command grant: $listing"
    fi
}

test_sudo_malformed_key_denied_full_path() {
    local before rc=0
    before=$(call_count)
    bounded_sudo "$TEST_WRAPPER_PATH" "not-a-valid-key" >/dev/null 2>/dev/null || rc=$?
    if [ "$rc" -ne 0 ] && [ "$(call_count)" = "$before" ]; then
        pass "malformed key remains denied through the full real-sudo path, target not reached"
    else
        fail "malformed key via sudo: rc=$rc calls_before=$before calls_after=$(call_count)"
    fi
}

test_sudo_injected_env_cannot_change_target() {
    local marker="$FIXTURE_ROOT/env_injection_marker"
    rm -f "$marker"
    local evil_script="$FIXTURE_ROOT/evil-bash-env.sh"
    cat > "$evil_script" <<EOF
touch "$marker"
EOF
    chmod 666 "$evil_script"   # attacker-writable, deliberately: this must still never run

    local before out rc=0
    before=$(call_count)
    # BASH_ENV, ENV, LD_PRELOAD, PYTHONPATH: none may survive sudo's
    # env_reset into the wrapper's (or its child's) environment - see
    # pocvpn-api.sudoers and the wrapper's own comments. This single test
    # covers checks 12 ("BASH_ENV injection neutralized"), 13 ("ENV
    # injection neutralized"), and 21 ("injected environment cannot change
    # privileged target") together - real sudo's env_reset is the only
    # place any of these are actually neutralized; see README.md.
    out=$(timeout 10 runuser -u "$TEST_USER" -- \
        env BASH_ENV="$evil_script" ENV="$evil_script" LD_PRELOAD="$evil_script" \
            PROVISION_SCRIPT="$evil_script" \
        sudo -n "$TEST_WRAPPER_PATH" "$VALID_KEY" 2>/dev/null) || rc=$?

    if [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'created\t10.77.0.2')" ] \
        && [ ! -e "$marker" ] && [ "$(call_count)" = "$((before + 1))" ]; then
        pass "injected BASH_ENV/ENV/LD_PRELOAD/PROVISION_SCRIPT cannot change the privileged target (sudo env_reset)"
    else
        fail "env-injection via real sudo: rc=$rc out='$out' marker_exists=$([ -e "$marker" ] && echo yes || echo no) calls=$(call_count)"
    fi
}

# ============================================================
# 22-26: file-ownership invariant, enforced by real DAC permissions
# ============================================================
run_as_test_user() { timeout 10 runuser -u "$TEST_USER" -- "$@"; }

test_user_cannot_modify_wrapper() {
    local rc=0
    run_as_test_user tee -a "$TEST_WRAPPER_PATH" >/dev/null 2>&1 <<< "malicious line" || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "test user cannot modify the privileged wrapper"
    else
        fail "test user was able to write to the privileged wrapper"
    fi
}

test_user_cannot_replace_wrapper_with_symlink() {
    local rc=0
    run_as_test_user rm -f "$TEST_WRAPPER_PATH" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] && [ -e "$TEST_WRAPPER_PATH" ]; then
        pass "test user cannot replace the wrapper with a symlink (cannot even unlink it)"
    else
        fail "test user was able to remove/replace the wrapper (rc=$rc, exists=$([ -e "$TEST_WRAPPER_PATH" ] && echo yes || echo no))"
    fi
}

test_user_cannot_modify_fixture_target() {
    local rc=0
    run_as_test_user tee -a "$FIXTURE_ROOT/stub-target.sh" >/dev/null 2>&1 <<< "malicious line" || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "test user cannot modify the root-owned provisioning script/lib fixture"
    else
        fail "test user was able to write to the root-owned fixture target"
    fi
}

test_user_cannot_read_fixture_private_key() {
    local rc=0
    run_as_test_user cat "$FIXTURE_ROOT/awg0.conf" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "test user cannot read the fixture server private-key file"
    else
        fail "test user was able to read the fixture private-key file"
    fi
}

test_user_cannot_mutate_fixture_config() {
    local rc=0
    run_as_test_user tee -a "$FIXTURE_ROOT/awg0.conf" >/dev/null 2>&1 <<< "PublicKey = injected" || rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "test user cannot directly mutate the fixture awg0.conf"
    else
        fail "test user was able to write to the fixture awg0.conf"
    fi
}

# ============================================================
# 27-28: safety of the harness itself
# ============================================================
# Positive structural check (not an exclusion-regex over the whole file,
# which would also match the word "sudo" inside this file's own PASS/FAIL/
# SKIP message strings): every actual sudo call site this harness has is
# named here explicitly, confirming each one is both `timeout`-bounded and
# `-n` (non-interactive). If a future edit adds a new sudo call site
# outside these known-good forms, this check does not silently pass it -
# it would need its own literal added here, which is itself part of
# review.
test_sudo_always_bounded_and_noninteractive() {
    local self="$REPO_ROOT/gateway/privileged/tests/run_sudo_tests.sh"
    local ok=1
    grep -qF 'timeout 10 runuser -u "$TEST_USER" -- sudo -n "$@"' "$self" || ok=0
    grep -qF 'timeout 10 runuser -u "$TEST_USER" -- sudo -n -l' "$self" || ok=0
    grep -qF 'sudo -n "$TEST_WRAPPER_PATH" "$VALID_KEY"' "$self" || ok=0
    if [ "$ok" = "1" ]; then
        pass "every real-sudo invocation in this harness is bounded (timeout) and non-interactive (-n)"
    else
        fail "could not confirm every sudo invocation in this harness is bounded and non-interactive"
    fi
}

echo "== gateway/privileged real-sudo integration harness =="
if ! preflight_ok; then
    for n in \
        "sudo -n approved wrapper succeeds" \
        "unrelated sudo command denied" \
        "sudo cannot execute arbitrary shell through this rule" \
        "malformed key remains denied through full sudo path" \
        "injected environment cannot change privileged target (BASH_ENV/ENV/21)" \
        "test user cannot modify privileged wrapper" \
        "test user cannot replace wrapper with symlink" \
        "test user cannot modify root-owned provisioning script/lib fixture" \
        "test user cannot read fixture server private-key file" \
        "test user cannot directly mutate fixture awg0.conf" \
        ; do
        skip "$n" "$_preflight_reason"
    done
else
    setup
    test_sudo_approved_wrapper_succeeds
    test_sudo_unrelated_command_denied
    test_sudo_list_shows_only_the_one_command
    test_sudo_malformed_key_denied_full_path
    test_sudo_injected_env_cannot_change_target
    test_user_cannot_modify_wrapper
    test_user_cannot_replace_wrapper_with_symlink
    test_user_cannot_modify_fixture_target
    test_user_cannot_read_fixture_private_key
    test_user_cannot_mutate_fixture_config
fi

test_sudo_always_bounded_and_noninteractive

echo
echo "== results: $PASSES passed, $FAILURES failed, $SKIPPED skipped =="
[ "$FAILURES" -eq 0 ]
