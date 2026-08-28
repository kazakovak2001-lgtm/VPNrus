#!/usr/bin/env bash
# B8B1C2: direct tests of gateway/privileged/pocvpn-provision-peer's own
# logic - argument/key validation, environment sanitization, and the
# fixed-target exec chain. No sudo, no root required, no real gateway or
# real awg0.conf touched.
#
# A TEST COPY of the tracked wrapper is used, with exactly one substituted
# constant (PROVISION_SCRIPT, pointed at a per-test stub target instead of
# /opt/pocvpn/...) - see gateway/privileged/README.md's "Testing approach"
# section for why the tracked production wrapper itself is never
# parameterized for this. The stub target records what it received
# (argv, environment, invocation count) instead of running the real
# provision-peer.sh - the real script's own behavior is already covered by
# gateway/scripts/tests/run_tests.sh; this suite is scoped to the wrapper.
#
#   bash gateway/privileged/tests/run_wrapper_tests.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER_SRC="$REPO_ROOT/gateway/privileged/pocvpn-provision-peer"
FAILURES=0
PASSES=0

fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }

VALID_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# make_fixture -> prints the fixture root dir. Builds:
#   $root/stub-target.sh   - records argv[1], env, and an invocation count
#   $root/wrapper          - test copy of the tracked wrapper, with
#                             PROVISION_SCRIPT substituted to stub-target.sh
fixture_make() {
    local root
    root=$(mktemp -d)

    # $root is baked in directly (heredoc WITHOUT quoting the delimiter,
    # so it expands here) rather than read from an environment variable at
    # runtime - the wrapper's own `env -i` (correctly) clears every
    # environment variable before this stub ever runs, including any test
    # instrumentation var, so the stub cannot rely on one to find its own
    # data directory. Baking in the path is also a stronger check: any
    # instrumentation env var this harness might have wired through would
    # have been silently wiped anyway.
    cat > "$root/stub-target.sh" <<STUB
#!/usr/bin/env bash
echo x >> "$root/call_count"
printf '%s\n' "\$1" >> "$root/captured_argv1"
printf '%s\n' "\$#" >> "$root/captured_argc"
env > "$root/captured_env.\$\$"
printf 'created\t10.77.0.2\n'
STUB
    chmod +x "$root/stub-target.sh"

    # Test-copy substitution: the ONLY line that differs from the tracked
    # wrapper is the PROVISION_SCRIPT literal - everything else is the
    # exact tracked file content, byte for byte.
    sed "s#^readonly PROVISION_SCRIPT=.*#readonly PROVISION_SCRIPT=\"$root/stub-target.sh\"#" \
        "$WRAPPER_SRC" > "$root/wrapper"
    chmod +x "$root/wrapper"

    echo "$root"
}

call_count() { cat "$1/call_count" 2>/dev/null | wc -l | tr -d ' '; }
captured_argv1_last() { tail -n1 "$1/captured_argv1" 2>/dev/null; }
captured_argc_last() { tail -n1 "$1/captured_argc" 2>/dev/null; }

run_wrapper() {
    local root=$1; shift
    POCVPN_STUB_DIR="$root" "$root/wrapper" "$@"
}

# --- 7. valid public key reaches the fixed target exactly once ---
test_valid_key_reaches_target_once() {
    local root; root=$(fixture_make)
    local out; out=$(run_wrapper "$root" "$VALID_KEY" 2>/dev/null)
    if [ "$out" = "$(printf 'created\t10.77.0.2')" ] && [ "$(call_count "$root")" = "1" ] \
        && [ "$(captured_argv1_last "$root")" = "$VALID_KEY" ]; then
        pass "valid public key reaches the fixed target exactly once"
    else
        fail "expected created/10.77.0.2 with 1 call, got out='$out' calls=$(call_count "$root")"
    fi
    rm -rf "$root"
}

# --- 8. malformed key rejected before the target is ever invoked ---
test_malformed_key_rejected() {
    local root; root=$(fixture_make)
    local rc=0
    run_wrapper "$root" "not-a-valid-key" >/dev/null 2>/dev/null || rc=$?
    if [ "$rc" -ne 0 ] && [ "$(call_count "$root")" = "0" ]; then
        pass "malformed key rejected, target never invoked"
    else
        fail "malformed key: rc=$rc calls=$(call_count "$root")"
    fi
    rm -rf "$root"
}

# --- 9. zero args rejected ---
test_zero_args_rejected() {
    local root; root=$(fixture_make)
    local rc=0
    run_wrapper "$root" >/dev/null 2>/dev/null || rc=$?
    if [ "$rc" -ne 0 ] && [ "$(call_count "$root")" = "0" ]; then
        pass "zero args rejected, target never invoked"
    else
        fail "zero args: rc=$rc calls=$(call_count "$root")"
    fi
    rm -rf "$root"
}

# --- 10. two args rejected (no label/extra argument accepted) ---
test_two_args_rejected() {
    local root; root=$(fixture_make)
    local rc=0
    run_wrapper "$root" "$VALID_KEY" "extra-label" >/dev/null 2>/dev/null || rc=$?
    if [ "$rc" -ne 0 ] && [ "$(call_count "$root")" = "0" ]; then
        pass "two args rejected, target never invoked"
    else
        fail "two args: rc=$rc calls=$(call_count "$root")"
    fi
    rm -rf "$root"
}

# --- 11. a malicious PATH entry cannot replace the executed helper/tools:
# a fake `env` binary earlier in PATH must never run instead of the real
# /usr/bin/env, since the wrapper always calls it by absolute path. ---
test_malicious_path_cannot_replace_helper() {
    local root; root=$(fixture_make)
    local evil_bin; evil_bin=$(mktemp -d)
    cat > "$evil_bin/env" <<EOF
#!/bin/bash
touch "$root/evil_env_was_used"
exit 1
EOF
    chmod +x "$evil_bin/env"

    local out rc=0
    out=$(PATH="$evil_bin:$PATH" run_wrapper "$root" "$VALID_KEY" 2>/dev/null) || rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'created\t10.77.0.2')" ] \
        && [ ! -e "$root/evil_env_was_used" ] && [ "$(call_count "$root")" = "1" ]; then
        pass "caller PATH cannot replace executed helper/tools (absolute /usr/bin/env used)"
    else
        fail "malicious PATH env: rc=$rc out='$out' evil_used=$([ -e "$root/evil_env_was_used" ] && echo yes || echo no)"
    fi
    rm -rf "$root" "$evil_bin"
}

# --- 14. a malicious helper/config-path environment variable cannot
# redirect the fixed target - the wrapper hardcodes PROVISION_SCRIPT as a
# shell literal, never reads it (or CONFIG_DIR/SERVICE_NAME/any override)
# from the environment. ---
test_env_var_cannot_redirect_target() {
    local root; root=$(fixture_make)
    local decoy; decoy=$(mktemp -d)
    cat > "$decoy/decoy-target.sh" <<EOF
#!/bin/bash
touch "$root/decoy_was_used"
printf 'created\t6.6.6.6\n'
EOF
    chmod +x "$decoy/decoy-target.sh"

    local out rc=0
    out=$(PROVISION_SCRIPT="$decoy/decoy-target.sh" \
          CONFIG_DIR="$decoy" \
          SERVICE_NAME="evil" \
          POCVPN_PROVISION_SCRIPT_PATH="$decoy/decoy-target.sh" \
          run_wrapper "$root" "$VALID_KEY" 2>/dev/null) || rc=$?
    if [ "$rc" -eq 0 ] && [ "$out" = "$(printf 'created\t10.77.0.2')" ] \
        && [ ! -e "$root/decoy_was_used" ] && [ "$(call_count "$root")" = "1" ]; then
        pass "malicious helper/config-path environment variable cannot redirect the fixed target"
    else
        fail "env-var redirect attempt: rc=$rc out='$out' decoy_used=$([ -e "$root/decoy_was_used" ] && echo yes || echo no)"
    fi
    rm -rf "$root" "$decoy"
}

# --- 15. wrapper stdout is exactly the target's machine result, nothing
# prepended/appended by the wrapper itself. ---
test_stdout_is_exactly_target_result() {
    local root; root=$(fixture_make)
    local out; out=$(run_wrapper "$root" "$VALID_KEY" 2>/dev/null)
    local line_count; line_count=$(printf '%s' "$out" | wc -l | tr -d ' ')
    if [ "$out" = "$(printf 'created\t10.77.0.2')" ] && [ "$line_count" = "0" ]; then
        pass "wrapper stdout passes through only the machine result from the target"
    else
        fail "unexpected stdout: '$out' (embedded-newline line_count=$line_count)"
    fi
    rm -rf "$root"
}

# --- 16. wrapper does not print the key on success, and does not echo
# the (attacker-supplied) key value back on rejection either. ---
test_no_unnecessary_key_diagnostics() {
    local root; root=$(fixture_make)
    local err_ok stderr_ok=1

    err_ok=$(run_wrapper "$root" "$VALID_KEY" 2>&1 >/dev/null)
    [ -z "$err_ok" ] || stderr_ok=0

    local err_bad
    err_bad=$(run_wrapper "$root" "not-a-valid-key-at-all-xyz" 2>&1 >/dev/null || true)
    echo "$err_bad" | grep -qF "not-a-valid-key-at-all-xyz" && stderr_ok=0
    echo "$err_bad" | grep -qF "$VALID_KEY" && stderr_ok=0

    if [ "$stderr_ok" = "1" ]; then
        pass "wrapper does not print key diagnostics unnecessarily"
    else
        fail "wrapper stderr leaked key material: ok_stderr='$err_ok' bad_stderr='$err_bad'"
    fi
    rm -rf "$root"
}

# --- structural: wrapper source uses #!/bin/bash, not #!/usr/bin/env bash ---
test_shebang_is_fixed_bin_bash() {
    local first_line; first_line=$(head -n1 "$WRAPPER_SRC")
    if [ "$first_line" = "#!/bin/bash" ]; then
        pass "wrapper shebang is the fixed #!/bin/bash, not #!/usr/bin/env bash"
    else
        fail "unexpected shebang: '$first_line'"
    fi
}

# --- structural: the exec line uses an absolute /usr/bin/env, not a bare
# `env` that would be subject to PATH search. ---
test_exec_uses_absolute_env() {
    if grep -qE '^\s*exec /usr/bin/env -i' "$WRAPPER_SRC"; then
        pass "wrapper execs via absolute /usr/bin/env -i"
    else
        fail "wrapper does not appear to exec via absolute /usr/bin/env -i"
    fi
}

# --- structural: no eval command anywhere in the wrapper's actual code
# (comment lines, which may discuss eval in prose, are excluded first) ---
test_no_eval() {
    if grep -vE '^\s*#' "$WRAPPER_SRC" | grep -qE '(^|[^A-Za-z0-9_])eval([^A-Za-z0-9_]|$)'; then
        fail "wrapper source contains an 'eval' command"
    else
        pass "wrapper source contains no eval command"
    fi
}

# --- structural: wrapper never sources another file (actual bash `source`/
# `.` command syntax at the start of a statement, not the English word
# "sourcing" appearing in a comment) ---
test_no_source() {
    if grep -qE '^\s*(source |\. )' "$WRAPPER_SRC"; then
        fail "wrapper source appears to source another file"
    else
        pass "wrapper source never sources another (mutable, caller-adjacent) file"
    fi
}

echo "== gateway/privileged wrapper test suite (no sudo, no root) =="
test_valid_key_reaches_target_once
test_malformed_key_rejected
test_zero_args_rejected
test_two_args_rejected
test_malicious_path_cannot_replace_helper
test_env_var_cannot_redirect_target
test_stdout_is_exactly_target_result
test_no_unnecessary_key_diagnostics
test_shebang_is_fixed_bin_bash
test_exec_uses_absolute_env
test_no_eval
test_no_source

echo
echo "== results: $PASSES passed, $FAILURES failed =="
[ "$FAILURES" -eq 0 ]
