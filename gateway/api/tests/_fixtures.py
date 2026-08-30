"""Shared test fixtures: fake provision-peer.sh, a throwaway token store,
and a background-thread instance of the real server (bound to an
ephemeral 127.0.0.1 port - never 0.0.0.0, never a fixed port that could
collide across parallel test runs).
"""
import base64
import json
import os
import secrets
import stat
import sys
import threading

# sys.path bootstrap, NOT a relative import: this file must import cleanly
# whether it's loaded as part of the `api.tests` package (unittest
# discover -t .) or as a bare top-level module (unittest discover with no
# -t, which is how this suite's own review instructions invoke it - see
# run_tests.sh and the B8B1B final review). A relative "from .. import"
# only works in the former case, so every test/helper module in this
# directory does this same bootstrap instead of relying on package
# context that may not exist yet at import time.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import config as config_module
from api import server as server_module
from api import tokens as tokens_module

FAKE_SCRIPT_BODY = """#!/usr/bin/env bash
if [ -n "${POCVPN_FAKE_ARGV_CAPTURE:-}" ]; then
    printf '%s\\n' "$@" > "$POCVPN_FAKE_ARGV_CAPTURE"
fi
plan_file="${POCVPN_FAKE_PLAN:?POCVPN_FAKE_PLAN not set}"
read -r cmd arg1 < "$plan_file"
case "$cmd" in
    CREATED) printf 'created\\t%s\\n' "$arg1"; exit 0 ;;
    EXISTING) printf 'existing\\t%s\\n' "$arg1"; exit 0 ;;
    EXIT) exit "$arg1" ;;
    SLEEP) sleep "$arg1"; printf 'created\\t10.77.0.2\\n'; exit 0 ;;
    MALFORMED) printf 'not-the-right-format\\n'; exit 0 ;;
    EXTRA) printf 'created\\t10.77.0.2\\nextra-line\\n'; exit 0 ;;
    BADIP) printf 'created\\t999.999.999.999\\n'; exit 0 ;;
    *) exit 99 ;;
esac
"""


def write_fake_provision_script(tmp_dir):
    path = os.path.join(tmp_dir, "fake-provision-peer.sh")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(FAKE_SCRIPT_BODY)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def set_plan(plan_path, command, arg=""):
    with open(plan_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{command} {arg}\n")


def make_public_key(seed_byte=0x01):
    return base64.b64encode(bytes([seed_byte]) * 32).decode("ascii")


def make_token_store(store_path, entries, lock_path):
    """entries: iterable of (raw_token, expected_public_key, status) or
    (raw_token, expected_public_key, status, token_id) - the 3-tuple form
    auto-generates a synthetic token_id (this is a test fixture, not the
    production writer - gateway/tools/enrollment_tokens.py is the only
    real issuer). lock_path is required (not defaulted) so every call
    site is explicit about which lock file the store it's writing is
    paired with - see B8B1C1: the HTTP reader now fails closed if the
    lock file doesn't already exist, so this fixture must create it too,
    exactly like the operator CLI's `init` would.
    """
    data = {}
    for entry in entries:
        if len(entry) == 4:
            raw_token, expected_public_key, status, token_id = entry
        else:
            raw_token, expected_public_key, status = entry
            token_id = secrets.token_hex(16)
        digest = tokens_module.token_digest(raw_token)
        data[digest] = {
            "token_id": token_id,
            "expected_public_key": expected_public_key,
            "status": status,
        }
    with open(store_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    if not os.path.exists(lock_path):
        os.close(os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600))


def make_app_config(
    tmp_dir, provision_script_path, subprocess_timeout_seconds=5.0, api_port=0, sudo_path="",
    activation_store_path="", activation_lock_path="",
    xray_store_path="", xray_lock_path="", xray_server_port=0,
    xray_server_name="", xray_fingerprint="", xray_reality_public_key="",
    xray_short_id="", xray_flow="",
    xray_reality_private_key_file="", xray_staging_config_path="",
    xray_activation_lock_path="", xray_activation_last_hash_path="",
    xray_activation_wrapper_path="", xray_activation_timeout_seconds=5.0,
    xray_dest="",
    xray_tls_server_port=0, xray_tls_server_name="", xray_tls_fingerprint="",
    xray_tls_cert_file="", xray_tls_key_file="",
):
    token_store_path = os.path.join(tmp_dir, "enrollment-tokens.json")
    token_lock_path = os.path.join(tmp_dir, ".tokens.lock")
    return config_module.AppConfig(
        endpoint_host="203.0.113.1",
        endpoint_port=51820,
        gateway_public_key=make_public_key(0xAA),
        gateway_tunnel_ip="10.77.0.1",
        token_store_path=token_store_path,
        token_lock_path=token_lock_path,
        provision_script_path=provision_script_path,
        subprocess_timeout_seconds=subprocess_timeout_seconds,
        api_port=api_port,
        sudo_path=sudo_path,
        activation_store_path=activation_store_path,
        activation_lock_path=activation_lock_path,
        xray_store_path=xray_store_path,
        xray_lock_path=xray_lock_path,
        xray_server_port=xray_server_port,
        xray_server_name=xray_server_name,
        xray_fingerprint=xray_fingerprint,
        xray_reality_public_key=xray_reality_public_key,
        xray_short_id=xray_short_id,
        xray_flow=xray_flow,
        xray_reality_private_key_file=xray_reality_private_key_file,
        xray_staging_config_path=xray_staging_config_path,
        xray_activation_lock_path=xray_activation_lock_path,
        xray_activation_last_hash_path=xray_activation_last_hash_path,
        xray_activation_wrapper_path=xray_activation_wrapper_path,
        xray_activation_timeout_seconds=xray_activation_timeout_seconds,
        xray_dest=xray_dest,
        xray_tls_server_port=xray_tls_server_port,
        xray_tls_server_name=xray_tls_server_name,
        xray_tls_fingerprint=xray_tls_fingerprint,
        xray_tls_cert_file=xray_tls_cert_file,
        xray_tls_key_file=xray_tls_key_file,
    )


_FAKE_XRAY_WRAPPER_BODY = """#!/usr/bin/env bash
# Fake nova-xray-reload for tests - see _fixtures.py's write_fake_xray_wrapper.
# Takes ZERO arguments, exactly like the real wrapper - reads its plan from
# POCVPN_FAKE_XRAY_PLAN, the staged candidate config path from
# POCVPN_FAKE_XRAY_STAGING (mirrors how the real wrapper hardcodes this
# path from gateway/config/xray.env instead of taking it as an argument).
if [ "$#" -ne 0 ]; then
    echo "usage: fake nova-xray-reload (no arguments)" >&2
    exit 2
fi
plan_file="${POCVPN_FAKE_XRAY_PLAN:?POCVPN_FAKE_XRAY_PLAN not set}"
staging="${POCVPN_FAKE_XRAY_STAGING:?POCVPN_FAKE_XRAY_STAGING not set}"
read -r cmd arg1 < "$plan_file"
case "$cmd" in
    ACTIVATE)
        sha=$(sha256sum "$staging" | awk '{print $1}')
        printf 'activated\\t%s\\n' "$sha"
        exit 0
        ;;
    FAIL_VALIDATION) exit 22 ;;
    FAIL_ACTIVATION_ROLLED_BACK) exit 23 ;;
    FAIL_ACTIVATION_ROLLBACK_FAILED) exit 24 ;;
    EXIT) exit "$arg1" ;;
    *) exit 99 ;;
esac
"""


def write_fake_xray_wrapper(tmp_dir):
    path = os.path.join(tmp_dir, "fake-nova-xray-reload")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(_FAKE_XRAY_WRAPPER_BODY)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_xray_app_config(tmp_dir, provision_script_path, activation_store_path, activation_lock_path, **kwargs):
    """Convenience wrapper: a full app config with /v1/xray-profile AND
    the B8K2A activation boundary actually configured (representative,
    non-secret-real values everywhere - a REAL 43-char-shaped test key,
    never a production one, written to a throwaway file for
    xray_reality_private_key_file)."""
    xray_store_path = kwargs.pop("xray_store_path", os.path.join(tmp_dir, "xray-identities.json"))
    xray_lock_path = kwargs.pop("xray_lock_path", os.path.join(tmp_dir, ".xray-identities.lock"))
    from api import xray_provisioning as xray_provisioning_module
    xray_provisioning_module.init_store(xray_store_path, xray_lock_path)

    from api import xray_activation as xray_activation_module

    private_key_file = kwargs.pop("xray_reality_private_key_file", None)
    if private_key_file is None:
        private_key_file = os.path.join(tmp_dir, "reality-private-key.txt")
        with open(private_key_file, "w", encoding="utf-8") as handle:
            handle.write("B" * 43)

    xray_activation_lock_path = kwargs.pop("xray_activation_lock_path", os.path.join(tmp_dir, ".xray-activation.lock"))
    xray_activation_module.init_activation_lock(xray_activation_lock_path)

    wrapper_path = kwargs.pop("xray_activation_wrapper_path", None)
    if wrapper_path is None:
        wrapper_path = write_fake_xray_wrapper(tmp_dir)

    return make_app_config(
        tmp_dir, provision_script_path,
        activation_store_path=activation_store_path, activation_lock_path=activation_lock_path,
        xray_store_path=xray_store_path, xray_lock_path=xray_lock_path,
        xray_server_port=kwargs.pop("xray_server_port", 8444),
        xray_server_name=kwargs.pop("xray_server_name", "www.microsoft.com"),
        xray_fingerprint=kwargs.pop("xray_fingerprint", "chrome"),
        xray_reality_public_key=kwargs.pop("xray_reality_public_key", "A" * 43),
        xray_short_id=kwargs.pop("xray_short_id", "ab12cd34"),
        xray_flow=kwargs.pop("xray_flow", "xtls-rprx-vision"),
        xray_reality_private_key_file=private_key_file,
        xray_staging_config_path=kwargs.pop("xray_staging_config_path", os.path.join(tmp_dir, "candidate-config.json")),
        xray_activation_lock_path=xray_activation_lock_path,
        xray_activation_last_hash_path=kwargs.pop("xray_activation_last_hash_path", os.path.join(tmp_dir, ".xray-last-hash")),
        xray_activation_wrapper_path=wrapper_path,
        xray_dest=kwargs.pop("xray_dest", "www.microsoft.com:443"),
        **kwargs,
    )


def make_tls_cert_and_key_files(tmp_dir):
    """Test-only stand-ins for a real cert/key pair - xray_config_renderer
    only ever checks that these paths are absolute and validates their
    CONTENT is never this module's concern (that's xray-core's own job at
    process start, see build_tls_config's own docs)."""
    cert_file = os.path.join(tmp_dir, "tls-cert.pem")
    key_file = os.path.join(tmp_dir, "tls-key.pem")
    with open(cert_file, "w", encoding="utf-8") as handle:
        handle.write("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
    with open(key_file, "w", encoding="utf-8") as handle:
        handle.write("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
    return cert_file, key_file


def make_xray_tls_app_config(tmp_dir, provision_script_path, activation_store_path, activation_lock_path, **kwargs):
    """B8O2 - convenience wrapper: a full app config with REALITY (via
    make_xray_app_config) AND TLS/TCP both configured - representative,
    non-secret test values throughout."""
    cert_file, key_file = make_tls_cert_and_key_files(tmp_dir)
    return make_xray_app_config(
        tmp_dir, provision_script_path, activation_store_path, activation_lock_path,
        xray_tls_server_port=kwargs.pop("xray_tls_server_port", 2053),
        xray_tls_server_name=kwargs.pop("xray_tls_server_name", "203.0.113.1"),
        xray_tls_fingerprint=kwargs.pop("xray_tls_fingerprint", "chrome"),
        xray_tls_cert_file=kwargs.pop("xray_tls_cert_file", cert_file),
        xray_tls_key_file=kwargs.pop("xray_tls_key_file", key_file),
        **kwargs,
    )


def make_activation_store(store_path, lock_path, activations):
    """activations: iterable of dicts already shaped like activations.py
    records (activation_id/status/max_devices/created_at/expires_at/
    bound_devices), keyed here by credential for convenience: pass
    (raw_credential, record_dict). Test-only writer - gateway/tools/
    activation_tokens.py is the only real issuer."""
    from api import activations as activations_module

    data = {}
    for raw_credential, record in activations:
        digest = activations_module.credential_digest(raw_credential)
        data[digest] = record
    with open(store_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    if not os.path.exists(lock_path):
        os.close(os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600))


class RunningServer:
    """A real ProvisioningServer bound to 127.0.0.1:<ephemeral>, serving in
    a background thread for the duration of a test."""

    def __init__(self, app_config):
        self.app_config = app_config
        self.srv = server_module.build_server(app_config)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.srv.server_address[1]

    @property
    def host(self):
        return self.srv.server_address[0]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)
