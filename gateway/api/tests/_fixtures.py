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


def make_app_config(tmp_dir, provision_script_path, subprocess_timeout_seconds=5.0, api_port=0, sudo_path=""):
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
    )


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
