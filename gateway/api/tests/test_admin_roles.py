"""Admin / viewer roles: a second secret logs in read-only."""

import json
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from _fixtures import RunningServer, make_activation_store, make_app_config, make_public_key
from _http import raw_request
from api import admin_auth
from api import config as config_module

ADMIN_PW = "a" * 32
VIEWER_PW = "v" * 32
_ID = "a" * 32


def _write_secret(directory, name, value):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(value.encode())
    return path


class AdminRoleTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = self._tmp.name
        script = os.path.join(d, "prov.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\nexit 0\n")
        self.store = os.path.join(d, "act.json")
        self.lock = self.store + ".lock"
        make_activation_store(self.store, self.lock, [("cred-one", {
            "activation_id": _ID, "status": "ACTIVE", "max_devices": 2,
            "created_at": "2026-10-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "bound_devices": [],
        })])
        os.chmod(self.store, 0o600)
        cfg = make_app_config(
            d, script,
            admin_secret_file=_write_secret(d, "admin-secret", ADMIN_PW),
            admin_viewer_secret_file=_write_secret(d, "viewer-secret", VIEWER_PW),
            activation_store_path=self.store, activation_lock_path=self.lock,
        )
        self.server = RunningServer(cfg)
        self.addCleanup(self.server.close)

    def _req(self, method, path, headers=None, body=b""):
        return raw_request(self.server.port, method, path, headers, body)

    def _login(self, password):
        payload = json.dumps({"password": password}).encode()
        status, headers, body = self._req(
            "POST", "/admin/login",
            {"Content-Type": "application/json", "Content-Length": str(len(payload))}, payload,
        )
        if status != 200:
            return status, None, None, None
        data = json.loads(body)
        sid = headers["set-cookie"].split(";")[0].split("=", 1)[1]
        return status, sid, data["csrf_token"], data["role"]

    def _mut(self, sid, csrf):
        return {
            "Content-Length": "0", "Cookie": f"pocvpn-admin-session={sid}", "X-CSRF-Token": csrf,
            "Origin": f"http://127.0.0.1:{self.server.port}",
        }

    def _json_post(self, path, sid, csrf, payload):
        body = json.dumps(payload).encode()
        h = self._mut(sid, csrf)
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(body))
        return self._req("POST", path, h, body)

    def test_logins_get_the_matching_role(self):
        self.assertEqual(self._login(ADMIN_PW)[3], "admin")
        self.assertEqual(self._login(VIEWER_PW)[3], "viewer")
        self.assertEqual(self._login("x" * 32)[0], 401)

    def test_status_reports_role(self):
        _, sid, _, _ = self._login(VIEWER_PW)
        _, _, body = self._req("GET", "/admin/status", {"Cookie": f"pocvpn-admin-session={sid}"})
        self.assertEqual(json.loads(body)["role"], "viewer")

    def test_viewer_can_read_but_not_mutate(self):
        _, sid, csrf, _ = self._login(VIEWER_PW)
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        self.assertEqual(self._req("GET", "/admin/activations", h)[0], 200)
        self.assertEqual(self._req("GET", f"/admin/activations/{_ID}", h)[0], 200)
        with open(self.store, encoding="utf-8") as fh:
            before = fh.read()
        for path, payload in [
            ("/admin/activations", {"max_devices": 1, "expires_in_days": 1}),
            (f"/admin/activations/{_ID}/extend", {"days": 5}),
            (f"/admin/activations/{_ID}/revoke", {}),
        ]:
            status, _, body = self._json_post(path, sid, csrf, payload)
            self.assertEqual((status, json.loads(body)["error"]), (403, "forbidden"), path)
        with open(self.store, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)
        self.assertFalse(os.path.exists(self.store + ".admin-audit.log"))

    def test_viewer_without_csrf_or_origin_still_fails_those_checks_first(self):
        _, sid, csrf, _ = self._login(VIEWER_PW)
        h = self._mut(sid, csrf)
        del h["X-CSRF-Token"]
        status, _, body = self._req("POST", f"/admin/activations/{_ID}/revoke", h)
        self.assertEqual((status, json.loads(body)["error"]), (400, "missing_csrf_token"))

    def test_viewer_can_log_out_and_session_dies(self):
        _, sid, csrf, _ = self._login(VIEWER_PW)
        self.assertEqual(self._req("POST", "/admin/logout", self._mut(sid, csrf))[0], 200)
        self.assertEqual(self._req("GET", "/admin/activations", {"Cookie": f"pocvpn-admin-session={sid}"})[0], 401)

    def test_audit_log_is_created_0600_and_loose_file_is_tightened(self):
        audit = self.store + ".admin-audit.log"
        _, sid, csrf, _ = self._login(ADMIN_PW)
        self.assertEqual(self._json_post(f"/admin/activations/{_ID}/extend", sid, csrf, {"days": 1})[0], 200)
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        os.chmod(audit, 0o644)
        self.assertEqual(self._json_post(f"/admin/activations/{_ID}/extend", sid, csrf, {"days": 1})[0], 200)
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        with open(audit, encoding="utf-8") as fh:
            self.assertEqual(len(fh.readlines()), 2)

    def test_admin_still_mutates_and_audit_records_role(self):
        _, sid, csrf, _ = self._login(ADMIN_PW)
        status, _, _ = self._json_post(f"/admin/activations/{_ID}/extend", sid, csrf, {"days": 5})
        self.assertEqual(status, 200)
        with open(self.store + ".admin-audit.log", encoding="utf-8") as f:
            self.assertEqual([json.loads(l)["role"] for l in f], ["admin"])


class AccountCounterResetTests(unittest.TestCase):
    """Only a verified ADMIN login clears the shared account failure counter."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = self._tmp.name
        self.auth = admin_auth.AdminAuthenticator(
            _write_secret(d, "admin", ADMIN_PW), _write_secret(d, "viewer", VIEWER_PW))
        # per_source_max=10, per_account_max=30: bring the account counter to 29.
        for src, n in (("10.0.0.1/32", 10), ("10.0.0.2/32", 10), ("10.0.0.3/32", 9)):
            for _ in range(n):
                self.auth.verify_password_and_create_session("wrong" * 4, src)

    def _wrong(self, src):
        return self.auth.verify_password_and_create_session("wrong" * 4, src)[2]

    def test_viewer_login_does_not_reset_account_counter(self):
        ok, _, _ = self.auth.verify_password_and_create_session(VIEWER_PW, "10.7.7.7/32")
        self.assertTrue(ok)
        self.assertEqual(self._wrong("10.6.6.6/32"), "unauthorized")  # 30th failure
        self.assertEqual(self._wrong("10.6.6.5/32"), "rate_limited")  # account now locked

    def test_admin_login_still_resets_account_counter(self):
        ok, _, _ = self.auth.verify_password_and_create_session(ADMIN_PW, "10.7.7.7/32")
        self.assertTrue(ok)
        self.assertEqual(self._wrong("10.6.6.6/32"), "unauthorized")
        self.assertEqual(self._wrong("10.6.6.5/32"), "unauthorized")


class AdminViewerSecretConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.d = self._tmp.name
        self.admin = _write_secret(self.d, "admin-secret", ADMIN_PW)

    def test_authenticator_rejects_identical_secrets(self):
        same = _write_secret(self.d, "same", ADMIN_PW)
        with self.assertRaises(admin_auth.ConfigError):
            admin_auth.AdminAuthenticator(self.admin, same)

    def test_authenticator_rejects_invalid_viewer_secret(self):
        short = _write_secret(self.d, "short", "tooshort")
        with self.assertRaises(admin_auth.ConfigError):
            admin_auth.AdminAuthenticator(self.admin, short)

    def test_load_config_validates_viewer_secret(self):
        base = {
            "POCVPN_API_ENDPOINT_HOST": "203.0.113.1", "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": make_public_key(0xAA),
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
            "POCVPN_API_TOKEN_STORE_PATH": os.path.join(self.d, "t.json"),
            "POCVPN_API_PROVISION_SCRIPT_PATH": "/bin/true",
            "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5", "POCVPN_API_API_PORT": "8787",
        }
        viewer = _write_secret(self.d, "viewer", VIEWER_PW)
        ok = config_module.load_config({**base, "POCVPN_API_ADMIN_SECRET_FILE": self.admin,
                                        "POCVPN_API_ADMIN_VIEWER_SECRET_FILE": viewer})
        self.assertEqual(ok.admin_viewer_secret_file, viewer)
        for env in (
            {"POCVPN_API_ADMIN_VIEWER_SECRET_FILE": viewer},  # viewer without admin
            {"POCVPN_API_ADMIN_SECRET_FILE": self.admin,
             "POCVPN_API_ADMIN_VIEWER_SECRET_FILE": _write_secret(self.d, "dup", ADMIN_PW)},
            {"POCVPN_API_ADMIN_SECRET_FILE": self.admin, "POCVPN_API_ADMIN_VIEWER_SECRET_FILE": "relative"},
        ):
            with self.assertRaises(config_module.ConfigError):
                config_module.load_config({**base, **env})


if __name__ == "__main__":
    unittest.main()
