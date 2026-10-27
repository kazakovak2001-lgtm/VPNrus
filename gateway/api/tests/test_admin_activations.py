"""Admin activation (device) management endpoints: list, detail, revoke."""

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

_ID = "a" * 32
_ID2 = "b" * 32


def _record(activation_id, status="ACTIVE", devices=()):
    return {
        "activation_id": activation_id,
        "status": status,
        "max_devices": 2,
        "created_at": "2026-10-01T00:00:00Z",
        "expires_at": None,
        "bound_devices": [
            {"public_key": make_public_key(0x01), "reservation_id": "", "state": "confirmed"}
            for _ in devices
        ],
    }


class AdminActivationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = self._tmp.name
        script = os.path.join(d, "prov.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\nexit 0\n")
        secret = os.path.join(d, "admin-secret")
        with open(secret, "wb") as f:
            f.write(b"x" * 32)
        self.store = os.path.join(d, "act.json")
        self.lock = self.store + ".lock"
        make_activation_store(self.store, self.lock, [
            ("cred-one", _record(_ID, devices=[1])),
            ("cred-two", _record(_ID2, status="REVOKED")),
        ])
        os.chmod(self.store, 0o600)
        cfg = make_app_config(
            d, script, admin_secret_file=secret,
            activation_store_path=self.store, activation_lock_path=self.lock,
        )
        self.server = RunningServer(cfg)
        self.addCleanup(self.server.close)

    def _req(self, method, path, headers=None, body=b""):
        return raw_request(self.server.port, method, path, headers, body)

    def _login(self):
        payload = json.dumps({"password": "x" * 32}).encode()
        status, headers, body = self._req(
            "POST", "/admin/login",
            {"Content-Type": "application/json", "Content-Length": str(len(payload))}, payload,
        )
        self.assertEqual(status, 200)
        sid = headers["set-cookie"].split(";")[0].split("=", 1)[1]
        return sid, json.loads(body)["csrf_token"]

    def _mut_headers(self, sid, csrf, origin=None):
        return {
            "Content-Length": "0",
            "Cookie": f"pocvpn-admin-session={sid}",
            "X-CSRF-Token": csrf,
            "Origin": origin or f"http://127.0.0.1:{self.server.port}",
        }

    def test_list_requires_session(self):
        status, _, _ = self._req("GET", "/admin/activations")
        self.assertEqual(status, 401)

    def test_list_and_detail(self):
        sid, _ = self._login()
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        status, _, body = self._req("GET", "/admin/activations", h)
        self.assertEqual(status, 200)
        items = json.loads(body)["activations"]
        self.assertEqual([i["activation_id"] for i in items], [_ID, _ID2])
        self.assertEqual(items[0]["entitlement"], "ACTIVE")
        self.assertEqual(len(items[0]["devices"]), 1)
        self.assertEqual(items[1]["entitlement"], "REVOKED")
        self.assertNotIn(b"cred-one", body)
        status, _, body = self._req("GET", f"/admin/activations/{_ID}", h)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["activation_id"], _ID)
        status, _, _ = self._req("GET", "/admin/activations/" + "c" * 32, h)
        self.assertEqual(status, 404)

    def test_revoke_requires_csrf_and_origin(self):
        sid, csrf = self._login()
        path = f"/admin/activations/{_ID}/revoke"
        status, _, _ = self._req("POST", path, {"Content-Length": "0", "Cookie": f"pocvpn-admin-session={sid}"})
        self.assertEqual(status, 400)
        status, _, body = self._req("POST", path, self._mut_headers(sid, csrf, "http://evil.example"))
        self.assertEqual(status, 403)
        status, _, _ = self._req("POST", path, self._mut_headers(sid, "wrong"))
        self.assertEqual(status, 401)
        status, _, body = self._req("GET", f"/admin/activations/{_ID}", {"Cookie": f"pocvpn-admin-session={sid}"})
        self.assertEqual(json.loads(body)["status"], "ACTIVE")

    def test_revoke_and_audit(self):
        sid, csrf = self._login()
        path = f"/admin/activations/{_ID}/revoke"
        status, _, body = self._req("POST", path, self._mut_headers(sid, csrf))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "revoked")
        status, _, body = self._req("POST", path, self._mut_headers(sid, csrf))
        self.assertEqual(json.loads(body)["status"], "already_revoked")
        status, _, body = self._req("GET", f"/admin/activations/{_ID}", {"Cookie": f"pocvpn-admin-session={sid}"})
        self.assertEqual(json.loads(body)["entitlement"], "REVOKED")
        with open(self.store + ".admin-audit.log", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual([l["outcome"] for l in lines], ["revoked", "already_revoked"])
        self.assertNotIn("password", json.dumps(lines))

    def test_revoke_unknown(self):
        sid, csrf = self._login()
        status, _, _ = self._req("POST", "/admin/activations/" + "c" * 32 + "/revoke", self._mut_headers(sid, csrf))
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
