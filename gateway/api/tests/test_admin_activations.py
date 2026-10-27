"""Admin activation (device) management endpoints: list, detail, revoke."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from _fixtures import RunningServer, make_activation_store, make_app_config, make_public_key
from _http import raw_request
from api import activations as activations_module
from api import ratelimit

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


    # --- M1: uncertain store commits ---
    def _revoke_with_error(self, exc):
        sid, csrf = self._login()
        path = f"/admin/activations/{_ID}/revoke"
        with mock.patch.object(activations_module, "revoke_activation", side_effect=exc):
            status, _, body = self._req("POST", path, self._mut_headers(sid, csrf))
        return status, json.loads(body)["error"]

    def test_uncertain_commit_has_distinct_error_code_and_audit(self):
        # StoreCommitUncertainError subclasses StoreWriteError; the handler
        # must classify it first rather than as a definite write failure.
        self.assertTrue(issubclass(
            activations_module.StoreCommitUncertainError, activations_module.StoreWriteError))
        status, code = self._revoke_with_error(activations_module.StoreCommitUncertainError("x"))
        self.assertEqual((status, code), (500, "store_commit_uncertain"))
        with open(self.store + ".admin-audit.log", encoding="utf-8") as f:
            self.assertEqual([json.loads(l)["outcome"] for l in f], ["commit_uncertain"])

    def test_definite_write_failure_keeps_existing_code(self):
        status, code = self._revoke_with_error(activations_module.StoreWriteError("x"))
        self.assertEqual((status, code), (500, "store_write_failed"))
        self.assertFalse(os.path.exists(self.store + ".admin-audit.log"))

    # --- M2: per-session rate limits ---
    def _limit(self, attr, n):
        setattr(self.server.srv, attr, ratelimit.RateLimiter(n, 60.0, clock=lambda: 0.0))

    def test_read_limit_covers_list_and_detail_without_store_reads(self):
        self._limit("admin_read_limiter", 2)
        sid, _ = self._login()
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        self.assertEqual(self._req("GET", "/admin/activations", h)[0], 200)
        self.assertEqual(self._req("GET", f"/admin/activations/{_ID}", h)[0], 200)
        with mock.patch.object(activations_module, "list_all") as la,                 mock.patch.object(activations_module, "find_by_activation_id") as fb:
            s1, _, b1 = self._req("GET", "/admin/activations", h)
            s2, _, _ = self._req("GET", f"/admin/activations/{_ID}", h)
            la.assert_not_called()
            fb.assert_not_called()
        self.assertEqual((s1, json.loads(b1)["error"], s2), (429, "rate_limited", 429))

    def test_mutation_limit_blocks_revoke_without_mutating(self):
        self._limit("admin_mutation_limiter", 1)
        sid, csrf = self._login()
        h = self._mut_headers(sid, csrf)
        self.assertEqual(self._req("POST", f"/admin/activations/{_ID2}/revoke", h)[0], 200)
        status, _, body = self._req("POST", f"/admin/activations/{_ID}/revoke", h)
        self.assertEqual((status, json.loads(body)["error"]), (429, "rate_limited"))
        with open(self.store, encoding="utf-8") as f:
            statuses = {r["activation_id"]: r["status"] for r in json.load(f).values()}
        self.assertEqual(statuses[_ID], "ACTIVE")

    def test_unauthenticated_cannot_consume_or_bypass_limits(self):
        self._limit("admin_read_limiter", 1)
        for _ in range(3):
            self.assertEqual(self._req("GET", "/admin/activations")[0], 401)
        sid, _ = self._login()
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        self.assertEqual(self._req("GET", "/admin/activations", h)[0], 200)

    def test_limits_are_per_session_and_independent_of_client_headers(self):
        self._limit("admin_read_limiter", 1)
        sid1, _ = self._login()
        sid2, _ = self._login()
        # Spoofed X-Real-IP / X-Forwarded-For must not select a fresh bucket.
        spoof = {"X-Real-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.9"}
        h1 = {"Cookie": f"pocvpn-admin-session={sid1}", **spoof}
        self.assertEqual(self._req("GET", "/admin/activations", h1)[0], 200)
        spoof2 = {"X-Real-IP": "203.0.113.10"}
        self.assertEqual(self._req("GET", "/admin/activations", {**h1, **spoof2})[0], 429)
        self.assertEqual(
            self._req("GET", "/admin/activations", {"Cookie": f"pocvpn-admin-session={sid2}"})[0], 200)

    def test_default_limits_do_not_hinder_normal_use(self):
        sid, csrf = self._login()
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        for _ in range(10):
            self.assertEqual(self._req("GET", "/admin/activations", h)[0], 200)


    # --- create / extend / list query ---
    def _post_json(self, path, sid, csrf, payload, origin=None):
        body = json.dumps(payload).encode()
        h = self._mut_headers(sid, csrf, origin)
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(body))
        return self._req("POST", path, h, body)

    def _create(self, sid, csrf, max_devices=2, days=30):
        status, headers, body = self._post_json(
            "/admin/activations", sid, csrf, {"max_devices": max_devices, "expires_in_days": days})
        self.assertEqual(status, 201)
        return headers, json.loads(body)

    def test_create_returns_credential_once_and_never_logs_it(self):
        sid, csrf = self._login()
        headers, data = self._create(sid, csrf)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(len(data["activation_id"]), 32)
        credential = data["credential"]
        self.assertTrue(len(credential) >= 20)
        # Stored only as a digest, listed without the credential, audited by id only.
        with open(self.store, encoding="utf-8") as f:
            self.assertNotIn(credential, f.read())
        with open(self.store + ".admin-audit.log", encoding="utf-8") as f:
            audit = f.read()
        self.assertNotIn(credential, audit)
        self.assertIn('"action": "create"', audit)
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        status, _, body = self._req("GET", "/admin/activations/" + data["activation_id"], h)
        self.assertEqual(status, 200)
        self.assertNotIn(credential.encode(), body)
        self.assertEqual(json.loads(body)["entitlement"], "ACTIVE")

    def test_create_requires_session_csrf_origin_and_valid_body(self):
        sid, csrf = self._login()
        status, _, _ = self._post_json("/admin/activations", "nosession", csrf, {"max_devices": 1, "expires_in_days": 1})
        self.assertEqual(status, 401)
        status, _, _ = self._post_json("/admin/activations", sid, "wrong", {"max_devices": 1, "expires_in_days": 1})
        self.assertEqual(status, 401)
        status, _, body = self._post_json(
            "/admin/activations", sid, csrf, {"max_devices": 1, "expires_in_days": 1}, origin="http://evil.example")
        self.assertEqual((status, json.loads(body)["error"]), (403, "origin_mismatch"))
        for payload, code in [
            ({"max_devices": 0, "expires_in_days": 1}, "invalid_max_devices"),
            ({"max_devices": True, "expires_in_days": 1}, "invalid_max_devices"),
            ({"max_devices": 101, "expires_in_days": 1}, "invalid_max_devices"),
            ({"max_devices": 1}, "invalid_expires_in_days"),
            ({"max_devices": 1, "expires_in_days": 0}, "invalid_expires_in_days"),
            ({"max_devices": 1, "expires_in_days": "7"}, "invalid_expires_in_days"),
            ({"max_devices": 1, "expires_in_days": 1, "status": "ACTIVE"}, "malformed_request"),
        ]:
            status, _, body = self._post_json("/admin/activations", sid, csrf, payload)
            self.assertEqual((status, json.loads(body)["error"]), (400, code), payload)
        # Nothing was created by any rejected request.
        with open(self.store, encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)), 2)

    def test_create_non_expiring_allowed_with_explicit_null(self):
        sid, csrf = self._login()
        status, _, body = self._post_json("/admin/activations", sid, csrf, {"max_devices": 1, "expires_in_days": None})
        self.assertEqual(status, 201)
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        _, _, detail = self._req("GET", "/admin/activations/" + json.loads(body)["activation_id"], h)
        self.assertIsNone(json.loads(detail)["expires_at"])

    def test_create_uncertain_commit_and_write_failure_codes(self):
        sid, csrf = self._login()
        for exc, code in [
            (activations_module.StoreCommitUncertainError("x"), "store_commit_uncertain"),
            (activations_module.StoreWriteError("x"), "store_write_failed"),
        ]:
            with mock.patch.object(activations_module, "issue_activation", side_effect=exc):
                status, _, body = self._post_json(
                    "/admin/activations", sid, csrf, {"max_devices": 1, "expires_in_days": 1})
            self.assertEqual((status, json.loads(body)["error"]), (500, code))

    def test_extend_adds_days_and_audits(self):
        sid, csrf = self._login()
        _, created = self._create(sid, csrf, days=10)
        aid = created["activation_id"]
        h = {"Cookie": f"pocvpn-admin-session={sid}"}
        _, _, before = self._req("GET", "/admin/activations/" + aid, h)
        status, _, body = self._post_json(f"/admin/activations/{aid}/extend", sid, csrf, {"days": 5})
        self.assertEqual(status, 200)
        _, _, after = self._req("GET", "/admin/activations/" + aid, h)
        from datetime import datetime
        delta = datetime.fromisoformat(json.loads(after)["expires_at"]) - datetime.fromisoformat(json.loads(before)["expires_at"])
        self.assertEqual(delta.days, 5)
        self.assertEqual(json.loads(body)["expires_at"], json.loads(after)["expires_at"])
        with open(self.store + ".admin-audit.log", encoding="utf-8") as f:
            self.assertIn('"action": "extend"', f.read())

    def test_extend_refuses_revoked_non_expiring_unknown_and_bad_days(self):
        sid, csrf = self._login()
        _, created = self._create(sid, csrf, days=10)
        aid = created["activation_id"]
        self._req("POST", f"/admin/activations/{aid}/revoke", self._mut_headers(sid, csrf) | {"Content-Length": "0"})
        status, _, body = self._post_json(f"/admin/activations/{aid}/extend", sid, csrf, {"days": 5})
        self.assertEqual((status, json.loads(body)["error"]), (409, "not_extendable_revoked"))
        status, _, body = self._post_json(f"/admin/activations/{_ID}/extend", sid, csrf, {"days": 5})
        self.assertEqual((status, json.loads(body)["error"]), (409, "not_extendable_not_expiring"))
        status, _, _ = self._post_json("/admin/activations/" + "c" * 32 + "/extend", sid, csrf, {"days": 5})
        self.assertEqual(status, 404)
        _, created2 = self._create(sid, csrf, days=10)
        for payload in ({"days": 0}, {"days": 3651}, {"days": "5"}, {"days": 1, "x": 1}, {}):
            status, _, _ = self._post_json(f"/admin/activations/{created2['activation_id']}/extend", sid, csrf, payload)
            self.assertEqual(status, 400, payload)

    def test_extend_from_now_when_already_expired(self):
        from datetime import datetime, timedelta, timezone
        past = datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat()
        rec = _record("e" * 32)
        rec["expires_at"] = past
        make_activation_store(self.store, self.lock, [("cred-exp", rec)])
        os.chmod(self.store, 0o600)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        new = activations_module.extend_activation(self.store, self.lock, "e" * 32, 7, now=now)
        self.assertEqual(datetime.fromisoformat(new), now + timedelta(days=7))

    def test_list_filters_and_pagination(self):
        sid, csrf = self._login()
        for _ in range(3):
            self._create(sid, csrf)
        h = {"Cookie": f"pocvpn-admin-session={sid}"}

        def get(query):
            status, _, body = self._req("GET", "/admin/activations" + query, h)
            return status, json.loads(body)

        status, data = get("")
        self.assertEqual((status, data["total"], len(data["activations"])), (200, 5, 5))
        status, data = get("?limit=2&offset=0")
        self.assertEqual((len(data["activations"]), data["total"], data["limit"], data["offset"]), (2, 5, 2, 0))
        status, page2 = get("?limit=2&offset=2")
        self.assertNotEqual(data["activations"][0]["activation_id"], page2["activation_id"] if "activation_id" in page2 else page2["activations"][0]["activation_id"])
        status, data = get("?status=REVOKED")
        self.assertEqual([a["activation_id"] for a in data["activations"]], [_ID2])
        status, data = get("?q=" + _ID[:6])
        self.assertEqual([a["activation_id"] for a in data["activations"]], [_ID])
        status, data = get("?q=ffffffffffffffff")
        self.assertEqual((data["total"], data["activations"]), (0, []))
        for bad in ("?limit=0", "?limit=101", "?offset=-1", "?limit=x", "?status=bogus", "?q=NOTHEX!", "?foo=1", "?limit=1&limit=2"):
            self.assertEqual(get(bad)[0], 400, bad)

    def test_new_endpoints_share_the_mutation_limiter(self):
        self._limit("admin_mutation_limiter", 1)
        sid, csrf = self._login()
        self._create(sid, csrf)
        status, _, body = self._post_json("/admin/activations", sid, csrf, {"max_devices": 1, "expires_in_days": 1})
        self.assertEqual((status, json.loads(body)["error"]), (429, "rate_limited"))
        with open(self.store, encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)), 3)


if __name__ == "__main__":
    unittest.main()
