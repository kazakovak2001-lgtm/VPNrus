"""B46-4A - narrow tests for hysteria_auth_backend's pure request/response
adapter, independent of any real HTTP framing or store."""
import json
import os
import sys
import unittest
from dataclasses import dataclass

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import hysteria_auth_backend as backend


@dataclass(frozen=True)
class _FakeVerification:
    ok: bool
    device_id: str = ""


class ParseAuthRequestTests(unittest.TestCase):
    def test_valid_request_parses(self):
        body = json.dumps({"addr": "203.0.113.5:41234", "auth": "abc123", "tx": 4096}).encode("utf-8")
        addr, auth, tx = backend.parse_auth_request(body)
        self.assertEqual(addr, "203.0.113.5:41234")
        self.assertEqual(auth, "abc123")
        self.assertEqual(tx, 4096)

    def test_missing_field_is_rejected(self):
        body = json.dumps({"addr": "203.0.113.5:1", "auth": "abc123"}).encode("utf-8")
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(body)

    def test_extra_field_is_rejected(self):
        body = json.dumps({"addr": "a", "auth": "b", "tx": 1, "extra": "x"}).encode("utf-8")
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(body)

    def test_non_json_body_is_rejected(self):
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(b"not json")

    def test_blank_auth_is_rejected(self):
        body = json.dumps({"addr": "a", "auth": "", "tx": 1}).encode("utf-8")
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(body)

    def test_negative_tx_is_rejected(self):
        body = json.dumps({"addr": "a", "auth": "b", "tx": -1}).encode("utf-8")
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(body)

    def test_oversized_body_is_rejected(self):
        body = json.dumps({"addr": "a", "auth": "b" * 100000, "tx": 1}).encode("utf-8")
        with self.assertRaises(backend.MalformedAuthRequest):
            backend.parse_auth_request(body)


class HandleAuthRequestTests(unittest.TestCase):
    def test_valid_secret_returns_ok_true(self):
        body = json.dumps({"addr": "203.0.113.5:1", "auth": "the-real-secret", "tx": 0}).encode("utf-8")
        status, response = backend.handle_auth_request(body, verify_fn=lambda auth: _FakeVerification(ok=True, device_id="deadbeef:cafef00d"))
        self.assertEqual(status, 200)
        self.assertEqual(response, {"ok": True, "id": "deadbeef:cafef00d"})

    def test_wrong_secret_returns_ok_false(self):
        body = json.dumps({"addr": "203.0.113.5:1", "auth": "wrong", "tx": 0}).encode("utf-8")
        status, response = backend.handle_auth_request(body, verify_fn=lambda auth: _FakeVerification(ok=False))
        self.assertEqual(status, 200)
        self.assertEqual(response, {"ok": False, "id": ""})

    def test_malformed_request_fails_closed_indistinguishably_from_wrong_secret(self):
        status, response = backend.handle_auth_request(b"not json", verify_fn=lambda auth: _FakeVerification(ok=True, device_id="should-never-be-reached"))
        self.assertEqual(status, 200)
        self.assertEqual(response, {"ok": False, "id": ""})

    def test_presented_secret_is_never_echoed_in_the_response(self):
        secret = "super-secret-value-should-not-leak"
        body = json.dumps({"addr": "a", "auth": secret, "tx": 0}).encode("utf-8")
        _status, response = backend.handle_auth_request(body, verify_fn=lambda auth: _FakeVerification(ok=True, device_id="x"))
        self.assertNotIn(secret, json.dumps(response))

    def test_verify_fn_receives_exactly_the_presented_secret(self):
        received = {}

        def capture(auth):
            received["auth"] = auth
            return _FakeVerification(ok=True, device_id="x")

        body = json.dumps({"addr": "a", "auth": "exact-secret-value", "tx": 0}).encode("utf-8")
        backend.handle_auth_request(body, verify_fn=capture)
        self.assertEqual(received["auth"], "exact-secret-value")


if __name__ == "__main__":
    unittest.main()
