"""B46-4P (Option A) - HTTP-level tests for POST /internal/hysteria-auth:
the live route implementing gateway/api/hysteria_auth_backend.py's own
wire contract, served by the SAME pocvpn-api process as
/v1/hysteria-profile (never a second unit/port - see
docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md's "Auth backend
architecture" decision)."""
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

from api import activations as activations_module
from _fixtures import RunningServer, make_hysteria2_app_config, make_public_key, set_plan, write_fake_provision_script
from _http import post_activate, post_hysteria_auth, post_hysteria_profile


class HysteriaAuthEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.app_config = make_hysteria2_app_config(
            self._tmp.name, self.script_path, self.activation_store_path, self.activation_lock_path,
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x40)

    def _issue_and_activate(self, max_devices=1):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=max_devices,
        )
        status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        return activation_id, credential

    def _provision_secret(self, credential):
        status, _headers, body = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        return json.loads(body)["auth_secret"]

    def test_valid_secret_is_accepted(self):
        _activation_id, credential = self._issue_and_activate()
        secret = self._provision_secret(credential)

        status, _headers, body = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": secret, "tx": 0})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["id"])

    def test_wrong_secret_is_rejected(self):
        _activation_id, credential = self._issue_and_activate()
        self._provision_secret(credential)

        status, _headers, body = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": "not-the-real-secret", "tx": 0})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])

    def test_revoked_activation_secret_stops_authenticating(self):
        activation_id, credential = self._issue_and_activate()
        secret = self._provision_secret(credential)
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        status, _headers, body = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": secret, "tx": 0})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"], "a revoked activation's Hysteria2 secret must stop authenticating immediately, with no Hysteria2 server reload")

    def test_rotated_secret_invalidates_the_old_one(self):
        _activation_id, credential = self._issue_and_activate()
        old_secret = self._provision_secret(credential)
        new_secret = self._provision_secret(credential)  # retry-safe rotation (B46-4A Finding 2)
        self.assertNotEqual(old_secret, new_secret)

        status_old, _h1, body_old = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": old_secret, "tx": 0})
        self.assertFalse(json.loads(body_old)["ok"], "the OLD secret must no longer authenticate once rotated")

        status_new, _h2, body_new = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": new_secret, "tx": 0})
        self.assertTrue(json.loads(body_new)["ok"])

    def test_malformed_body_returns_200_ok_false_never_a_distinguishable_error(self):
        # hysteria_auth_backend's own "never give a probing client a
        # distinguishable signal between malformed and wrong-secret" rule.
        status, _headers, body = post_hysteria_auth(self.server.port, raw_body=b"not json at all")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])
        self.assertEqual(json.loads(body)["id"], "")

    def test_no_authorization_header_required(self):
        # This route authenticates via the Hysteria2 wire secret IN THE
        # BODY, never an activation-credential Bearer header - proven by
        # post_hysteria_auth's own helper never sending one and the
        # request still being processed (200, not 401).
        _activation_id, credential = self._issue_and_activate()
        secret = self._provision_secret(credential)
        status, _headers, _body = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": secret, "tx": 0})
        self.assertEqual(status, 200)

    def test_raw_secret_never_appears_in_the_durable_store(self):
        _activation_id, credential = self._issue_and_activate()
        secret = self._provision_secret(credential)
        post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": secret, "tx": 0})
        with open(self.app_config.hysteria2_store_path, "rb") as handle:
            raw_store_bytes = handle.read()
        self.assertNotIn(secret.encode("ascii"), raw_store_bytes)

    def test_not_configured_fails_closed_as_ok_false(self):
        from _fixtures import make_app_config
        unconfigured = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path, activation_lock_path=self.activation_lock_path,
        )
        server = RunningServer(unconfigured)
        self.addCleanup(server.close)
        status, _headers, body = post_hysteria_auth(server.port, body_obj={"addr": "203.0.113.9:51820", "auth": "whatever", "tx": 0})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])

    def test_unknown_device_never_bound_secret_never_existed_is_rejected(self):
        # No provisioning ever happened for this credential - the wire
        # secret space has nothing to match against at all.
        status, _headers, body = post_hysteria_auth(self.server.port, body_obj={"addr": "203.0.113.9:51820", "auth": "cd" * 32, "tx": 0})
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main()
