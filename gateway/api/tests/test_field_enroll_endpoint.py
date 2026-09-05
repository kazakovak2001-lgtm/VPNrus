"""HTTP-level tests for POST /v1/field-enroll - the Russia field-test
zero-touch enrollment endpoint. See test_field_enrollment.py for the pure
module-level tests and test_config.py for FIELD_ENROLLMENT_* env parsing.
"""
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from _fixtures import (
    RunningServer,
    make_app_config,
    make_public_key,
    set_plan,
    write_fake_provision_script,
)
from _http import post_activate, post_field_enroll


class FieldEnrollEndpointTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path
        set_plan(self.plan_path, "CREATED", "10.77.0.9")

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.index_path = os.path.join(self._tmp.name, "field-enrollment-index.json")
        self.index_lock_path = os.path.join(self._tmp.name, ".field-enrollment-index.lock")

    def _server(self, enabled=True, max_devices=5):
        app_config = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path,
            activation_lock_path=self.activation_lock_path,
            field_enrollment_enabled=enabled,
            field_enrollment_max_devices=max_devices,
            field_enrollment_index_path=self.index_path if enabled else "",
            field_enrollment_index_lock_path=self.index_lock_path if enabled else "",
        )
        server = RunningServer(app_config)
        self.addCleanup(server.close)
        return server

    def test_fresh_device_enrolls_with_no_bearer_token_and_gets_a_credential(self):
        server = self._server()
        key = make_public_key(0x01)
        status, _headers, body = post_field_enroll(server.port, body_obj={"public_key": key})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["activation_credential"])
        self.assertEqual(payload["client_tunnel_ip"], "10.77.0.9")
        self.assertEqual(payload["gateway_public_key"], server.app_config.gateway_public_key)
        self.assertEqual(payload["endpoint_host"], server.app_config.endpoint_host)

    def test_disabled_by_default_fails_closed(self):
        server = self._server(enabled=False)
        key = make_public_key(0x02)
        status, _headers, _body = post_field_enroll(server.port, body_obj={"public_key": key})
        self.assertEqual(status, 503)

    def test_the_returned_credential_actually_authorizes_v1_activate(self):
        """Proves the field-enrolled credential is a REAL activation
        credential - not a distinct/parallel token type - by using it
        against the ordinary POST /v1/activate endpoint directly."""
        server = self._server()
        key = make_public_key(0x03)
        status, _headers, body = post_field_enroll(server.port, body_obj={"public_key": key})
        self.assertEqual(status, 200)
        credential = json.loads(body)["activation_credential"]

        status2, _headers2, body2 = post_activate(server.port, credential=credential, body_obj={"public_key": key})
        self.assertEqual(status2, 200)
        self.assertEqual(json.loads(body2)["client_tunnel_ip"], "10.77.0.9")

    def test_two_devices_never_receive_the_same_credential(self):
        server = self._server()
        _s1, _h1, b1 = post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x10)})
        _s2, _h2, b2 = post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x11)})
        self.assertNotEqual(json.loads(b1)["activation_credential"], json.loads(b2)["activation_credential"])

    def test_repeat_enrollment_for_the_same_public_key_is_idempotent(self):
        server = self._server()
        key = make_public_key(0x20)
        _s1, _h1, b1 = post_field_enroll(server.port, body_obj={"public_key": key})
        _s2, _h2, b2 = post_field_enroll(server.port, body_obj={"public_key": key})
        self.assertEqual(json.loads(b1)["activation_credential"], json.loads(b2)["activation_credential"])

    def test_device_cap_reached_returns_403_and_fails_closed(self):
        server = self._server(max_devices=1)
        post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x30)})
        status, _headers, body = post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x31)})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"], "device_limit_reached")

    def test_per_key_rate_limit_enforced(self):
        server = self._server()
        key = make_public_key(0x40)
        statuses = []
        for _ in range(6):
            status, _headers, _body = post_field_enroll(server.port, body_obj={"public_key": key})
            statuses.append(status)
        self.assertIn(429, statuses)

    def test_global_rate_limit_enforced_across_distinct_public_keys(self):
        """Round-2 review fix (cap exhaustion) - a burst of requests using
        a DIFFERENT public key each time (the per-key limiter cannot help
        here at all) must still eventually be throttled by the endpoint's
        own global limiter."""
        server = self._server(max_devices=100)  # cap set high so DEVICE_CAP_REACHED never masks the rate-limit assertion
        statuses = []
        for seed in range(20):
            status, _headers, _body = post_field_enroll(server.port, body_obj={"public_key": make_public_key(seed)})
            statuses.append(status)
        self.assertIn(429, statuses)

    def test_malformed_public_key_is_rejected(self):
        server = self._server()
        status, _headers, _body = post_field_enroll(server.port, body_obj={"public_key": "not-a-key"})
        self.assertEqual(status, 400)

    def test_no_bearer_token_is_required_or_accepted_as_input(self):
        """A request carrying an Authorization header must still succeed
        (the header is simply ignored - this endpoint never reads it) -
        proving the endpoint's own authority comes from the public key
        alone, never from a client-supplied credential."""
        server = self._server()
        key = make_public_key(0x50)
        status, _headers, body = post_field_enroll(
            server.port, body_obj={"public_key": key}, extra_headers={"Authorization": "Bearer whatever-junk"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["activation_credential"])

    def test_credential_never_appears_in_the_error_response_for_a_cap_failure(self):
        server = self._server(max_devices=1)
        post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x60)})
        _status, _headers, body = post_field_enroll(server.port, body_obj={"public_key": make_public_key(0x61)})
        self.assertNotIn("activation_credential", json.loads(body))


if __name__ == "__main__":
    unittest.main()
