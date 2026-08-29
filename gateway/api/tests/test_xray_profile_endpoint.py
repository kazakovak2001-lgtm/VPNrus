"""B8K2 - HTTP-level tests for POST /v1/xray-profile."""
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
from _fixtures import RunningServer, make_public_key, make_xray_app_config, write_fake_provision_script
from _http import post_activate, post_xray_profile


class XrayProfileEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
        from _fixtures import set_plan
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.app_config = make_xray_app_config(
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

    def test_successful_issuance_maps_to_the_android_XrayProfile_fields(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)

        import json
        payload = json.loads(body)
        # Exactly these keys - the same set net.pocvpn.client.identity.XrayProfile
        # (Android) parses: server, serverPort, uuid, flow, serverName,
        # fingerprint, realityPublicKey, shortId - via this snake_case wire
        # shape, matching the rest of this API's existing convention.
        self.assertEqual(
            set(payload.keys()),
            {"server_address", "server_port", "uuid", "flow", "server_name", "fingerprint", "reality_public_key", "short_id"},
        )
        self.assertEqual(payload["server_port"], self.app_config.xray_server_port)
        self.assertEqual(payload["server_name"], self.app_config.xray_server_name)
        self.assertEqual(payload["fingerprint"], self.app_config.xray_fingerprint)
        self.assertEqual(payload["reality_public_key"], self.app_config.xray_reality_public_key)
        self.assertEqual(payload["short_id"], self.app_config.xray_short_id)
        self.assertRegex(payload["uuid"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_reality_private_key_never_appears_in_the_response(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        # The private key is never even part of AppConfig - this asserts
        # the wire response contains none of the RealityServerConfig
        # server-only field names either.
        self.assertNotIn(b"privateKey", body)
        self.assertNotIn(b"private_key", body)

    def test_retry_returns_the_same_uuid(self):
        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body1 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        _s2, _h2, body2 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        import json
        self.assertEqual(json.loads(body1)["uuid"], json.loads(body2)["uuid"])

    def test_unknown_credential_is_unauthorized(self):
        status, _headers, _body = post_xray_profile(self.server.port, credential="not-a-real-credential", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)

    def test_device_never_activated_is_forbidden(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 403)
        self.assertIn(b"device_not_bound", body)

    def test_revoked_activation_is_forbidden(self):
        activation_id, credential = self._issue_and_activate()
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 403)
        self.assertIn(b"revoked", body)

    def test_not_configured_fails_closed_with_503(self):
        from _fixtures import make_app_config
        unconfigured = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path, activation_lock_path=self.activation_lock_path,
        )
        server = RunningServer(unconfigured)
        self.addCleanup(server.close)
        status, _headers, _body = post_xray_profile(server.port, credential="whatever", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)


if __name__ == "__main__":
    unittest.main()
