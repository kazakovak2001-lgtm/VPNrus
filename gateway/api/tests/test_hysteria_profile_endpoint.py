"""B46-4P - HTTP-level tests for POST /v1/hysteria-profile: the live route
that dispatches to hysteria_provisioning.provision_hysteria_identity, closing
B46-4A's own deliberately-deferred Finding 9."""
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
from _http import post_activate, post_hysteria_profile


class HysteriaProfileEndpointTests(unittest.TestCase):
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

    def test_successful_issuance_maps_to_the_android_Hysteria2Profile_fields(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)

        payload = json.loads(body)
        # Exactly the keys Android's parseHysteria2ProfileSuccessBody reads:
        # profile_version, server_address, server_port, auth_secret, sni,
        # obfuscation_mode, obfuscation_secret (issued_at/expires_at are
        # OPTIONAL there - omitted here, same as /v1/xray-profile's own
        # convention of only returning fields this gateway actually has).
        self.assertEqual(
            set(payload.keys()),
            {"profile_version", "server_address", "server_port", "auth_secret", "sni", "obfuscation_mode", "obfuscation_secret"},
        )
        self.assertEqual(payload["profile_version"], 1)
        # B46-4P (production endpoint contract fix) - server_address is
        # hysteria2_sni, a DEDICATED hostname distinct from endpoint_host
        # (still the shared bare-IP other transports use) - see
        # handler.py's own _handle_hysteria_profile_inner comment for why
        # reusing endpoint_host would break Android's own trusted-binding
        # cross-check the moment a real manifest named this dedicated
        # hostname.
        self.assertEqual(payload["server_address"], self.app_config.hysteria2_sni)
        self.assertNotEqual(payload["server_address"], self.app_config.endpoint_host)
        self.assertEqual(payload["server_port"], self.app_config.hysteria2_server_port)
        self.assertEqual(payload["sni"], self.app_config.hysteria2_sni)
        self.assertEqual(payload["obfuscation_mode"], "NONE")
        self.assertIsNone(payload["obfuscation_secret"])
        self.assertTrue(payload["auth_secret"])

    def test_retry_rotates_to_a_different_but_still_valid_secret(self):
        # B46-4A's own "retry-safe rotation, not idempotence" contract
        # (Finding 2) - proven again here at the live HTTP layer, not just
        # inside hysteria_provisioning's own unit tests.
        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body1 = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        _s2, _h2, body2 = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        secret1 = json.loads(body1)["auth_secret"]
        secret2 = json.loads(body2)["auth_secret"]
        self.assertNotEqual(secret1, secret2)

    def test_unknown_credential_is_unauthorized(self):
        status, _headers, _body = post_hysteria_profile(self.server.port, credential="not-a-real-credential", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)

    def test_device_never_activated_is_forbidden(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        status, _headers, body = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 403)
        self.assertIn(b"device_not_bound", body)

    def test_revoked_activation_is_forbidden(self):
        activation_id, credential = self._issue_and_activate()
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)
        status, _headers, body = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
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
        status, _headers, body = post_hysteria_profile(server.port, credential="whatever", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)
        self.assertIn(b"hysteria_not_configured", body)

    def test_no_raw_secret_appears_in_the_durable_store(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        auth_secret = json.loads(body)["auth_secret"]
        with open(self.app_config.hysteria2_store_path, "rb") as handle:
            raw_store_bytes = handle.read()
        self.assertNotIn(auth_secret.encode("ascii"), raw_store_bytes)

    def test_malformed_body_is_bad_request(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, _body = post_hysteria_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "unexpected": "field"},
        )
        self.assertEqual(status, 400)

    def test_missing_bearer_token_is_unauthorized(self):
        status, _headers, _body = post_hysteria_profile(self.server.port, credential=None, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
