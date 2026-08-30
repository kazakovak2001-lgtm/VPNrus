"""B8K2 / B8K2A - HTTP-level tests for POST /v1/xray-profile, including
the activation transaction (identity + confirmed Xray activation) that
closes the false-success window."""
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
from _fixtures import RunningServer, make_public_key, make_xray_app_config, set_plan, write_fake_provision_script
from _http import post_activate, post_xray_profile


class XrayProfileEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
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

        self.xray_plan_path = os.path.join(self._tmp.name, "xray-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.xray_plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.app_config.xray_staging_config_path
        set_plan(self.xray_plan_path, "ACTIVATE")

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
        self.assertNotIn(b"privateKey", body)
        self.assertNotIn(b"private_key", body)
        with open(self.app_config.xray_reality_private_key_file, "rb") as handle:
            raw_private_key = handle.read().strip()
        self.assertNotIn(raw_private_key, body)

    def test_retry_returns_the_same_uuid(self):
        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body1 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        _s2, _h2, body2 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
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

    # --- B8K2A: the false-success window ---

    def test_validation_failure_never_returns_200(self):
        set_plan(self.xray_plan_path, "FAIL_VALIDATION")
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)
        self.assertIn(b"xray_activation_failed", body)

    def test_activation_failure_never_returns_200(self):
        set_plan(self.xray_plan_path, "FAIL_ACTIVATION_ROLLED_BACK")
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)
        self.assertIn(b"xray_activation_failed", body)

    def test_same_device_retry_after_activation_failure_reuses_the_same_uuid_not_a_new_one(self):
        _activation_id, credential = self._issue_and_activate()

        set_plan(self.xray_plan_path, "FAIL_ACTIVATION_ROLLED_BACK")
        status1, _headers1, _body1 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status1, 503)

        # Inspect the durable identity store directly - the identity must
        # have been minted and RETAINED (never rolled back) even though
        # activation failed.
        from api import xray_provisioning as xray_provisioning_module
        digest = activations_module.credential_digest(credential)
        stored = xray_provisioning_module.read_store_shared(self.app_config.xray_store_path, self.app_config.xray_lock_path)
        self.assertEqual(len(stored[digest]), 1)
        retained_uuid = stored[digest][0]["vless_uuid"]

        set_plan(self.xray_plan_path, "ACTIVATE")
        status2, _headers2, body2 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status2, 200)
        self.assertEqual(json.loads(body2)["uuid"], retained_uuid)  # same identity, not a new one

    # --- B8O2: transport="tls" ---

    def test_tls_transport_not_configured_fails_closed_with_503(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "tls"},
        )
        self.assertEqual(status, 503)
        self.assertIn(b"xray_tls_not_configured", body)

    def test_tls_transport_returns_only_tls_fields(self):
        import dataclasses
        from _fixtures import make_tls_cert_and_key_files
        cert_file, key_file = make_tls_cert_and_key_files(self._tmp.name)
        self.server.srv.config = dataclasses.replace(
            self.app_config,
            xray_tls_server_port=2053,
            xray_tls_server_name="203.0.113.1",
            xray_tls_fingerprint="chrome",
            xray_tls_cert_file=cert_file,
            xray_tls_key_file=key_file,
        )

        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "tls"},
        )
        self.assertEqual(status, 200)

        payload = json.loads(body)
        self.assertEqual(
            set(payload.keys()),
            {"server_address", "server_port", "uuid", "server_name", "fingerprint"},
        )
        self.assertEqual(payload["server_port"], 2053)
        self.assertEqual(payload["server_name"], "203.0.113.1")
        self.assertRegex(payload["uuid"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_tls_and_reality_transports_return_the_same_identity_uuid(self):
        import dataclasses
        from _fixtures import make_tls_cert_and_key_files
        cert_file, key_file = make_tls_cert_and_key_files(self._tmp.name)
        self.server.srv.config = dataclasses.replace(
            self.app_config,
            xray_tls_server_port=2053,
            xray_tls_server_name="203.0.113.1",
            xray_tls_fingerprint="chrome",
            xray_tls_cert_file=cert_file,
            xray_tls_key_file=key_file,
        )

        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body_reality = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "reality"},
        )
        _s2, _h2, body_tls = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "tls"},
        )
        self.assertEqual(json.loads(body_reality)["uuid"], json.loads(body_tls)["uuid"])

    def test_malformed_transport_value_is_bad_request(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, _body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "quic"},
        )
        self.assertEqual(status, 400)

    def test_a_second_request_while_one_is_already_active_does_not_reinvoke_the_wrapper(self):
        # Proves the "skip if unchanged" optimization: after one successful
        # activation, a plain idempotent retry must not need the wrapper to
        # run again - simulated here by making a second call unconditionally
        # fail if invoked, and asserting the retry still succeeds.
        _activation_id, credential = self._issue_and_activate()
        status1, _headers1, _body1 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status1, 200)

        set_plan(self.xray_plan_path, "FAIL_VALIDATION")  # would fail if actually invoked again
        status2, _headers2, _body2 = post_xray_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status2, 200)  # canonical state unchanged -> wrapper never re-invoked


if __name__ == "__main__":
    unittest.main()
