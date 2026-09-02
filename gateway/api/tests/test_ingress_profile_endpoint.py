"""B25 (task G) - HTTP-level tests for POST /v1/ingress-profile: only the
requesting device's own credential is ever issued, a revoked/unbound
device is refused, and the response never carries the ingress private key
or the upstream relay uuid."""
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
from _fixtures import RunningServer, make_app_config, make_ingress_config, make_public_key, set_plan, write_fake_provision_script
from _http import post_activate, post_ingress_profile


class IngressProfileEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.ingress_cfg = make_ingress_config(self._tmp.name)
        self.app_config = make_app_config(self._tmp.name, script_path)

        self.plan_path = os.path.join(self._tmp.name, "ingress-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.ingress_cfg.ingress_staging_config_path
        set_plan(self.plan_path, "ACTIVATE")

        self.server = RunningServer(self.app_config, ingress_config=self.ingress_cfg)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x70)
        self.key_b = make_public_key(0x71)

    def _issue_bind_confirm(self, public_key, max_devices=1):
        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=max_devices,
        )
        status, _headers, _body = post_activate(
            self.server.port,
            credential=credential,
            body_obj={"public_key": public_key},
            # /v1/activate on this same server instance reads self.server.config
            # (the ORDINARY app_config, not the ingress one) - activations.py
            # itself is agnostic to which role issued the credential, so this
            # is the SAME real /v1/activate boundary an ingress device goes
            # through, wired to this ingress deployment's OWN activation store
            # via self.app_config.activation_store_path below.
        )
        return activation_id, credential, status

    def test_ingress_not_configured_fails_closed_with_503(self):
        server = RunningServer(self.app_config)  # no ingress_config at all
        self.addCleanup(server.close)
        status, _headers, body = post_ingress_profile(server.port, credential="whatever", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)
        self.assertIn(b"ingress_not_configured", body)

    def test_successful_issuance_returns_client_safe_ingress_fields(self):
        # Wire /v1/activate to write into THIS ingress deployment's own
        # activation store by pointing app_config at the same store path.
        self.app_config = make_app_config(
            self._tmp.name, self.app_config.provision_script_path,
            activation_store_path=self.ingress_cfg.activation_store_path,
            activation_lock_path=self.ingress_cfg.activation_lock_path,
        )
        self.server.close()
        self.server = RunningServer(self.app_config, ingress_config=self.ingress_cfg)

        activations_module.issue_activation  # noqa: B018 - just documenting the module is imported
        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)

        status, _headers, body = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["server_address"], self.ingress_cfg.ingress_endpoint_host)
        self.assertEqual(payload["server_port"], self.ingress_cfg.ingress_server_port)
        self.assertEqual(payload["reality_public_key"], self.ingress_cfg.ingress_reality_public_key)
        self.assertRegex(payload["uuid"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertNotIn("private_key", payload)
        self.assertNotIn("upstream_uuid", payload)

        # B26 (task B/C) - the real end-to-end probe coordinates.
        self.assertIn("probe_url", payload)
        self.assertIn("probe_token", payload)
        self.assertEqual(payload["probe_url"], f"https://{self.ingress_cfg.ingress_exit_probe_host}/v1/relay-health")
        self.assertGreater(len(payload["probe_token"]), 0)

        with open(self.ingress_cfg.ingress_reality_private_key_file, "rb") as handle:
            raw_private_key = handle.read().strip()
        with open(self.ingress_cfg.ingress_upstream_uuid_file, "rb") as handle:
            raw_upstream_uuid = handle.read().strip()
        with open(self.ingress_cfg.ingress_probe_hmac_secret_file, "rb") as handle:
            raw_probe_secret = handle.read().strip()
        self.assertNotIn(raw_private_key, body)
        self.assertNotIn(raw_upstream_uuid, body)
        self.assertNotIn(raw_probe_secret, body)

    def test_device_never_activated_against_this_ingress_is_forbidden(self):
        status, _headers, body = post_ingress_profile(self.server.port, credential="unknown-credential", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)

    def test_revoked_device_cannot_obtain_an_ingress_profile(self):
        self.app_config = make_app_config(
            self._tmp.name, self.app_config.provision_script_path,
            activation_store_path=self.ingress_cfg.activation_store_path,
            activation_lock_path=self.ingress_cfg.activation_lock_path,
        )
        self.server.close()
        self.server = RunningServer(self.app_config, ingress_config=self.ingress_cfg)

        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        status, _headers, body = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)

        activations_module.revoke_activation(self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, activation_id)
        status, _headers, body = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 403)
        self.assertIn(b"revoked", body)

    def test_a_different_device_receives_a_different_uuid_never_another_devices_credential(self):
        self.app_config = make_app_config(
            self._tmp.name, self.app_config.provision_script_path,
            activation_store_path=self.ingress_cfg.activation_store_path,
            activation_lock_path=self.ingress_cfg.activation_lock_path,
        )
        self.server.close()
        self.server = RunningServer(self.app_config, ingress_config=self.ingress_cfg)

        _id_a, credential_a = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        post_activate(self.server.port, credential=credential_a, body_obj={"public_key": self.key_a})
        _s_a, _h_a, body_a = post_ingress_profile(self.server.port, credential=credential_a, body_obj={"public_key": self.key_a})

        _id_b, credential_b = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        post_activate(self.server.port, credential=credential_b, body_obj={"public_key": self.key_b})
        _s_b, _h_b, body_b = post_ingress_profile(self.server.port, credential=credential_b, body_obj={"public_key": self.key_b})

        self.assertNotEqual(json.loads(body_a)["uuid"], json.loads(body_b)["uuid"])


if __name__ == "__main__":
    unittest.main()
