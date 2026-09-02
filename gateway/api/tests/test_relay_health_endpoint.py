"""B26 (task B/K) - HTTP-level tests for GET /v1/relay-health: not
configured fails closed, missing/wrong/expired token fails closed with
401, and a real token minted by POST /v1/ingress-profile actually verifies
against an EXIT server provisioned with the SAME shared secret - the real
ingress->exit probe-token round trip, exercised end to end at the HTTP
layer (never faking either side)."""
import json
import os
import sys
import tempfile
import time
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import relay_probe_token as rpt
from _fixtures import (
    RunningServer,
    make_app_config,
    make_ingress_config,
    make_public_key,
    make_relay_probe_hmac_secret_file,
    set_plan,
    write_fake_provision_script,
)
from _http import get_relay_health, post_activate, post_ingress_profile


class RelayHealthNotConfiguredTests(unittest.TestCase):
    def test_relay_health_not_configured_fails_closed_with_503(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script_path = write_fake_provision_script(tmp_dir)
            app_config = make_app_config(tmp_dir, script_path)  # relay_probe_hmac_secret_file blank
            server = RunningServer(app_config)
            try:
                status, _headers, body = get_relay_health(server.port, token="whatever")
                self.assertEqual(status, 503)
                self.assertIn(b"relay_health_not_configured", body)
            finally:
                server.close()


class RelayHealthDirectTokenTests(unittest.TestCase):
    """Exercises verify() failure modes through the real HTTP handler,
    independent of a real ingress mint - a shared secret file this test
    controls directly."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.secret_path = make_relay_probe_hmac_secret_file(self._tmp.name)
        with open(self.secret_path, "rb") as handle:
            self.secret = handle.read()
        script_path = write_fake_provision_script(self._tmp.name)
        self.app_config = make_app_config(self._tmp.name, script_path, relay_probe_hmac_secret_file=self.secret_path)
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)

    def test_missing_token_is_unauthorized(self):
        status, _headers, _body = get_relay_health(self.server.port, token=None)
        self.assertEqual(status, 401)

    def test_valid_token_returns_the_bound_path_identity(self):
        token = rpt.mint(self.secret, "ingress-a:XRAY_REALITY->exit-a:XRAY_REALITY", "dev-key", int(time.time()), 300)
        status, _headers, body = get_relay_health(self.server.port, token=token)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["path"], "ingress-a:XRAY_REALITY->exit-a:XRAY_REALITY")

    def test_expired_token_is_unauthorized(self):
        token = rpt.mint(self.secret, "path-x", "dev-key", int(time.time()) - 1000, 60)
        status, _headers, _body = get_relay_health(self.server.port, token=token)
        self.assertEqual(status, 401)

    def test_token_signed_with_a_different_secret_is_unauthorized(self):
        token = rpt.mint(b"W" * 32, "path-x", "dev-key", int(time.time()), 300)
        status, _headers, _body = get_relay_health(self.server.port, token=token)
        self.assertEqual(status, 401)

    def test_no_response_leaks_the_secret_or_the_token(self):
        token = rpt.mint(self.secret, "path-x", "dev-key", int(time.time()), 300)
        status, _headers, body = get_relay_health(self.server.port, token=token)
        self.assertEqual(status, 200)
        self.assertNotIn(self.secret, body)
        self.assertNotIn(token.encode("ascii"), body)

    def test_get_only(self):
        status, _headers, _body = get_relay_health(self.server.port, token="x", method="POST")
        self.assertEqual(status, 405)


class RelayHealthRealIngressRoundTripTests(unittest.TestCase):
    """The full task-B/C contract: a token minted by a REAL POST
    /v1/ingress-profile response is verified by a REAL GET /v1/relay-health
    on a separately-configured server that only shares the secret FILE -
    proving the two roles genuinely interoperate without any other coupling."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.shared_secret_path = make_relay_probe_hmac_secret_file(self._tmp.name)

        script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.ingress_cfg = make_ingress_config(self._tmp.name, ingress_probe_hmac_secret_file=self.shared_secret_path)
        self.ingress_app_config = make_app_config(
            self._tmp.name, script_path,
            activation_store_path=self.ingress_cfg.activation_store_path,
            activation_lock_path=self.ingress_cfg.activation_lock_path,
        )

        self.plan_path = os.path.join(self._tmp.name, "ingress-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.ingress_cfg.ingress_staging_config_path
        set_plan(self.plan_path, "ACTIVATE")

        self.ingress_server = RunningServer(self.ingress_app_config, ingress_config=self.ingress_cfg)
        self.addCleanup(self.ingress_server.close)

        # A SEPARATE server process/instance standing in for the exit -
        # only the secret FILE is shared, nothing else (no shared store, no
        # in-process object reuse) - proving this is a real cross-process
        # contract, not an artifact of sharing Python objects.
        exit_app_config = make_app_config(self._tmp.name, script_path, relay_probe_hmac_secret_file=self.shared_secret_path)
        self.exit_server = RunningServer(exit_app_config)
        self.addCleanup(self.exit_server.close)

    def test_a_real_minted_probe_token_verifies_on_a_separate_exit_process(self):
        key = make_public_key(0x90)
        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        status, _headers, _body = post_activate(self.ingress_server.port, credential=credential, body_obj={"public_key": key})
        self.assertEqual(status, 200)

        status, _headers, body = post_ingress_profile(self.ingress_server.port, credential=credential, body_obj={"public_key": key})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn("probe_url", payload)
        self.assertIn("probe_token", payload)
        self.assertTrue(payload["probe_url"].startswith("https://"))
        self.assertIn("/v1/relay-health", payload["probe_url"])

        expected_path = (
            f"{self.ingress_cfg.ingress_endpoint_id}:XRAY_REALITY->"
            f"{self.ingress_cfg.ingress_exit_endpoint_id}:XRAY_REALITY"
        )

        status, _headers, body = get_relay_health(self.exit_server.port, token=payload["probe_token"])
        self.assertEqual(status, 200)
        health_payload = json.loads(body)
        self.assertEqual(health_payload["path"], expected_path)

    def test_a_token_minted_for_this_ingress_is_rejected_by_an_exit_with_a_different_secret(self):
        key = make_public_key(0x91)
        script_path = self.ingress_app_config.provision_script_path
        other_secret_path = make_relay_probe_hmac_secret_file(self._tmp.name, name="different-exit-secret.bin")
        other_exit_app_config = make_app_config(self._tmp.name, script_path, relay_probe_hmac_secret_file=other_secret_path)
        other_exit_server = RunningServer(other_exit_app_config)
        self.addCleanup(other_exit_server.close)

        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        post_activate(self.ingress_server.port, credential=credential, body_obj={"public_key": key})
        _status, _headers, body = post_ingress_profile(self.ingress_server.port, credential=credential, body_obj={"public_key": key})
        payload = json.loads(body)

        status, _headers, _body = get_relay_health(other_exit_server.port, token=payload["probe_token"])
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
