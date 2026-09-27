"""B46-4P.1 - POST /v1/hysteria-profile (live route in handler.py) and the
Hysteria2 config completeness group, exercised through the real HTTP API.
Ported from closed PR #112 commit 3ebcd58 minus its loopback auth-listener
and nginx-route tests (both out of scope here): a provisioned secret is
instead checked against hysteria_provisioning.verify_hysteria_auth directly,
and the edge tests assert the route is NOT publicly routed."""
import base64
import contextlib
import dataclasses
import json
import logging
import os
import sys
import tempfile
import time
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import config as config_module
from api import hysteria_provisioning
from api import hysteria_store
from _fixtures import RunningServer, make_app_config, make_public_key, set_plan, write_fake_provision_script
from _http import post_activate, raw_request

_SNI = "hy2.example.test"
_PORT = 34443


def post_hysteria_profile(port, credential=None, body_obj=None, raw_body=None, content_type="application/json"):
    body = raw_body if raw_body is not None else json.dumps({} if body_obj is None else body_obj).encode("utf-8")
    headers = {"Content-Length": str(len(body))}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    return raw_request(port, "POST", "/v1/hysteria-profile", headers, body)


class _CollectingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


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
        self.hy_store = os.path.join(self._tmp.name, "hysteria2-identities.json")
        self.hy_lock = os.path.join(self._tmp.name, ".hysteria2-identities.lock")
        hysteria_store.init_store(self.hy_store, self.hy_lock)

        base = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path, activation_lock_path=self.activation_lock_path,
        )
        self.app_config = dataclasses.replace(
            base,
            hysteria2_store_path=self.hy_store, hysteria2_lock_path=self.hy_lock,
            hysteria2_server_port=_PORT, hysteria2_sni=_SNI,
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x40)
        self.key_b = make_public_key(0x41)

    def _issue_and_bind(self, max_devices=1, expires_in_days=None, key=None):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=max_devices, expires_in_days=expires_in_days,
        )
        status, _h, _b = post_activate(self.server.port, credential=credential, body_obj={"public_key": key or self.key_a})
        self.assertEqual(status, 200)
        return activation_id, credential

    def _provision(self, credential, key=None):
        return post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": key or self.key_a})

    def _verify(self, secret):
        return hysteria_provisioning.verify_hysteria_auth(
            secret, self.activation_store_path, self.activation_lock_path, self.hy_store, self.hy_lock,
        ).ok

    # --- response contract (must match PR #111's Android Hysteria2 profile parser) ---
    def test_success_returns_exactly_the_android_contract_fields(self):
        _aid, credential = self._issue_and_bind()
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(
            set(payload),
            {"profile_version", "server_address", "server_port", "auth_secret", "sni",
             "obfuscation_mode", "issued_at_epoch_seconds", "expires_at_epoch_seconds"},
        )
        self.assertEqual(payload["profile_version"], 1)
        self.assertEqual(payload["server_address"], self.app_config.endpoint_host)
        self.assertEqual(payload["server_port"], _PORT)
        self.assertEqual(payload["sni"], _SNI)
        self.assertEqual(payload["obfuscation_mode"], "NONE")
        self.assertRegex(payload["auth_secret"], r"^[0-9a-f]{64}$")
        self.assertIsNone(payload["expires_at_epoch_seconds"])
        self.assertLessEqual(abs(payload["issued_at_epoch_seconds"] - time.time()), 60)

    def test_expiring_activation_reports_its_expiry(self):
        _aid, credential = self._issue_and_bind(expires_in_days=10)
        payload = json.loads(self._provision(credential)[2])
        expected = datetime.now(timezone.utc) + timedelta(days=10)
        self.assertLessEqual(abs(payload["expires_at_epoch_seconds"] - expected.timestamp()), 120)
        self.assertGreater(payload["expires_at_epoch_seconds"], payload["issued_at_epoch_seconds"])

    def test_raw_secret_is_never_persisted(self):
        _aid, credential = self._issue_and_bind()
        secret = json.loads(self._provision(credential)[2])["auth_secret"]
        with open(self.hy_store, encoding="utf-8") as handle:
            stored = handle.read()
        self.assertNotIn(secret, stored)
        self.assertNotIn(credential, stored)

    def test_activation_credential_is_never_the_wire_secret(self):
        _aid, credential = self._issue_and_bind()
        self.assertNotEqual(json.loads(self._provision(credential)[2])["auth_secret"], credential)

    def test_raw_secret_and_credential_are_never_logged(self):
        collector = _CollectingHandler()
        api_logger = logging.getLogger("pocvpn.api")
        api_logger.addHandler(collector)
        previous_level = api_logger.level
        api_logger.setLevel(logging.DEBUG)
        self.addCleanup(api_logger.setLevel, previous_level)
        self.addCleanup(api_logger.removeHandler, collector)

        _aid, credential = self._issue_and_bind()
        secret = json.loads(self._provision(credential)[2])["auth_secret"]
        self._provision(credential, key=self.key_b)

        self.assertTrue(any("/v1/hysteria-profile" in m for m in collector.messages))
        for message in collector.messages:
            self.assertNotIn(secret, message)
            self.assertNotIn(credential, message)

    # --- provisioned secret against the existing verification function ---
    def test_provisioned_secret_verifies_and_rotation_invalidates_the_old_one(self):
        _aid, credential = self._issue_and_bind()
        first = json.loads(self._provision(credential)[2])["auth_secret"]
        self.assertTrue(self._verify(first))

        second = json.loads(self._provision(credential)[2])["auth_secret"]
        self.assertNotEqual(first, second)
        self.assertFalse(self._verify(first))
        self.assertTrue(self._verify(second))

    def test_revocation_takes_effect_on_the_next_verification(self):
        aid, credential = self._issue_and_bind()
        secret = json.loads(self._provision(credential)[2])["auth_secret"]
        self.assertTrue(self._verify(secret))
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, aid)
        self.assertFalse(self._verify(secret))

    # --- lock discipline ---
    def test_provisioning_runs_under_the_existing_per_activation_lock(self):
        _aid, credential = self._issue_and_bind()
        real_lock = activations_module.per_activation_lock
        seen = []

        @contextlib.contextmanager
        def recording_lock(store_path, digest):
            seen.append((store_path, digest))
            with real_lock(store_path, digest):
                yield

        with unittest.mock.patch.object(activations_module, "per_activation_lock", recording_lock):
            status, _h, _b = self._provision(credential)
        self.assertEqual(status, 200)
        self.assertIn((self.activation_store_path, activations_module.credential_digest(credential)), seen)

    # --- entitlement failures ---
    def test_unknown_credential_is_401(self):
        status, _h, _b = post_hysteria_profile(self.server.port, credential="nope", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)

    def test_missing_bearer_is_401(self):
        status, _h, _b = post_hysteria_profile(self.server.port, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 401)

    def test_device_not_bound_is_403(self):
        _aid, credential = activations_module.issue_activation(self.activation_store_path, self.activation_lock_path, max_devices=1)
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "device_not_bound"})

    def test_wrong_device_for_a_bound_activation_is_403(self):
        _aid, credential = self._issue_and_bind()
        status, _h, body = self._provision(credential, key=self.key_b)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "device_not_bound"})

    def test_revoked_is_403(self):
        aid, credential = self._issue_and_bind()
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, aid)
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "revoked"})

    def test_expired_is_403(self):
        _aid, credential = self._issue_and_bind(expires_in_days=1)
        digest = activations_module.credential_digest(credential)
        with open(self.activation_store_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data[digest]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with open(self.activation_store_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "expired"})

    # --- request framing ---
    def test_get_is_405(self):
        status, _h, _b = raw_request(self.server.port, "GET", "/v1/hysteria-profile", {}, b"")
        self.assertEqual(status, 405)

    def test_extra_body_field_is_rejected(self):
        _aid, credential = self._issue_and_bind()
        status, _h, _b = post_hysteria_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "reality"},
        )
        self.assertEqual(status, 400)

    def test_invalid_public_key_is_400(self):
        _aid, credential = self._issue_and_bind()
        status, _h, _b = post_hysteria_profile(self.server.port, credential=credential, body_obj={"public_key": "x"})
        self.assertEqual(status, 400)

    def test_malformed_json_is_400(self):
        _aid, credential = self._issue_and_bind()
        status, _h, _b = post_hysteria_profile(self.server.port, credential=credential, raw_body=b"{not json")
        self.assertEqual(status, 400)

    def test_non_json_content_type_is_415(self):
        _aid, credential = self._issue_and_bind()
        status, _h, _b = post_hysteria_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a}, content_type="text/plain",
        )
        self.assertEqual(status, 415)

    # --- fail-closed configuration ---
    def test_not_configured_fails_closed_with_503(self):
        unconfigured = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path, activation_lock_path=self.activation_lock_path,
        )
        server = RunningServer(unconfigured)
        self.addCleanup(server.close)
        status, _h, body = post_hysteria_profile(server.port, credential="x", body_obj={"public_key": self.key_a})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "hysteria_not_configured"})

    def test_default_app_config_leaves_hysteria_disabled(self):
        cfg = make_app_config(self._tmp.name, self.script_path)
        self.assertEqual((cfg.hysteria2_store_path, cfg.hysteria2_lock_path, cfg.hysteria2_server_port, cfg.hysteria2_sni), ("", "", 0, ""))

    def test_missing_store_fails_closed_with_503(self):
        _aid, credential = self._issue_and_bind()
        os.remove(self.hy_lock)
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "hysteria_store_unavailable"})


class HysteriaConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script = os.path.join(self._tmp.name, "provision-peer.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")
        self.env = {
            "POCVPN_API_ENDPOINT_HOST": "203.0.113.1",
            "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
            "POCVPN_API_TOKEN_STORE_PATH": os.path.join(self._tmp.name, "enrollment-tokens.json"),
            "POCVPN_API_PROVISION_SCRIPT_PATH": script,
            "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5",
            "POCVPN_API_API_PORT": "8443",
            "POCVPN_API_ACTIVATION_STORE_PATH": os.path.join(self._tmp.name, "activations.json"),
        }
        self.hy = {
            "POCVPN_API_HYSTERIA2_STORE_PATH": os.path.join(self._tmp.name, "hy.json"),
            "POCVPN_API_HYSTERIA2_LOCK_PATH": os.path.join(self._tmp.name, ".hy.lock"),
            "POCVPN_API_HYSTERIA2_SERVER_PORT": str(_PORT),
            "POCVPN_API_HYSTERIA2_SNI": _SNI,
        }

    def test_unset_group_leaves_hysteria_unconfigured(self):
        cfg = config_module.load_config(env=self.env)
        self.assertEqual((cfg.hysteria2_store_path, cfg.hysteria2_server_port, cfg.hysteria2_sni), ("", 0, ""))

    def test_full_group_loads(self):
        cfg = config_module.load_config(env={**self.env, **self.hy})
        self.assertEqual(cfg.hysteria2_server_port, _PORT)
        self.assertEqual(cfg.hysteria2_sni, _SNI)
        self.assertEqual(cfg.hysteria2_store_path, self.hy["POCVPN_API_HYSTERIA2_STORE_PATH"])

    def test_each_partial_group_is_a_startup_error(self):
        for missing in self.hy:
            env = {**self.env, **{k: v for k, v in self.hy.items() if k != missing}}
            with self.subTest(missing=missing), self.assertRaisesRegex(config_module.ConfigError, missing):
                config_module.load_config(env=env)

    def test_requires_activation_store(self):
        env = {**self.env, **self.hy}
        del env["POCVPN_API_ACTIVATION_STORE_PATH"]
        with self.assertRaisesRegex(config_module.ConfigError, "activation store"):
            config_module.load_config(env=env)

    def test_relative_store_path_rejected(self):
        with self.assertRaisesRegex(config_module.ConfigError, "absolute"):
            config_module.load_config(env={**self.env, **self.hy, "POCVPN_API_HYSTERIA2_STORE_PATH": "hy.json"})

    def test_bad_ports_rejected(self):
        for bad in ("0", "70000", "abc"):
            with self.subTest(bad=bad), self.assertRaises(config_module.ConfigError):
                config_module.load_config(env={**self.env, **self.hy, "POCVPN_API_HYSTERIA2_SERVER_PORT": bad})

    def test_implausible_sni_rejected(self):
        for bad in ("hy2 example.test", "a" * 254):
            with self.subTest(bad=bad[:20]), self.assertRaisesRegex(config_module.ConfigError, "SNI"):
                config_module.load_config(env={**self.env, **self.hy, "POCVPN_API_HYSTERIA2_SNI": bad})


class HysteriaNotPubliclyExposedTests(unittest.TestCase):
    """B46-4P.1 is git-only: no edge config may route the new path, so the
    existing catch-all keeps it unreachable from the internet."""

    _EDGE = os.path.join(_GATEWAY_DIR, "edge")

    def _read(self, name):
        with open(os.path.join(self._EDGE, name), encoding="utf-8") as handle:
            return handle.read()

    def test_no_edge_config_routes_hysteria_profile(self):
        for name in os.listdir(self._EDGE):
            if name.endswith(".conf"):
                with self.subTest(conf=name):
                    self.assertNotIn("hysteria", self._read(name).lower())

    def test_stockholm_catch_all_still_returns_404(self):
        text = self._read("nginx-pocvpn-stockholm.conf")
        self.assertRegex(text, r"location / \{\s*return 404;\s*\}")


if __name__ == "__main__":
    unittest.main()
