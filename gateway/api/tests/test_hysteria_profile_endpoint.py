"""B46-4P - POST /v1/hysteria-profile (live route in handler.py), the
Hysteria2 config completeness group, and the loopback-only auth backend
listener, exercised end to end: provision through the real HTTP API, then
authenticate that exact secret through the real auth listener the
Hysteria2 server would call."""
import base64
import dataclasses
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import config as config_module
from api import hysteria_auth_server
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


class _AuthListener:
    def __init__(self, app_config):
        self.srv = hysteria_auth_server.build_server(app_config, port=0)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.srv.server_address[1]

    def auth(self, secret, raw=None):
        body = raw if raw is not None else json.dumps({"addr": "198.51.100.7:40000", "auth": secret, "tx": 0}).encode("utf-8")
        status, _h, resp = raw_request(
            self.port, "POST", "/auth", {"Content-Type": "application/json", "Content-Length": str(len(body))}, body,
        )
        return status, json.loads(resp)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)


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
            hysteria2_server_port=_PORT, hysteria2_sni=_SNI, hysteria2_auth_backend_port=18899,
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.auth = _AuthListener(self.app_config)
        self.addCleanup(self.auth.close)
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

    # --- response contract (must match ProvisioningClient.parseHysteria2ProfileSuccessBody) ---
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

    def test_non_json_content_type_is_415(self):
        _aid, credential = self._issue_and_bind()
        status, _h, _b = post_hysteria_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a}, content_type="text/plain",
        )
        self.assertEqual(status, 415)

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

    def test_missing_store_fails_closed_with_503(self):
        _aid, credential = self._issue_and_bind()
        os.remove(self.hy_lock)
        status, _h, body = self._provision(credential)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "hysteria_store_unavailable"})

    # --- end to end through the loopback auth backend ---
    def test_provisioned_secret_authenticates_and_rotation_invalidates_the_old_one(self):
        _aid, credential = self._issue_and_bind()
        first = json.loads(self._provision(credential)[2])["auth_secret"]
        status, resp = self.auth.auth(first)
        self.assertEqual(status, 200)
        self.assertTrue(resp["ok"])
        self.assertNotIn(first, resp["id"])

        second = json.loads(self._provision(credential)[2])["auth_secret"]
        self.assertNotEqual(first, second)
        self.assertFalse(self.auth.auth(first)[1]["ok"])
        self.assertTrue(self.auth.auth(second)[1]["ok"])

    def test_revocation_takes_effect_on_the_next_connection_without_reload(self):
        aid, credential = self._issue_and_bind()
        secret = json.loads(self._provision(credential)[2])["auth_secret"]
        self.assertTrue(self.auth.auth(secret)[1]["ok"])
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, aid)
        self.assertEqual(self.auth.auth(secret)[1], {"ok": False, "id": ""})

    def test_wrong_and_malformed_auth_are_indistinguishable(self):
        self.assertEqual(self.auth.auth("0" * 64), (200, {"ok": False, "id": ""}))
        self.assertEqual(self.auth.auth(None, raw=b"{not json"), (200, {"ok": False, "id": ""}))

    def test_auth_backend_store_failure_denies(self):
        _aid, credential = self._issue_and_bind()
        secret = json.loads(self._provision(credential)[2])["auth_secret"]
        os.remove(self.hy_lock)
        self.assertEqual(self.auth.auth(secret)[1], {"ok": False, "id": ""})

    def test_auth_backend_binds_loopback_only(self):
        self.assertEqual(self.auth.srv.server_address[0], "127.0.0.1")

    def test_auth_backend_refuses_to_start_unconfigured(self):
        unconfigured = make_app_config(self._tmp.name, self.script_path)
        with self.assertRaises(config_module.ConfigError):
            hysteria_auth_server.build_server(unconfigured, port=0)


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
            "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": "8899",
        }

    def test_unset_group_leaves_hysteria_unconfigured(self):
        cfg = config_module.load_config(env=self.env)
        self.assertEqual((cfg.hysteria2_store_path, cfg.hysteria2_server_port, cfg.hysteria2_auth_backend_port), ("", 0, 0))

    def test_full_group_loads(self):
        cfg = config_module.load_config(env={**self.env, **self.hy})
        self.assertEqual(cfg.hysteria2_server_port, _PORT)
        self.assertEqual(cfg.hysteria2_sni, _SNI)
        self.assertEqual(cfg.hysteria2_auth_backend_port, 8899)

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
        for key in ("POCVPN_API_HYSTERIA2_SERVER_PORT", "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT"):
            for bad in ("0", "70000", "abc"):
                with self.subTest(key=key, bad=bad), self.assertRaises(config_module.ConfigError):
                    config_module.load_config(env={**self.env, **self.hy, key: bad})

    def test_auth_backend_port_must_differ_from_api_port(self):
        with self.assertRaisesRegex(config_module.ConfigError, "must differ"):
            config_module.load_config(env={**self.env, **self.hy, "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": "8443"})


class HysteriaEdgeRouteTests(unittest.TestCase):
    _EDGE = os.path.join(_GATEWAY_DIR, "edge")

    def _read(self, name):
        with open(os.path.join(self._EDGE, name), encoding="utf-8") as handle:
            return handle.read()

    def _block(self, text, route):
        marker = f"location = {route} {{"
        start = text.index(marker) + len(marker)
        return text[start:text.index("\n    }", start)]

    def test_stockholm_exposes_post_only_route_to_exit_api(self):
        block = self._block(self._read("nginx-pocvpn-stockholm.conf"), "/v1/hysteria-profile")
        self.assertIn("limit_except POST", block)
        self.assertIn("proxy_pass http://127.0.0.1:8443;", block)

    def test_auth_backend_is_never_exposed_at_the_edge(self):
        for name in os.listdir(self._EDGE):
            if name.endswith(".conf"):
                with self.subTest(conf=name):
                    text = self._read(name)
                    self.assertNotIn("8899", text)
                    self.assertNotIn("location = /auth", text)

    def test_germany_does_not_route_hysteria(self):
        self.assertNotIn("/v1/hysteria-profile", self._read("nginx-pocvpn.conf"))


if __name__ == "__main__":
    unittest.main()
