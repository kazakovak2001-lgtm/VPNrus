"""B46-4P.2 - hysteria_auth_server.py (loopback-only Hysteria2 auth backend
listener) and POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT validation. Every
server here binds 127.0.0.1 on an ephemeral or free port; nothing is
deployed and no public listener is ever opened."""
import base64
import dataclasses
import inspect
import ipaddress
import json
import logging
import os
import socket
import sys
import tempfile
import threading
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
from api import hysteria_auth_backend
from api import hysteria_auth_server
from api import hysteria_provisioning
from api import hysteria_store
from _fixtures import make_app_config, make_public_key, write_fake_provision_script
from _http import raw_request

_SNI = "hy2.example.test"


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _CollectingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class _AuthServerTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
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
            hysteria2_server_port=34443, hysteria2_sni=_SNI,
            hysteria2_auth_backend_port=_free_loopback_port(),
        )
        self.key_a = make_public_key(0x50)
        self.key_b = make_public_key(0x51)

        self.log = _CollectingHandler()
        auth_logger = logging.getLogger("pocvpn.hysteria_auth")
        previous_level = auth_logger.level
        auth_logger.setLevel(logging.DEBUG)
        auth_logger.addHandler(self.log)
        self.addCleanup(auth_logger.setLevel, previous_level)
        self.addCleanup(auth_logger.removeHandler, self.log)

    def _start(self, app_config=None, port=0):
        srv = hysteria_auth_server.build_server(app_config or self.app_config, port=port)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        def close():
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=5)

        self.addCleanup(close)
        return srv

    def _issue_bound_and_provisioned(self, key=None, expires_in_days=None):
        key = key or self.key_a
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1, expires_in_days=expires_in_days,
        )
        decision = activations_module.decide_and_bind(credential, key, self.activation_store_path, self.activation_lock_path)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        activations_module.finalize_reservation(credential, key, self.activation_store_path, self.activation_lock_path)
        result = hysteria_provisioning.provision_hysteria_identity(
            credential, key,
            self.activation_store_path, self.activation_lock_path, self.hy_store, self.hy_lock,
        )
        self.assertEqual(result.outcome, hysteria_provisioning.ISSUED)
        return activation_id, credential, result.auth_secret

    def _mutate_activation(self, credential, mutate):
        digest = activations_module.credential_digest(credential)
        with open(self.activation_store_path, encoding="utf-8") as handle:
            data = json.load(handle)
        mutate(data[digest])
        with open(self.activation_store_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    @staticmethod
    def _auth(srv, secret=None, raw=None, path="/auth"):
        body = raw if raw is not None else json.dumps({"addr": "198.51.100.7:40000", "auth": secret, "tx": 0}).encode("utf-8")
        status, _headers, resp = raw_request(
            srv.server_address[1], "POST", path,
            {"Content-Type": "application/json", "Content-Length": str(len(body))}, body,
        )
        return status, resp


class LoopbackBindingTests(_AuthServerTestBase):
    def test_bind_host_constant_is_loopback(self):
        self.assertEqual(hysteria_auth_server._BIND_HOST, "127.0.0.1")
        self.assertTrue(ipaddress.ip_address(hysteria_auth_server._BIND_HOST).is_loopback)

    def test_running_server_is_bound_to_loopback(self):
        srv = self._start()
        self.assertEqual(srv.server_address[0], "127.0.0.1")
        self.assertTrue(ipaddress.ip_address(srv.server_address[0]).is_loopback)

    def test_server_uses_the_configured_port(self):
        srv = self._start(port=None)
        self.assertEqual(srv.server_address, ("127.0.0.1", self.app_config.hysteria2_auth_backend_port))

    def test_socket_bind_is_never_called_with_a_non_loopback_address(self):
        bound = []
        real_bind = socket.socket.bind

        def recording_bind(sock, address):
            bound.append(address)
            return real_bind(sock, address)

        with unittest.mock.patch.object(socket.socket, "bind", recording_bind):
            srv = hysteria_auth_server.build_server(self.app_config, port=0)
        srv.server_close()
        self.assertTrue(bound)
        for address in bound:
            self.assertNotIn(address[0], ("0.0.0.0", "", "::"))
            self.assertTrue(ipaddress.ip_address(address[0]).is_loopback, address)

    def test_no_host_is_configurable(self):
        self.assertEqual(list(inspect.signature(hysteria_auth_server.build_server).parameters), ["app_config", "port"])
        field_names = {f.name for f in dataclasses.fields(config_module.AppConfig)}
        self.assertFalse(any("hysteria" in name and ("host" in name or "bind" in name) for name in field_names))

    def test_refuses_to_start_when_auth_port_is_not_configured(self):
        with self.assertRaises(config_module.ConfigError):
            hysteria_auth_server.build_server(dataclasses.replace(self.app_config, hysteria2_auth_backend_port=0))

    def test_refuses_to_start_when_hysteria_group_is_not_configured(self):
        unconfigured = make_app_config(self._tmp.name, self.script_path)
        with self.assertRaises(config_module.ConfigError):
            hysteria_auth_server.build_server(dataclasses.replace(unconfigured, hysteria2_auth_backend_port=18899))


class AuthContractTests(_AuthServerTestBase):
    def test_valid_secret_is_accepted(self):
        _aid, _credential, secret = self._issue_bound_and_provisioned()
        status, resp = self._auth(self._start(), secret)
        self.assertEqual(status, 200)
        payload = json.loads(resp)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["id"])

    def test_unknown_secret_is_rejected(self):
        self._issue_bound_and_provisioned()
        status, resp = self._auth(self._start(), "0" * 64)
        self.assertEqual((status, json.loads(resp)), (200, {"ok": False, "id": ""}))

    def test_revoked_activation_is_rejected_without_restart(self):
        aid, _credential, secret = self._issue_bound_and_provisioned()
        srv = self._start()
        self.assertTrue(json.loads(self._auth(srv, secret)[1])["ok"])
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, aid)
        self.assertEqual(json.loads(self._auth(srv, secret)[1]), {"ok": False, "id": ""})

    def test_expired_activation_is_rejected(self):
        _aid, credential, secret = self._issue_bound_and_provisioned(expires_in_days=1)
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self._mutate_activation(credential, lambda record: record.__setitem__("expires_at", past))
        self.assertEqual(json.loads(self._auth(self._start(), secret)[1]), {"ok": False, "id": ""})

    def test_secret_whose_device_is_no_longer_bound_is_rejected(self):
        _aid, credential, secret = self._issue_bound_and_provisioned()

        def rebind_to_other_device(record):
            for device in record["bound_devices"]:
                device["public_key"] = self.key_b

        self._mutate_activation(credential, rebind_to_other_device)
        self.assertEqual(json.loads(self._auth(self._start(), secret)[1]), {"ok": False, "id": ""})

    def test_rotated_old_secret_is_rejected(self):
        _aid, credential, first = self._issue_bound_and_provisioned()
        second = hysteria_provisioning.provision_hysteria_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path, self.hy_store, self.hy_lock,
        ).auth_secret
        srv = self._start()
        self.assertFalse(json.loads(self._auth(srv, first)[1])["ok"])
        self.assertTrue(json.loads(self._auth(srv, second)[1])["ok"])

    def test_malformed_and_oversized_requests_fail_closed_like_a_wrong_secret(self):
        srv = self._start()
        denied = {"ok": False, "id": ""}
        self.assertEqual(json.loads(self._auth(srv, raw=b"{not json")[1]), denied)
        self.assertEqual(json.loads(self._auth(srv, raw=b"x" * (hysteria_auth_backend._MAX_BODY_BYTES + 1))[1]), denied)

    def test_store_failure_denies(self):
        _aid, _credential, secret = self._issue_bound_and_provisioned()
        srv = self._start()
        os.remove(self.hy_lock)
        self.assertEqual(json.loads(self._auth(srv, secret)[1]), {"ok": False, "id": ""})
        self.assertIn("auth_backend_error exc_type=HysteriaStoreError", self.log.messages)

    def test_unknown_path_is_404_and_get_is_405(self):
        srv = self._start()
        self.assertEqual(self._auth(srv, "x", path="/other")[0], 404)
        status, _h, _b = raw_request(srv.server_address[1], "GET", "/auth", {}, b"")
        self.assertEqual(status, 405)


class SecretHandlingTests(_AuthServerTestBase):
    def test_secret_and_credential_never_appear_in_logs(self):
        aid, credential, secret = self._issue_bound_and_provisioned()
        srv = self._start()
        self._auth(srv, secret)
        self._auth(srv, secret + "0")
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, aid)
        self._auth(srv, secret)
        os.remove(self.hy_lock)
        self._auth(srv, secret)

        self.assertGreaterEqual(len(self.log.messages), 4)
        for message in self.log.messages:
            self.assertNotIn(secret, message)
            self.assertNotIn(credential, message)
            self.assertNotIn("198.51.100.7", message)

    def test_response_never_echoes_the_secret(self):
        _aid, _credential, secret = self._issue_bound_and_provisioned()
        srv = self._start()
        for presented in (secret, "f" * 64):
            self.assertNotIn(presented.encode("ascii"), self._auth(srv, presented)[1])

    def test_secret_is_not_stored_in_plaintext(self):
        _aid, credential, secret = self._issue_bound_and_provisioned()
        with open(self.hy_store, encoding="utf-8") as handle:
            stored = handle.read()
        self.assertNotIn(secret, stored)
        self.assertNotIn(credential, stored)

    def test_secret_never_appears_in_exception_messages(self):
        marker = "S3CRET" * 20
        with self.assertRaises(hysteria_auth_backend.MalformedAuthRequest) as ctx:
            hysteria_auth_backend.parse_auth_request(
                json.dumps({"addr": "198.51.100.7:1", "auth": marker, "tx": -1}).encode("utf-8"),
            )
        self.assertNotIn(marker, str(ctx.exception))

        os.remove(self.hy_lock)
        with self.assertRaises(hysteria_provisioning.HysteriaStoreError) as ctx:
            hysteria_provisioning.verify_hysteria_auth(
                marker, self.activation_store_path, self.activation_lock_path, self.hy_store, self.hy_lock,
            )
        self.assertNotIn(marker, str(ctx.exception))

    def test_default_request_log_is_suppressed(self):
        _aid, _credential, secret = self._issue_bound_and_provisioned()
        srv = self._start()
        with unittest.mock.patch("sys.stderr") as fake_stderr:
            self._auth(srv, secret)
        written = "".join(str(call.args[0]) for call in fake_stderr.write.call_args_list if call.args)
        self.assertNotIn(secret, written)
        self.assertNotIn("POST /auth", written)


class AuthBackendPortConfigTests(unittest.TestCase):
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
            "POCVPN_API_HYSTERIA2_STORE_PATH": os.path.join(self._tmp.name, "hy.json"),
            "POCVPN_API_HYSTERIA2_LOCK_PATH": os.path.join(self._tmp.name, ".hy.lock"),
            "POCVPN_API_HYSTERIA2_SERVER_PORT": "34443",
            "POCVPN_API_HYSTERIA2_SNI": _SNI,
        }

    def test_unset_defaults_to_disabled(self):
        self.assertEqual(config_module.load_config(env=self.env).hysteria2_auth_backend_port, 0)

    def test_valid_api_port_and_auth_backend_port_load(self):
        cfg = config_module.load_config(env={**self.env, "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": "8899"})
        self.assertEqual((cfg.api_port, cfg.hysteria2_auth_backend_port), (8443, 8899))

    def test_auth_backend_port_equal_to_api_port_is_rejected(self):
        with self.assertRaisesRegex(config_module.ConfigError, "must differ"):
            config_module.load_config(env={**self.env, "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": "8443"})

    def test_out_of_range_or_non_integer_port_is_rejected(self):
        for bad in ("0", "-1", "65536", "70000", "abc", "88.5"):
            with self.subTest(bad=bad), self.assertRaisesRegex(config_module.ConfigError, "HYSTERIA2_AUTH_BACKEND_PORT"):
                config_module.load_config(env={**self.env, "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": bad})

    def test_auth_backend_port_without_hysteria_group_is_rejected(self):
        env = {k: v for k, v in self.env.items() if "HYSTERIA2" not in k}
        with self.assertRaisesRegex(config_module.ConfigError, "HYSTERIA2_STORE_PATH"):
            config_module.load_config(env={**env, "POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT": "8899"})

    def test_hysteria_profile_group_is_unchanged_without_auth_port(self):
        cfg = config_module.load_config(env=self.env)
        self.assertEqual((cfg.hysteria2_server_port, cfg.hysteria2_sni), (34443, _SNI))


if __name__ == "__main__":
    unittest.main()
