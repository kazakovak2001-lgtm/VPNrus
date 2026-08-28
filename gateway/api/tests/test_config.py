import base64
import dataclasses
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import config as config_module


def _valid_key():
    return base64.b64encode(b"\x02" * 32).decode("ascii")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = os.path.join(self._tmp.name, "provision-peer.sh")
        with open(self.script_path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")

    def _valid_env(self):
        return {
            "POCVPN_API_ENDPOINT_HOST": "203.0.113.1",
            "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": _valid_key(),
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
            "POCVPN_API_TOKEN_STORE_PATH": os.path.join(self._tmp.name, "enrollment-tokens.json"),
            "POCVPN_API_PROVISION_SCRIPT_PATH": self.script_path,
            "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5",
            "POCVPN_API_API_PORT": "8765",
        }

    def test_valid_config_loads(self):
        cfg = config_module.load_config(env=self._valid_env())
        self.assertEqual(cfg.endpoint_host, "203.0.113.1")
        self.assertEqual(cfg.endpoint_port, 51820)
        self.assertEqual(cfg.api_port, 8765)
        self.assertEqual(cfg.subprocess_timeout_seconds, 5.0)
        self.assertTrue(cfg.token_lock_path.endswith(".lock"))

    def test_no_bind_host_field_exists(self):
        # Structural proof the bind host is not configurable from here:
        # AppConfig simply has no field for it at all.
        field_names = {f.name for f in dataclasses.fields(config_module.AppConfig)}
        for suspicious in ("bind_host", "host", "listen_host", "bind_address"):
            self.assertNotIn(suspicious, field_names)

    def test_missing_required_key_raises(self):
        env = self._valid_env()
        del env["POCVPN_API_GATEWAY_PUBLIC_KEY"]
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_blank_required_key_raises(self):
        env = self._valid_env()
        env["POCVPN_API_ENDPOINT_HOST"] = "   "
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_invalid_endpoint_port_raises(self):
        env = self._valid_env()
        env["POCVPN_API_ENDPOINT_PORT"] = "not-a-port"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_out_of_range_api_port_raises(self):
        env = self._valid_env()
        env["POCVPN_API_API_PORT"] = "70000"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_invalid_gateway_public_key_raises(self):
        env = self._valid_env()
        env["POCVPN_API_GATEWAY_PUBLIC_KEY"] = "not-a-key"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_invalid_gateway_tunnel_ip_raises(self):
        env = self._valid_env()
        env["POCVPN_API_GATEWAY_TUNNEL_IP"] = "not-an-ip"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_missing_provision_script_raises(self):
        env = self._valid_env()
        env["POCVPN_API_PROVISION_SCRIPT_PATH"] = os.path.join(self._tmp.name, "does-not-exist.sh")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_invalid_timeout_raises(self):
        env = self._valid_env()
        env["POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS"] = "-1"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_token_lock_path_override_honored(self):
        env = self._valid_env()
        override = os.path.join(self._tmp.name, "custom.lock")
        env["POCVPN_API_TOKEN_LOCK_PATH"] = override
        cfg = config_module.load_config(env=env)
        self.assertEqual(cfg.token_lock_path, override)

    def test_relative_provision_script_path_raises(self):
        env = self._valid_env()
        env["POCVPN_API_PROVISION_SCRIPT_PATH"] = "relative/provision-peer.sh"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    # --- B8B1C2: optional POCVPN_API_SUDO_PATH ---
    def test_sudo_path_absent_defaults_to_empty(self):
        cfg = config_module.load_config(env=self._valid_env())
        self.assertEqual(cfg.sudo_path, "")

    def test_sudo_path_valid_absolute_file_honored(self):
        sudo_path = os.path.join(self._tmp.name, "sudo")
        with open(sudo_path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")
        env = self._valid_env()
        env["POCVPN_API_SUDO_PATH"] = sudo_path
        cfg = config_module.load_config(env=env)
        self.assertEqual(cfg.sudo_path, sudo_path)

    def test_sudo_path_relative_raises(self):
        env = self._valid_env()
        env["POCVPN_API_SUDO_PATH"] = "relative/sudo"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_sudo_path_nonexistent_raises(self):
        env = self._valid_env()
        env["POCVPN_API_SUDO_PATH"] = os.path.join(self._tmp.name, "does-not-exist")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)


if __name__ == "__main__":
    unittest.main()
