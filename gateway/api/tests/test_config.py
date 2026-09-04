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

    def _valid_xray_env(self):
        private_key_file = os.path.join(self._tmp.name, "reality-private-key.txt")
        with open(private_key_file, "w", encoding="utf-8") as handle:
            handle.write("B" * 43)

        env = self._valid_env()
        env.update({
            "POCVPN_API_XRAY_STORE_PATH": os.path.join(self._tmp.name, "xray.json"),
            "POCVPN_API_XRAY_SERVER_PORT": "2053",
            "POCVPN_API_XRAY_SERVER_NAME": "example.invalid",
            "POCVPN_API_XRAY_FINGERPRINT": "chrome",
            "POCVPN_API_XRAY_REALITY_PUBLIC_KEY": "A" * 43,
            "POCVPN_API_XRAY_SHORT_ID": "ab12cd34",
            "POCVPN_API_XRAY_FLOW": "xtls-rprx-vision",
            "POCVPN_API_XRAY_REALITY_PRIVATE_KEY_FILE": private_key_file,
            "POCVPN_API_XRAY_STAGING_CONFIG_PATH": os.path.join(self._tmp.name, "candidate.json"),
            "POCVPN_API_XRAY_ACTIVATION_LOCK_PATH": os.path.join(self._tmp.name, ".xray-activation.lock"),
            "POCVPN_API_XRAY_ACTIVATION_LAST_HASH_PATH": os.path.join(self._tmp.name, ".xray-last-hash"),
            "POCVPN_API_XRAY_ACTIVATION_WRAPPER_PATH": "/usr/local/libexec/nova-xray-reload",
            "POCVPN_API_XRAY_DEST": "example.invalid:443",
        })
        return env

    def test_fully_configured_xray_settings_load(self):
        cfg = config_module.load_config(env=self._valid_xray_env())
        self.assertEqual(cfg.xray_server_port, 2053)
        self.assertEqual(cfg.xray_reality_public_key, "A" * 43)

    def test_xray_completely_unset_is_fine(self):
        cfg = config_module.load_config(env=self._valid_env())
        self.assertEqual(cfg.xray_server_port, 0)
        self.assertEqual(cfg.xray_store_path, "")

    def test_xray_partially_configured_raises(self):
        env = self._valid_xray_env()
        del env["POCVPN_API_XRAY_SERVER_NAME"]
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_invalid_fingerprint_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_FINGERPRINT"] = "netscape-navigator"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_wrong_length_public_key_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_REALITY_PUBLIC_KEY"] = "tooshort"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_odd_length_short_id_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_SHORT_ID"] = "abc"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_invalid_flow_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_FLOW"] = "made-up-flow"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_activation_partially_configured_raises(self):
        env = self._valid_xray_env()
        del env["POCVPN_API_XRAY_ACTIVATION_WRAPPER_PATH"]
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_private_key_file_nonexistent_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_REALITY_PRIVATE_KEY_FILE"] = os.path.join(self._tmp.name, "does-not-exist.txt")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_activation_wrapper_relative_path_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_ACTIVATION_WRAPPER_PATH"] = "relative/nova-xray-reload"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_server_name_and_dest_hostname_mismatch_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_SERVER_NAME"] = "example.invalid"
        env["POCVPN_API_XRAY_DEST"] = "different.invalid:443"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_xray_server_name_matching_dest_hostname_is_accepted(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_SERVER_NAME"] = "example.invalid"
        env["POCVPN_API_XRAY_DEST"] = "example.invalid:443"
        cfg = config_module.load_config(env=env)
        self.assertEqual(cfg.xray_server_name, "example.invalid")

    def test_xray_server_name_equal_to_gateway_endpoint_host_raises(self):
        env = self._valid_xray_env()
        env["POCVPN_API_XRAY_SERVER_NAME"] = env["POCVPN_API_ENDPOINT_HOST"]
        env["POCVPN_API_XRAY_DEST"] = env["POCVPN_API_ENDPOINT_HOST"] + ":443"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    # --- B8O2: TLS/TCP fallback's own optional completeness group ---

    def _valid_tls_cert_files(self):
        cert_file = os.path.join(self._tmp.name, "tls-cert.pem")
        key_file = os.path.join(self._tmp.name, "tls-key.pem")
        with open(cert_file, "w", encoding="utf-8") as handle:
            handle.write("cert")
        with open(key_file, "w", encoding="utf-8") as handle:
            handle.write("key")
        return cert_file, key_file

    def _valid_tls_env(self):
        cert_file, key_file = self._valid_tls_cert_files()
        env = self._valid_xray_env()
        env.update({
            "POCVPN_API_XRAY_TLS_SERVER_PORT": "2054",
            "POCVPN_API_XRAY_TLS_SERVER_NAME": "203.0.113.1",
            "POCVPN_API_XRAY_TLS_FINGERPRINT": "chrome",
            "POCVPN_API_XRAY_TLS_CERT_FILE": cert_file,
            "POCVPN_API_XRAY_TLS_KEY_FILE": key_file,
        })
        return env

    def test_tls_completely_unset_is_fine_alongside_configured_reality(self):
        cfg = config_module.load_config(env=self._valid_xray_env())
        self.assertEqual(cfg.xray_tls_server_port, 0)

    def test_fully_configured_tls_settings_load(self):
        cfg = config_module.load_config(env=self._valid_tls_env())
        self.assertEqual(cfg.xray_tls_server_port, 2054)
        self.assertEqual(cfg.xray_tls_server_name, "203.0.113.1")
        self.assertEqual(cfg.xray_tls_fingerprint, "chrome")

    def test_tls_partially_configured_raises(self):
        env = self._valid_tls_env()
        del env["POCVPN_API_XRAY_TLS_SERVER_NAME"]
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_tls_invalid_fingerprint_raises(self):
        env = self._valid_tls_env()
        env["POCVPN_API_XRAY_TLS_FINGERPRINT"] = "netscape-navigator"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_tls_cert_file_nonexistent_raises(self):
        env = self._valid_tls_env()
        env["POCVPN_API_XRAY_TLS_CERT_FILE"] = os.path.join(self._tmp.name, "does-not-exist.pem")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_tls_key_file_relative_path_raises(self):
        env = self._valid_tls_env()
        env["POCVPN_API_XRAY_TLS_KEY_FILE"] = "relative-key.pem"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_tls_port_colliding_with_reality_port_raises(self):
        env = self._valid_tls_env()
        env["POCVPN_API_XRAY_TLS_SERVER_PORT"] = env["POCVPN_API_XRAY_SERVER_PORT"]
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_tls_without_activation_boundary_configured_raises(self):
        cert_file, key_file = self._valid_tls_cert_files()
        env = self._valid_env()
        env.update({
            "POCVPN_API_XRAY_STORE_PATH": os.path.join(self._tmp.name, "xray.json"),
            "POCVPN_API_XRAY_SERVER_PORT": "8444",
            "POCVPN_API_XRAY_SERVER_NAME": "example.invalid",
            "POCVPN_API_XRAY_FINGERPRINT": "chrome",
            "POCVPN_API_XRAY_REALITY_PUBLIC_KEY": "A" * 43,
            "POCVPN_API_XRAY_SHORT_ID": "ab12cd34",
            "POCVPN_API_XRAY_TLS_SERVER_PORT": "2053",
            "POCVPN_API_XRAY_TLS_SERVER_NAME": "203.0.113.1",
            "POCVPN_API_XRAY_TLS_FINGERPRINT": "chrome",
            "POCVPN_API_XRAY_TLS_CERT_FILE": cert_file,
            "POCVPN_API_XRAY_TLS_KEY_FILE": key_file,
        })
        # Deliberately no activation-boundary fields at all (no private key
        # file/staging/lock/wrapper) - REALITY's own completeness group would
        # already reject this, but this test pins the TLS-specific message
        # path distinctly in case REALITY's own group is ever loosened.
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)


class ManifestConfigTests(unittest.TestCase):
    """B12 - AppConfig.manifest_path's own optional completeness group."""

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

    def test_manifest_path_absent_is_fine(self):
        cfg = config_module.load_config(env=self._valid_env())
        self.assertEqual(cfg.manifest_path, "")

    def test_manifest_path_valid_absolute_file_honored(self):
        manifest_file = os.path.join(self._tmp.name, "endpoint-manifest.bin")
        with open(manifest_file, "wb") as handle:
            handle.write(b"\x00\x00\x00\x01fake")
        env = dict(self._valid_env())
        env["POCVPN_API_MANIFEST_PATH"] = manifest_file
        cfg = config_module.load_config(env=env)
        self.assertEqual(cfg.manifest_path, manifest_file)

    def test_manifest_path_relative_raises(self):
        env = dict(self._valid_env())
        env["POCVPN_API_MANIFEST_PATH"] = "relative/manifest.bin"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_manifest_path_nonexistent_raises(self):
        env = dict(self._valid_env())
        env["POCVPN_API_MANIFEST_PATH"] = os.path.join(self._tmp.name, "does-not-exist.bin")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    # --- FIELD_ENROLLMENT_* (Russia field-test zero-touch enrollment) ---

    def _field_enrollment_secret_file(self):
        path = os.path.join(self._tmp.name, "field-enrollment-secret.bin")
        with open(path, "wb") as handle:
            handle.write(b"s" * 32)
        return path

    def test_field_enrollment_disabled_by_default(self):
        cfg = config_module.load_config(env=self._valid_env())
        self.assertFalse(cfg.field_enrollment_enabled)

    def test_field_enrollment_enabled_requires_activation_store_path(self):
        env = dict(self._valid_env())
        env["POCVPN_API_FIELD_ENROLLMENT_ENABLED"] = "true"
        env["POCVPN_API_FIELD_ENROLLMENT_MAX_DEVICES"] = "5"
        env["POCVPN_API_FIELD_ENROLLMENT_HMAC_SECRET_FILE"] = self._field_enrollment_secret_file()
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_field_enrollment_enabled_requires_max_devices(self):
        env = dict(self._valid_env())
        env["POCVPN_API_ACTIVATION_STORE_PATH"] = os.path.join(self._tmp.name, "activations.json")
        env["POCVPN_API_FIELD_ENROLLMENT_ENABLED"] = "true"
        env["POCVPN_API_FIELD_ENROLLMENT_HMAC_SECRET_FILE"] = self._field_enrollment_secret_file()
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_field_enrollment_enabled_requires_secret_file(self):
        env = dict(self._valid_env())
        env["POCVPN_API_ACTIVATION_STORE_PATH"] = os.path.join(self._tmp.name, "activations.json")
        env["POCVPN_API_FIELD_ENROLLMENT_ENABLED"] = "true"
        env["POCVPN_API_FIELD_ENROLLMENT_MAX_DEVICES"] = "5"
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)

    def test_field_enrollment_valid_full_config_loads(self):
        env = dict(self._valid_env())
        env["POCVPN_API_ACTIVATION_STORE_PATH"] = os.path.join(self._tmp.name, "activations.json")
        env["POCVPN_API_FIELD_ENROLLMENT_ENABLED"] = "true"
        env["POCVPN_API_FIELD_ENROLLMENT_MAX_DEVICES"] = "5"
        env["POCVPN_API_FIELD_ENROLLMENT_HMAC_SECRET_FILE"] = self._field_enrollment_secret_file()
        cfg = config_module.load_config(env=env)
        self.assertTrue(cfg.field_enrollment_enabled)
        self.assertEqual(cfg.field_enrollment_max_devices, 5)

    def test_field_enrollment_secret_file_must_exist(self):
        env = dict(self._valid_env())
        env["POCVPN_API_ACTIVATION_STORE_PATH"] = os.path.join(self._tmp.name, "activations.json")
        env["POCVPN_API_FIELD_ENROLLMENT_ENABLED"] = "true"
        env["POCVPN_API_FIELD_ENROLLMENT_MAX_DEVICES"] = "5"
        env["POCVPN_API_FIELD_ENROLLMENT_HMAC_SECRET_FILE"] = os.path.join(self._tmp.name, "does-not-exist.bin")
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env=env)


if __name__ == "__main__":
    unittest.main()
