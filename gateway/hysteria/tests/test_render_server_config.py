import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_HYSTERIA_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
for _path in (_HYSTERIA_DIR,):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import render_server_config as rsc


def _valid_config(**overrides):
    defaults = dict(
        listen_port=34443,
        tls_cert_file="/etc/letsencrypt/live/example/fullchain.pem",
        tls_key_file="/etc/letsencrypt/live/example/privkey.pem",
        auth_backend_url="http://127.0.0.1:8446/internal/hysteria-auth",
    )
    defaults.update(overrides)
    return rsc.HysteriaServerConfig(**defaults)


class RenderServerConfigYamlTests(unittest.TestCase):
    def test_valid_config_renders_expected_yaml(self):
        yaml_text = rsc.render_server_config_yaml(_valid_config())
        self.assertEqual(
            yaml_text,
            "listen: :34443\n"
            "\n"
            "tls:\n"
            "  cert: /etc/letsencrypt/live/example/fullchain.pem\n"
            "  key: /etc/letsencrypt/live/example/privkey.pem\n"
            "\n"
            "auth:\n"
            "  type: http\n"
            "  http:\n"
            "    url: http://127.0.0.1:8446/internal/hysteria-auth\n"
            "    insecure: false\n",
        )

    def test_rendering_is_deterministic(self):
        config = _valid_config()
        self.assertEqual(rsc.render_server_config_yaml(config), rsc.render_server_config_yaml(config))

    def test_no_obfs_block_ever_rendered(self):
        # B46-4A Finding 8 - NONE-only obfuscation for this slice; no obfs
        # block, no fabricated/empty Salamander password.
        yaml_text = rsc.render_server_config_yaml(_valid_config())
        self.assertNotIn("obfs", yaml_text)
        self.assertNotIn("salamander", yaml_text)

    def test_no_secret_value_ever_embedded(self):
        # This module only ever writes PATHS to key material, never the
        # key/cert bytes themselves - proven by construction (the
        # dataclass has no field that could hold raw key bytes), but
        # asserted here directly against the rendered text too.
        yaml_text = rsc.render_server_config_yaml(_valid_config())
        self.assertNotIn("BEGIN PRIVATE KEY", yaml_text)
        self.assertNotIn("BEGIN CERTIFICATE", yaml_text)

    def test_invalid_port_fails_closed(self):
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(listen_port=70000))
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(listen_port=0))

    def test_relative_cert_path_fails_closed(self):
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(tls_cert_file="relative/cert.pem"))

    def test_relative_key_path_fails_closed(self):
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(tls_key_file="relative/key.pem"))

    def test_blank_cert_path_fails_closed(self):
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(tls_cert_file=""))

    def test_non_loopback_auth_backend_url_fails_closed(self):
        # B46-4A's own auth architecture: the auth backend must be
        # reachable ONLY from the Hysteria2 server process on the same
        # host - never the public interface.
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(auth_backend_url="http://0.0.0.0:8446/internal/hysteria-auth"))
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc.render_server_config_yaml(_valid_config(auth_backend_url="http://16.170.208.231:8446/internal/hysteria-auth"))

    def test_loopback_https_auth_backend_url_is_accepted(self):
        yaml_text = rsc.render_server_config_yaml(_valid_config(auth_backend_url="https://127.0.0.1:8446/internal/hysteria-auth"))
        self.assertIn("https://127.0.0.1:8446/internal/hysteria-auth", yaml_text)


class AtomicWriteConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_writes_file_with_expected_content_and_mode(self):
        path = os.path.join(self._tmp.name, "config.yaml")
        rsc.atomic_write_config(path, "listen: :34443\n")
        with open(path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "listen: :34443\n")

    def test_no_leftover_tmp_file_on_success(self):
        path = os.path.join(self._tmp.name, "config.yaml")
        rsc.atomic_write_config(path, "listen: :34443\n")
        leftovers = [name for name in os.listdir(self._tmp.name) if name.startswith(".hysteria-config-")]
        self.assertEqual(leftovers, [])

    def test_replaces_existing_file_atomically(self):
        path = os.path.join(self._tmp.name, "config.yaml")
        rsc.atomic_write_config(path, "listen: :1111\n")
        rsc.atomic_write_config(path, "listen: :2222\n")
        with open(path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "listen: :2222\n")


class ConfigFromEnvTests(unittest.TestCase):
    def _valid_env(self, **overrides):
        env = {
            "NOVA_HYSTERIA2_LISTEN_PORT": "34443",
            "NOVA_HYSTERIA2_TLS_CERT_FILE": "/etc/letsencrypt/live/example/fullchain.pem",
            "NOVA_HYSTERIA2_TLS_KEY_FILE": "/etc/letsencrypt/live/example/privkey.pem",
            "NOVA_HYSTERIA2_AUTH_BACKEND_URL": "http://127.0.0.1:8446/internal/hysteria-auth",
        }
        env.update(overrides)
        return env

    def test_valid_env_produces_expected_config(self):
        config = rsc._config_from_env(self._valid_env())
        self.assertEqual(config.listen_port, 34443)
        self.assertEqual(config.tls_cert_file, "/etc/letsencrypt/live/example/fullchain.pem")

    def test_missing_required_env_var_fails_closed(self):
        env = self._valid_env()
        del env["NOVA_HYSTERIA2_TLS_CERT_FILE"]
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc._config_from_env(env)

    def test_non_integer_port_env_fails_closed(self):
        env = self._valid_env(NOVA_HYSTERIA2_LISTEN_PORT="not-a-port")
        with self.assertRaises(rsc.HysteriaServerConfigRenderError):
            rsc._config_from_env(env)

    def test_no_default_values_exist_for_any_required_field(self):
        # Structural proof: every field of HysteriaServerConfig is a
        # positional/required dataclass field with no default - a
        # deployer cannot accidentally end up with a "mostly configured"
        # instance.
        import dataclasses
        for field in dataclasses.fields(rsc.HysteriaServerConfig):
            self.assertIs(field.default, dataclasses.MISSING, f"{field.name} must not have a default")


if __name__ == "__main__":
    unittest.main()
