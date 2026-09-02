"""B25 (task G/I) - ingress_config.load_ingress_config: absent-by-default,
all-or-nothing once any NOVA_INGRESS_* variable is set."""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import ingress_config as ingress_config_module


def _valid_env(tmp_dir, **overrides):
    reality_key_file = os.path.join(tmp_dir, "reality.key")
    with open(reality_key_file, "w", encoding="utf-8") as handle:
        handle.write("fake-reality-private-key\n")
    upstream_uuid_file = os.path.join(tmp_dir, "upstream.uuid")
    with open(upstream_uuid_file, "w", encoding="utf-8") as handle:
        handle.write("11111111-1111-1111-1111-111111111111\n")
    wrapper_path = os.path.join(tmp_dir, "fake-wrapper")
    with open(wrapper_path, "w", encoding="utf-8") as handle:
        handle.write("#!/usr/bin/env bash\nexit 0\n")

    env = {
        "NOVA_INGRESS_ENDPOINT_ID": "ru-ingress-1",
        "NOVA_INGRESS_ENDPOINT_HOST": "203.0.113.50",
        "NOVA_INGRESS_REALITY_PRIVATE_KEY_FILE": reality_key_file,
        "NOVA_INGRESS_SERVER_PORT": "443",
        "NOVA_INGRESS_SERVER_NAME": "www.microsoft.com",
        "NOVA_INGRESS_DEST": "www.microsoft.com:443",
        "NOVA_INGRESS_SHORT_ID": "ab12",
        "NOVA_INGRESS_FINGERPRINT": "chrome",
        "NOVA_INGRESS_REALITY_PUBLIC_KEY": "A" * 43,
        "NOVA_INGRESS_UPSTREAM_HOST": "203.0.113.60",
        "NOVA_INGRESS_UPSTREAM_PORT": "443",
        "NOVA_INGRESS_UPSTREAM_TRANSPORT": "reality",
        "NOVA_INGRESS_UPSTREAM_UUID_FILE": upstream_uuid_file,
        "NOVA_INGRESS_UPSTREAM_SERVER_NAME": "www.apple.com",
        "NOVA_INGRESS_UPSTREAM_PUBLIC_KEY": "B" * 43,
        "NOVA_INGRESS_UPSTREAM_SHORT_ID": "cd34",
        "NOVA_INGRESS_ACTIVATION_STORE_PATH": os.path.join(tmp_dir, "activations.json"),
        "NOVA_INGRESS_ACTIVATION_LOCK_PATH": os.path.join(tmp_dir, ".activations.lock"),
        "NOVA_INGRESS_XRAY_STORE_PATH": os.path.join(tmp_dir, "xray.json"),
        "NOVA_INGRESS_XRAY_LOCK_PATH": os.path.join(tmp_dir, ".xray.lock"),
        "NOVA_INGRESS_ACTIVATION_WRAPPER_PATH": wrapper_path,
        "NOVA_INGRESS_STAGING_CONFIG_PATH": os.path.join(tmp_dir, "staging.json"),
        "NOVA_INGRESS_ACTIVATION_GLOBAL_LOCK_PATH": os.path.join(tmp_dir, ".ingress-activation.lock"),
        "NOVA_INGRESS_ACTIVATION_LAST_HASH_PATH": os.path.join(tmp_dir, ".ingress-last-hash"),
    }
    env.update(overrides)
    return env


class IngressConfigTests(unittest.TestCase):
    def test_no_ingress_vars_set_returns_none(self):
        self.assertIsNone(ingress_config_module.load_ingress_config(env={}))

    def test_a_fully_valid_environment_loads_successfully(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg = ingress_config_module.load_ingress_config(env=_valid_env(tmp_dir))
            self.assertEqual(cfg.ingress_endpoint_id, "ru-ingress-1")
            self.assertEqual(cfg.ingress_upstream_transport, "reality")
            self.assertEqual(cfg.ingress_profile_ttl_seconds, 0)

    def test_a_partially_configured_environment_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            del env["NOVA_INGRESS_UPSTREAM_HOST"]
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_malformed_reality_public_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_REALITY_PUBLIC_KEY="not-a-key")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_unsupported_upstream_transport_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_UPSTREAM_TRANSPORT="quic")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_tls_upstream_requires_sni_not_reality_fields(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            env["NOVA_INGRESS_UPSTREAM_TRANSPORT"] = "tls"
            del env["NOVA_INGRESS_UPSTREAM_SERVER_NAME"]
            del env["NOVA_INGRESS_UPSTREAM_PUBLIC_KEY"]
            del env["NOVA_INGRESS_UPSTREAM_SHORT_ID"]
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)
            env["NOVA_INGRESS_UPSTREAM_SNI"] = "www.apple.com"
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_upstream_sni, "www.apple.com")

    def test_upstream_uuid_file_must_exist(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            env["NOVA_INGRESS_UPSTREAM_UUID_FILE"] = os.path.join(tmp_dir, "does-not-exist")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)


if __name__ == "__main__":
    unittest.main()
