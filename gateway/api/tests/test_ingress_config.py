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
    probe_secret_file = os.path.join(tmp_dir, "probe-hmac-secret.bin")
    with open(probe_secret_file, "wb") as handle:
        handle.write(b"S" * 32)

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
        "NOVA_INGRESS_UPSTREAM_FLOW": "xtls-rprx-vision",
        "NOVA_INGRESS_EXIT_ENDPOINT_ID": "frankfurt",
        "NOVA_INGRESS_EXIT_PROBE_HOST": "203.0.113.60",
        "NOVA_INGRESS_PROBE_HMAC_SECRET_FILE": probe_secret_file,
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
    def test_xhttp_only_ingress_has_no_extra_reality_listener(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_KIND="cdn_fronted",
                             NOVA_INGRESS_XHTTP_CLIENT_HOST="edge.example.org",
                             NOVA_INGRESS_XHTTP_CLIENT_PORT="443",
                             NOVA_INGRESS_XHTTP_SERVER_PORT="2100",
                             NOVA_INGRESS_XHTTP_HOST="edge.example.org",
                             NOVA_INGRESS_XHTTP_PATH="/nova-xhttp/",
                             NOVA_INGRESS_XHTTP_MODE="packet-up",
                             NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES="524288",
                             NOVA_INGRESS_XHTTP_PADDING_PLACEMENT="query",
                             NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES="1",
                             NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES="64")
            for name in ("REALITY_PRIVATE_KEY_FILE", "SERVER_PORT", "SERVER_NAME", "DEST",
                         "SHORT_ID", "FINGERPRINT", "REALITY_PUBLIC_KEY"):
                env.pop("NOVA_INGRESS_" + name)
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(0, cfg.ingress_server_port)
            self.assertEqual(2100, cfg.ingress_xhttp_server_port)
            env.pop("NOVA_INGRESS_XHTTP_SERVER_PORT")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_no_ingress_vars_set_returns_none(self):
        self.assertIsNone(ingress_config_module.load_ingress_config(env={}))

    def test_a_fully_valid_environment_loads_successfully(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg = ingress_config_module.load_ingress_config(env=_valid_env(tmp_dir))
            self.assertEqual(cfg.ingress_endpoint_id, "ru-ingress-1")
            self.assertEqual(cfg.ingress_upstream_transport, "reality")
            self.assertEqual(cfg.ingress_profile_ttl_seconds, 0)
            self.assertEqual(cfg.ingress_exit_endpoint_id, "frankfurt")
            self.assertEqual(cfg.ingress_probe_ttl_seconds, 300)
            self.assertEqual(cfg.ingress_kind, "direct_ip")

    def test_ingress_kind_defaults_to_direct_ip_when_unset(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            self.assertNotIn("NOVA_INGRESS_KIND", env)
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_kind, "direct_ip")

    def test_ingress_kind_cdn_fronted_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_KIND="cdn_fronted")
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_kind, "cdn_fronted")

    def test_xhttp_public_binding_is_all_or_nothing_and_cdn_only(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(
                tmp_dir,
                NOVA_INGRESS_KIND="cdn_fronted",
                NOVA_INGRESS_XHTTP_CLIENT_HOST="edge.example.org",
                NOVA_INGRESS_XHTTP_CLIENT_PORT="443",
            )

            cfg = ingress_config_module.load_ingress_config(env=env)

            self.assertEqual(
                "edge.example.org",
                cfg.ingress_xhttp_client_host,
            )
            self.assertEqual(443, cfg.ingress_xhttp_client_port)

            partial = dict(env)
            partial.pop("NOVA_INGRESS_XHTTP_CLIENT_PORT")

            with self.assertRaises(
                ingress_config_module.IngressConfigError
            ):
                ingress_config_module.load_ingress_config(env=partial)

            direct = dict(env)
            direct["NOVA_INGRESS_KIND"] = "direct_ip"

            with self.assertRaises(
                ingress_config_module.IngressConfigError
            ):
                ingress_config_module.load_ingress_config(env=direct)

    def test_ingress_kind_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_KIND="CDN_FRONTED")
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_kind, "cdn_fronted")

    def test_unsupported_ingress_kind_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_KIND="satellite")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_probe_hmac_secret_file_must_exist(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            env["NOVA_INGRESS_PROBE_HMAC_SECRET_FILE"] = os.path.join(tmp_dir, "does-not-exist")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_missing_exit_endpoint_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            del env["NOVA_INGRESS_EXIT_ENDPOINT_ID"]
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_negative_probe_ttl_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_PROBE_TTL_SECONDS="-1")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

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

    # --- B31C - relay upstream VLESS flow parity ---

    def test_configured_upstream_flow_reaches_config_exactly(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_upstream_flow, "xtls-rprx-vision")

    def test_reality_upstream_missing_flow_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            del env["NOVA_INGRESS_UPSTREAM_FLOW"]
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_unsupported_upstream_flow_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir, NOVA_INGRESS_UPSTREAM_FLOW="xtls-rprx-splice")
            with self.assertRaises(ingress_config_module.IngressConfigError):
                ingress_config_module.load_ingress_config(env=env)

    def test_tls_upstream_flow_is_optional(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env = _valid_env(tmp_dir)
            env["NOVA_INGRESS_UPSTREAM_TRANSPORT"] = "tls"
            del env["NOVA_INGRESS_UPSTREAM_SERVER_NAME"]
            del env["NOVA_INGRESS_UPSTREAM_PUBLIC_KEY"]
            del env["NOVA_INGRESS_UPSTREAM_SHORT_ID"]
            del env["NOVA_INGRESS_UPSTREAM_FLOW"]
            env["NOVA_INGRESS_UPSTREAM_SNI"] = "www.apple.com"
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_upstream_flow, "")

    def test_client_facing_ingress_flow_is_unaffected_by_upstream_flow(self):
        # B31C touches ONLY the ingress -> exit relay leg - the client-
        # facing ingress inbound's own flow (NOVA_INGRESS_FLOW, unrelated
        # env var, absent from _valid_env by default) must be completely
        # untouched by this change: still absent by default, and still
        # settable independently of NOVA_INGRESS_UPSTREAM_FLOW.
        with tempfile.TemporaryDirectory() as tmp_dir:
            default_env = _valid_env(tmp_dir)
            self.assertNotIn("NOVA_INGRESS_FLOW", default_env)
            self.assertEqual(ingress_config_module.load_ingress_config(env=default_env).ingress_flow, "")

            env = _valid_env(tmp_dir, NOVA_INGRESS_FLOW="xtls-rprx-vision")
            cfg = ingress_config_module.load_ingress_config(env=env)
            self.assertEqual(cfg.ingress_flow, "xtls-rprx-vision")
            self.assertEqual(cfg.ingress_upstream_flow, "xtls-rprx-vision")


    def test_xhttp_origin_backend_is_all_or_nothing_and_requires_public_binding(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            origin_only = _valid_env(
                tmp_dir,
                NOVA_INGRESS_KIND="cdn_fronted",
                NOVA_INGRESS_XHTTP_SERVER_PORT="2100",
            )
            with self.assertRaises(
                ingress_config_module.IngressConfigError
            ):
                ingress_config_module.load_ingress_config(
                    env=origin_only
                )

            complete = _valid_env(
                tmp_dir,
                NOVA_INGRESS_KIND="cdn_fronted",
                NOVA_INGRESS_XHTTP_CLIENT_HOST="edge.example.org",
                NOVA_INGRESS_XHTTP_CLIENT_PORT="443",
                NOVA_INGRESS_XHTTP_SERVER_PORT="2100",
                NOVA_INGRESS_XHTTP_HOST="origin.example.org",
                NOVA_INGRESS_XHTTP_PATH="/nova-xhttp/",
                NOVA_INGRESS_XHTTP_MODE="packet-up",
                NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES="524288",
                NOVA_INGRESS_XHTTP_PADDING_PLACEMENT="query",
                NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES="1",
                NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES="64",
            )

            cfg = ingress_config_module.load_ingress_config(
                env=complete
            )

            self.assertEqual(
                2100,
                cfg.ingress_xhttp_server_port,
            )
            self.assertEqual(
                "origin.example.org",
                cfg.ingress_xhttp_host,
            )
            self.assertEqual(
                "/nova-xhttp/",
                cfg.ingress_xhttp_path,
            )
            self.assertEqual(
                "packet-up",
                cfg.ingress_xhttp_mode,
            )
            self.assertEqual(
                524288,
                cfg.ingress_xhttp_max_each_post_bytes,
            )

    def test_xhttp_origin_rejects_streaming_invalid_path_and_disabled_padding(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = _valid_env(
                tmp_dir,
                NOVA_INGRESS_KIND="cdn_fronted",
                NOVA_INGRESS_XHTTP_CLIENT_HOST="edge.example.org",
                NOVA_INGRESS_XHTTP_CLIENT_PORT="443",
                NOVA_INGRESS_XHTTP_SERVER_PORT="2100",
                NOVA_INGRESS_XHTTP_HOST="origin.example.org",
                NOVA_INGRESS_XHTTP_PATH="/nova-xhttp/",
                NOVA_INGRESS_XHTTP_MODE="packet-up",
                NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES="524288",
                NOVA_INGRESS_XHTTP_PADDING_PLACEMENT="query",
                NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES="1",
                NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES="64",
            )

            for mutation in (
                {"NOVA_INGRESS_XHTTP_MODE": "stream-up"},
                {"NOVA_INGRESS_XHTTP_PATH": "/nova-xhttp"},
                {
                    "NOVA_INGRESS_XHTTP_PADDING_PLACEMENT": "none",
                    "NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES": "0",
                    "NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES": "0",
                },
            ):
                bad = dict(base)
                bad.update(mutation)

                with self.assertRaises(
                    ingress_config_module.IngressConfigError
                ):
                    ingress_config_module.load_ingress_config(
                        env=bad
                    )

if __name__ == "__main__":
    unittest.main()
