"""B60 - HTTP-level tests for POST /v1/xray-profile, transport="xhttp".

Mirrors test_xray_profile_endpoint.py's own TLS transport tests
(test_tls_transport_not_configured_fails_closed_with_503,
test_tls_transport_returns_only_tls_fields,
test_tls_and_reality_transports_return_the_same_identity_uuid) - same
activation transaction, same request/response shape discipline, no
parallel test mechanism.
"""
import dataclasses
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
from _fixtures import RunningServer, make_public_key, make_xray_xhttp_app_config, set_plan, write_fake_provision_script
from _http import post_activate, post_xray_profile


class XrayXhttpProfileEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.app_config = make_xray_xhttp_app_config(
            self._tmp.name, self.script_path, self.activation_store_path, self.activation_lock_path,
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x40)

        self.xray_plan_path = os.path.join(self._tmp.name, "xray-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.xray_plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.app_config.xray_staging_config_path
        set_plan(self.xray_plan_path, "ACTIVATE")

    def _issue_and_activate(self, max_devices=1):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=max_devices,
        )
        status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        return activation_id, credential

    # --- Transport selection ---

    def test_xhttp_transport_is_accepted(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, _body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)

    def test_reality_still_works_when_xhttp_is_also_configured(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "reality"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            set(json.loads(body).keys()),
            {"server_address", "server_port", "uuid", "flow", "server_name", "fingerprint", "reality_public_key", "short_id"},
        )

    def test_reality_default_transport_still_works_when_xhttp_is_also_configured(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, _body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a},
        )
        self.assertEqual(status, 200)

    def test_unknown_transport_still_400s_when_xhttp_is_configured(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, _body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "quic"},
        )
        self.assertEqual(status, 400)

    def test_xhttp_transport_not_configured_fails_closed_with_503(self):
        import dataclasses as _dc
        from _fixtures import write_fake_provision_script as _wfps
        # A REALITY-only config (make_xray_app_config, not the xhttp
        # wrapper) - xray_xhttp_server_port/client_host/client_port all
        # blank, matching every pre-B60 deployment byte-for-byte.
        from _fixtures import make_xray_app_config
        tmp2 = tempfile.TemporaryDirectory()
        self.addCleanup(tmp2.cleanup)
        script2 = _wfps(tmp2.name)
        store2 = os.path.join(tmp2.name, "activations.json")
        lock2 = os.path.join(tmp2.name, ".activations.lock")
        activations_module.init_store(store2, lock2)
        cfg2 = make_xray_app_config(tmp2.name, script2, store2, lock2)
        server2 = RunningServer(cfg2)
        self.addCleanup(server2.close)

        activation_id, credential = activations_module.issue_activation(store2, lock2, max_devices=1)
        status, _headers, body = post_activate(server2.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)

        status, _headers, body = post_xray_profile(
            server2.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 503)
        self.assertIn(b"xray_xhttp_not_configured", body)

    def test_xhttp_not_configured_when_only_loopback_port_is_set(self):
        """Client-facing host/port missing (server-port/path only, matching
        an operator who enabled the loopback inbound but has not yet
        completed B60's public identity wiring) - fails closed, exactly
        like the reverse would."""
        cfg = dataclasses.replace(
            self.app_config,
            xray_xhttp_client_host="",
            xray_xhttp_client_port=0,
        )
        self.server.srv.config = cfg
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 503)
        self.assertIn(b"xray_xhttp_not_configured", body)

    # --- Endpoint identity / XHTTP field values ---

    def test_xhttp_transport_returns_the_decided_frankfurt_identity(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)

        self.assertEqual(payload["server_address"], "edge.aknova.pp.ua")
        self.assertEqual(payload["server_port"], 443)
        self.assertEqual(payload["xhttp_host"], "edge.aknova.pp.ua")
        self.assertEqual(payload["xhttp_path"], "/nova-xhttp/")
        self.assertEqual(payload["mode"], "packet-up")
        self.assertEqual(payload["uplink_http_method"], "POST")
        self.assertRegex(payload["uuid"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_xhttp_transport_returns_exactly_the_documented_fields(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(
            set(payload.keys()),
            {"server_address", "server_port", "uuid", "xhttp_host", "xhttp_path", "mode", "uplink_http_method", "fingerprint"},
        )

    def test_xhttp_fingerprint_reuses_the_existing_tls_fingerprint_config(self):
        cfg = dataclasses.replace(self.app_config, xray_tls_fingerprint="firefox")
        self.server.srv.config = cfg
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["fingerprint"], "firefox")

    def test_xhttp_server_address_is_the_public_client_host_never_the_loopback_backend(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotEqual(payload["server_address"], "127.0.0.1")
        self.assertNotEqual(payload["server_port"], self.app_config.xray_xhttp_server_port)

    def test_xhttp_and_reality_transports_return_the_same_identity_uuid(self):
        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body_reality = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "reality"},
        )
        _s2, _h2, body_xhttp = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(json.loads(body_reality)["uuid"], json.loads(body_xhttp)["uuid"])

    def test_xhttp_retry_returns_the_same_uuid(self):
        _activation_id, credential = self._issue_and_activate()
        _s1, _h1, body1 = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        _s2, _h2, body2 = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(json.loads(body1)["uuid"], json.loads(body2)["uuid"])

    # --- Security: never leak internal/secret values ---

    def test_xhttp_response_never_contains_the_loopback_backend_address(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"127.0.0.1", body)
        self.assertNotIn(str(self.app_config.xray_xhttp_server_port).encode(), body)

    def test_xhttp_response_never_contains_filesystem_paths(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"/etc/nova-xray", body)
        self.assertNotIn(b"/etc/pocvpn", body)
        self.assertNotIn(b"/etc/nginx", body)

    def test_xhttp_response_never_contains_reality_or_tls_private_key_material(self):
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"private_key", body)
        self.assertNotIn(b"privateKey", body)
        self.assertNotIn(b"BEGIN PRIVATE KEY", body)
        with open(self.app_config.xray_reality_private_key_file, "rb") as handle:
            raw_reality_key = handle.read().strip()
        self.assertNotIn(raw_reality_key, body)

    def test_xhttp_response_never_contains_cloudflare_or_padding_fields(self):
        """No invented values (B60 scope) - these simply must never appear,
        since no server-side source of truth exists for them."""
        _activation_id, credential = self._issue_and_activate()
        status, _headers, body = post_xray_profile(
            self.server.port, credential=credential, body_obj={"public_key": self.key_a, "transport": "xhttp"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        for forbidden_key in (
            "paddingPlacement", "padding_placement",
            "paddingMinBytes", "padding_min_bytes",
            "paddingMaxBytes", "padding_max_bytes",
            "cloudflare_api", "cf_api_token",
        ):
            self.assertNotIn(forbidden_key, payload)


if __name__ == "__main__":
    unittest.main()
