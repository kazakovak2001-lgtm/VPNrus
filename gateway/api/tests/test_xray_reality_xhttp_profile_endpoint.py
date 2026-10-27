"""HTTP-level tests for POST /v1/xray-profile, transport="reality-xhttp".

Same activation transaction and response discipline as
test_xray_xhttp_profile_endpoint.py: the REALITY client fields plus the
XHTTP path/mode, the public endpoint host (never loopback), no `flow`, no
private key, and fail-closed 503 when the inbound is not configured.
"""
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
from _fixtures import (
    RunningServer, make_public_key, make_xray_app_config, make_xray_xhttp_app_config, set_plan,
    write_fake_provision_script,
)
from _http import post_activate, post_xray_profile

_FIELDS = {
    "server_address", "server_port", "uuid", "server_name", "fingerprint", "reality_public_key",
    "short_id", "xhttp_path", "mode", "uplink_http_method",
}


class XrayRealityXhttpProfileEndpointTests(unittest.TestCase):
    def _start(self, factory, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        script = write_fake_provision_script(tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(tmp.name, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")
        store = os.path.join(tmp.name, "activations.json")
        lock = os.path.join(tmp.name, ".activations.lock")
        activations_module.init_store(store, lock)
        cfg = factory(tmp.name, script, store, lock, **kwargs)
        server = RunningServer(cfg)
        self.addCleanup(server.close)
        xray_plan = os.path.join(tmp.name, "xray-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = xray_plan
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = cfg.xray_staging_config_path
        set_plan(xray_plan, "ACTIVATE")
        _activation_id, credential = activations_module.issue_activation(store, lock, max_devices=1)
        status, _h, _b = post_activate(server.port, credential=credential, body_obj={"public_key": self.key})
        self.assertEqual(status, 200)
        return cfg, server, credential

    def setUp(self):
        self.key = make_public_key(0x41)
        self.cfg, self.server, self.credential = self._start(
            make_xray_xhttp_app_config, xray_reality_xhttp_server_port=8443, xray_reality_xhttp_path="/nova-rx/",
        )

    def _profile(self, transport, server=None, credential=None):
        status, _headers, body = post_xray_profile(
            (server or self.server).port, credential=credential or self.credential,
            body_obj={"public_key": self.key, "transport": transport},
        )
        return status, body

    def test_returns_exactly_the_reality_and_xhttp_client_fields(self):
        status, body = self._profile("reality-xhttp")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(set(payload), _FIELDS)
        self.assertEqual(payload["server_address"], self.cfg.endpoint_host)
        self.assertEqual(payload["server_port"], 8443)
        self.assertEqual(payload["xhttp_path"], "/nova-rx/")
        self.assertEqual(payload["mode"], "packet-up")
        self.assertEqual(payload["server_name"], self.cfg.xray_server_name)
        self.assertEqual(payload["reality_public_key"], self.cfg.xray_reality_public_key)

    def test_same_identity_as_reality_and_never_a_flow_or_private_key(self):
        _s, reality_body = self._profile("reality")
        status, body = self._profile("reality-xhttp")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["uuid"], json.loads(reality_body)["uuid"])
        self.assertNotIn(b"flow", body)
        self.assertNotIn(b"B" * 43, body)

    def test_existing_transports_are_unchanged(self):
        status, body = self._profile("reality")
        self.assertEqual(status, 200)
        self.assertEqual(
            set(json.loads(body)),
            {"server_address", "server_port", "uuid", "flow", "server_name", "fingerprint", "reality_public_key", "short_id"},
        )
        self.assertEqual(self._profile("xhttp")[0], 200)

    def test_not_configured_fails_closed_with_503(self):
        _cfg, server, credential = self._start(make_xray_app_config)
        status, body = self._profile("reality-xhttp", server=server, credential=credential)
        self.assertEqual(status, 503)
        self.assertIn(b"xray_reality_xhttp_not_configured", body)


if __name__ == "__main__":
    unittest.main()
