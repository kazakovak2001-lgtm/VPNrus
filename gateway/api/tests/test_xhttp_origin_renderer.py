"""B35 focused XHTTP origin renderer tests."""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import xray_config_renderer as base
from api import xray_ingress_config_renderer as renderer


class XhttpOriginRendererTests(unittest.TestCase):
    def setUp(self):
        self.reality = base.RealityServerConfig(
            listen_port=8444,
            server_names=("example.org",),
            dest="example.org:443",
            private_key="A" * 43,
            short_ids=("ab12cd34",),
        )
        self.upstream = renderer.UpstreamExitConfig(
            host="203.0.113.60",
            port=8444,
            transport="reality",
            uuid="99999999-9999-9999-9999-999999999999",
            server_name="example.org",
            public_key="B" * 43,
            short_id="ef567890",
            flow="xtls-rprx-vision",
        )
        self.xhttp = renderer.XhttpOriginInboundConfig(
            listen_port=2100,
            host="origin.example.org",
            path="/nova-xhttp/",
            mode="packet-up",
            max_each_post_bytes=524288,
            padding_placement="query",
            padding_min_bytes=1,
            padding_max_bytes=64,
        )
        self.digest = "a" * 64
        self.uuid = "11111111-1111-1111-1111-111111111111"
        self.activations = {
            self.digest: {"activation_id": "act1", "status": activations_module.ACTIVE},
        }
        self.identities = {
            self.digest: [{"device_public_key": "device-public-key", "vless_uuid": self.uuid}],
        }

    def render(self, xhttp=None):
        return renderer.render_ingress_server_config(
            self.activations,
            self.identities,
            self.reality,
            self.upstream,
            xhttp=xhttp or self.xhttp,
        )

    def test_backend_is_hard_loopback_plaintext_xhttp_with_exact_policy(self):
        config = self.render()
        inbound = next(i for i in config["inbounds"] if i["tag"] == self.xhttp.inbound_tag)
        self.assertEqual("127.0.0.1", inbound["listen"])
        self.assertEqual(2100, inbound["port"])
        self.assertEqual("vless", inbound["protocol"])
        self.assertEqual(self.uuid, inbound["settings"]["clients"][0]["id"])
        self.assertNotIn("flow", inbound["settings"]["clients"][0])
        stream = inbound["streamSettings"]
        self.assertEqual("xhttp", stream["network"])
        self.assertEqual("none", stream["security"])
        self.assertNotIn("tlsSettings", stream)
        self.assertNotIn("realitySettings", stream)
        policy = stream["xhttpSettings"]
        self.assertEqual("origin.example.org", policy["host"])
        self.assertEqual("/nova-xhttp/", policy["path"])
        self.assertEqual("packet-up", policy["mode"])
        self.assertEqual(524288, policy["scMaxEachPostBytes"])
        self.assertEqual("1-64", policy["xPaddingBytes"])
        self.assertEqual("query", policy["xPaddingPlacement"])

    def test_reuses_activation_authority_and_revocation(self):
        expected = base._vless_clients(
            base._active_clients(self.activations, self.identities),
            flow=None,
        )
        inbound = next(i for i in self.render()["inbounds"] if i["tag"] == self.xhttp.inbound_tag)
        self.assertEqual(expected, inbound["settings"]["clients"])
        self.activations[self.digest]["status"] = activations_module.REVOKED
        revoked = next(i for i in self.render()["inbounds"] if i["tag"] == self.xhttp.inbound_tag)
        self.assertEqual([], revoked["settings"]["clients"])

    def test_xhttp_routes_only_to_authenticated_upstream_never_freedom(self):
        config = self.render()
        self.assertNotIn("freedom", {o["protocol"] for o in config["outbounds"]})
        self.assertEqual(1, len(config["outbounds"]))
        rule = config["routing"]["rules"][0]
        self.assertIn(self.xhttp.inbound_tag, rule["inboundTag"])
        self.assertEqual(self.upstream.outbound_tag, rule["outboundTag"])

    def test_streaming_auto_and_disabled_padding_fail_closed(self):
        for mode in ("auto", "stream-up", "stream-one"):
            bad = renderer.XhttpOriginInboundConfig(
                2100, "origin.example.org", "/nova-xhttp/", mode,
                524288, "query", 1, 64,
            )
            with self.assertRaises(renderer.IngressConfigRenderError):
                self.render(bad)
        disabled = renderer.XhttpOriginInboundConfig(
            2100, "origin.example.org", "/nova-xhttp/", "packet-up",
            524288, "none", 0, 0,
        )
        with self.assertRaises(renderer.IngressConfigRenderError):
            self.render(disabled)


if __name__ == "__main__":
    unittest.main()
