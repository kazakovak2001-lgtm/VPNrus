"""REALITY + XHTTP - the fourth Xray inbound: structure, shared identity and
entitlement, redaction of every REALITY private key, Exit Target ACL
coverage, and that omitting it leaves the rendered config unchanged."""
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import exit_target_policy
from api import xray_config_renderer as renderer_module
from test_xray_config_renderer import RendererTestBase, _activation_record, _identity


class RealityXhttpInboundTests(RendererTestBase):
    def setUp(self):
        super().setUp()
        self.reality_xhttp = renderer_module.RealityXhttpServerConfig(listen_port=8443, path="/nova-rx/")
        digest = "a" * 64
        self.activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        self.xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

    def _render(self, **kwargs):
        return renderer_module.render_server_config(
            self.activations_data, self.xray_data, self.reality, flow="xtls-rprx-vision", **kwargs,
        )

    def test_omitted_reality_xhttp_leaves_the_config_unchanged(self):
        xhttp = renderer_module.XhttpServerConfig(listen_port=2099, path="/nova-xhttp/")
        self.assertEqual(self._render(xhttp=xhttp), self._render(xhttp=xhttp, reality_xhttp=None))

    def test_inbound_is_xhttp_secured_by_reality_on_a_public_port(self):
        inbound = self._render(reality_xhttp=self.reality_xhttp)["inbounds"][-1]
        self.assertEqual(inbound["tag"], "nova-vless-reality-xhttp-in")
        self.assertEqual(inbound["listen"], "0.0.0.0")
        self.assertEqual(inbound["port"], 8443)
        stream = inbound["streamSettings"]
        self.assertEqual((stream["network"], stream["security"]), ("xhttp", "reality"))
        self.assertEqual(stream["xhttpSettings"], {"path": "/nova-rx/", "mode": "packet-up"})

    def test_reuses_the_reality_key_material_of_the_reality_inbound(self):
        inbounds = self._render(reality_xhttp=self.reality_xhttp)["inbounds"]
        self.assertEqual(inbounds[0]["streamSettings"]["realitySettings"], inbounds[-1]["streamSettings"]["realitySettings"])

    def test_same_clients_as_reality_but_never_a_flow(self):
        inbounds = self._render(reality_xhttp=self.reality_xhttp)["inbounds"]
        clients = inbounds[-1]["settings"]["clients"]
        self.assertEqual([c["id"] for c in clients], [c["id"] for c in inbounds[0]["settings"]["clients"]])
        self.assertTrue(all("flow" not in c for c in clients))

    def test_revoked_activation_is_excluded(self):
        self.activations_data = {"a" * 64: _activation_record("act1", activations_module.REVOKED)}
        inbound = self._render(reality_xhttp=self.reality_xhttp)["inbounds"][-1]
        self.assertEqual(inbound["settings"]["clients"], [])

    def test_redacted_render_hides_the_private_key_in_every_reality_inbound(self):
        config = renderer_module.render_server_config_redacted(
            self.activations_data, self.xray_data, self.reality, reality_xhttp=self.reality_xhttp,
        )
        self.assertNotIn("A" * 43, json.dumps(config))
        redacted = [i["streamSettings"]["realitySettings"]["privateKey"] for i in config["inbounds"]
                    if "realitySettings" in i["streamSettings"]]
        self.assertEqual(redacted, ["<redacted>", "<redacted>"])

    def test_exit_target_acl_still_covers_the_new_inbound(self):
        config = self._render(reality_xhttp=self.reality_xhttp)
        rule = config["routing"]["rules"][0]
        self.assertEqual(rule, exit_target_policy.xray_routing_block_rule())
        # Inbound-agnostic: no inboundTag filter, so the new tag is covered too.
        self.assertNotIn("inboundTag", rule)
        self.assertIn("finalRules", config["outbounds"][0]["settings"])

    def test_port_clash_with_any_other_inbound_is_rejected(self):
        tls = renderer_module.TlsServerConfig(listen_port=2053, cert_file="/a", key_file="/b")
        for port in (self.reality.listen_port, 2053):
            clash = renderer_module.RealityXhttpServerConfig(listen_port=port, path="/nova-rx/")
            with self.subTest(port=port), self.assertRaises(renderer_module.XrayConfigRenderError):
                self._render(tls=tls, reality_xhttp=clash)

    def test_malformed_path_and_mode_are_rejected(self):
        for bad in (
            renderer_module.RealityXhttpServerConfig(listen_port=8443, path="nova-rx/"),
            renderer_module.RealityXhttpServerConfig(listen_port=8443, path="/nova-rx"),
            renderer_module.RealityXhttpServerConfig(listen_port=8443, path="/nova-rx/", mode="stream-one"),
            renderer_module.RealityXhttpServerConfig(listen_port=0, path="/nova-rx/"),
        ):
            with self.subTest(bad=bad), self.assertRaises(renderer_module.XrayConfigRenderError):
                self._render(reality_xhttp=bad)


if __name__ == "__main__":
    unittest.main()
