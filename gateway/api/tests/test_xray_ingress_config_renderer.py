"""B24 - narrow tests for xray_ingress_config_renderer: real client-facing
authorization reuse, a genuinely non-open upstream relay, per-hop transport
independence, fail-closed validation, and secret redaction."""
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
from api import xray_config_renderer as base_renderer
from api import xray_ingress_config_renderer as renderer_module
from _fixtures import make_public_key


def _activation_record(activation_id, status, max_devices=1, bound_devices=None):
    return {
        "activation_id": activation_id,
        "status": status,
        "max_devices": max_devices,
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": None,
        "bound_devices": bound_devices or [],
    }


def _identity(public_key, vless_uuid):
    return {"device_public_key": public_key, "vless_uuid": vless_uuid, "created_at": "2026-01-01T00:00:00+00:00"}


class IngressRendererTestBase(unittest.TestCase):
    def setUp(self):
        self.reality = base_renderer.RealityServerConfig(
            listen_port=8444,
            server_names=("www.microsoft.com",),
            dest="www.microsoft.com:443",
            private_key="A" * 43,
            short_ids=("ab12cd34",),
        )
        self.tls = base_renderer.TlsServerConfig(
            listen_port=8443,
            cert_file="/etc/nova/fullchain.pem",
            key_file="/etc/nova/privkey.pem",
        )
        self.upstream_reality = renderer_module.UpstreamExitConfig(
            host="203.0.113.60",
            port=8444,
            transport="reality",
            uuid="99999999-9999-9999-9999-999999999999",
            server_name="www.microsoft.com",
            public_key="B" * 43,
            short_id="ef567890",
        )
        self.upstream_tls = renderer_module.UpstreamExitConfig(
            host="203.0.113.60",
            port=8443,
            transport="tls",
            uuid="88888888-8888-8888-8888-888888888888",
            sni="relay-exit.example.test",
        )
        self.key_a = make_public_key(0x10)
        self.uuid_a = "11111111-1111-1111-1111-111111111111"

    def _activations_and_xray(self, status=activations_module.ACTIVE):
        digest = "a" * 64
        return {digest: _activation_record("act1", status)}, {digest: [_identity(self.key_a, self.uuid_a)]}


class ClientAuthorizationReuseTests(IngressRendererTestBase):
    """Task requirement 8 - ingress authorization reuses per-device identity, never a second/open system."""

    def test_only_active_clients_from_activations_appear_in_the_inbound(self):
        activations_data, xray_data = self._activations_and_xray(status=activations_module.ACTIVE)
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        clients = config["inbounds"][0]["settings"]["clients"]
        self.assertEqual(1, len(clients))
        self.assertEqual(self.uuid_a, clients[0]["id"])

    def test_a_revoked_activation_never_appears_in_the_ingress_inbound(self):
        activations_data, xray_data = self._activations_and_xray(status=activations_module.REVOKED)
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        self.assertEqual([], config["inbounds"][0]["settings"]["clients"])

    def test_identity_authorization_is_the_SAME_function_the_real_gateway_renderer_uses(self):
        # Not merely "produces the same result" - literally the same
        # _active_clients call, so there is only ever ONE place this
        # decision is made across both roles.
        self.assertIs(renderer_module.base._active_clients, base_renderer._active_clients)


class NoOpenRelayTests(IngressRendererTestBase):
    """Task requirement L - the renderer cannot generate an unauthenticated/open relay."""

    def test_outbound_is_never_freedom_direct(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        protocols = {o["protocol"] for o in config["outbounds"]}
        self.assertNotIn("freedom", protocols)

    def test_no_direct_or_freedom_outbound_exists_at_all_in_the_rendered_config(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality, tls=self.tls)
        tags = {o["tag"] for o in config["outbounds"]}
        self.assertNotIn("direct", tags)
        self.assertEqual(1, len(config["outbounds"]))

    def test_every_client_facing_inbound_is_routed_exclusively_to_the_upstream_outbound(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality, tls=self.tls)
        rule = config["routing"]["rules"][0]
        self.assertEqual(self.upstream_reality.outbound_tag, rule["outboundTag"])
        self.assertEqual({self.reality.inbound_tag, self.tls.inbound_tag}, set(rule["inboundTag"]))

    def test_the_upstream_outbound_carries_a_real_authenticated_vless_user_id_not_a_bare_forward(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        vnext = config["outbounds"][0]["settings"]["vnext"][0]
        self.assertEqual(self.upstream_reality.host, vnext["address"])
        self.assertEqual(self.upstream_reality.port, vnext["port"])
        self.assertEqual(self.upstream_reality.uuid, vnext["users"][0]["id"])

    def test_a_malformed_upstream_uuid_fails_closed_rather_than_rendering_an_unauthenticated_relay(self):
        activations_data, xray_data = self._activations_and_xray()
        bad_upstream = renderer_module.UpstreamExitConfig(
            host="203.0.113.60", port=8444, transport="reality", uuid="not-a-uuid",
            server_name="www.microsoft.com", public_key="B" * 43, short_id="ef567890",
        )
        with self.assertRaises(renderer_module.IngressConfigRenderError):
            renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, bad_upstream)

    def test_a_blank_upstream_host_fails_closed(self):
        activations_data, xray_data = self._activations_and_xray()
        bad_upstream = renderer_module.UpstreamExitConfig(
            host="", port=8444, transport="reality", uuid=self.upstream_reality.uuid,
            server_name="www.microsoft.com", public_key="B" * 43, short_id="ef567890",
        )
        with self.assertRaises(renderer_module.IngressConfigRenderError):
            renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, bad_upstream)

    def test_an_unsupported_upstream_transport_fails_closed(self):
        activations_data, xray_data = self._activations_and_xray()
        bad_upstream = renderer_module.UpstreamExitConfig(host="203.0.113.60", port=8444, transport="awg", uuid=self.upstream_reality.uuid)
        with self.assertRaises(renderer_module.IngressConfigRenderError):
            renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, bad_upstream)


class PerHopTransportIndependenceTests(IngressRendererTestBase):
    """Task requirement 6/14 - client->ingress transport may differ from ingress->exit transport; never collapsed to one."""

    def test_a_REALITY_client_facing_inbound_with_a_TLS_upstream_outbound(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_tls)
        self.assertEqual("reality", config["inbounds"][0]["streamSettings"]["security"])
        self.assertEqual("tls", config["outbounds"][0]["streamSettings"]["security"])

    def test_a_TLS_client_facing_inbound_with_a_REALITY_upstream_outbound(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality, tls=self.tls)
        tls_inbound = next(i for i in config["inbounds"] if i["tag"] == self.tls.inbound_tag)
        self.assertEqual("tls", tls_inbound["streamSettings"]["security"])
        self.assertEqual("reality", config["outbounds"][0]["streamSettings"]["security"])

    def test_both_hops_may_independently_use_REALITY_without_being_conflated_into_one_shared_setting(self):
        activations_data, xray_data = self._activations_and_xray()
        config = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        inbound_reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        outbound_reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertNotEqual(inbound_reality["privateKey"], outbound_reality["publicKey"])
        self.assertEqual(self.upstream_reality.public_key, outbound_reality["publicKey"])


class DeterminismTests(IngressRendererTestBase):
    def test_two_renders_of_the_same_inputs_are_byte_for_byte_identical(self):
        activations_data, xray_data = self._activations_and_xray()
        a = json.dumps(renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality), sort_keys=True)
        b = json.dumps(renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality), sort_keys=True)
        self.assertEqual(a, b)


class RedactionTests(IngressRendererTestBase):
    """Task requirement 9/M - no secrets serialized into diagnostics/logs."""

    def test_redacted_render_never_contains_the_ingress_private_key(self):
        activations_data, xray_data = self._activations_and_xray()
        redacted = renderer_module.render_ingress_server_config_redacted(activations_data, xray_data, self.reality, self.upstream_reality)
        serialized = json.dumps(redacted)
        self.assertNotIn(self.reality.private_key, serialized)
        self.assertIn("<redacted>", serialized)

    def test_redacted_render_never_contains_the_upstream_relay_uuid(self):
        activations_data, xray_data = self._activations_and_xray()
        redacted = renderer_module.render_ingress_server_config_redacted(activations_data, xray_data, self.reality, self.upstream_reality)
        serialized = json.dumps(redacted)
        self.assertNotIn(self.upstream_reality.uuid, serialized)

    def test_unredacted_render_does_contain_secrets_proving_the_redacted_variant_is_the_one_actually_doing_something(self):
        activations_data, xray_data = self._activations_and_xray()
        full = renderer_module.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream_reality)
        serialized = json.dumps(full)
        self.assertIn(self.reality.private_key, serialized)
        self.assertIn(self.upstream_reality.uuid, serialized)


if __name__ == "__main__":
    unittest.main()
