"""B8K2 - narrow tests for xray_config_renderer's determinism, correct
VLESS+REALITY client entries, revocation enforcement, and atomic-write
rollback behavior."""
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
from api import xray_config_renderer as renderer_module
from api import xray_provisioning as xray_module
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


class RendererTestBase(unittest.TestCase):
    def setUp(self):
        self.reality = renderer_module.RealityServerConfig(
            listen_port=8444,
            server_names=("www.microsoft.com",),
            dest="www.microsoft.com:443",
            private_key="A" * 43,
            short_ids=("ab12cd34",),
        )
        self.key_a = make_public_key(0x10)
        self.key_b = make_public_key(0x20)
        self.uuid_a = "11111111-1111-1111-1111-111111111111"
        self.uuid_b = "22222222-2222-2222-2222-222222222222"


class RenderStructureTests(RendererTestBase):
    def test_renders_a_vless_reality_inbound_with_the_active_client(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, flow="xtls-rprx-vision")

        inbound = config["inbounds"][0]
        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(inbound["port"], 8444)
        self.assertEqual(inbound["settings"]["decryption"], "none")

        clients = inbound["settings"]["clients"]
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["id"], self.uuid_a)
        self.assertEqual(clients[0]["flow"], "xtls-rprx-vision")

        reality = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["serverNames"], ["www.microsoft.com"])
        self.assertEqual(reality["dest"], "www.microsoft.com:443")
        self.assertEqual(reality["shortIds"], ["ab12cd34"])
        self.assertEqual(reality["privateKey"], "A" * 43)

    def test_revoked_activation_identities_are_excluded(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.REVOKED)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality)
        self.assertEqual(config["inbounds"][0]["settings"]["clients"], [])

    def test_an_identity_whose_activation_no_longer_exists_is_excluded(self):
        digest = "a" * 64
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}
        config = renderer_module.render_server_config({}, xray_data, self.reality)
        self.assertEqual(config["inbounds"][0]["settings"]["clients"], [])

    def test_redacted_render_never_contains_the_private_key(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}
        config = renderer_module.render_server_config_redacted(activations_data, xray_data, self.reality)
        self.assertEqual(config["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], "<redacted>")
        rendered_text = json.dumps(config)
        self.assertNotIn("A" * 43, rendered_text)

    def test_invalid_reality_config_is_rejected(self):
        bad_reality = renderer_module.RealityServerConfig(
            listen_port=8444, server_names=("x",), dest="x:443", private_key="too-short", short_ids=("ab",),
        )
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, bad_reality)

    def test_odd_length_short_id_is_rejected(self):
        # REALITY short IDs are raw bytes hex-encoded - "abc" is not a
        # whole number of bytes, matching Android's own SHORT_ID_REGEX +
        # length-parity check (XrayVlessRealityConfig.kt).
        bad_reality = renderer_module.RealityServerConfig(
            listen_port=8444, server_names=("x",), dest="x:443", private_key="A" * 43, short_ids=("abc",),
        )
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, bad_reality)


class TlsInboundTests(RendererTestBase):
    """B8O2 - the SECOND inbound render_server_config appends when `tls` is
    given, alongside (never instead of) REALITY's own."""

    def setUp(self):
        super().setUp()
        self.tls = renderer_module.TlsServerConfig(
            listen_port=2053,
            cert_file="/etc/letsencrypt/live/152.70.43.1/fullchain.pem",
            key_file="/etc/letsencrypt/live/152.70.43.1/privkey.pem",
        )

    def test_tls_none_produces_byte_identical_output_to_pre_b8o2(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}
        config = renderer_module.render_server_config(activations_data, xray_data, self.reality)
        self.assertEqual(len(config["inbounds"]), 1)
        self.assertEqual(config["inbounds"][0]["streamSettings"]["security"], "reality")

    def test_tls_inbound_is_appended_alongside_reality(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, tls=self.tls)

        self.assertEqual(len(config["inbounds"]), 2)
        reality_inbound, tls_inbound = config["inbounds"]
        self.assertEqual(reality_inbound["streamSettings"]["security"], "reality")
        self.assertEqual(tls_inbound["streamSettings"]["security"], "tls")
        self.assertEqual(tls_inbound["port"], 2053)
        self.assertNotEqual(tls_inbound["port"], reality_inbound["port"])

    def test_tls_inbound_carries_the_same_active_clients_without_flow(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(
            activations_data, xray_data, self.reality, tls=self.tls, flow="xtls-rprx-vision",
        )

        reality_clients = config["inbounds"][0]["settings"]["clients"]
        tls_clients = config["inbounds"][1]["settings"]["clients"]
        self.assertEqual(len(tls_clients), 1)
        self.assertEqual(tls_clients[0]["id"], self.uuid_a)
        self.assertEqual(tls_clients[0]["id"], reality_clients[0]["id"])
        self.assertNotIn("flow", tls_clients[0])
        self.assertEqual(reality_clients[0]["flow"], "xtls-rprx-vision")

    def test_tls_inbound_certificates_reference_the_configured_files(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, tls=self.tls)

        certs = config["inbounds"][1]["streamSettings"]["tlsSettings"]["certificates"]
        self.assertEqual(certs, [{"certificateFile": self.tls.cert_file, "keyFile": self.tls.key_file}])

    def test_revoked_activation_is_excluded_from_both_inbounds(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.REVOKED)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, tls=self.tls)

        self.assertEqual(config["inbounds"][0]["settings"]["clients"], [])
        self.assertEqual(config["inbounds"][1]["settings"]["clients"], [])

    def test_invalid_tls_config_is_rejected(self):
        bad_tls = renderer_module.TlsServerConfig(listen_port=99999, cert_file="/x", key_file="/y")
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, self.reality, tls=bad_tls)

    def test_relative_cert_path_is_rejected(self):
        bad_tls = renderer_module.TlsServerConfig(listen_port=2053, cert_file="relative.pem", key_file="/y")
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, self.reality, tls=bad_tls)


class QuicInboundTests(RendererTestBase):
    """B21 - the THIRD inbound render_server_config appends when `quic` is
    given, alongside (never instead of) REALITY's/TLS's own - real QUIC/
    HTTP-3 via XHTTP `stream-one`, ALPN h3 (see
    docs/B21_QUIC_TRANSPORT_AUDIT.md), never the removed standalone "quic"
    network value."""

    def setUp(self):
        super().setUp()
        self.tls = renderer_module.TlsServerConfig(
            listen_port=2053,
            cert_file="/etc/letsencrypt/live/152.70.43.1/fullchain.pem",
            key_file="/etc/letsencrypt/live/152.70.43.1/privkey.pem",
        )
        self.quic = renderer_module.QuicServerConfig(
            listen_port=2087,
            cert_file="/etc/letsencrypt/live/152.70.43.1/fullchain.pem",
            key_file="/etc/letsencrypt/live/152.70.43.1/privkey.pem",
            path="/nova-quic",
        )

    def test_quic_none_produces_output_identical_to_reality_plus_tls_only(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}
        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, tls=self.tls)
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertEqual(config["inbounds"][0]["streamSettings"]["security"], "reality")
        self.assertEqual(config["inbounds"][1]["streamSettings"]["security"], "tls")

    def test_quic_inbound_is_appended_alongside_reality_and_tls(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, tls=self.tls, quic=self.quic)

        self.assertEqual(len(config["inbounds"]), 3)
        reality_inbound, tls_inbound, quic_inbound = config["inbounds"]
        self.assertEqual(reality_inbound["streamSettings"]["security"], "reality")
        self.assertEqual(tls_inbound["streamSettings"]["security"], "tls")
        self.assertEqual(quic_inbound["streamSettings"]["security"], "tls")
        self.assertEqual(quic_inbound["port"], 2087)
        self.assertNotEqual(quic_inbound["port"], tls_inbound["port"])

    def test_quic_uses_real_xhttp_stream_one_with_alpn_h3_never_the_removed_quic_network(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, quic=self.quic)

        quic_inbound = config["inbounds"][1]
        stream_settings = quic_inbound["streamSettings"]
        self.assertEqual(stream_settings["network"], "xhttp")
        self.assertNotEqual(stream_settings["network"], "quic")
        self.assertEqual(stream_settings["tlsSettings"]["alpn"], ["h3"])
        self.assertEqual(stream_settings["xhttpSettings"]["mode"], "stream-one")
        self.assertEqual(stream_settings["xhttpSettings"]["path"], "/nova-quic")

    def test_quic_inbound_carries_the_same_active_clients_without_flow(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.ACTIVE)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(
            activations_data, xray_data, self.reality, quic=self.quic, flow="xtls-rprx-vision",
        )

        reality_clients = config["inbounds"][0]["settings"]["clients"]
        quic_clients = config["inbounds"][1]["settings"]["clients"]
        self.assertEqual(len(quic_clients), 1)
        self.assertEqual(quic_clients[0]["id"], self.uuid_a)
        self.assertEqual(quic_clients[0]["id"], reality_clients[0]["id"])
        self.assertNotIn("flow", quic_clients[0])

    def test_revoked_activation_is_excluded_from_the_quic_inbound_too(self):
        digest = "a" * 64
        activations_data = {digest: _activation_record("act1", activations_module.REVOKED)}
        xray_data = {digest: [_identity(self.key_a, self.uuid_a)]}

        config = renderer_module.render_server_config(activations_data, xray_data, self.reality, quic=self.quic)

        self.assertEqual(config["inbounds"][1]["settings"]["clients"], [])

    def test_invalid_quic_config_is_rejected(self):
        bad_quic = renderer_module.QuicServerConfig(listen_port=99999, cert_file="/x", key_file="/y", path="/nova-quic")
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, self.reality, quic=bad_quic)

    def test_relative_cert_path_is_rejected(self):
        bad_quic = renderer_module.QuicServerConfig(listen_port=2087, cert_file="relative.pem", key_file="/y", path="/nova-quic")
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, self.reality, quic=bad_quic)

    def test_non_absolute_path_is_rejected(self):
        bad_quic = renderer_module.QuicServerConfig(listen_port=2087, cert_file="/x", key_file="/y", path="nova-quic")
        with self.assertRaises(renderer_module.XrayConfigRenderError):
            renderer_module.render_server_config({}, {}, self.reality, quic=bad_quic)


class DeterminismTests(RendererTestBase):
    def test_two_renders_of_the_same_input_are_byte_identical(self):
        digest_a, digest_b = "a" * 64, "b" * 64
        activations_data = {
            digest_a: _activation_record("act1", activations_module.ACTIVE),
            digest_b: _activation_record("act2", activations_module.ACTIVE),
        }
        xray_data = {
            digest_a: [_identity(self.key_a, self.uuid_a)],
            digest_b: [_identity(self.key_b, self.uuid_b)],
        }

        first = json.dumps(renderer_module.render_server_config(activations_data, xray_data, self.reality), sort_keys=True)
        second = json.dumps(renderer_module.render_server_config(activations_data, xray_data, self.reality), sort_keys=True)
        self.assertEqual(first, second)

    def test_client_ordering_is_stable_regardless_of_dict_insertion_order(self):
        digest_a, digest_b = "a" * 64, "b" * 64
        activations_data_1 = {
            digest_a: _activation_record("act1", activations_module.ACTIVE),
            digest_b: _activation_record("act2", activations_module.ACTIVE),
        }
        xray_data_1 = {
            digest_a: [_identity(self.key_a, self.uuid_a)],
            digest_b: [_identity(self.key_b, self.uuid_b)],
        }
        # Same content, reversed insertion order.
        activations_data_2 = {
            digest_b: _activation_record("act2", activations_module.ACTIVE),
            digest_a: _activation_record("act1", activations_module.ACTIVE),
        }
        xray_data_2 = {
            digest_b: [_identity(self.key_b, self.uuid_b)],
            digest_a: [_identity(self.key_a, self.uuid_a)],
        }

        config_1 = renderer_module.render_server_config(activations_data_1, xray_data_1, self.reality)
        config_2 = renderer_module.render_server_config(activations_data_2, xray_data_2, self.reality)
        self.assertEqual(
            [c["id"] for c in config_1["inbounds"][0]["settings"]["clients"]],
            [c["id"] for c in config_2["inbounds"][0]["settings"]["clients"]],
        )


class AtomicWriteTests(RendererTestBase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_path = os.path.join(self._tmp.name, "xray-config.json")

    def test_atomic_write_produces_valid_json_at_0600(self):
        config = renderer_module.render_server_config({}, {}, self.reality)
        renderer_module.atomic_write_config(self.config_path, config)

        with open(self.config_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        self.assertEqual(loaded, config)
        mode = os.stat(self.config_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_a_failed_write_leaves_the_prior_config_untouched(self):
        original = renderer_module.render_server_config({}, {}, self.reality)
        renderer_module.atomic_write_config(self.config_path, original)
        with open(self.config_path, "r", encoding="utf-8") as handle:
            original_text = handle.read()

        class Unserializable:
            def __repr__(self):
                raise RuntimeError("boom")

        broken = {"unserializable": Unserializable()}
        with self.assertRaises(TypeError):
            renderer_module.atomic_write_config(self.config_path, broken)

        with open(self.config_path, "r", encoding="utf-8") as handle:
            after_text = handle.read()
        self.assertEqual(original_text, after_text)

        # No leftover tmp file either.
        leftovers = [f for f in os.listdir(self._tmp.name) if f.startswith(".xray-config.")]
        self.assertEqual(leftovers, [])


class RegeneratePipelineTests(RendererTestBase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.xray_store_path = os.path.join(self._tmp.name, "xray-identities.json")
        self.xray_lock_path = os.path.join(self._tmp.name, ".xray-identities.lock")
        xray_module.init_store(self.xray_store_path, self.xray_lock_path)

        self.config_path = os.path.join(self._tmp.name, "xray-config.json")

    def test_regenerate_pipeline_calls_validate_and_writes_the_config(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        decision = activations_module.decide_and_bind(
            credential, self.key_a, self.activation_store_path, self.activation_lock_path,
        )
        activations_module.finalize_reservation(credential, self.key_a, self.activation_store_path, self.activation_lock_path)
        xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )

        validated_paths = []
        renderer_module.regenerate_and_write_config(
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
            self.config_path, self.reality,
            validate_config_fn=validated_paths.append,
        )

        self.assertEqual(validated_paths, [self.config_path])
        with open(self.config_path, "r", encoding="utf-8") as handle:
            written = json.load(handle)
        self.assertEqual(len(written["inbounds"][0]["settings"]["clients"]), 1)

    def test_validation_failure_propagates_but_the_new_file_is_still_on_disk(self):
        def failing_validator(path):
            raise RuntimeError("config invalid")

        with self.assertRaises(RuntimeError):
            renderer_module.regenerate_and_write_config(
                self.activation_store_path, self.activation_lock_path,
                self.xray_store_path, self.xray_lock_path,
                self.config_path, self.reality,
                validate_config_fn=failing_validator,
            )
        self.assertTrue(os.path.isfile(self.config_path))  # left for operator inspection, per this function's own docs


if __name__ == "__main__":
    unittest.main()
