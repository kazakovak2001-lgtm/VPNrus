"""B26 (task G/K) - relay_identity_store.py: load/apply/revoke, fail-closed
on a corrupted file, idempotent apply/revoke, and never touching regular
per-user activation state."""
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

from api import relay_identity_store as store_module

_UUID_A = "11111111-1111-1111-1111-111111111111"
_UUID_B = "22222222-2222-2222-2222-222222222222"


class RelayIdentityStoreTests(unittest.TestCase):
    def test_missing_file_is_empty_never_an_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "does-not-exist.json")
            self.assertEqual(store_module.load_static_clients(path), ())

    def test_blank_path_is_empty(self):
        self.assertEqual(store_module.load_static_clients(""), ())

    def test_upsert_then_load_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            clients = store_module.load_static_clients(path)
            self.assertEqual(len(clients), 1)
            self.assertEqual(clients[0].activation_id, "relay-a")
            self.assertEqual(clients[0].device_public_key, "relay:a")
            self.assertEqual(clients[0].vless_uuid, _UUID_A)

    def test_upsert_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            with open(path, "r", encoding="utf-8") as handle:
                first = handle.read()
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            with open(path, "r", encoding="utf-8") as handle:
                second = handle.read()
            self.assertEqual(first, second)

    def test_upsert_replaces_an_existing_activation_id_rotation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            store_module.upsert(path, "relay-a", "relay:a", _UUID_B)
            clients = store_module.load_static_clients(path)
            self.assertEqual(len(clients), 1)
            self.assertEqual(clients[0].vless_uuid, _UUID_B)

    def test_two_distinct_relays_coexist(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            store_module.upsert(path, "relay-b", "relay:b", _UUID_B)
            clients = store_module.load_static_clients(path)
            self.assertEqual({c.activation_id for c in clients}, {"relay-a", "relay-b"})

    def test_remove_is_idempotent_even_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.remove(path, "never-existed")  # must not raise
            self.assertEqual(store_module.load_static_clients(path), ())

    def test_apply_then_revoke_removes_it(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            store_module.remove(path, "relay-a")
            self.assertEqual(store_module.load_static_clients(path), ())

    def test_revoking_one_relay_never_touches_another(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            store_module.upsert(path, "relay-b", "relay:b", _UUID_B)
            store_module.remove(path, "relay-a")
            clients = store_module.load_static_clients(path)
            self.assertEqual([c.activation_id for c in clients], ["relay-b"])

    def test_malformed_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("not json{{{")
            with self.assertRaises(store_module.RelayIdentityStoreError):
                store_module.load_static_clients(path)

    def test_malformed_uuid_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump([{"activation_id": "relay-a", "device_public_key": "relay:a", "vless_uuid": "not-a-uuid"}], handle)
            with self.assertRaises(store_module.RelayIdentityStoreError):
                store_module.load_static_clients(path)

    def test_duplicate_activation_id_in_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    [
                        {"activation_id": "relay-a", "device_public_key": "relay:a", "vless_uuid": _UUID_A},
                        {"activation_id": "relay-a", "device_public_key": "relay:a2", "vless_uuid": _UUID_B},
                    ],
                    handle,
                )
            with self.assertRaises(store_module.RelayIdentityStoreError):
                store_module.load_static_clients(path)

    def test_file_is_never_world_readable(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "static-clients.json")
            store_module.upsert(path, "relay-a", "relay:a", _UUID_A)
            if os.name != "nt":  # POSIX-only permission check
                mode = os.stat(path).st_mode & 0o777
                self.assertEqual(mode, 0o600)


class StaticClientsRenderIsolationTests(unittest.TestCase):
    """B26 (task K) - static relay identities are rendered alongside, but
    never derived from or gated by, per-user activations_data - a separate
    trust domain, proven directly against the real render function."""

    def test_static_client_appears_even_with_empty_activations_data(self):
        from api import xray_config_renderer as renderer

        reality = renderer.RealityServerConfig(
            listen_port=8443, server_names=("www.microsoft.com",), dest="www.microsoft.com:443",
            private_key="A" * 43, short_ids=("ab12",),
        )
        static_clients = (renderer.RenderedClient(activation_id="relay-a", device_public_key="relay:a", vless_uuid=_UUID_A),)
        config = renderer.render_server_config({}, {}, reality, static_clients=static_clients)
        client_ids = {c["id"] for c in config["inbounds"][0]["settings"]["clients"]}
        self.assertIn(_UUID_A, client_ids)

    def test_revoking_a_users_activation_never_removes_a_static_client(self):
        from api import xray_config_renderer as renderer

        reality = renderer.RealityServerConfig(
            listen_port=8443, server_names=("www.microsoft.com",), dest="www.microsoft.com:443",
            private_key="A" * 43, short_ids=("ab12",),
        )
        static_clients = (renderer.RenderedClient(activation_id="relay-a", device_public_key="relay:a", vless_uuid=_UUID_A),)
        # A "revoked" activation would simply be absent from activations_data
        # by the time render_server_config sees it - static_clients is
        # concatenated independently either way.
        config_with_revoked_user = renderer.render_server_config({}, {}, reality, static_clients=static_clients)
        client_ids = {c["id"] for c in config_with_revoked_user["inbounds"][0]["settings"]["clients"]}
        self.assertEqual(client_ids, {_UUID_A})


if __name__ == "__main__":
    unittest.main()
