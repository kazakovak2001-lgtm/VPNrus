"""Local admin hub: node registry, fan-out client and the loopback HTTP face."""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from _fixtures import RunningServer, make_activation_store, make_app_config
from admin_hub import client, registry, server

ADMIN_PW_A, VIEWER_PW_A = "a" * 32, "v" * 32
ADMIN_PW_B, VIEWER_PW_B = "b" * 32, "w" * 32


def _secret(directory, name, value):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(value.encode())
    os.chmod(path, 0o600)
    return path


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.secret = _secret(self._tmp.name, "viewer", VIEWER_PW_A)

    def _entry(self, **over):
        entry = {"id": "fra", "name": "Frankfurt", "role": "primary",
                 "url": "http://127.0.0.1:18787", "viewer_secret_file": self.secret}
        entry.update(over)
        return entry

    def _parse(self, *entries):
        return registry.parse_registry(json.dumps({"nodes": list(entries)}))

    def test_valid_registry(self):
        nodes = self._parse(self._entry(), self._entry(id="sto", url="http://localhost:18788"))
        self.assertEqual([(n.id, n.host, n.port) for n in nodes], [("fra", "127.0.0.1", 18787), ("sto", "localhost", 18788)])

    def test_rejects_unsafe_or_malformed_entries(self):
        bad = [
            self._entry(url="http://203.0.113.5:8787"),          # not loopback
            self._entry(url="http://example.com:8787"),
            self._entry(url="https://127.0.0.1:8787"),           # not the tunnel scheme
            self._entry(url="http://user:pw@127.0.0.1:8787"),    # credentials in url
            self._entry(url="http://127.0.0.1"),                 # no port
            self._entry(url="http://127.0.0.1:8787/admin"),      # path
            self._entry(url="http://127.0.0.1:8787?x=1"),
            self._entry(id="Bad Id"),
            self._entry(role="Has Space"),
            self._entry(name=""),
            self._entry(viewer_secret_file="relative/secret"),
            self._entry(viewer_secret_file=os.path.join(self._tmp.name, "missing")),
            {**self._entry(), "extra": 1},
        ]
        for entry in bad:
            with self.assertRaises(registry.RegistryError, msg=entry):
                self._parse(entry)

    def test_rejects_duplicate_ids_empty_and_bad_json(self):
        with self.assertRaises(registry.RegistryError):
            self._parse(self._entry(), self._entry())
        for raw in ("{}", '{"nodes": []}', '{"nodes": {}}', "not json", '{"nodes": [1]}'):
            with self.assertRaises(registry.RegistryError, msg=raw):
                registry.parse_registry(raw)

    def test_rejects_invalid_or_loose_secret_file(self):
        short = _secret(self._tmp.name, "short", "tooshort")
        with self.assertRaises(registry.RegistryError):
            self._parse(self._entry(viewer_secret_file=short))
        if os.name == "posix":
            os.chmod(self.secret, 0o644)
            with self.assertRaises(registry.RegistryError):
                self._parse(self._entry())

    def test_load_registry_missing_file(self):
        with self.assertRaises(registry.RegistryError):
            registry.load_registry(os.path.join(self._tmp.name, "nope.json"))


class _Gateways(unittest.TestCase):
    """Two real dev gateways (admin + viewer secrets, own activation store)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = self._tmp.name
        script = os.path.join(d, "prov.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\nexit 0\n")
        self.servers = {}
        self.viewer_files = {}
        for key, admin_pw, viewer_pw, count in (("a", ADMIN_PW_A, VIEWER_PW_A, 1), ("b", ADMIN_PW_B, VIEWER_PW_B, 2)):
            node_dir = os.path.join(d, key)
            os.makedirs(node_dir)
            store = os.path.join(node_dir, "act.json")
            records = [(f"cred-{key}-{i}", {
                "activation_id": f"{i}{key}" * 16, "status": "ACTIVE", "max_devices": 1,
                "created_at": "2026-10-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00+00:00",
                "bound_devices": [],
            }) for i in range(count)]
            make_activation_store(store, store + ".lock", records)
            os.chmod(store, 0o600)
            cfg = make_app_config(
                node_dir, script,
                admin_secret_file=_secret(node_dir, "admin", admin_pw),
                admin_viewer_secret_file=_secret(node_dir, "viewer", viewer_pw),
                activation_store_path=store, activation_lock_path=store + ".lock",
            )
            srv = RunningServer(cfg)
            self.addCleanup(srv.close)
            self.servers[key] = srv
            self.viewer_files[key] = os.path.join(node_dir, "viewer")
        self.admin_files = {k: os.path.join(d, k, "admin") for k in "ab"}

    def node(self, key, node_id, **over):
        fields = dict(id=node_id, name=node_id.title(), role="edge", host="127.0.0.1",
                      port=self.servers[key].port, viewer_secret_file=self.viewer_files[key])
        fields.update(over)
        return registry.Node(**fields)


class HubClientTests(_Gateways):
    def test_two_nodes_report_ok_with_their_own_data(self):
        hub = client.Hub([self.node("a", "alpha"), self.node("b", "beta")])
        results = hub.fetch_all()
        self.assertEqual([r["id"] for r in results], ["alpha", "beta"])
        self.assertEqual([r["status"] for r in results], [client.OK, client.OK])
        self.assertEqual([r["gateway"]["activations"]["total"] for r in results], [1, 2])

    def test_dead_node_degrades_only_itself(self):
        dead = self.node("a", "dead", port=_free_port())
        results = client.Hub([dead, self.node("b", "beta")]).fetch_all()
        self.assertEqual((results[0]["status"], results[0]["detail"]), (client.UNREACHABLE, "connection_failed"))
        self.assertEqual(results[1]["status"], client.OK)

    def test_wrong_viewer_secret_is_auth_failed(self):
        wrong = _secret(self._tmp.name, "wrong", "z" * 32)
        results = client.Hub([self.node("a", "alpha", viewer_secret_file=wrong)]).fetch_all()
        self.assertEqual((results[0]["status"], results[0]["gateway"]), (client.AUTH_FAILED, None))

    def test_admin_secret_is_refused_and_its_session_closed(self):
        node = self.node("a", "alpha", viewer_secret_file=self.admin_files["a"])
        results = client.Hub([node]).fetch_all()
        self.assertEqual((results[0]["status"], results[0]["gateway"]), (client.MISCONFIGURED, None))
        self.assertEqual(len(self.servers["a"].srv.admin_authenticator._sessions), 0)

    def test_session_is_reused_and_recovered_after_server_side_loss(self):
        hub = client.Hub([self.node("a", "alpha")])
        auth = self.servers["a"].srv.admin_authenticator
        self.assertEqual(hub.fetch_all()[0]["status"], client.OK)
        self.assertEqual(hub.fetch_all()[0]["status"], client.OK)
        self.assertEqual(len(auth._sessions), 1)  # no second login
        auth._sessions.clear()
        self.assertEqual(hub.fetch_all()[0]["status"], client.OK)  # transparent re-login
        self.assertEqual(len(auth._sessions), 1)

    def test_results_never_contain_secrets_or_cookies(self):
        hub = client.Hub([self.node("a", "alpha"), self.node("b", "beta")])
        text = json.dumps(hub.fetch_all())
        for forbidden in (VIEWER_PW_A, VIEWER_PW_B, ADMIN_PW_A, "csrf", "pocvpn-admin-session", self._tmp.name):
            self.assertNotIn(forbidden, text)

    def _raw_server(self, behavior):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)

        def run():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    conn.recv(65536)
                    behavior(conn)
                except OSError:
                    pass

        threading.Thread(target=run, daemon=True).start()
        return listener.getsockname()[1]

    def test_silent_node_times_out(self):
        port = self._raw_server(lambda conn: threading.Event().wait(1.5))
        results = client.Hub([self.node("a", "slow", port=port)], timeout=0.3).fetch_all()
        self.assertEqual((results[0]["status"], results[0]["detail"]), (client.UNREACHABLE, "timeout"))

    def test_oversized_response_is_rejected(self):
        def flood(conn):
            body = b"x" * 5000
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

        port = self._raw_server(flood)
        results = client.Hub([self.node("a", "big", port=port)], max_bytes=1000).fetch_all()
        self.assertEqual((results[0]["status"], results[0]["detail"]), (client.ERROR, "response_too_large"))

    def test_redirect_is_not_followed(self):
        def redirect(conn):
            conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://203.0.113.9/\r\nContent-Length: 0\r\n\r\n")

        port = self._raw_server(redirect)
        results = client.Hub([self.node("a", "redir", port=port)]).fetch_all()
        self.assertEqual(results[0]["status"], client.ERROR)


class HubServerTests(_Gateways):
    def setUp(self):
        super().setUp()
        self.hub = client.Hub([self.node("a", "alpha"), self.node("b", "beta")])
        self.srv = server.HubServer(0, self.hub, min_interval=0.0)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.port = self.srv.server_address[1]

    def _stop(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _http(self, method, path, host=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method)
        req.add_header("Host", host or f"127.0.0.1:{self.port}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, dict(exc.headers), exc.read()
            finally:
                exc.close()

    def test_nodes_endpoint_shape_and_no_leaks(self):
        status, headers, body = self._http("GET", "/hub/nodes")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        data = json.loads(body)
        self.assertEqual([n["id"] for n in data["nodes"]], ["alpha", "beta"])
        self.assertEqual({n["status"] for n in data["nodes"]}, {client.OK})
        text = body.decode()
        for forbidden in (str(self.servers["a"].port), VIEWER_PW_A, "csrf", self._tmp.name, "127.0.0.1"):
            self.assertNotIn(forbidden, text)

    def test_binds_loopback_only(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")

    def test_foreign_host_header_is_rejected(self):
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1"):
            status, _, _ = self._http("GET", "/hub/nodes", host=host)
            self.assertEqual(status, 403, host)
        self.assertEqual(self._http("GET", "/hub/nodes", host=f"localhost:{self.port}")[0], 200)

    def test_only_get_on_the_one_path(self):
        self.assertEqual(self._http("POST", "/hub/nodes")[0], 405)
        self.assertEqual(self._http("DELETE", "/hub/nodes")[0], 405)
        self.assertEqual(self._http("GET", "/hub/other")[0], 404)

    def test_snapshot_is_cached_between_requests(self):
        self.srv._min_interval = 60.0
        with mock.patch.object(self.hub, "fetch_all", wraps=self.hub.fetch_all) as spy:
            self.assertEqual(self._http("GET", "/hub/nodes")[0], 200)
            self.assertEqual(self._http("GET", "/hub/nodes")[0], 200)
            self.assertEqual(spy.call_count, 1)


if __name__ == "__main__":
    unittest.main()
