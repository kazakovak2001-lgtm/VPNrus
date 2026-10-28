"""Local HTTP face of the hub: GET /hub/nodes, loopback only, read-only.

Browser safety: it binds to 127.0.0.1, sends no CORS headers (a foreign page
cannot read the response) and rejects any Host header other than its own
address (DNS rebinding). Results are cached for a few seconds so a busy UI
cannot hammer the gateways. Responses carry node names, roles and status only
- never tunnel addresses, secrets or cookies.
"""
import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND_HOST = "127.0.0.1"
PATH_NODES = "/hub/nodes"


class HubServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port, hub, min_interval=5.0, clock=time.monotonic):
        super().__init__((BIND_HOST, port), _Handler)
        self.hub = hub
        self._min_interval = min_interval
        self._clock = clock
        self._cache = None
        self._cache_at = 0.0
        self._cache_lock = threading.Lock()

    def allowed_hosts(self):
        port = self.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def snapshot(self):
        with self._cache_lock:
            now = self._clock()
            if self._cache is None or now - self._cache_at >= self._min_interval:
                self._cache = {"nodes": self.hub.fetch_all(), "generated_at": time.time()}
                self._cache_at = now
            return self._cache


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pocvpn-hub"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        self.close_connection = True
        if self.headers.get("Host") not in self.server.allowed_hosts():
            return self._send(HTTPStatus.FORBIDDEN, {"error": "host_not_allowed"})
        if self.path != PATH_NODES:
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        if method != "GET":
            return self._send(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method_not_allowed"})
        return self._send(HTTPStatus.OK, self.server.snapshot())

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PATCH(self):
        self._handle("PATCH")
