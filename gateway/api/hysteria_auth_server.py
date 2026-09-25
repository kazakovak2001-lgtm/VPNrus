"""B46-4P - the loopback-only HTTP listener the pinned Hysteria2 server's
`auth.type: http` backend calls for every connection attempt (see
hysteria_auth_backend.py for the request/response contract and
hysteria_provisioning.verify_hysteria_auth for the decision logic).

Server-boundary invariant (same as server.py): the bind host is the literal
"127.0.0.1" right here and nowhere else - no configuration value can make
this listener public. A public auth-check endpoint would let anyone probe
which strings are valid Hysteria2 secrets. Only
POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT is configurable, and the process
refuses to start unless the whole Hysteria2 config group is set.

Logging: method/path/status/latency and the boolean outcome only - never
the request body (it carries the presented secret), never `addr`.
"""
import json
import logging
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config as config_module
from . import hysteria_auth_backend, hysteria_provisioning, hysteria_store

logger = logging.getLogger("pocvpn.hysteria_auth")

_BIND_HOST = "127.0.0.1"
_PATH_AUTH = "/auth"
_SOCKET_TIMEOUT_SECONDS = 5.0


class HysteriaAuthRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pocvpn-hysteria-auth"

    def log_message(self, fmt, *args):
        pass  # never the default access log (raw request line) - see _log.

    def setup(self):
        super().setup()
        self.connection.settimeout(_SOCKET_TIMEOUT_SECONDS)

    def do_POST(self):
        self.close_connection = True
        start = time.monotonic()
        ok = False
        status = HTTPStatus.INTERNAL_SERVER_ERROR
        try:
            if self.path != _PATH_AUTH:
                status = self._write(HTTPStatus.NOT_FOUND, b'{"error":"not_found"}')
                return
            raw = self._read_body()
            if raw is None:
                # Oversized/unframed: same fail-closed shape as a wrong secret.
                status = self._write_json_auth(False, "")
                return
            code, response = hysteria_auth_backend.handle_auth_request(raw, self.server.verify_fn)
            ok = bool(response.get("ok"))
            status = self._write_json_auth(ok, response.get("id", ""), code)
        except Exception:
            # Store unavailable or anything unexpected: deny (fail closed),
            # log only the exception type - never a message that could
            # carry request content.
            exc_type = sys.exc_info()[0]
            logger.error("auth_backend_error exc_type=%s", exc_type.__name__ if exc_type else "unknown")
            try:
                status = self._write_json_auth(False, "")
            except Exception:
                status = HTTPStatus.INTERNAL_SERVER_ERROR
        finally:
            logger.info(
                "auth path=%s status=%s ok=%s latency_ms=%.2f",
                self.path if self.path == _PATH_AUTH else "other",
                int(status), ok, (time.monotonic() - start) * 1000.0,
            )

    def do_GET(self):
        self.close_connection = True
        self._write(HTTPStatus.METHOD_NOT_ALLOWED, b'{"error":"method_not_allowed"}')

    def _read_body(self):
        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1 or not values[0].strip().isdigit() or self.headers.get_all("Transfer-Encoding"):
            return None
        length = int(values[0].strip())
        if length > hysteria_auth_backend._MAX_BODY_BYTES:
            return None
        return self.rfile.read(length)

    def _write_json_auth(self, ok, device_id, code=HTTPStatus.OK):
        return self._write(code, json.dumps({"ok": bool(ok), "id": device_id if ok else ""}).encode("utf-8"))

    def _write(self, status, body):
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        return int(status)


class HysteriaAuthServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, verify_fn):
        super().__init__(server_address, handler_class)
        self.verify_fn = verify_fn


def make_verify_fn(app_config):
    def verify(presented_secret):
        return hysteria_provisioning.verify_hysteria_auth(
            presented_secret,
            app_config.activation_store_path, app_config.activation_lock_path,
            app_config.hysteria2_store_path, app_config.hysteria2_lock_path,
        )
    return verify


def build_server(app_config, port=None):
    if not app_config.hysteria2_store_path or not app_config.hysteria2_auth_backend_port:
        raise config_module.ConfigError("Hysteria2 is not configured - the auth backend refuses to start")
    listen_port = app_config.hysteria2_auth_backend_port if port is None else port
    return HysteriaAuthServer((_BIND_HOST, listen_port), HysteriaAuthRequestHandler, make_verify_fn(app_config))


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        app_config = config_module.load_config()
        server = build_server(app_config)
    except config_module.ConfigError as exc:
        print(f"pocvpn-hysteria-auth: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    # Fail at startup, not on the first connection, if the store is absent.
    try:
        hysteria_store.read_store_shared(app_config.hysteria2_store_path, app_config.hysteria2_lock_path)
    except hysteria_store.HysteriaStoreLockError:
        print("pocvpn-hysteria-auth: hysteria2 store unreadable - run init first", file=sys.stderr)
        raise SystemExit(1)
    logger.info("listening on %s:%d", _BIND_HOST, server.server_address[1])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
