"""Fan-out client: asks every registered node for GET /admin/gateway.

Least privilege: the hub logs in with each node's *viewer* secret only. If a
secret turns out to grant the admin role, the node is reported MISCONFIGURED,
the session is closed immediately and nothing is fetched with it. Requests go
only to registry loopback addresses, never follow redirects, are bounded in
time and size, and results never contain secrets, cookies or CSRF tokens.
"""
import http.client
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from api import admin_auth

OK = "OK"
UNREACHABLE = "UNREACHABLE"
AUTH_FAILED = "AUTH_FAILED"
MISCONFIGURED = "MISCONFIGURED"
ERROR = "ERROR"

_COOKIE = "pocvpn-admin-session"


class _Failure(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class Hub:
    def __init__(self, nodes, timeout=3.0, max_bytes=64 * 1024):
        self._nodes = list(nodes)
        self._timeout = timeout
        self._max_bytes = max_bytes
        # Secrets stay in memory only; read once and validated by the same
        # reader the gateways use.
        self._secrets = {n.id: admin_auth.read_admin_secret(n.viewer_secret_file) for n in self._nodes}
        self._sessions = {}  # node id -> session cookie value
        self._lock = threading.Lock()

    # -- low-level -------------------------------------------------------
    def _request(self, node, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection(node.host, node.port, timeout=self._timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read(self._max_bytes + 1)
            if len(data) > self._max_bytes:
                raise _Failure(ERROR, "response_too_large")
            return resp.status, resp.getheader("Set-Cookie", ""), data
        except socket.timeout:
            raise _Failure(UNREACHABLE, "timeout")
        except (OSError, http.client.HTTPException):
            raise _Failure(UNREACHABLE, "connection_failed")
        finally:
            conn.close()

    @staticmethod
    def _json(data):
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _Failure(ERROR, "malformed_response")
        if not isinstance(parsed, dict):
            raise _Failure(ERROR, "malformed_response")
        return parsed

    def _logout(self, node, cookie, csrf):
        origin = f"http://{node.host}:{node.port}"
        try:
            self._request(
                node, "POST", "/admin/logout",
                {"Cookie": f"{_COOKIE}={cookie}", "X-CSRF-Token": csrf, "Origin": origin, "Content-Length": "0"},
                b"",
            )
        except _Failure:
            pass

    def _login(self, node):
        body = json.dumps({"password": self._secrets[node.id].decode("ascii")}).encode()
        status, set_cookie, data = self._request(
            node, "POST", "/admin/login",
            {"Content-Type": "application/json", "Content-Length": str(len(body))}, body,
        )
        if status in (400, 401):
            raise _Failure(AUTH_FAILED, "login_rejected")
        if status == 429:
            raise _Failure(ERROR, "rate_limited")
        if status != 200:
            raise _Failure(ERROR, f"http_{status}")
        parsed = self._json(data)
        cookie = ""
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith(_COOKIE + "="):
                cookie = part.split("=", 1)[1]
        if not cookie or not isinstance(parsed.get("csrf_token"), str):
            raise _Failure(ERROR, "malformed_response")
        if parsed.get("role") != "viewer":
            self._logout(node, cookie, parsed["csrf_token"])
            raise _Failure(MISCONFIGURED, "secret_is_not_a_viewer_credential")
        return cookie

    def _get_gateway(self, node, cookie):
        status, _, data = self._request(node, "GET", "/admin/gateway", {"Cookie": f"{_COOKIE}={cookie}"})
        if status == 401:
            return None
        if status == 429:
            raise _Failure(ERROR, "rate_limited")
        if status != 200:
            raise _Failure(ERROR, f"http_{status}")
        return self._json(data)

    # -- per node --------------------------------------------------------
    def _fetch_one(self, node):
        started = time.monotonic()
        result = {"id": node.id, "name": node.name, "role": node.role, "status": OK, "detail": "", "gateway": None}
        try:
            with self._lock:
                cookie = self._sessions.get(node.id)
            gateway = self._get_gateway(node, cookie) if cookie else None
            if gateway is None:
                cookie = self._login(node)
                with self._lock:
                    self._sessions[node.id] = cookie
                gateway = self._get_gateway(node, cookie)
                if gateway is None:
                    raise _Failure(ERROR, "session_rejected")
            result["gateway"] = gateway
        except _Failure as failure:
            result["status"], result["detail"] = failure.status, failure.detail
            with self._lock:
                self._sessions.pop(node.id, None)
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return result

    # -- all nodes -------------------------------------------------------
    def fetch_all(self):
        """One result per registered node, in registry order. A slow or dead
        node degrades only its own entry."""
        deadline = self._timeout * 4 + 1
        pool = ThreadPoolExecutor(max_workers=min(8, len(self._nodes)))
        try:
            futures = [pool.submit(self._fetch_one, n) for n in self._nodes]
            results = []
            for node, future in zip(self._nodes, futures):
                try:
                    results.append(future.result(timeout=deadline))
                except FutureTimeout:
                    results.append({
                        "id": node.id, "name": node.name, "role": node.role,
                        "status": UNREACHABLE, "detail": "timeout", "gateway": None, "latency_ms": None,
                    })
            return results
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
