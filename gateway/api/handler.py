"""HTTP request handling for POST /v1/peers - the only endpoint.

No other endpoint mutates state; no GET/DELETE/admin/token-issuance routes
exist in this slice. See gateway/api/__init__.py for the architectural
invariant this handler is built around: it never touches awg0.conf,
.provision.lock, or a private key directly - it only calls
gateway/scripts/provision-peer.sh (via provision.py) and reads the
enrollment-token store read-only (via tokens.py).
"""
import hmac
import json
import logging
import re
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from . import provision, tokens
from .wgkey import is_valid_wg_public_key

logger = logging.getLogger("pocvpn.api")

_PATH_PEERS = "/v1/peers"
_MAX_BODY_BYTES = 1024
_BEARER_PREFIX = "Bearer "
_SOCKET_TIMEOUT_SECONDS = 5.0

# ASCII decimal digits only - deliberately NOT Python's int(), which also
# accepts a leading "+", "_" digit-group separators (e.g. "1_024"), and
# any Unicode decimal-digit character (e.g. Arabic-indic digits), any of
# which would silently pass int() but must be rejected here.
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")


def _is_json_content_type(content_type):
    return content_type.split(";", 1)[0].strip().lower() == "application/json"


class _RequestError(Exception):
    """Internal control-flow only - carries the (status, error_code) an
    early validation failure inside _handle_post should respond with.
    Never escapes _handle_post."""

    def __init__(self, status, error_code):
        super().__init__(error_code)
        self.status = status
        self.error_code = error_code


class ProvisioningRequestHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 so Content-Length/Connection framing is well-defined; every
    # response still explicitly sends "Connection: close" and sets
    # close_connection = True (see _dispatch) so a client can never send a
    # second request on the same socket - malformed/extra bytes just get
    # dropped when the socket closes, rather than risking their
    # misinterpretation as the start of a pipelined next request.
    protocol_version = "HTTP/1.1"
    server_version = "pocvpn-api"

    def log_message(self, fmt, *args):
        # Silence BaseHTTPRequestHandler's default stderr access log (which
        # would print the raw request line verbatim, including query
        # strings). All logging goes through _log_request's explicit,
        # allowlisted fields instead - see that method.
        pass

    def setup(self):
        # Bounds every socket operation on this connection (header read AND
        # rfile.read(content_length) for the body) to a few seconds, so a
        # client that opens a connection, declares a Content-Length, and
        # then never sends the body cannot hold a ThreadingHTTPServer
        # worker thread forever. A timeout here surfaces as socket.timeout
        # (an OSError subclass), caught by _dispatch's generic Exception
        # handler like any other failure - no exception detail is ever
        # exposed to the client either way.
        super().setup()
        self.connection.settimeout(_SOCKET_TIMEOUT_SECONDS)

    # --- method dispatch: every verb routes through one place so 404 vs
    # 405 is a deliberate decision, never http.server's default 501 ---
    def do_POST(self):
        self._dispatch("POST")

    def do_GET(self):
        self._dispatch("GET")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def _dispatch(self, method):
        self.close_connection = True
        start = time.monotonic()
        self._log_fields = {}
        status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        try:
            if self.path != _PATH_PEERS:
                status_code = self._error(HTTPStatus.NOT_FOUND, "not_found")
            elif method != "POST":
                status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
            else:
                status_code = self._handle_post()
        except Exception:
            # Deliberately no exception message/repr in the log line - only
            # the exception's type name, so a future refactor that ever
            # raises with sensitive text embedded (body, token, ...) can
            # never leak it through this catch-all.
            exc_type = sys.exc_info()[0]
            logger.error("unhandled_exception exc_type=%s", exc_type.__name__ if exc_type else "unknown")
            try:
                status_code = self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            except Exception:
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        finally:
            self._log_request(method, self.path, int(status_code), time.monotonic() - start)

    # --- POST /v1/peers ---
    def _handle_post(self):
        try:
            return self._handle_post_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_post_inner(self):
        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        # Chunked (or any other) Transfer-Encoding is not supported at all -
        # never attempt to parse it. Checked before Content-Length so a
        # request carrying BOTH headers (a classic request-smuggling shape)
        # is rejected outright, regardless of what Content-Length says.
        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_request")

        content_length = self._read_content_length()

        content_type = self.headers.get("Content-Type", "")
        if not _is_json_content_type(content_type):
            raise _RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")

        token = self._require_bearer_token()

        raw_body = self.rfile.read(content_length)
        public_key = self._parse_and_validate_body(raw_body)
        self._log_fields["pubkey_prefix"] = public_key[:8]

        try:
            lookup = tokens.lookup_token(
                token, self.server.config.token_store_path, self.server.config.token_lock_path
            )
        except tokens.TokenLookupError:
            logger.error("token_store_error")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        full_digest = tokens.token_digest(token)
        self._log_fields["token_digest"] = full_digest[:8]

        if not lookup.found or lookup.status != tokens.ACTIVE:
            # Unknown and revoked are intentionally indistinguishable -
            # same status, same body, no branch-specific side effect.
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")

        if not self.server.per_token_limiter.allow(full_digest):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if not hmac.compare_digest(lookup.expected_public_key, public_key):
            raise _RequestError(HTTPStatus.FORBIDDEN, "forbidden")

        try:
            outcome = provision.run_provision_peer(
                self.server.config.provision_script_path,
                public_key,
                self.server.config.subprocess_timeout_seconds,
            )
        except provision.ProvisionError as exc:
            logger.error("provision_error kind=%s", exc.kind)
            if exc.kind == "exhausted":
                raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "subnet_exhausted")
            if exc.kind == "timeout":
                raise _RequestError(HTTPStatus.GATEWAY_TIMEOUT, "provisioning_timeout")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        self._log_fields["state"] = outcome.state
        self._log_fields["tunnel_ip"] = outcome.ip

        payload = {
            "client_tunnel_ip": outcome.ip,
            "gateway_public_key": self.server.config.gateway_public_key,
            "gateway_tunnel_ip": self.server.config.gateway_tunnel_ip,
            "endpoint_host": self.server.config.endpoint_host,
            "endpoint_port": self.server.config.endpoint_port,
        }
        status = HTTPStatus.CREATED if outcome.state == provision.CREATED else HTTPStatus.OK
        return self._success(status, payload)

    def _require_bearer_token(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith(_BEARER_PREFIX):
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        token = auth_header[len(_BEARER_PREFIX):]
        if not token:
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        return token

    def _read_content_length(self):
        # get_all(), NOT get(): .get() silently returns only the first of
        # several same-named headers, which would let a duplicate
        # Content-Length through unnoticed - exactly the ambiguous framing
        # this must fail closed on, even when every duplicate value is
        # identical.
        values = self.headers.get_all("Content-Length")
        if not values:
            raise _RequestError(HTTPStatus.LENGTH_REQUIRED, "length_required")
        if len(values) > 1:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        raw = values[0].strip()
        if not _CONTENT_LENGTH_RE.match(raw):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        value = int(raw)  # safe: _CONTENT_LENGTH_RE already guarantees ASCII digits only
        if value > _MAX_BODY_BYTES:
            raise _RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large")
        return value

    def _parse_and_validate_body(self, raw_body):
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_json")

        if not isinstance(parsed, dict):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        if set(parsed.keys()) != {"public_key"}:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        public_key = parsed["public_key"]
        if not isinstance(public_key, str):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        if not is_valid_wg_public_key(public_key):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_public_key")

        return public_key

    # --- response helpers ---
    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        return int(status)

    def _error(self, status, error_code):
        return self._write_json(status, {"error": error_code})

    def _success(self, status, payload):
        return self._write_json(status, payload)

    # --- logging: explicit allowlisted fields only, never raw
    # headers/body/token - see module docstring and _log_fields sites
    # above, which are the ONLY places allowed to populate this dict ---
    def _log_request(self, method, path, status_code, elapsed_seconds):
        fields = getattr(self, "_log_fields", {}) or {}
        extra = " ".join(f"{key}={value}" for key, value in fields.items())
        logger.info(
            "request method=%s path=%s status=%s latency_ms=%.2f %s",
            method,
            path,
            status_code,
            elapsed_seconds * 1000.0,
            extra,
        )
