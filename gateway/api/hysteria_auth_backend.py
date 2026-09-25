"""B46-4A - the internal `auth.type: http` backend the pinned Hysteria2
server (upstream `apernet/hysteria`, commit
`e1366b173ccf5706e1e4630fe8aa654a4b574085`) calls for every real connection
attempt, per `extras/auth/http.go`'s own `HTTPAuthenticator.Authenticate`:
POST `{"addr": "<client ip:port>", "auth": "<presented secret>", "tx": <uint64>}`,
expects back `{"ok": <bool>, "id": "<non-secret label>"}`.

This module is a THIN request/response adapter only - all real decision
logic (hash comparison, live activation-state check) lives in
gateway/api/hysteria_provisioning.verify_hysteria_auth, unit-tested
independently of any HTTP framing.

DEPLOYMENT BOUNDARY (B46-4A does not cross this - see
docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "server deployment
proposal" section): this endpoint must be reachable ONLY from the Hysteria2
server process on the SAME host - bound to `127.0.0.1`/a Unix domain
socket, never a public interface, with a firewall rule (or the loopback
binding alone) enforcing that. It must never require the internet-facing
nginx edge, and must never itself be internet-routable - a public HTTP
auth-check endpoint would let anyone probe which arbitrary strings are
valid Hysteria2 secrets. No code in this module opens a socket or binds a
port; the loopback-only listener that calls it is
gateway/api/hysteria_auth_server.py (unit: pocvpn-hysteria-auth.service).
"""
import ipaddress
import json

_MAX_AUTH_LENGTH = 4096  # generous upper bound - the real secret is 64 hex chars; this only guards against an absurd/malicious body.
_MAX_BODY_BYTES = 8192


class MalformedAuthRequest(Exception):
    """The request body failed structural validation - caller returns HTTP 400, never a raw stack trace, never echoes the body."""


def _validate_addr(addr):
    # Hysteria's own httpAuthRequest.Addr is `net.Addr.String()` - typically
    # "host:port". Validated loosely (never rejects a legitimate client) but
    # bounded in length and never logged with the auth secret alongside it
    # at anything above a coarse, non-identifying level (see
    # handle_auth_request's own doc on what callers may log).
    if not isinstance(addr, str) or not addr or len(addr) > 128:
        raise MalformedAuthRequest("addr missing, blank, or implausibly long")
    return addr


def parse_auth_request(raw_body_bytes):
    if len(raw_body_bytes) > _MAX_BODY_BYTES:
        raise MalformedAuthRequest("request body too large")
    try:
        body = json.loads(raw_body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedAuthRequest(f"request body is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(body, dict) or set(body.keys()) != {"addr", "auth", "tx"}:
        raise MalformedAuthRequest("request body does not have exactly the required fields")

    addr = _validate_addr(body["addr"])
    auth = body["auth"]
    if not isinstance(auth, str) or not auth or len(auth) > _MAX_AUTH_LENGTH:
        raise MalformedAuthRequest("auth missing, blank, or implausibly long")
    tx = body["tx"]
    if not isinstance(tx, int) or isinstance(tx, bool) or tx < 0:
        raise MalformedAuthRequest("tx missing or not a non-negative integer")

    return addr, auth, tx


def handle_auth_request(raw_body_bytes, verify_fn):
    """Pure: no socket I/O, no store access of its own - [verify_fn] is
    injected (production: a closure around
    hysteria_provisioning.verify_hysteria_auth bound to the real store
    paths) so this function is unit-testable with a fake. Returns
    (http_status, response_dict). NEVER includes [auth] (the presented
    secret) in the returned dict, in any exception message this function
    raises, or in any value a caller might reasonably log - callers must log
    at most `addr`/`tx`/the boolean outcome, never `auth`.
    """
    try:
        addr, auth, tx = parse_auth_request(raw_body_bytes)
    except MalformedAuthRequest:
        # Same shape as a failed auth, deliberately: this endpoint must not
        # give a probing client a distinguishable signal between "malformed
        # request" and "wrong secret" - both simply fail closed.
        return 200, {"ok": False, "id": ""}

    try:
        ipaddress.ip_address(addr.rsplit(":", 1)[0].strip("[]"))
    except ValueError:
        pass  # addr is diagnostic-only here; an unparsed shape never blocks a real auth decision.

    result = verify_fn(auth)
    if result.ok:
        return 200, {"ok": True, "id": result.device_id}
    return 200, {"ok": False, "id": ""}
