"""B26 (task B/C) - self-verifying, short-lived HMAC probe token binding a
real end-to-end relay proof to the exact relayed path identity
(historyPathId), WITHOUT requiring the EXIT to share a live store with the
INGRESS at verification time (the two processes normally run on different,
independently-administered hosts).

Minted by the INGRESS at POST /v1/ingress-profile time
(gateway/api/handler.py's _handle_ingress_profile_inner), verified by the
EXIT at GET /v1/relay-health time (gateway/api/handler.py's
_handle_relay_health_inner). The two sides share exactly ONE offline-
provisioned secret file - see gateway/tools/provision_relay_upstream_identity.py
(--probe-hmac-secret-file), distributed out-of-band alongside the ingress->
exit relay UUID it is provisioned next to: never committed, never printed,
never logged.

Deliberately narrow in what a stolen token can do (task C's "tokens scoped
narrowly enough that stealing one does not grant VPN access"): it
authenticates ONLY a GET to /v1/relay-health, never VPN traffic, never any
other endpoint - see that handler's own docs. A short TTL
(ingress_config.ingress_probe_ttl_seconds, independent of and normally much
shorter than the ingress profile's own TTL) bounds how long a leaked token
stays useful; the EXIT never persists anything about a token it verifies
(no revocation list, no replay cache) - the only "revocation" is expiry,
which is enough given the token grants nothing beyond a bound health probe.

Self-contained by design: no database, no shared store, no network call
between ingress and exit at verification time - just an HMAC-SHA256
signature over a small JSON payload, exactly the shape a JWT would use, but
without pulling in a JWT library for one claim shape.
"""
import base64
import hashlib
import hmac
import json

_TOKEN_VERSION = 1
_CLOCK_SKEW_ALLOWANCE_SECONDS = 30


class ProbeTokenError(Exception):
    """Malformed/unverifiable/expired token - the caller MUST treat every
    case identically (map to HTTP 401), never distinguish "expired" from
    "forged" from "malformed" in the response - task B's own "fail closed
    on missing/expired/wrong token", never leaking which."""


class ProbeTokenClaims:
    __slots__ = ("history_path_id",)

    def __init__(self, history_path_id):
        self.history_path_id = history_path_id


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    if not isinstance(text, str) or not text:
        raise ProbeTokenError("empty payload segment")
    # Reject anything but the exact base64url alphabet before padding/
    # decoding - urlsafe_b64decode silently tolerates some malformed input
    # depending on padding, and this must fail closed on all of it.
    for ch in text:
        if not (ch.isalnum() or ch in "-_"):
            raise ProbeTokenError("payload segment is not valid base64url")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProbeTokenError("payload segment is not valid base64url") from exc


def device_binding(device_public_key):
    """A non-reversible per-device binding value, present in the token
    purely as a diagnostic/audit aid - the token's own security relies
    solely on the HMAC signature + expiry, never on this field being kept
    secret. Truncated to 16 hex chars to keep the token short; a collision
    here has no security consequence (it is never compared against
    anything, only carried for operators reading a decoded token by hand)."""
    return hashlib.sha256(device_public_key.encode("utf-8")).hexdigest()[:16]


def mint(secret, history_path_id, device_public_key, issued_at_epoch_seconds, ttl_seconds):
    """Mint a fresh token bound to `history_path_id` and `device_public_key`,
    expiring `ttl_seconds` after `issued_at_epoch_seconds`. `secret` is raw
    bytes (the caller reads it from the shared secret file transiently -
    never holds it beyond one mint() call, same discipline as every other
    secret-file read in this package)."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ValueError("secret must be at least 16 raw bytes")
    if not history_path_id:
        raise ValueError("history_path_id must not be blank")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    payload = {
        "v": _TOKEN_VERSION,
        "path": history_path_id,
        "dev": device_binding(device_public_key),
        "iat": int(issued_at_epoch_seconds),
        "exp": int(issued_at_epoch_seconds) + int(ttl_seconds),
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(bytes(secret), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def verify(secret, token, now_epoch_seconds):
    """Raises ProbeTokenError on ANY problem - malformed shape, bad
    signature, unsupported version, missing/malformed claims, expired, or
    issued implausibly far in the future (beyond a small clock-skew
    allowance). Returns ProbeTokenClaims on success. The caller maps every
    ProbeTokenError to the SAME 401 response - see module docstring."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ProbeTokenError("server misconfiguration: probe secret too short")
    if not token or token.count(".") != 1:
        raise ProbeTokenError("malformed token")

    payload_b64, _, signature = token.partition(".")
    if not payload_b64 or not signature:
        raise ProbeTokenError("malformed token")
    if not all(c in "0123456789abcdef" for c in signature.lower()) or len(signature) != 64:
        raise ProbeTokenError("malformed signature")

    expected_signature = hmac.new(bytes(secret), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, signature.lower()):
        raise ProbeTokenError("signature mismatch")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProbeTokenError("malformed payload") from exc
    if not isinstance(payload, dict):
        raise ProbeTokenError("payload is not an object")
    if payload.get("v") != _TOKEN_VERSION:
        raise ProbeTokenError("unsupported token version")

    history_path_id = payload.get("path")
    exp = payload.get("exp")
    iat = payload.get("iat")
    if not isinstance(history_path_id, str) or not history_path_id:
        raise ProbeTokenError("missing path claim")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise ProbeTokenError("malformed exp claim")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise ProbeTokenError("malformed iat claim")

    now = int(now_epoch_seconds)
    if now >= exp:
        raise ProbeTokenError("expired")
    if iat - _CLOCK_SKEW_ALLOWANCE_SECONDS > now:
        raise ProbeTokenError("issued in the future")

    return ProbeTokenClaims(history_path_id=history_path_id)
