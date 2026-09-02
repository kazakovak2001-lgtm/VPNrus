"""B25 (task G/I) - configuration for ONE ingress-role deployment of this
SAME pocvpn-api process (task G's own "extend the existing gateway API/
control-plane architecture ... rather than a completely separate service").

Deliberately a SEPARATE, additive loader from config.py's AppConfig, never a
field bolted onto that dataclass: an ingress deployment is its own process
instance (its own host, its own activation/xray identity stores - exactly
the same "a second gateway is a pure deployment action, zero code change"
discipline PROJECT_ARCHITECTURE.md already documents for a second EXIT
gateway), so it needs its own env-var-driven config, not a widened shared
one. load_ingress_config() returns None when NO NOVA_INGRESS_* variable is
set at all - the default for every existing (non-ingress) deployment,
completely unaffected by this module's mere existence. Once ANY is set, the
full required group must be present and valid (same all-or-nothing
discipline config.py's own optional groups already use) - a half-configured
ingress role fails closed at startup, never silently serves a partial one.
"""
import os
import re
from dataclasses import dataclass

_ENV_PREFIX = "NOVA_INGRESS_"

_REALITY_PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{2,16}$")
_SUPPORTED_UPSTREAM_TRANSPORTS = ("reality", "tls")


class IngressConfigError(Exception):
    """Raised when the ingress role is partially configured or a value is
    invalid - the caller (server.py's main()) must let this abort startup,
    never fall back to running with the ingress role half-enabled."""


@dataclass(frozen=True)
class IngressAppConfig:
    # A stable, non-secret, operator-chosen identifier for THIS ingress
    # deployment (e.g. "ru-ingress-1") - logs/diagnostics only, never a
    # secret, never returned as anything other than an opaque label.
    ingress_endpoint_id: str
    ingress_endpoint_host: str

    # --- client-facing REALITY inbound (mirrors config.py's xray_* group) ---
    ingress_reality_private_key_file: str
    ingress_server_port: int
    ingress_server_name: str
    ingress_dest: str
    ingress_short_id: str
    ingress_fingerprint: str
    ingress_reality_public_key: str
    ingress_flow: str = ""

    # --- client-facing TLS inbound (optional group, mirrors config.py's xray_tls_* group) ---
    ingress_tls_server_port: int = 0
    ingress_tls_server_name: str = ""
    ingress_tls_fingerprint: str = ""
    ingress_tls_cert_file: str = ""
    ingress_tls_key_file: str = ""

    # --- ingress -> exit upstream relay identity (task H - NEVER returned to a client) ---
    ingress_upstream_host: str = ""
    ingress_upstream_port: int = 0
    ingress_upstream_transport: str = ""  # "reality" | "tls"
    # A FILE path, read once per activation render, never held beyond that
    # call's local scope - same discipline as ingress_reality_private_key_file.
    ingress_upstream_uuid_file: str = ""
    ingress_upstream_server_name: str = ""
    ingress_upstream_public_key: str = ""
    ingress_upstream_short_id: str = ""
    ingress_upstream_sni: str = ""
    ingress_upstream_flow: str = ""

    # --- B26 (task B/C) - the exit-side end-to-end health-probe contract ---
    # A stable, non-secret identifier for the PINNED exit this ingress
    # relays to - the SAME endpoint id value Android's manifest/reachability
    # model uses for that exit (never invented independently), so the
    # historyPathId this process computes for a probe token
    # (ingress_endpoint_id:transport->ingress_exit_endpoint_id:upstream_transport)
    # matches EXACTLY what the client's own PathCandidate.Relayed.historyPathId
    # already computes - see relay_probe_token.py's own docs and
    # PathCandidate.kt's historyPathId format.
    ingress_exit_endpoint_id: str = ""
    # The exit's own public HTTPS control-plane host (same edge every other
    # /v1/* endpoint on that exit is served from) - NOT necessarily identical
    # to ingress_upstream_host (that one is the Xray upstream connect
    # target; this one is where a GET /v1/relay-health lands after
    # traversing the tunnel). In today's one-VPS-per-role topology they are
    # typically the same host, but this is kept as its own explicit field
    # rather than assumed, since conflating "Xray upstream address" with
    # "control-plane address" is exactly the kind of silent coupling that
    # breaks the first time they diverge.
    ingress_exit_probe_host: str = ""
    # A FILE path (never a raw value here) - the ONE secret this ingress and
    # its pinned exit share, minted together by
    # gateway/tools/provision_relay_upstream_identity.py and distributed
    # out-of-band (task C's "never in PR/docs/logcat/server logs"). Read
    # once per /v1/ingress-profile request, transiently, never held beyond
    # that call's local scope - same discipline as
    # ingress_upstream_uuid_file.
    ingress_probe_hmac_secret_file: str = ""
    # Task C's "short-lived credential" - independent of, and normally much
    # shorter than, ingress_profile_ttl_seconds below (a leaked probe token
    # only ever authenticates one bound health GET, never VPN traffic - see
    # relay_probe_token.py - so a short TTL here is a real, effective bound
    # on exposure even though the surrounding profile lives longer).
    ingress_probe_ttl_seconds: int = 300

    # --- this deployment's own activation/identity stores (never shared with a different gateway/ingress instance) ---
    activation_store_path: str = ""
    activation_lock_path: str = ""
    xray_store_path: str = ""
    xray_lock_path: str = ""

    # --- the same render/validate/stage/apply boundary xray_activation.py already uses ---
    ingress_activation_wrapper_path: str = ""
    ingress_activation_timeout_seconds: float = 5.0
    ingress_staging_config_path: str = ""
    ingress_activation_lock_path: str = ""
    ingress_activation_last_hash_path: str = ""
    sudo_path: str = ""

    # --- profile validity window handed to a device (task E) ---
    ingress_profile_ttl_seconds: int = 0  # 0 means no expiry


def _get(env, name):
    return env.get(_ENV_PREFIX + name, "").strip()


def _any_ingress_var_set(env):
    return any(key.startswith(_ENV_PREFIX) and env[key].strip() for key in env)


def load_ingress_config(env=None):
    env = os.environ if env is None else env
    if not _any_ingress_var_set(env):
        return None

    def require(name):
        value = _get(env, name)
        if not value:
            raise IngressConfigError(f"{_ENV_PREFIX}{name} is required once any {_ENV_PREFIX}* variable is set")
        return value

    ingress_endpoint_id = require("ENDPOINT_ID")
    ingress_endpoint_host = require("ENDPOINT_HOST")

    reality_private_key_file = require("REALITY_PRIVATE_KEY_FILE")
    if not os.path.isabs(reality_private_key_file):
        raise IngressConfigError(f"{_ENV_PREFIX}REALITY_PRIVATE_KEY_FILE must be an absolute path")
    if not os.path.isfile(reality_private_key_file):
        raise IngressConfigError(f"{_ENV_PREFIX}REALITY_PRIVATE_KEY_FILE does not exist: {reality_private_key_file!r}")

    try:
        server_port = int(require("SERVER_PORT"))
    except ValueError as exc:
        raise IngressConfigError(f"{_ENV_PREFIX}SERVER_PORT is not an integer") from exc
    if not (1 <= server_port <= 65535):
        raise IngressConfigError(f"{_ENV_PREFIX}SERVER_PORT out of range: {server_port}")

    server_name = require("SERVER_NAME")
    dest = require("DEST")
    short_id = require("SHORT_ID")
    if not _SHORT_ID_RE.match(short_id) or len(short_id) % 2 != 0:
        raise IngressConfigError(f"{_ENV_PREFIX}SHORT_ID is malformed: {short_id!r}")
    fingerprint = require("FINGERPRINT")
    reality_public_key = require("REALITY_PUBLIC_KEY")
    if not _REALITY_PUBLIC_KEY_RE.match(reality_public_key):
        raise IngressConfigError(f"{_ENV_PREFIX}REALITY_PUBLIC_KEY is not a well-formed X25519 base64url key")
    flow = _get(env, "FLOW")

    tls_server_port_raw = _get(env, "TLS_SERVER_PORT")
    tls_server_port = 0
    if tls_server_port_raw:
        try:
            tls_server_port = int(tls_server_port_raw)
        except ValueError as exc:
            raise IngressConfigError(f"{_ENV_PREFIX}TLS_SERVER_PORT is not an integer") from exc
        if not (1 <= tls_server_port <= 65535):
            raise IngressConfigError(f"{_ENV_PREFIX}TLS_SERVER_PORT out of range: {tls_server_port}")

    upstream_host = require("UPSTREAM_HOST")
    try:
        upstream_port = int(require("UPSTREAM_PORT"))
    except ValueError as exc:
        raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_PORT is not an integer") from exc
    upstream_transport = require("UPSTREAM_TRANSPORT").lower()
    if upstream_transport not in _SUPPORTED_UPSTREAM_TRANSPORTS:
        raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_TRANSPORT must be one of {_SUPPORTED_UPSTREAM_TRANSPORTS}")
    upstream_uuid_file = require("UPSTREAM_UUID_FILE")
    if not os.path.isabs(upstream_uuid_file):
        raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_UUID_FILE must be an absolute path")
    if not os.path.isfile(upstream_uuid_file):
        raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_UUID_FILE does not exist: {upstream_uuid_file!r}")

    upstream_server_name = ""
    upstream_public_key = ""
    upstream_short_id = ""
    upstream_sni = ""
    if upstream_transport == "reality":
        upstream_server_name = require("UPSTREAM_SERVER_NAME")
        upstream_public_key = require("UPSTREAM_PUBLIC_KEY")
        if not _REALITY_PUBLIC_KEY_RE.match(upstream_public_key):
            raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_PUBLIC_KEY is not a well-formed X25519 base64url key")
        upstream_short_id = require("UPSTREAM_SHORT_ID")
        if not _SHORT_ID_RE.match(upstream_short_id) or len(upstream_short_id) % 2 != 0:
            raise IngressConfigError(f"{_ENV_PREFIX}UPSTREAM_SHORT_ID is malformed")
    else:
        upstream_sni = require("UPSTREAM_SNI")
    upstream_flow = _get(env, "UPSTREAM_FLOW")

    # B26 (task B/C) - the exit-side probe contract. Required once the
    # ingress role is configured at all - a real ingress deployment with no
    # way to prove end-to-end reachability is not deployment-ready (see
    # PROJECT_ARCHITECTURE.md's B25 "remaining condition" list, item 4).
    exit_endpoint_id = require("EXIT_ENDPOINT_ID")
    exit_probe_host = require("EXIT_PROBE_HOST")
    probe_hmac_secret_file = require("PROBE_HMAC_SECRET_FILE")
    if not os.path.isabs(probe_hmac_secret_file):
        raise IngressConfigError(f"{_ENV_PREFIX}PROBE_HMAC_SECRET_FILE must be an absolute path")
    if not os.path.isfile(probe_hmac_secret_file):
        raise IngressConfigError(f"{_ENV_PREFIX}PROBE_HMAC_SECRET_FILE does not exist: {probe_hmac_secret_file!r}")
    probe_ttl_raw = _get(env, "PROBE_TTL_SECONDS")
    probe_ttl_seconds = int(probe_ttl_raw) if probe_ttl_raw else 300
    if probe_ttl_seconds <= 0:
        raise IngressConfigError(f"{_ENV_PREFIX}PROBE_TTL_SECONDS must be positive")

    activation_store_path = require("ACTIVATION_STORE_PATH")
    activation_lock_path = require("ACTIVATION_LOCK_PATH")
    xray_store_path = require("XRAY_STORE_PATH")
    xray_lock_path = require("XRAY_LOCK_PATH")

    activation_wrapper_path = require("ACTIVATION_WRAPPER_PATH")
    if not os.path.isabs(activation_wrapper_path):
        raise IngressConfigError(f"{_ENV_PREFIX}ACTIVATION_WRAPPER_PATH must be an absolute path")
    staging_config_path = require("STAGING_CONFIG_PATH")
    # The GLOBAL ingress activation lock (xray_activation.py's own
    # "innermost lock" - see that module's lock-ordering docs) - a
    # DIFFERENT lock file from activation_lock_path above (activations.py's
    # per-activation-credential lock), never the same file reused for two
    # distinct locking scopes.
    ingress_activation_lock_path = require("ACTIVATION_GLOBAL_LOCK_PATH")
    activation_last_hash_path = require("ACTIVATION_LAST_HASH_PATH")
    timeout_raw = _get(env, "ACTIVATION_TIMEOUT_SECONDS")
    timeout_seconds = float(timeout_raw) if timeout_raw else 5.0
    sudo_path = _get(env, "SUDO_PATH")
    if sudo_path and not os.path.isabs(sudo_path):
        raise IngressConfigError(f"{_ENV_PREFIX}SUDO_PATH must be an absolute path")

    ttl_raw = _get(env, "PROFILE_TTL_SECONDS")
    profile_ttl_seconds = int(ttl_raw) if ttl_raw else 0
    if profile_ttl_seconds < 0:
        raise IngressConfigError(f"{_ENV_PREFIX}PROFILE_TTL_SECONDS must not be negative")

    return IngressAppConfig(
        ingress_endpoint_id=ingress_endpoint_id,
        ingress_endpoint_host=ingress_endpoint_host,
        ingress_reality_private_key_file=reality_private_key_file,
        ingress_server_port=server_port,
        ingress_server_name=server_name,
        ingress_dest=dest,
        ingress_short_id=short_id,
        ingress_fingerprint=fingerprint,
        ingress_reality_public_key=reality_public_key,
        ingress_flow=flow,
        ingress_tls_server_port=tls_server_port,
        ingress_tls_server_name=_get(env, "TLS_SERVER_NAME"),
        ingress_tls_fingerprint=_get(env, "TLS_FINGERPRINT"),
        ingress_tls_cert_file=_get(env, "TLS_CERT_FILE"),
        ingress_tls_key_file=_get(env, "TLS_KEY_FILE"),
        ingress_upstream_host=upstream_host,
        ingress_upstream_port=upstream_port,
        ingress_upstream_transport=upstream_transport,
        ingress_upstream_uuid_file=upstream_uuid_file,
        ingress_upstream_server_name=upstream_server_name,
        ingress_upstream_public_key=upstream_public_key,
        ingress_upstream_short_id=upstream_short_id,
        ingress_upstream_sni=upstream_sni,
        ingress_upstream_flow=upstream_flow,
        ingress_exit_endpoint_id=exit_endpoint_id,
        ingress_exit_probe_host=exit_probe_host,
        ingress_probe_hmac_secret_file=probe_hmac_secret_file,
        ingress_probe_ttl_seconds=probe_ttl_seconds,
        activation_store_path=activation_store_path,
        activation_lock_path=activation_lock_path,
        xray_store_path=xray_store_path,
        xray_lock_path=xray_lock_path,
        ingress_activation_wrapper_path=activation_wrapper_path,
        ingress_activation_timeout_seconds=timeout_seconds,
        ingress_staging_config_path=staging_config_path,
        ingress_activation_lock_path=ingress_activation_lock_path,
        ingress_activation_last_hash_path=activation_last_hash_path,
        sudo_path=sudo_path,
        ingress_profile_ttl_seconds=profile_ttl_seconds,
    )
