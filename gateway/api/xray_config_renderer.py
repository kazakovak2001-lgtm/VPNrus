"""B8K2 - deterministic Xray server config renderer.

    durable canonical state (activations.json + xray identity store)
        -> render_server_config()          [pure, deterministic]
        -> atomic_write_config()           [atomic, all-or-nothing]
        -> validate_config_fn(path)        [caller-supplied, e.g. `xray -test -config`]
        -> (a LATER, separate, deliberately-manual step) reload/restart

This module never triggers a reload/restart itself - see reload_xray()'s
own docstring for why that stays a distinct, explicit action.

Revocation is realized ENTIRELY here, not in xray_provisioning.py: an
identity is included in the rendered client list if and only if its
owning activation is currently ACTIVE and unexpired in activations.json.
Renaming this "the config renderer skips revoked/expired identities" is
deliberate - there is exactly one source of truth for "is this
entitlement still valid" (activations.json), never a second copy of that
decision baked into the xray identity store itself.

Server private key material is NEVER read, held, or handled by this
module - see REALITYServerConfig's own docstring. This module renders a
config that REFERENCES the private key by value (the way xray-core's own
config.json format requires - the key must be present in that file for
Xray to start), but the value is supplied by the caller from wherever it
is stored server-side (see gateway/xray/README.md), never generated,
logged, or persisted by this module.
"""
import json
import os
import re
import tempfile
from dataclasses import dataclass, field

from . import activations
from . import xray_provisioning

# Same shape Android's XrayVlessRealityConfig validator requires (see
# android/.../vpn/xray/XrayVlessRealityConfig.kt's SHORT_ID_REGEX) - REALITY
# short IDs are raw bytes hex-encoded, so the string must have EVEN length
# (checked separately below - a bare {2,16} character-count regex would
# wrongly accept an odd length like "abc"). Case-insensitive, matching the
# Android side exactly (Android's own regex is also case-insensitive).
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{2,16}$")
_REALITY_PRIVATE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class XrayConfigRenderError(Exception):
    """Raised when the inputs to render_server_config are themselves
    invalid (e.g. a malformed private key) - fails closed rather than
    emitting a config Xray would refuse (or worse, silently misparse)."""


@dataclass(frozen=True)
class RealityServerConfig:
    """Operator-chosen, server-local REALITY settings. [private_key] is
    the ONLY field here that is a real secret - the caller is responsible
    for reading it from wherever it is stored (see
    gateway/xray/README.md's key-management model) and it is never logged
    by this module (see render_server_config's own care not to include it
    in any log-safe representation - callers must apply the same care).
    """

    listen_port: int
    server_names: tuple  # camouflage SNI domain(s) reported as `dest`'s host and accepted by the server
    dest: str  # "<host>:<port>" the REALITY handshake proxies to, e.g. "www.microsoft.com:443"
    private_key: str  # base64.RawURLEncoding X25519 private key, from the real `xray x25519` tool
    short_ids: tuple
    inbound_tag: str = "nova-vless-reality-in"


@dataclass(frozen=True)
class TlsServerConfig:
    """B8O2 - operator-chosen, server-local TLS/TCP settings for a SECOND
    Xray inbound, alongside (never instead of) REALITY's own. [cert_file]/
    [key_file] are the ONLY fields here with any secret-adjacent handling
    requirement, and even those are FILE PATHS, not raw key material - this
    module never opens them; xray-core itself reads their contents at
    process start (see docs/B8O1A_TLS_GATEWAY_INBOUND_AUDIT.md). Reuses the
    EXISTING publicly-trusted Let's Encrypt certificate already provisioned
    for the control-plane API (gateway/edge/nginx-pocvpn.conf) - no new ACME
    workflow, per B8O0's own audit finding."""

    listen_port: int
    cert_file: str
    key_file: str
    inbound_tag: str = "nova-vless-tls-in"


@dataclass(frozen=True)
class RenderedClient:
    activation_id: str
    device_public_key: str
    vless_uuid: str


def _validate_tls_server_config(tls):
    if not (1 <= tls.listen_port <= 65535):
        raise XrayConfigRenderError(f"invalid tls listen_port: {tls.listen_port}")
    if not tls.cert_file or not os.path.isabs(tls.cert_file):
        raise XrayConfigRenderError("tls cert_file must be an absolute path")
    if not tls.key_file or not os.path.isabs(tls.key_file):
        raise XrayConfigRenderError("tls key_file must be an absolute path")


def _validate_reality_server_config(reality):
    if not (1 <= reality.listen_port <= 65535):
        raise XrayConfigRenderError(f"invalid listen_port: {reality.listen_port}")
    if not reality.server_names:
        raise XrayConfigRenderError("server_names must not be empty")
    if not reality.dest:
        raise XrayConfigRenderError("dest must not be empty")
    if not _REALITY_PRIVATE_KEY_RE.match(reality.private_key):
        raise XrayConfigRenderError("private_key is not a well-formed X25519 base64url key")
    if not reality.short_ids:
        raise XrayConfigRenderError("short_ids must not be empty")
    for short_id in reality.short_ids:
        if not _SHORT_ID_RE.match(short_id) or len(short_id) % 2 != 0:
            raise XrayConfigRenderError(f"malformed short id: {short_id!r}")


def _active_clients(activations_data, xray_data):
    """Pure. Deterministic ordering: sorted by activation digest, then by
    device_public_key - so two renders of the same input are byte-for-byte
    identical (see this module's own determinism test)."""
    clients = []
    for digest in sorted(xray_data.keys()):
        activation_record = activations_data.get(digest)
        if activation_record is None:
            continue  # identity store outlived its activation record - never render an orphan
        if activation_record["status"] != activations.ACTIVE:
            continue  # revoked - the one enforcement point for Xray-side revocation

        identities = sorted(xray_data[digest], key=lambda entry: entry["device_public_key"])
        for identity in identities:
            clients.append(
                RenderedClient(
                    activation_id=activation_record["activation_id"],
                    device_public_key=identity["device_public_key"],
                    vless_uuid=identity["vless_uuid"],
                )
            )
    return clients


def _vless_clients(clients, flow=None):
    """Shared client-list builder for both inbounds - see [_active_clients].
    `flow` is included only when explicitly given a value (REALITY); TLS
    omits the key entirely, mirroring the Android side's own
    renderVlessTlsOutbound, which never emits `flow` for a plain-TLS
    outbound (a REALITY/XTLS-specific optimization - see
    docs/B8O0_TLS_TCP_FALLBACK_AUDIT.md)."""
    result = []
    for client in clients:
        entry = {
            "id": client.vless_uuid,
            # Not a real email - Xray's own per-client traffic-stats tag.
            # activation_id is a random 32-hex value, never sensitive.
            "email": f"{client.activation_id}-{client.device_public_key[:8]}",
        }
        if flow is not None:
            entry["flow"] = flow
        result.append(entry)
    return result


def _render_reality_inbound(clients, reality, flow):
    return {
        "tag": reality.inbound_tag,
        "listen": "0.0.0.0",
        "port": reality.listen_port,
        "protocol": "vless",
        "settings": {
            "clients": _vless_clients(clients, flow=flow),
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": reality.dest,
                "serverNames": list(reality.server_names),
                "privateKey": reality.private_key,
                "shortIds": list(reality.short_ids),
            },
        },
    }


def _render_tls_inbound(clients, tls):
    """B8O2 - the SAME active-client list REALITY's own inbound uses (see
    [_active_clients]) - device identity is shared across both transports,
    never a second/independent identity system (per this module's own
    revocation-is-realized-entirely-here docstring, which applies equally to
    this inbound: an identity excluded above is excluded from BOTH
    inbounds). No `flow` key - see [_vless_clients]'s own docs."""
    return {
        "tag": tls.inbound_tag,
        "listen": "0.0.0.0",
        "port": tls.listen_port,
        "protocol": "vless",
        "settings": {
            "clients": _vless_clients(clients, flow=None),
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "certificates": [
                    {"certificateFile": tls.cert_file, "keyFile": tls.key_file},
                ],
            },
        },
    }


def render_server_config(activations_data, xray_data, reality, tls=None, flow=""):
    """Pure function: (parsed activations store, parsed xray identity
    store, RealityServerConfig, optional TlsServerConfig) -> the full Xray
    server config dict, ready for json.dumps. Deterministic - same inputs
    always produce the same output (verified by this module's own
    determinism test), so diffing two renders is a meaningful way to review
    a pending change. [tls] is None by default (REALITY-only, byte-for-byte
    the pre-B8O2 output) - passing a real TlsServerConfig appends a SECOND,
    independent inbound on its own port (see
    docs/B8O1A_TLS_GATEWAY_INBOUND_AUDIT.md for why REALITY and TLS require
    separate xray-core inbounds, never a shared one), sharing the SAME
    active-client list [_active_clients] computes once."""
    _validate_reality_server_config(reality)
    if tls is not None:
        _validate_tls_server_config(tls)

    clients = _active_clients(activations_data, xray_data)

    inbounds = [_render_reality_inbound(clients, reality, flow)]
    if tls is not None:
        inbounds.append(_render_tls_inbound(clients, tls))

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


def render_server_config_redacted(activations_data, xray_data, reality, tls=None, flow=""):
    """Same as render_server_config but with privateKey replaced by a
    fixed placeholder - the only form of the rendered config that may
    ever be logged, diffed in an error message, or otherwise surfaced
    outside the config file itself. TLS's own inbound carries no secret
    value at all (cert_file/key_file are non-secret file paths), so nothing
    else needs redacting there."""
    full = render_server_config(activations_data, xray_data, reality, tls=tls, flow=flow)
    full["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "<redacted>"
    return full


def atomic_write_config(config_path, config_dict):
    """Same mkstemp/fsync/replace/dir-fsync discipline as
    activations._atomic_write_store - restrictive 0600 always (this file
    contains the REALITY private key), never a partial write, and the
    prior file is left byte-for-byte untouched if any step fails."""
    directory = os.path.dirname(os.path.abspath(config_path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".xray-config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config_dict, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, config_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def regenerate_and_write_config(
    activation_store_path, activation_lock_path,
    xray_store_path, xray_lock_path,
    config_path, reality, tls=None, flow="",
    validate_config_fn=None,
):
    """The full pipeline this module's docstring describes, minus reload:
    read both durable stores (short, released locks - read_store_shared/
    activations.read_store_shared, never this module's own write lock),
    render deterministically, atomically write, then optionally validate
    (e.g. `xray -test -config <path>`) - if validation fails, the NEW
    config file that was just written is left in place for operator
    inspection (this function does not attempt to resurrect the prior
    config from nothing - callers that need "never leave an unvalidated
    config live" must keep their own last-known-good copy and restore it
    on a validation failure, exactly like reload_xray's own docstring
    describes for the reload step). Returns the rendered config dict.
    """
    activations_data = activations.read_store_shared(activation_store_path, activation_lock_path)
    xray_data = xray_provisioning.read_store_shared(xray_store_path, xray_lock_path)

    config_dict = render_server_config(activations_data, xray_data, reality, tls=tls, flow=flow)
    atomic_write_config(config_path, config_dict)

    if validate_config_fn is not None:
        validate_config_fn(config_path)

    return config_dict


def reload_xray(reload_fn, config_path):
    """Deliberately a thin, explicit, separately-called wrapper - NOT
    invoked automatically by regenerate_and_write_config or by the HTTP
    provisioning path. `reload_fn` is caller-supplied (e.g. a function
    that shells out to `systemctl reload nova-xray`) so this module never
    hardcodes a service-manager assumption and, critically, so no
    production code path in this B8K2 slice can trigger a live reload by
    accident - the only callers are an explicit operator action or a
    future, separately-reviewed automation slice."""
    reload_fn(config_path)
