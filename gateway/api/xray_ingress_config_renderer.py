"""B24 - real ingress relay Xray server config renderer: client -> INGRESS
-> EXIT -> Internet.

Reuses xray_config_renderer's own client-facing inbound rendering AND its
identity/authorization boundary VERBATIM (`_active_clients`/
`_render_reality_inbound`/`_render_tls_inbound`) - an ingress is NOT a
second, independent authorization system; a client excluded from
xray_config_renderer's rendered gateway config (revoked/expired activation)
is excluded here too, by construction (same source function, same
activations.json source of truth).

What is genuinely NEW for the ingress role is the OUTBOUND: instead of
`freedom` (direct-to-Internet, what every existing gateway config renders),
this module points the server's outbound at a pinned [UpstreamExitConfig] -
a SEPARATE encrypted VLESS connection (REALITY or TLS, independent of
whatever transport the client dialed the ingress over) authenticated by its
own dedicated relay credential. Every client-facing inbound is routed
EXCLUSIVELY to that upstream outbound (never a "direct"/freedom fallback),
which is what makes an ingress deployment structurally incapable of
becoming an open Internet exit by accident - see
[render_ingress_server_config]'s own docs for the exact routing contract.

Server private key material and the upstream relay credential are NEVER
read, held, or logged by this module beyond what is needed to embed them in
the rendered config - same "the caller supplies it, this module never
generates/persists it" discipline as xray_config_renderer.
"""
import re
import uuid as uuid_module

from . import xray_config_renderer as base

_SUPPORTED_UPSTREAM_TRANSPORTS = ("reality", "tls")
_REALITY_PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{2,16}$")
_XHTTP_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?=.*[A-Za-z])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_SUPPORTED_XHTTP_ORIGIN_MODES = ("packet-up",)
_SUPPORTED_XHTTP_PADDING_PLACEMENTS = ("header", "query")
# B31C - same pinned constant as ingress_config.py's own
# _SUPPORTED_UPSTREAM_FLOWS (that module's docstring has the full "why") -
# duplicated here deliberately: this renderer is called directly by tests
# and any future caller with an UpstreamExitConfig built by hand, not only
# via ingress_config.load_ingress_config, so an invalid flow must fail
# closed at render time too, not only at config-load time.
_SUPPORTED_UPSTREAM_FLOWS = ("xtls-rprx-vision",)


class IngressConfigRenderError(Exception):
    """Raised when ingress-specific inputs are themselves invalid - fails
    closed rather than emitting a config that would silently misroute or,
    worse, silently become an open relay."""


class UpstreamExitConfig:
    """B24 - the ingress's OWN dedicated identity/credential to authenticate
    to the pinned EXIT (task requirement 9 - "the INGRESS -> EXIT link must
    itself authenticate... do not assume source IP == trusted ingress").

    [transport] ("reality" or "tls") is INDEPENDENT of whatever transport
    the client dialed the ingress over (task requirement 6's own "client ->
    ingress transport may differ from ingress -> exit transport" - never
    collapsed to one shared TransportKind here either).

    [uuid] is a VLESS client identity the EXIT's own Xray server must
    already have provisioned specifically FOR THIS INGRESS - the SAME
    per-identity authorization model this module's own inbound rendering
    already uses for end-user clients (never a shared/global plaintext
    credential - task requirement 8/9's own "no shared global plaintext
    credential committed to repo", and this value is never written to a
    string constant in this repository - it is always caller-supplied at
    render time from wherever the EXIT's own provisioning issued it).
    """

    def __init__(
        self,
        host,
        port,
        transport,
        uuid,
        outbound_tag="nova-relay-upstream-out",
        server_name=None,
        public_key=None,
        short_id=None,
        sni=None,
        flow=None,
    ):
        self.host = host
        self.port = port
        self.transport = transport
        self.uuid = uuid
        self.outbound_tag = outbound_tag
        self.server_name = server_name
        self.public_key = public_key
        self.short_id = short_id
        self.sni = sni
        self.flow = flow


class XhttpOriginInboundConfig:
    """Private CDN-origin XHTTP backend. Listen address is intentionally not configurable."""

    def __init__(
        self,
        listen_port,
        host,
        path,
        mode,
        max_each_post_bytes,
        padding_placement,
        padding_min_bytes,
        padding_max_bytes,
        inbound_tag="nova-client-xhttp-in",
    ):
        self.listen_port = listen_port
        self.host = host
        self.path = path
        self.mode = mode
        self.max_each_post_bytes = max_each_post_bytes
        self.padding_placement = padding_placement
        self.padding_min_bytes = padding_min_bytes
        self.padding_max_bytes = padding_max_bytes
        self.inbound_tag = inbound_tag


def _validate_upstream(upstream):
    if upstream.transport not in _SUPPORTED_UPSTREAM_TRANSPORTS:
        raise IngressConfigRenderError(f"unsupported upstream transport: {upstream.transport!r}")
    if not (1 <= upstream.port <= 65535):
        raise IngressConfigRenderError(f"invalid upstream port: {upstream.port}")
    if not upstream.host:
        raise IngressConfigRenderError("upstream host must not be blank")
    try:
        uuid_module.UUID(str(upstream.uuid))
    except (ValueError, AttributeError, TypeError):
        raise IngressConfigRenderError("upstream uuid is not a well-formed UUID - refusing an unauthenticated/malformed relay identity")

    if upstream.transport == "reality":
        if not upstream.server_name:
            raise IngressConfigRenderError("REALITY upstream requires server_name")
        if not upstream.public_key or not _REALITY_PUBLIC_KEY_RE.match(upstream.public_key):
            raise IngressConfigRenderError("REALITY upstream public_key is not a well-formed X25519 base64url key")
        if not upstream.short_id or not _SHORT_ID_RE.match(upstream.short_id) or len(upstream.short_id) % 2 != 0:
            raise IngressConfigRenderError("REALITY upstream short_id is malformed")
        # B31C - a REALITY relay upstream's flow is REQUIRED here too, not
        # merely validated-if-present: this renderer is called directly by
        # callers that build an UpstreamExitConfig by hand (tests, or any
        # future caller), not only via ingress_config.load_ingress_config's
        # own now-required check - a blank flow must fail closed at BOTH
        # layers, the same "no layer alone is trusted" discipline this
        # function already applies to public_key/short_id above. The live
        # failure this whole change closes was exactly a blank flow that
        # rendered "successfully".
        if not upstream.flow or upstream.flow not in _SUPPORTED_UPSTREAM_FLOWS:
            raise IngressConfigRenderError(
                f"REALITY upstream flow must be one of {_SUPPORTED_UPSTREAM_FLOWS}: {upstream.flow!r}"
            )
    else:  # tls
        if not upstream.sni:
            raise IngressConfigRenderError("TLS upstream requires sni")
        if upstream.flow and upstream.flow not in _SUPPORTED_UPSTREAM_FLOWS:
            raise IngressConfigRenderError(
                f"upstream flow must be blank or one of {_SUPPORTED_UPSTREAM_FLOWS}: {upstream.flow!r}"
            )


def _render_upstream_outbound(upstream):
    stream_settings = {"network": "tcp"}
    if upstream.transport == "reality":
        stream_settings["security"] = "reality"
        stream_settings["realitySettings"] = {
            "serverName": upstream.server_name,
            "fingerprint": "chrome",
            "publicKey": upstream.public_key,
            "shortId": upstream.short_id,
        }
    else:
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {"serverName": upstream.sni}

    user = {"id": upstream.uuid, "encryption": "none"}
    if upstream.flow:
        user["flow"] = upstream.flow

    return {
        "tag": upstream.outbound_tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {"address": upstream.host, "port": upstream.port, "users": [user]},
            ],
        },
        "streamSettings": stream_settings,
    }


def _validate_xhttp_origin(xhttp):
    if not (1 <= xhttp.listen_port <= 65535):
        raise IngressConfigRenderError("invalid XHTTP origin listen_port")
    if not xhttp.host or not _XHTTP_HOST_RE.match(xhttp.host):
        raise IngressConfigRenderError("XHTTP origin host must be an ASCII DNS hostname")
    if (
        not xhttp.path
        or not xhttp.path.startswith("/")
        or xhttp.path.startswith("//")
        or not xhttp.path.endswith("/")
        or "?" in xhttp.path
        or "#" in xhttp.path
        or "\\" in xhttp.path
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in xhttp.path)
    ):
        raise IngressConfigRenderError("XHTTP origin path must be a normalized trailing-slash ASCII path")
    if xhttp.mode not in _SUPPORTED_XHTTP_ORIGIN_MODES:
        raise IngressConfigRenderError(
            f"XHTTP origin mode must be one of {_SUPPORTED_XHTTP_ORIGIN_MODES}"
        )
    if not (1 <= xhttp.max_each_post_bytes <= 2_147_483_647):
        raise IngressConfigRenderError("XHTTP max_each_post_bytes must be a positive int32")
    if xhttp.padding_placement not in _SUPPORTED_XHTTP_PADDING_PLACEMENTS:
        raise IngressConfigRenderError(
            "XHTTP padding must be explicit header/query; pinned core cannot represent disabled padding"
        )
    if not (1 <= xhttp.padding_min_bytes <= xhttp.padding_max_bytes <= 65536):
        raise IngressConfigRenderError("XHTTP padding range must be positive and bounded")


def _render_xhttp_origin_inbound(clients, xhttp):
    xhttp_settings = {
        "host": xhttp.host,
        "path": xhttp.path,
        "mode": xhttp.mode,
        "scMaxEachPostBytes": xhttp.max_each_post_bytes,
        "xPaddingBytes": (
            xhttp.padding_min_bytes
            if xhttp.padding_min_bytes == xhttp.padding_max_bytes
            else f"{xhttp.padding_min_bytes}-{xhttp.padding_max_bytes}"
        ),
        "xPaddingObfsMode": True,
        "xPaddingPlacement": xhttp.padding_placement,
        "xPaddingMethod": "repeat-x",
    }
    return {
        "tag": xhttp.inbound_tag,
        "listen": "127.0.0.1",
        "port": xhttp.listen_port,
        "protocol": "vless",
        "settings": {
            "clients": base._vless_clients(clients, flow=None),
            "decryption": "none",
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": xhttp_settings,
        },
    }


def render_ingress_server_config(activations_data, xray_data, reality, upstream, tls=None, flow="", xhttp=None):
    """B24 - the real ingress relay config: the SAME client-facing
    inbound(s) `xray_config_renderer.render_server_config` already produces
    (identity/authorization reuse - task requirement 7/8, never a second/
    parallel client identity system), but with the server's OWN outbound
    pointed at [upstream] (the pinned EXIT) instead of "freedom" - the
    ingress is therefore structurally incapable of becoming the open
    Internet exit unless a caller deliberately renders it with
    `xray_config_renderer.render_server_config` instead (task requirement
    6's own "must NOT become the public Internet exit unless explicitly
    configured as such" - THIS function's own contract IS that explicit
    configuration; there is no "default to open" code path anywhere in it).

    Routing rules bind EVERY client-facing inbound tag to the upstream
    outbound tag EXCLUSIVELY - `outbounds` contains only the upstream
    outbound (no `direct`/`freedom` outbound exists in the rendered config
    at all, so even a routing-rule bug could never fall through to one -
    task requirement L's own "cannot generate an unauthenticated/open
    relay").
    """
    base._validate_reality_server_config(reality)
    if tls is not None:
        base._validate_tls_server_config(tls)
    if xhttp is not None:
        _validate_xhttp_origin(xhttp)
    _validate_upstream(upstream)

    clients = base._active_clients(activations_data, xray_data)

    inbounds = [base._render_reality_inbound(clients, reality, flow)]
    inbound_tags = [reality.inbound_tag]
    if tls is not None:
        inbounds.append(base._render_tls_inbound(clients, tls))
        inbound_tags.append(tls.inbound_tag)
    if xhttp is not None:
        inbounds.append(_render_xhttp_origin_inbound(clients, xhttp))
        inbound_tags.append(xhttp.inbound_tag)

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [_render_upstream_outbound(upstream)],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": inbound_tags, "outboundTag": upstream.outbound_tag},
            ],
        },
    }


def render_ingress_server_config_redacted(activations_data, xray_data, reality, upstream, tls=None, flow="", xhttp=None):
    """Same as [render_ingress_server_config] but with every secret value
    replaced by a fixed placeholder - the ONLY form of the rendered config
    that may ever be logged, diffed in an error message, or otherwise
    surfaced outside the config file itself (task requirement 9's own "keep
    credentials out of diagnostics" / requirement M's own "no secrets
    serialized into diagnostics"). Redacts the ingress's own REALITY
    private key (same field [xray_config_renderer.render_server_config_redacted]
    already redacts) AND the upstream relay credential (the ONE new secret
    this module introduces) - REALITY's own `publicKey`/`shortId` for the
    upstream are NOT secrets (a public key and a non-secret short id, by
    design of the REALITY protocol itself) and are left as-is."""
    full = render_ingress_server_config(activations_data, xray_data, reality, upstream, tls=tls, flow=flow, xhttp=xhttp)
    full["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "<redacted>"
    for user in full["outbounds"][0]["settings"]["vnext"][0]["users"]:
        user["id"] = "<redacted>"
    return full
