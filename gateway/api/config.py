"""Required startup configuration for the B8B1B provisioning API.

Fail-closed by design: load_config() raises ConfigError, and the process
must refuse to start, if any required value is missing or invalid. There
is deliberately NO bind-host field anywhere in AppConfig - the listen
address is hard-coded to 127.0.0.1 in server.py and is not configurable
from here or anywhere else, per the B8B1B server-boundary requirement.
"""
import ipaddress
import os
import re
from dataclasses import dataclass

from .wgkey import is_valid_wg_public_key

_ENV_PREFIX = "POCVPN_API_"

_REQUIRED_KEYS = (
    "ENDPOINT_HOST",
    "ENDPOINT_PORT",
    "GATEWAY_PUBLIC_KEY",
    "GATEWAY_TUNNEL_IP",
    "TOKEN_STORE_PATH",
    "PROVISION_SCRIPT_PATH",
    "SUBPROCESS_TIMEOUT_SECONDS",
    "API_PORT",
)


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid - the
    caller (server.py's main()) must let this abort startup, never fall
    back to a default."""


@dataclass(frozen=True)
class AppConfig:
    endpoint_host: str
    endpoint_port: int
    gateway_public_key: str
    gateway_tunnel_ip: str
    token_store_path: str
    token_lock_path: str
    provision_script_path: str
    subprocess_timeout_seconds: float
    api_port: int
    # B8B1C2: optional absolute path to `sudo` - see provision.py. Empty
    # string (the default, and the only value B8B1B/C1 ever had) means
    # "invoke provision_script_path directly, no sudo" - this preserves
    # every existing direct-invocation test/deployment unchanged. Never
    # required: B8B1C3 is what actually wires production sudo, this slice
    # only proves the argv shape is ready for it.
    sudo_path: str = ""
    # B8C1: optional - blank (the default) means POST /v1/activate is not
    # configured and always fails closed with 503 (see handler.py). Not in
    # _REQUIRED_KEYS so every existing B8B1 deployment/test that knows
    # nothing about activations is completely unaffected.
    activation_store_path: str = ""
    activation_lock_path: str = ""

    # B8K2: optional - blank/zero (the default) means POST /v1/xray-profile
    # is not configured and always fails closed with 503 (see handler.py),
    # exactly like activation_store_path above. Every field below except
    # xray_reality_private_key_file is a public-safe value a client is
    # allowed to receive verbatim - see xray_config_renderer.py's own docstring.
    xray_store_path: str = ""
    xray_lock_path: str = ""
    xray_server_port: int = 0
    xray_server_name: str = ""
    xray_fingerprint: str = ""
    xray_reality_public_key: str = ""
    xray_short_id: str = ""
    xray_flow: str = ""

    # B8K2A - the activation boundary. xray_reality_private_key_file is a
    # FILE PATH, never a raw value in this dataclass or in any environment
    # variable - see xray_activation.py's own docstring for the one place
    # (and only place) this process ever reads its contents: transiently,
    # in memory, immediately before rendering a candidate config for the
    # privileged wrapper to independently re-validate - never logged, never
    # part of any HTTP response, never cached beyond one render call.
    xray_reality_private_key_file: str = ""
    xray_staging_config_path: str = ""
    xray_activation_lock_path: str = ""
    xray_activation_last_hash_path: str = ""
    xray_activation_wrapper_path: str = ""
    xray_activation_timeout_seconds: float = 15.0
    xray_dest: str = ""

    # B8O2 - TLS/TCP fallback: a SECOND Xray inbound, same activation
    # pipeline/staging/lock/wrapper as REALITY above (see xray_activation.py's
    # build_tls_config), sharing the SAME device identities (xray_store_path/
    # xray_lock_path) - never a second identity system. Blank/zero (the
    # default) means POST /v1/xray-profile never offers "tls" as a transport
    # option, exactly like REALITY's own optional-group convention. Unlike
    # the REALITY private key, xray_tls_cert_file/xray_tls_key_file are FILE
    # PATHS only (xray-core itself reads their contents at process start) -
    # this process never opens or reads them.
    xray_tls_server_port: int = 0
    xray_tls_server_name: str = ""
    xray_tls_fingerprint: str = ""
    xray_tls_cert_file: str = ""
    xray_tls_key_file: str = ""

    # B12 - GET /v1/manifest: serves an ALREADY-SIGNED EndpointManifest
    # artifact (see gateway/tools/manifest_signing.py's `sign-and-package`
    # subcommand, run OFFLINE) verbatim, as raw bytes. Blank (the default)
    # means the endpoint is not configured and always fails closed with 503,
    # same convention as every other optional group above. This process
    # NEVER signs anything and NEVER holds the manifest signing private key -
    # it only reads and serves a file an operator placed here, exactly the
    # "no private signing key on the production VPS if avoidable" requirement.
    manifest_path: str = ""


def _get(env, key):
    return env.get(_ENV_PREFIX + key, "").strip()


def load_config(env=None):
    env = os.environ if env is None else env

    missing = [key for key in _REQUIRED_KEYS if not _get(env, key)]
    if missing:
        raise ConfigError(
            "missing required configuration: "
            + ", ".join(_ENV_PREFIX + k for k in missing)
        )

    endpoint_host = _get(env, "ENDPOINT_HOST")

    endpoint_port_raw = _get(env, "ENDPOINT_PORT")
    try:
        endpoint_port = int(endpoint_port_raw)
    except ValueError:
        raise ConfigError(f"{_ENV_PREFIX}ENDPOINT_PORT is not an integer: {endpoint_port_raw!r}")
    if not (1 <= endpoint_port <= 65535):
        raise ConfigError(f"{_ENV_PREFIX}ENDPOINT_PORT out of range: {endpoint_port}")

    gateway_public_key = _get(env, "GATEWAY_PUBLIC_KEY")
    if not is_valid_wg_public_key(gateway_public_key):
        raise ConfigError(f"{_ENV_PREFIX}GATEWAY_PUBLIC_KEY is not a valid AmneziaWG/WireGuard public key")

    gateway_tunnel_ip = _get(env, "GATEWAY_TUNNEL_IP")
    try:
        ipaddress.IPv4Address(gateway_tunnel_ip)
    except ValueError:
        raise ConfigError(f"{_ENV_PREFIX}GATEWAY_TUNNEL_IP is not a valid IPv4 address: {gateway_tunnel_ip!r}")

    token_store_path = _get(env, "TOKEN_STORE_PATH")
    token_lock_path = _get(env, "TOKEN_LOCK_PATH") or (token_store_path + ".lock")

    provision_script_path = _get(env, "PROVISION_SCRIPT_PATH")
    if not os.path.isabs(provision_script_path):
        raise ConfigError(
            f"{_ENV_PREFIX}PROVISION_SCRIPT_PATH must be an absolute path: {provision_script_path!r}"
        )
    if not os.path.isfile(provision_script_path):
        raise ConfigError(
            f"{_ENV_PREFIX}PROVISION_SCRIPT_PATH does not exist or is not a file: {provision_script_path!r}"
        )

    # Optional - see AppConfig.sudo_path. Not in _REQUIRED_KEYS: an unset/
    # blank value means sudo is not used at all (B8B1B/C1's direct-
    # invocation behavior, unchanged). When set, it is held to the same
    # "absolute and actually a file" bar as provision_script_path - a
    # future production sudo argv must never be built from a relative or
    # nonexistent path.
    sudo_path = _get(env, "SUDO_PATH")
    if sudo_path:
        if not os.path.isabs(sudo_path):
            raise ConfigError(f"{_ENV_PREFIX}SUDO_PATH must be an absolute path: {sudo_path!r}")
        if not os.path.isfile(sudo_path):
            raise ConfigError(f"{_ENV_PREFIX}SUDO_PATH does not exist or is not a file: {sudo_path!r}")

    timeout_raw = _get(env, "SUBPROCESS_TIMEOUT_SECONDS")
    try:
        subprocess_timeout_seconds = float(timeout_raw)
    except ValueError:
        raise ConfigError(f"{_ENV_PREFIX}SUBPROCESS_TIMEOUT_SECONDS is not a number: {timeout_raw!r}")
    if subprocess_timeout_seconds <= 0:
        raise ConfigError(f"{_ENV_PREFIX}SUBPROCESS_TIMEOUT_SECONDS must be positive: {subprocess_timeout_seconds}")

    api_port_raw = _get(env, "API_PORT")
    try:
        api_port = int(api_port_raw)
    except ValueError:
        raise ConfigError(f"{_ENV_PREFIX}API_PORT is not an integer: {api_port_raw!r}")
    if not (1 <= api_port <= 65535):
        raise ConfigError(f"{_ENV_PREFIX}API_PORT out of range: {api_port}")

    activation_store_path = _get(env, "ACTIVATION_STORE_PATH")
    activation_lock_path = _get(env, "ACTIVATION_LOCK_PATH") or (
        activation_store_path + ".lock" if activation_store_path else ""
    )

    xray_store_path = _get(env, "XRAY_STORE_PATH")
    xray_lock_path = _get(env, "XRAY_LOCK_PATH") or (
        xray_store_path + ".lock" if xray_store_path else ""
    )
    xray_server_port_raw = _get(env, "XRAY_SERVER_PORT")
    xray_server_port = 0
    if xray_server_port_raw:
        try:
            xray_server_port = int(xray_server_port_raw)
        except ValueError:
            raise ConfigError(f"{_ENV_PREFIX}XRAY_SERVER_PORT is not an integer: {xray_server_port_raw!r}")
        if not (1 <= xray_server_port <= 65535):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_SERVER_PORT out of range: {xray_server_port}")
    xray_server_name = _get(env, "XRAY_SERVER_NAME")

    # Same whitelist as Android's XrayVlessRealityConfig validator (confirmed
    # against xray-core's common/utils/browser.go - see
    # docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md) - a fingerprint Android would
    # reject must never be handed out by the server either.
    xray_fingerprint = _get(env, "XRAY_FINGERPRINT")
    if xray_fingerprint and xray_fingerprint not in ("chrome", "firefox", "safari", "edge"):
        raise ConfigError(f"{_ENV_PREFIX}XRAY_FINGERPRINT is not one of chrome/firefox/safari/edge: {xray_fingerprint!r}")

    # Same base64.RawURLEncoding X25519 public-key shape the pinned `xray
    # x25519` tool emits and Android's REALITY_PUBLIC_KEY_REGEX requires -
    # 32 raw bytes -> 43 chars, no padding.
    xray_reality_public_key = _get(env, "XRAY_REALITY_PUBLIC_KEY")
    if xray_reality_public_key and not re.match(r"^[A-Za-z0-9_-]{43}$", xray_reality_public_key):
        raise ConfigError(f"{_ENV_PREFIX}XRAY_REALITY_PUBLIC_KEY is not a well-formed X25519 public key")

    # Even-length hex, matching both xray_config_renderer.py's own
    # RealityServerConfig validation and Android's SHORT_ID_REGEX.
    xray_short_id = _get(env, "XRAY_SHORT_ID")
    if xray_short_id and not re.match(r"^[0-9a-fA-F]{2,16}$", xray_short_id):
        raise ConfigError(f"{_ENV_PREFIX}XRAY_SHORT_ID is not valid hex: {xray_short_id!r}")
    if xray_short_id and len(xray_short_id) % 2 != 0:
        raise ConfigError(f"{_ENV_PREFIX}XRAY_SHORT_ID must have an even number of hex digits: {xray_short_id!r}")

    # Same whitelist as Android's XrayVlessRealityConfig validator and
    # xray-core's own proxy/vless package (only "xtls-rprx-vision" is
    # actually implemented there, besides no flow at all).
    xray_flow = _get(env, "XRAY_FLOW")
    if xray_flow and xray_flow != "xtls-rprx-vision":
        raise ConfigError(f"{_ENV_PREFIX}XRAY_FLOW must be blank or 'xtls-rprx-vision': {xray_flow!r}")

    # B8K2A - the activation boundary's own paths/settings. Same
    # optional/blank-by-default convention: unset means the activation
    # pipeline is not configured, in which case provision_and_activate
    # must fail closed rather than silently skip activation - see
    # xray_activation.py.
    xray_reality_private_key_file = _get(env, "XRAY_REALITY_PRIVATE_KEY_FILE")
    if xray_reality_private_key_file:
        if not os.path.isabs(xray_reality_private_key_file):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_REALITY_PRIVATE_KEY_FILE must be an absolute path")
        if not os.path.isfile(xray_reality_private_key_file):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_REALITY_PRIVATE_KEY_FILE does not exist or is not a file")
    xray_staging_config_path = _get(env, "XRAY_STAGING_CONFIG_PATH")
    xray_activation_lock_path = _get(env, "XRAY_ACTIVATION_LOCK_PATH")
    xray_activation_last_hash_path = _get(env, "XRAY_ACTIVATION_LAST_HASH_PATH")
    xray_activation_wrapper_path = _get(env, "XRAY_ACTIVATION_WRAPPER_PATH")
    if xray_activation_wrapper_path and not os.path.isabs(xray_activation_wrapper_path):
        raise ConfigError(f"{_ENV_PREFIX}XRAY_ACTIVATION_WRAPPER_PATH must be an absolute path")
    xray_activation_timeout_raw = _get(env, "XRAY_ACTIVATION_TIMEOUT_SECONDS")
    xray_activation_timeout_seconds = 15.0
    if xray_activation_timeout_raw:
        try:
            xray_activation_timeout_seconds = float(xray_activation_timeout_raw)
        except ValueError:
            raise ConfigError(f"{_ENV_PREFIX}XRAY_ACTIVATION_TIMEOUT_SECONDS is not a number: {xray_activation_timeout_raw!r}")
        if xray_activation_timeout_seconds <= 0:
            raise ConfigError(f"{_ENV_PREFIX}XRAY_ACTIVATION_TIMEOUT_SECONDS must be positive")
    # xray_dest is server-only (never returned to a client - see
    # xray_config_renderer.RealityServerConfig.dest) so it is deliberately
    # NOT part of the client-facing completeness check below; it has its
    # own check in the activation-specific completeness group instead.
    xray_dest = _get(env, "XRAY_DEST")

    # /v1/xray-profile is considered "configured" the instant a store path
    # and a port are set (see handler.py's own gate) - if that much is
    # present, every other public-facing field it would hand to a client
    # must ALSO be present and well-formed. Half-configured is not a safe
    # middle ground: it would let the endpoint return a response with a
    # blank server_name/fingerprint/reality_public_key/short_id, which
    # Android's own XrayVlessRealityConfig validator would then reject -
    # fail closed at startup instead of at every request.
    xray_partially_configured = bool(xray_store_path or xray_server_port)
    if xray_partially_configured:
        missing = [
            name for name, value in (
                ("XRAY_STORE_PATH", xray_store_path),
                ("XRAY_SERVER_PORT", xray_server_port_raw),
                ("XRAY_SERVER_NAME", xray_server_name),
                ("XRAY_FINGERPRINT", xray_fingerprint),
                ("XRAY_REALITY_PUBLIC_KEY", xray_reality_public_key),
                ("XRAY_SHORT_ID", xray_short_id),
            ) if not value
        ]
        if missing:
            raise ConfigError(
                "partial Xray configuration: "
                + ", ".join(_ENV_PREFIX + k for k in missing)
                + " must all be set once any Xray setting is set (or none of them, to leave /v1/xray-profile unconfigured)"
            )

        # B8K2A - the activation pipeline is a SEPARATE completeness group:
        # a deployment could (in principle) want /v1/xray-profile to
        # answer with static, pre-activated client-facing values while
        # the activation boundary is provisioned in a later step - so this
        # is checked only once xray_partially_configured is already true,
        # not folded into the group above.
        activation_missing = [
            name for name, value in (
                ("XRAY_REALITY_PRIVATE_KEY_FILE", xray_reality_private_key_file),
                ("XRAY_STAGING_CONFIG_PATH", xray_staging_config_path),
                ("XRAY_ACTIVATION_LOCK_PATH", xray_activation_lock_path),
                ("XRAY_ACTIVATION_LAST_HASH_PATH", xray_activation_last_hash_path),
                ("XRAY_ACTIVATION_WRAPPER_PATH", xray_activation_wrapper_path),
                ("XRAY_DEST", xray_dest),
            ) if not value
        ]
        if activation_missing:
            raise ConfigError(
                "partial Xray activation configuration: "
                + ", ".join(_ENV_PREFIX + k for k in activation_missing)
                + " must all be set once any Xray setting is set"
            )

        # B8K3A - the one consistency check that actually matters here:
        # XRAY_SERVER_NAME (the REALITY camouflage SNI Android is told to
        # present, and the same value the server's own realitySettings.
        # serverNames must accept) and XRAY_DEST (the REAL external TLS
        # target the server proxies non-REALITY-authenticated traffic to)
        # must name the SAME hostname - never Nova's own gateway address
        # (endpoint_host/xray_server_address, a completely different axis:
        # what a client's TCP socket connects to, not what SNI it presents).
        # A mismatch here would mean the server accepts a REALITY ClientHello
        # camouflaged as one site while actually proxying disguise traffic
        # to a different one - either breaks REALITY's own validation inside
        # the pinned Xray binary, or (worse) silently produces a REALITY
        # config that doesn't camouflage as the SNI it claims to.
        dest_host = xray_dest.rsplit(":", 1)[0] if xray_dest else ""
        if xray_server_name and dest_host and dest_host != xray_server_name:
            raise ConfigError(
                f"{_ENV_PREFIX}XRAY_SERVER_NAME ({xray_server_name!r}) and the host portion of "
                f"{_ENV_PREFIX}XRAY_DEST ({dest_host!r}) must be the same hostname - REALITY's "
                "camouflage SNI and its real proxy target must match"
            )
        if xray_server_name == endpoint_host or dest_host == endpoint_host:
            raise ConfigError(
                f"{_ENV_PREFIX}XRAY_SERVER_NAME/XRAY_DEST must never be Nova's own gateway address "
                f"({endpoint_host!r}) - that field is the REALITY camouflage target, a real third-party "
                "site, never this server's own hostname/IP"
            )

    # B8O2 - TLS/TCP fallback's own optional completeness group, checked
    # independently of REALITY's above (a deployment may run REALITY without
    # TLS, or - once B6 physical verification lands - both). Unlike REALITY's
    # server_name (a THIRD-PARTY camouflage domain, never this gateway's own
    # address), TLS's server_name IS this gateway's own address - see
    # xray_activation.build_tls_config's own docs for why: it is the identity
    # a REAL, publicly-trusted certificate (already reused from B8B2A) was
    # issued for, not a REALITY-style camouflage target.
    xray_tls_server_port_raw = _get(env, "XRAY_TLS_SERVER_PORT")
    xray_tls_server_port = 0
    if xray_tls_server_port_raw:
        try:
            xray_tls_server_port = int(xray_tls_server_port_raw)
        except ValueError:
            raise ConfigError(f"{_ENV_PREFIX}XRAY_TLS_SERVER_PORT is not an integer: {xray_tls_server_port_raw!r}")
        if not (1 <= xray_tls_server_port <= 65535):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_TLS_SERVER_PORT out of range: {xray_tls_server_port}")
    xray_tls_server_name = _get(env, "XRAY_TLS_SERVER_NAME")

    xray_tls_fingerprint = _get(env, "XRAY_TLS_FINGERPRINT")
    if xray_tls_fingerprint and xray_tls_fingerprint not in ("chrome", "firefox", "safari", "edge"):
        raise ConfigError(f"{_ENV_PREFIX}XRAY_TLS_FINGERPRINT is not one of chrome/firefox/safari/edge: {xray_tls_fingerprint!r}")

    xray_tls_cert_file = _get(env, "XRAY_TLS_CERT_FILE")
    xray_tls_key_file = _get(env, "XRAY_TLS_KEY_FILE")

    xray_tls_partially_configured = bool(xray_tls_server_port or xray_tls_server_name or xray_tls_cert_file or xray_tls_key_file)
    if xray_tls_partially_configured:
        tls_missing = [
            name for name, value in (
                ("XRAY_TLS_SERVER_PORT", xray_tls_server_port_raw),
                ("XRAY_TLS_SERVER_NAME", xray_tls_server_name),
                ("XRAY_TLS_FINGERPRINT", xray_tls_fingerprint),
                ("XRAY_TLS_CERT_FILE", xray_tls_cert_file),
                ("XRAY_TLS_KEY_FILE", xray_tls_key_file),
            ) if not value
        ]
        if tls_missing:
            raise ConfigError(
                "partial Xray TLS configuration: "
                + ", ".join(_ENV_PREFIX + k for k in tls_missing)
                + " must all be set once any Xray TLS setting is set (or none of them, to leave TLS/TCP unconfigured)"
            )
        if not os.path.isabs(xray_tls_cert_file) or not os.path.isfile(xray_tls_cert_file):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_TLS_CERT_FILE must be an absolute path to an existing file")
        if not os.path.isabs(xray_tls_key_file) or not os.path.isfile(xray_tls_key_file):
            raise ConfigError(f"{_ENV_PREFIX}XRAY_TLS_KEY_FILE must be an absolute path to an existing file")
        # A TLS inbound is a SEPARATE public TCP listener from REALITY's own
        # (see docs/B8O1A_TLS_GATEWAY_INBOUND_AUDIT.md) - two inbounds on the
        # same port is a config Xray would refuse at best, or silently
        # misbehave at worst; fail closed here instead.
        if xray_server_port and xray_tls_server_port == xray_server_port:
            raise ConfigError(
                f"{_ENV_PREFIX}XRAY_TLS_SERVER_PORT must differ from {_ENV_PREFIX}XRAY_SERVER_PORT "
                "- REALITY and TLS are separate xray-core inbounds and cannot share one listen port"
            )
        # TLS's own activation-boundary completeness (staging/lock/wrapper) is
        # shared with REALITY's group above - both inbounds are rendered into
        # the SAME Xray config file and activated together (see
        # xray_activation.activate_if_needed) - so TLS being configured
        # without that shared boundary already configured would leave it
        # unreachable, the same "half-configured is not a safe middle ground"
        # reasoning as REALITY's own activation_missing check above.
        if not xray_activation_wrapper_path:
            raise ConfigError(
                "partial Xray TLS configuration: the shared Xray activation boundary "
                f"({_ENV_PREFIX}XRAY_ACTIVATION_WRAPPER_PATH etc.) must be configured before TLS can be enabled"
            )

    # B12 - see AppConfig.manifest_path's own docs. When set, held to the
    # same "absolute and actually a file" bar as every other file-path
    # config value above (provision_script_path, xray_tls_cert_file, ...) -
    # fail closed at startup, never at first request.
    manifest_path = _get(env, "MANIFEST_PATH")
    if manifest_path:
        if not os.path.isabs(manifest_path):
            raise ConfigError(f"{_ENV_PREFIX}MANIFEST_PATH must be an absolute path: {manifest_path!r}")
        if not os.path.isfile(manifest_path):
            raise ConfigError(f"{_ENV_PREFIX}MANIFEST_PATH does not exist or is not a file: {manifest_path!r}")

    return AppConfig(
        endpoint_host=endpoint_host,
        endpoint_port=endpoint_port,
        gateway_public_key=gateway_public_key,
        gateway_tunnel_ip=gateway_tunnel_ip,
        token_store_path=token_store_path,
        token_lock_path=token_lock_path,
        provision_script_path=provision_script_path,
        subprocess_timeout_seconds=subprocess_timeout_seconds,
        api_port=api_port,
        sudo_path=sudo_path,
        activation_store_path=activation_store_path,
        activation_lock_path=activation_lock_path,
        xray_store_path=xray_store_path,
        xray_lock_path=xray_lock_path,
        xray_server_port=xray_server_port,
        xray_server_name=xray_server_name,
        xray_fingerprint=xray_fingerprint,
        xray_reality_public_key=xray_reality_public_key,
        xray_short_id=xray_short_id,
        xray_flow=xray_flow,
        xray_reality_private_key_file=xray_reality_private_key_file,
        xray_staging_config_path=xray_staging_config_path,
        xray_activation_lock_path=xray_activation_lock_path,
        xray_activation_last_hash_path=xray_activation_last_hash_path,
        xray_activation_wrapper_path=xray_activation_wrapper_path,
        xray_activation_timeout_seconds=xray_activation_timeout_seconds,
        xray_dest=xray_dest,
        xray_tls_server_port=xray_tls_server_port,
        xray_tls_server_name=xray_tls_server_name,
        xray_tls_fingerprint=xray_tls_fingerprint,
        xray_tls_cert_file=xray_tls_cert_file,
        xray_tls_key_file=xray_tls_key_file,
        manifest_path=manifest_path,
    )
