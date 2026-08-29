"""Required startup configuration for the B8B1B provisioning API.

Fail-closed by design: load_config() raises ConfigError, and the process
must refuse to start, if any required value is missing or invalid. There
is deliberately NO bind-host field anywhere in AppConfig - the listen
address is hard-coded to 127.0.0.1 in server.py and is not configurable
from here or anywhere else, per the B8B1B server-boundary requirement.
"""
import ipaddress
import os
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
    # exactly like activation_store_path above. None of these fields ever
    # include the REALITY server PRIVATE key - only public-safe values a
    # client is allowed to receive verbatim (see xray_config_renderer.py's
    # own docstring for why the private key never needs to flow through
    # this API process at all).
    xray_store_path: str = ""
    xray_lock_path: str = ""
    xray_server_port: int = 0
    xray_server_name: str = ""
    xray_fingerprint: str = ""
    xray_reality_public_key: str = ""
    xray_short_id: str = ""
    xray_flow: str = ""


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
    xray_fingerprint = _get(env, "XRAY_FINGERPRINT")
    xray_reality_public_key = _get(env, "XRAY_REALITY_PUBLIC_KEY")
    xray_short_id = _get(env, "XRAY_SHORT_ID")
    xray_flow = _get(env, "XRAY_FLOW")

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
    )
