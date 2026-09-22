"""B46-4P - deterministic Hysteria2 SERVER config renderer.

Unlike gateway/api/xray_config_renderer.py, this is NOT re-rendered on
every activation/device change. Hysteria2's own `auth.type: http` backend
(see docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "Server auth
architecture") answers with LIVE activation state on every connection
attempt - the Hysteria2 server's own YAML config never needs to know
about individual devices/activations at all. It is a small, static file,
rendered once (or whenever one of its own few inputs changes - a port,
cert path, or the auth backend's own loopback port), never on a
provisioning-loop cadence the way Xray's REALITY client list is.

Static shape, intentionally minimal (mirrors gateway/xray/README.md's own
"minimal, single-purpose config" discipline): `listen`/`tls`/
`auth.type: http` only.

No `obfs:` block at all - B46-4A Finding 8 (see
docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md): this production slice
only ever offers the signed `obfuscationMode: NONE`, and upstream
Hysteria2 has no per-connection Salamander secret this architecture could
configure here even if a future slice wanted SALAMANDER - omitting the
block entirely is the correct "NONE" representation, never a block with
an empty/fabricated password.

No `quic:`/`masquerade:`/`acl:`/`outbounds:`/`resolver:`/`sniff:`/
`trafficStats:`/`mimic:`/`congestion:`/`bandwidth:`/`ech:`/`acme:` block -
none of B46-4A's own design docs call for any of these, and this module
does not invent tuning values that were never specified. `acme:` in
particular is deliberately never used: this gateway's existing TLS
certificate lifecycle (Let's Encrypt via `gateway/edge/pocvpn-cert-check.sh`,
see gateway/hysteria/README.md's own TLS section) is reused as-is, never
a second, Hysteria2-managed ACME flow.
"""
import os
import tempfile
from dataclasses import dataclass


class HysteriaServerConfigRenderError(Exception):
    """Raised when a required production value is missing/malformed - fails
    closed rather than emitting a config the pinned Hysteria2 binary would
    refuse to start with, or (worse) silently misinterpret."""


@dataclass(frozen=True)
class HysteriaServerConfig:
    """Every field here is a production value this repository does NOT
    decide on its own (see gateway/hysteria/README.md's "Production
    values not yet decided" section) - the caller must supply real values
    only once the corresponding B46-4P blocker is actually resolved
    (listen_port needs #3, tls_cert_file/tls_key_file need #4).
    auth_backend_url is the one field this repo's own deployment DOES
    get to choose (a loopback-only URL never exposed publicly - see
    README's port-numbering note) but it is still a real, explicit value,
    never a default silently baked into this module - see
    render_server_config_yaml's own validation.
    """

    listen_port: int
    tls_cert_file: str
    tls_key_file: str
    auth_backend_url: str


def _validate(config: HysteriaServerConfig) -> None:
    if not (1 <= config.listen_port <= 65535):
        raise HysteriaServerConfigRenderError(f"invalid listen_port: {config.listen_port}")
    if not config.tls_cert_file or not os.path.isabs(config.tls_cert_file):
        raise HysteriaServerConfigRenderError("tls_cert_file must be an absolute path")
    if not config.tls_key_file or not os.path.isabs(config.tls_key_file):
        raise HysteriaServerConfigRenderError("tls_key_file must be an absolute path")
    # B46-4A's own auth architecture requires the Hysteria2 server to
    # reach the auth backend over LOOPBACK ONLY - never a public address
    # (docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "Server auth
    # architecture": "reachable ONLY from the Hysteria2 server process on
    # the same host - never the public interface, never routed through
    # the internet-facing nginx edge"). Fail closed rather than render a
    # config that would silently violate that boundary.
    if not (config.auth_backend_url.startswith("http://127.0.0.1:") or config.auth_backend_url.startswith("https://127.0.0.1:")):
        raise HysteriaServerConfigRenderError(
            f"auth_backend_url must be a loopback (127.0.0.1) URL, got: {config.auth_backend_url!r}"
        )


def render_server_config_yaml(config: HysteriaServerConfig) -> str:
    """Pure, deterministic: the same input always produces the same
    output. See module docstring for exactly which upstream config
    sections are and are not represented."""
    _validate(config)
    return (
        f"listen: :{config.listen_port}\n"
        "\n"
        "tls:\n"
        f"  cert: {config.tls_cert_file}\n"
        f"  key: {config.tls_key_file}\n"
        "\n"
        "auth:\n"
        "  type: http\n"
        "  http:\n"
        f"    url: {config.auth_backend_url}\n"
        "    insecure: false\n"
    )


def atomic_write_config(config_path: str, yaml_text: str) -> None:
    """Same atomic-replace discipline as
    gateway/api/xray_config_renderer.atomic_write_config /
    gateway/api/hysteria_store.atomic_write_store: write to a sibling tmp
    file in the SAME directory (so os.replace is on the same filesystem),
    fsync before replace, os.replace - a crash mid-write never corrupts or
    partially-overwrites a previously-good config. Always written at
    0600: this file's `tls.key` line names a private-key file PATH, and
    this gateway's own convention (see gateway/systemd/nova-xray.service's
    own config-file mode) treats that path itself as not meant to be
    world-readable metadata, independent of whether the target filesystem
    permissions already enforce that."""
    directory = os.path.dirname(config_path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".hysteria-config-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(yaml_text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, config_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _config_from_env(env: dict) -> HysteriaServerConfig:
    """CLI/deploy-time entry point - see gateway/hysteria/README.md for
    the full env var reference. Every value is required; a missing one is
    a loud KeyError, never a silently-accepted empty default (this is a
    ONE-TIME-per-change deploy step, not a request-path hot path, so a
    startup-time crash is exactly the right failure mode - never emit a
    partially-configured server config)."""
    missing = [
        name for name in ("NOVA_HYSTERIA2_LISTEN_PORT", "NOVA_HYSTERIA2_TLS_CERT_FILE", "NOVA_HYSTERIA2_TLS_KEY_FILE", "NOVA_HYSTERIA2_AUTH_BACKEND_URL")
        if not env.get(name)
    ]
    if missing:
        raise HysteriaServerConfigRenderError(f"missing required environment variable(s): {', '.join(missing)}")
    try:
        listen_port = int(env["NOVA_HYSTERIA2_LISTEN_PORT"])
    except ValueError:
        raise HysteriaServerConfigRenderError(f"NOVA_HYSTERIA2_LISTEN_PORT is not an integer: {env['NOVA_HYSTERIA2_LISTEN_PORT']!r}")
    return HysteriaServerConfig(
        listen_port=listen_port,
        tls_cert_file=env["NOVA_HYSTERIA2_TLS_CERT_FILE"],
        tls_key_file=env["NOVA_HYSTERIA2_TLS_KEY_FILE"],
        auth_backend_url=env["NOVA_HYSTERIA2_AUTH_BACKEND_URL"],
    )


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_path", help="Where to atomically write the rendered config.yaml")
    args = parser.parse_args(argv)
    config = _config_from_env(os.environ)
    yaml_text = render_server_config_yaml(config)
    atomic_write_config(args.output_path, yaml_text)
    print(f"Rendered: {args.output_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
