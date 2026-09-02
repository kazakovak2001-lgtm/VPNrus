#!/usr/bin/env python3
"""B25 (task I) - read-only ingress health/status command. Never mutates
anything: no lock is taken in exclusive mode, no config is rendered or
staged, no reload wrapper is invoked. Reports:

  - whether the ingress role is configured at all in this env file;
  - whether the last-activated config hash file exists (a proxy for "has
    this ingress ever been successfully activated since boot/reconcile");
  - a REDACTED render of what the NEXT activation would stage, for a human
    to sanity-check the routing/inbound shape without ever seeing the
    REALITY private key or the upstream relay uuid (task M's own "no
    secrets in diagnostics").

    ingress_status.py --env-file /etc/pocvpn/ingress.env
"""
import argparse
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import activations as activations_module  # noqa: E402
from api import ingress_activation as ingress_activation_module  # noqa: E402
from api import ingress_config as ingress_config_module  # noqa: E402
from api import xray_ingress_config_renderer as ingress_renderer  # noqa: E402
from api import xray_provisioning as xray_provisioning_module  # noqa: E402


def _parse_env_file(path):
    result = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            result[key.strip()] = value.strip()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ingress_status.py",
        description="B25 - read-only ingress health/status (secret-safe)",
    )
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of text")
    args = parser.parse_args(argv)

    env = dict(os.environ)
    env.update(_parse_env_file(args.env_file))

    try:
        ingress_cfg = ingress_config_module.load_ingress_config(env=env)
    except ingress_config_module.IngressConfigError as exc:
        report = {"configured": False, "config_error": str(exc)}
        print(json.dumps(report, indent=2) if args.json else f"ingress role: CONFIG ERROR: {exc}")
        raise SystemExit(1)

    if ingress_cfg is None:
        report = {"configured": False}
        print(json.dumps(report, indent=2) if args.json else "ingress role: not configured (no NOVA_INGRESS_* variable set)")
        return

    last_hash_present = os.path.isfile(ingress_cfg.ingress_activation_last_hash_path)
    last_hash = None
    if last_hash_present:
        with open(ingress_cfg.ingress_activation_last_hash_path, "r", encoding="utf-8") as handle:
            last_hash = handle.read().strip()

    render_error = None
    redacted_config = None
    try:
        reality = ingress_activation_module.build_reality_config(ingress_cfg)
        tls = ingress_activation_module.build_tls_config(ingress_cfg)
        upstream = ingress_activation_module.build_upstream_config(ingress_cfg)
        activations_data = activations_module.read_store_shared(ingress_cfg.activation_store_path, ingress_cfg.activation_lock_path)
        xray_data = xray_provisioning_module.read_store_shared(ingress_cfg.xray_store_path, ingress_cfg.xray_lock_path)
        redacted_config = ingress_renderer.render_ingress_server_config_redacted(
            activations_data, xray_data, reality, upstream, tls=tls, flow=ingress_cfg.ingress_flow,
        )
    except Exception as exc:  # noqa: BLE001 - status must never crash, only report
        render_error = f"{exc.__class__.__name__}: {exc}"

    client_count = None
    if redacted_config is not None:
        client_count = sum(
            len(inbound["settings"]["clients"]) for inbound in redacted_config["inbounds"]
        )

    report = {
        "configured": True,
        "ingress_endpoint_id": ingress_cfg.ingress_endpoint_id,
        "ingress_endpoint_host": ingress_cfg.ingress_endpoint_host,
        "upstream_host": ingress_cfg.ingress_upstream_host,
        "upstream_port": ingress_cfg.ingress_upstream_port,
        "upstream_transport": ingress_cfg.ingress_upstream_transport,
        "last_activated": last_hash_present,
        "last_activated_sha256": last_hash,
        "render_ok": render_error is None,
        "render_error": render_error,
        "active_client_count": client_count,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"ingress role: configured (endpoint_id={ingress_cfg.ingress_endpoint_id})")
        print(f"  client-facing host: {ingress_cfg.ingress_endpoint_host}")
        print(f"  upstream exit:      {ingress_cfg.ingress_upstream_host}:{ingress_cfg.ingress_upstream_port} ({ingress_cfg.ingress_upstream_transport})")
        print(f"  last activated:     {'yes (sha256=' + last_hash[:12] + '...)' if last_hash_present else 'no'}")
        if render_error:
            print(f"  render:             FAILED: {render_error}")
        else:
            print(f"  render:             ok, {client_count} active client(s) would be authorized")


if __name__ == "__main__":
    main()
