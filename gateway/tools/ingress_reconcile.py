#!/usr/bin/env python3
"""B25 (task I) - the ingress-role counterpart of xray_reconcile.py: operator/
startup recovery convergence for the ingress activation boundary (client-
facing REALITY/TLS inbound, upstream-relay outbound to the pinned EXIT).
Safe to run after a process crash, host reboot, a failed prior reload, or a
durable revocation whose reload attempt failed - see
gateway/api/ingress_activation.reconcile's own docstring.

Idempotent - see ingress_activation.activate_if_needed's own "skip if
unchanged" optimization.

    ingress_reconcile.py --env-file /etc/pocvpn/ingress.env
"""
import argparse
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import ingress_activation as ingress_activation_module  # noqa: E402
from api import ingress_config as ingress_config_module  # noqa: E402


def _fail(message):
    print(f"ingress_reconcile: error: {message}", file=sys.stderr)
    raise SystemExit(1)


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
        prog="ingress_reconcile.py",
        description="B25 - idempotent recovery convergence for the ingress activation boundary",
    )
    parser.add_argument("--env-file", required=True, help="path to the ingress env file (e.g. /etc/pocvpn/ingress.env)")
    args = parser.parse_args(argv)

    try:
        env = dict(os.environ)
        env.update(_parse_env_file(args.env_file))
        ingress_cfg = ingress_config_module.load_ingress_config(env=env)
    except ingress_config_module.IngressConfigError as exc:
        _fail(f"config error: {exc}")
        return

    if ingress_cfg is None:
        _fail("no NOVA_INGRESS_* variable is set in this env file - ingress role is not configured")
        return

    result = ingress_activation_module.reconcile(ingress_cfg)
    if result.activated:
        if result.skipped:
            print(f"ingress_reconcile[{ingress_cfg.ingress_endpoint_id}]: already converged - no change needed")
        else:
            print(f"ingress_reconcile[{ingress_cfg.ingress_endpoint_id}]: converged - running Xray now reflects current canonical state")
        return

    kind = getattr(result.error, "kind", "internal")
    _fail(f"convergence FAILED (kind={kind}) - see stderr from the activation wrapper for detail; retry later")


if __name__ == "__main__":
    main()
