#!/usr/bin/env python3
"""B8K2A - operator/startup recovery convergence for the Xray activation
boundary. Safe to run after a process crash, host reboot, a failed prior
reload, or a durable revocation whose reload attempt failed - see
gateway/api/xray_activation.reconcile's own docstring.

Idempotent: running this with nothing changed since the last successful
activation is a cheap no-op (see xray_activation.activate_if_needed's own
"skip if unchanged" optimization) - safe to run as often as an operator
likes, and safe to wire into a periodic timer later if desired (NOT done
by this slice - see B8K2A's own scope notes on why an explicit command is
preferred for now).

    xray_reconcile.py --env-file /etc/pocvpn/api.env
"""
import argparse
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import config as config_module  # noqa: E402
from api import xray_activation as xray_activation_module  # noqa: E402


def _fail(message):
    print(f"xray_reconcile: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _parse_env_file(path):
    """Minimal KEY=VALUE parser for an env-style file - same shape as
    activation_tokens.py's own helper of the same name (each gateway/tools/
    CLI is deliberately standalone, no cross-imports between them)."""
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
        prog="xray_reconcile.py",
        description="B8K2A - idempotent recovery convergence for the Xray activation boundary",
    )
    parser.add_argument("--env-file", required=True, help="path to the pocvpn-api env file (e.g. /etc/pocvpn/api.env)")
    args = parser.parse_args(argv)

    try:
        env = dict(os.environ)
        env.update(_parse_env_file(args.env_file))
        app_config = config_module.load_config(env=env)
    except config_module.ConfigError as exc:
        _fail(f"config error: {exc}")
        return

    if not app_config.xray_activation_wrapper_path:
        _fail("Xray activation boundary is not configured in this env file")
        return

    result = xray_activation_module.reconcile(app_config)
    if result.activated:
        if result.skipped:
            print("xray_reconcile: already converged - no change needed")
        else:
            print("xray_reconcile: converged - running Xray now reflects current canonical state")
        return

    kind = getattr(result.error, "kind", "internal")
    _fail(f"convergence FAILED (kind={kind}) - see stderr from the activation wrapper for detail; retry later")


if __name__ == "__main__":
    main()
