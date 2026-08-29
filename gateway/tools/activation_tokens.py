#!/usr/bin/env python3
"""B8C1 - operator CLI for activation/device-entitlement lifecycle
management. Mirrors gateway/tools/enrollment_tokens.py's structure and
stdout/stderr contract deliberately, for the same reasons: the raw
activation credential must be printed to stdout EXACTLY ONCE, on issue,
and NEVER written to the durable store (see gateway/api/activations.py,
which is the only place that ever writes it - as a SHA-256 digest, never
the raw value).

    activation_tokens.py --store PATH [--lock PATH] init
    activation_tokens.py --store PATH [--lock PATH] issue [--max-devices N] [--expires-in-days N]
    activation_tokens.py --store PATH [--lock PATH] revoke <ACTIVATION_ID>
    activation_tokens.py --store PATH [--lock PATH] status <ACTIVATION_ID>
    activation_tokens.py --store PATH [--lock PATH] list

--lock defaults to "<store>.lock".

Every mutating command (init/issue/revoke) acquires LOCK_EX and holds it
across the entire read -> validate -> decide -> durable-write sequence -
the SAME discipline the running API's own decide_and_bind/unbind_device
use, so a concurrent operator command and a concurrent live activation
request are always correctly serialized against each other via the
filesystem lock, never by in-process state alone.
"""
import argparse
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import activations as activations_module  # noqa: E402
from api import config as config_module  # noqa: E402
from api import xray_activation as xray_activation_module  # noqa: E402


def _parse_env_file(path):
    """Minimal KEY=VALUE parser for an env-style file (e.g. /etc/pocvpn/api.env) -
    blank lines and lines starting with # are skipped. Not a shell parser -
    values are taken literally, no quoting/expansion, matching this file's
    own env vars' actual shape (paths, ports, keys - never a value that
    needs shell semantics)."""
    result = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            result[key.strip()] = value.strip()
    return result


def _attempt_xray_convergence(args):
    """B8K2A - optional, opt-in only (--xray-env-file): revoke's effect on
    the RUNNING Xray process is realized by the SAME activate_if_needed
    pipeline POST /v1/xray-profile uses (see xray_activation.py's own
    docstring) - never a second revocation authority. Omitted entirely
    when --xray-env-file is not given, so every existing pure-AWG operator
    invocation of this CLI is completely unaffected."""
    if not getattr(args, "xray_env_file", None):
        return
    try:
        env = dict(os.environ)
        env.update(_parse_env_file(args.xray_env_file))
        app_config = config_module.load_config(env=env)
    except config_module.ConfigError as exc:
        print(f"activation_tokens: Xray convergence skipped - config error: {exc}", file=sys.stderr)
        return
    if not app_config.xray_activation_wrapper_path:
        print("activation_tokens: Xray activation boundary not configured - convergence skipped", file=sys.stderr)
        return

    result = xray_activation_module.reconcile(app_config)
    if result.activated:
        state = "already converged (no change needed)" if result.skipped else "converged"
        print(f"activation_tokens: Xray runtime {state}")
    else:
        kind = getattr(result.error, "kind", "internal")
        print(f"activation_tokens: WARNING - Xray runtime convergence FAILED (kind={kind}); "
              "revocation is still durably recorded and fail-closed, retry convergence "
              "separately (see gateway/tools/xray_reconcile.py)", file=sys.stderr)


def _fail(message):
    print(f"activation_tokens: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def cmd_init(args):
    created = activations_module.init_store(args.store, args.lock)
    if created:
        print(f"initialized empty activation store: {args.store}")
    else:
        print(f"already initialized: {args.store}")


def cmd_issue(args):
    try:
        activation_id, credential = activations_module.issue_activation(
            args.store, args.lock, args.max_devices, args.expires_in_days,
        )
    except (activations_module.ActivationStoreError, ValueError) as exc:
        _fail(str(exc))

    print(f"issued activation_id={activation_id} max_devices={args.max_devices}", file=sys.stderr)
    # Success stdout: the plaintext activation credential, exactly one
    # line, no prefix, nothing else - the ONLY place it is ever displayed.
    # It is never written to the durable store - see activations.py.
    sys.stdout.write(credential + "\n")
    sys.stdout.flush()


def cmd_revoke(args):
    try:
        changed = activations_module.revoke_activation(args.store, args.lock, args.activation_id)
    except activations_module.ActivationStoreError as exc:
        _fail(str(exc))
    except KeyError as exc:
        _fail(str(exc))

    if changed:
        print(f"activation_id={args.activation_id} revoked")
    else:
        print(f"activation_id={args.activation_id} is already REVOKED (no change)")

    # B8K2A - durable revocation is unconditional and already complete above
    # regardless of what happens next: this can only ever attempt to make
    # the RUNNING Xray process reflect it sooner, never undo it. See
    # _attempt_xray_convergence's own docs.
    _attempt_xray_convergence(args)


def _print_record(record):
    print(
        f"activation_id={record['activation_id']} status={record['status']} "
        f"max_devices={record['max_devices']} devices_bound={len(record['bound_devices'])} "
        f"created_at={record['created_at']} expires_at={record['expires_at']}"
    )


def cmd_status(args):
    try:
        record = activations_module.find_by_activation_id(args.store, args.lock, args.activation_id)
    except activations_module.ActivationStoreError as exc:
        _fail(str(exc))
    if record is None:
        _fail(f"no activation found with activation_id {args.activation_id}")
    _print_record(record)


def cmd_list(args):
    try:
        records = activations_module.list_all(args.store, args.lock)
    except activations_module.ActivationStoreError as exc:
        _fail(str(exc))
    for record in records:
        _print_record(record)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="activation_tokens.py", description="B8C1 activation/device-entitlement operator CLI"
    )
    parser.add_argument("--store", required=True, help="path to activations.json")
    parser.add_argument("--lock", help="path to .activations.lock (default: <store>.lock)")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty durable activation store if one doesn't exist")

    p_issue = sub.add_parser("issue", help="issue a new activation credential")
    p_issue.add_argument("--max-devices", type=int, default=1, help="device limit for this activation (default: 1)")
    p_issue.add_argument("--expires-in-days", type=float, default=None, help="optional expiry, in days from now")

    p_revoke = sub.add_parser("revoke", help="revoke an activation by its activation_id")
    p_revoke.add_argument("activation_id")
    p_revoke.add_argument(
        "--xray-env-file", default=None,
        help="B8K2A, optional - path to the pocvpn-api env file (e.g. /etc/pocvpn/api.env); "
             "if given, attempts to synchronously converge the running Xray process to reflect "
             "this revocation (see gateway/api/xray_activation.py). Omitted entirely by default - "
             "existing pure-AWG usage of this command is completely unaffected.",
    )

    p_status = sub.add_parser("status", help="show one activation's non-secret status by activation_id")
    p_status.add_argument("activation_id")

    sub.add_parser("list", help="list all activations' non-secret status")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.lock:
        args.lock = args.store + ".lock"

    dispatch = {
        "init": cmd_init,
        "issue": cmd_issue,
        "revoke": cmd_revoke,
        "status": cmd_status,
        "list": cmd_list,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
