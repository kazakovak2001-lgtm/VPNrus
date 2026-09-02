#!/usr/bin/env python3
"""B26 (task G) - the operator-safe EXIT-side apply/revoke boundary for the
ingress->exit relay identity gateway/tools/provision_relay_upstream_identity.py
mints (its "exit fragment" JSON output). Wraps relay_identity_store.py's
upsert/remove behind a small, idempotent CLI - see that module's own docs
for the exact isolation/idempotency guarantees.

Deliberately does NOT itself reload the live Xray service - it only writes
the EXIT's own POCVPN_API_STATIC_RELAY_CLIENTS_FILE. Reloading remains a
SEPARATE, already-existing step (gateway/tools/xray_reconcile.py), which
reuses the SAME render -> `xray run -test` -> stage -> atomic replace ->
reload -> rollback pipeline every other config change on this EXIT already
goes through - this script never duplicates that pipeline, it only changes
one of its inputs.

    # apply (from the exit-fragment file provision_relay_upstream_identity.py wrote):
    apply_relay_upstream_identity.py apply \\
        --static-clients-file /etc/pocvpn/static-relay-clients.json \\
        --exit-fragment-file /tmp/ru-ingress-1-exit-fragment.json

    # or apply explicit values directly:
    apply_relay_upstream_identity.py apply \\
        --static-clients-file /etc/pocvpn/static-relay-clients.json \\
        --activation-id relay-ru-ingress-1 \\
        --device-public-key relay:ru-ingress-1 \\
        --vless-uuid 11111111-1111-1111-1111-111111111111

    # revoke:
    apply_relay_upstream_identity.py revoke \\
        --static-clients-file /etc/pocvpn/static-relay-clients.json \\
        --activation-id relay-ru-ingress-1

    # then, on THIS exit host, converge the running service:
    xray_reconcile.py --env-file /etc/pocvpn/api.env
"""
import argparse
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import relay_identity_store as store_module  # noqa: E402


def _fail(message):
    print(f"apply_relay_upstream_identity: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _load_exit_fragment(path):
    with open(path, "r", encoding="utf-8") as handle:
        fragment = json.load(handle)
    for key in ("activation_id", "device_public_key", "vless_uuid"):
        if key not in fragment:
            _fail(f"exit-fragment file is missing required field {key!r}")
    return fragment["activation_id"], fragment["device_public_key"], fragment["vless_uuid"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="apply_relay_upstream_identity.py",
        description="B26 (task G) - apply/revoke an ingress->exit relay identity on THIS exit's static-clients file",
    )
    parser.add_argument("action", choices=("apply", "revoke", "status"))
    parser.add_argument("--static-clients-file", required=True, help="this EXIT's POCVPN_API_STATIC_RELAY_CLIENTS_FILE path")
    parser.add_argument("--exit-fragment-file", help="apply only: path to provision_relay_upstream_identity.py's exit-fragment JSON output")
    parser.add_argument("--activation-id", help="apply/revoke: the relay's activation_id (e.g. relay-ru-ingress-1)")
    parser.add_argument("--device-public-key", help="apply only (with explicit values): the relay's device_public_key label")
    parser.add_argument("--vless-uuid", help="apply only (with explicit values): the relay's vless uuid")
    args = parser.parse_args(argv)

    if args.action == "status":
        try:
            clients = store_module.load_static_clients(args.static_clients_file)
        except store_module.RelayIdentityStoreError as exc:
            _fail(f"static clients file is corrupted: {exc}")
            return
        if not clients:
            print("apply_relay_upstream_identity: no relay identities currently applied")
            return
        for client in clients:
            print(f"  activation_id={client.activation_id}  device_public_key={client.device_public_key}  vless_uuid=<redacted>")
        return

    if args.action == "revoke":
        if not args.activation_id:
            _fail("--activation-id is required for revoke")
        store_module.remove(args.static_clients_file, args.activation_id)
        print(f"apply_relay_upstream_identity: revoked activation_id={args.activation_id} from {args.static_clients_file}")
        print("apply_relay_upstream_identity: run xray_reconcile.py on THIS host next to converge the running service")
        return

    # action == "apply"
    if args.exit_fragment_file:
        activation_id, device_public_key, vless_uuid = _load_exit_fragment(args.exit_fragment_file)
    else:
        if not (args.activation_id and args.device_public_key and args.vless_uuid):
            _fail("apply requires either --exit-fragment-file, or all three of --activation-id/--device-public-key/--vless-uuid")
        activation_id, device_public_key, vless_uuid = args.activation_id, args.device_public_key, args.vless_uuid

    try:
        store_module.upsert(args.static_clients_file, activation_id, device_public_key, vless_uuid)
    except store_module.RelayIdentityStoreError as exc:
        _fail(f"invalid relay identity: {exc}")
        return
    print(f"apply_relay_upstream_identity: applied activation_id={activation_id} to {args.static_clients_file} (uuid not printed)")
    print("apply_relay_upstream_identity: run xray_reconcile.py on THIS host next to converge the running service")


if __name__ == "__main__":
    main()
