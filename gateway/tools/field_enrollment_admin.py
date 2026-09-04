#!/usr/bin/env python3
"""Operator CLI for the Russia field-test zero-touch enrollment mechanism
(gateway/api/field_enrollment.py). A field-enrolled device's credential is
NEVER stored raw anywhere (see that module's own docstring) - so, unlike
gateway/tools/activation_tokens.py's `revoke <ACTIVATION_ID>` (which still
works completely unmodified on a field-enrolled record, since it is an
ordinary activation record), an operator first needs a way to go from
"this device's public key" to "its activation_id", without ever needing the
credential itself. That is the ONE thing this tool adds - it is a thin
lookup/listing layer, never a second store or a second revocation authority.

    field_enrollment_admin.py --store PATH [--lock PATH] --secret-file PATH \
        find <PUBLIC_KEY>
    field_enrollment_admin.py --store PATH [--lock PATH] list
    field_enrollment_admin.py --store PATH [--lock PATH] --secret-file PATH \
        revoke <PUBLIC_KEY>

`find`/`revoke` re-derive the device's credential deterministically from
its public key and the SAME secret file the running API's
FIELD_ENROLLMENT_HMAC_SECRET_FILE points at (never read raw credential
input from the operator - there is none). `list` never needs the secret at
all - it only ever prints activation_id/status/created_at/bound public
keys, exactly what gateway/tools/activation_tokens.py's own `list` already
shows for any activation record.

`revoke` is a thin wrapper around gateway/api/activations.revoke_activation
- the SAME function/lock discipline/effect `activation_tokens.py revoke`
already uses. There is deliberately no separate revocation code path for a
field-enrolled device.
"""
import argparse
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import activations as activations_module  # noqa: E402
from api import field_enrollment as field_enrollment_module  # noqa: E402
from api.wgkey import is_valid_wg_public_key  # noqa: E402


def _resolve_lock_path(args):
    return args.lock or (args.store + ".lock")


def _read_secret(path):
    with open(path, "rb") as handle:
        return handle.read().strip()


def _find_activation_id(store_path, lock_path, secret_file, public_key):
    if not is_valid_wg_public_key(public_key):
        print(f"error: not a well-formed AmneziaWG/WireGuard public key: {public_key!r}", file=sys.stderr)
        return None
    secret = _read_secret(secret_file)
    try:
        credential = field_enrollment_module.derive_credential(secret, public_key)
        digest = activations_module.credential_digest(credential)
    finally:
        secret = None
        credential = None
    record = activations_module.find_by_credential_digest(store_path, lock_path, digest)
    if record is None:
        print(f"error: no field-enrollment record found for public key {public_key}", file=sys.stderr)
        return None
    return record["activation_id"]


def cmd_find(args):
    activation_id = _find_activation_id(args.store, _resolve_lock_path(args), args.secret_file, args.public_key)
    if activation_id is None:
        return 1
    print(activation_id)
    return 0


def cmd_list(args):
    records = activations_module.list_all(args.store, _resolve_lock_path(args))
    if not records:
        print("(no activation records)")
        return 0
    for record in records:
        device_keys = ", ".join(d["public_key"] for d in record["bound_devices"]) or "(none bound yet)"
        print(
            f"{record['activation_id']}  status={record['status']}  "
            f"max_devices={record['max_devices']}  created_at={record['created_at']}  "
            f"devices=[{device_keys}]"
        )
    return 0


def cmd_revoke(args):
    activation_id = _find_activation_id(args.store, _resolve_lock_path(args), args.secret_file, args.public_key)
    if activation_id is None:
        return 1
    changed = activations_module.revoke_activation(args.store, _resolve_lock_path(args), activation_id)
    if changed:
        print(f"revoked {activation_id} (public key {args.public_key})")
    else:
        print(f"{activation_id} was already revoked")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", required=True, help="path to the activation store (the SAME file FIELD_ENROLLMENT is configured against)")
    parser.add_argument("--lock", default=None, help='defaults to "<store>.lock"')

    subparsers = parser.add_subparsers(dest="command", required=True)

    find_parser = subparsers.add_parser("find", help="print the activation_id for a field-enrolled device's public key")
    find_parser.add_argument("public_key")
    find_parser.add_argument("--secret-file", required=True, help="the FIELD_ENROLLMENT_HMAC_SECRET_FILE this deployment uses")
    find_parser.set_defaults(func=cmd_find)

    list_parser = subparsers.add_parser("list", help="list every activation record in the store (field-enrolled or not)")
    list_parser.set_defaults(func=cmd_list)

    revoke_parser = subparsers.add_parser("revoke", help="revoke a field-enrolled device's activation by its public key")
    revoke_parser.add_argument("public_key")
    revoke_parser.add_argument("--secret-file", required=True, help="the FIELD_ENROLLMENT_HMAC_SECRET_FILE this deployment uses")
    revoke_parser.set_defaults(func=cmd_revoke)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (activations_module.ActivationStoreError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
