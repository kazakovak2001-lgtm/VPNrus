#!/usr/bin/env python3
"""Operator CLI for the Russia field-test zero-touch enrollment mechanism
(gateway/api/field_enrollment.py). Round-2 review fix: field_enrollment.py
no longer derives a device's credential from a server secret - it looks up
the small, self-initializing FieldEnrollmentIndex (public key -> already-
issued credential/activation_id) that module itself owns. This tool is a
thin, read-mostly wrapper around that index plus the ordinary
activations.py revoke primitive - never a second store, never a second
revocation authority.

    field_enrollment_admin.py --index PATH [--index-lock PATH] list
    field_enrollment_admin.py --index PATH [--index-lock PATH] find <PUBLIC_KEY>
    field_enrollment_admin.py --index PATH [--index-lock PATH] \
        --store PATH [--lock PATH] revoke <PUBLIC_KEY>

`list`/`find` never need the activation store at all (the index already
carries the activation_id). `revoke` additionally needs `--store`/`--lock`
(the SAME activation store this deployment's POCVPN_API_ACTIVATION_STORE_PATH
names) to actually call activations.revoke_activation, then purges the
index entry so a later enrollment attempt for that same public key is
treated as genuinely fresh (a new random credential, a new activation
record) rather than replaying the now-revoked one forever.
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


def _index_lock_path(args):
    return args.index_lock or (args.index + ".lock")


def _store_lock_path(args):
    return args.lock or (args.store + ".lock")


def cmd_list(args):
    entries = field_enrollment_module.list_index(args.index, _index_lock_path(args))
    if not entries:
        print("(no field-enrolled devices)")
        return 0
    for public_key, entry in sorted(entries.items()):
        print(f"{entry['activation_id']}  public_key={public_key}  created_at={entry['created_at']}")
    return 0


def cmd_find(args):
    entry = field_enrollment_module.find_in_index(args.index, _index_lock_path(args), args.public_key)
    if entry is None:
        print(f"error: no field-enrollment record found for public key {args.public_key}", file=sys.stderr)
        return 1
    print(entry["activation_id"])
    return 0


def cmd_revoke(args):
    entry = field_enrollment_module.find_in_index(args.index, _index_lock_path(args), args.public_key)
    if entry is None:
        print(f"error: no field-enrollment record found for public key {args.public_key}", file=sys.stderr)
        return 1
    changed = activations_module.revoke_activation(args.store, _store_lock_path(args), entry["activation_id"])
    field_enrollment_module.remove_from_index(args.index, _index_lock_path(args), args.public_key)
    if changed:
        print(f"revoked {entry['activation_id']} (public key {args.public_key}) and cleared its field-enrollment index entry")
    else:
        print(f"{entry['activation_id']} was already revoked - field-enrollment index entry cleared")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--index", required=True, help="path to the field-enrollment index (FIELD_ENROLLMENT_INDEX_PATH)")
    parser.add_argument("--index-lock", default=None, help='defaults to "<index>.lock"')

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list every field-enrolled device")
    list_parser.set_defaults(func=cmd_list)

    find_parser = subparsers.add_parser("find", help="print the activation_id for a field-enrolled device's public key")
    find_parser.add_argument("public_key")
    find_parser.set_defaults(func=cmd_find)

    revoke_parser = subparsers.add_parser("revoke", help="revoke a field-enrolled device's activation by its public key")
    revoke_parser.add_argument("public_key")
    revoke_parser.add_argument("--store", required=True, help="the activation store this deployment's POCVPN_API_ACTIVATION_STORE_PATH names")
    revoke_parser.add_argument("--lock", default=None, help='defaults to "<store>.lock"')
    revoke_parser.set_defaults(func=cmd_revoke)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (activations_module.ActivationStoreError, field_enrollment_module.FieldEnrollmentIndexError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
