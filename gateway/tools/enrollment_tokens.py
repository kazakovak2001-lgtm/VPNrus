#!/usr/bin/env python3
"""B8B1C1: operator CLI for enrollment-token lifecycle management.

This is the ONLY program that ever writes gateway/api's enrollment token
store. The HTTP provisioning API (gateway/api/tokens.py) is read-only by
construction - it has no write-capable code path at all (see that
module's docstring) - so the read/write split is enforced structurally,
not just by convention: nothing under gateway/api/ can ever mutate the
store, and this is the only file that does.

    enrollment_tokens.py --store PATH [--lock PATH] init
    enrollment_tokens.py --store PATH [--lock PATH] issue <PUBLIC_KEY>
    enrollment_tokens.py --store PATH [--lock PATH] revoke <TOKEN_ID>
    enrollment_tokens.py --store PATH [--lock PATH] status <TOKEN_ID>
    enrollment_tokens.py --store PATH [--lock PATH] list

--lock defaults to "<store>.lock", matching gateway/api/config.py's own
default (POCVPN_API_TOKEN_LOCK_PATH unset -> "<store>.lock").

Every mutating command (init/issue/revoke) acquires LOCK_EX on the lock
file and holds it across the ENTIRE read -> validate -> decide -> write
temp file -> fsync -> atomic replace -> fsync directory sequence - never
released early, never satisfied by an in-process-only mutex (a future
second operator invocation, or the HTTP API's own LOCK_SH reader, must be
correctly serialized against this one via the filesystem lock, not
Python-level state).
"""
import argparse
import contextlib
import fcntl
import json
import os
import secrets
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import tokens as tokens_module  # noqa: E402
from api.wgkey import is_valid_wg_public_key  # noqa: E402

_BEARER_TOKEN_BYTES = 32  # secrets.token_urlsafe(32) -> 256 bits of entropy
_TOKEN_ID_BYTES = 16  # secrets.token_hex(16) -> 128 bits, 32 lowercase hex chars
_MAX_GENERATION_ATTEMPTS = 5

# Reject an existing store whose mode has any of: group-write (0o020),
# other-write (0o002), other-read (0o004), or any exec bit (0o111).
# 0o600 (local/test init) and 0o640 (root:pocvpn-api, the intended B8B1C3
# production mode) both satisfy this; 0o644 and 0o660 do not.
_UNSAFE_MODE_MASK = 0o137


class StoreWriteError(Exception):
    """A durable-write precondition or step failed. Callers must treat
    this exactly like an OSError during the write: abort, clean up, leave
    the prior store byte-for-byte untouched, report a clean operator
    error - and critically, never let a caller emit a "success" stdout
    token for an issue whose durable write didn't actually happen."""


def _fail(message):
    print(f"enrollment_tokens: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _validate_existing_mode_is_safe(mode, store_path):
    if mode & _UNSAFE_MODE_MASK:
        raise StoreWriteError(
            f"refusing to replace {store_path}: its current mode {oct(mode)} is unsafe "
            "(group/other-writable, other-readable, or executable) - correct its "
            "ownership/mode out of band before retrying; no write was attempted"
        )


# --- durable atomic writer - the ONLY place in this whole codebase that
# ever writes enrollment-tokens.json ---
def _atomic_write_store(store_path, data):
    directory = os.path.dirname(os.path.abspath(store_path)) or "."
    prior_mode = None
    prior_uid = None
    prior_gid = None
    try:
        st = os.stat(store_path)
        prior_mode = st.st_mode & 0o777
        prior_uid = st.st_uid
        prior_gid = st.st_gid
        # Validated BEFORE anything is written - an unsafe existing mode
        # must abort the whole operation with nothing touched at all, not
        # even a temp file created.
        _validate_existing_mode_is_safe(prior_mode, store_path)
    except FileNotFoundError:
        pass  # brand-new store - see restrictive-default handling below

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".enrollment-tokens.", suffix=".tmp")
    # tempfile.mkstemp always creates its file mode 0600 regardless of
    # umask - already maximally restrictive, so nothing can read the
    # in-progress write before we explicitly widen it (if at all) below.
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        if prior_mode is not None:
            # Replacing an existing store: metadata MUST be reproduced
            # EXACTLY, and BOTH calls MUST succeed, before os.replace()
            # ever runs - no best-effort, no silently swallowed
            # PermissionError. A chmod/chown failure here aborts the
            # whole write (via the except below): we must never report a
            # successful mutation that accidentally leaves the running
            # API unable to read the store (wrong mode) or read it with
            # the wrong ownership.
            os.chmod(tmp_path, prior_mode)
            os.chown(tmp_path, prior_uid, prior_gid)
        else:
            # Brand-new store: restrictive default. Production ownership
            # (root:pocvpn-api, 0640) is established by the deploy
            # process / B8B1C3, not assumed here.
            os.chmod(tmp_path, 0o600)

        os.replace(tmp_path, store_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _atomic_write_store_or_fail(store_path, data):
    """Wraps _atomic_write_store with the CLI's standard failure handling:
    any filesystem-level failure (write, fsync, chmod, chown, replace,
    directory fsync) or unsafe-existing-mode rejection becomes a clean
    operator-facing error and non-zero exit via _fail(), never a raw
    traceback. Called only while the caller already holds LOCK_EX (see
    _exclusive_lock) - _fail()'s SystemExit still unwinds through that
    context manager's finally clauses, so the lock is released even on
    this failure path."""
    try:
        _atomic_write_store(store_path, data)
    except (OSError, StoreWriteError) as exc:
        _fail(f"failed to durably write the token store: {exc}")


@contextlib.contextmanager
def _exclusive_lock(lock_path, create):
    if create:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    else:
        try:
            fd = os.open(lock_path, os.O_RDWR)
        except OSError as exc:
            _fail(f"token lock not found at {lock_path} - run 'init' first: {exc}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_and_validate_under_lock(store_path):
    """Caller must already hold LOCK_EX on the corresponding lock file.
    Plain read (no additional flock call here) - a second flock() on a
    fresh fd for the SAME file, from the SAME process that already holds
    LOCK_EX via another fd, is unnecessary and a needless footgun; the
    LOCK_EX already held is sufficient exclusion."""
    if not os.path.isfile(store_path):
        _fail(f"token store not found at {store_path} - run 'init' first")
    with open(store_path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return tokens_module.parse_store(raw)
    except tokens_module.TokenLookupError as exc:
        _fail(f"token store is invalid: {exc}")


def _read_store_readonly_or_fail(store_path, lock_path):
    """Shared by the read-only status/list commands: reads under LOCK_SH
    (never creating the lock, exactly like the HTTP API's own reader -
    see gateway/api/tokens.py) and converts a TokenLookupError into a
    clean operator-facing error instead of letting it propagate as a raw
    traceback."""
    try:
        return tokens_module.parse_store(tokens_module.read_store_shared(store_path, lock_path))
    except tokens_module.TokenLookupError as exc:
        _fail(f"token store is invalid: {exc}")


def _print_record(record):
    print(
        f"token_id={record['token_id']} status={record['status']} "
        f"public_key_prefix={record['expected_public_key'][:8]}"
    )


# --- commands ---
def cmd_init(args):
    lock_dir = os.path.dirname(os.path.abspath(args.lock)) or "."
    store_dir = os.path.dirname(os.path.abspath(args.store)) or "."
    # Directory creation happens ONLY here, in the explicit operator-
    # invoked init command - no other command (and never the HTTP API)
    # creates any directory.
    os.makedirs(lock_dir, exist_ok=True)
    os.makedirs(store_dir, exist_ok=True)

    with _exclusive_lock(args.lock, create=True):
        if os.path.isfile(args.store):
            existing_mode = os.stat(args.store).st_mode & 0o777
            try:
                _validate_existing_mode_is_safe(existing_mode, args.store)
            except StoreWriteError as exc:
                _fail(str(exc))
            with open(args.store, "r", encoding="utf-8") as handle:
                raw = handle.read()
            try:
                tokens_module.parse_store(raw)
            except tokens_module.TokenLookupError as exc:
                _fail(f"refusing to touch an existing store that fails validation: {exc}")
            print(f"already initialized: {args.store}")
            return
        _atomic_write_store_or_fail(args.store, {})
        print(f"initialized empty token store: {args.store}")


def cmd_issue(args):
    public_key = args.public_key
    if not is_valid_wg_public_key(public_key):
        _fail("not a valid AmneziaWG/WireGuard public key")

    with _exclusive_lock(args.lock, create=False):
        data = _read_and_validate_under_lock(args.store)

        existing_token_ids = {record["token_id"] for record in data.values()}
        token = None
        for _attempt in range(_MAX_GENERATION_ATTEMPTS):
            candidate_token = secrets.token_urlsafe(_BEARER_TOKEN_BYTES)
            digest = tokens_module.token_digest(candidate_token)
            if digest in data:
                continue  # collision on the token itself - vanishingly unlikely
            candidate_token_id = secrets.token_hex(_TOKEN_ID_BYTES)
            if candidate_token_id in existing_token_ids:
                continue  # collision on the independently-generated token_id
            token, token_id = candidate_token, candidate_token_id
            break
        if token is None:
            _fail("failed to generate a unique token/token_id after several attempts")

        data[digest] = {
            "token_id": token_id,
            "expected_public_key": public_key,
            "status": tokens_module.ACTIVE,
        }
        _atomic_write_store_or_fail(args.store, data)

    print(f"issued token_id={token_id} public_key_prefix={public_key[:8]}", file=sys.stderr)
    # Success stdout: the plaintext bearer token, exactly one line, no
    # prefix, nothing else - the ONLY place it is ever displayed.
    sys.stdout.write(token + "\n")
    sys.stdout.flush()


def cmd_revoke(args):
    token_id = args.token_id
    if not tokens_module.TOKEN_ID_RE.match(token_id):
        _fail("token_id must be exactly 32 lowercase hex characters")

    with _exclusive_lock(args.lock, create=False):
        data = _read_and_validate_under_lock(args.store)

        digest = next((d for d, record in data.items() if record["token_id"] == token_id), None)
        if digest is None:
            _fail(f"no token found with token_id {token_id}")

        record = data[digest]
        if record["status"] == tokens_module.REVOKED:
            print(f"token_id={token_id} is already REVOKED (no change)")
            return

        data[digest] = {**record, "status": tokens_module.REVOKED}
        _atomic_write_store_or_fail(args.store, data)

    print(f"token_id={token_id} revoked")


def cmd_status(args):
    data = _read_store_readonly_or_fail(args.store, args.lock)
    for record in data.values():
        if record["token_id"] == args.token_id:
            _print_record(record)
            return
    _fail(f"no token found with token_id {args.token_id}")


def cmd_list(args):
    data = _read_store_readonly_or_fail(args.store, args.lock)
    for record in sorted(data.values(), key=lambda r: r["token_id"]):
        _print_record(record)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="enrollment_tokens.py", description="B8B1C1 enrollment-token operator CLI"
    )
    parser.add_argument("--store", required=True, help="path to enrollment-tokens.json")
    parser.add_argument("--lock", help="path to .tokens.lock (default: <store>.lock)")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty durable token store if one doesn't exist")

    p_issue = sub.add_parser("issue", help="issue a new bearer token bound to a public key")
    p_issue.add_argument("public_key")

    p_revoke = sub.add_parser("revoke", help="revoke a token by its token_id")
    p_revoke.add_argument("token_id")

    p_status = sub.add_parser("status", help="show one token's non-secret status by token_id")
    p_status.add_argument("token_id")

    sub.add_parser("list", help="list all tokens' non-secret status")

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
