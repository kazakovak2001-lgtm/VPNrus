"""Read-only enrollment-token store access.

This module NEVER writes enrollment-tokens.json - issuance/revocation is
B8B1C's responsibility, via separate operator tooling. Every function here
only reads the store, under a shared (LOCK_SH) flock on a dedicated
token-state lock file (NOT gateway/scripts' .provision.lock - that lock
protects peer/IP state and this API must never touch it). A future B8B1C
writer taking LOCK_EX on the same lock file is safely excluded from a
read in progress here, and vice versa.

Fail-closed schema validation: a missing, non-JSON, or structurally
invalid store raises TokenLookupError, which callers MUST map to HTTP 500
- never to 401. Collapsing "store is corrupted" into "token not found"
would make an operational failure indistinguishable from ordinary
unauthorized traffic.
"""
import fcntl
import hashlib
import json
import os
from dataclasses import dataclass

ACTIVE = "ACTIVE"
REVOKED = "REVOKED"
_VALID_STATUSES = (ACTIVE, REVOKED)


class TokenLookupError(Exception):
    """The token store itself is missing/corrupted/malformed - a hard
    internal failure. See module docstring: callers must map this to 500,
    never 401."""


@dataclass(frozen=True)
class TokenLookupResult:
    found: bool
    status: str = ""
    expected_public_key: str = ""


def token_digest(token):
    """SHA-256 hex digest of a raw bearer token - the only form of the
    token ever used for lookup or logging. The raw token itself must never
    be passed to logging or persisted anywhere."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read_store_locked(store_path, lock_path):
    lock_dir = os.path.dirname(lock_path) or "."
    os.makedirs(lock_dir, exist_ok=True)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        try:
            if not os.path.isfile(store_path):
                raise TokenLookupError(f"token store not found at {store_path}")
            with open(store_path, "r", encoding="utf-8") as handle:
                return handle.read()
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _parse_store(raw):
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TokenLookupError(f"token store is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise TokenLookupError("token store root must be a JSON object")

    for digest, record in data.items():
        if not isinstance(digest, str) or len(digest) != 64:
            raise TokenLookupError("token store contains a malformed digest key")
        if not isinstance(record, dict):
            raise TokenLookupError("token store entry is not an object")
        status = record.get("status")
        expected_public_key = record.get("expected_public_key")
        if status not in _VALID_STATUSES:
            raise TokenLookupError("token store entry has an invalid status")
        if not isinstance(expected_public_key, str) or not expected_public_key:
            raise TokenLookupError("token store entry has an invalid expected_public_key")

    return data


def lookup_token(token, store_path, lock_path):
    """Look up `token` (raw, never logged) in the store at `store_path`.

    Returns TokenLookupResult(found=False) for a digest not present in an
    otherwise well-formed store - this is the ordinary "unknown token"
    case, mapped by the caller to the same 401 response as a revoked
    token. Raises TokenLookupError if the store itself could not be
    trusted (see module docstring) - never silently treated as "not
    found".
    """
    raw = _read_store_locked(store_path, lock_path)
    data = _parse_store(raw)
    digest = token_digest(token)
    record = data.get(digest)
    if record is None:
        return TokenLookupResult(found=False)
    return TokenLookupResult(
        found=True,
        status=record["status"],
        expected_public_key=record["expected_public_key"],
    )
