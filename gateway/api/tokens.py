"""Read-only enrollment-token store access.

This module NEVER writes enrollment-tokens.json - issuance/revocation is
B8B1C1's gateway/tools/enrollment_tokens.py operator CLI, a separate
program. Every function here only reads the store, under a shared
(LOCK_SH) flock on a dedicated token-state lock file (NOT gateway/scripts'
.provision.lock - that lock protects peer/IP state and this API must
never touch it). The operator writer taking LOCK_EX on the same lock file
is safely excluded from a read in progress here, and vice versa.

The reader NEVER creates anything: the lock file is opened O_RDONLY with
no O_CREAT, and a missing lock or missing store both fail closed via
TokenLookupError rather than being silently created. Initialization is
exclusively the operator CLI's `init` command's responsibility (see
gateway/tools/enrollment_tokens.py) - this keeps pocvpn-api from ever
needing filesystem-create permission on /var/lib/pocvpn-provision/,
which is exactly the property the production ownership model in the
B8B1C read-only audit depends on.

Fail-closed schema validation: a missing, non-JSON, or structurally
invalid store raises TokenLookupError, which callers MUST map to HTTP 500
- never to 401. Collapsing "store is corrupted" into "token not found"
would make an operational failure indistinguishable from ordinary
unauthorized traffic.

parse_store() and read_store_shared() are deliberately public: the
operator CLI's read-only commands (status/list) reuse them rather than
maintaining a second, independent schema-validation implementation that
could drift from this one. Neither function ever opens anything for
writing - reusing them from the operator tool does not grant that tool
(or anything importing this module) any additional capability beyond
what pocvpn-api itself has.
"""
import fcntl
import hashlib
import json
import os
import re
from dataclasses import dataclass

from .wgkey import is_valid_wg_public_key

ACTIVE = "ACTIVE"
REVOKED = "REVOKED"
VALID_STATUSES = (ACTIVE, REVOKED)

# Exactly these three fields, nothing more, nothing less - see B8B1C1's
# schema-tightening: a record with any extra field is rejected, not
# silently accepted.
_REQUIRED_RECORD_FIELDS = frozenset({"token_id", "expected_public_key", "status"})

# token_id is independently generated (secrets.token_hex(16) in the
# operator CLI) - exactly 32 lowercase hex characters, never derived from
# or equal to the token digest.
TOKEN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


class TokenLookupError(Exception):
    """The token store (or its lock file) itself is missing/corrupted/
    malformed - a hard internal failure. See module docstring: the HTTP
    API must map this to 500, never 401. The operator CLI maps it to a
    loud, non-zero-exit operator error instead - either way, this
    exception means "do not trust this store's contents", never "proceed
    as if empty/absent"."""


@dataclass(frozen=True)
class TokenLookupResult:
    found: bool
    status: str = ""
    expected_public_key: str = ""
    token_id: str = ""


def token_digest(token):
    """SHA-256 hex digest of a raw bearer token - the only form of the
    token ever used for lookup or logging. The raw token itself must never
    be passed to logging or persisted anywhere."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_store(raw):
    """Parse and fully validate raw JSON store text. Raises
    TokenLookupError on ANY schema violation - malformed JSON, wrong root
    type, malformed digest key, a record with missing/extra fields, an
    invalid token_id/public key/status, or a token_id repeated across two
    different digest keys (which could otherwise let one operator
    identifier ambiguously resolve to two different tokens - see
    B8B1C1's revoke design). Returns the parsed dict on success."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TokenLookupError(f"token store is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise TokenLookupError("token store root must be a JSON object")

    seen_token_ids = set()
    for digest, record in data.items():
        if not isinstance(digest, str) or not _DIGEST_KEY_RE.match(digest):
            raise TokenLookupError("token store contains a malformed digest key")
        if not isinstance(record, dict):
            raise TokenLookupError("token store entry is not an object")
        if set(record.keys()) != _REQUIRED_RECORD_FIELDS:
            raise TokenLookupError("token store entry does not have exactly the required fields")

        token_id = record.get("token_id")
        expected_public_key = record.get("expected_public_key")
        status = record.get("status")

        if not isinstance(token_id, str) or not TOKEN_ID_RE.match(token_id):
            raise TokenLookupError("token store entry has an invalid token_id")
        if token_id in seen_token_ids:
            raise TokenLookupError("token store contains a duplicate token_id")
        seen_token_ids.add(token_id)

        if not isinstance(expected_public_key, str) or not is_valid_wg_public_key(expected_public_key):
            raise TokenLookupError("token store entry has an invalid expected_public_key")

        if status not in VALID_STATUSES:
            raise TokenLookupError("token store entry has an invalid status")

    return data


def _open_lock_readonly(lock_path):
    # O_RDONLY, no O_CREAT: the reader must never bring a lock file into
    # existence - see module docstring. flock() only needs the fd to be
    # open, not writable, to take LOCK_SH.
    try:
        return os.open(lock_path, os.O_RDONLY)
    except OSError as exc:
        raise TokenLookupError(f"token lock not found or unreadable at {lock_path}: {exc}") from exc


def read_store_shared(store_path, lock_path):
    """Open lock_path read-only (never creating it), take LOCK_SH, and
    return the full raw store text. Shared by lookup_token() below and
    the operator CLI's read-only status/list commands - see module
    docstring for why this sharing is safe (read-only either way)."""
    lock_fd = _open_lock_readonly(lock_path)
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


def lookup_token(token, store_path, lock_path):
    """Look up `token` (raw, never logged) in the store at `store_path`.

    Returns TokenLookupResult(found=False) for a digest not present in an
    otherwise well-formed store - this is the ordinary "unknown token"
    case, mapped by the caller to the same 401 response as a revoked
    token. Raises TokenLookupError if the store or its lock file could
    not be trusted (see module docstring) - never silently treated as
    "not found".
    """
    raw = read_store_shared(store_path, lock_path)
    data = parse_store(raw)
    digest = token_digest(token)
    record = data.get(digest)
    if record is None:
        return TokenLookupResult(found=False)
    return TokenLookupResult(
        found=True,
        status=record["status"],
        expected_public_key=record["expected_public_key"],
        token_id=record["token_id"],
    )
