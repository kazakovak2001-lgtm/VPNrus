"""B46-4A - durable store/lock primitives for the Hysteria2 per-device
credential-hash store (gateway/api/hysteria_provisioning.py). Byte-for-byte
mirrors gateway/api/xray_provisioning.py's own store/lock discipline
(mkstemp mode 0600, write+fsync, restore prior mode/ownership or a
restrictive 0600 default, os.replace, fsync the containing directory;
fcntl.flock exclusive lock; strict schema validation on every read) - kept
in its own module (not xray_provisioning.py) so the two stores stay
independent files with independent locks, never sharing state, exactly like
gateway/api/activations.py stays independent of both.

Record shape enforced by [parse_store] - see hysteria_provisioning.py's own
module docstring for the authoritative field-by-field description.
"""
import contextlib
import fcntl
import json
import os
import re
import tempfile
from datetime import datetime

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SALT_RE = re.compile(r"^[0-9a-f]{32}$")
_REQUIRED_IDENTITY_FIELDS = frozenset(
    {"device_public_key", "auth_secret_hash", "auth_secret_salt", "created_at"},
)
_UNSAFE_MODE_MASK = 0o137  # same rejection rule as activations.py/xray_provisioning.py's own


class HysteriaStoreLockError(Exception):
    """The store or its lock file is missing/corrupted/unreadable."""


class HysteriaStoreWriteError(Exception):
    """A durable-write precondition or step failed - caller must abort, leave the prior store byte-for-byte untouched."""


def parse_store(raw):
    """Strict schema validation - a malformed/tampered store fails closed
    (raises), never silently treated as empty or partially trusted."""
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise HysteriaStoreLockError(f"hysteria store is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HysteriaStoreLockError("hysteria store root must be a JSON object")

    for digest, identities in data.items():
        if not _DIGEST_RE.match(digest):
            raise HysteriaStoreLockError("hysteria store has a malformed activation digest key")
        if not isinstance(identities, list):
            raise HysteriaStoreLockError("hysteria identity store entry is not a list")

        seen_keys = set()
        for identity in identities:
            if not isinstance(identity, dict) or set(identity.keys()) != _REQUIRED_IDENTITY_FIELDS:
                raise HysteriaStoreLockError("hysteria identity entry does not have exactly the required fields")

            public_key = identity.get("device_public_key")
            if not isinstance(public_key, str) or not public_key:
                raise HysteriaStoreLockError("hysteria identity entry has an invalid device_public_key")
            if public_key in seen_keys:
                raise HysteriaStoreLockError("hysteria identity store has duplicate device_public_key entries under one activation")
            seen_keys.add(public_key)

            auth_hash = identity.get("auth_secret_hash")
            auth_salt = identity.get("auth_secret_salt")
            if not isinstance(auth_hash, str) or not _HASH_RE.match(auth_hash):
                raise HysteriaStoreLockError("hysteria identity entry has an invalid auth_secret_hash")
            if not isinstance(auth_salt, str) or not _SALT_RE.match(auth_salt):
                raise HysteriaStoreLockError("hysteria identity entry has an invalid auth_secret_salt")

            created_at = identity.get("created_at")
            if not isinstance(created_at, str):
                raise HysteriaStoreLockError("hysteria identity entry has an invalid created_at")
            try:
                datetime.fromisoformat(created_at)
            except ValueError:
                raise HysteriaStoreLockError("hysteria identity entry has an unparseable created_at") from None

    return data


def _validate_existing_mode_is_safe(mode, store_path):
    if mode & _UNSAFE_MODE_MASK:
        raise HysteriaStoreWriteError(
            f"refusing to replace {store_path}: its current mode {oct(mode)} is unsafe "
            "(group/other-writable, other-readable, or executable) - correct its "
            "ownership/mode out of band before retrying; no write was attempted",
        )


def atomic_write_store(store_path, data):
    directory = os.path.dirname(os.path.abspath(store_path)) or "."
    prior_mode = None
    prior_uid = None
    prior_gid = None
    try:
        st = os.stat(store_path)
        prior_mode = st.st_mode & 0o777
        prior_uid = st.st_uid
        prior_gid = st.st_gid
        _validate_existing_mode_is_safe(prior_mode, store_path)
    except FileNotFoundError:
        pass

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".hysteria-identities.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        if prior_mode is not None:
            os.chmod(tmp_path, prior_mode)
            os.chown(tmp_path, prior_uid, prior_gid)
        else:
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


def atomic_write_store_or_raise(store_path, data):
    try:
        atomic_write_store(store_path, data)
    except (OSError, HysteriaStoreWriteError) as exc:
        raise HysteriaStoreLockError(f"failed to durably write the hysteria identity store: {exc}") from exc


@contextlib.contextmanager
def exclusive_lock(lock_path, create):
    if create:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    else:
        try:
            fd = os.open(lock_path, os.O_RDWR)
        except OSError as exc:
            raise HysteriaStoreLockError(f"hysteria identity lock not found at {lock_path} - run 'init' first: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _shared_lock_readonly(lock_path):
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except OSError as exc:
        raise HysteriaStoreLockError(f"hysteria identity lock not found at {lock_path} - run 'init' first: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_and_validate_under_lock(store_path):
    if not os.path.isfile(store_path):
        raise HysteriaStoreLockError(f"hysteria identity store not found at {store_path} - run 'init' first")
    with open(store_path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    return parse_store(raw)


def read_store_shared(store_path, lock_path):
    """Momentary SHARED read - mirrors activations.read_store_shared/
    xray_provisioning.read_store_shared exactly. Safe to call while another
    process holds [exclusive_lock] for a write; blocks only until that
    write's lock is released."""
    with _shared_lock_readonly(lock_path):
        return read_and_validate_under_lock(store_path)


def init_store(store_path, lock_path):
    lock_dir = os.path.dirname(os.path.abspath(lock_path)) or "."
    store_dir = os.path.dirname(os.path.abspath(store_path)) or "."
    os.makedirs(lock_dir, exist_ok=True)
    os.makedirs(store_dir, exist_ok=True)

    with exclusive_lock(lock_path, create=True):
        if os.path.isfile(store_path):
            existing_mode = os.stat(store_path).st_mode & 0o777
            _validate_existing_mode_is_safe(existing_mode, store_path)
            with open(store_path, "r", encoding="utf-8") as handle:
                parse_store(handle.read())  # refuse to touch an existing store that fails validation
            return False  # already initialized
        atomic_write_store_or_raise(store_path, {})
        return True
