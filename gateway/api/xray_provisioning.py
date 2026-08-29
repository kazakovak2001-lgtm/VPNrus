"""B8K2 - per-device VLESS/REALITY identity store, extending the EXISTING
B8C1 activation/device-binding model (gateway/api/activations.py) rather
than creating a second, unrelated account/token system.

This module owns exactly one thing: a durable mapping from
(activation credential digest, device public key) -> a distinct VLESS
client UUID, generated once and returned identically on every retry. It
deliberately does NOT re-implement device-entitlement, revocation,
max_devices, or credential validation - all of that stays owned by
activations.py, and this module treats it as authoritative:

  - Eligibility gate: a device may only receive (or retrieve) a VLESS
    identity if activations.py's own store already shows that EXACT
    (digest, public_key) pair as a CONFIRMED bound device on an ACTIVE,
    non-expired activation - i.e. it already completed POST /v1/activate
    successfully. This is what "extend the existing activation/device
    binding model" means concretely: no new entitlement decision is ever
    made here, only a lookup against the decision activations.py already
    made and durably recorded.
  - Revocation: there is deliberately NO revoke function in this module.
    When an activation is revoked (activations.revoke_activation), this
    module's own store is untouched - the effect is realized entirely by
    xray_config_renderer.py, which cross-references activations.py's
    CURRENT status for every stored identity's owning activation when
    building the Xray server config, and omits any identity whose
    activation is not ACTIVE. One source of truth for "is this
    entitlement still valid", not two.

Record shape (this store, keyed by the SAME credential-digest scheme
activations.py uses - never the raw credential):
    {
      "<64-hex activation digest>": [
        {"device_public_key": "<AmneziaWG/WireGuard public key>",
         "vless_uuid": "<RFC 4122 UUID, lowercase>",
         "created_at": "<ISO 8601 UTC>"},
        ...
      ]
    }

Concurrency / lock ordering (mirrors activations.py's own documented
discipline exactly - see its per_activation_lock docstring):

    PER-ACTIVATION LOCK (activations.per_activation_lock, REUSED, same
    digest, same lock file activations.py already owns)
        -> (short, released) SHARED read of the activation store
           (activations.read_store_shared) to check eligibility
        -> (short, released) EXCLUSIVE lock of THIS module's OWN,
           independent store+lock file, to decide/write the identity

The per-activation lock is always the outermost lock, exactly as
activations.py's own docstring requires, and this module never acquires
activations.py's global store lock directly (only via its public
read_store_shared function, which owns and releases that lock itself,
momentarily). This module's own store lock is never held while trying to
acquire any activations.py lock - so the two stores' locks are never
nested in conflicting order and can never deadlock against each other.
"""
import contextlib
import fcntl
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from . import activations

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REQUIRED_IDENTITY_FIELDS = frozenset({"device_public_key", "vless_uuid", "created_at"})

# decide_or_issue outcomes.
NOT_ELIGIBLE_UNKNOWN = "not_eligible_unknown"       # no such activation
NOT_ELIGIBLE_REVOKED = "not_eligible_revoked"
NOT_ELIGIBLE_EXPIRED = "not_eligible_expired"
NOT_ELIGIBLE_DEVICE_NOT_BOUND = "not_eligible_device_not_bound"  # never went through /v1/activate
ISSUED = "issued"

_UNSAFE_MODE_MASK = 0o137  # same rejection rule as activations.py's own


class XrayStoreError(Exception):
    """The store or its lock file is missing/corrupted/unreadable - the
    HTTP layer must map this to 503, never silently treat it as "no
    identity yet"."""


class XrayStoreWriteError(Exception):
    """A durable-write precondition or step failed - caller must abort,
    leave the prior store byte-for-byte untouched, never claim success
    for a write that did not durably happen."""


@dataclass(frozen=True)
class XrayIdentityResult:
    outcome: str
    vless_uuid: str = ""  # set only for ISSUED


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value):
    return datetime.fromisoformat(value)


def parse_store(raw):
    """Same strictness discipline as activations.parse_store: malformed
    JSON, wrong root type, a malformed digest key, a record that is not a
    list, a malformed/duplicate device entry, or an invalid uuid all fail
    closed."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise XrayStoreError(f"xray identity store is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise XrayStoreError("xray identity store root must be a JSON object")

    # Global across ALL activations, not just within one digest's list -
    # two different activations/devices must never share a vless_uuid:
    # Xray's own client list is global to the inbound, so a collision would
    # silently merge two different users' traffic/stats under one identity
    # and make revoking one indistinguishably affect the other.
    seen_uuids_globally = set()

    for digest, identities in data.items():
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise XrayStoreError("xray identity store contains a malformed digest key")
        if not isinstance(identities, list):
            raise XrayStoreError("xray identity store entry is not a list")

        seen_keys = set()
        for identity in identities:
            if not isinstance(identity, dict) or set(identity.keys()) != _REQUIRED_IDENTITY_FIELDS:
                raise XrayStoreError("xray identity entry does not have exactly the required fields")

            public_key = identity.get("device_public_key")
            if not isinstance(public_key, str) or not public_key:
                raise XrayStoreError("xray identity entry has an invalid device_public_key")
            if public_key in seen_keys:
                raise XrayStoreError("xray identity store has duplicate device_public_key entries under one activation")
            seen_keys.add(public_key)

            vless_uuid = identity.get("vless_uuid")
            if not isinstance(vless_uuid, str) or not _UUID_RE.match(vless_uuid):
                raise XrayStoreError("xray identity entry has an invalid vless_uuid")
            if vless_uuid in seen_uuids_globally:
                raise XrayStoreError("xray identity store has a duplicate vless_uuid across activations")
            seen_uuids_globally.add(vless_uuid)

            created_at = identity.get("created_at")
            if not isinstance(created_at, str):
                raise XrayStoreError("xray identity entry has an invalid created_at")
            try:
                _parse_iso(created_at)
            except ValueError:
                raise XrayStoreError("xray identity entry has an unparseable created_at")

    return data


def _validate_existing_mode_is_safe(mode, store_path):
    if mode & _UNSAFE_MODE_MASK:
        raise XrayStoreWriteError(
            f"refusing to replace {store_path}: its current mode {oct(mode)} is unsafe "
            "(group/other-writable, other-readable, or executable) - correct its "
            "ownership/mode out of band before retrying; no write was attempted"
        )


def _atomic_write_store(store_path, data):
    """Byte-for-byte the same discipline as activations._atomic_write_store
    (mkstemp mode 0600, write+fsync, restore prior mode/ownership or a
    restrictive 0600 default, os.replace, fsync the containing directory).
    On any failure the prior store file is left completely untouched - the
    tmp file is unlinked and the exception propagates, never a partial
    write."""
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

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".xray-identities.", suffix=".tmp")
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


def _atomic_write_store_or_raise(store_path, data):
    try:
        _atomic_write_store(store_path, data)
    except (OSError, XrayStoreWriteError) as exc:
        raise XrayStoreError(f"failed to durably write the xray identity store: {exc}") from exc


@contextlib.contextmanager
def _exclusive_lock(lock_path, create):
    if create:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    else:
        try:
            fd = os.open(lock_path, os.O_RDWR)
        except OSError as exc:
            raise XrayStoreError(f"xray identity lock not found at {lock_path} - run 'init' first: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_and_validate_under_lock(store_path):
    if not os.path.isfile(store_path):
        raise XrayStoreError(f"xray identity store not found at {store_path} - run 'init' first")
    with open(store_path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    return parse_store(raw)


def init_store(store_path, lock_path):
    lock_dir = os.path.dirname(os.path.abspath(lock_path)) or "."
    store_dir = os.path.dirname(os.path.abspath(store_path)) or "."
    os.makedirs(lock_dir, exist_ok=True)
    os.makedirs(store_dir, exist_ok=True)

    with _exclusive_lock(lock_path, create=True):
        if os.path.isfile(store_path):
            existing_mode = os.stat(store_path).st_mode & 0o777
            _validate_existing_mode_is_safe(existing_mode, store_path)
            with open(store_path, "r", encoding="utf-8") as handle:
                parse_store(handle.read())  # refuse to touch an existing store that fails validation
            return False  # already initialized
        _atomic_write_store_or_raise(store_path, {})
        return True


def _check_device_eligibility(credential, public_key, activation_store_path, activation_lock_path, now):
    """Read-only. Momentary SHARED read of the ACTIVATION store (not this
    module's own store) - mirrors activations.revoke_activation's own
    step-1 pattern. Returns one of the NOT_ELIGIBLE_* constants, or None
    if eligible."""
    try:
        data = activations.read_store_shared(activation_store_path, activation_lock_path)
    except activations.ActivationStoreError as exc:
        raise XrayStoreError(f"activation store unavailable while checking Xray eligibility: {exc}") from exc

    digest = activations.credential_digest(credential)
    record = data.get(digest)
    if record is None:
        return NOT_ELIGIBLE_UNKNOWN
    if record["status"] != activations.ACTIVE:
        return NOT_ELIGIBLE_REVOKED
    expires_at = record["expires_at"]
    if expires_at is not None and now >= _parse_iso(expires_at):
        return NOT_ELIGIBLE_EXPIRED

    for device in record["bound_devices"]:
        if device["public_key"] == public_key and device["state"] == activations.CONFIRMED:
            return None  # eligible
    return NOT_ELIGIBLE_DEVICE_NOT_BOUND


def provision_xray_identity(
    credential, public_key,
    activation_store_path, activation_lock_path,
    xray_store_path, xray_lock_path,
    now=None,
):
    """The ONE entry point POST /v1/xray-profile calls. Idempotent: a
    retry for the same (credential, public_key) always returns the SAME
    vless_uuid, never generates a second one, and never re-validates
    eligibility more than once per call (a single per-activation-locked
    critical section covers both the eligibility read and the identity
    decide/write).
    """
    now = now or datetime.now(timezone.utc)
    digest = activations.credential_digest(credential)

    with activations.per_activation_lock(activation_store_path, digest):
        ineligible = _check_device_eligibility(
            credential, public_key, activation_store_path, activation_lock_path, now,
        )
        if ineligible is not None:
            return XrayIdentityResult(outcome=ineligible)

        with _exclusive_lock(xray_lock_path, create=False):
            data = _read_and_validate_under_lock(xray_store_path)
            identities = data.get(digest, [])

            for identity in identities:
                if identity["device_public_key"] == public_key:
                    # Idempotent retry - never mutate, never mint a second uuid.
                    return XrayIdentityResult(outcome=ISSUED, vless_uuid=identity["vless_uuid"])

            new_uuid = str(uuid.uuid4())
            new_identity = {
                "device_public_key": public_key,
                "vless_uuid": new_uuid,
                "created_at": _utc_now_iso(),
            }
            data[digest] = identities + [new_identity]
            _atomic_write_store_or_raise(xray_store_path, data)
            return XrayIdentityResult(outcome=ISSUED, vless_uuid=new_uuid)


def read_store_shared(store_path, lock_path):
    """Read-only helper for the config renderer/operator CLI - LOCK_SH,
    never creates the lock, never writes."""
    fd = None
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except OSError as exc:
        raise XrayStoreError(f"xray identity lock not found or unreadable at {lock_path}: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            if not os.path.isfile(store_path):
                raise XrayStoreError(f"xray identity store not found at {store_path}")
            with open(store_path, "r", encoding="utf-8") as handle:
                return parse_store(handle.read())
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
