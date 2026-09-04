"""Russia field-test zero-touch enrollment (POST /v1/field-enroll).

NOT the final production signup architecture - a bounded, explicitly-scoped
mechanism for a small field-test device cohort. Reuses activations.py's own
entitlement/binding/provisioning primitives VERBATIM (registration ->
provision_with_activation, the SAME orchestration POST /v1/activate uses) -
this is not a second, parallel authorization system, only a different way
for a device to obtain its own activation credential.

Credential model (round-2 review fix - replaces an earlier
HMAC-SHA256(secret, public_key) design). The credential is now GENUINELY
RANDOM (secrets.token_urlsafe), minted once per device, exactly like
gateway/tools/activation_tokens.py's own operator-issued credentials -
never derived from any server-held secret. This closes a real problem the
earlier deterministic design had: a single leaked FIELD_ENROLLMENT secret
would have let anyone compute ANY device's credential - past devices
already enrolled AND devices that had not enrolled yet - with no way to
"rotate" out of it short of individually revoking every affected
activation. A random credential has no such blast radius: compromising the
mechanism below discloses only the (at most `global_device_cap`, e.g. 5)
credentials it has ALREADY issued, never anything for a device that has
not enrolled, and there is no secret whose leak matters at all - there is
no secret.

A random, non-derivable credential does need ONE piece of durable,
non-secret bookkeeping to stay idempotent-and-cap-race-free under
concurrency: [FieldEnrollmentIndex] below, keyed by public key (never
secret - already sent in cleartext on every request to this and every
other endpoint in this API, already loggable, already the plaintext key
this module and activations.py's own `bound_devices` field always store).
Its own docstring covers why this is the SINGLE atomic operation that makes
"same public key => idempotent replay" and "global device cap" race-free
together, and why this does not reopen the "never persist a raw
credential" concern activations.py's own module docstring states: this
index is field-enrollment's OWN small, capped (at most `global_device_cap`
entries), single-purpose store - never activations.py's own shared,
long-lived, multi-purpose store, and a compromise of it discloses nothing
about, and grants no authority over, any ordinary operator-issued
activation credential.
"""
import contextlib
import fcntl
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone

from . import activations
from .wgkey import is_valid_wg_public_key

_CREDENTIAL_BYTES = 32  # secrets.token_urlsafe(32) -> 256 bits, same entropy as activations.issue_activation's own operator-issued credentials
_INDEX_REQUIRED_FIELDS = frozenset({"activation_id", "credential", "created_at"})

# enroll_device() outcomes.
ENROLLED = "enrolled"
DISABLED = "disabled"
INVALID_PUBLIC_KEY = "invalid_public_key"
DEVICE_CAP_REACHED = "device_cap_reached"
REVOKED = "revoked"
EXPIRED = "expired"
PROVISION_FAILED = "provision_failed"


class FieldEnrollmentIndexError(Exception):
    """The index file or its lock is corrupted/unreadable - handler.py must
    map this to 503, never silently treat it as any other outcome."""


class FieldEnrollmentResult:
    __slots__ = ("outcome", "credential", "client_tunnel_ip", "provision_error")

    def __init__(self, outcome, credential=None, client_tunnel_ip=None, provision_error=None):
        self.outcome = outcome
        self.credential = credential
        self.client_tunnel_ip = client_tunnel_ip
        self.provision_error = provision_error


# --- FieldEnrollmentIndex: public_key -> {activation_id, credential} -------
#
# Same atomic-write/flock discipline as activations.py's own store (mkstemp
# in the same directory, write+fsync, 0600, os.replace, fsync the
# directory) - but, unlike activations.py's operator-managed store, this
# one self-initializes on first use (no separate `init` CLI step exists or
# is needed for it - it is pure internal bookkeeping the running server
# creates for itself).

def _read_index(index_path):
    if not os.path.isfile(index_path):
        return {}
    with open(index_path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FieldEnrollmentIndexError(f"field-enrollment index is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FieldEnrollmentIndexError("field-enrollment index root must be a JSON object")
    for public_key, entry in data.items():
        if not is_valid_wg_public_key(public_key):
            raise FieldEnrollmentIndexError("field-enrollment index contains a malformed public key")
        if not isinstance(entry, dict) or set(entry.keys()) != _INDEX_REQUIRED_FIELDS:
            raise FieldEnrollmentIndexError("field-enrollment index entry does not have exactly the required fields")
    return data


def _atomic_write_index(index_path, data):
    directory = os.path.dirname(os.path.abspath(index_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".field-enrollment-index.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, index_path)
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


@contextlib.contextmanager
def _index_lock(lock_path):
    directory = os.path.dirname(os.path.abspath(lock_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def find_in_index(index_path, index_lock_path, public_key):
    """Read-only lookup - used by the operator CLI (field_enrollment_admin.py)
    to find a device's activation_id/credential from its (non-secret)
    public key, without recomputing anything."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
    return data.get(public_key)


def list_index(index_path, index_lock_path):
    with _index_lock(index_lock_path):
        return dict(_read_index(index_path))


def remove_from_index(index_path, index_lock_path, public_key):
    """Operator-only: purge a device's index entry (e.g. after revoking its
    activations.json record) so a LATER enrollment attempt for the SAME
    public key is treated as genuinely fresh - a new random credential and
    a new activation record - rather than replaying the now-revoked one
    forever. Safe no-op if no entry exists."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        if public_key not in data:
            return False
        del data[public_key]
        _atomic_write_index(index_path, data)
        return True


def _reserve_locked(index_path, index_lock_path, public_key, global_cap):
    """The ONE atomic operation that makes a RANDOM (non-deterministic)
    per-device credential safe under concurrency: under a SINGLE
    index-file lock, either (a) find and return this public key's
    ALREADY-issued (credential, activation_id) - an idempotent replay, or
    (b) if genuinely new, check the index's TOTAL entry count against
    `global_cap` and, if there is room, mint a fresh credential and
    durably reserve the slot for this exact public key BEFORE releasing
    the lock - so two concurrent requests for two DIFFERENT new public
    keys can never both push the index past `global_cap` (whichever
    request's flock() completes first commits the true count; the second
    sees the just-updated count under the same lock), and two concurrent
    requests for the SAME new public key can never mint two different
    credentials for it (the second sees the first's just-written entry
    under the same lock and returns it instead).

    Returns (credential, activation_id, is_new_reservation). Returns
    (None, None, False) only when this would be a genuinely new public key
    and the cap is already reached.
    """
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        existing = data.get(public_key)
        if existing is not None:
            return existing["credential"], existing["activation_id"], False

        if len(data) >= global_cap:
            return None, None, False

        credential = secrets.token_urlsafe(_CREDENTIAL_BYTES)
        activation_id = secrets.token_hex(16)
        data[public_key] = {
            "activation_id": activation_id,
            "credential": credential,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write_index(index_path, data)
        return credential, activation_id, True


def enroll_device(
    public_key,
    index_path, index_lock_path,
    activation_store_path, activation_lock_path,
    provision_script_path, subprocess_timeout_seconds,
    global_device_cap,
    sudo_path=None,
    now=None,
):
    """The ONE function POST /v1/field-enroll calls once handler.py's own
    config/enabled gate has already passed. Caller is responsible for rate
    limiting - this function has none of its own.
    """
    if not is_valid_wg_public_key(public_key):
        return FieldEnrollmentResult(INVALID_PUBLIC_KEY)

    try:
        credential, activation_id, is_new = _reserve_locked(index_path, index_lock_path, public_key, global_device_cap)
    except FieldEnrollmentIndexError:
        raise
    if credential is None:
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)

    if is_new:
        # Register the durable activations.json record for this exact
        # credential BEFORE ever attempting provisioning - provision_with_activation
        # requires a record to already exist at decide_and_bind time (this
        # mirrors activations.issue_activation's own two-step "mint, then
        # provision" shape). Passes the SAME activation_id the index just
        # committed - see register_credential's own docs for why this must
        # never be a second, independently-generated id.
        activations.register_credential(activation_store_path, activation_lock_path, credential, activation_id, max_devices=1)

    # Reuse the EXACT SAME orchestration POST /v1/activate uses - decide_and_bind
    # -> run_provision_peer -> finalize/rollback, one per-activation lock.
    # For an idempotent replay (is_new=False) this is ALSO exactly right:
    # it re-confirms the same device against the same credential, covering
    # the case where the device's ORIGINAL request actually succeeded but
    # its response never reached the client.
    result = activations.provision_with_activation(
        credential, public_key,
        activation_store_path, activation_lock_path,
        provision_script_path, subprocess_timeout_seconds, sudo_path=sudo_path,
        now=now,
    )
    decision = result.decision
    if decision.outcome == activations.INVALID:
        # Unreachable in practice for a fresh reservation (register_credential
        # just created this exact digest under its own lock); reachable for
        # a replay only if activations.json was somehow separately wiped -
        # never silently swallowed either way.
        return FieldEnrollmentResult(DISABLED)
    if decision.outcome == activations.REVOKED_OUTCOME:
        return FieldEnrollmentResult(REVOKED)
    if decision.outcome == activations.EXPIRED:
        return FieldEnrollmentResult(EXPIRED)
    if decision.outcome == activations.DEVICE_LIMIT:
        # This credential's own max_devices=1 already reached by a
        # DIFFERENT public key - structurally shouldn't happen (this
        # credential is 1:1 with this exact public key via the index), but
        # fails closed rather than reporting success either way.
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)

    if result.provision_error is not None:
        if is_new:
            # This reservation never actually became a working device -
            # release it so a retry (or a genuinely different future
            # attempt) can claim a fresh slot instead of being stuck behind
            # a permanently-broken one that still counts against the cap.
            remove_from_index(index_path, index_lock_path, public_key)
        return FieldEnrollmentResult(PROVISION_FAILED, provision_error=result.provision_error)

    finalize_result = result.finalize_result
    if not finalize_result.confirmed:
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)
    if finalize_result.status != activations.ACTIVE:
        return FieldEnrollmentResult(REVOKED)

    return FieldEnrollmentResult(
        ENROLLED, credential=credential, client_tunnel_ip=result.provision_outcome.ip,
    )
