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
not enrolled.

Round-3 review fix (plaintext-credential-at-rest finding). A random
credential still needs to be durably RECOVERABLE for an idempotent retry
(the SAME credential must be returned to the same public key on a repeat
request, e.g. because the device's original response never arrived) - but
the earlier version of this module stored that credential in
[FieldEnrollmentIndex] as plaintext JSON, in the clear, on disk. That
contradicts activations.py's own "never persist a raw credential" store
discipline and, if the index file leaked, would have handed out every
already-issued field-enrollment credential directly. Fixed by AUTHENTICATED
ENCRYPTION (AES-256-GCM, `cryptography.hazmat.primitives.ciphers.aead
.AESGCM` - the SAME library this repo's own manifest/envelope signing
tooling already depends on, never a hand-rolled cipher): the index stores
only `credential_digest` (the SAME SHA-256 digest activations.py already
uses everywhere - never itself sufficient to re-derive or replay the
credential) and `wrapped_credential` (nonce + AES-GCM ciphertext, base64,
with the device's own public key bound in as associated data so a wrapped
blob can never be decrypted under a DIFFERENT index entry). The wrapping
key ([AppConfig.field_enrollment_wrap_key_file] - 32 raw bytes, read
transiently, never logged, never returned, never embedded in the Android
APK) is a server-only secret in its OWN trust domain, disjoint from every
other key/secret this codebase already has; it lets THIS SERVER recover a
credential it already minted for an idempotent replay, while a leaked
index file alone (without that separate key file) discloses nothing
usable - authentication (GCM's own tag) additionally means a corrupted or
tampered index entry fails closed at decrypt time rather than silently
producing wrong bytes.

A random, non-derivable credential does need ONE piece of durable
bookkeeping to stay idempotent-and-cap-race-free under concurrency:
[FieldEnrollmentIndex] below, keyed by public key (never secret - already
sent in cleartext on every request to this and every other endpoint in
this API, already loggable, already the plaintext key this module and
activations.py's own `bound_devices` field always store). Its own
docstring covers why this is the SINGLE atomic operation that makes "same
public key => idempotent replay" and "global device cap" race-free
together, and why this does not reopen the "never persist a raw
credential" concern activations.py's own module docstring states: this
index is field-enrollment's OWN small, capped (at most `global_device_cap`
entries), single-purpose store - never activations.py's own shared,
long-lived, multi-purpose store, and a compromise of it (WITHOUT the
separate wrap key) discloses nothing about, and grants no authority over,
any ordinary operator-issued activation credential.

Round-3 review fix (transactional integrity findings). `enroll_device`'s
own docstring below covers the full reserve -> register -> provision ->
commit-or-rollback state machine and its explicit ownership model - see
that function and `activations.remove_credential_if_unbound`'s own docs.
"""
import base64
import contextlib
import fcntl
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import activations
from .wgkey import is_valid_wg_public_key

_CREDENTIAL_BYTES = 32  # secrets.token_urlsafe(32) -> 256 bits, same entropy as activations.issue_activation's own operator-issued credentials
_WRAP_KEY_BYTES = 32  # AES-256
_WRAP_NONCE_BYTES = 12  # AES-GCM standard nonce length
_INDEX_REQUIRED_FIELDS = frozenset({"activation_id", "credential_digest", "wrapped_credential", "created_at"})

# enroll_device() outcomes.
ENROLLED = "enrolled"
DISABLED = "disabled"
INVALID_PUBLIC_KEY = "invalid_public_key"
DEVICE_CAP_REACHED = "device_cap_reached"
REVOKED = "revoked"
EXPIRED = "expired"
PROVISION_FAILED = "provision_failed"


class FieldEnrollmentIndexError(Exception):
    """The index file, its lock, or its wrap-key material is corrupted/
    unreadable/unusable - handler.py must map this to 503, never silently
    treat it as any other outcome."""


class FieldEnrollmentResult:
    __slots__ = ("outcome", "credential", "client_tunnel_ip", "provision_error")

    def __init__(self, outcome, credential=None, client_tunnel_ip=None, provision_error=None):
        self.outcome = outcome
        self.credential = credential
        self.client_tunnel_ip = client_tunnel_ip
        self.provision_error = provision_error


def _load_wrap_key(wrap_key_file):
    """Reads and validates the AES-256-GCM wrap key fresh on every call -
    same "transient read, never cached across requests" discipline
    handler.py's own relay-probe-secret handling already uses. A missing/
    wrong-length key file is a FieldEnrollmentIndexError (fail closed,
    mapped to 503 by handler.py) - config.py already validates this at
    startup, but this module never trusts that as its ONLY guarantee (the
    file could be removed/truncated at runtime)."""
    try:
        with open(wrap_key_file, "rb") as handle:
            key_bytes = handle.read()
    except OSError as exc:
        raise FieldEnrollmentIndexError(f"field-enrollment wrap key file is unreadable: {exc}") from exc
    if len(key_bytes) != _WRAP_KEY_BYTES:
        raise FieldEnrollmentIndexError(
            f"field-enrollment wrap key file must contain exactly {_WRAP_KEY_BYTES} bytes, got {len(key_bytes)}"
        )
    return key_bytes


def _wrap_credential(wrap_key_bytes, credential, public_key):
    """Authenticated-encrypts `credential` under `wrap_key_bytes`, with
    `public_key` bound in as associated data (AAD) - so a wrapped blob
    copied into a DIFFERENT index entry (a different public key) fails to
    decrypt rather than silently succeeding. Returns base64(nonce || ciphertext),
    a single opaque string safe to store as ordinary JSON text."""
    nonce = secrets.token_bytes(_WRAP_NONCE_BYTES)
    ciphertext = AESGCM(wrap_key_bytes).encrypt(nonce, credential.encode("utf-8"), public_key.encode("utf-8"))
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def _unwrap_credential(wrap_key_bytes, wrapped_credential, public_key):
    """Inverse of [_wrap_credential]. Raises FieldEnrollmentIndexError
    (never returns a wrong/partial value) on any authentication failure -
    a corrupted index entry, a tampered ciphertext, or a wrap-key mismatch
    (e.g. after a key rotation with no migration) all fail closed here,
    the same discipline every other decode/verify path in this codebase
    already uses."""
    try:
        raw = base64.b64decode(wrapped_credential, validate=True)
    except (ValueError, TypeError) as exc:
        raise FieldEnrollmentIndexError(f"field-enrollment index has a malformed wrapped credential: {exc}") from exc
    if len(raw) <= _WRAP_NONCE_BYTES:
        raise FieldEnrollmentIndexError("field-enrollment index has a truncated wrapped credential")
    nonce, ciphertext = raw[:_WRAP_NONCE_BYTES], raw[_WRAP_NONCE_BYTES:]
    try:
        plaintext = AESGCM(wrap_key_bytes).decrypt(nonce, ciphertext, public_key.encode("utf-8"))
    except InvalidTag as exc:
        raise FieldEnrollmentIndexError("field-enrollment index wrapped credential failed authentication") from exc
    return plaintext.decode("utf-8")


# --- FieldEnrollmentIndex: public_key -> {activation_id, credential_digest, wrapped_credential} --
#
# Same atomic-write/flock discipline as activations.py's own store (mkstemp
# in the same directory, write+fsync, 0600, os.replace, fsync the
# directory) - but, unlike activations.py's operator-managed store, this
# one self-initializes on first use (no separate `init` CLI step exists or
# is needed for it - it is pure internal bookkeeping the running server
# creates for itself). NEVER stores a raw/plaintext credential - see this
# module's own docstring for the wrap-at-rest design.

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
        if not isinstance(entry["credential_digest"], str) or not entry["credential_digest"]:
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid credential_digest")
        if not isinstance(entry["wrapped_credential"], str) or not entry["wrapped_credential"]:
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid wrapped_credential")
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
    to find a device's activation_id/credential_digest from its (non-secret)
    public key. Never unwraps the credential (the CLI never needs the raw
    value - see field_enrollment_admin.py's own docs)."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
    return data.get(public_key)


def list_index(index_path, index_lock_path):
    with _index_lock(index_lock_path):
        return dict(_read_index(index_path))


def remove_from_index(index_path, index_lock_path, public_key):
    """Removes a device's index entry (e.g. an operator cleanup after
    revoking its activations.json record, or this module's OWN rollback on
    a definitive enrollment failure - see `enroll_device`'s own docs) so a
    LATER enrollment attempt for the SAME public key is treated as
    genuinely fresh - a new random credential and a new activation record -
    rather than replaying a now-dead reservation forever. Safe no-op if no
    entry exists."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        if public_key not in data:
            return False
        del data[public_key]
        _atomic_write_index(index_path, data)
        return True


class _Reservation:
    """One outcome of [_reserve_locked] - see that function's own docs.
    `is_new_index_entry` is TRUE only when THIS call durably wrote the
    index entry (never a pre-existing one) - the ownership signal
    `enroll_device`'s own rollback logic needs, mirroring
    `activations.RegisterCredentialResult.created`'s role for the
    activation-store side of the same transaction."""

    __slots__ = ("credential", "activation_id", "is_new_index_entry")

    def __init__(self, credential, activation_id, is_new_index_entry):
        self.credential = credential
        self.activation_id = activation_id
        self.is_new_index_entry = is_new_index_entry


def _reserve_locked(index_path, index_lock_path, wrap_key_bytes, public_key, global_cap):
    """The ONE atomic operation that makes a RANDOM (non-deterministic)
    per-device credential safe under concurrency: under a SINGLE
    index-file lock, either (a) find this public key's ALREADY-issued
    entry and unwrap its credential - an idempotent replay, or (b) if
    genuinely new, check the index's TOTAL entry count against
    `global_cap` and, if there is room, mint a fresh credential, wrap it
    at rest, and durably reserve the slot for this exact public key BEFORE
    releasing the lock - so two concurrent requests for two DIFFERENT new
    public keys can never both push the index past `global_cap`
    (whichever request's flock() completes first commits the true count;
    the second sees the just-updated count under the same lock), and two
    concurrent requests for the SAME new public key can never mint two
    different credentials for it (the second sees the first's just-written
    entry under the same lock and unwraps that instead).

    Returns a [_Reservation], or `None` only when this would be a
    genuinely new public key and the cap is already reached.
    """
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        existing = data.get(public_key)
        if existing is not None:
            credential = _unwrap_credential(wrap_key_bytes, existing["wrapped_credential"], public_key)
            return _Reservation(credential, existing["activation_id"], is_new_index_entry=False)

        if len(data) >= global_cap:
            return None

        credential = secrets.token_urlsafe(_CREDENTIAL_BYTES)
        activation_id = secrets.token_hex(16)
        data[public_key] = {
            "activation_id": activation_id,
            "credential_digest": activations.credential_digest(credential),
            "wrapped_credential": _wrap_credential(wrap_key_bytes, credential, public_key),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write_index(index_path, data)
        return _Reservation(credential, activation_id, is_new_index_entry=True)


def enroll_device(
    public_key,
    index_path, index_lock_path,
    activation_store_path, activation_lock_path,
    provision_script_path, subprocess_timeout_seconds,
    global_device_cap,
    wrap_key_file,
    sudo_path=None,
    now=None,
):
    """The ONE function POST /v1/field-enroll calls once handler.py's own
    config/enabled gate has already passed. Caller is responsible for rate
    limiting - this function has none of its own.

    Round-3 review fix - explicit transactional state machine, replacing
    the earlier version's unguarded `register_credential()` call and
    activation-store-orphaning provisioning-failure path:

        1. RESERVE  - _reserve_locked (index lock only). Mints or recovers
           a (credential, activation_id) pair. `reservation.is_new_index_entry`
           marks whether THIS call created the index entry.
        2. REGISTER - activations.register_credential (its own short,
           independent store lock). ALWAYS attempted, even on an
           idempotent replay (`is_new_index_entry=False`) - this is what
           lets a device recover cleanly if a PREVIOUS attempt reserved an
           index entry but crashed/failed before ever registering the
           activation record (see `activations.register_credential`'s own
           docs). `register_result.created` marks whether THIS call wrote
           the activation record.
           - On failure: this call created NOTHING durable in the
             activation store yet, so the only rollback needed is the
             index reservation, and ONLY if THIS call made one
             (`is_new_index_entry`) - see the `except` block below. The
             original exception is always re-raised (never swallowed) so
             handler.py's own existing 503 mapping applies unchanged.
        3. PROVISION - activations.provision_with_activation (its own
           per_activation_lock critical section, entirely independent of
           steps 1/2's locks - no nested/re-entrant locking anywhere in
           this sequence).
           - On failure: the EXISTING `unbind_reservation` mechanism
             (inside provision_with_activation itself) already removes any
             PENDING device bind this attempt made. What it does NOT do is
             remove the activation RECORD `register_credential` created in
             step 2 - that is this module's own responsibility, and ONLY
             when `register_result.created` is True (this call's own
             record, never one that pre-existed or that a concurrent
             request might be using - see `remove_credential_if_unbound`'s
             own ownership+state check). The index reservation is likewise
             removed ONLY when `is_new_index_entry` is True.
        4. COMMIT   - ENROLLED, returning the plaintext credential (this
           function's caller, handler.py, hands it straight to the client
           and never persists it itself).

    Every rollback step below is allowed to itself fail (disk full, I/O
    error) - such a failure is NEVER silently swallowed. The step-2
    (registration-failure) rollback chains its own cleanup failure onto
    the original exception (`raise ... from cleanup_exc`) so both are
    visible. The step-3 (provisioning-failure) rollback is deliberately
    sequential and non-nested: if removing the activation record itself
    fails, that failure propagates immediately and the index reservation
    is left in place rather than attempting a second, independent cleanup
    that could itself fail silently - see that block's own comment for why
    leaving the index entry is safe (a later retry self-heals through
    step 2's own idempotency). Either way, every raised exception is still
    caught by handler.py's existing except clause (or its outer generic
    handler) and mapped to a closed HTTP response - never left unhandled.
    """
    if not is_valid_wg_public_key(public_key):
        return FieldEnrollmentResult(INVALID_PUBLIC_KEY)

    wrap_key_bytes = _load_wrap_key(wrap_key_file)

    reservation = _reserve_locked(index_path, index_lock_path, wrap_key_bytes, public_key, global_device_cap)
    if reservation is None:
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)
    credential, activation_id = reservation.credential, reservation.activation_id

    # Step 2: REGISTER. Always attempted (see docstring above) - never
    # gated on is_new_index_entry.
    try:
        register_result = activations.register_credential(
            activation_store_path, activation_lock_path, credential, activation_id, max_devices=1,
        )
    except Exception as exc:
        if reservation.is_new_index_entry:
            try:
                remove_from_index(index_path, index_lock_path, public_key)
            except Exception as cleanup_exc:
                raise FieldEnrollmentIndexError(
                    f"field-enrollment index rollback failed after a registration failure: {cleanup_exc}"
                ) from exc
        raise

    # Reuse the EXACT SAME orchestration POST /v1/activate uses - decide_and_bind
    # -> run_provision_peer -> finalize/rollback, one per-activation lock.
    # For an idempotent replay this is ALSO exactly right: it re-confirms
    # the same device against the same credential, covering the case where
    # the device's ORIGINAL request actually succeeded but its response
    # never reached the client.
    result = activations.provision_with_activation(
        credential, public_key,
        activation_store_path, activation_lock_path,
        provision_script_path, subprocess_timeout_seconds, sudo_path=sudo_path,
        now=now,
    )
    decision = result.decision
    if decision.outcome == activations.INVALID:
        # Unreachable in practice for a fresh registration (register_credential
        # just created/confirmed this exact digest under its own lock); reachable
        # for a replay only if activations.json was somehow separately wiped -
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
        # Step 3 failure: unbind_reservation has already run internally
        # (provision_with_activation's own rollback for a fresh
        # BOUND_NEW device bind). This module's own additional cleanup:
        # remove the activation record itself (only if THIS call created
        # it) THEN the index reservation (only if THIS call created it) -
        # never orphaning either, never touching a record/entry this call
        # does not own. Deliberately sequential, never a nested best-effort
        # "try the other one anyway" on failure: if the activation-record
        # removal itself fails, that failure is raised immediately and
        # loudly (never swallowed) and the index entry is deliberately
        # LEFT IN PLACE rather than independently cleaned up - a later
        # retry of the same public key finds that same index entry,
        # re-runs register_credential (idempotent - finds the still-present
        # record, created=False) and re-attempts provisioning, so the
        # system self-heals rather than risking a second silent failure
        # compounding the first.
        if register_result.created:
            activations.remove_credential_if_unbound(activation_store_path, activation_lock_path, credential, activation_id)
        if reservation.is_new_index_entry:
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
