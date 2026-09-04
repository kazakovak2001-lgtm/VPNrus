"""B8C1 - activation/device-entitlement store.

Durable JSON store, keyed by SHA-256 digest of the activation credential
(never the raw credential itself - see credential_digest/parse_store).
Unlike gateway/api/tokens.py's strict read-only-for-the-API split, THIS
store is legitimately written by both the operator CLI
(gateway/tools/activation_tokens.py: init/issue/revoke) AND the running
API process itself (decide_and_bind/unbind_device, on first device use) -
that is the one deliberate architectural difference from the enrollment
token store, made necessary by the product requirement that device
binding be decided and persisted atomically, in-request, under a single
flock-held critical section (see decide_and_bind's own docstring for the
concurrency argument). It does NOT relax any invariant of the existing
enrollment-token store or the AWG privilege boundary: this module never
touches awg0.conf, .provision.lock, or the privileged wrapper - the only
gateway mutation it ever triggers is via gateway/api/provision.py's
existing run_provision_peer(), exactly like the /v1/peers handler already
does.

Record shape (exactly these six fields, nothing more - same
no-extra-fields strictness as tokens.py's schema):
    {
      "activation_id": "<32 lowercase hex>",
      "status": "ACTIVE" | "REVOKED",
      "max_devices": <positive int>,
      "created_at": "<ISO 8601 UTC>",
      "expires_at": "<ISO 8601 UTC>" | null,
      "bound_devices": [
        {"public_key": "<AmneziaWG/WireGuard public key>",
         "reservation_id": "<32 lowercase hex>" | "",
         "state": "pending" | "confirmed"},
        ...
      ]
    }

The raw activation credential is NEVER written here or anywhere else in
this codebase - only its SHA-256 digest (the store's dict key) is ever
persisted, matching gateway/api/tokens.py's token_digest design exactly.

B8C1A - reservation/ownership model (fixes a same-device concurrent
provision/rollback race found in the original B8C1 design, where an
unconditional unbind-by-public-key could remove a binding that a
concurrent identical-key request had already turned into a real,
successfully-provisioned peer):

  - decide_and_bind() creates a "pending" entry, owned by a fresh
    reservation_id, ONLY when no entry for that public_key exists yet at
    all (counted toward max_devices the instant it exists, pending or
    not - see decide_and_bind's own docstring for why this alone already
    prevents two different first-use keys from both winning). A
    concurrent request for the SAME key that finds an existing entry
    (pending OR confirmed) gets BOUND_EXISTING and NO reservation_id - it
    owns nothing and must never attempt to roll anything back.

  - finalize_reservation() is called after a SUCCESSFUL
    run_provision_peer() call, by every request that reaches that point
    (both BOUND_NEW and BOUND_EXISTING) - it is monotonic and ownership-
    agnostic: it ensures a CONFIRMED entry for that public_key exists,
    whether or not the pending entry that first reserved capacity for it
    is still present (a concurrent identical-key request's own rollback
    may have already removed it - see the ordering analysis in this
    module's own tests). It never re-checks max_devices: the capacity was
    already validated and reserved once, at decide_and_bind time, by
    whichever request first observed the key absent.

  - unbind_reservation() is called ONLY by a request whose OWN
    provisioning attempt failed AND which owns a reservation_id (i.e.
    only ever a BOUND_NEW outcome). It removes the entry ONLY if it is
    STILL pending under exactly that reservation_id - i.e. only if no
    concurrent identical-key request has already finalized it to
    confirmed. This ownership+state check is precisely what closes the
    race: whichever of two concurrent identical-key requests finalizes
    first "wins" the binding permanently, and the other's rollback
    becomes a safe no-op instead of destroying a real, live entitlement.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

from . import provision
from .wgkey import is_valid_wg_public_key

ACTIVE = "ACTIVE"
REVOKED = "REVOKED"
_VALID_STATUSES = (ACTIVE, REVOKED)

# decide_and_bind outcomes.
INVALID = "invalid"
REVOKED_OUTCOME = "revoked"
EXPIRED = "expired"
DEVICE_LIMIT = "device_limit"
BOUND_NEW = "bound_new"
BOUND_EXISTING = "bound_existing"

PENDING = "pending"
CONFIRMED = "confirmed"
_VALID_DEVICE_STATES = (PENDING, CONFIRMED)

_ACTIVATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_RESERVATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_REQUIRED_RECORD_FIELDS = frozenset({
    "activation_id", "status", "max_devices", "created_at", "expires_at", "bound_devices",
})
_REQUIRED_DEVICE_FIELDS = frozenset({"public_key", "reservation_id", "state"})

_CREDENTIAL_BYTES = 32  # secrets.token_urlsafe(32) -> 256 bits of entropy, same as enrollment tokens
_ACTIVATION_ID_BYTES = 16  # secrets.token_hex(16) -> 32 lowercase hex chars
_MAX_GENERATION_ATTEMPTS = 5

# Same unsafe-mode rejection as enrollment_tokens.py's _validate_existing_mode_is_safe:
# refuse to replace a store whose current mode is group/other-writable,
# other-readable, or has any exec bit.
_UNSAFE_MODE_MASK = 0o137


class ActivationStoreError(Exception):
    """The store or its lock file is missing/corrupted/unreadable - the
    HTTP layer must map this to 503, never silently treat it as
    'credential invalid'. The operator CLI maps it to a loud, non-zero-exit
    error instead."""


class StoreWriteError(Exception):
    """A durable-write precondition or step failed - caller must abort,
    leave the prior store byte-for-byte untouched, and report a clean
    error, never claim success for a write that didn't durably happen."""


@dataclass(frozen=True)
class ActivationDecision:
    outcome: str
    activation_id: str = ""
    # B8C1A: set ONLY for BOUND_NEW - proof of ownership of the pending
    # reservation this decision just created. A BOUND_EXISTING decision
    # deliberately carries "" here - see unbind_reservation's docstring
    # for why a caller that doesn't own a reservation must never attempt
    # to roll one back.
    reservation_id: str = ""


def credential_digest(credential):
    """SHA-256 hex digest of a raw activation credential - the only form
    of the credential ever used for lookup or logging. The raw credential
    itself must never be logged or persisted anywhere."""
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value):
    return datetime.fromisoformat(value)


def parse_store(raw):
    """Parse and fully validate raw JSON store text - raises
    ActivationStoreError on ANY schema violation. Mirrors
    gateway/api/tokens.py's parse_store strictness: malformed JSON, wrong
    root type, a record with missing/extra fields, an invalid
    activation_id/status/max_devices/expires_at/bound_devices entry, or a
    duplicate activation_id across two different digest keys, all fail
    closed rather than being silently accepted or ignored."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ActivationStoreError(f"activation store is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ActivationStoreError("activation store root must be a JSON object")

    seen_activation_ids = set()
    for digest, record in data.items():
        if not isinstance(digest, str) or not re.match(r"^[0-9a-f]{64}$", digest):
            raise ActivationStoreError("activation store contains a malformed digest key")
        if not isinstance(record, dict):
            raise ActivationStoreError("activation store entry is not an object")
        if set(record.keys()) != _REQUIRED_RECORD_FIELDS:
            raise ActivationStoreError("activation store entry does not have exactly the required fields")

        activation_id = record.get("activation_id")
        if not isinstance(activation_id, str) or not _ACTIVATION_ID_RE.match(activation_id):
            raise ActivationStoreError("activation store entry has an invalid activation_id")
        if activation_id in seen_activation_ids:
            raise ActivationStoreError("activation store contains a duplicate activation_id")
        seen_activation_ids.add(activation_id)

        status = record.get("status")
        if status not in _VALID_STATUSES:
            raise ActivationStoreError("activation store entry has an invalid status")

        max_devices = record.get("max_devices")
        if not isinstance(max_devices, int) or isinstance(max_devices, bool) or max_devices < 1:
            raise ActivationStoreError("activation store entry has an invalid max_devices")

        created_at = record.get("created_at")
        if not isinstance(created_at, str):
            raise ActivationStoreError("activation store entry has an invalid created_at")
        try:
            _parse_iso(created_at)
        except ValueError:
            raise ActivationStoreError("activation store entry has an unparseable created_at")

        expires_at = record.get("expires_at")
        if expires_at is not None:
            if not isinstance(expires_at, str):
                raise ActivationStoreError("activation store entry has an invalid expires_at")
            try:
                _parse_iso(expires_at)
            except ValueError:
                raise ActivationStoreError("activation store entry has an unparseable expires_at")

        bound_devices = record.get("bound_devices")
        if not isinstance(bound_devices, list):
            raise ActivationStoreError("activation store entry has an invalid bound_devices list")

        seen_keys = set()
        for device in bound_devices:
            if not isinstance(device, dict) or set(device.keys()) != _REQUIRED_DEVICE_FIELDS:
                raise ActivationStoreError("activation store bound_devices entry does not have exactly the required fields")
            public_key = device.get("public_key")
            if not is_valid_wg_public_key(public_key):
                raise ActivationStoreError("activation store entry has a malformed bound device key")
            if public_key in seen_keys:
                raise ActivationStoreError("activation store entry has duplicate bound_devices entries")
            seen_keys.add(public_key)

            reservation_id = device.get("reservation_id")
            if not isinstance(reservation_id, str):
                raise ActivationStoreError("activation store bound_devices entry has an invalid reservation_id")
            if reservation_id and not _RESERVATION_ID_RE.match(reservation_id):
                raise ActivationStoreError("activation store bound_devices entry has a malformed reservation_id")

            state = device.get("state")
            if state not in _VALID_DEVICE_STATES:
                raise ActivationStoreError("activation store bound_devices entry has an invalid state")

        if len(bound_devices) > max_devices:
            raise ActivationStoreError("activation store entry has more bound_devices than max_devices")

    return data


def _validate_existing_mode_is_safe(mode, store_path):
    if mode & _UNSAFE_MODE_MASK:
        raise StoreWriteError(
            f"refusing to replace {store_path}: its current mode {oct(mode)} is unsafe "
            "(group/other-writable, other-readable, or executable) - correct its "
            "ownership/mode out of band before retrying; no write was attempted"
        )


def _atomic_write_store(store_path, data):
    """Same discipline as enrollment_tokens.py's _atomic_write_store:
    mkstemp (always mode 0600) in the same directory, write+fsync, restore
    the PRIOR file's exact mode/ownership (or a restrictive 0600 default
    for a brand-new store), os.replace, then fsync the containing
    directory. Never a partial/best-effort write."""
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

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".activations.", suffix=".tmp")
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
    except (OSError, StoreWriteError) as exc:
        raise ActivationStoreError(f"failed to durably write the activation store: {exc}") from exc


@contextlib.contextmanager
def _exclusive_lock(lock_path, create):
    """Held across the ENTIRE read -> decide -> write sequence in every
    mutating operation below - this flock is the sole mechanism that makes
    decide_and_bind's device-limit check race-free (see its docstring)."""
    if create:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    else:
        try:
            fd = os.open(lock_path, os.O_RDWR)
        except OSError as exc:
            raise ActivationStoreError(f"activation lock not found at {lock_path} - run 'init' first: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _per_activation_lock_dir(store_path):
    return os.path.join(os.path.dirname(os.path.abspath(store_path)) or ".", ".activation-locks")


@contextlib.contextmanager
def per_activation_lock(store_path, digest):
    """B8C1C - the per-activation OS-level flock that serializes the WHOLE
    logical operation (decide/reserve -> run_provision_peer -> finalize/
    rollback) for ONE activation, including the external, irreversible AWG
    provisioning side effect - see provision_with_activation, the only
    caller that should hold this across a provisioning attempt.

    Keyed by `digest` (the credential's SHA-256 digest - never the
    plaintext credential, matching this module's existing no-raw-credential
    invariant everywhere else) so a DIFFERENT activation's requests never
    contend for this lock at all: one lock file per digest, under a
    dedicated directory next to the store, created on first use.

    LOCK ORDER (fixed, always in this direction, never the reverse):
        PER-ACTIVATION LOCK  ->  GLOBAL ACTIVATION STORE LOCK (_exclusive_lock)
    This function's own critical section never itself takes
    _exclusive_lock - callers (provision_with_activation, revoke_activation)
    take the global lock only in short, independent sub-operations
    (decide_and_bind/finalize_reservation/unbind_reservation each already
    acquire-and-release it on their own) while ALREADY holding this lock -
    so the global lock is always acquired-and-released strictly INSIDE an
    already-held per-activation lock, never the other way around. This
    fixed order is what makes the ordering deadlock-free without needing
    any lock-acquisition timeout.

    Process death: this is a plain flock on an fd this process owns - the
    OS releases it automatically the instant the process exits, for any
    reason (crash, kill, normal exit). Nothing here depends on cooperative
    cleanup.
    """
    lock_dir = _per_activation_lock_dir(store_path)
    os.makedirs(lock_dir, exist_ok=True)
    lock_file_path = os.path.join(lock_dir, f"{digest}.lock")
    fd = os.open(lock_file_path, os.O_CREAT | os.O_RDWR, 0o600)
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
        raise ActivationStoreError(f"activation store not found at {store_path} - run 'init' first")
    with open(store_path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    return parse_store(raw)


@contextlib.contextmanager
def _open_lock_readonly(lock_path):
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except OSError as exc:
        raise ActivationStoreError(f"activation lock not found or unreadable at {lock_path}: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_store_shared(store_path, lock_path):
    """Read-only, LOCK_SH - used by status/list. Never creates the lock
    (mirrors tokens.py's reader), never writes."""
    with _open_lock_readonly(lock_path):
        if not os.path.isfile(store_path):
            raise ActivationStoreError(f"activation store not found at {store_path}")
        with open(store_path, "r", encoding="utf-8") as handle:
            return parse_store(handle.read())


# --- the one function POST /v1/activate actually calls -------------------

def decide_and_bind(credential, public_key, store_path, lock_path, now=None):
    """Validate `credential` against the store and, if this is the first
    time `public_key` has been presented for that activation, durably bind
    it - all under ONE flock(LOCK_EX) critical section spanning the read,
    the decision, and the write. This is exactly what makes two concurrent
    first-use requests for the same max_devices=1 activation, with
    DIFFERENT public keys, unable to both succeed: whichever request's
    open()+flock() completes first sees bound_devices still empty, binds,
    writes, and releases the lock; the second request's flock() call
    blocks until the first releases, then reads the ALREADY-updated
    bound_devices list under the same lock and correctly sees the device
    limit reached. No other synchronization primitive is introduced -
    this is the same flock discipline gateway/tools/enrollment_tokens.py
    and gateway/scripts/provision-peer.sh's .provision.lock already use.

    `public_key` must already be validated by the caller (see
    wgkey.is_valid_wg_public_key) - this function does not re-validate it.

    Returns an ActivationDecision. Never mutates the store for any outcome
    other than BOUND_NEW.
    """
    now = now or datetime.now(timezone.utc)
    with _exclusive_lock(lock_path, create=False):
        data = _read_and_validate_under_lock(store_path)
        digest = credential_digest(credential)
        record = data.get(digest)
        if record is None:
            return ActivationDecision(INVALID)

        activation_id = record["activation_id"]

        if record["status"] != ACTIVE:
            return ActivationDecision(REVOKED_OUTCOME, activation_id)

        expires_at = record["expires_at"]
        if expires_at is not None and now >= _parse_iso(expires_at):
            return ActivationDecision(EXPIRED, activation_id)

        bound_devices = record["bound_devices"]
        for device in bound_devices:
            if device["public_key"] == public_key:
                # Idempotent path (pending OR confirmed): do NOT mutate, do
                # NOT consume a new device slot, do NOT hand out a
                # reservation_id - this caller owns nothing (see module docs).
                return ActivationDecision(BOUND_EXISTING, activation_id)

        # Pending entries count toward max_devices the instant they exist -
        # this is what makes two concurrent DIFFERENT first-use keys unable
        # to both win, without needing to wait for either to finalize.
        if len(bound_devices) >= record["max_devices"]:
            return ActivationDecision(DEVICE_LIMIT, activation_id)

        reservation_id = secrets.token_hex(_ACTIVATION_ID_BYTES)
        new_device = {"public_key": public_key, "reservation_id": reservation_id, "state": PENDING}
        data[digest] = {**record, "bound_devices": bound_devices + [new_device]}
        _atomic_write_store_or_raise(store_path, data)
        return ActivationDecision(BOUND_NEW, activation_id, reservation_id)


@dataclass(frozen=True)
class FinalizeResult:
    # False ONLY for the B8C1B capacity-reused case below - every other
    # path (found-pending, found-confirmed, or a genuinely free slot to
    # reinsert into) confirms successfully.
    confirmed: bool
    status: str  # activation's CURRENT status ("ACTIVE"/"REVOKED"), observed under this same lock


def finalize_reservation(credential, public_key, store_path, lock_path):
    """Called after run_provision_peer() SUCCEEDS for `public_key` under
    this activation - by every request that reaches that point, whether
    its own decide_and_bind outcome was BOUND_NEW or BOUND_EXISTING (both
    are safe/idempotent to call this from). Ensures a CONFIRMED entry for
    that key exists - ownership-agnostic and monotonic by design (see
    module docstring's "B8C1A"/"B8C1B" sections for the full race analyses
    this resolves): if an entry already exists (pending or already
    confirmed), it is (re)marked confirmed - unconditionally, since this
    never changes bound_devices' length. If NO entry exists at all (the
    original pending reservation was already removed by a concurrent
    identical-key request's own, correctly-ownership-checked rollback -
    see unbind_reservation), this is the ONLY case where reinserting could
    ever grow bound_devices, so it is the ONLY case that re-validates
    max_devices, under this SAME lock, before doing so:

      - B8C1B fix: if capacity has since been legitimately consumed by a
        DIFFERENT key (a concurrent decide_and_bind for that key ran, saw
        the slot this request's own rollback just freed, and reserved it)
        finalize does NOT reinsert - confirmed=False is returned instead,
        and the caller (handler.py) must not report plain success for
        this request, even though its own provisioning subprocess did, in
        fact, create a real peer. Resurrecting the entry here would push
        bound_devices past max_devices - exactly the entitlement bypass
        this fix closes. There is deliberately no compensating
        "de-provision the now-orphaned peer" step - out of scope for this
        slice, same as the revoke-during-finalize case below.
      - Otherwise (still room), the reinsert proceeds: capacity for this
        exact key was already validated and reserved once, at
        decide_and_bind time, by whichever request first observed it
        absent - this branch only ever records an already-real
        provisioning result for a slot that is still legitimately free,
        never grants NEW capacity beyond max_devices.

    The returned status also carries the revoke-during-provisioning rule
    (B8C1A): a revoke that completes AFTER decide_and_bind already
    approved this request is still observed here, under the same lock, so
    the HTTP layer can refuse to report success for an activation that is
    revoked by the time provisioning actually finished.
    """
    with _exclusive_lock(lock_path, create=False):
        data = _read_and_validate_under_lock(store_path)
        digest = credential_digest(credential)
        record = data.get(digest)
        if record is None:
            raise ActivationStoreError("activation disappeared during finalize (store corruption or concurrent deletion)")

        bound_devices = record["bound_devices"]
        new_devices = []
        found = False
        changed = False
        for device in bound_devices:
            if device["public_key"] == public_key:
                found = True
                if device["state"] != CONFIRMED:
                    device = {**device, "state": CONFIRMED}
                    changed = True
            new_devices.append(device)

        if not found:
            # B8C1B: the slot this key originally reserved may have since
            # been legitimately handed to a different key - never grow
            # bound_devices past max_devices to resurrect it.
            if len(bound_devices) >= record["max_devices"]:
                return FinalizeResult(confirmed=False, status=record["status"])
            new_devices.append({"public_key": public_key, "reservation_id": "", "state": CONFIRMED})
            changed = True

        if changed:
            data[digest] = {**record, "bound_devices": new_devices}
            _atomic_write_store_or_raise(store_path, data)

        return FinalizeResult(confirmed=True, status=record["status"])


def unbind_reservation(credential, public_key, reservation_id, store_path, lock_path):
    """Compensating rollback for decide_and_bind's BOUND_NEW outcome when
    the SAME request's OWN provisioning call fails - see handler.py's call
    site. `reservation_id` MUST be the value decide_and_bind returned for
    THIS request; a caller whose own outcome was BOUND_EXISTING owns no
    reservation and must never call this (an empty reservation_id is
    treated as owning nothing and is always a no-op, as a defensive
    backstop, not the intended calling convention).

    Removes the entry ONLY if it is still present, still PENDING, and its
    reservation_id still matches exactly - i.e. ONLY if no concurrent
    identical-key request has already finalized it to CONFIRMED. This
    ownership+state check is the actual fix for the B8C1A race: it is safe
    to call unconditionally on every provisioning failure, because it can
    only ever remove the ONE entry this exact call created, and only while
    it is still unconfirmed."""
    if not reservation_id:
        return
    with _exclusive_lock(lock_path, create=False):
        data = _read_and_validate_under_lock(store_path)
        digest = credential_digest(credential)
        record = data.get(digest)
        if record is None:
            return
        bound_devices = record["bound_devices"]
        new_devices = [
            device for device in bound_devices
            if not (
                device["public_key"] == public_key
                and device["state"] == PENDING
                and device["reservation_id"] == reservation_id
            )
        ]
        if new_devices == bound_devices:
            return  # nothing matched our exact ownership - safe no-op
        data[digest] = {**record, "bound_devices": new_devices}
        _atomic_write_store_or_raise(store_path, data)


@dataclass(frozen=True)
class ProvisionWithActivationResult:
    decision: ActivationDecision
    # None unless decision.outcome is BOUND_NEW/BOUND_EXISTING and
    # run_provision_peer() was actually attempted.
    provision_outcome: object = None
    provision_error: object = None  # a provision.ProvisionError, if the attempt failed
    finalize_result: object = None  # a FinalizeResult, only set on provisioning success


def provision_with_activation(
    credential, public_key,
    store_path, lock_path,
    provision_script_path, subprocess_timeout_seconds, sudo_path=None,
    now=None,
):
    """B8C1C - the ONE orchestration entry point POST /v1/activate calls.
    Wraps decide_and_bind -> run_provision_peer -> finalize_reservation/
    unbind_reservation in a SINGLE per_activation_lock(store_path, digest)
    critical section, so the entire logical operation for a given
    activation - including the external, irreversible AWG provisioning
    side effect itself - is serialized against any other concurrent
    request for the SAME activation (regardless of which public key each
    request presents), while requests for DIFFERENT activations (a
    different credential digest -> a different lock file) remain fully
    concurrent. This is what closes the B8C1C race: with this lock held,
    a second request for the same activation cannot even begin its OWN
    run_provision_peer() call - let alone finish one - until the first
    request's entire decide/provision/finalize-or-rollback sequence has
    completed and released the lock, so two DIFFERENT keys can never both
    reach a successful run_provision_peer() call for a max_devices=1
    activation, and a same-key retry always sees the fully-settled result
    of the previous attempt before proceeding.

    Only decide_and_bind/finalize_reservation/unbind_reservation (each
    already its own short _exclusive_lock critical section) ever touch the
    global store lock from inside here - per_activation_lock's own
    docstring documents why this fixed nesting order is deadlock-free.
    """
    digest = credential_digest(credential)
    with per_activation_lock(store_path, digest):
        decision = decide_and_bind(credential, public_key, store_path, lock_path, now=now)
        if decision.outcome not in (BOUND_NEW, BOUND_EXISTING):
            return ProvisionWithActivationResult(decision=decision)

        try:
            provision_outcome = provision.run_provision_peer(
                provision_script_path, public_key, subprocess_timeout_seconds, sudo_path=sudo_path,
            )
        except provision.ProvisionError as exc:
            if decision.outcome == BOUND_NEW:
                unbind_reservation(credential, public_key, decision.reservation_id, store_path, lock_path)
            return ProvisionWithActivationResult(decision=decision, provision_error=exc)

        finalize_result = finalize_reservation(credential, public_key, store_path, lock_path)
        return ProvisionWithActivationResult(
            decision=decision, provision_outcome=provision_outcome, finalize_result=finalize_result,
        )


# --- operator-CLI-facing operations (gateway/tools/activation_tokens.py) --

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


def issue_activation(store_path, lock_path, max_devices, expires_in_days=None):
    if not isinstance(max_devices, int) or max_devices < 1:
        raise ValueError("max_devices must be a positive integer")

    with _exclusive_lock(lock_path, create=False):
        data = _read_and_validate_under_lock(store_path)

        existing_ids = {r["activation_id"] for r in data.values()}
        credential = None
        for _attempt in range(_MAX_GENERATION_ATTEMPTS):
            candidate_credential = secrets.token_urlsafe(_CREDENTIAL_BYTES)
            digest = credential_digest(candidate_credential)
            if digest in data:
                continue
            candidate_id = secrets.token_hex(_ACTIVATION_ID_BYTES)
            if candidate_id in existing_ids:
                continue
            credential, activation_id = candidate_credential, candidate_id
            break
        if credential is None:
            raise ActivationStoreError("failed to generate a unique activation credential/id after several attempts")

        expires_at = None
        if expires_in_days is not None:
            from datetime import timedelta
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()

        digest = credential_digest(credential)
        data[digest] = {
            "activation_id": activation_id,
            "status": ACTIVE,
            "max_devices": max_devices,
            "created_at": _utc_now_iso(),
            "expires_at": expires_at,
            "bound_devices": [],
        }
        _atomic_write_store_or_raise(store_path, data)

    return activation_id, credential


# --- field-enrollment support (Russia field test - see gateway/api/field_enrollment.py) --

def issue_activation_if_under_cap(store_path, lock_path, global_cap, credential, max_devices=1, expires_in_days=None, now=None):
    """Bounded, race-free counterpart of issue_activation() for zero-touch
    field enrollment: the caller has already DERIVED `credential`
    deterministically (see field_enrollment.derive_credential - this
    function never generates a credential itself, unlike issue_activation)
    and this is the ONE atomic operation that both (a) checks the store's
    TOTAL record count against `global_cap` and (b) creates a new
    single-device activation record for it, under the SAME
    _exclusive_lock(lock_path) issue_activation already uses - so two
    concurrent field-enrollment requests for two DIFFERENT new public keys
    can never both push the store past global_cap (whichever request's
    flock() completes first sees and commits the true count; the second
    sees the just-updated count under the same lock).

    Idempotent: if a record for this exact credential's digest ALREADY
    exists (a benign race with a concurrent identical-public-key request,
    or a genuine client retry after a previous response was lost), this
    returns that existing record's activation_id UNCHANGED - it never
    double-writes and never counts a repeat request against the cap a
    second time.

    Returns the activation_id on success (new or already-existing).
    Returns None ONLY when this would be a genuinely NEW record and the
    cap is already reached - the caller (field_enrollment.enroll_device)
    must treat None as "device cap reached", never as an error.
    """
    if not isinstance(max_devices, int) or max_devices < 1:
        raise ValueError("max_devices must be a positive integer")
    if not isinstance(global_cap, int) or global_cap < 1:
        raise ValueError("global_cap must be a positive integer")

    digest = credential_digest(credential)
    with _exclusive_lock(lock_path, create=False):
        data = _read_and_validate_under_lock(store_path)

        existing = data.get(digest)
        if existing is not None:
            return existing["activation_id"]

        if len(data) >= global_cap:
            return None

        existing_ids = {r["activation_id"] for r in data.values()}
        activation_id = None
        for _attempt in range(_MAX_GENERATION_ATTEMPTS):
            candidate_id = secrets.token_hex(_ACTIVATION_ID_BYTES)
            if candidate_id not in existing_ids:
                activation_id = candidate_id
                break
        if activation_id is None:
            raise ActivationStoreError("failed to generate a unique activation id after several attempts")

        expires_at = None
        if expires_in_days is not None:
            from datetime import timedelta
            expires_at = ((now or datetime.now(timezone.utc)) + timedelta(days=expires_in_days)).isoformat()

        data[digest] = {
            "activation_id": activation_id,
            "status": ACTIVE,
            "max_devices": max_devices,
            "created_at": _utc_now_iso(),
            "expires_at": expires_at,
            "bound_devices": [],
        }
        _atomic_write_store_or_raise(store_path, data)
        return activation_id


def find_by_credential_digest(store_path, lock_path, digest):
    """Read-only (LOCK_SH) lookup by an ALREADY-COMPUTED credential digest -
    never takes a raw credential, matching every other read path's own
    no-raw-credential discipline. Returns the record dict, or None."""
    data = read_store_shared(store_path, lock_path)
    return data.get(digest)


def revoke_activation(store_path, lock_path, activation_id):
    """B8C1C: revoke must serialize with any in-flight provisioning for the
    SAME activation - otherwise a revoke could complete without a
    concurrent provision_with_activation() call ever observing it (or vice
    versa: revoke could run between decide_and_bind and finalize with no
    per-activation lock protecting it at all). Uses the exact 5-step
    procedure required to keep the fixed lock order (per-activation lock
    always acquired BEFORE the global store lock, never the reverse, never
    while already holding the global lock):

      1. resolve activation_id -> credential digest under a brief SHARED
         global-store read (read_store_shared - LOCK_SH, released
         immediately after)
      2. (implicit) the global lock from step 1 is already released here
      3. acquire the per-activation lock for that digest - this is what
         actually blocks until any in-flight provision_with_activation()
         call for this activation finishes
      4. re-acquire the global store lock (a fresh, short _exclusive_lock
         critical section, correctly nested INSIDE the per-activation lock)
      5. re-read/revalidate under that lock and perform the revoke
    """
    # Step 1: resolve activation_id -> digest. Read-only, momentary.
    data = read_store_shared(store_path, lock_path)
    digest = next((d for d, r in data.items() if r["activation_id"] == activation_id), None)
    if digest is None:
        raise KeyError(f"no activation found with activation_id {activation_id}")

    # Steps 3-5: per-activation lock (blocks out in-flight provisioning for
    # this SAME activation), THEN the global store lock, re-validated fresh.
    with per_activation_lock(store_path, digest):
        with _exclusive_lock(lock_path, create=False):
            data = _read_and_validate_under_lock(store_path)
            record = data.get(digest)
            if record is None:
                raise KeyError(f"no activation found with activation_id {activation_id}")
            if record["status"] == REVOKED:
                return False  # already revoked, no change
            data[digest] = {**record, "status": REVOKED}
            _atomic_write_store_or_raise(store_path, data)
            return True


def find_by_activation_id(store_path, lock_path, activation_id):
    data = read_store_shared(store_path, lock_path)
    for record in data.values():
        if record["activation_id"] == activation_id:
            return record
    return None


def list_all(store_path, lock_path):
    data = read_store_shared(store_path, lock_path)
    return sorted(data.values(), key=lambda r: r["activation_id"])
