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

B67.4 corrective-pass fix (independent post-round-3 audit, two MAJOR
findings). (1) The round-3 transactional design above still had a live
same-public-key race: nothing serialized the WHOLE reserve -> register ->
provision -> commit-or-rollback lifecycle for one public key against a
CONCURRENT attempt for that SAME key, so a request whose OWN provisioning
failed could roll back an index entry a concurrent request for the same
key had, by then, already turned into a real confirmed device (the
rollback's own ownership check on the ACTIVATION record - `activation_id`
match + empty `bound_devices` - correctly refused to delete the
activation record itself, but the INDEX removal that followed had no
equivalent check and could still delete the concurrent request's live
index entry). Fixed with an explicit, OS-level, per-public-key lock -
[field_enrollment_key_lock] - that now wraps `enroll_device`'s entire
body: same public key => fully serialized end to end; different public
keys => independently concurrent unless they happen to collide on the
same fixed shard (see below). See that function's own docstring for the
fixed lock order this introduces (this key lock is always the OUTERMOST
lock - acquired before, and released after, every lock already inside
`enroll_device`'s call graph - `_index_lock`, `activations
.per_activation_lock`, and `activations._exclusive_lock` - never the
reverse, and nothing INSIDE any of those inner critical sections ever
attempts to acquire this key lock, so this ordering cannot deadlock).
Independently of the lock, [remove_reservation_if_owned] replaces the old
rollback's blind `remove_from_index(public_key)` call with an
ownership-checked removal (matches on `activation_id`, exactly mirroring
`activations.remove_credential_if_unbound`'s own discipline) - defense in
depth even though the key lock alone already makes the original race
unreachable, and the SAME primitive the operator CLI's own revoke flow
now reuses (see field_enrollment_admin.py and [revoke_and_remove_if_owned]
below) rather than that tool's own prior TOCTOU-prone
find-then-blind-remove sequence.

(1b) Second corrective-pass fix (independent post-fix audit, same day) -
[field_enrollment_key_lock]'s FIRST version keyed its lock filename
directly by a digest of the public key, which meant the number of
persistent lock files grew without bound as new, distinct, individually
valid public keys were presented - a cheap unbounded-filesystem-growth
vector, in tension with this whole mechanism's own "bounded" design goal
(`FieldEnrollmentIndex` itself, by contrast, is already capped at
`global_device_cap` entries). Fixed by mapping every public key onto one
of a FIXED-SIZE pool of `_KEY_LOCK_SHARD_COUNT` lock files
(SHA-256(public_key) % N, never one file per key) - see
`_key_lock_shard_index`/`_key_lock_file_path`'s own docs for the sizing
rationale and `field_enrollment_key_lock`'s own docs for why a shard
collision between two DIFFERENT keys only ever costs them concurrency
with each other, never correctness (every read/write inside the locked
section is still keyed by the real public_key/credential digest), and
for why this shard-file scheme cannot be bypassed via an inode-
replacement race (a shard's lock file, once created, is never unlinked
or replaced for the life of the deployment).

(1c) Second corrective-pass fix (activation_id consistency, MAJOR BUG #2
of that same audit) - `enroll_device` used to proceed straight into
provisioning using `reservation.activation_id` without ever confirming
that `activations.register_credential`'s own returned `activation_id`
(the ACTUAL id the durable activation-store record now carries for this
exact credential digest) still matched it. In the ordinary path these
are always equal (the same value flows: `_reserve_locked` mints it,
`register_credential` is called with exactly that value, and either
writes a fresh record under it or finds an EXISTING record for this
credential digest whose OWN `activation_id` must, by `register_credential`'s
own defensive check, already equal it - see that function's own
"activation_id collides with a DIFFERENT existing record" guard).  But a
prior process crash/corruption/manual edit could, in principle, leave the
index and the activation store disagreeing about which activation_id a
given credential digest belongs to - and `enroll_device` had no explicit
check that would ever catch that instead of silently provisioning
against whichever id the STORE actually used. `enroll_device` now checks
`register_result.activation_id == activation_id` immediately after
`register_credential` returns and, on a mismatch, fails closed
(`FieldEnrollmentIndexError`, mapped to 503) WITHOUT provisioning,
WITHOUT reporting success, and WITHOUT silently "fixing" the index to
agree with the store - see that check's own comment for its exact
rollback semantics (never revoking/removing the store's OWN,
already-durable `register_result.activation_id` record, which this
attempt does not own merely by virtue of having presented a matching
credential digest).

(2) `activations.register_credential`'s own durable write
(`_atomic_write_store`) can raise AFTER its `os.replace()` has already
succeeded - visible-but-durability-uncertain, an outcome
`activations.ActivationCommitUncertainError` now names explicitly (see
that class's own docs). `enroll_device`'s registration-failure handler
below now catches that type FIRST and re-raises without touching the
index reservation at all - a same-key retry finds the same reservation
and reconciles with whatever `register_credential` actually left durable
via its own idempotent-insert semantics, never risking a
index-entry-exists/activation-record-exists split-brain by guessing
"nothing happened" for an outcome that cannot honestly be called that.
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
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

# B67.4 corrective-pass fix (index integrity audit, item 17) - exact shape
# checks, not merely "is a non-empty string": activation_id mirrors
# activations.py's own 32-lowercase-hex convention (secrets.token_hex(16)),
# credential_digest is always a SHA-256 hex digest (64 lowercase hex - see
# activations.credential_digest), and wrapped_credential is always
# base64(12-byte nonce || AES-GCM ciphertext-with-16-byte-tag) - a decoded
# length below nonce+tag (28 bytes) can never be a real wrapped credential
# and must fail closed here, at read time, rather than only at decrypt
# time deeper in _unwrap_credential.
_ACTIVATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_CREDENTIAL_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_WRAPPED_CREDENTIAL_MIN_DECODED_BYTES = _WRAP_NONCE_BYTES + 16  # nonce + GCM's own 16-byte auth tag, empty plaintext

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
        activation_id = entry["activation_id"]
        if not isinstance(activation_id, str) or not _ACTIVATION_ID_RE.match(activation_id):
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid activation_id")
        credential_digest_value = entry["credential_digest"]
        if not isinstance(credential_digest_value, str) or not _CREDENTIAL_DIGEST_RE.match(credential_digest_value):
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid credential_digest")
        wrapped_credential = entry["wrapped_credential"]
        if not isinstance(wrapped_credential, str) or not wrapped_credential:
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid wrapped_credential")
        try:
            decoded_wrapped = base64.b64decode(wrapped_credential, validate=True)
        except (ValueError, TypeError) as exc:
            raise FieldEnrollmentIndexError(f"field-enrollment index entry has a malformed wrapped_credential: {exc}") from exc
        if len(decoded_wrapped) < _WRAPPED_CREDENTIAL_MIN_DECODED_BYTES:
            raise FieldEnrollmentIndexError("field-enrollment index entry has an implausibly short wrapped_credential")
        if not isinstance(entry["created_at"], str) or not entry["created_at"]:
            raise FieldEnrollmentIndexError("field-enrollment index entry has an invalid created_at")
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


def _key_lock_dir(index_path):
    return os.path.join(os.path.dirname(os.path.abspath(index_path)) or ".", ".field-enrollment-key-locks")


# B67.4 second corrective-pass fix (MAJOR BUG #1, unbounded lock-file
# growth) - a FIXED-SIZE pool of lock files, never one file per distinct
# public key ever presented. A public key deterministically maps to
# exactly one of these `_KEY_LOCK_SHARD_COUNT` slots
# (`_key_lock_shard_index`, below) - so the persistent filesystem
# footprint this module's own locking ever creates is bounded by this
# constant, REGARDLESS of how many distinct public keys are ever
# submitted (including an attacker minting an unbounded stream of freshly
# generated, individually-valid public keys that never enroll
# successfully - see this constant's own sizing rationale below).
#
# 64 is chosen, not merely "some fixed number", for a concrete reason:
# this mechanism exists ONLY for a small, capped field-test cohort
# (`AppConfig.field_enrollment_max_devices` - a handful of real devices,
# e.g. 5, per this module's own docs) - 64 slots keeps the odds of two
# DISTINCT, LEGITIMATELY enrolling devices ever landing in the same shard
# implausible at that real scale (a shard collision only ever costs those
# two keys their concurrency with EACH OTHER - see the module's own
# correctness argument below - never correctness), while still being a
# small, fixed, easily-audited constant, not a large table sized as if
# this served the whole production device base the way
# `activations.per_activation_lock`'s own per-CREDENTIAL-digest scheme
# does (that mechanism is intentionally NOT bounded the same way - see
# its own docstring - because every activation record it locks is already
# itself a bounded, operator-issued/durably-tracked resource; a
# not-yet-issued, possibly-never-issued public key is not).
_KEY_LOCK_SHARD_COUNT = 64


def _key_lock_shard_index(public_key):
    """Deterministic public_key -> shard mapping: the same public key
    ALWAYS maps to the same shard (SHA-256 is a pure function of the
    input bytes - no randomness, no process-local state), so two
    requests for the SAME public key - even from two entirely SEPARATE
    processes that have never communicated - always contend for the
    SAME lock file. Different public keys MAY map to the same shard (a
    collision merely serializes those two keys' attempts against each
    other for the duration of one attempt each - see this module's own
    correctness argument: shard collision only ever REDUCES concurrency
    between unrelated keys, it can never merge or confuse their actual
    index/activation-store state, since every read/write inside the
    locked section is still keyed by the real `public_key`/credential
    digest, never by the shard index itself)."""
    digest_bytes = hashlib.sha256(public_key.encode("utf-8")).digest()
    # First 8 bytes as a big-endian integer - any fixed-width slice of a
    # cryptographic hash's output is itself uniformly distributed, so this
    # is exactly as good a sharding input as hashing the whole digest and
    # is one line simpler.
    shard_seed = int.from_bytes(digest_bytes[:8], "big")
    return shard_seed % _KEY_LOCK_SHARD_COUNT


def _key_lock_file_path(index_path, public_key):
    # A FIXED filename per shard (never per public key - see
    # _KEY_LOCK_SHARD_COUNT's own docs) - "shard-NNN.lock", zero-padded to
    # a constant width purely for tidy `ls` output, never parsed back.
    shard = _key_lock_shard_index(public_key)
    return os.path.join(_key_lock_dir(index_path), f"shard-{shard:03d}.lock")


@contextlib.contextmanager
def field_enrollment_key_lock(index_path, public_key):
    """B67.4 corrective-pass fix (MAJOR BUG #1) - the ONE lock that
    serializes a public key's ENTIRE field-enrollment lifecycle end to
    end: reserve -> register -> provision -> commit-or-rollback
    (`enroll_device`) and the operator CLI's own revoke/cleanup flow
    (`revoke_and_remove_if_owned`) both acquire this SAME lock, keyed by
    `public_key`, before touching anything else. Same public key => fully
    serialized (a second attempt for that key - whether a concurrent HTTP
    retry or a concurrent operator revoke - blocks until the first's
    entire attempt has committed or rolled back). Different public keys
    => independently concurrent UNLESS they happen to land in the same
    fixed shard (see `_KEY_LOCK_SHARD_COUNT`'s own docs) - a shard
    collision only ever costs those two keys their concurrency with each
    other for the duration of one attempt, never correctness: every
    operation inside the locked section still reads/writes by the real
    `public_key`/credential digest, never by the shard index.

    B67.4 second corrective-pass fix (MAJOR BUG #1, unbounded lock-file
    growth) - this used to open one lock file NAMED BY a digest of the
    public key itself, so the number of persistent lock files grew
    without bound as new DISTINCT, individually-valid public keys were
    presented - including ones that never successfully enrolled (rejected
    by the device cap, a provisioning failure, or simply never retried) -
    a cheap, unbounded filesystem-growth vector for anyone who can mint
    fresh public keys. Now backed by a FIXED-SIZE shard pool
    (`_key_lock_file_path`) - the persistent footprint this function ever
    creates is bounded by `_KEY_LOCK_SHARD_COUNT`, full stop, regardless
    of request volume or the number of distinct public keys ever
    presented.

    A real OS-level `flock`, NOT a `threading.Lock` - deliberately, since
    this API's own worker model (ThreadingHTTPServer today, but nothing
    architecturally rules out a future multi-process/gunicorn-style
    deployment) means two concurrent requests for the same public key are
    not guaranteed to land in the same process, let alone the same
    thread - only a real file lock is safe across that boundary, exactly
    the same reasoning `activations.per_activation_lock` already applies.
    This is also why sharding is safe against a lock-bypass-via-inode-
    replacement race: THIS function never calls `os.unlink()` on a shard
    lock file (unlike `_atomic_write_index`'s temp-file dance, which
    unlinks its OWN never-yet-visible temp file, never a lock file another
    process might be holding open) - a shard's lock file is opened once,
    ever, the first time that shard number is used, and is never removed
    or replaced for the lifetime of the deployment; every subsequent
    `os.open(lock_file_path, os.O_CREAT | os.O_RDWR, ...)` for that same
    shard resolves to that SAME, still-existing inode (`O_CREAT` is a
    no-op once the path exists), so two processes locking the same shard
    always `flock()` the same underlying file - there is no window in
    which a second process could create a fresh inode at that path and
    silently acquire an independent, non-conflicting lock. Crash-safe:
    the OS releases a held flock automatically the instant the holding
    process exits, for any reason - nothing here depends on cooperative
    cleanup. Each shard's lock file carries no sensitive content (0600,
    empty, a fixed predictable name - never derived from or containing
    any public key or credential material).

    LOCK ORDER (fixed, always in this direction, never the reverse): this
    key lock is always the OUTERMOST lock in this module's call graph -
    acquired BEFORE, and released AFTER, every other lock `enroll_device`
    or `revoke_and_remove_if_owned` may take beneath it:

        FIELD-ENROLLMENT KEY LOCK (this function)
          -> FieldEnrollmentIndex lock (`_index_lock`, via `_reserve_locked`/
             `find_in_index`/`remove_reservation_if_owned`/etc.)
          -> activations.py's per-activation lock (`per_activation_lock`,
             via `register_credential`/`provision_with_activation`/
             `remove_credential_if_unbound`/`revoke_activation`)
             -> activations.py's own global store lock (`_exclusive_lock`,
                already nested INSIDE the per-activation lock by
                activations.py's own existing, unchanged fixed order)

    Nothing INSIDE any of those three inner critical sections ever
    attempts to acquire THIS key lock (this module's own index-lock and
    activations.py's own per-activation/global-store locks are each
    self-contained, short critical sections that only ever touch their
    own file) - so this fixed order introduces no cycle and is
    deadlock-free without needing any lock-acquisition timeout, the exact
    same reasoning `activations.per_activation_lock`'s own docstring
    already applies one level down. Every acquisition of this key lock in
    this codebase (both call sites: `enroll_device` and
    `revoke_and_remove_if_owned`) acquires it FIRST, before any of the
    inner locks - there is no code path anywhere that acquires an inner
    lock (index/per-activation/global-store) and THEN attempts to acquire
    this key lock, so the reverse ordering this docstring warns against
    (KEY -> ACTIVATION in one process, ACTIVATION -> KEY in another) does
    not occur."""
    lock_dir = _key_lock_dir(index_path)
    os.makedirs(lock_dir, exist_ok=True)
    lock_file_path = _key_lock_file_path(index_path, public_key)
    fd = os.open(lock_file_path, os.O_CREAT | os.O_RDWR, 0o600)
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
    """Unconditional, NOT ownership-checked removal of a device's index
    entry, keyed by public key alone. B67.4 corrective-pass fix: this is
    now a plain, general-purpose primitive ONLY - `enroll_device`'s own
    rollback and the operator CLI's own revoke flow no longer call this
    (see [remove_reservation_if_owned]/[revoke_and_remove_if_owned]
    instead, which check the entry still belongs to the exact attempt
    doing the removing before deleting anything). Safe to keep using for
    a genuinely unconditional, caller-already-certain-of-ownership
    removal (e.g. a test fixture standing in for direct operator/database
    surgery), but never for a rollback/cleanup path that must not delete a
    LIVE concurrent reservation out from under it - those callers MUST
    hold [field_enrollment_key_lock] for this exact public key AND use the
    ownership-checked primitive below. Safe no-op if no entry exists."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        if public_key not in data:
            return False
        del data[public_key]
        _atomic_write_index(index_path, data)
        return True


def remove_reservation_if_owned(index_path, index_lock_path, public_key, expected_activation_id):
    """B67.4 corrective-pass fix (MAJOR BUG #1 cleanup) - the
    ownership-checked replacement for a blind `remove_from_index` call in
    every TRANSACTIONAL rollback/cleanup path (`enroll_device`'s own
    registration/provisioning-failure rollback, and the operator CLI's
    `revoke_and_remove_if_owned` below). Removes the entry for
    `public_key` ONLY if it still exists AND its `activation_id` still
    matches `expected_activation_id` exactly - i.e. only if this is still
    genuinely the SAME reservation the caller believes it owns, never
    whatever entry happens to be there NOW (a concurrent attempt may have
    already replaced it with an unrelated one, or already committed a
    real device against it). Mirrors
    `activations.remove_credential_if_unbound`'s own "only remove what
    this call is certain it owns" discipline on the index side of the
    same transaction.

    Idempotent and a safe no-op (returns False, never raises) whenever
    the ownership check does not match - a concurrent attempt already
    won this public key's slot, or a previous call already removed this
    exact entry. Callers performing a genuine rollback MUST call this
    while still holding [field_enrollment_key_lock] for this exact
    `public_key` (every caller in this module already does - the lock
    already makes the race this check defends against unreachable in
    practice, but the check itself costs nothing and removes any doubt,
    exactly like `remove_credential_if_unbound`'s own defensive
    activation_id-match reasoning)."""
    with _index_lock(index_lock_path):
        data = _read_index(index_path)
        entry = data.get(public_key)
        if entry is None:
            return False
        if entry["activation_id"] != expected_activation_id:
            return False
        del data[public_key]
        _atomic_write_index(index_path, data)
        return True


class RevokeResult:
    """One outcome of [revoke_and_remove_if_owned]."""

    __slots__ = ("activation_id", "changed")

    def __init__(self, activation_id, changed):
        self.activation_id = activation_id
        self.changed = changed


def revoke_and_remove_if_owned(index_path, index_lock_path, store_path, store_lock_path, public_key):
    """B67.4 corrective-pass fix (operator-CLI TOCTOU, item 15) - the ONE
    transactional operation `gateway/tools/field_enrollment_admin.py`'s
    `revoke` subcommand now calls, replacing its former
    find-then-revoke-then-blind-remove sequence (three independent,
    unsynchronized operations - a concurrent enrollment attempt for the
    SAME public key could revoke/remove a stale entry the CLI read, then
    have its OWN fresh entry deleted out from under it by that same CLI
    call's final `remove_from_index`). Entirely inside
    [field_enrollment_key_lock] for this exact `public_key`, so a
    concurrent `enroll_device` attempt for the SAME key cannot interleave
    with ANY part of this sequence - it either runs entirely before this
    call acquires the lock (this call then revokes/removes exactly the
    fresh entry that attempt created) or entirely after this call
    releases it (that attempt then sees a genuinely empty slot and
    enrolls the public key fresh, never a half-revoked leftover).

    Returns `None` if no index entry exists for this public key (nothing
    to revoke - the caller should report that, not attempt a revoke
    against a name that resolves to nothing). Otherwise returns a
    [RevokeResult] - `changed` mirrors `activations.revoke_activation`'s
    own return (True if this call actually flipped ACTIVE -> REVOKED,
    False if it was already revoked) - and the index entry naming that
    activation_id is removed via the SAME ownership-checked
    [remove_reservation_if_owned] primitive `enroll_device`'s own
    rollback uses, never a blind delete. If the activation record itself
    is already gone by the time this runs (e.g. a concurrent provisioning
    failure's own rollback already removed it via
    `remove_credential_if_unbound` - see that function's own docs), the
    revoke step is treated as `changed=False` (nothing left to revoke)
    and the stale index entry naming it is still cleaned up - a
    field-enrollment index entry must never outlive the activation record
    it names.
    """
    with field_enrollment_key_lock(index_path, public_key):
        entry = find_in_index(index_path, index_lock_path, public_key)
        if entry is None:
            return None
        activation_id = entry["activation_id"]
        try:
            changed = activations.revoke_activation(store_path, store_lock_path, activation_id)
        except KeyError:
            changed = False
        remove_reservation_if_owned(index_path, index_lock_path, public_key, activation_id)
        return RevokeResult(activation_id, changed)


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

    B67.4 corrective-pass fix - this entire sequence (steps 1-4, including
    every rollback path) now runs inside [field_enrollment_key_lock] for
    THIS exact `public_key` - see that function's own docstring for why
    this closes the same-public-key rollback race a prior version of this
    function had (a failed attempt's own rollback could delete a
    concurrent, successful attempt's live index entry) and for the fixed
    lock order this introduces. Rollback removals below additionally use
    [remove_reservation_if_owned] (ownership-checked - matches on
    `activation_id`) rather than a blind `remove_from_index`, as defense
    in depth on top of the lock itself. A registration failure that is
    specifically `activations.ActivationCommitUncertainError` (its own
    `os.replace()` already succeeded, durability merely unconfirmed - see
    that class's own docs) is re-raised WITHOUT any index rollback at
    all, even if this call made a new reservation - the activation record
    it was writing may already durably exist, and deleting the index
    reservation naming it would strand that record with no way back to
    its public key on a same-key retry.
    """
    if not is_valid_wg_public_key(public_key):
        return FieldEnrollmentResult(INVALID_PUBLIC_KEY)

    with field_enrollment_key_lock(index_path, public_key):
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
        except activations.ActivationCommitUncertainError:
            # See this function's own docstring and
            # ActivationCommitUncertainError's own docs: os.replace()
            # already succeeded - the activation record MAY already
            # durably exist - so this NEVER rolls back the index
            # reservation, even if this call created it. Re-raised
            # unchanged; handler.py's existing
            # ActivationStoreError/FieldEnrollmentIndexError catch (this
            # IS an ActivationStoreError) still maps it to a closed 503.
            # A retry of this SAME public key re-enters this same
            # reserve -> register sequence, finds this SAME index entry
            # (is_new_index_entry=False on that replay), and
            # register_credential's own idempotent-insert semantics
            # reconcile with whatever this attempt actually left durable.
            raise
        except Exception as exc:
            if reservation.is_new_index_entry:
                try:
                    remove_reservation_if_owned(index_path, index_lock_path, public_key, activation_id)
                except Exception as cleanup_exc:
                    raise FieldEnrollmentIndexError(
                        f"field-enrollment index rollback failed after a registration failure: {cleanup_exc}"
                    ) from exc
            raise

        # B67.4 second corrective-pass fix (MAJOR BUG #2, activation_id
        # consistency) - register_credential's own idempotent-insert
        # contract only ever returns created=False when a record for THIS
        # EXACT credential digest already exists; that existing record's
        # OWN activation_id is an independent fact from whatever THIS
        # module's own index currently names for this public key. In the
        # ordinary path these are always equal (the same reservation.
        # activation_id flows into register_credential, which either
        # writes a fresh record under it or - for a genuine replay -
        # finds the SAME record it or an earlier attempt already wrote
        # under it). A mismatch here means the index and the activation
        # store have DIVERGED for this exact credential digest (e.g. a
        # prior corruption, a manual edit, or a bug elsewhere) - this is
        # an integrity violation, never ordinary idempotence, and must
        # never be silently "resolved" by proceeding with whichever id
        # happens to be in the store, or by rewriting the index to agree
        # with it.
        if register_result.activation_id != activation_id:
            if reservation.is_new_index_entry:
                # This call's OWN, just-created reservation is what is
                # inconsistent with the store (its freshly minted
                # credential's digest already resolves to a DIFFERENT
                # activation_id than the one this call just reserved for
                # it) - safe to remove, since this call unambiguously
                # owns it. The store's own record under
                # register_result.activation_id is NEVER touched here -
                # this attempt has no ownership claim over it.
                try:
                    remove_reservation_if_owned(index_path, index_lock_path, public_key, activation_id)
                except Exception as cleanup_exc:
                    raise FieldEnrollmentIndexError(
                        "field-enrollment index rollback failed after an activation_id mismatch: "
                        f"{cleanup_exc}"
                    ) from cleanup_exc
            # Fail closed - no provisioning, no success response, no
            # further side effects. If this was a PRE-EXISTING index entry
            # (not this call's own reservation), it is deliberately left
            # completely untouched - never blindly repaired/rewritten,
            # since this call cannot tell which of the two disagreeing
            # records (if either) is the one actually in legitimate use.
            raise FieldEnrollmentIndexError(
                "field-enrollment index/activation-store integrity violation: the index names "
                f"activation_id={activation_id!r} for this public key, but the activation store's "
                f"own record for this exact credential digest carries activation_id="
                f"{register_result.activation_id!r} - refusing to provision or report success"
            )

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
                remove_reservation_if_owned(index_path, index_lock_path, public_key, activation_id)
            return FieldEnrollmentResult(PROVISION_FAILED, provision_error=result.provision_error)

        finalize_result = result.finalize_result
        if not finalize_result.confirmed:
            return FieldEnrollmentResult(DEVICE_CAP_REACHED)
        if finalize_result.status != activations.ACTIVE:
            return FieldEnrollmentResult(REVOKED)

        return FieldEnrollmentResult(
            ENROLLED, credential=credential, client_tunnel_ip=result.provision_outcome.ip,
        )
