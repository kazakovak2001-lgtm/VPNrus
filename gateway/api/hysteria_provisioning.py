"""B46-4A - per-device Hysteria2 data-plane credential store, extending the
EXISTING B8C1 activation/device-binding model (gateway/api/activations.py)
rather than creating a second, unrelated account/token system - the SAME
discipline gateway/api/xray_provisioning.py already established for
VLESS/REALITY identities.

PINNED-UPSTREAM EVIDENCE (server auth mechanism): the Hysteria2 server this
module supports is upstream `apernet/hysteria`, pinned commit
`e1366b173ccf5706e1e4630fe8aa654a4b574085` (the SAME pin B46-2P/B46-2C/B46-3C
physically validated against). At that exact commit,
`app/cmd/server.go`'s `fillAuthenticator` supports four `auth.type` backends:
`password` (one global static string), `userpass` (a static in-config
username/password map), `http`/`https` (`extras/auth/http.go`'s
`HTTPAuthenticator` - POSTs `{"addr","auth","tx"}` JSON to a configured URL
and expects `{"ok": bool, "id": string}` back), and `command`/`cmd` (shells
out to an external command per attempt). `password`/`userpass` both require
every valid secret to already be present in the Hysteria server's own static
config file at process start - reloading either to add or revoke ONE device
means restarting (or re-templating and reloading) the whole Hysteria server
process, and revocation cannot be enforced until that reload happens.
`command` shells out per connection attempt - real overhead and a much
larger review surface for a hard security boundary. `http` is chosen here:
it lets THIS gateway process answer with LIVE, per-request activation state
(ACTIVE/revoked/expired, exactly what [verify_hysteria_auth] below checks)
with ZERO Hysteria server restart/reload on every device provisioned or
revoked - the closest fit to "per-device/revocable credentials" without a
second entitlement authority. Chosen ONLY after this verification, not
assumed - see docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's own
"pinned-upstream auth mechanism" section for the full citation and the
rejected alternatives' reasoning.

STORAGE: unlike xray_provisioning.py's VLESS UUID (a non-secret client
identifier that is safe to persist in plaintext), a Hysteria2 `auth_secret`
IS the wire credential itself. This module never persists the raw secret at
rest: it stores only a salted SHA-256 hash. The raw secret is generated
once, returned to the client in the (TLS-protected) provisioning response,
and from that point on the server only ever needs to verify a hash match
against what the connecting Hysteria2 server presents to [verify_hysteria_auth]
over the (loopback-only, see the design doc) HTTP auth backend - it never
needs the raw value again. This is a genuine advantage `password`/`userpass`
auth (which requires the RAW secret to sit in the Hysteria server's own
config file) cannot offer.

SALAMANDER OBFUSCATION IS NOT PROVISIONED HERE (B46-4A review fix, Finding
8): upstream `apernet/hysteria`'s Salamander obfuscation is a LISTENER-LEVEL
server config setting (`obfs: {type: salamander, salamander: {password:
...}}`) - one static password for the whole server process, applied before
any QUIC handshake and therefore before any per-connection `auth` exchange.
It cannot vary per connecting device the way `auth.type: http` can select a
per-device `auth_secret`. An earlier version of this module minted a
per-device "obfuscation secret" anyway - that was never a real capability
this server architecture could act on. This module mints and stores ONLY
the Hysteria2 wire `auth_secret`; the signed client-side profile's
`obfuscationMode` stays `NONE` for this production slice (see
`net.pocvpn.client.reachability.Hysteria2ProfileMetadata`'s own doc). A
future slice may reintroduce Salamander support via a real SHARED,
endpoint-level secret distributed and rotated independently of this
per-device store.

Record shape (this store, keyed by the SAME credential-digest scheme
activations.py uses - never the raw activation credential):
    {
      "<64-hex activation digest>": [
        {"device_public_key": "<AmneziaWG/WireGuard public key>",
         "auth_secret_hash": "<64-hex sha256(salt || auth_secret)>",
         "auth_secret_salt": "<32-hex random salt>",
         "created_at": "<ISO 8601 UTC>"},
        ...
      ]
    }

Concurrency / lock ordering: identical to xray_provisioning.py's own
documented discipline - the per-activation lock (activations.per_activation_lock,
REUSED, same digest, same lock file activations.py already owns) is always
the outermost lock; this module's own store lock is a separate, independent
file, never held while acquiring an activations.py lock.

NOT WIRED TO A RUNNING HYSTERIA2 SERVER YET (B46-4A scope): this module and
gateway/api/hysteria_auth_backend.py are code-only. No systemd unit, no
firewall rule, no nginx route, and no production manifest binding are
created or modified by this slice - see docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's
"server deployment proposal" section for what B46-4P still has to do.
"""
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from . import activations, hysteria_store

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_IDENTITY_FIELDS = frozenset(
    {"device_public_key", "auth_secret_hash", "auth_secret_salt", "created_at"},
)

# provision_hysteria_identity outcomes - mirrors xray_provisioning.py's own
# NOT_ELIGIBLE_* constants exactly (same activations.py entitlement model).
NOT_ELIGIBLE_UNKNOWN = "not_eligible_unknown"
NOT_ELIGIBLE_REVOKED = "not_eligible_revoked"
NOT_ELIGIBLE_EXPIRED = "not_eligible_expired"
NOT_ELIGIBLE_DEVICE_NOT_BOUND = "not_eligible_device_not_bound"
ISSUED = "issued"

AUTH_SECRET_BYTES = 32  # 256 bits - secrets.token_hex(32) below -> 64 hex chars.
_SALT_BYTES = 16


class HysteriaStoreError(Exception):
    """The store or its lock file is missing/corrupted/unreadable - the HTTP layer must map this to 503."""


class HysteriaStoreWriteError(Exception):
    """A durable-write precondition or step failed - caller must abort, leave the prior store byte-for-byte untouched."""


@dataclass(frozen=True)
class HysteriaIdentityResult:
    outcome: str
    # Set only for ISSUED. auth_secret is the fresh RAW value this exact
    # call just minted (see provision_hysteria_identity's own "retry-safe
    # rotation, not idempotence" doc) - present only in this in-memory
    # result, never re-derivable from the store afterward (only the hash is
    # durable). Every successful call rotates: a retry gets a NEW secret,
    # not a recalled old one. No per-device obfuscation secret is minted -
    # see this module's own "SALAMANDER OBFUSCATION IS NOT PROVISIONED HERE"
    # doc (Finding 8).
    auth_secret: str = ""


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _hash_secret(secret, salt_hex):
    return hashlib.sha256(bytes.fromhex(salt_hex) + secret.encode("utf-8")).hexdigest()


def _check_device_eligibility(credential, public_key, activation_store_path, activation_lock_path, now):
    """Read-only. Momentary SHARED read of the ACTIVATION store - mirrors
    xray_provisioning._check_device_eligibility exactly (same entitlement
    authority, never re-implemented independently)."""
    try:
        data = activations.read_store_shared(activation_store_path, activation_lock_path)
    except activations.ActivationStoreError as exc:
        raise HysteriaStoreError(f"activation store unavailable while checking Hysteria2 eligibility: {exc}") from exc

    digest = activations.credential_digest(credential)
    record = data.get(digest)
    if record is None:
        return NOT_ELIGIBLE_UNKNOWN
    if record["status"] != activations.ACTIVE:
        return NOT_ELIGIBLE_REVOKED
    expires_at = record["expires_at"]
    if expires_at is not None and now >= datetime.fromisoformat(expires_at):
        return NOT_ELIGIBLE_EXPIRED

    for device in record["bound_devices"]:
        if device["public_key"] == public_key and device["state"] == activations.CONFIRMED:
            return None  # eligible
    return NOT_ELIGIBLE_DEVICE_NOT_BOUND


def provision_hysteria_identity(
    credential, public_key,
    activation_store_path, activation_lock_path,
    hysteria_store_path, hysteria_lock_path,
    now=None,
):
    """Durable credential mint/rotate. **RETRY-SAFE ROTATION, NOT BYTE-IDENTICAL
    IDEMPOTENCE**: an earlier version of this function treated a retry for an
    already-existing (credential, public_key) as a no-op returning an EMPTY
    `auth_secret` - since only the SALTED HASH is ever durable, that left a
    device that never received its first response (dropped response,
    app killed mid-request, network failure) with NO way to recover a usable
    secret, permanently. That was a real bug, not a documentation gap.

    The corrected contract: EVERY successful call - first mint or any later
    retry - generates a FRESH random secret, atomically REPLACES the stored
    hash/salt for that exact (digest, public_key) record, and returns the
    fresh RAW secret. The previous secret (if any) stops authenticating the
    instant this call durably commits - [verify_hysteria_auth] only ever
    compares against whatever hash is CURRENTLY stored, so an old, now-
    orphaned secret simply no longer matches anything. This is safe for a
    legitimate client retry (it always has exactly one live secret to use -
    whichever this call's own response carries) and does NOT weaken
    security: rotation-on-retry is functionally equivalent to the client
    proactively rotating its own credential, something it is already
    entitled to do given a valid, bound activation.

    Concurrency: the surrounding [activations.per_activation_lock] (digest-
    scoped) already serializes every provisioning call for the SAME
    activation, including concurrent retries for the SAME device - two
    concurrent callers can never race to mint two different "current"
    secrets; whichever acquires the lock second sees (and replaces) the
    first's freshly-written record deterministically, and only ITS own
    response secret remains valid afterward.
    """
    now = now or datetime.now(timezone.utc)
    digest = activations.credential_digest(credential)

    with activations.per_activation_lock(activation_store_path, digest):
        ineligible = _check_device_eligibility(credential, public_key, activation_store_path, activation_lock_path, now)
        if ineligible is not None:
            return HysteriaIdentityResult(outcome=ineligible)

        with hysteria_store.exclusive_lock(hysteria_lock_path, create=False):
            data = hysteria_store.read_and_validate_under_lock(hysteria_store_path)
            identities = data.get(digest, [])
            other_devices = [identity for identity in identities if identity["device_public_key"] != public_key]

            auth_secret = secrets.token_hex(AUTH_SECRET_BYTES)
            auth_salt = secrets.token_hex(_SALT_BYTES)

            new_identity = {
                "device_public_key": public_key,
                "auth_secret_hash": _hash_secret(auth_secret, auth_salt),
                "auth_secret_salt": auth_salt,
                "created_at": _utc_now_iso(),
            }
            # atomic_write_store_or_raise never partially writes - see
            # hysteria_store.atomic_write_store's own crash-safety doc: on
            # any failure the tmp file is discarded and the PRIOR store
            # (still containing the device's still-valid previous secret's
            # hash) is left completely untouched. This function propagates
            # that failure (never swallows it) so a caller never believes a
            # rotation happened when it did not.
            data[digest] = other_devices + [new_identity]
            hysteria_store.atomic_write_store_or_raise(hysteria_store_path, data)
            return HysteriaIdentityResult(outcome=ISSUED, auth_secret=auth_secret)


@dataclass(frozen=True)
class AuthVerificationResult:
    ok: bool
    # Non-secret identity label returned to the Hysteria server's own `id`
    # field (its own event log correlates traffic to this, never the raw
    # secret - see extras/auth/http.go's own httpAuthResponse shape). Empty
    # when ok is False.
    device_id: str = ""


def verify_hysteria_auth(presented_secret, activation_store_path, activation_lock_path, hysteria_store_path, hysteria_lock_path, now=None):
    """The ONE function gateway/api/hysteria_auth_backend.py's HTTP handler
    calls for every real Hysteria2 connection attempt. Bounded, read-only,
    concurrency-safe (shared reads of both stores, no lock held across the
    whole scan). Linear scan over all stored device records: acceptable at
    this project's actual device-count scale (B46-4A design-time trade-off,
    documented rather than silently accepted - see the design doc's own
    "server storage" section for the indexed-lookup upgrade path if device
    count ever grows enough to matter). NEVER logs [presented_secret] - the
    caller must not either.
    """
    now = now or datetime.now(timezone.utc)
    try:
        hysteria_data = hysteria_store.read_store_shared(hysteria_store_path, hysteria_lock_path)
    except hysteria_store.HysteriaStoreLockError as exc:
        raise HysteriaStoreError(f"hysteria store unavailable during auth verification: {exc}") from exc

    for digest, identities in hysteria_data.items():
        for identity in identities:
            candidate_hash = _hash_secret(presented_secret, identity["auth_secret_salt"])
            if not secrets.compare_digest(candidate_hash, identity["auth_secret_hash"]):
                continue
            # Hash matched - now, and only now, check LIVE activation state
            # (never cached, never trusted from the moment of provisioning -
            # this is what makes revocation/expiry take effect without any
            # Hysteria server reload, the whole point of the http backend).
            try:
                activation_data = activations.read_store_shared(activation_store_path, activation_lock_path)
            except activations.ActivationStoreError as exc:
                raise HysteriaStoreError(f"activation store unavailable during auth verification: {exc}") from exc
            record = activation_data.get(digest)
            if record is None or record["status"] != activations.ACTIVE:
                return AuthVerificationResult(ok=False)
            expires_at = record["expires_at"]
            if expires_at is not None and now >= datetime.fromisoformat(expires_at):
                return AuthVerificationResult(ok=False)
            bound = any(
                device["public_key"] == identity["device_public_key"] and device["state"] == activations.CONFIRMED
                for device in record["bound_devices"]
            )
            if not bound:
                return AuthVerificationResult(ok=False)
            return AuthVerificationResult(ok=True, device_id=f"{digest[:8]}:{identity['device_public_key'][:8]}")
    return AuthVerificationResult(ok=False)
