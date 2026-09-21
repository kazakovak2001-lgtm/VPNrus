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

Record shape (this store, keyed by the SAME credential-digest scheme
activations.py uses - never the raw activation credential):
    {
      "<64-hex activation digest>": [
        {"device_public_key": "<AmneziaWG/WireGuard public key>",
         "auth_secret_hash": "<64-hex sha256(salt || auth_secret)>",
         "auth_secret_salt": "<32-hex random salt>",
         "obfuscation_secret_hash": "<64-hex sha256(salt || secret)> | null",
         "obfuscation_secret_salt": "<32-hex random salt> | null",
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
    {"device_public_key", "auth_secret_hash", "auth_secret_salt", "obfuscation_secret_hash", "obfuscation_secret_salt", "created_at"},
)

# provision_hysteria_identity outcomes - mirrors xray_provisioning.py's own
# NOT_ELIGIBLE_* constants exactly (same activations.py entitlement model).
NOT_ELIGIBLE_UNKNOWN = "not_eligible_unknown"
NOT_ELIGIBLE_REVOKED = "not_eligible_revoked"
NOT_ELIGIBLE_EXPIRED = "not_eligible_expired"
NOT_ELIGIBLE_DEVICE_NOT_BOUND = "not_eligible_device_not_bound"
ISSUED = "issued"

AUTH_SECRET_BYTES = 32  # 256 bits - secrets.token_hex(32) below -> 64 hex chars.
OBFUSCATION_SECRET_BYTES = 32
_SALT_BYTES = 16


class HysteriaStoreError(Exception):
    """The store or its lock file is missing/corrupted/unreadable - the HTTP layer must map this to 503."""


class HysteriaStoreWriteError(Exception):
    """A durable-write precondition or step failed - caller must abort, leave the prior store byte-for-byte untouched."""


@dataclass(frozen=True)
class HysteriaIdentityResult:
    outcome: str
    # Set only for ISSUED. auth_secret/obfuscation_secret are the ONE-TIME
    # RAW values - present only in the in-memory result of a mint/idempotent
    # lookup this same process just performed; never re-derivable from the
    # store afterward (only the hash is durable). obfuscation_secret is None
    # when this endpoint was not configured to use Salamander obfuscation.
    auth_secret: str = ""
    obfuscation_secret: str | None = None


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
    use_obfuscation,
    now=None,
):
    """Durable credential decide/mint. Idempotent: a retry for the same
    (credential, public_key) returns the SAME auth_secret it minted the
    first time (re-derivable ONLY because this process still holds the
    freshly-generated raw value in its own local store-write branch below -
    a retry that lands on the ALREADY-existing-identity branch instead
    cannot return the original raw secret, since only its hash is durable;
    see [HysteriaIdentityResult]'s own doc and the design doc's "retry
    semantics" section for how the client is expected to handle this: a
    lost/never-received response must re-provision, which mints a FRESH
    secret and durably invalidates the old hash, rather than the server
    ever being asked to recall a secret it deliberately does not retain).
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

            for identity in identities:
                if identity["device_public_key"] == public_key:
                    # Idempotent retry - never mutate, never mint a second
                    # secret. The raw secret is NOT recoverable here (only
                    # its hash is durable) - see this function's own doc.
                    return HysteriaIdentityResult(outcome=ISSUED)

            auth_secret = secrets.token_hex(AUTH_SECRET_BYTES)
            auth_salt = secrets.token_hex(_SALT_BYTES)
            obfuscation_secret = secrets.token_hex(OBFUSCATION_SECRET_BYTES) if use_obfuscation else None
            obfuscation_salt = secrets.token_hex(_SALT_BYTES) if use_obfuscation else None

            new_identity = {
                "device_public_key": public_key,
                "auth_secret_hash": _hash_secret(auth_secret, auth_salt),
                "auth_secret_salt": auth_salt,
                "obfuscation_secret_hash": _hash_secret(obfuscation_secret, obfuscation_salt) if use_obfuscation else None,
                "obfuscation_secret_salt": obfuscation_salt,
                "created_at": _utc_now_iso(),
            }
            data[digest] = identities + [new_identity]
            hysteria_store.atomic_write_store_or_raise(hysteria_store_path, data)
            return HysteriaIdentityResult(outcome=ISSUED, auth_secret=auth_secret, obfuscation_secret=obfuscation_secret)


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
