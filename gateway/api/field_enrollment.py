"""Russia field-test zero-touch enrollment (POST /v1/field-enroll).

NOT the final production signup architecture - a bounded, explicitly-scoped
mechanism for a small field-test device cohort. Reuses activations.py's own
entitlement/binding/provisioning primitives VERBATIM (decide_and_bind ->
run_provision_peer -> finalize_reservation, via provision_with_activation) -
this is not a second, parallel authorization system, only a different way
for a device to obtain its own activation credential.

Credential derivation (deliberate design choice - see the owner-facing
report this PR's own description carries for the rationale in full): rather
than generating a random credential and persisting it in some NEW
raw-credential-bearing store (which would be the only such store in this
codebase - activations.py's own module docstring is explicit that "the raw
activation credential is NEVER written here or anywhere else in this
codebase"), each device's credential is DERIVED deterministically as

    HMAC-SHA256(field_enrollment_secret, "nova-field-enroll:v1:" + public_key)

This is:
  - unique per device: a collision would require two devices sharing one
    AmneziaWG/WireGuard public key (a real 256-bit key space) - never two
    different devices deriving the same credential;
  - computationally indistinguishable from a uniformly random 256-bit
    credential to anyone without field_enrollment_secret (the same PRF
    security assumption HMAC's own design rests on) - genuinely a
    "cryptographically random-equivalent, unguessable" credential, just not
    literally the output of secrets.token_bytes();
  - trivially, race-free-ly idempotent: a device that calls this endpoint
    again (crash/lost-response retry, or simply because it has not yet
    persisted a credential locally) re-derives the IDENTICAL value without
    the server ever needing to look up or return a previously-issued raw
    value from anywhere;
  - individually revocable: the underlying activations.py record this
    credential's digest maps to is a REAL, ordinary single-device
    (max_devices=1) activation record - gateway/tools/field_enrollment_admin.py's
    `revoke` command (or the pre-existing gateway/tools/activation_tokens.py
    `revoke`, given the activation_id) works on it completely unmodified.

field_enrollment_secret itself is a server-only, operator-provisioned file
(FIELD_ENROLLMENT_HMAC_SECRET_FILE) - never embedded in the APK, never
logged, never returned in any response, read transiently once per request.
"""
import base64
import hashlib
import hmac as hmac_module

from . import activations
from .wgkey import is_valid_wg_public_key

_CREDENTIAL_HMAC_CONTEXT = b"nova-field-enroll:v1:"

# enroll_device() outcomes.
ENROLLED = "enrolled"
DISABLED = "disabled"
INVALID_PUBLIC_KEY = "invalid_public_key"
DEVICE_CAP_REACHED = "device_cap_reached"
REVOKED = "revoked"
EXPIRED = "expired"
PROVISION_FAILED = "provision_failed"


class FieldEnrollmentResult:
    __slots__ = ("outcome", "credential", "client_tunnel_ip", "provision_error")

    def __init__(self, outcome, credential=None, client_tunnel_ip=None, provision_error=None):
        self.outcome = outcome
        self.credential = credential
        self.client_tunnel_ip = client_tunnel_ip
        self.provision_error = provision_error


def derive_credential(hmac_secret, public_key):
    """`hmac_secret` is raw bytes. See module docstring for why this is
    deterministic rather than randomly generated-and-stored. URL-safe
    base64, unpadded - the same shape secrets.token_urlsafe(32) produces,
    so it round-trips through the exact same Bearer-header/digest handling
    every other activation credential already uses, unmodified."""
    digest = hmac_module.new(
        hmac_secret, _CREDENTIAL_HMAC_CONTEXT + public_key.encode("ascii"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def enroll_device(
    public_key,
    hmac_secret,
    activation_store_path, activation_lock_path,
    provision_script_path, subprocess_timeout_seconds,
    global_device_cap,
    sudo_path=None,
    now=None,
):
    """The ONE function POST /v1/field-enroll calls once handler.py's own
    config/enabled gate has already passed. Caller is responsible for rate
    limiting - this function has none of its own.

    Never mutates/creates anything for INVALID_PUBLIC_KEY - fails closed
    before touching the activation store at all.
    """
    if not is_valid_wg_public_key(public_key):
        return FieldEnrollmentResult(INVALID_PUBLIC_KEY)

    credential = derive_credential(hmac_secret, public_key)

    try:
        activation_id = activations.issue_activation_if_under_cap(
            activation_store_path, activation_lock_path,
            global_cap=global_device_cap,
            credential=credential,
            max_devices=1,
        )
    except activations.ActivationStoreError:
        raise
    if activation_id is None:
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)

    # Reuse the EXACT SAME orchestration POST /v1/activate uses - decide_and_bind
    # -> run_provision_peer -> finalize/rollback, one per-activation lock.
    result = activations.provision_with_activation(
        credential, public_key,
        activation_store_path, activation_lock_path,
        provision_script_path, subprocess_timeout_seconds, sudo_path=sudo_path,
        now=now,
    )
    decision = result.decision
    if decision.outcome == activations.INVALID:
        # Unreachable in practice - issue_activation_if_under_cap just
        # created/confirmed this exact digest under the same lock
        # discipline - but never silently swallowed if it ever happens
        # (e.g. a corrupted store read between the two calls).
        return FieldEnrollmentResult(DISABLED)
    if decision.outcome == activations.REVOKED_OUTCOME:
        return FieldEnrollmentResult(REVOKED)
    if decision.outcome == activations.EXPIRED:
        return FieldEnrollmentResult(EXPIRED)
    if decision.outcome == activations.DEVICE_LIMIT:
        # This credential's own max_devices=1 was already reached by a
        # DIFFERENT public key - structurally shouldn't happen (this
        # credential is derived 1:1 from this exact public key), but fails
        # closed rather than reporting success either way.
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)

    if result.provision_error is not None:
        return FieldEnrollmentResult(PROVISION_FAILED, provision_error=result.provision_error)

    finalize_result = result.finalize_result
    if not finalize_result.confirmed:
        return FieldEnrollmentResult(DEVICE_CAP_REACHED)
    if finalize_result.status != activations.ACTIVE:
        return FieldEnrollmentResult(REVOKED)

    return FieldEnrollmentResult(
        ENROLLED, credential=credential, client_tunnel_ip=result.provision_outcome.ip,
    )
