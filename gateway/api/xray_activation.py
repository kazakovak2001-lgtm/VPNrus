"""B8K2A - the Xray activation boundary: durable canonical state ->
deterministic render -> stage -> privileged validate/publish/reload ->
confirmed success. This is the ONE module that closes the false-success
window POST /v1/xray-profile and revocation both had (see
gateway/api/xray_provisioning.py and gateway/api/xray_config_renderer.py's
own docstrings for the pieces this composes).

Reads the REALITY private key file exactly once per activation attempt,
transiently, only long enough to build the candidate config this process
stages for the privileged wrapper to independently re-validate before ever
publishing it live - see build_reality_config's own docstring. Never
logs it, never returns it in any HTTP response, never holds it beyond one
render call's local variables.

Optimization (not a correctness requirement, but see this module's own
docstring on why it matters operationally): nova-xray.service is restarted,
not gracefully reloaded, on every activation (see xray-activate.sh's own
docstring for why - the pinned binary has no verified graceful-reload
path). Restarting on EVERY idempotent profile-fetch retry would drop every
currently-connected Xray client's connection on every single duplicate
request from any user - unacceptable. activate_if_needed therefore renders
first, compares the candidate's sha256 against the last-successfully-
activated one (a small pocvpn-api-owned fingerprint file), and skips
invoking the privileged wrapper entirely when nothing has changed. This
comparison is pure/local - it changes no security property (the wrapper's
own `xray run -test` validation and the fixed argv/paths are still the
only things that ever decide what gets published).
"""
import hashlib
import json
import os
import tempfile

from . import activations, xray_config_renderer, xray_provisioning, xray_reload


class XrayActivationNotConfigured(Exception):
    """Raised when AppConfig's B8K2A fields are incomplete - see
    config.py's own all-or-nothing validation, which should make this
    unreachable in practice; kept as a defensive, explicit failure rather
    than a silent skip."""


class ActivationResult:
    __slots__ = ("activated", "skipped", "error")

    def __init__(self, activated, skipped=False, error=None):
        self.activated = activated
        self.skipped = skipped
        self.error = error


def init_activation_lock(lock_path):
    """Create the global activation lock file if it doesn't exist yet -
    mirrors activations.init_store's own lock-creation step. Idempotent."""
    directory = os.path.dirname(os.path.abspath(lock_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)


def build_reality_config(app_config):
    """The ONE place this process reads the REALITY private key file's
    contents. Transient: the value lives only in this function's local
    scope and the RealityServerConfig it returns - never assigned to a
    module-level/long-lived variable, never logged."""
    if not app_config.xray_reality_private_key_file:
        raise XrayActivationNotConfigured("xray_reality_private_key_file is not configured")
    with open(app_config.xray_reality_private_key_file, "r", encoding="utf-8") as handle:
        private_key = handle.read().strip()

    return xray_config_renderer.RealityServerConfig(
        listen_port=app_config.xray_server_port,
        server_names=(app_config.xray_server_name,),
        dest=app_config.xray_dest,
        private_key=private_key,
        short_ids=(app_config.xray_short_id,),
    )


def _read_last_activated_hash(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return None


def _write_last_activated_hash(path, sha256_hex):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".xray-last-hash.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sha256_hex + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _render_candidate(app_config):
    """Reads BOTH durable stores fresh (short, released locks - never this
    module's own long-held lock) and renders. Returns (config_dict,
    canonical_json_text, sha256_hex)."""
    reality = build_reality_config(app_config)
    activations_data = activations.read_store_shared(app_config.activation_store_path, app_config.activation_lock_path)
    xray_data = xray_provisioning.read_store_shared(app_config.xray_store_path, app_config.xray_lock_path)
    config_dict = xray_config_renderer.render_server_config(activations_data, xray_data, reality, flow=app_config.xray_flow)
    canonical_text = json.dumps(config_dict, indent=2, sort_keys=True) + "\n"
    sha256_hex = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    return config_dict, sha256_hex


def activate_if_needed(app_config):
    """The one function callers (provision_and_activate, the revoke CLI,
    and the recovery/reconcile path) all use. Must be called while holding
    whatever OUTER lock the caller already needs for its own correctness
    (e.g. per-activation lock for a single provisioning request) - this
    function itself acquires ONLY the global Xray activation lock
    (app_config.xray_activation_lock_path), which is always the INNERMOST
    lock in this codebase's fixed ordering:

        per-activation lock (activations.per_activation_lock)
            -> xray provisioning store lock (xray_provisioning._exclusive_lock,
               already released by the time this function is called)
            -> THIS global xray activation lock

    Never the reverse - this function never calls into activations.py or
    xray_provisioning.py's own write paths while holding its lock, only
    their read-only, momentarily-locked accessors.

    Concurrency correctness: because this lock is held across the ENTIRE
    render -> compare -> stage -> invoke-wrapper sequence, two concurrent
    callers (even for different activations) can never publish a
    configuration derived from a stale snapshot over a newer one - the
    second caller to acquire the lock always re-renders from
    whatever-is-durably-true at that moment, which already reflects
    anything the first caller wrote.
    """
    if not app_config.xray_activation_wrapper_path:
        raise XrayActivationNotConfigured("Xray activation boundary is not configured")

    with xray_provisioning.global_lock(app_config.xray_activation_lock_path, create=False):
        try:
            config_dict, sha256_hex = _render_candidate(app_config)
        except xray_config_renderer.XrayConfigRenderError as exc:
            return ActivationResult(activated=False, error=exc)

        last_hash = _read_last_activated_hash(app_config.xray_activation_last_hash_path)
        if last_hash == sha256_hex:
            return ActivationResult(activated=True, skipped=True)

        xray_config_renderer.atomic_write_config(app_config.xray_staging_config_path, config_dict)

        try:
            xray_reload.activate(
                app_config.xray_activation_wrapper_path,
                app_config.xray_activation_timeout_seconds,
                sudo_path=app_config.sudo_path or None,
            )
        except xray_reload.XrayReloadError as exc:
            return ActivationResult(activated=False, error=exc)

        _write_last_activated_hash(app_config.xray_activation_last_hash_path, sha256_hex)
        return ActivationResult(activated=True)


def provision_and_activate(credential, public_key, app_config, now=None):
    """The full POST /v1/xray-profile transaction: identity decide/create
    (under the existing per-activation lock, see
    xray_provisioning.provision_and_activate_identity) followed
    IMMEDIATELY, still inside that SAME lock, by activate_if_needed - so no
    revoke or competing identity write can slip in between minting/
    confirming an identity and confirming it is actually live. See that
    function's own docstring for why this is not simply "call
    provision_xray_identity, then separately call activate_if_needed"."""
    return xray_provisioning.provision_and_activate_identity(
        credential, public_key,
        app_config.activation_store_path, app_config.activation_lock_path,
        app_config.xray_store_path, app_config.xray_lock_path,
        activate_fn=lambda: activate_if_needed(app_config),
        now=now,
    )


def reconcile(app_config):
    """Idempotent recovery/startup-convergence entry point (B8K2A step 7) -
    safe to call after a process crash, host reboot, a failed prior
    reload, or a durable revoke whose reload attempt failed. Does exactly
    what activate_if_needed always does: render current canonical state,
    skip if already activated, otherwise validate/publish/reload. Not
    wired to run automatically on every request or on a timer in this
    slice - see gateway/tools/xray_reconcile.py, the explicit operator
    entry point."""
    return activate_if_needed(app_config)
