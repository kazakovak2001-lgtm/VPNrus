"""B25 (task F/G/H/I) - the ingress-role counterpart of xray_activation.py:
durable canonical state -> deterministic render (via
xray_ingress_config_renderer, upstream-relay outbound, NEVER freedom) ->
stage -> privileged validate/publish/reload -> confirmed success.

Reuses xray_provisioning.py's identity store and
provision_and_activate_identity VERBATIM for the client-facing VLESS
identity (task G's own "reuse existing activation authentication,
revocation and quota discipline" - an ingress has NO second, independent
client identity system) - the ONLY thing genuinely new here is the RENDER
step, which points the server's outbound at the pinned EXIT via
[ingress_config.IngressAppConfig]'s own upstream fields instead of
"freedom" (task requirement H).

Reads the ingress's own REALITY private key file AND the ingress->exit
upstream relay UUID file exactly once per activation attempt, transiently -
never logs either, never returns either in an HTTP response, never holds
either beyond one render call's local variables (task requirement H's own
"never printed in diagnostics/PR/tests").
"""
import hashlib
import json
import os
import tempfile

from . import activations, xray_provisioning, xray_reload
from . import xray_ingress_config_renderer as ingress_renderer


class IngressActivationNotConfigured(Exception):
    """Raised when IngressAppConfig's own activation-boundary fields are
    incomplete - should be unreachable given ingress_config.py's all-or-
    nothing validation; kept as a defensive, explicit failure."""


class ActivationResult:
    __slots__ = ("activated", "skipped", "error")

    def __init__(self, activated, skipped=False, error=None):
        self.activated = activated
        self.skipped = skipped
        self.error = error


def build_reality_config(ingress_config):
    with open(ingress_config.ingress_reality_private_key_file, "r", encoding="utf-8") as handle:
        private_key = handle.read().strip()
    from . import xray_config_renderer as base
    return base.RealityServerConfig(
        listen_port=ingress_config.ingress_server_port,
        server_names=(ingress_config.ingress_server_name,),
        dest=ingress_config.ingress_dest,
        private_key=private_key,
        short_ids=(ingress_config.ingress_short_id,),
    )


def build_tls_config(ingress_config):
    if not ingress_config.ingress_tls_server_port:
        return None
    from . import xray_config_renderer as base
    return base.TlsServerConfig(
        listen_port=ingress_config.ingress_tls_server_port,
        cert_file=ingress_config.ingress_tls_cert_file,
        key_file=ingress_config.ingress_tls_key_file,
    )


def build_upstream_config(ingress_config):
    """The ONE place this process reads the ingress->exit relay UUID file's
    contents (task requirement H) - transient, never assigned to a
    module-level/long-lived variable, never logged, never returned to a
    caller of this module's own public functions."""
    with open(ingress_config.ingress_upstream_uuid_file, "r", encoding="utf-8") as handle:
        upstream_uuid = handle.read().strip()
    return ingress_renderer.UpstreamExitConfig(
        host=ingress_config.ingress_upstream_host,
        port=ingress_config.ingress_upstream_port,
        transport=ingress_config.ingress_upstream_transport,
        uuid=upstream_uuid,
        server_name=ingress_config.ingress_upstream_server_name or None,
        public_key=ingress_config.ingress_upstream_public_key or None,
        short_id=ingress_config.ingress_upstream_short_id or None,
        sni=ingress_config.ingress_upstream_sni or None,
        flow=ingress_config.ingress_upstream_flow or None,
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
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".ingress-last-hash.", suffix=".tmp")
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


def _render_candidate(ingress_config):
    reality = build_reality_config(ingress_config)
    tls = build_tls_config(ingress_config)
    upstream = build_upstream_config(ingress_config)
    activations_data = activations.read_store_shared(ingress_config.activation_store_path, ingress_config.activation_lock_path)
    xray_data = xray_provisioning.read_store_shared(ingress_config.xray_store_path, ingress_config.xray_lock_path)
    config_dict = ingress_renderer.render_ingress_server_config(
        activations_data, xray_data, reality, upstream, tls=tls, flow=ingress_config.ingress_flow,
    )
    canonical_text = json.dumps(config_dict, indent=2, sort_keys=True) + "\n"
    sha256_hex = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    return config_dict, sha256_hex


def activate_if_needed(ingress_config):
    """Mirrors xray_activation.activate_if_needed's own lock-ordering and
    skip-when-unchanged optimization exactly - see that function's own
    docstring for the full rationale, reused verbatim here."""
    if not ingress_config.ingress_activation_wrapper_path:
        raise IngressActivationNotConfigured("ingress activation boundary is not configured")

    with xray_provisioning.global_lock(ingress_config.ingress_activation_lock_path, create=False):
        try:
            config_dict, sha256_hex = _render_candidate(ingress_config)
        except ingress_renderer.IngressConfigRenderError as exc:
            return ActivationResult(activated=False, error=exc)

        last_hash = _read_last_activated_hash(ingress_config.ingress_activation_last_hash_path)
        if last_hash == sha256_hex:
            return ActivationResult(activated=True, skipped=True)

        from . import xray_config_renderer as base
        base.atomic_write_config(ingress_config.ingress_staging_config_path, config_dict)

        try:
            xray_reload.activate(
                ingress_config.ingress_activation_wrapper_path,
                ingress_config.ingress_activation_timeout_seconds,
                sudo_path=ingress_config.sudo_path or None,
            )
        except xray_reload.XrayReloadError as exc:
            return ActivationResult(activated=False, error=exc)

        _write_last_activated_hash(ingress_config.ingress_activation_last_hash_path, sha256_hex)
        return ActivationResult(activated=True)


def provision_and_activate(credential, public_key, ingress_config, now=None):
    """The full POST /v1/ingress-profile transaction. B31A: reuses
    xray_provisioning.provision_and_activate_identity_selfbind, NOT
    provision_and_activate_identity - the ingress role has no separate
    POST /v1/activate step and no AWG peer to provision, so it is its own
    first-use binding authority rather than a lookup against some other
    flow's prior CONFIRMED decision (see that function's own docstring for
    the full root-cause analysis and why this is still task G's "reuse
    existing activation credential/revocation/quota discipline" - it reuses
    activations.py's own decide_and_bind/finalize_reservation primitives
    directly, never a second identity/entitlement system)."""
    return xray_provisioning.provision_and_activate_identity_selfbind(
        credential, public_key,
        ingress_config.activation_store_path, ingress_config.activation_lock_path,
        ingress_config.xray_store_path, ingress_config.xray_lock_path,
        activate_fn=lambda: activate_if_needed(ingress_config),
        now=now,
    )


def reconcile(ingress_config):
    """Idempotent recovery/startup-convergence entry point - mirrors
    xray_activation.reconcile exactly (task I's own "reload/restart
    semantics")."""
    return activate_if_needed(ingress_config)
