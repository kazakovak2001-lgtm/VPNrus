"""B26 (task G) - the operator-safe apply/revoke boundary for an EXIT's
ingress->exit relay identities: a small, durable JSON file naming the
[xray_config_renderer.RenderedClient] entries an EXIT authorizes
unconditionally via render_server_config's own `static_clients` parameter
(see that function's own B25 docs - NEVER cross-referenced against
activations_data/revocation; a genuinely separate infra-level trust domain
from ordinary per-user device activations).

This module is the ONLY writer (via gateway/tools/apply_relay_upstream_identity.py,
an operator CLI - never pocvpn-api itself, which only reads it at render
time through xray_activation.py's own _render_candidate). Applying a new/
changed entry here does NOT itself reload the live Xray service - that
remains the separate, already-existing gateway/tools/xray_reconcile.py step
(reusing the SAME render -> `xray run -test` -> stage -> atomic replace ->
reload -> rollback pipeline xray_reload.py already implements for every
other config change on this EXIT - task F/G's own "use the existing
gateway operational conventions").
"""
import json
import os
import re
import tempfile

from . import xray_config_renderer

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ACTIVATION_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class RelayIdentityStoreError(Exception):
    """The static-clients file exists but is not valid/well-formed - the
    caller (xray_activation._render_candidate) must let this abort the
    render, never silently treat a corrupted file as empty (that would
    silently revoke every relay identity on the next activation)."""


def _validate_entry(entry):
    if not isinstance(entry, dict) or set(entry.keys()) != {"activation_id", "device_public_key", "vless_uuid"}:
        raise RelayIdentityStoreError("relay identity entry does not have exactly the required fields")
    activation_id = entry["activation_id"]
    device_public_key = entry["device_public_key"]
    vless_uuid = entry["vless_uuid"]
    if not isinstance(activation_id, str) or not _ACTIVATION_ID_RE.match(activation_id):
        raise RelayIdentityStoreError(f"relay identity has an invalid activation_id: {activation_id!r}")
    if not isinstance(device_public_key, str) or not device_public_key:
        raise RelayIdentityStoreError("relay identity has a blank device_public_key")
    if not isinstance(vless_uuid, str) or not _UUID_RE.match(vless_uuid):
        raise RelayIdentityStoreError(f"relay identity has a malformed vless_uuid: {vless_uuid!r}")


def load_static_clients(path):
    """Returns a tuple of [xray_config_renderer.RenderedClient], in the
    file's own order (deterministic - render_server_config's own docs
    already require deterministic output). A MISSING file means "no relay
    identity has been applied yet" - () - never an error (this is the
    normal state before the first gateway/tools/apply_relay_upstream_identity.py
    run). A file that EXISTS but is malformed/corrupted raises
    [RelayIdentityStoreError] - fails closed rather than silently rendering
    with fewer authorized relays than an operator believes are configured."""
    if not path:
        return ()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return ()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RelayIdentityStoreError(f"static relay clients file is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise RelayIdentityStoreError("static relay clients file root must be a JSON array")

    seen_activation_ids = set()
    clients = []
    for entry in data:
        _validate_entry(entry)
        if entry["activation_id"] in seen_activation_ids:
            raise RelayIdentityStoreError(f"duplicate activation_id in static relay clients file: {entry['activation_id']!r}")
        seen_activation_ids.add(entry["activation_id"])
        clients.append(
            xray_config_renderer.RenderedClient(
                activation_id=entry["activation_id"],
                device_public_key=entry["device_public_key"],
                vless_uuid=entry["vless_uuid"],
            )
        )
    return tuple(clients)


def _write_entries(path, entries):
    """Atomic write, restrictive 0600 (a vless_uuid is exactly as secret as
    any other client's - never world-readable), same mkstemp/replace
    discipline as activations._atomic_write_store."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    canonical = sorted(entries, key=lambda e: e["activation_id"])
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".relay-identities.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(canonical, handle, indent=2, sort_keys=True)
            handle.write("\n")
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


def upsert(path, activation_id, device_public_key, vless_uuid):
    """Idempotent: applying the SAME (activation_id, device_public_key,
    vless_uuid) twice leaves the file byte-for-byte unchanged (task K's
    "relay identity add/remove is idempotent"). A different vless_uuid/key
    under an EXISTING activation_id REPLACES that entry (a deliberate
    rotation), never appends a duplicate."""
    entry = {"activation_id": activation_id, "device_public_key": device_public_key, "vless_uuid": vless_uuid}
    _validate_entry(entry)
    existing = load_static_clients(path)
    remaining = [
        {"activation_id": c.activation_id, "device_public_key": c.device_public_key, "vless_uuid": c.vless_uuid}
        for c in existing
        if c.activation_id != activation_id
    ]
    remaining.append(entry)
    _write_entries(path, remaining)


def remove(path, activation_id):
    """Idempotent: removing an activation_id that is not present leaves the
    file unchanged (still a success - task K's own "idempotent" bar)."""
    existing = load_static_clients(path)
    remaining = [
        {"activation_id": c.activation_id, "device_public_key": c.device_public_key, "vless_uuid": c.vless_uuid}
        for c in existing
        if c.activation_id != activation_id
    ]
    _write_entries(path, remaining)
