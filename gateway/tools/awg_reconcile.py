#!/usr/bin/env python3
"""B47 T1 - AWG entitlement desired-state PLANNER.

Answers exactly one question: "which of the AWG peers currently in
awg0.conf belong to an entitlement that is no longer valid?" It never
touches awg0.conf, never takes .provision.lock and never runs awg/systemctl
itself - gateway/scripts/reconcile-peers.sh owns the lock and every
mutation (through lib/peer_mutations.sh, the single awg0.conf mutation
authority), and calls this planner WHILE holding .provision.lock, so the
plan can never be computed from a store snapshot older than the lock.

    reconcile-peers.sh (root, holds .provision.lock)
        awg_reconcile.py --env-file /etc/pocvpn/api.env < awg0.conf
        -> stdout: one public key per line = peers to remove

The planner receives the WHOLE awg0.conf on stdin (it never opens the file
itself) and validates its structure before anything else - see
parse_awg_config(). A file it cannot interpret unambiguously yields no plan.

Desired-state rules (activations.entitlement_state is the ONLY entitlement
predicate - status AND expiry, never status alone):

  DESIRED      key bound (pending OR confirmed) to >= 1 entitled activation,
               or the expected_public_key of >= 1 ACTIVE legacy enrollment
               token (POST /v1/peers)
  DISENTITLED  key bound only to revoked/expired activations and/or only to
               REVOKED legacy tokens
  UNKNOWN      key in awg0.conf that no store mentions at all (operator/
               manual peers, orphans of a failed provisioning attempt)

  remove = (DISENTITLED - DESIRED) & peers currently in awg0.conf

UNKNOWN peers are REPORTED ONLY, never removed: "unknown" is not evidence
of revocation. A key that is DESIRED through any one entitlement stays,
even if another entitlement binding it was revoked. Pending bindings count
as DESIRED so an in-flight /v1/activate is never undercut.

Fail closed: if any configured store is missing, unreadable, malformed, or
holds a naive/unparseable expires_at, or awg0.conf fails structural
validation (parse_awg_config), NO plan is printed and the exit code is
non-zero - reconcile-peers.sh then makes no change at all. An incomplete
or ambiguous view of entitlement or of the peer set must never drive
deletions.

Exit codes: 0 = plan printed (possibly empty); 2 = usage/config error;
3 = store or input unavailable/invalid (nothing planned).
"""
import argparse
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module  # noqa: E402
from api import config as config_module  # noqa: E402
from api import tokens as tokens_module  # noqa: E402
from api.wgkey import is_valid_wg_public_key  # noqa: E402
import migrate_peer_markers  # noqa: E402  (the existing strict awg0.conf parser)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_STORE = 3


class PlanInputError(Exception):
    """A store or awg0.conf could not be trusted - never plan from it."""


@dataclass(frozen=True)
class ReconcilePlan:
    remove: tuple  # sorted public keys to remove
    unknown: tuple  # sorted public keys present but unknown to every store (report only)
    desired_present: int  # number of current peers that are desired


def plan_peer_removals(activations_data, token_data, current_peers, now):
    """Pure. `activations_data` is a parsed activations store (or None when
    this gateway has no activation store configured), `token_data` a parsed
    legacy enrollment-token store, `current_peers` an iterable of public
    keys currently in awg0.conf, `now` a timezone-aware datetime.

    Raises PlanInputError instead of ever returning a partial plan."""
    try:
        desired = set()
        disentitled = set()
        for record in (activations_data or {}).values():
            entitled = activations_module.is_entitled(record, now)
            for device in record["bound_devices"]:
                (desired if entitled else disentitled).add(device["public_key"])
        for record in (token_data or {}).values():
            key = record["expected_public_key"]
            (desired if record["status"] == tokens_module.ACTIVE else disentitled).add(key)
    except activations_module.ActivationStoreError as exc:
        raise PlanInputError(f"activation store entry unusable: {exc}") from exc
    except (KeyError, TypeError) as exc:
        raise PlanInputError(f"store record has an unexpected shape: {exc!r}") from exc

    peers = set(current_peers)
    remove = sorted((disentitled - desired) & peers)
    unknown = sorted(peers - desired - disentitled)
    return ReconcilePlan(remove=tuple(remove), unknown=tuple(unknown), desired_present=len(peers & desired))


_LINE_NO_RE = re.compile(r"^line (\d+)")


def parse_awg_config(text):
    """B47 T1 - the peer set a removal plan may be computed from.

    Delegates ALL structural validation to
    migrate_peer_markers.parse_marked_conf (markers, section order, known
    fields only, one PublicKey + AllowedIPs per [Peer], no duplicate field
    in a block, peer block boundaries identical to mutate_remove_peer's),
    then additionally requires every PublicKey to be a canonical
    AmneziaWG/WireGuard key (api.wgkey, the API's own definition) and
    unique across peers. Returns the list of peer public keys.

    Any failure raises PlanInputError carrying at most a line number -
    never line content, which could include [Interface] PrivateKey or a
    PresharedKey."""
    if not isinstance(text, str):
        raise PlanInputError("awg0.conf content unavailable")
    try:
        _interface, peers = migrate_peer_markers.parse_marked_conf(text.splitlines())
    except migrate_peer_markers.ConfigError as exc:
        match = _LINE_NO_RE.match(str(exc))
        where = f" near line {match.group(1)}" if match else ""
        raise PlanInputError(f"awg0.conf failed structural validation{where} (details withheld)") from None
    keys = []
    for position, peer in enumerate(peers, start=1):
        if not is_valid_wg_public_key(peer["PublicKey"]):
            raise PlanInputError(f"awg0.conf peer #{position} has a non-canonical PublicKey")
        keys.append(peer["PublicKey"])
    if len(keys) != len(set(keys)):
        raise PlanInputError("awg0.conf contains a duplicate PublicKey (ambiguous peer set)")
    return keys


def load_stores(app_config):
    """Reads every store that decides AWG entitlement on this gateway,
    through the SAME read-only, shared-lock readers the API itself uses.
    Any failure -> PlanInputError (never an empty/partial dict)."""
    activations_data = None
    if app_config.activation_store_path:
        try:
            activations_data = activations_module.read_store_shared(
                app_config.activation_store_path, app_config.activation_lock_path,
            )
        except (activations_module.ActivationStoreError, OSError) as exc:
            raise PlanInputError(f"activation store unavailable: {exc}") from exc
    try:
        raw = tokens_module.read_store_shared(app_config.token_store_path, app_config.token_lock_path)
        token_data = tokens_module.parse_store(raw)
    except (tokens_module.TokenLookupError, OSError) as exc:
        raise PlanInputError(f"token store unavailable: {exc}") from exc
    return activations_data, token_data


def _parse_env_file(path):
    """Minimal KEY=VALUE parser - same shape as xray_reconcile.py's own
    helper (each gateway/tools/ CLI is deliberately standalone)."""
    result = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, _, value = stripped.partition("=")
            result[key.strip()] = value.strip()
    return result


def _parse_now(value):
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--now must include a UTC offset")
    return parsed


def _log(message):
    print(f"awg_reconcile: {message}", file=sys.stderr)


def main(argv=None, stdin=None, stdout=None):
    parser = argparse.ArgumentParser(
        prog="awg_reconcile.py",
        description="B47 T1 - plan AWG peer removals for revoked/expired entitlements (read-only)",
    )
    parser.add_argument("--env-file", required=True, help="pocvpn-api env file (e.g. /etc/pocvpn/api.env)")
    parser.add_argument("--now", default=None, help="evaluation instant, ISO 8601 with UTC offset (tests only)")
    args = parser.parse_args(argv)
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout

    try:
        now = _parse_now(args.now)
        env = dict(os.environ)
        env.update(_parse_env_file(args.env_file))
        app_config = config_module.load_config(env=env)
    except (ValueError, OSError, config_module.ConfigError) as exc:
        _log(f"error: config: {exc} - nothing planned")
        return EXIT_CONFIG

    try:
        try:
            config_text = stdin.read()
        except (OSError, UnicodeDecodeError):
            raise PlanInputError("awg0.conf content unreadable") from None
        peers = parse_awg_config(config_text)
        activations_data, token_data = load_stores(app_config)
        plan = plan_peer_removals(activations_data, token_data, peers, now)
    except PlanInputError as exc:
        _log(f"error: {exc} - FAIL CLOSED, nothing planned, no peer will be removed")
        return EXIT_STORE

    for key in plan.unknown:
        _log(f"warning: unknown peer {key[:8]}... not referenced by any entitlement store - reported only, NOT removed")
    _log(
        f"plan: {len(peers)} peer(s) present, {plan.desired_present} entitled, "
        f"{len(plan.remove)} to remove (revoked/expired), {len(plan.unknown)} unknown (report only)"
    )
    for key in plan.remove:
        stdout.write(key + "\n")
    stdout.flush()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
