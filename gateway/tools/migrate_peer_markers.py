#!/usr/bin/env python3
"""ORACLE-MIGRATION-DESIGN-1: operator CLI prototype for migrating an
already-live awg0.conf (no `# --- PEERS BEGIN/END ---` markers) into the
marker-bearing shape B8B1's `gateway/lib/peer_mutations.sh` requires -
WITHOUT touching PrivateKey, Address, ListenPort, any AWG protocol
parameter, or any existing peer's PublicKey/AllowedIPs.

DESIGN-SLICE STATUS: this is a prototype, tested only against local
sanitized fixtures (see gateway/tools/tests/test_migrate_peer_markers.py
and gateway/tools/tests/fixtures/). It has never been run against a real
awg0.conf, local or remote, and per ORACLE-MIGRATION-DESIGN-1 it must not
be until a human has reviewed this design and a separate live-migration
slice implements the full transaction (precondition check, lock, backup,
atomic replace, post-write verify, rollback) - this file provides only the
`migrate`/`verify`/`diff` primitives that transaction would call, not the
transaction itself. Corrected in the ORACLE-MIGRATION-DESIGN-1 hardening
review:

  - This migration changes ONLY comment markers - the live AWG interface
    never needs to consume it. The future transaction must NOT run
    `systemctl reload` (or any equivalent) as part of a marker-only
    migration, and must NOT require a fresh handshake/traffic-counter
    increase as a success criterion for it. Post-write verification is
    file-level only: re-read the replaced file, re-run `verify`/`diff`
    against it, confirm `awg show awg0 peers` (read-only) still lists the
    same peer set it did before the write, and confirm the `awg0`
    interface is still present - none of that requires or implies a
    reload. Reload/convergence is real, and gets exercised for the first
    time, only when B8B1 performs an actual peer *mutation* later (see
    gateway/lib/peer_mutations.sh's own converge_live_state, unchanged).

  - The future transaction must serialize through the SAME lock
    provision-peer.sh already uses - `/etc/amnezia/amneziawg/
    .provision.lock` (see gateway/scripts/provision-peer.sh) - held
    (LOCK_EX) across the entire read/migrate/verify/human-approval/
    backup/replace/post-write-verify/optional-rollback sequence. There
    must be exactly one serialization authority for all awg0.conf
    mutations; a second, independent migration-specific lock was
    considered and rejected for that reason.

  - Secure candidate/backup file rules the future transaction must follow
    (NOT implemented by this file - `cmd_migrate` here writes to whatever
    path the caller supplies with a plain `open(..., "w")`, appropriate
    for local testing/fixtures only):
      * candidate and backup on the SAME filesystem as awg0.conf (so the
        eventual replace can be a single atomic rename, never a cross-
        filesystem copy+delete)
      * in a root-only directory, root:root ownership
      * mode 0600 from the moment of creation - via `os.open(path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)` or
        `tempfile.mkstemp` in the target directory, NEVER a permissive
        `open()` followed by a later `chmod` (a window where the file is
        briefly more-than-root-readable must never exist); `O_EXCL` also
        makes symlink/path-race attacks fail closed instead of silently
        following an existing link
      * NEVER an ordinary world-writable /tmp
      * NEVER printed, copied off-host, committed, or logged
      * backup lifecycle: retained only through post-write verification;
        removed by an explicit operator step after human confirmation of
        a successful migration - not automatically, and not retained
        indefinitely (an indefinitely-retained root-owned copy of the
        PrivateKey is exposure without benefit once the migration is
        confirmed converged)

Three subcommands, each read-only with respect to the input:

    migrate_peer_markers.py migrate <input-conf> <output-conf>
        Parses <input-conf>, rejects it (exit 1, clear stderr reason) if
        it is malformed or already (partially) marked, and otherwise
        writes a NEW file at <output-conf> - the input is never modified
        in place, and the two are required to be different paths.

    migrate_peer_markers.py verify <original-conf> <migrated-conf>
        Re-parses both files and checks TWO independent things, both
        required for success:

        1. Field-level semantic equivalence: Address/ListenPort/every AWG
           protocol parameter/peer count/every peer's PublicKey+AllowedIPs
           (+PresharedKey if present) match, and PrivateKey/PresharedKey
           values are unchanged - compared only as SHA-256 hashes, never
           printed. Prints `PRIVATE_KEY_UNCHANGED=YES` and
           `SEMANTIC_EQUIVALENCE=YES` on success.

        2. Byte-equivalence-except-markers - the AUTHORITATIVE, strongest
           check: with the exact inserted marker lines removed from the
           migrated file, its text must equal the original's text BYTE
           FOR BYTE (including whitespace, comments, field ordering,
           blank lines, and trailing-newline behavior). Field-level
           equivalence alone is not enough - a value-preserving edit that
           changes only formatting (extra whitespace around `=`, a
           reordered field, an edited comment) leaves every field's
           parsed VALUE unchanged and so would pass check 1, but is
           exactly the kind of unreviewed change this migration must
           never make silently. Prints `BYTE_EQUIVALENCE_EXCEPT_MARKERS=
           YES` on success. On failure, only a bare `=NO` plus a
           non-content reason is printed - never the original or
           candidate content itself, so a diagnostic run can't become a
           leak.

        A specific mismatch reason (never a key value, never file
        content) is printed and the command exits 1 on any difference in
        either check.

    migrate_peer_markers.py diff <original-conf> <migrated-conf>
        Prints a redacted unified diff between the two files - any line
        content that could contain a secret value (a `PrivateKey =` line
        on the [Interface] side, or a `PresharedKey =` line on either
        side of a [Peer] block) is replaced with a FIXED placeholder
        before the diff is computed, so neither value can appear in the
        diff output even transiently, and the diff can never reveal
        whether two secret values are equal by displaying them adjacent
        to each other. Exits 1 (STOP) if the diff contains anything
        beyond the two expected marker-line additions.

        IMPORTANT: because both sides redact to the identical fixed
        placeholder, `diff` CANNOT detect a changed PrivateKey or
        PresharedKey - a real change and no change look identical after
        redaction, by design (the alternative would mean comparing the
        raw values to decide what to show, which is exactly the exposure
        this must avoid). Redaction is for SAFE DISPLAY only - it is NOT
        an integrity proof. The integrity proof is `verify`'s
        `BYTE_EQUIVALENCE_EXCEPT_MARKERS=YES` (plus its semantic checks,
        as defense-in-depth). The future live transaction must require
        BOTH `diff` (`DIFF_POLICY_OK`) AND `verify`
        (`BYTE_EQUIVALENCE_EXCEPT_MARKERS=YES` +
        `SEMANTIC_EQUIVALENCE=YES` + `PRIVATE_KEY_UNCHANGED=YES`) to pass
        before the human approval gate - neither alone is sufficient.

Secret handling invariant, honored by every subcommand: PrivateKey and
PresharedKey values are read into memory only to be written out unchanged
(migrate) or hashed (verify), and are NEVER passed to print/log/stderr in
this file. `diff` never even parses them - it redacts at the raw-line
level before any comparison, so a bug in the parser can't leak either
value through that path either.
"""
import argparse
import difflib
import hashlib
import sys

_BEGIN_MARKER = "# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)"
_END_MARKER = "# --- PEERS END ---"
_BEGIN_PREFIX = "# --- PEERS BEGIN ---"
_END_PREFIX = "# --- PEERS END ---"

_INTERFACE_HEADER = "[Interface]"
_PEER_HEADER = "[Peer]"

# Fields lib/peer_mutations.sh and the AmneziaWG protocol distinguish -
# only PrivateKey is secret; every other Interface field is plain
# operational metadata already visible to anyone who can `ip addr show`
# or capture a handshake.
_INTERFACE_FIELDS = (
    "PrivateKey", "Address", "ListenPort",
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "RandomTrailers", "DisableCookies",
)
# PublicKey/AllowedIPs are required on every peer; PresharedKey is
# optional (most peers won't have one) but must be recognized as a valid
# field when present - it is a secret value (like PrivateKey) and is
# handled with the same never-print discipline throughout this file.
_PEER_REQUIRED_FIELDS = ("PublicKey", "AllowedIPs")
_PEER_OPTIONAL_FIELDS = ("PresharedKey",)
_PEER_FIELDS = _PEER_REQUIRED_FIELDS + _PEER_OPTIONAL_FIELDS


class ConfigError(Exception):
    """Malformed or already-migrated input - caller must reject, never
    guess or repair."""


def _split_kv(line):
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    return key.strip(), value.strip()


def parse_conf(lines):
    """Parse a wg-quick/awg-quick style config into a structured form.
    `lines` is the file's lines WITHOUT trailing newlines (as from
    str.splitlines()). Raises ConfigError on anything this migration
    tool is not prepared to safely handle - it never guesses at intent.

    Returns (interface_fields: dict, peers: list[dict], first_peer_line:
    int|None, last_content_line: int) - the two line indices are into the
    ORIGINAL `lines` list and are what the migrator uses to place the
    marker insertions; parse_conf itself never mutates anything.
    """
    interface_seen = 0
    interface_fields = {}
    peers = []
    current_peer = None
    first_peer_line = None
    last_content_line = -1
    section = None

    for idx, raw_line in enumerate(lines):
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.startswith(_BEGIN_PREFIX) or stripped.startswith(_END_PREFIX):
            raise ConfigError(
                f"line {idx + 1}: this file already contains a peer marker "
                "line - refusing to migrate an already-(partially-)marked "
                "config. If markers exist on only one side (BEGIN without "
                "END or vice versa), that is exactly the 'reversed/partial "
                "markers' case this tool refuses to guess how to repair."
            )

        if not stripped or stripped.startswith("#"):
            continue

        if stripped == _INTERFACE_HEADER:
            interface_seen += 1
            if interface_seen > 1:
                raise ConfigError(f"line {idx + 1}: more than one [Interface] section")
            if peers or current_peer is not None:
                raise ConfigError(f"line {idx + 1}: [Interface] appears after a [Peer] section")
            section = "interface"
            last_content_line = idx
            continue

        if stripped == _PEER_HEADER:
            if interface_seen != 1:
                raise ConfigError(f"line {idx + 1}: [Peer] section before any [Interface] section")
            if current_peer is not None:
                _validate_peer(current_peer, idx)
                peers.append(current_peer)
            current_peer = {}
            if first_peer_line is None:
                first_peer_line = idx
            section = "peer"
            last_content_line = idx
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            raise ConfigError(f"line {idx + 1}: unrecognized section header {stripped!r}")

        kv = _split_kv(stripped)
        if kv is None:
            raise ConfigError(f"line {idx + 1}: expected a key = value line, got {stripped!r}")
        key, value = kv

        if section == "interface":
            if key not in _INTERFACE_FIELDS:
                raise ConfigError(f"line {idx + 1}: unrecognized [Interface] field {key!r}")
            if key in interface_fields:
                raise ConfigError(f"line {idx + 1}: duplicate [Interface] field {key!r}")
            interface_fields[key] = value
            last_content_line = idx
        elif section == "peer":
            if key not in _PEER_FIELDS:
                raise ConfigError(f"line {idx + 1}: unrecognized [Peer] field {key!r}")
            if key in current_peer:
                raise ConfigError(f"line {idx + 1}: duplicate [Peer] field {key!r} in one peer block")
            current_peer[key] = value
            last_content_line = idx
        else:
            raise ConfigError(f"line {idx + 1}: content outside any section: {stripped!r}")

    if current_peer is not None:
        _validate_peer(current_peer, len(lines))
        peers.append(current_peer)

    if interface_seen != 1:
        raise ConfigError("no [Interface] section found")
    if "PrivateKey" not in interface_fields:
        raise ConfigError("[Interface] section has no PrivateKey field")

    return interface_fields, peers, first_peer_line, last_content_line


def _validate_peer(peer, end_idx):
    missing = [f for f in _PEER_REQUIRED_FIELDS if f not in peer]
    if missing:
        raise ConfigError(
            f"[Peer] block ending near line {end_idx + 1} is missing required "
            f"field(s): {', '.join(missing)}"
        )


def migrate_lines(lines):
    """Pure function: given the ORIGINAL file's lines (no trailing
    newlines), return the MIGRATED file's lines. Raises ConfigError if the
    input cannot be safely migrated. Never mutates `lines` in place -
    returns a new list."""
    _interface_fields, peers, first_peer_line, last_content_line = parse_conf(lines)

    out = list(lines)
    if first_peer_line is not None:
        # BEGIN goes immediately before the first [Peer] line - the
        # existing blank line (if any) that already precedes it is left
        # exactly where it is, so nothing already there is reordered.
        out.insert(first_peer_line, _BEGIN_MARKER)
        # last_content_line was computed against the ORIGINAL indices;
        # inserting BEGIN shifted everything from first_peer_line onward
        # by one.
        out.insert(last_content_line + 2, _END_MARKER)
    else:
        # Zero-peer case: both markers go together, immediately after the
        # last Interface content line - matches
        # gateway/config/awg0.conf.example's own zero-peer shape exactly
        # (BEGIN immediately followed by END, no blank line between).
        insert_at = last_content_line + 1
        out.insert(insert_at, _BEGIN_MARKER)
        out.insert(insert_at + 1, _END_MARKER)
    return out


def _read_text_preserving_newline(path):
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    trailing_newline = text.endswith("\n")
    lines = text.splitlines()
    return lines, trailing_newline


def _write_text_preserving_newline(path, lines, trailing_newline):
    text = "\n".join(lines)
    if trailing_newline:
        text += "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def cmd_migrate(args):
    if args.input == args.output:
        print("migrate_peer_markers: error: input and output must be different paths - no in-place editing", file=sys.stderr)
        return 1
    try:
        lines, trailing_newline = _read_text_preserving_newline(args.input)
        migrated = migrate_lines(lines)
    except ConfigError as exc:
        print(f"migrate_peer_markers: refusing to migrate: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"migrate_peer_markers: error reading {args.input}: {exc}", file=sys.stderr)
        return 1

    try:
        _write_text_preserving_newline(args.output, migrated, trailing_newline)
    except OSError as exc:
        print(f"migrate_peer_markers: error writing {args.output}: {exc}", file=sys.stderr)
        return 1

    print(f"MIGRATION_CANDIDATE_WRITTEN={args.output}")
    return 0


def _byte_equivalence_except_markers(orig_lines, orig_trailing_nl, mig_lines, mig_trailing_nl):
    """The AUTHORITATIVE integrity check - see module docstring. Returns
    True/False only; NEVER returns or logs the compared content, so a
    caller can safely report failure without any risk of echoing file
    content (secret or not - even non-secret content must not leak
    through what is meant to be a boolean gate)."""
    mig_no_markers = [
        line for line in mig_lines
        if line != _BEGIN_MARKER and line != _END_MARKER
    ]
    orig_text = "\n".join(orig_lines) + ("\n" if orig_trailing_nl else "")
    mig_text = "\n".join(mig_no_markers) + ("\n" if mig_trailing_nl else "")
    return orig_text == mig_text


def cmd_verify(args):
    try:
        orig_lines, orig_trailing_nl = _read_text_preserving_newline(args.original)
        mig_lines, mig_trailing_nl = _read_text_preserving_newline(args.migrated)
    except OSError as exc:
        print(f"migrate_peer_markers: error reading input: {exc}", file=sys.stderr)
        return 1

    try:
        orig_if, orig_peers, _, _ = parse_conf(orig_lines)
    except ConfigError as exc:
        print(f"migrate_peer_markers: original config does not parse: {exc}", file=sys.stderr)
        return 1

    # The migrated file DOES contain marker lines by design - parse_conf
    # rejects any marker line unconditionally (see parse_conf), so parsing
    # the migrated output directly would always fail. Strip marker lines
    # first (structurally, by exact-text match only) before reparsing -
    # this is the one place `verify` treats them specially, and it never
    # touches any other line while doing so.
    mig_lines_no_markers = [
        line for line in mig_lines
        if line.strip() != _BEGIN_MARKER and line.strip() != _END_MARKER
    ]
    marker_lines_removed = len(mig_lines) - len(mig_lines_no_markers)
    try:
        mig_if, mig_peers, _, _ = parse_conf(mig_lines_no_markers)
    except ConfigError as exc:
        print(f"migrate_peer_markers: migrated config does not parse after stripping markers: {exc}", file=sys.stderr)
        return 1

    failures = []

    if marker_lines_removed not in (1, 2):
        failures.append(f"expected exactly 1 or 2 marker lines (1 if zero peers, else 2), found {marker_lines_removed}")

    orig_priv = orig_if.get("PrivateKey", "")
    mig_priv = mig_if.get("PrivateKey", "")
    orig_priv_hash = hashlib.sha256(orig_priv.encode("utf-8")).hexdigest()
    mig_priv_hash = hashlib.sha256(mig_priv.encode("utf-8")).hexdigest()
    private_key_unchanged = orig_priv_hash == mig_priv_hash
    if not private_key_unchanged:
        failures.append("PrivateKey hash mismatch - PRIVATE_KEY_UNCHANGED=NO")

    for field in _INTERFACE_FIELDS:
        if field == "PrivateKey":
            continue
        if orig_if.get(field) != mig_if.get(field):
            failures.append(
                f"[Interface] field {field!r} changed: present_before={field in orig_if} "
                f"present_after={field in mig_if} equal={orig_if.get(field) == mig_if.get(field)}"
            )

    if len(orig_peers) != len(mig_peers):
        failures.append(f"peer count changed: {len(orig_peers)} -> {len(mig_peers)}")
    else:
        for i, (op, mp) in enumerate(zip(orig_peers, mig_peers)):
            if op != mp:
                # Deliberately does not say WHICH field differs when
                # PresharedKey could be involved - "changed" is enough
                # detail without risking a value ever entering this
                # message in a future edit.
                failures.append(f"peer #{i} changed (one or more of PublicKey/AllowedIPs/PresharedKey no longer match)")

    byte_equivalent = _byte_equivalence_except_markers(orig_lines, orig_trailing_nl, mig_lines, mig_trailing_nl)
    if not byte_equivalent:
        # No content, no line numbers, no hint of WHAT differs - see
        # _byte_equivalence_except_markers's own docstring for why. A
        # human comparing the two files directly (never through this
        # tool's stdout) is how a real failure here gets diagnosed.
        failures.append("byte content differs beyond the two marker lines - BYTE_EQUIVALENCE_EXCEPT_MARKERS=NO")

    if failures:
        print("SEMANTIC_EQUIVALENCE=NO", file=sys.stderr)
        print(f"BYTE_EQUIVALENCE_EXCEPT_MARKERS={'YES' if byte_equivalent else 'NO'}", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("PRIVATE_KEY_UNCHANGED=YES")
    print("SEMANTIC_EQUIVALENCE=YES")
    print("BYTE_EQUIVALENCE_EXCEPT_MARKERS=YES")
    return 0


_REDACTED_FIELDS = ("PrivateKey", "PresharedKey")


def _redact_secret_line(line):
    stripped = line.strip()
    kv = _split_kv(stripped)
    if kv and kv[0] in _REDACTED_FIELDS:
        return f"{kv[0]} = <REDACTED>"
    return line


def cmd_diff(args):
    try:
        orig_lines, _ = _read_text_preserving_newline(args.original)
        mig_lines, _ = _read_text_preserving_newline(args.migrated)
    except OSError as exc:
        print(f"migrate_peer_markers: error reading input: {exc}", file=sys.stderr)
        return 1

    # Redact at the raw-line level, BEFORE difflib ever sees the content -
    # neither secret value can reach the diff output through any code
    # path below this point, including a future refactor of this
    # function, because both have already been replaced in the input
    # lists. Redacting to the SAME fixed placeholder regardless of the
    # actual value also means the diff can never reveal whether two
    # secret values are equal - see module docstring.
    orig_redacted = [_redact_secret_line(l) for l in orig_lines]
    mig_redacted = [_redact_secret_line(l) for l in mig_lines]

    diff_lines = list(difflib.unified_diff(
        orig_redacted, mig_redacted,
        fromfile=args.original, tofile=args.migrated, lineterm="",
    ))
    for line in diff_lines:
        print(line)

    additions = [l for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
    removals = [l for l in diff_lines if l.startswith("-") and not l.startswith("---")]
    unexpected_additions = [l for l in additions if l[1:].strip() not in (_BEGIN_MARKER, _END_MARKER)]

    if removals or unexpected_additions:
        print(
            "DIFF_POLICY_VIOLATION: migration must STOP - this diff contains changes "
            "beyond the two expected marker-line additions "
            f"(removals={len(removals)}, unexpected_additions={len(unexpected_additions)})",
            file=sys.stderr,
        )
        return 1

    print(f"DIFF_POLICY_OK: only {len(additions)} marker-line addition(s), 0 removals, 0 other changes")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="migrate_peer_markers.py",
        description="ORACLE-MIGRATION-DESIGN-1 prototype: peer-marker migration for an already-live awg0.conf",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_migrate = sub.add_parser("migrate", help="produce a migrated candidate at a NEW path")
    p_migrate.add_argument("input")
    p_migrate.add_argument("output")

    p_verify = sub.add_parser("verify", help="prove original and migrated are semantically equivalent")
    p_verify.add_argument("original")
    p_verify.add_argument("migrated")

    p_diff = sub.add_parser("diff", help="print a PrivateKey-redacted diff, enforcing the markers-only policy")
    p_diff.add_argument("original")
    p_diff.add_argument("migrated")

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    dispatch = {"migrate": cmd_migrate, "verify": cmd_verify, "diff": cmd_diff}
    return dispatch[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
