"""The ONE gateway mutation boundary this API is allowed to cross.

Invokes gateway/scripts/provision-peer.sh as an external subprocess and
treats its stdout + exit code as an opaque, strictly-parsed machine
protocol (see gateway/scripts/provision-peer.sh's own header comment for
the authoritative contract this module implements against).

This module NEVER:
  - parses or mutates awg0.conf
  - allocates a tunnel IP itself
  - acquires .provision.lock (provision-peer.sh owns that, exactly once,
    entirely inside the subprocess)
  - receives the bearer token or any caller-supplied label - the only
    argument ever passed is the validated public key
  - builds a shell command string, or passes shell=True - argv is always
    a plain list, so nothing here is ever subject to shell word-splitting
    or expansion regardless of what a public key or path contains

If provision-peer.sh's actual behavior ever needs to change, that is a
change to provision-peer.sh (B8B1A) reviewed on its own - this module
must keep parsing whatever provision-peer.sh's committed contract says,
not the other way around.

B8B1C2: optional sudo argv. `sudo_path` (see config.py's AppConfig) is
None/empty by default, which reproduces B8B1B/C1's exact direct-
invocation argv - `[script_path, public_key]`. When a caller passes a
non-empty `sudo_path`, argv becomes `[sudo_path, "-n", script_path,
public_key]` - always `-n` (non-interactive: sudo must fail immediately
rather than ever block this HTTP request on a password prompt it can
never satisfy). This is still just an argv list handed to
subprocess.run(shell=False) - the sudo binary itself, not this process,
is what actually enforces the privilege boundary (see
gateway/privileged/). Both script_path and sudo_path (when given) are
independently required to be absolute here, on top of config.py already
enforcing that at startup - defense in depth against a future caller of
run_provision_peer() that bypasses load_config().
"""
import ipaddress
import os
import re
import subprocess

CREATED = "created"
EXISTING = "existing"

# Exit codes from provision-peer.sh's own committed contract.
_EXIT_SUCCESS = 0
_EXIT_SUBNET_EXHAUSTED = 20

_STDOUT_LINE_RE = re.compile(r"^(created|existing)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")

_SUDO_NONINTERACTIVE_FLAG = "-n"

# Diagnostic-only stderr sanitization (observability boundary - see
# ProvisionError.stderr's own docs). Two DISTINCT patterns, not one
# open-ended "long run" heuristic - the original single-regex version
# (`[A-Za-z0-9+/_-]{20,}={0,2}`) allowed '/' in its character class, which
# made it swallow an entire filesystem path (e.g.
# "/etc/amnezia/amneziawg/awg0.conf", every character of which except '.'
# is in that class) as one giant "token", destroying exactly the
# diagnostic value this field exists for. Fixed by anchoring the two REAL
# secret shapes this process can ever produce to their EXACT lengths
# (never "20+"), and keeping '/' ONLY in the one pattern that genuinely
# needs it for real base64 key data:
#
#   - WireGuard/AmneziaWG public or private key: 32 raw bytes, standard
#     base64 -> EXACTLY 44 chars, always ending in exactly one '=' pad
#     character. A real filesystem path essentially never ends in a bare
#     '=' immediately followed by a non-base64 character, so anchoring to
#     this exact shape is what makes it safe to allow '/' here at all.
#   - Any other genuinely token/key-like value (activation credentials -
#     secrets.token_urlsafe(32) -> EXACTLY 43 URL-safe-base64 chars, never
#     containing '/' or '.' - and any future similarly-shaped secret this
#     process was never meant to log). This pattern deliberately EXCLUDES
#     '/' and '.' from its character class: a filesystem path is
#     fundamentally '/'-and-'.'-structured, so a charset that can never
#     contain either can never absorb one, no matter how long the path is.
#     This is what fixes the awg0.conf false positive above.
_WG_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
_GENERIC_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])")
_BEARER_HEADER_RE = re.compile(r"Bearer\s+\S+", re.IGNORECASE)

_MAX_DIAGNOSTIC_STDERR_CHARS = 2000


def _sanitize_diagnostic_stderr(stderr):
    """Best-effort redaction of a provisioning subprocess's stderr before it
    is ever attached to a ProvisionError for logging - see the module-level
    regexes' own docs for exactly what shape is redacted. Never raises;
    empty/None input yields "". Output is single-line (embedded newlines
    collapsed) and length-bounded, since this is a log field, not a
    diagnostic dump."""
    if not stderr:
        return ""
    sanitized = _BEARER_HEADER_RE.sub("Bearer [REDACTED]", stderr)
    sanitized = _WG_KEY_RE.sub("[REDACTED]", sanitized)
    sanitized = _GENERIC_TOKEN_RE.sub("[REDACTED]", sanitized)
    sanitized = " ".join(sanitized.split())
    if len(sanitized) > _MAX_DIAGNOSTIC_STDERR_CHARS:
        sanitized = sanitized[:_MAX_DIAGNOSTIC_STDERR_CHARS] + "...[truncated]"
    return sanitized


class ProvisionError(Exception):
    """kind is one of "exhausted" / "timeout" / "internal" - the only
    three outcomes handler.py needs to distinguish for its HTTP status
    mapping (503 / 504 / 500 respectively). The human-readable message is
    for server-side logs only and must never be echoed to the HTTP
    client.

    exit_code/stderr are diagnostic-only, populated ONLY for the
    non-zero-exit-code branch of run_provision_peer (the only case where a
    real subprocess actually ran and produced its own diagnostics) - both
    default to None/"" for every other raise site (OSError, timeout,
    malformed stdout, path validation), where there is nothing meaningful
    to attach. `stderr` has already been through
    _sanitize_diagnostic_stderr by the time it reaches here - this class
    never re-sanitizes, so any new raise site that wants to attach stderr
    MUST sanitize it first."""

    def __init__(self, kind, message, exit_code=None, stderr=""):
        super().__init__(message)
        self.kind = kind
        self.exit_code = exit_code
        self.stderr = stderr


class ProvisionOutcome:
    __slots__ = ("state", "ip")

    def __init__(self, state, ip):
        self.state = state
        self.ip = ip


def _parse_stdout(stdout):
    lines = stdout.split("\n")
    # A well-formed "created\t10.x.x.x\n" splits on "\n" into exactly
    # [line, ""] (the trailing empty string after the final newline).
    # Anything else - no trailing newline collapsed to one element, or
    # more elements than that - means extra output the contract forbids.
    if len(lines) == 2 and lines[1] == "":
        line = lines[0]
    elif len(lines) == 1:
        line = lines[0]
    else:
        raise ProvisionError("internal", "provisioning helper produced unexpected extra stdout")

    match = _STDOUT_LINE_RE.match(line)
    if not match:
        raise ProvisionError("internal", "provisioning helper produced malformed stdout")

    state, ip = match.group(1), match.group(2)
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ProvisionError("internal", "provisioning helper returned an invalid IPv4 address")

    return ProvisionOutcome(state=state, ip=ip)


def _require_absolute_path(path, label):
    if not os.path.isabs(path):
        raise ProvisionError("internal", f"{label} must be an absolute path, got {path!r}")


def _build_argv(script_path, public_key, sudo_path):
    _require_absolute_path(script_path, "provisioning script path")
    if sudo_path:
        _require_absolute_path(sudo_path, "sudo path")
        return [sudo_path, _SUDO_NONINTERACTIVE_FLAG, script_path, public_key]
    return [script_path, public_key]


def run_provision_peer(script_path, public_key, timeout_seconds, sudo_path=None):
    """Run `script_path <public_key>` (optionally through `sudo -n`, when
    `sudo_path` is given - see module docstring) and return a
    ProvisionOutcome, or raise ProvisionError. `public_key` must already be
    validated by the caller (see wgkey.is_valid_wg_public_key) - this
    function does not re-validate it, it only ever forwards it as a single
    argv element, never through a shell. No bearer token, label, or other
    request-derived value is ever part of argv - the only HTTP-derived
    element is `public_key` itself."""
    argv = _build_argv(script_path, public_key, sudo_path)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise ProvisionError("timeout", "provisioning subprocess timed out")
    except OSError as exc:
        raise ProvisionError("internal", f"failed to invoke provisioning helper: {exc}")

    if proc.returncode == _EXIT_SUBNET_EXHAUSTED:
        raise ProvisionError("exhausted", "subnet exhausted")
    if proc.returncode != _EXIT_SUCCESS:
        sanitized_stderr = _sanitize_diagnostic_stderr(proc.stderr)
        raise ProvisionError(
            "internal",
            f"provisioning helper exited with code {proc.returncode}",
            exit_code=proc.returncode,
            stderr=sanitized_stderr,
        )

    return _parse_stdout(proc.stdout)
