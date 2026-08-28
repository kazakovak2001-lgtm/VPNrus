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

If provision-peer.sh's actual behavior ever needs to change, that is a
change to provision-peer.sh (B8B1A) reviewed on its own - this module
must keep parsing whatever provision-peer.sh's committed contract says,
not the other way around.
"""
import ipaddress
import re
import subprocess

CREATED = "created"
EXISTING = "existing"

# Exit codes from provision-peer.sh's own committed contract.
_EXIT_SUCCESS = 0
_EXIT_SUBNET_EXHAUSTED = 20

_STDOUT_LINE_RE = re.compile(r"^(created|existing)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


class ProvisionError(Exception):
    """kind is one of "exhausted" / "timeout" / "internal" - the only
    three outcomes handler.py needs to distinguish for its HTTP status
    mapping (503 / 504 / 500 respectively). The human-readable message is
    for server-side logs only and must never be echoed to the HTTP
    client."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


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


def run_provision_peer(script_path, public_key, timeout_seconds):
    """Run `script_path <public_key>` and return a ProvisionOutcome, or
    raise ProvisionError. `public_key` must already be validated by the
    caller (see wgkey.is_valid_wg_public_key) - this function does not
    re-validate it, it only ever forwards it as a single argv element,
    never through a shell."""
    try:
        proc = subprocess.run(
            [script_path, public_key],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise ProvisionError("timeout", "provisioning subprocess timed out")
    except OSError as exc:
        raise ProvisionError("internal", f"failed to invoke provisioning helper: {exc}")

    if proc.returncode == _EXIT_SUBNET_EXHAUSTED:
        raise ProvisionError("exhausted", "subnet exhausted")
    if proc.returncode != _EXIT_SUCCESS:
        raise ProvisionError("internal", f"provisioning helper exited with code {proc.returncode}")

    return _parse_stdout(proc.stdout)
