"""B8K2A - the ONE gateway mutation boundary provision_and_activate is
allowed to cross for the Xray activation pipeline. Invokes
gateway/privileged/nova-xray-reload (optionally via `sudo -n`) as an
external subprocess and treats its stdout/exit code as an opaque, strictly
parsed machine protocol - see gateway/scripts/xray-activate.sh's own
header comment for the authoritative contract this module implements
against. Mirrors gateway/api/provision.py's own shape and invariants
deliberately (same never-shell=True, never-a-caller-controlled-path
discipline) - see that module's docstring for the parts not repeated here.

This module NEVER:
  - reads or holds the REALITY private key (the caller renders/stages the
    candidate config BEFORE calling this module - see xray_activation.py)
  - builds a shell command string, or passes shell=True
  - accepts a caller-supplied wrapper path override at the argv-shape
    level beyond what AppConfig already validated at startup (see
    config.py's own absolute-path check)
"""
import os
import re
import subprocess

ACTIVATED = "activated"

# Exit codes from xray-activate.sh's own committed contract (see that
# file's header comment).
_EXIT_SUCCESS = 0
_EXIT_USAGE = 20
_EXIT_STAGING_MISSING = 21
_EXIT_VALIDATION_FAILED = 22
_EXIT_ACTIVATION_FAILED_ROLLED_BACK = 23
_EXIT_ACTIVATION_FAILED_ROLLBACK_ALSO_FAILED = 24

_SUDO_NONINTERACTIVE_FLAG = "-n"

_STDOUT_LINE_RE = re.compile(r"^activated\t([0-9a-f]{64})$")


class XrayReloadError(Exception):
    """kind is one of:
      "validation_failed"   - candidate config rejected by `xray run -test`;
                               live config/service were NOT touched.
      "activation_failed"   - candidate validated but did not converge to
                               an active service; the wrapper attempted a
                               best-effort rollback to the previous config
                               (kind carries whether that rollback itself
                               succeeded - see rollback_succeeded).
      "timeout" / "internal" - same meaning as provision.ProvisionError.
    The human-readable message is for server-side logs only."""

    def __init__(self, kind, message, rollback_succeeded=None):
        super().__init__(message)
        self.kind = kind
        self.rollback_succeeded = rollback_succeeded


class XrayReloadOutcome:
    __slots__ = ("published_config_sha256",)

    def __init__(self, published_config_sha256):
        self.published_config_sha256 = published_config_sha256


def _build_argv(wrapper_path, sudo_path):
    if not os.path.isabs(wrapper_path):
        raise XrayReloadError("internal", f"activation wrapper path must be absolute, got {wrapper_path!r}")
    if sudo_path:
        if not os.path.isabs(sudo_path):
            raise XrayReloadError("internal", f"sudo path must be absolute, got {sudo_path!r}")
        return [sudo_path, _SUDO_NONINTERACTIVE_FLAG, wrapper_path]
    return [wrapper_path]


def activate(wrapper_path, timeout_seconds, sudo_path=None):
    """Runs the Xray activation wrapper (optionally through `sudo -n`) and
    returns an XrayReloadOutcome, or raises XrayReloadError. Takes NO
    caller-supplied config path - the wrapper itself only ever reads the
    ONE fixed staging path baked into gateway/config/xray.env (see that
    file and gateway/privileged/nova-xray-reload's own docstring); the
    caller's job is to have already written the candidate there (see
    xray_activation.py) before calling this function."""
    argv = _build_argv(wrapper_path, sudo_path)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise XrayReloadError("timeout", "xray activation subprocess timed out")
    except OSError as exc:
        raise XrayReloadError("internal", f"failed to invoke xray activation wrapper: {exc}")

    if proc.returncode == _EXIT_VALIDATION_FAILED:
        raise XrayReloadError("validation_failed", "candidate Xray config failed validation")
    if proc.returncode == _EXIT_ACTIVATION_FAILED_ROLLED_BACK:
        raise XrayReloadError(
            "activation_failed",
            "candidate validated but did not activate; rolled back to previous config",
            rollback_succeeded=True,
        )
    if proc.returncode == _EXIT_ACTIVATION_FAILED_ROLLBACK_ALSO_FAILED:
        raise XrayReloadError(
            "activation_failed",
            "candidate validated but did not activate; rollback ALSO failed - operator attention required",
            rollback_succeeded=False,
        )
    if proc.returncode == _EXIT_STAGING_MISSING:
        raise XrayReloadError("internal", "staging config was missing or empty when the wrapper ran")
    if proc.returncode == _EXIT_USAGE:
        raise XrayReloadError("internal", "activation wrapper usage error - argv shape mismatch")
    if proc.returncode != _EXIT_SUCCESS:
        raise XrayReloadError("internal", f"activation wrapper exited with unexpected code {proc.returncode}")

    lines = proc.stdout.split("\n")
    if len(lines) == 2 and lines[1] == "":
        line = lines[0]
    elif len(lines) == 1:
        line = lines[0]
    else:
        raise XrayReloadError("internal", "activation wrapper produced unexpected extra stdout")

    match = _STDOUT_LINE_RE.match(line)
    if not match:
        raise XrayReloadError("internal", "activation wrapper produced malformed stdout")

    return XrayReloadOutcome(published_config_sha256=match.group(1))
