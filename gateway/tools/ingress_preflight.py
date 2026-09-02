#!/usr/bin/env python3
"""B26 (task I) - single PASS/FAIL preflight/doctor for an ingress host.
Read-only: never mutates anything (unlike ingress_reconcile.py). Emits no
secret VALUE anywhere - a path is fine to print, a key/uuid/token/hash
never is.

    ingress_preflight.py --env-file /etc/pocvpn/ingress.env

Exit code 0 = every check passed. Exit code 1 = at least one FAILed.
"""
import argparse
import grp
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import ingress_activation as ingress_activation_module  # noqa: E402
from api import ingress_config as ingress_config_module  # noqa: E402
from api import relay_identity_store as relay_identity_store_module  # noqa: E402

_XRAY_BIN_PATH_EXPECTED_PREFIX = "/opt/pocvpn/xray/"
_MAX_SANE_CLOCK_SKEW_SECONDS = 300


class Check:
    __slots__ = ("name", "ok", "detail")

    def __init__(self, name, ok, detail=""):
        self.name = name
        self.ok = ok
        self.detail = detail


def _parse_env_file(path):
    result = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            result[key.strip()] = value.strip()
    return result


def _check_file_not_world_readable(path):
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError as exc:
        return False, f"cannot stat: {exc.__class__.__name__}"
    if mode & 0o077:
        return False, f"mode {oct(mode)} grants group/other access - expected 0600/0640 or tighter"
    return True, f"mode {oct(mode)}"


def run_checks(ingress_cfg, env):
    checks = []

    xray_bin = None
    unit_path = "/etc/systemd/system/nova-xray-ingress.service"
    if os.path.isfile(unit_path):
        with open(unit_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip().startswith("ExecStart="):
                    xray_bin = line.split("ExecStart=", 1)[1].split()[0]
                    break
    if xray_bin:
        ok = os.path.isfile(xray_bin) and os.access(xray_bin, os.X_OK)
        checks.append(Check("xray binary present and executable", ok, xray_bin if ok else f"missing/non-executable: {xray_bin}"))
        if ok:
            try:
                proc = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=5)
                checks.append(Check("xray version reports successfully", proc.returncode == 0, proc.stdout.strip().splitlines()[0] if proc.stdout else ""))
            except (OSError, subprocess.TimeoutExpired) as exc:
                checks.append(Check("xray version reports successfully", False, exc.__class__.__name__))
    else:
        checks.append(Check("xray binary present and executable", False, f"could not determine ExecStart from {unit_path} (unit not installed yet?)"))

    checks.append(Check("python3 runtime available", shutil.which("python3") is not None))

    for unit in ("nova-xray-ingress.service", "pocvpn-api-ingress.service"):
        installed = os.path.isfile(f"/etc/systemd/system/{unit}")
        checks.append(Check(f"systemd unit installed: {unit}", installed))

    for user in ("pocvpn-api", "nova-xray-ingress"):
        try:
            pwd.getpwnam(user)
            checks.append(Check(f"system user exists: {user}", True))
        except KeyError:
            checks.append(Check(f"system user exists: {user}", False, "not found - run install-ingress-role.sh"))

    for path in (
        ingress_cfg.ingress_reality_private_key_file,
        ingress_cfg.ingress_upstream_uuid_file,
        ingress_cfg.ingress_probe_hmac_secret_file,
    ):
        ok, detail = _check_file_not_world_readable(path)
        checks.append(Check(f"secret file not world-readable: {os.path.basename(path)}", ok, detail))

    if ingress_cfg.ingress_tls_cert_file:
        ok, detail = _check_file_not_world_readable(ingress_cfg.ingress_tls_key_file)
        checks.append(Check("TLS key file not world-readable", ok, detail))

    static_clients_file = env.get("POCVPN_API_STATIC_RELAY_CLIENTS_FILE", "").strip()
    checks.append(Check(
        "exit upstream coordinates configured",
        bool(ingress_cfg.ingress_upstream_host and ingress_cfg.ingress_upstream_port),
        f"{ingress_cfg.ingress_upstream_host}:{ingress_cfg.ingress_upstream_port}",
    ))
    checks.append(Check(
        "static_relay_clients_file note (informational, this is an EXIT-side setting)",
        True,
        "n/a on an ingress host - relay identity presence is checked on the EXIT via apply_relay_upstream_identity.py status",
    ))
    del static_clients_file

    try:
        candidate, sha256_hex = ingress_activation_module._render_candidate(ingress_cfg)  # noqa: SLF001 - preflight deliberately exercises the real render path read-only
        checks.append(Check("candidate ingress config renders and validates structurally", True, f"sha256={sha256_hex[:12]}..."))
        outbound_protocols = {o.get("protocol") for o in candidate.get("outbounds", [])}
        no_freedom = "freedom" not in outbound_protocols and "direct" not in outbound_protocols
        checks.append(Check("no freedom/direct outbound in ingress candidate config", no_freedom, f"outbound protocols: {sorted(outbound_protocols)}"))
    except Exception as exc:  # noqa: BLE001 - preflight must report, never crash
        checks.append(Check("candidate ingress config renders and validates structurally", False, f"{exc.__class__.__name__}: {exc}"))
        checks.append(Check("no freedom/direct outbound in ingress candidate config", False, "could not render to check"))

    if os.path.isfile(unit_path):
        with open(unit_path, "r", encoding="utf-8") as handle:
            unit_text = handle.read()
        checks.append(Check("nova-xray-ingress.service runs a dedicated non-root user", "User=nova-xray-ingress" in unit_text))

    api_port_raw = env.get("POCVPN_API_API_PORT", "")
    if api_port_raw.isdigit():
        api_port = int(api_port_raw)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            bound_locally = sock.connect_ex(("127.0.0.1", api_port)) == 0
        finally:
            sock.close()
        checks.append(Check(f"pocvpn-api bound and reachable on 127.0.0.1:{api_port}", bound_locally))
    else:
        checks.append(Check("pocvpn-api API port configured", False, "POCVPN_API_API_PORT missing/non-numeric in env file"))

    checks.append(Check(
        "relay identity presence (informational)",
        True,
        "verify on the PINNED EXIT via: apply_relay_upstream_identity.py status --static-clients-file <exit's file>",
    ))

    now = time.time()
    checks.append(Check("system clock is plausible (not 1970, not far future)", 1_700_000_000 < now < 4_100_000_000, time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))))

    checks.append(Check(
        "firewall expectations documented (manual check)",
        True,
        f"operator must confirm inbound TCP {ingress_cfg.ingress_server_port} (and {ingress_cfg.ingress_tls_server_port or 'n/a'} if TLS) allowed; nothing else exposed",
    ))

    try:
        gid = pwd.getpwnam("nova-xray-ingress").pw_gid
        grp.getgrgid(gid)
        checks.append(Check("nova-xray-ingress group resolvable", True))
    except KeyError:
        checks.append(Check("nova-xray-ingress group resolvable", False))

    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ingress_preflight.py", description="B26 - read-only ingress host preflight/doctor")
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    env = dict(os.environ)
    env.update(_parse_env_file(args.env_file))

    try:
        ingress_cfg = ingress_config_module.load_ingress_config(env=env)
    except ingress_config_module.IngressConfigError as exc:
        if args.json:
            print(json.dumps({"pass": False, "config_error": str(exc)}, indent=2))
        else:
            print(f"ingress_preflight: FAIL - config error: {exc}")
        raise SystemExit(1)

    if ingress_cfg is None:
        print("ingress_preflight: FAIL - no NOVA_INGRESS_* variable set in this env file")
        raise SystemExit(1)

    checks = run_checks(ingress_cfg, env)
    overall_pass = all(c.ok for c in checks)

    if args.json:
        print(json.dumps({
            "pass": overall_pass,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in checks],
        }, indent=2))
    else:
        for c in checks:
            status = "PASS" if c.ok else "FAIL"
            print(f"  [{status}] {c.name}" + (f" - {c.detail}" if c.detail else ""))
        print(f"ingress_preflight: {'PASS' if overall_pass else 'FAIL'} ({sum(1 for c in checks if c.ok)}/{len(checks)} checks passed)")

    raise SystemExit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
