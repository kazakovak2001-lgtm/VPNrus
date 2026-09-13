#!/usr/bin/env python3
"""B35 read-only deployment preflight for a CDN-fronted XHTTP origin.

This proves deployment invariants only. It does not prove external CDN
compatibility, end-to-end data-plane success, or restricted-network reachability.
"""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

_REQUIRED_ENV = (
    "NOVA_INGRESS_KIND",
    "NOVA_INGRESS_XHTTP_CLIENT_HOST",
    "NOVA_INGRESS_XHTTP_CLIENT_PORT",
    "NOVA_INGRESS_XHTTP_SERVER_PORT",
    "NOVA_INGRESS_XHTTP_HOST",
    "NOVA_INGRESS_XHTTP_PATH",
    "NOVA_INGRESS_XHTTP_MODE",
    "NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES",
    "NOVA_INGRESS_XHTTP_PADDING_PLACEMENT",
    "NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES",
    "NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES",
)

_FORBIDDEN_FORWARD_HEADERS = ("X-Forwarded-For", "X-Real-IP", "Forwarded")
_REQUIRED_TUNNEL_DIRECTIVES = (
    "proxy_cache off;",
    "proxy_no_cache 1;",
    "proxy_cache_bypass 1;",
    'add_header Cache-Control "no-store" always;',
    "proxy_request_buffering off;",
    "proxy_buffering off;",
    "proxy_http_version 1.1;",
    'proxy_set_header Connection "";',
)


class Check:
    __slots__ = ("name", "ok", "detail")

    def __init__(self, name, ok, detail=""):
        self.name = name
        self.ok = bool(ok)
        self.detail = detail


def _parse_env_file(path):
    result = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            result[key.strip()] = value
    return result


def _extract_location_block(text, path):
    pattern = re.compile(r"location\s+\^~\s+" + re.escape(path) + r"\s*\{")
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        return None, len(matches)

    match = matches[0]
    open_brace = text.find("{", match.start(), match.end())
    depth = 0
    for index in range(open_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:index], 1
    return None, 1


def _directive_values(text, directive):
    return re.findall(
        r"(?m)^\s*" + re.escape(directive) + r"\s+([^;]+?)\s*;\s*(?:#.*)?$",
        text,
    )


def _top_level_access_rules(block):
    rules = []
    depth = 0
    for raw_line in block.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if depth == 0:
            match = re.fullmatch(r"(allow|deny)\s+([^;]+)\s*;", line)
            if match:
                rules.append((match.group(1), match.group(2).strip()))

        depth += line.count("{")
        depth -= line.count("}")
        if depth < 0:
            depth = 0

    return rules


def _parse_size_bytes(value):
    match = re.fullmatch(r"([0-9]+)([kKmMgG]?)", value.strip())
    if not match:
        return None
    number = int(match.group(1))
    multiplier = {
        "": 1,
        "k": 1024,
        "m": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
    }[match.group(2).lower()]
    return number * multiplier


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def evaluate_static_contract(env, nginx_text):
    checks = []

    missing = [name for name in _REQUIRED_ENV if not env.get(name, "").strip()]
    checks.append(Check(
        "all B35 XHTTP ingress fields are configured",
        not missing,
        "missing=" + ",".join(missing) if missing else "",
    ))

    kind = env.get("NOVA_INGRESS_KIND", "").strip().lower()
    mode = env.get("NOVA_INGRESS_XHTTP_MODE", "").strip().lower()
    checks.append(Check("ingress kind is cdn_fronted", kind == "cdn_fronted", f"kind={kind or 'missing'}"))
    checks.append(Check("first executable XHTTP mode is packet-up", mode == "packet-up", f"mode={mode or 'missing'}"))

    client_port = _safe_int(env.get("NOVA_INGRESS_XHTTP_CLIENT_PORT", ""))
    backend_port = _safe_int(env.get("NOVA_INGRESS_XHTTP_SERVER_PORT", ""))
    max_each_post = _safe_int(env.get("NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES", ""))
    padding_min = _safe_int(env.get("NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES", ""))
    padding_max = _safe_int(env.get("NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES", ""))

    checks.append(Check(
        "XHTTP numeric deployment fields are sane",
        client_port is not None
        and 1 <= client_port <= 65535
        and backend_port is not None
        and 1 <= backend_port <= 65535
        and max_each_post is not None
        and max_each_post > 0
        and padding_min is not None
        and padding_max is not None
        and 0 <= padding_min <= padding_max,
    ))

    checks.append(Check("no unreplaced REPLACE_WITH_ placeholders", "REPLACE_WITH_" not in nginx_text))

    path = env.get("NOVA_INGRESS_XHTTP_PATH", "").strip()
    block = None
    count = 0
    if path:
        block, count = _extract_location_block(nginx_text, path)

    checks.append(Check(
        "dedicated XHTTP location exists exactly once",
        block is not None and count == 1,
        f"matches={count}",
    ))
    if block is None:
        return checks

    expected_host = env.get("NOVA_INGRESS_XHTTP_HOST", "").strip()
    proxy_pass_values = _directive_values(block, "proxy_pass")
    expected_proxy = f"http://127.0.0.1:{backend_port}" if backend_port is not None else None
    checks.append(Check(
        "Xray proxy is pinned to configured loopback backend",
        expected_proxy is not None and proxy_pass_values == [expected_proxy],
        f"expected={expected_proxy}; count={len(proxy_pass_values)}" if expected_proxy else "invalid backend port",
    ))

    host_values = _directive_values(block, "proxy_set_header Host")
    checks.append(Check(
        "fixed backend Host matches NOVA_INGRESS_XHTTP_HOST",
        bool(expected_host) and host_values == [expected_host],
        f"host_directives={len(host_values)}",
    ))

    limit_ok = bool(re.search(r"limit_except\s+GET\s+POST\s*\{\s*deny\s+all\s*;", block, re.DOTALL))
    checks.append(Check("first-slice nginx methods are GET+POST only", limit_ok))

    access_rules = _top_level_access_rules(block)
    allow_values = [value for directive, value in access_rules if directive == "allow"]
    cidrs_ok = bool(allow_values)
    for value in allow_values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            cidrs_ok = False
            continue
        if (
            network.prefixlen == 0
            or not network.is_global
            or network.is_loopback
            or network.is_private
            or network.is_link_local
            or network.is_multicast
            or network.is_unspecified
        ):
            cidrs_ok = False

    checks.append(Check(
        "CDN source allows are explicit global CIDRs",
        cidrs_ok,
        f"allow_count={len(allow_values)}",
    ))
    checks.append(Check(
        "CDN allow list terminates with deny all",
        bool(access_rules) and access_rules[-1] == ("deny", "all"),
    ))

    checks.append(Check(
        "satisfy-any bypass is absent",
        not bool(re.search(r"(?m)^\s*satisfy\s+any\s*;", block)),
    ))

    checks.append(Check(
        "cache/buffering/streaming safety directives are present",
        all(directive in block for directive in _REQUIRED_TUNNEL_DIRECTIVES),
    ))

    body_values = _directive_values(block, "client_max_body_size")
    body_limit = _parse_size_bytes(body_values[0]) if len(body_values) == 1 else None
    checks.append(Check(
        "nginx body ceiling covers Xray packet ceiling",
        body_limit is not None and max_each_post is not None and body_limit >= max_each_post,
        f"nginx_bytes={body_limit}; xray_bytes={max_each_post}",
    ))

    forwarded = [
        header
        for header in _FORBIDDEN_FORWARD_HEADERS
        if re.search(r"(?mi)^\s*proxy_set_header\s+" + re.escape(header) + r"\b", block)
    ]
    checks.append(Check(
        "client IP forwarding headers are absent",
        not forwarded,
        "found=" + ",".join(forwarded) if forwarded else "",
    ))

    server_names = _directive_values(nginx_text, "server_name")
    one_plain_name = (
        len(server_names) == 1
        and len(server_names[0].split()) == 1
        and "*" not in server_names[0]
        and "$" not in server_names[0]
    )
    checks.append(Check("origin TLS server_name is one explicit hostname", one_plain_name))
    return checks


def _run(command, timeout=10):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _runtime_checks(env, nginx_config):
    checks = []

    nginx = shutil.which("nginx")
    checks.append(Check("nginx binary is available", nginx is not None))
    if nginx is None:
        return checks

    try:
        proc = _run([nginx, "-t"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks.append(Check("nginx -t passes", False, exc.__class__.__name__))
        return checks
    checks.append(Check("nginx -t passes", proc.returncode == 0, f"exit={proc.returncode}"))

    try:
        dump = _run([nginx, "-T"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks.append(Check("deployed nginx config is loaded", False, exc.__class__.__name__))
        dump = None

    if dump is not None:
        dumped_text = dump.stdout + "\n" + dump.stderr
        requested = os.path.abspath(nginx_config)
        real = os.path.realpath(nginx_config)
        loaded = (
            f"# configuration file {requested}:" in dumped_text
            or f"# configuration file {real}:" in dumped_text
        )
        checks.append(Check(
            "deployed nginx config is loaded",
            dump.returncode == 0 and loaded,
            os.path.basename(nginx_config),
        ))

    ss = shutil.which("ss")
    checks.append(Check("ss is available for listener verification", ss is not None))
    backend_port = _safe_int(env.get("NOVA_INGRESS_XHTTP_SERVER_PORT", ""))
    if ss and backend_port:
        try:
            proc = _run([ss, "-ltnH"])
            lines = proc.stdout.splitlines() if proc.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired):
            lines = []

        listeners = []
        suffix = f":{backend_port}"
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[3].endswith(suffix):
                listeners.append(fields[3])

        loopback = f"127.0.0.1:{backend_port}"
        checks.append(Check(
            "Xray XHTTP backend is listening on IPv4 loopback",
            loopback in listeners,
            f"listener_count={len(listeners)}",
        ))
        public = [value for value in listeners if value != loopback]
        checks.append(Check(
            "Xray XHTTP backend has no non-loopback TCP listener",
            not public,
            f"non_loopback_count={len(public)}",
        ))

    client_host = env.get("NOVA_INGRESS_XHTTP_CLIENT_HOST", "").strip()
    client_port = _safe_int(env.get("NOVA_INGRESS_XHTTP_CLIENT_PORT", ""))
    if client_host and client_port:
        try:
            addresses = socket.getaddrinfo(client_host, client_port, type=socket.SOCK_STREAM)
            dns_ok = bool(addresses)
        except socket.gaierror:
            dns_ok = False
        checks.append(Check("client-facing CDN hostname resolves", dns_ok, client_host))

    curl = shutil.which("curl")
    checks.append(Check("curl is available for direct-origin denial proof", curl is not None))
    if curl:
        try:
            nginx_text = Path(nginx_config).read_text(encoding="utf-8")
        except OSError:
            nginx_text = ""

        server_names = _directive_values(nginx_text, "server_name")
        path = env.get("NOVA_INGRESS_XHTTP_PATH", "").strip()
        if len(server_names) == 1 and len(server_names[0].split()) == 1 and path:
            server_name = server_names[0].strip()
            try:
                proc = _run(
                    [
                        curl,
                        "-k",
                        "-sS",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "10",
                        "--resolve",
                        f"{server_name}:443:127.0.0.1",
                        f"https://{server_name}{path}",
                    ],
                    timeout=15,
                )
                status = proc.stdout.strip()
                denied = proc.returncode == 0 and status == "403"
            except (OSError, subprocess.TimeoutExpired):
                denied = False
                status = "execution-failed"

            checks.append(Check(
                "direct non-CDN request to tunnel path is denied",
                denied,
                f"http_status={status}",
            ))

    return checks


def _print_checks(checks):
    for check in checks:
        state = "PASS" if check.ok else "FAIL"
        suffix = f" -- {check.detail}" if check.detail else ""
        print(f"[{state}] {check.name}{suffix}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only B35 CDN/XHTTP origin deployment preflight.")
    parser.add_argument("--env-file", required=True, help="deployed ingress env file")
    parser.add_argument("--nginx-config", required=True, help="deployed CDN-origin nginx config")
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="validate file/config contracts only; skip nginx, listener, DNS and local runtime checks",
    )
    args = parser.parse_args(argv)

    try:
        env = _parse_env_file(args.env_file)
        nginx_text = Path(args.nginx_config).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[FAIL] input files readable -- {exc.__class__.__name__}")
        print("CDN ORIGIN PREFLIGHT: FAIL")
        return 1

    checks = evaluate_static_contract(env, nginx_text)
    if not args.static_only:
        checks.extend(_runtime_checks(env, args.nginx_config))

    _print_checks(checks)
    ok = all(check.ok for check in checks)
    print()
    print("CDN ORIGIN PREFLIGHT: " + ("PASS" if ok else "FAIL"))
    if ok:
        print("NOTE: PASS proves deployment invariants only; it is NOT CDN end-to-end proof and NOT Russia verification.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
