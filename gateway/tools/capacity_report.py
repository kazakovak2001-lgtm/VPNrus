#!/usr/bin/env python3
"""Capacity / Load Validation - read-only measurement of THIS gateway.

ROADMAP "Capacity / Load Validation": before any scale claim the project
must measure its own sessions, request rate, latency, error rate and host
pressure instead of copying community numbers. This command reports what
the gateway already exposes, and says "unavailable" (never 0) for what it
does not:

  - control-plane requests from the loopback edge's `pocvpn_cp_log`
    (rate, status classes, error rate, p50/p95/p99 of $request_time);
  - requests from `combined` access logs (rate, status classes, error
    rate; this format has no latency field);
  - AmneziaWG peers with a handshake inside the activity window
    (`awg show <if> dump`, read-only);
  - host load, memory and established TCP connections per local port.

Xray sessions are reported as unavailable: the gateway's Xray configs do
not enable the stats API, and turning it on is a production config change
this tool must not make.

Never mutates anything. Output is aggregate only: no client IP, URI,
key or token ever leaves the parser.

    capacity_report.py --cp-log /var/log/nginx/pocvpn-cp-loopback-access.log \\
        --combined-log /var/log/nginx/pocvpn_access.log \\
        --awg-interface awg0 --tcp-port 443 --since-minutes 15
"""
import argparse
import datetime as dt
import json
import math
import os
import re
import subprocess
import sys

AWG_ACTIVE_SECONDS = 180  # WireGuard re-handshakes every 2 min while traffic flows

# The gateway's own API paths (gateway/edge nginx `location =` blocks). Any
# other path - scanners, typos, probes - is reported only as "other", so a
# request path never reaches the output.
KNOWN_ENDPOINTS = (
    "/v1/activate",
    "/v1/field-enroll",
    "/v1/hysteria-profile",
    "/v1/ingress-profile",
    "/v1/manifest",
    "/v1/peers",
    "/v1/tunnel-probe",
    "/v1/xray-profile",
)

_CP_LOG = re.compile(
    r'^(?P<time>\S+) \S+ "\S+ (?P<uri>[^" ]*)[^"]*" (?P<status>\d{3}) \d+ (?P<rt>[\d.]+)$'
)
_COMBINED = re.compile(
    r'^\S+ \S+ \S+ \[(?P<time>[^\]]+)\] "(?:\S+ (?P<uri>[^" ]*))?[^"]*" (?P<status>\d{3}) '
)


def endpoint_label(uri):
    path = (uri or "").split("?", 1)[0]
    return path if path in KNOWN_ENDPOINTS else "other"


def parse_cp_log_line(line):
    """-> (datetime, status, request_time_seconds, endpoint) or None for an unparsable line."""
    m = _CP_LOG.match(line.strip())
    if not m:
        return None
    try:
        when = dt.datetime.fromisoformat(m.group("time"))
    except ValueError:
        return None
    return when, int(m.group("status")), float(m.group("rt")), endpoint_label(m.group("uri"))


def parse_combined_line(line):
    """-> (datetime, status, None, endpoint) or None. The client address is never kept."""
    m = _COMBINED.match(line.strip())
    if not m:
        return None
    try:
        when = dt.datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return when, int(m.group("status")), None, endpoint_label(m.group("uri"))


def percentile(sorted_values, p):
    """Nearest-rank percentile of an already sorted list; None when empty."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(p / 100.0 * len(sorted_values)))
    return sorted_values[rank - 1]


def summarize_requests(lines, parser, since, window_seconds):
    """Aggregate one log over [since, now]. Unparsable lines are counted, not guessed."""
    statuses = {"2xx": 0, "3xx": 0, "4xx": 0, "429": 0, "5xx": 0}
    latencies, total, unparsed = [], 0, 0
    by_endpoint = {}
    for line in lines:
        if not line.strip():
            continue
        parsed = parser(line)
        if parsed is None:
            unparsed += 1
            continue
        when, status, request_time, endpoint = parsed
        if when < since:
            continue
        total += 1
        if status == 429:
            statuses["429"] += 1
        elif 200 <= status < 600:
            statuses[f"{status // 100}xx"] += 1
        bucket = by_endpoint.setdefault(endpoint, {"requests": 0})
        bucket["requests"] += 1
        code = str(status)
        bucket[code] = bucket.get(code, 0) + 1
        if request_time is not None:
            latencies.append(request_time)
    latencies.sort()
    errors = statuses["5xx"]
    return {
        "requests": total,
        "requests_per_second": round(total / window_seconds, 3) if window_seconds else None,
        "status": statuses,
        "error_rate_5xx": round(errors / total, 4) if total else None,
        "rate_limited_429": statuses["429"],
        "by_endpoint": by_endpoint,
        "latency_seconds": (
            {p: percentile(latencies, q) for p, q in (("p50", 50), ("p95", 95), ("p99", 99))}
            if latencies else "unavailable"
        ),
        "unparsed_lines": unparsed,
    }


def parse_awg_dump(text, now_epoch, active_seconds=AWG_ACTIVE_SECONDS):
    """`awg show <if> dump`: line 1 is the interface, every further line one peer.

    Peer fields: public-key preshared-key endpoint allowed-ips latest-handshake rx tx keepalive.
    """
    peers = active = 0
    rx = tx = 0
    for line in text.strip().splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        peers += 1
        handshake = int(fields[4] or 0)
        if handshake and now_epoch - handshake <= active_seconds:
            active += 1
        rx += int(fields[5] or 0)
        tx += int(fields[6] or 0)
    return {
        "peers_configured": peers,
        "peers_active": active,
        "active_window_seconds": active_seconds,
        # Cumulative since the interface (or peer) came up - not traffic in this window.
        "rx_bytes_since_interface_up": rx,
        "tx_bytes_since_interface_up": tx,
    }


def parse_loadavg(text):
    one, five, fifteen = (float(v) for v in text.split()[:3])
    return {"load_1m": one, "load_5m": five, "load_15m": fifteen}


def parse_meminfo(text):
    kb = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if rest.strip():
            kb[key] = int(rest.split()[0])
    total, available = kb.get("MemTotal"), kb.get("MemAvailable")
    if not total or available is None:
        return "unavailable"
    return {
        "total_mb": total // 1024,
        "available_mb": available // 1024,
        "used_ratio": round(1 - available / total, 4),
    }


def count_established(proc_net_texts, ports):
    """Established TCP connections whose LOCAL port is in `ports` (/proc/net/tcp{,6})."""
    counts = {port: 0 for port in ports}
    for text in proc_net_texts:
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "01":  # 01 = ESTABLISHED
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
            if port in counts:
                counts[port] += 1
    return counts


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        yield from handle


def build_report(args, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    window = args.since_minutes * 60
    since = now - dt.timedelta(seconds=window)
    report = {
        "generated_at": now.isoformat(timespec="seconds"),
        "window_seconds": window,
        "control_plane": {},
        "access_logs": {},
        "sessions": {"xray": "unavailable (stats API not enabled in gateway Xray configs)"},
        "host": {},
    }
    for path in args.cp_log:
        report["control_plane"][os.path.basename(path)] = (
            summarize_requests(_read_lines(path), parse_cp_log_line, since, window)
            if os.path.exists(path) else "unavailable (log not found)"
        )
    for path in args.combined_log:
        report["access_logs"][os.path.basename(path)] = (
            summarize_requests(_read_lines(path), parse_combined_line, since, window)
            if os.path.exists(path) else "unavailable (log not found)"
        )
    for interface in args.awg_interface:
        try:
            dump = subprocess.run(
                [args.awg_bin, "show", interface, "dump"],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout
            report["sessions"][f"awg:{interface}"] = parse_awg_dump(dump, int(now.timestamp()))
        except (OSError, subprocess.SubprocessError) as exc:
            report["sessions"][f"awg:{interface}"] = f"unavailable ({type(exc).__name__})"
    proc = args.proc_root
    loadavg, meminfo = _read(os.path.join(proc, "loadavg")), _read(os.path.join(proc, "meminfo"))
    report["host"]["load"] = parse_loadavg(loadavg) if loadavg else "unavailable"
    report["host"]["cpu_count"] = os.cpu_count()
    report["host"]["memory"] = parse_meminfo(meminfo) if meminfo else "unavailable"
    if args.tcp_port:
        texts = [t for t in (_read(os.path.join(proc, "net", n)) for n in ("tcp", "tcp6")) if t]
        report["host"]["tcp_established_by_local_port"] = (
            {str(k): v for k, v in count_established(texts, args.tcp_port).items()}
            if texts else "unavailable"
        )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cp-log", action="append", default=[], help="pocvpn_cp_log access log (repeatable)")
    parser.add_argument("--combined-log", action="append", default=[], help="nginx combined access log (repeatable)")
    parser.add_argument("--awg-interface", action="append", default=[], help="AmneziaWG interface (repeatable)")
    parser.add_argument("--awg-bin", default="awg")
    parser.add_argument("--tcp-port", action="append", type=int, default=[], help="local TCP port to count (repeatable)")
    parser.add_argument("--since-minutes", type=int, default=15)
    parser.add_argument("--proc-root", default="/proc")
    args = parser.parse_args(argv)
    if args.since_minutes <= 0:
        parser.error("--since-minutes must be positive")
    json.dump(build_report(args), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
