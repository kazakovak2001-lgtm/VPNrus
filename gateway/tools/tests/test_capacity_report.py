"""Capacity / Load Validation - capacity_report.py parsing and privacy."""
import argparse
import datetime as dt
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

import capacity_report as cr  # noqa: E402

NOW = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
SINCE = NOW - dt.timedelta(minutes=15)

CP_LINES = [
    '2026-10-27T11:50:00+00:00 cp.example "GET /v1/manifest" 200 512 0.010',
    '2026-10-27T11:51:00+00:00 cp.example "POST /v1/activate" 200 900 0.200',
    '2026-10-27T11:52:00+00:00 cp.example "POST /v1/activate" 429 10 0.001',
    '2026-10-27T11:53:00+00:00 cp.example "GET /v1/manifest" 502 10 1.500',
    '2026-10-27T11:00:00+00:00 cp.example "GET /v1/manifest" 200 512 9.000',  # outside window
    'garbage line',
]
COMBINED_LINES = [
    '203.0.113.7 - - [27/Oct/2026:11:55:00 +0000] "GET /v1/manifest?t=SECRET HTTP/1.1" 200 51 "-" "ua"',
    '198.51.100.9 - - [27/Oct/2026:11:56:00 +0000] "GET /x HTTP/1.1" 503 0 "-" "ua"',
    '198.51.100.9 - - [27/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 200 0 "-" "ua"',
]
AWG_DUMP = "\n".join([
    "PRIVKEY\tPUBKEY\t51820\toff",
    f"peerA\t(none)\t203.0.113.7:4000\t10.8.0.2/32\t{int(NOW.timestamp()) - 30}\t1000\t2000\t25",
    f"peerB\t(none)\t(none)\t10.8.0.3/32\t{int(NOW.timestamp()) - 3600}\t10\t20\toff",
    "peerC\t(none)\t(none)\t10.8.0.4/32\t0\t0\t0\toff",
])


class RequestSummaryTests(unittest.TestCase):
    def test_cp_log_rates_statuses_and_latency_in_window(self):
        s = cr.summarize_requests(CP_LINES, cr.parse_cp_log_line, SINCE, 900)
        self.assertEqual(s["requests"], 4)
        self.assertEqual(s["status"], {"2xx": 2, "3xx": 0, "4xx": 0, "429": 1, "5xx": 1})
        self.assertEqual(s["error_rate_5xx"], 0.25)
        self.assertEqual(s["rate_limited_429"], 1)
        self.assertEqual(s["unparsed_lines"], 1)
        self.assertEqual(s["latency_seconds"], {"p50": 0.01, "p95": 1.5, "p99": 1.5})
        self.assertAlmostEqual(s["requests_per_second"], 4 / 900, places=3)

    def test_combined_log_has_no_latency_and_never_guesses_one(self):
        s = cr.summarize_requests(COMBINED_LINES, cr.parse_combined_line, SINCE, 900)
        self.assertEqual(s["requests"], 2)
        self.assertEqual(s["latency_seconds"], "unavailable")
        self.assertEqual(s["error_rate_5xx"], 0.5)

    def test_empty_window_reports_none_not_zero_error_rate(self):
        s = cr.summarize_requests([], cr.parse_cp_log_line, SINCE, 900)
        self.assertEqual(s["requests"], 0)
        self.assertIsNone(s["error_rate_5xx"])

    def test_percentile_nearest_rank(self):
        self.assertIsNone(cr.percentile([], 95))
        self.assertEqual(cr.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(cr.percentile(list(range(1, 101)), 95), 95)


class AwgAndHostTests(unittest.TestCase):
    def test_awg_dump_counts_only_recent_handshakes_as_active(self):
        s = cr.parse_awg_dump(AWG_DUMP, int(NOW.timestamp()))
        self.assertEqual((s["peers_configured"], s["peers_active"]), (3, 1))
        self.assertEqual((s["rx_bytes_total"], s["tx_bytes_total"]), (1010, 2020))

    def test_meminfo_and_loadavg(self):
        mem = cr.parse_meminfo("MemTotal: 2048000 kB\nMemFree: 1 kB\nMemAvailable: 512000 kB\n")
        self.assertEqual(mem, {"total_mb": 2000, "available_mb": 500, "used_ratio": 0.75})
        self.assertEqual(cr.parse_meminfo("MemFree: 1 kB\n"), "unavailable")
        self.assertEqual(cr.parse_loadavg("0.50 0.40 0.30 1/200 999")["load_5m"], 0.4)

    def test_established_connections_by_local_port(self):
        tcp = (
            "  sl  local_address rem_address   st\n"
            "   0: 0100007F:01BB 0200007F:C000 01\n"   # :443 established
            "   1: 0100007F:01BB 0200007F:C001 06\n"   # :443 TIME_WAIT
            "   2: 0100007F:1F91 0200007F:C002 01\n"   # :8081 established
            "   3: 0100007F:01BB 00000000:0000 0A\n"   # :443 LISTEN
        )
        self.assertEqual(cr.count_established([tcp], [443, 8081]), {443: 1, 8081: 1})


class ReportTests(unittest.TestCase):
    def _args(self, **kw):
        base = dict(cp_log=[], combined_log=[], awg_interface=[], awg_bin="awg",
                    tcp_port=[], since_minutes=15, proc_root="/nonexistent-proc")
        base.update(kw)
        return argparse.Namespace(**base)

    def test_report_never_contains_client_addresses_uris_or_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp, comb = os.path.join(tmp, "cp.log"), os.path.join(tmp, "access.log")
            with open(cp, "w", encoding="utf-8") as h:
                h.write("\n".join(CP_LINES))
            with open(comb, "w", encoding="utf-8") as h:
                h.write("\n".join(COMBINED_LINES))
            text = json.dumps(cr.build_report(self._args(cp_log=[cp], combined_log=[comb]), now=NOW))
        for secret in ("203.0.113.7", "198.51.100.9", "SECRET", "/v1/manifest", "PRIVKEY", "peerA"):
            self.assertNotIn(secret, text)

    def test_missing_sources_are_unavailable_not_zero(self):
        report = cr.build_report(
            self._args(cp_log=["/nope/cp.log"], awg_interface=["awg0"], awg_bin="/nope/awg", tcp_port=[443]),
            now=NOW,
        )
        self.assertTrue(report["control_plane"]["cp.log"].startswith("unavailable"))
        self.assertTrue(report["sessions"]["awg:awg0"].startswith("unavailable"))
        self.assertTrue(report["sessions"]["xray"].startswith("unavailable"))
        self.assertEqual(report["host"]["load"], "unavailable")
        self.assertEqual(report["host"]["tcp_established_by_local_port"], "unavailable")

    def test_cli_rejects_non_positive_window(self):
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cr.main(["--since-minutes", "0"])


if __name__ == "__main__":
    unittest.main()
