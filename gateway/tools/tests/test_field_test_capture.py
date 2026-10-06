"""Field test - server-side capture script contract (dry-run only; never
captures anything here)."""
import os
import shutil
import subprocess
import unittest

_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "field_test_capture.sh"))


@unittest.skipUnless(shutil.which("bash"), "bash required")
class FieldTestCaptureScriptTest(unittest.TestCase):
    def run_script(self, *args):
        return subprocess.run(["bash", _SCRIPT, *args], capture_output=True, text=True, timeout=30)

    def test_dry_run_captures_headers_only_on_nova_ports_for_the_window(self):
        r = self.run_script("--minutes", "5", "--dry-run", "--out", "/tmp/x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("timeout --signal=INT 5m tcpdump", r.stdout)
        self.assertIn("-s 96", r.stdout)
        for port in ("51820", "2053", "2083", "2093", "443", "28388"):
            self.assertIn(f"port {port}", r.stdout)
        self.assertIn("journalctl -u nova-xray", r.stdout)

    def test_client_net_restricts_the_capture(self):
        r = self.run_script("--minutes", "1", "--client-net", "203.0.113.0/24", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("and net 203.0.113.0/24", r.stdout)

    def test_rejects_bad_arguments(self):
        self.assertEqual(self.run_script("--dry-run").returncode, 2)
        self.assertEqual(self.run_script("--minutes", "0", "--dry-run").returncode, 2)
        self.assertEqual(self.run_script("--minutes", "999", "--dry-run").returncode, 2)
        self.assertEqual(self.run_script("--minutes", "5", "--client-net", "x;rm -rf /", "--dry-run").returncode, 2)

    def test_never_reloads_or_changes_services(self):
        with open(_SCRIPT, encoding="utf-8") as f:
            text = f.read()
        for forbidden in ("systemctl restart", "systemctl reload", "systemctl stop", "nft -f", "iptables -", "syncconf", "awg set"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
