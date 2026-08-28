import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import provision as provision_module
from _fixtures import set_plan, write_fake_provision_script


class ProvisionSubprocessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        self._env_backup = dict(os.environ)
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path
        os.environ.pop("POCVPN_FAKE_ARGV_CAPTURE", None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_created(self):
        set_plan(self.plan_path, "CREATED", "10.77.0.5")
        outcome = provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(outcome.state, provision_module.CREATED)
        self.assertEqual(outcome.ip, "10.77.0.5")

    def test_existing(self):
        set_plan(self.plan_path, "EXISTING", "10.77.0.6")
        outcome = provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(outcome.state, provision_module.EXISTING)
        self.assertEqual(outcome.ip, "10.77.0.6")

    def test_exit_20_is_exhausted(self):
        set_plan(self.plan_path, "EXIT", "20")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "exhausted")

    def test_exit_1_is_internal(self):
        set_plan(self.plan_path, "EXIT", "1")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_exit_2_is_internal(self):
        set_plan(self.plan_path, "EXIT", "2")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_unexpected_exit_code_is_internal(self):
        set_plan(self.plan_path, "EXIT", "7")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_timeout(self):
        set_plan(self.plan_path, "SLEEP", "5")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 0.2)
        self.assertEqual(ctx.exception.kind, "timeout")

    def test_malformed_stdout_is_internal(self):
        set_plan(self.plan_path, "MALFORMED")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_extra_stdout_line_is_internal(self):
        set_plan(self.plan_path, "EXTRA")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_invalid_ip_is_internal(self):
        set_plan(self.plan_path, "BADIP")
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "pubkey", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_argv_contains_only_public_key(self):
        set_plan(self.plan_path, "CREATED", "10.77.0.9")
        capture_path = os.path.join(self._tmp.name, "argv_capture.txt")
        os.environ["POCVPN_FAKE_ARGV_CAPTURE"] = capture_path
        provision_module.run_provision_peer(self.script_path, "the-public-key-value", 5.0)
        with open(capture_path, "r", encoding="utf-8") as handle:
            captured = handle.read().splitlines()
        self.assertEqual(captured, ["the-public-key-value"])


if __name__ == "__main__":
    unittest.main()
