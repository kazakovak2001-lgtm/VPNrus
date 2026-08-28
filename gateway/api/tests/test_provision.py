import os
import sys
import tempfile
import unittest
from unittest import mock

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


# ============================================================
# B8B1C2: sudo argv shape (mocked subprocess.run - these are pure argv/
# call-shape unit tests, never a real subprocess.run or real sudo; the
# real-sudo boundary itself is proven in gateway/privileged/tests/).
# ============================================================
class SudoArgvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = os.path.join(self._tmp.name, "provision-peer.sh")
        with open(self.script_path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")
        self.sudo_path = os.path.join(self._tmp.name, "sudo")
        with open(self.sudo_path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")

    def _mocked_run(self, stdout="created\t10.77.0.5\n", returncode=0):
        completed = mock.Mock()
        completed.returncode = returncode
        completed.stdout = stdout
        return mock.patch("api.provision.subprocess.run", return_value=completed)

    def test_argv_without_sudo_is_script_and_key_only(self):
        with self._mocked_run() as run_mock:
            provision_module.run_provision_peer(self.script_path, "the-key", 5.0)
        (argv,), kwargs = run_mock.call_args
        self.assertEqual(argv, [self.script_path, "the-key"])

    def test_argv_with_sudo_is_sudo_dash_n_script_key(self):
        with self._mocked_run() as run_mock:
            provision_module.run_provision_peer(self.script_path, "the-key", 5.0, sudo_path=self.sudo_path)
        (argv,), kwargs = run_mock.call_args
        self.assertEqual(argv, [self.sudo_path, "-n", self.script_path, "the-key"])

    def test_bearer_token_never_part_of_argv(self):
        # run_provision_peer's signature has no bearer-token parameter at
        # all - structural proof, not just "this call happened to omit it".
        import inspect

        sig = inspect.signature(provision_module.run_provision_peer)
        self.assertNotIn("token", sig.parameters)
        self.assertNotIn("bearer_token", sig.parameters)
        self.assertNotIn("label", sig.parameters)

        with self._mocked_run() as run_mock:
            provision_module.run_provision_peer(self.script_path, "the-key", 5.0, sudo_path=self.sudo_path)
        (argv,), kwargs = run_mock.call_args
        for element in argv:
            self.assertNotIn("Bearer", element)

    def test_subprocess_run_called_with_argv_list_and_shell_false(self):
        with self._mocked_run() as run_mock:
            provision_module.run_provision_peer(self.script_path, "the-key", 5.0, sudo_path=self.sudo_path)
        (argv,), kwargs = run_mock.call_args
        self.assertIsInstance(argv, list)
        self.assertNotIsInstance(argv, str)
        self.assertIs(kwargs.get("shell"), False)

    def test_relative_sudo_path_rejected(self):
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(self.script_path, "the-key", 5.0, sudo_path="relative/sudo")
        self.assertEqual(ctx.exception.kind, "internal")

    def test_relative_script_path_rejected(self):
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer("relative/provision-peer.sh", "the-key", 5.0)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_relative_script_path_rejected_even_with_sudo(self):
        with self.assertRaises(provision_module.ProvisionError) as ctx:
            provision_module.run_provision_peer(
                "relative/provision-peer.sh", "the-key", 5.0, sudo_path=self.sudo_path
            )
        self.assertEqual(ctx.exception.kind, "internal")


if __name__ == "__main__":
    unittest.main()
