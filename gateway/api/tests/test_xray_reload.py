"""B8K2A - narrow tests for xray_reload.activate: strict stdout/exit-code
parsing, shell=False + bounded timeout, no arbitrary target."""
import os
import stat
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import xray_reload as xray_reload_module
from _fixtures import set_plan, write_fake_xray_wrapper


class XrayReloadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.wrapper_path = write_fake_xray_wrapper(self._tmp.name)
        self.staging_path = os.path.join(self._tmp.name, "candidate.json")
        with open(self.staging_path, "w", encoding="utf-8") as handle:
            handle.write('{"fake": "config"}')
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.staging_path

    def test_successful_activation_returns_the_published_sha256(self):
        set_plan(self.plan_path, "ACTIVATE")
        outcome = xray_reload_module.activate(self.wrapper_path, timeout_seconds=5)
        self.assertRegex(outcome.published_config_sha256, r"^[0-9a-f]{64}$")

    def test_validation_failure_raises_typed_error(self):
        set_plan(self.plan_path, "FAIL_VALIDATION")
        with self.assertRaises(xray_reload_module.XrayReloadError) as ctx:
            xray_reload_module.activate(self.wrapper_path, timeout_seconds=5)
        self.assertEqual(ctx.exception.kind, "validation_failed")

    def test_activation_failure_with_rollback_reports_rollback_succeeded(self):
        set_plan(self.plan_path, "FAIL_ACTIVATION_ROLLED_BACK")
        with self.assertRaises(xray_reload_module.XrayReloadError) as ctx:
            xray_reload_module.activate(self.wrapper_path, timeout_seconds=5)
        self.assertEqual(ctx.exception.kind, "activation_failed")
        self.assertTrue(ctx.exception.rollback_succeeded)

    def test_activation_failure_with_failed_rollback_reports_that_too(self):
        set_plan(self.plan_path, "FAIL_ACTIVATION_ROLLBACK_FAILED")
        with self.assertRaises(xray_reload_module.XrayReloadError) as ctx:
            xray_reload_module.activate(self.wrapper_path, timeout_seconds=5)
        self.assertEqual(ctx.exception.kind, "activation_failed")
        self.assertFalse(ctx.exception.rollback_succeeded)

    def test_unexpected_exit_code_is_internal_error(self):
        set_plan(self.plan_path, "EXIT", "7")
        with self.assertRaises(xray_reload_module.XrayReloadError) as ctx:
            xray_reload_module.activate(self.wrapper_path, timeout_seconds=5)
        self.assertEqual(ctx.exception.kind, "internal")

    def test_relative_wrapper_path_is_rejected(self):
        with self.assertRaises(xray_reload_module.XrayReloadError):
            xray_reload_module.activate("relative/path", timeout_seconds=5)

    def test_relative_sudo_path_is_rejected(self):
        with self.assertRaises(xray_reload_module.XrayReloadError):
            xray_reload_module.activate(self.wrapper_path, timeout_seconds=5, sudo_path="relative/sudo")

    def test_invocation_uses_no_shell_and_a_bounded_timeout(self):
        # A wrapper that sleeps longer than the timeout must raise a
        # timeout error, not hang - proves shell=False (no shell wrapping
        # that could swallow the timeout) and a real bounded subprocess call.
        sleepy = os.path.join(self._tmp.name, "sleepy-wrapper")
        with open(sleepy, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("#!/usr/bin/env bash\nsleep 5\n")
        os.chmod(sleepy, os.stat(sleepy).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        with self.assertRaises(xray_reload_module.XrayReloadError) as ctx:
            xray_reload_module.activate(sleepy, timeout_seconds=0.2)
        self.assertEqual(ctx.exception.kind, "timeout")


if __name__ == "__main__":
    unittest.main()
