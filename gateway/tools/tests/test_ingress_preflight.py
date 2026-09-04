"""B31A - focused tests for the deployment-convergence fixes found live
during the first real Stockholm ingress deployment: canonical secret file
mode, and the pinned-xray-core-commit check ingress_preflight.py's own
_XRAY_BIN_PATH_EXPECTED_PREFIX constant was defined but never actually
enforced by (dead code found live). install-ingress-role.sh itself is
bash, not importable - its own directory-ownership/xray-binary-convergence
fixes are covered here by asserting on the TRACKED SCRIPT TEXT (a
regression guard against an accidental revert of the exact chown targets/
fetch-xray-server.sh call this PR added - not a substitute for a real
root/systemd sandboxed run, which this environment cannot provide), plus
`bash -n` syntax validation.
"""
import os
import stat
import subprocess
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import ingress_preflight  # noqa: E402


class PinnedCommitParsingTests(unittest.TestCase):
    def test_parses_the_real_tracked_version_files_own_commit(self):
        commit = ingress_preflight._pinned_xray_core_commit()
        self.assertIsNotNone(commit)
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        # Cross-check against the file's own raw text, independent of the
        # parser, so this test fails if the parser and the file ever
        # silently disagree.
        with open(ingress_preflight._XRAY_VERSION_FILE, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertIn(f"XRAY_CORE_COMMIT={commit}", raw)

    def test_missing_version_file_returns_none_not_an_exception(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            original = ingress_preflight._XRAY_VERSION_FILE
            ingress_preflight._XRAY_VERSION_FILE = os.path.join(tmp_dir, "does-not-exist")
            try:
                self.assertIsNone(ingress_preflight._pinned_xray_core_commit())
            finally:
                ingress_preflight._XRAY_VERSION_FILE = original


class CanonicalSecretModeTests(unittest.TestCase):
    """B31A - installer and preflight must agree on ONE canonical secure
    policy (task requirement B) - these prove the ACTUAL check function
    against the ACTUAL mode the fixed installer now produces (0600), and
    against the mode the pre-B31A installer used to leave behind (0640) -
    which must still fail, since _check_file_not_world_readable's own
    check (`mode & 0o077`) has always required strict 0600 despite its own
    pre-B31A error message wrongly claiming 0640 was also acceptable."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, mode):
        path = os.path.join(self._tmp.name, "secret.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("not-a-real-secret\n")
        os.chmod(path, mode)
        return path

    def test_canonical_0600_passes(self):
        path = self._write(0o600)
        ok, _detail = ingress_preflight._check_file_not_world_readable(path)
        self.assertTrue(ok)

    def test_the_old_installers_own_0640_output_fails(self):
        path = self._write(0o640)
        ok, detail = ingress_preflight._check_file_not_world_readable(path)
        self.assertFalse(ok, "0640 must fail - this is the exact pre-B31A installer/preflight disagreement found live")
        self.assertIn("0o640", detail)

    def test_world_readable_fails(self):
        path = self._write(0o644)
        ok, _detail = ingress_preflight._check_file_not_world_readable(path)
        self.assertFalse(ok)


class InstallerScriptTextTests(unittest.TestCase):
    """Regression guards against reverting this PR's exact fixes -
    complements (never substitutes for) real deployment verification,
    which this sandboxed environment cannot perform (no root, no real
    systemd, no /etc/pocvpn)."""

    def setUp(self):
        script_path = os.path.join(_GATEWAY_DIR, "scripts", "install-ingress-role.sh")
        with open(script_path, "r", encoding="utf-8") as handle:
            self.script_text = handle.read()
        self.script_path = script_path

    def test_syntax_is_valid_bash(self):
        # Reads with universal newlines (strips a local git core.autocrlf=true
        # checkout's own CRLF conversion, which affects only the WORKING TREE
        # copy on a Windows-side checkout, never the actual committed LF
        # blob) so this test validates the real script content, not a
        # local-checkout artifact.
        with open(self.script_path, "r", encoding="utf-8", newline=None) as handle:
            normalized = handle.read()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as handle:
            handle.write(normalized)
            tmp_path = handle.name
        try:
            result = subprocess.run(["bash", "-n", tmp_path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(tmp_path)

    def test_ingress_secret_directory_is_group_pocvpn_api_not_root(self):
        self.assertIn("chown root:pocvpn-api /etc/pocvpn/ingress", self.script_text)
        self.assertNotIn("chown root:root /etc/pocvpn/ingress", self.script_text)

    def test_durable_state_directories_are_owned_by_the_service_account_itself(self):
        self.assertIn("chown pocvpn-api:pocvpn-api \"$dir\"", self.script_text)

    def test_pinned_xray_core_is_converged_via_the_real_fetch_script_not_a_manual_symlink(self):
        self.assertIn("fetch-xray-server.sh", self.script_text)
        # No ACTUAL `ln -s` command anywhere in the script body (a comment
        # explaining why a manual symlink is the wrong fix, as this file's
        # own B31A comment does, is fine and expected) - check real command
        # lines only.
        command_lines = [line for line in self.script_text.splitlines() if not line.strip().startswith("#")]
        self.assertFalse(any("ln -s" in line for line in command_lines))

    def test_remaining_manual_steps_run_store_init_as_the_service_account(self):
        # The exact bug found live: init commands run as plain root left
        # store/lock files the pocvpn-api-ingress service itself could not
        # write to.
        self.assertIn("sudo -u pocvpn-api python3", self.script_text)

    def test_remaining_manual_steps_include_the_previously_missing_activation_lock_init(self):
        self.assertIn("init_activation_lock", self.script_text)


class FetchXrayServerScriptTests(unittest.TestCase):
    def test_syntax_is_valid_bash(self):
        script_path = os.path.join(_GATEWAY_DIR, "xray", "fetch-xray-server.sh")
        with open(script_path, "r", encoding="utf-8", newline=None) as handle:
            normalized = handle.read()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n") as handle:
            handle.write(normalized)
            tmp_path = handle.name
        try:
            result = subprocess.run(["bash", "-n", tmp_path], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
