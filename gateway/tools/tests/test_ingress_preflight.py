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

    def _with_version_file(self, content):
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp_dir, ignore_errors=True))
        path = os.path.join(tmp_dir, "VERSION")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_D_malformed_commit_in_version_file_fails_closed_returns_none(self):
        # item D - "missing/invalid VERSION commit fails closed": a
        # too-short, too-long, or non-hex value must never be treated as a
        # usable pin.
        for bad_value in ("5ca6f4b", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", ""):
            path = self._with_version_file(f"XRAY_CORE_COMMIT={bad_value}\n")
            original = ingress_preflight._XRAY_VERSION_FILE
            ingress_preflight._XRAY_VERSION_FILE = path
            try:
                self.assertIsNone(ingress_preflight._pinned_xray_core_commit(), f"bad_value={bad_value!r} must fail closed")
            finally:
                ingress_preflight._XRAY_VERSION_FILE = original

    def test_G_canonical_full_commit_is_unchanged_and_still_40_chars(self):
        # item G - VERSION's own full commit stays the canonical pinned
        # fact, never shortened to 7 characters by this fix.
        with open(ingress_preflight._XRAY_VERSION_FILE, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertIn("XRAY_CORE_COMMIT=5ca6f4b7d4dc20a881d4330e498892697627ec0c\n", raw)


class ShortCommitMatchTests(unittest.TestCase):
    """B31B - root cause: a real, SHA256-verified fetch of the genuinely-
    pinned v26.7.28 release reported 'Xray 26.7.28 (Xray, Penetrates
    Everything.) 5ca6f4b (go1.26.5 linux/amd64)' for pinned commit
    '5ca6f4b7d4dc20a881d4330e498892697627ec0c' - `xray version` only ever
    exposes the SHORT (7-char) commit. These test the SAME
    _short_commit_matches function both fetch-xray-server.sh's own
    verification and ingress_preflight.py's own check are built from
    (preflight imports and calls it directly - see run_checks)."""

    _PINNED_FULL = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
    _REAL_VERSION_OUTPUT = "Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.5 linux/amd64)\n"

    def test_A_the_real_pinned_release_output_passes(self):
        self.assertTrue(ingress_preflight._short_commit_matches(self._PINNED_FULL, self._REAL_VERSION_OUTPUT))

    def test_B_a_different_short_commit_fails(self):
        wrong_output = "Xray 26.7.28 (Xray, Penetrates Everything.) deadbee (go1.26.5 linux/amd64)\n"
        self.assertFalse(ingress_preflight._short_commit_matches(self._PINNED_FULL, wrong_output))

    def test_token_aware_not_substring_a_longer_hex_run_containing_the_short_token_does_not_false_positive(self):
        # The exact false-positive a bare "in" substring check would risk:
        # a longer, UNRELATED hex string that happens to CONTAIN the 7-char
        # short commit as a substring, but is never its own whitespace token.
        sneaky_output = "Xray 26.7.28 (Xray, Penetrates Everything.) aa5ca6f4bbb (go1.26.5 linux/amd64)\n"
        self.assertFalse(ingress_preflight._short_commit_matches(self._PINNED_FULL, sneaky_output))

    def test_derives_short_form_from_the_full_pinned_value_never_a_second_hardcoded_constant(self):
        other_full = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        other_output = "Xray 1.0.0 (Xray, Penetrates Everything.) deadbee (go1.26.5 linux/amd64)\n"
        self.assertTrue(ingress_preflight._short_commit_matches(other_full, other_output))
        self.assertFalse(ingress_preflight._short_commit_matches(other_full, self._REAL_VERSION_OUTPUT))


class PreflightPinnedCommitCheckIntegrationTests(unittest.TestCase):
    """E/F at the level run_checks's own Check list would report, by
    calling the same helpers with real (subprocess-shaped) inputs -
    run_checks itself needs a real systemd unit file present to reach this
    branch at all (see this test file's own module docstring on why a full
    root/systemd sandbox is out of scope here)."""

    def test_E_a_canonically_pinned_binarys_version_output_passes(self):
        pinned = ingress_preflight._pinned_xray_core_commit()
        self.assertIsNotNone(pinned)
        real_release_output = f"Xray 26.7.28 (Xray, Penetrates Everything.) {pinned[:7]} (go1.26.5 linux/amd64)\n"
        self.assertTrue(ingress_preflight._short_commit_matches(pinned, real_release_output))

    def test_F_a_manually_symlinked_unpinned_binarys_version_output_fails(self):
        # The exact live finding this whole fix responds to: a manually
        # symlinked, executable, real-but-WRONG-version binary must not
        # pass merely because it is executable and reports SOME version.
        pinned = ingress_preflight._pinned_xray_core_commit()
        self.assertIsNotNone(pinned)
        unpinned_output = "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)\n"
        self.assertFalse(ingress_preflight._short_commit_matches(pinned, unpinned_output))


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


class FetchXrayServerFunctionalTests(unittest.TestCase):
    """B31B - real end-to-end runs of the actual script against a local
    fake release asset (no network needed - the script's own
    XRAY_RELEASE_ASSET_URL is pointed at a file:// URL, and real curl
    handles that scheme natively) - proves the full pipeline order (item
    2's own "download -> SHA256 -> extract -> version -> commit -> install"),
    never just the isolated comparison function in the classes above."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.xray_dir = os.path.join(self._tmp.name, "xray")
        os.makedirs(self.xray_dir)
        with open(os.path.join(_GATEWAY_DIR, "xray", "fetch-xray-server.sh"), "r", encoding="utf-8", newline=None) as handle:
            script_text = handle.read()
        self.script_path = os.path.join(self.xray_dir, "fetch-xray-server.sh")
        with open(self.script_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script_text)
        os.chmod(self.script_path, 0o755)
        self.install_root = os.path.join(self._tmp.name, "install-root")

    def _make_fake_release_zip(self, version_output_line):
        # A minimal, self-contained fake release: a zip whose single
        # top-level entry is an executable "xray" shell script that just
        # echoes the caller-controlled version line - the real script only
        # ever cares that `xray version` produces text on stdout, never
        # that the binary is a genuine Go build.
        extract_src = os.path.join(self._tmp.name, "fake-release-src")
        os.makedirs(extract_src)
        fake_xray = os.path.join(extract_src, "xray")
        with open(fake_xray, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("#!/bin/sh\n")
            handle.write(f'echo "{version_output_line}"\n')
        os.chmod(fake_xray, 0o755)
        zip_path = os.path.join(self._tmp.name, "fake-release.zip")
        subprocess.run(["zip", "-q", "-j", zip_path, fake_xray], check=True)
        return zip_path

    def _write_version_file(self, commit, sha256, asset_url):
        version_path = os.path.join(self.xray_dir, "VERSION")
        with open(version_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("XRAY_CORE_REPO=https://example.invalid/Xray-core.git\n")
            handle.write("XRAY_CORE_TAG=v0.0.0-test\n")
            handle.write(f"XRAY_CORE_COMMIT={commit}\n")
            handle.write("XRAY_CORE_LICENSE=MPL-2.0\n")
            handle.write("XRAY_RELEASE_ASSET=Xray-linux-64.zip\n")
            handle.write(f"XRAY_RELEASE_ASSET_URL={asset_url}\n")
            handle.write(f"XRAY_RELEASE_ASSET_SHA256={sha256}\n")
        return version_path

    def _run(self):
        env = dict(os.environ)
        env["XRAY_INSTALL_ROOT"] = self.install_root
        return subprocess.run(
            ["bash", self.script_path], capture_output=True, text=True, timeout=30, env=env,
        )

    def test_C_sha256_mismatch_fails_before_extract_or_install(self):
        pinned_full = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
        zip_path = self._make_fake_release_zip(f"Xray 26.7.28 (Xray, Penetrates Everything.) {pinned_full[:7]} (go1.26.5 linux/amd64)")
        self._write_version_file(pinned_full, "0" * 64, f"file://{zip_path}")  # deliberately WRONG sha256

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("checksum mismatch", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root), "nothing must be installed when the checksum check fails")

    def test_A_real_pinned_short_commit_in_output_installs_successfully(self):
        pinned_full = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
        zip_path = self._make_fake_release_zip(f"Xray 26.7.28 (Xray, Penetrates Everything.) {pinned_full[:7]} (go1.26.5 linux/amd64)")
        real_sha256 = subprocess.run(["sha256sum", zip_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file(pinned_full, real_sha256, f"file://{zip_path}")

        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed_binary = os.path.join(self.install_root, "v0.0.0-test", "xray")
        self.assertTrue(os.path.isfile(installed_binary))

    def test_B_wrong_short_commit_in_output_fails_closed_never_installs(self):
        pinned_full = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
        zip_path = self._make_fake_release_zip("Xray 26.7.28 (Xray, Penetrates Everything.) deadbee (go1.26.5 linux/amd64)")
        real_sha256 = subprocess.run(["sha256sum", zip_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file(pinned_full, real_sha256, f"file://{zip_path}")

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not report the pinned commit", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root), "nothing must be installed when the commit check fails")

    def test_D_malformed_pinned_commit_in_version_file_fails_closed(self):
        zip_path = self._make_fake_release_zip("Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.5 linux/amd64)")
        real_sha256 = subprocess.run(["sha256sum", zip_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file("not-a-real-commit", real_sha256, f"file://{zip_path}")

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not a well-formed 40-char lowercase hex commit", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root))


if __name__ == "__main__":
    unittest.main()
