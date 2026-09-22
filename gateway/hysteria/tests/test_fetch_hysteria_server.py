"""B46-4P - end-to-end tests for fetch-hysteria-server.sh, mirroring
gateway/tools/tests/test_ingress_preflight.py's own proven pattern for
exercising a real bash script against a fake `file://` release asset
(curl supports file:// natively, so this is a REAL run of the tracked
script, not a re-implementation of its logic in Python) - never a
substitute for a real root/systemd sandboxed run, which this environment
cannot provide, but a genuine exercise of the actual checksum/commit
fail-closed behavior this script implements.
"""
import os
import subprocess
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_HYSTERIA_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))


class FetchHysteriaServerScriptTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.hysteria_dir = os.path.join(self._tmp.name, "hysteria")
        os.makedirs(self.hysteria_dir)
        with open(os.path.join(_HYSTERIA_DIR, "fetch-hysteria-server.sh"), "r", encoding="utf-8", newline=None) as handle:
            script_text = handle.read()
        self.script_path = os.path.join(self.hysteria_dir, "fetch-hysteria-server.sh")
        with open(self.script_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script_text)
        os.chmod(self.script_path, 0o755)
        self.install_root = os.path.join(self._tmp.name, "install-root")

    def test_bash_syntax_is_valid(self):
        result = subprocess.run(["bash", "-n", self.script_path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _make_fake_release_binary(self, version_output_line):
        # A minimal, self-contained fake release: a single executable
        # shell script standing in for the real Go binary - the real
        # fetch script only ever cares that `hysteria version` produces
        # text on stdout, never that the binary is a genuine Go build.
        path = os.path.join(self._tmp.name, "fake-hysteria-linux-amd64")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("#!/bin/sh\n")
            handle.write(f'echo "{version_output_line}"\n')
        os.chmod(path, 0o755)
        return path

    def _write_version_file(self, commit, sha256, asset_url):
        version_path = os.path.join(self.hysteria_dir, "VERSION")
        with open(version_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("HYSTERIA_REPO=https://example.invalid/hysteria.git\n")
            handle.write("HYSTERIA_TAG=app/v0.0.0-test\n")
            handle.write(f"HYSTERIA_COMMIT={commit}\n")
            handle.write("HYSTERIA_LICENSE=MIT\n")
            handle.write("HYSTERIA_RELEASE_ASSET=hysteria-linux-amd64\n")
            handle.write(f"HYSTERIA_RELEASE_ASSET_URL={asset_url}\n")
            handle.write(f"HYSTERIA_RELEASE_ASSET_SHA256={sha256}\n")
        return version_path

    def _run(self):
        env = dict(os.environ)
        env["HYSTERIA_INSTALL_ROOT"] = self.install_root
        return subprocess.run(
            ["bash", self.script_path], capture_output=True, text=True, timeout=30, env=env,
        )

    def test_never_uses_a_floating_latest_release_url_or_tag(self):
        # Static, text-level guard (mirrors test_ingress_preflight.py's
        # own "asserting on the TRACKED SCRIPT TEXT" discipline) - a
        # floating "latest" release URL/tag must never creep in. The bare
        # word "latest" legitimately appears in this script's own
        # comments (documenting that it deliberately does NOT do that),
        # so this checks the specific dangerous SHAPES, not the word.
        with open(self.script_path, "r", encoding="utf-8") as handle:
            script_text = handle.read()
        self.assertNotIn("/releases/latest/", script_text)
        self.assertNotIn("releases/latest/download", script_text)
        with open(os.path.join(_HYSTERIA_DIR, "VERSION"), "r", encoding="utf-8") as handle:
            version_text = handle.read()
        self.assertNotIn("HYSTERIA_TAG=latest", version_text)
        self.assertNotIn("/releases/latest/", version_text)

    def test_real_tracked_VERSION_pins_a_well_formed_commit_and_checksum(self):
        # Cross-checks the REAL, tracked VERSION file (not a fake one) -
        # a regression guard against a future bump that forgets to fill
        # in a real value.
        with open(os.path.join(_HYSTERIA_DIR, "VERSION"), "r", encoding="utf-8") as handle:
            version_text = handle.read()
        commit_line = next(line for line in version_text.splitlines() if line.startswith("HYSTERIA_COMMIT="))
        commit = commit_line.split("=", 1)[1]
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        sha_line = next(line for line in version_text.splitlines() if line.startswith("HYSTERIA_RELEASE_ASSET_SHA256="))
        sha256 = sha_line.split("=", 1)[1]
        self.assertRegex(sha256, r"^[0-9a-f]{64}$")

    def test_missing_artifact_url_fails_closed(self):
        pinned_full = "e1366b173ccf5706e1e4630fe8aa654a4b574085"
        nonexistent_path = os.path.join(self._tmp.name, "does-not-exist-binary")
        self._write_version_file(pinned_full, "0" * 64, f"file://{nonexistent_path}")

        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root), "nothing must be installed when the artifact download fails")

    def test_sha256_mismatch_fails_before_install(self):
        pinned_full = "e1366b173ccf5706e1e4630fe8aa654a4b574085"
        binary_path = self._make_fake_release_binary(f"hysteria version app/v0.0.0-test ({pinned_full[:7]})")
        self._write_version_file(pinned_full, "0" * 64, f"file://{binary_path}")  # deliberately WRONG sha256

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("checksum mismatch", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root), "nothing must be installed when the checksum check fails")

    def test_malformed_placeholder_checksum_fails_before_any_download(self):
        # The exact scenario this check exists to prevent: a future VERSION
        # bump that forgets to fill in the real checksum (e.g. leaves a
        # "TBD"/empty placeholder) must fail LOUDLY before ever attempting
        # a download, never silently "verify" against whatever arrives.
        pinned_full = "e1366b173ccf5706e1e4630fe8aa654a4b574085"
        self._write_version_file(pinned_full, "TBD", "file:///does/not/matter")

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not a well-formed 64-char lowercase hex sha256", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root))

    def test_valid_checksum_and_commit_installs_successfully(self):
        pinned_full = "e1366b173ccf5706e1e4630fe8aa654a4b574085"
        binary_path = self._make_fake_release_binary(f"hysteria version app/v0.0.0-test ({pinned_full[:7]})")
        real_sha256 = subprocess.run(["sha256sum", binary_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file(pinned_full, real_sha256, f"file://{binary_path}")

        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed_binary = os.path.join(self.install_root, "app/v0.0.0-test", "hysteria")
        self.assertTrue(os.path.isfile(installed_binary))

    def test_malformed_pinned_commit_in_version_file_fails_closed(self):
        binary_path = self._make_fake_release_binary("hysteria version app/v0.0.0-test (e1366b1)")
        real_sha256 = subprocess.run(["sha256sum", binary_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file("not-a-real-commit", real_sha256, f"file://{binary_path}")

        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not a well-formed 40-char lowercase hex commit", result.stdout + result.stderr)
        self.assertFalse(os.path.isdir(self.install_root))

    def test_second_run_does_not_reinstall(self):
        pinned_full = "e1366b173ccf5706e1e4630fe8aa654a4b574085"
        binary_path = self._make_fake_release_binary(f"hysteria version app/v0.0.0-test ({pinned_full[:7]})")
        real_sha256 = subprocess.run(["sha256sum", binary_path], capture_output=True, text=True, check=True).stdout.split()[0]
        self._write_version_file(pinned_full, real_sha256, f"file://{binary_path}")

        first = self._run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self._run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("already installed", second.stdout + second.stderr)


if __name__ == "__main__":
    unittest.main()
