"""manifest_signing.py private-key input: --private-key-file / stdin must
produce the same artifact as the legacy --private-key-b64, and no error path
may echo key material."""
from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

import manifest_signing  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# Deterministic TEST-ONLY key. Never a production key.
_TEST_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
_V9_DRAFT = os.path.join(_TOOLS_DIR, "production_manifest_2026-10-27_v9_DRAFT.json")


def _run(*argv, stdin=None):
    r = subprocess.run(
        [sys.executable, manifest_signing.__file__, *argv],
        input=stdin, capture_output=True, text=True, timeout=30,
    )
    return r.stdout, r.stderr, r.returncode


class ManifestSigningKeyInputTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.key_path = os.path.join(self._tmp.name, "key.b64")
        with open(self.key_path, "w", encoding="ascii") as f:
            f.write(_TEST_KEY_B64 + "\n")
        os.chmod(self.key_path, 0o600)

    def _out(self, name):
        return os.path.join(self._tmp.name, name)

    def _package(self, out, *key_args, stdin=None):
        return _run("sign-and-package", "--manifest", _V9_DRAFT, *key_args, "--out", out, stdin=stdin)

    def _read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_file_stdin_and_legacy_produce_identical_artifact(self):
        a, b, c = self._out("a.bin"), self._out("b.bin"), self._out("c.bin")
        for out, args, stdin in (
            (a, ("--private-key-file", self.key_path), None),
            (b, ("--private-key-file", "-"), _TEST_KEY_B64 + "\n"),
            (c, ("--private-key-b64", _TEST_KEY_B64), None),
        ):
            stdout, stderr, rc = self._package(out, *args, stdin=stdin)
            self.assertEqual(rc, 0, stderr)
            self.assertNotIn(_TEST_KEY_B64, stdout + stderr)
        self.assertEqual(self._read(a), self._read(b))
        self.assertEqual(self._read(a), self._read(c))

    def test_artifact_verifies_and_carries_v9(self):
        out = self._out("v9.bin")
        _, stderr, rc = self._package(out, "--private-key-file", self.key_path)
        self.assertEqual(rc, 0, stderr)
        manifest = manifest_signing.load_manifest_json(_V9_DRAFT)
        canonical = manifest_signing.canonical_bytes(manifest)
        self.assertEqual(self._read(out), manifest_signing.pack_signed_manifest(
            canonical,
            manifest_signing.sign(manifest, Ed25519PrivateKey.from_private_bytes(bytes(range(32)))),
        ))
        self.assertEqual(manifest.manifest_version, 9)

    def test_sign_accepts_key_file(self):
        stdout, stderr, rc = _run("sign", "--manifest", _V9_DRAFT, "--private-key-file", self.key_path)
        self.assertEqual(rc, 0, stderr)
        self.assertIn('"manifestVersion": 9', stdout)
        self.assertNotIn(_TEST_KEY_B64, stdout + stderr)

    def test_key_sources_are_mutually_exclusive_and_required(self):
        _, _, rc = self._package(self._out("x.bin"))
        self.assertNotEqual(rc, 0)
        _, _, rc = self._package(self._out("x.bin"), "--private-key-file", self.key_path,
                                 "--private-key-b64", _TEST_KEY_B64)
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(self._out("x.bin")))

    def test_bad_key_fails_closed_without_echo(self):
        for content in ("not base64 !!!", base64.b64encode(b"short").decode("ascii"), "žluťoučký"):
            with open(self.key_path, "w", encoding="utf-8") as f:
                f.write(content)
            out = self._out("bad.bin")
            stdout, stderr, rc = self._package(out, "--private-key-file", self.key_path)
            self.assertNotEqual(rc, 0)
            self.assertNotIn(content, stdout + stderr)
            self.assertFalse(os.path.exists(out))

    def test_missing_key_file_fails_without_traceback(self):
        out = self._out("missing.bin")
        _, stderr, rc = self._package(out, "--private-key-file", self._out("nope.b64"))
        self.assertNotEqual(rc, 0)
        self.assertNotIn("Traceback", stderr)
        self.assertFalse(os.path.exists(out))

    def test_bad_stdin_fails_closed(self):
        out = self._out("stdin-bad.bin")
        _, stderr, rc = self._package(out, "--private-key-file", "-", stdin="")
        self.assertNotEqual(rc, 0)
        self.assertNotIn("Traceback", stderr)
        self.assertFalse(os.path.exists(out))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits only")
    def test_group_readable_key_file_refused(self):
        os.chmod(self.key_path, 0o640)
        out = self._out("perm.bin")
        stdout, stderr, rc = self._package(out, "--private-key-file", self.key_path)
        self.assertNotEqual(rc, 0)
        self.assertIn("chmod 600", stderr)
        self.assertNotIn(_TEST_KEY_B64, stdout + stderr)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
