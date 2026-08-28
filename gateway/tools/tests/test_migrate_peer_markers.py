"""ORACLE-MIGRATION-DESIGN-1: tests for gateway/tools/migrate_peer_markers.py.

Every fixture in this file uses obviously-synthetic key material - never a
real AmneziaWG/WireGuard key, and never anything read from a live host.
This suite also asserts, across every captured tool invocation, that the
fixture's own synthetic PrivateKey value never appears in ANY stdout/
stderr this tool produces - the same invariant a real PrivateKey would be
held to, exercised here so a future refactor that weakens it fails loudly.
"""
import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_GATEWAY_DIR = os.path.abspath(os.path.join(_TOOLS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import migrate_peer_markers as mpm  # noqa: E402

_FIXTURES_DIR = os.path.join(_THIS_DIR, "fixtures")
_LIVE_SHAPE_ONE_PEER = os.path.join(_FIXTURES_DIR, "live_shape_one_peer.conf.example")
_LIVE_SHAPE_WITH_PSK = os.path.join(_FIXTURES_DIR, "live_shape_one_peer_with_psk.conf.example")
_SYNTHETIC_PRIVATE_KEY = "SYNTHETICNOTREALPRIVATEKEYVALUEFAKEFAKE0="
_SYNTHETIC_PRESHARED_KEY = "SYNTHETICPRESHAREDKEY000000000000000000001="


def _run(func, *args):
    """Run a cmd_* function, capturing stdout/stderr, returning
    (returncode, stdout, stderr). Also asserts the synthetic PrivateKey
    AND PresharedKey values never appear in either stream - every single
    call through this helper is implicitly a secrecy check for BOTH
    secret fields, not just a correctness check."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = func(*args)
    stdout, stderr = out.getvalue(), err.getvalue()
    for secret, label in ((_SYNTHETIC_PRIVATE_KEY, "PrivateKey"), (_SYNTHETIC_PRESHARED_KEY, "PresharedKey")):
        assert secret not in stdout, f"{label} leaked to stdout: {stdout!r}"
        assert secret not in stderr, f"{label} leaked to stderr: {stderr!r}"
    return rc, stdout, stderr


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class TempConfMixin:
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)

    def _path(self, name):
        return os.path.join(self._tmpdir.name, name)

    def _write(self, name, text):
        path = self._path(name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        return path

    def _read(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()


class ParseConfTests(unittest.TestCase):
    def test_live_shape_one_peer_parses(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        interface, peers, first_peer_line, last_content_line = mpm.parse_conf(lines)
        self.assertEqual(interface["Address"], "10.77.0.1/24")
        self.assertEqual(interface["ListenPort"], "51820")
        self.assertEqual(interface["Jc"], "0")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["AllowedIPs"], "10.77.0.2/32")
        self.assertIsNotNone(first_peer_line)
        self.assertGreater(last_content_line, first_peer_line)

    def test_zero_peers_parses(self):
        text = "[Interface]\nPrivateKey = X\nAddress = 10.77.0.1/24\nListenPort = 51820\n"
        interface, peers, first_peer_line, last_content_line = mpm.parse_conf(text.splitlines())
        self.assertEqual(peers, [])
        self.assertIsNone(first_peer_line)
        self.assertEqual(last_content_line, 3)

    def test_multi_peer_parses(self):
        text = (
            "[Interface]\nPrivateKey = X\nAddress = 10.77.0.1/24\nListenPort = 51820\n"
            "\n[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n"
            "\n[Peer]\nPublicKey = B\nAllowedIPs = 10.77.0.3/32\n"
        )
        _interface, peers, _first, _last = mpm.parse_conf(text.splitlines())
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0]["PublicKey"], "A")
        self.assertEqual(peers[1]["PublicKey"], "B")

    def test_already_marked_begin_only_rejected(self):
        text = "[Interface]\nPrivateKey = X\n# --- PEERS BEGIN ---\n[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_already_marked_end_only_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n# --- PEERS END ---\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_already_marked_both_rejected(self):
        text = (
            "[Interface]\nPrivateKey = X\n# --- PEERS BEGIN ---\n"
            "[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n# --- PEERS END ---\n"
        )
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_reversed_markers_rejected(self):
        # END appears before BEGIN - still caught by the same
        # "any marker line at all" rejection, since parse_conf never
        # tries to reason about ordering of markers it refuses to accept.
        text = "[Interface]\nPrivateKey = X\n# --- PEERS END ---\n# --- PEERS BEGIN ---\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_duplicate_interface_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Interface]\nPrivateKey = Y\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_peer_before_interface_rejected(self):
        text = "[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n[Interface]\nPrivateKey = X\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_missing_private_key_rejected(self):
        text = "[Interface]\nAddress = 10.77.0.1/24\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_peer_missing_allowedips_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Peer]\nPublicKey = A\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_peer_missing_publickey_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Peer]\nAllowedIPs = 10.77.0.2/32\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_unknown_interface_field_rejected(self):
        text = "[Interface]\nPrivateKey = X\nMysteryField = 1\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_unknown_section_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Bogus]\nFoo = 1\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_content_outside_section_rejected(self):
        text = "PrivateKey = X\n[Interface]\nPrivateKey = Y\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())

    def test_duplicate_field_in_one_peer_rejected(self):
        text = "[Interface]\nPrivateKey = X\n[Peer]\nPublicKey = A\nPublicKey = B\nAllowedIPs = 10.77.0.2/32\n"
        with self.assertRaises(mpm.ConfigError):
            mpm.parse_conf(text.splitlines())


class MigrateLinesTests(unittest.TestCase):
    def test_live_shape_inserts_exactly_two_markers_in_right_place(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            original = f.read().splitlines()
        migrated = mpm.migrate_lines(original)

        self.assertEqual(len(migrated), len(original) + 2)
        begin_idx = migrated.index(mpm._BEGIN_MARKER)
        end_idx = migrated.index(mpm._END_MARKER)
        self.assertLess(begin_idx, end_idx)
        # BEGIN sits immediately before [Peer]
        self.assertEqual(migrated[begin_idx + 1].strip(), "[Peer]")
        # END sits immediately after the last peer's AllowedIPs line
        self.assertTrue(migrated[end_idx - 1].strip().startswith("AllowedIPs"))

        # Every original line still appears, in original relative order,
        # with only the two marker lines interposed - nothing reordered
        # or dropped.
        without_markers = [l for l in migrated if l not in (mpm._BEGIN_MARKER, mpm._END_MARKER)]
        self.assertEqual(without_markers, original)

    def test_zero_peers_markers_adjacent(self):
        original = ["[Interface]", "PrivateKey = X", "Address = 10.77.0.1/24", "ListenPort = 51820"]
        migrated = mpm.migrate_lines(original)
        begin_idx = migrated.index(mpm._BEGIN_MARKER)
        self.assertEqual(migrated[begin_idx + 1], mpm._END_MARKER)

    def test_multi_peer_end_after_last_peer_only(self):
        original = (
            "[Interface]\nPrivateKey = X\nAddress = 10.77.0.1/24\nListenPort = 51820\n"
            "\n[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n"
            "\n[Peer]\nPublicKey = B\nAllowedIPs = 10.77.0.3/32\n"
        ).splitlines()
        migrated = mpm.migrate_lines(original)
        end_idx = migrated.index(mpm._END_MARKER)
        self.assertTrue(migrated[end_idx - 1].strip() == "AllowedIPs = 10.77.0.3/32")
        # only one [Peer] worth of lines between BEGIN and the second peer
        begin_idx = migrated.index(mpm._BEGIN_MARKER)
        self.assertEqual(migrated[begin_idx + 1].strip(), "[Peer]")

    def test_migrate_lines_rejects_malformed_input(self):
        with self.assertRaises(mpm.ConfigError):
            mpm.migrate_lines(["[Peer]", "PublicKey = A", "AllowedIPs = 10.77.0.2/32"])


class CliMigrateTests(TempConfMixin, unittest.TestCase):
    def test_migrate_happy_path_writes_new_file_output_has_no_privatekey_leak(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")

        rc, stdout, _stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 0)
        self.assertIn("MIGRATION_CANDIDATE_WRITTEN=", stdout)
        self.assertTrue(os.path.isfile(outp))

        migrated_text = self._read(outp)
        self.assertIn("# --- PEERS BEGIN ---", migrated_text)
        self.assertIn("# --- PEERS END ---", migrated_text)
        # PrivateKey is preserved BYTE-FOR-BYTE in the output file (this is
        # the one place the real value legitimately appears - the output
        # is the candidate config itself, not a log/report).
        self.assertIn(f"PrivateKey = {_SYNTHETIC_PRIVATE_KEY}", migrated_text)

    def test_migrate_refuses_same_input_output_path(self):
        inp = self._write("same.conf", "[Interface]\nPrivateKey = X\n")
        rc, _stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=inp))
        self.assertEqual(rc, 1)
        self.assertIn("different paths", stderr)

    def test_migrate_never_writes_output_on_malformed_input(self):
        inp = self._write("bad.conf", "[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n")
        outp = self._path("out.conf")
        rc, _stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(outp))

    def test_migrate_preserves_trailing_newline_behavior(self):
        with_nl = self._write("with_nl.conf", "[Interface]\nPrivateKey = X\n")
        out1 = self._path("out1.conf")
        _run(mpm.cmd_migrate, _Args(input=with_nl, output=out1))
        with open(out1, "rb") as f:
            self.assertTrue(f.read().endswith(b"\n"))

        without_nl = self._path("without_nl.conf")
        with open(without_nl, "w", encoding="utf-8", newline="\n") as f:
            f.write("[Interface]\nPrivateKey = X")  # no trailing \n
        out2 = self._path("out2.conf")
        _run(mpm.cmd_migrate, _Args(input=without_nl, output=out2))
        with open(out2, "rb") as f:
            self.assertFalse(f.read().endswith(b"\n"))


class CandidateSecureCreationTests(TempConfMixin, unittest.TestCase):
    """ORACLE-MIGRATION-DESIGN-1 output-hardening review: proves the
    candidate is created with restrictive permissions FROM CREATION (no
    open()-then-chmod window), fails closed on an existing path or an
    existing symlink WITHOUT following it, never truncates anything that
    was already there, cleans up after itself on a forced write failure,
    and never leaks a secret on any of these failure paths."""

    def _sentinel_source(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            return f.read()

    # --- A: mode 0600 from creation ---
    @unittest.skipUnless(os.name == "posix", "POSIX file mode bits are not meaningful on this platform")
    def test_a_new_candidate_is_mode_0600_immediately_after_migrate(self):
        inp = self._write("in.conf", self._sentinel_source())
        outp = self._path("out.conf")
        rc, _stdout, _stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 0)
        mode = stat.S_IMODE(os.stat(outp).st_mode)
        self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

    # --- B: existing output file causes failure, remains byte-for-byte unchanged ---
    def test_b_existing_output_file_rejected_and_left_untouched(self):
        inp = self._write("in.conf", self._sentinel_source())
        outp = self._write("out.conf", "PRE-EXISTING SENTINEL CONTENT - MUST NOT CHANGE\n")
        before = self._read(outp)

        rc, _stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 1)
        self.assertIn("already exists", stderr)

        after = self._read(outp)
        self.assertEqual(before, after, "pre-existing output content must be byte-for-byte unchanged")

    # --- C: symlink output path causes failure, symlink target unchanged ---
    def test_c_symlink_output_path_rejected_and_target_untouched(self):
        inp = self._write("in.conf", self._sentinel_source())
        target = self._write("real_target.conf", "SYMLINK TARGET SENTINEL - MUST NOT CHANGE\n")
        link_path = self._path("out_symlink.conf")
        try:
            os.symlink(target, link_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted in this environment")

        before = self._read(target)
        rc, _stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=link_path))
        self.assertEqual(rc, 1)
        self.assertIn("already exists", stderr)
        self.assertTrue(os.path.islink(link_path), "the symlink itself must not be replaced")

        after = self._read(target)
        self.assertEqual(before, after, "symlink TARGET content must be byte-for-byte unchanged - never written through")

    # --- D: input remains unchanged on every failure path ---
    def test_d_input_unchanged_after_malformed_input_failure(self):
        bad_text = "[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n"
        inp = self._write("bad.conf", bad_text)
        outp = self._path("out.conf")
        rc, _stdout, _stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 1)
        self.assertEqual(self._read(inp), bad_text)

    def test_d_input_unchanged_after_existing_output_failure(self):
        src = self._sentinel_source()
        inp = self._write("in.conf", src)
        outp = self._write("out.conf", "PRE-EXISTING\n")
        rc, _stdout, _stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 1)
        self.assertEqual(self._read(inp), src)

    def test_d_input_unchanged_after_symlink_output_failure(self):
        src = self._sentinel_source()
        inp = self._write("in.conf", src)
        target = self._write("real_target.conf", "TARGET\n")
        link_path = self._path("out_symlink.conf")
        try:
            os.symlink(target, link_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted in this environment")
        rc, _stdout, _stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=link_path))
        self.assertEqual(rc, 1)
        self.assertEqual(self._read(inp), src)

    # --- E: forced write failure does not truncate/modify the source, and
    # cleans up the partially-created candidate rather than leaving it
    # behind looking complete ---
    def test_e_forced_write_failure_cleans_up_candidate_and_leaves_source_untouched(self):
        src = self._sentinel_source()
        inp = self._write("in.conf", src)
        outp = self._path("out.conf")

        real_fdopen = os.fdopen

        class _FailingWriter:
            """Wraps the REAL fd (so it is still properly closed, never
            leaked) but makes .write() raise - exercises
            _write_candidate_exclusive's actual cleanup path rather than
            a fake that never touches the filesystem at all."""

            def __init__(self, fd):
                self._fd = fd

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                os.close(self._fd)
                return False

            def write(self, _data):
                raise OSError("simulated disk write failure")

        def failing_fdopen(fd, mode):
            return _FailingWriter(fd)

        with mock.patch.object(mpm.os, "fdopen", side_effect=failing_fdopen):
            rc, _stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))

        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(outp), "a failed write must not leave a partial candidate behind")
        self.assertEqual(self._read(inp), src, "source must be untouched by a downstream write failure")

    # --- F: secrets absent from stdout/stderr on every failure path above
    # (the with-PSK fixture, so both PrivateKey and PresharedKey are in
    # play) - _run() already asserts this on every call in this class, but
    # this test makes the requirement explicit and independent of that
    # helper's own implementation ---
    def test_f_no_secret_leak_across_all_failure_paths_with_psk_fixture(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src = f.read()
        inp = self._write("in.conf", src)

        outp1 = self._write("existing.conf", "X\n")
        rc, stdout, stderr = _run(mpm.cmd_migrate, _Args(input=inp, output=outp1))
        self.assertEqual(rc, 1)
        for secret in (_SYNTHETIC_PRIVATE_KEY, _SYNTHETIC_PRESHARED_KEY):
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)

        bad_inp = self._write("bad.conf", "[Peer]\nPublicKey = A\nAllowedIPs = 10.77.0.2/32\n")
        outp2 = self._path("out2.conf")
        rc, stdout, stderr = _run(mpm.cmd_migrate, _Args(input=bad_inp, output=outp2))
        self.assertEqual(rc, 1)
        for secret in (_SYNTHETIC_PRIVATE_KEY, _SYNTHETIC_PRESHARED_KEY):
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)


class CliVerifyTests(TempConfMixin, unittest.TestCase):
    def _migrate(self, src_text):
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        rc, _out, _err = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 0)
        return inp, outp

    def test_verify_passes_on_real_migration(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        rc, stdout, _stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0)
        self.assertIn("PRIVATE_KEY_UNCHANGED=YES", stdout)
        self.assertIn("SEMANTIC_EQUIVALENCE=YES", stdout)

    def test_verify_catches_privatekey_change(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace(_SYNTHETIC_PRIVATE_KEY, "DIFFERENTKEYVALUEFAKEFAKEFAKEFAKEFAKE00=")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("PrivateKey hash mismatch", stderr)

    def test_verify_catches_address_change(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("Address = 10.77.0.1/24", "Address = 10.77.0.99/24")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("Address", stderr)

    def test_verify_catches_peer_allowedips_change(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("AllowedIPs = 10.77.0.2/32", "AllowedIPs = 10.77.0.9/32")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("peer #0 changed", stderr)

    def test_verify_catches_dropped_peer(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        lines = self._read(outp).splitlines()
        # Remove the whole [Peer] block (3 lines: header + 2 fields)
        peer_idx = next(i for i, l in enumerate(lines) if l.strip() == "[Peer]")
        del lines[peer_idx:peer_idx + 3]
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("peer count changed", stderr)

    def test_verify_catches_awg_param_change(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("Jc = 0", "Jc = 6")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("Jc", stderr)


class CliDiffTests(TempConfMixin, unittest.TestCase):
    def test_diff_ok_when_only_markers_added(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        _run(mpm.cmd_migrate, _Args(input=inp, output=outp))

        rc, stdout, _stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0)
        self.assertIn("DIFF_POLICY_OK", stdout)
        self.assertIn("+# --- PEERS BEGIN ---", stdout)
        self.assertIn("+# --- PEERS END ---", stdout)
        # The diff must show the redaction placeholder for any PrivateKey
        # context line, never the real value, even though the real value
        # is identical on both sides (context lines are still redacted -
        # the policy is "never printed", not "only printed when it
        # differs").
        self.assertNotIn(_SYNTHETIC_PRIVATE_KEY, stdout)

    def test_diff_stops_on_extra_change(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        tampered = self._read(outp).replace("ListenPort = 51820", "ListenPort = 51821")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)

        rc, _stdout, stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("DIFF_POLICY_VIOLATION", stderr)

    def test_diff_redaction_hides_a_privatekey_change_from_diff_itself_by_design(self):
        # IMPORTANT DESIGN INVARIANT, proven here rather than just
        # asserted in a comment: redacting BOTH sides to the identical
        # placeholder before diffing means `diff` CANNOT distinguish "the
        # PrivateKey line is unchanged" from "it changed" - both redact to
        # the same text, so no PrivateKey difference ever reaches the
        # diff, in either direction. This is deliberate (the alternative -
        # comparing raw values to decide whether to show a diff line -
        # would mean the raw value transiently exists in a diff-shaped
        # comparison, which is exactly the exposure surface `diff` must
        # never have). It is also exactly why the transaction design
        # (section 6) requires BOTH `diff` AND `verify` before the human
        # approval gate: `verify`'s hash-based check is what actually
        # proves PrivateKey equality; `diff` proves only that nothing
        # ELSE changed. This test would fail loudly if `diff` were ever
        # "improved" to leak a comparison result for the redacted field.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        tampered = self._read(outp).replace(_SYNTHETIC_PRIVATE_KEY, "DIFFERENTVALUEFAKEFAKEFAKEFAKEFAKEFAKE0=")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)

        rc, stdout, stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0, "diff alone does not and must not detect a redacted-field change")
        self.assertNotIn(_SYNTHETIC_PRIVATE_KEY, stdout)
        self.assertNotIn(_SYNTHETIC_PRIVATE_KEY, stderr)
        self.assertNotIn("DIFFERENTVALUEFAKEFAKEFAKEFAKEFAKEFAKE0=", stdout)

        # verify() is the check that actually catches it:
        rc, _stdout, verify_stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("PrivateKey hash mismatch", verify_stderr)


class PresharedKeyTests(TempConfMixin, unittest.TestCase):
    def _migrate(self, src_text):
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        rc, _out, _err = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 0)
        return inp, outp

    def test_parse_conf_accepts_presharedkey(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        _interface, peers, _first, _last = mpm.parse_conf(lines)
        self.assertEqual(peers[0]["PresharedKey"], _SYNTHETIC_PRESHARED_KEY)

    def test_migrate_preserves_presharedkey_byte_for_byte(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src_text = f.read()
        _inp, outp = self._migrate(src_text)
        migrated_text = self._read(outp)
        self.assertIn(f"PresharedKey = {_SYNTHETIC_PRESHARED_KEY}", migrated_text)

    def test_verify_passes_with_presharedkey_unchanged(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        rc, stdout, _stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0)
        self.assertIn("SEMANTIC_EQUIVALENCE=YES", stdout)
        self.assertIn("BYTE_EQUIVALENCE_EXCEPT_MARKERS=YES", stdout)

    def test_verify_catches_presharedkey_change(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace(
            _SYNTHETIC_PRESHARED_KEY, "DIFFERENTPSKVALUEFAKEFAKEFAKEFAKEFAKEFAKE0="
        )
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("peer #0 changed", stderr)
        # The failure message must never contain the actual values on
        # either side of the mismatch.
        self.assertNotIn(_SYNTHETIC_PRESHARED_KEY, stderr)
        self.assertNotIn("DIFFERENTPSKVALUEFAKEFAKEFAKEFAKEFAKEFAKE0=", stderr)

    def test_diff_never_prints_presharedkey_even_when_unchanged(self):
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        rc, stdout, _stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0)
        self.assertNotIn(_SYNTHETIC_PRESHARED_KEY, stdout)
        self.assertIn("PresharedKey = <REDACTED>", stdout)

    def test_diff_redaction_hides_a_presharedkey_change_from_diff_itself(self):
        # Same invariant as the PrivateKey case (see
        # test_diff_redaction_hides_a_privatekey_change_from_diff_itself_
        # by_design in CliDiffTests): both sides redact to the identical
        # placeholder, so `diff` cannot and must not be relied on to
        # detect a PresharedKey change - `verify` is.
        with open(_LIVE_SHAPE_WITH_PSK, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace(
            _SYNTHETIC_PRESHARED_KEY, "DIFFERENTPSKVALUEFAKEFAKEFAKEFAKEFAKEFAKE0="
        )
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)

        rc, stdout, _stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0, "diff alone does not and must not detect a redacted-field change")

        rc, _stdout, verify_stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("peer #0 changed", verify_stderr)


class ByteEquivalenceExceptMarkersTests(TempConfMixin, unittest.TestCase):
    """The authoritative strongest invariant: with the two marker lines
    removed, migrated text must equal original text byte-for-byte. Every
    test here mutates a MIGRATED candidate in a way that a value-only
    field-level comparison would miss, and proves byte-equivalence still
    catches it."""

    def _migrate(self, src_text):
        inp = self._write("in.conf", src_text)
        outp = self._path("out.conf")
        rc, _out, _err = _run(mpm.cmd_migrate, _Args(input=inp, output=outp))
        self.assertEqual(rc, 0)
        return inp, outp

    def _assert_byte_equivalence_fails(self, inp, outp):
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("BYTE_EQUIVALENCE_EXCEPT_MARKERS=NO", stderr)
        self.assertIn("byte content differs beyond the two marker lines", stderr)

    def test_happy_path_reports_byte_equivalence_yes(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        rc, stdout, _stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 0)
        self.assertIn("BYTE_EQUIVALENCE_EXCEPT_MARKERS=YES", stdout)

    def test_whitespace_only_change_caught(self):
        # Field-level parsing strips whitespace around '=' and the value,
        # so "Address = X" vs "Address  =  X" parse to an IDENTICAL field
        # value - semantic equivalence alone would not catch this.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("Address = 10.77.0.1/24", "Address  =  10.77.0.1/24")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        self._assert_byte_equivalence_fails(inp, outp)

    def test_comment_change_caught(self):
        # parse_conf ignores comment lines entirely - a comment edit is
        # invisible to every field-level check.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace(
            "# AmneziaWG protocol parameters", "# AmneziaWG protocol parameters (edited)"
        )
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        self._assert_byte_equivalence_fails(inp, outp)

    def test_field_reordering_caught(self):
        # Interface fields are stored in a dict for the semantic check,
        # so swapping the order of two lines with unchanged values is
        # invisible to that check - byte-equivalence must catch it.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        lines = self._read(outp).splitlines()
        i_jc = lines.index("Jc = 0")
        i_jmin = lines.index("Jmin = 0")
        lines[i_jc], lines[i_jmin] = lines[i_jmin], lines[i_jc]
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        self._assert_byte_equivalence_fails(inp, outp)

    def test_peer_field_reordering_caught(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        lines = self._read(outp).splitlines()
        i_pub = next(i for i, l in enumerate(lines) if l.startswith("PublicKey"))
        i_allowed = next(i for i, l in enumerate(lines) if l.startswith("AllowedIPs"))
        lines[i_pub], lines[i_allowed] = lines[i_allowed], lines[i_pub]
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        self._assert_byte_equivalence_fails(inp, outp)

    def test_final_newline_change_caught(self):
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        text = self._read(outp)
        self.assertTrue(text.endswith("\n"))
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text.rstrip("\n"))  # drop the trailing newline
        self._assert_byte_equivalence_fails(inp, outp)

    def test_unknown_interface_field_added_is_rejected(self):
        # An unrecognized field causes parse_conf itself to reject the
        # migrated file before byte-equivalence is even reached - a
        # stronger (parse-level) rejection, exercised here to prove
        # `verify` still fails overall rather than silently ignoring an
        # unparseable migrated file.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("Address = 10.77.0.1/24", "Address = 10.77.0.1/24\nMysteryField = 1")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_verify, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("does not parse", stderr)

    def test_diff_policy_also_rejects_the_same_extra_changes(self):
        # Defense-in-depth cross-check: `diff`'s own additions/removals
        # policy independently rejects a non-marker change too, not just
        # `verify`'s byte-equivalence check.
        with open(_LIVE_SHAPE_ONE_PEER, "r", encoding="utf-8") as f:
            src_text = f.read()
        inp, outp = self._migrate(src_text)
        tampered = self._read(outp).replace("Jmin = 0", "Jmin = 5")
        with open(outp, "w", encoding="utf-8", newline="\n") as f:
            f.write(tampered)
        rc, _stdout, stderr = _run(mpm.cmd_diff, _Args(original=inp, migrated=outp))
        self.assertEqual(rc, 1)
        self.assertIn("DIFF_POLICY_VIOLATION", stderr)


if __name__ == "__main__":
    unittest.main()
