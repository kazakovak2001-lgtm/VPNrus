import argparse
import base64
import contextlib
import fcntl
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_GATEWAY_DIR = os.path.abspath(os.path.join(_TOOLS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import enrollment_tokens
from api import tokens as tokens_module


def _make_public_key(byte=0x01):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def _run(argv):
    """Invoke enrollment_tokens.main() in-process, capturing stdout/stderr
    separately and translating SystemExit into a plain exit code - avoids
    a real subprocess per test while still exercising the actual CLI
    entry point (argument parsing included, not just the cmd_* functions
    directly)."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = 0
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            enrollment_tokens.main(argv)
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return stdout.getvalue(), stderr.getvalue(), exit_code


def _run_subprocess(argv):
    """Like _run(), but as a genuinely separate OS process via
    subprocess.run(). contextlib.redirect_stdout/redirect_stderr swap the
    process-global sys.stdout/sys.stderr, which is NOT thread-safe - two
    threads calling _run() concurrently would race on which thread's
    StringIO captures which output. Tests that launch multiple CLI
    invocations concurrently (to exercise real LOCK_EX serialization) use
    this instead, sidestepping that race entirely - and, as a bonus, more
    faithfully models how independent operator invocations (or a future
    real deployment) actually run: as separate processes, never sharing
    interpreter-global state."""
    result = subprocess.run(
        [sys.executable, enrollment_tokens.__file__, *argv],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout, result.stderr, result.returncode


class EnrollmentTokensTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "enrollment-tokens.json")
        self.lock_path = os.path.join(self._tmp.name, ".tokens.lock")

    def _argv(self, *rest):
        return ["--store", self.store_path, "--lock", self.lock_path, *rest]

    def _init(self):
        out, err, rc = _run(self._argv("init"))
        self.assertEqual(rc, 0, err)
        return out, err

    def _issue(self, public_key=None):
        public_key = public_key or _make_public_key()
        out, err, rc = _run(self._argv("issue", public_key))
        self.assertEqual(rc, 0, err)
        token = out.rstrip("\n")
        return token, public_key, err

    def _read_store(self):
        with open(self.store_path, "r", encoding="utf-8") as handle:
            return json.load(handle)


# ============================================================
# INIT
# ============================================================
class InitTests(EnrollmentTokensTestCase):
    def test_init_creates_lock_and_empty_store(self):
        self._init()
        self.assertTrue(os.path.isfile(self.lock_path))
        self.assertTrue(os.path.isfile(self.store_path))
        self.assertEqual(self._read_store(), {})

    def test_repeated_init_is_idempotent(self):
        self._init()
        out1, err1, rc1 = _run(self._argv("init"))
        self.assertEqual(rc1, 0, err1)
        self.assertIn("already initialized", out1)
        self.assertEqual(self._read_store(), {})

    def test_init_does_not_erase_existing_records(self):
        self._init()
        token, public_key, _err = self._issue()
        before = self._read_store()
        self.assertEqual(len(before), 1)

        out, err, rc = _run(self._argv("init"))
        self.assertEqual(rc, 0, err)
        after = self._read_store()
        self.assertEqual(before, after)

    def test_init_refuses_to_touch_invalid_existing_store(self):
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        with open(self.store_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        out, err, rc = _run(self._argv("init"))
        self.assertNotEqual(rc, 0)
        with open(self.store_path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "{not valid json")

    def test_init_existing_0600_store_succeeds_unchanged(self):
        self._init()
        os.chmod(self.store_path, 0o600)
        before = self._raw_store_bytes()

        out, err, rc = _run(self._argv("init"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._raw_store_bytes(), before)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o600)

    def test_init_existing_0640_store_succeeds_unchanged(self):
        self._init()
        os.chmod(self.store_path, 0o640)
        before = self._raw_store_bytes()

        out, err, rc = _run(self._argv("init"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._raw_store_bytes(), before)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o640)

    def test_init_existing_0644_store_fails_nonzero(self):
        self._init()
        os.chmod(self.store_path, 0o644)

        out, err, rc = _run(self._argv("init"))
        self.assertNotEqual(rc, 0)

    def test_init_existing_0660_store_fails_nonzero(self):
        self._init()
        os.chmod(self.store_path, 0o660)

        out, err, rc = _run(self._argv("init"))
        self.assertNotEqual(rc, 0)

    def test_init_unsafe_mode_failure_does_not_chmod_store(self):
        self._init()
        os.chmod(self.store_path, 0o644)

        out, err, rc = _run(self._argv("init"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o644)

    def test_init_unsafe_mode_failure_leaves_records_byte_for_byte_unchanged(self):
        self._init()
        self._issue()
        os.chmod(self.store_path, 0o644)
        before = self._raw_store_bytes()

        out, err, rc = _run(self._argv("init"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(self._raw_store_bytes(), before)

    def _raw_store_bytes(self):
        with open(self.store_path, "rb") as handle:
            return handle.read()


# ============================================================
# ISSUE
# ============================================================
class IssueTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def test_issue_creates_active_record(self):
        token, public_key, _err = self._issue()
        digest = tokens_module.token_digest(token)
        store = self._read_store()
        self.assertIn(digest, store)
        record = store[digest]
        self.assertEqual(record["status"], tokens_module.ACTIVE)
        self.assertEqual(record["expected_public_key"], public_key)

    def test_bearer_token_entropy_at_least_256_bits(self):
        token, _pk, _err = self._issue()
        # secrets.token_urlsafe(32) base64url-decodes back to exactly 32
        # raw bytes = 256 bits, once standard padding is restored.
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        self.assertGreaterEqual(len(decoded), 32)

    def test_issue_stdout_is_exactly_token_and_newline(self):
        public_key = _make_public_key()
        out, err, rc = _run(self._argv("issue", public_key))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("\n"), 1)
        self.assertTrue(out.endswith("\n"))
        token = out[:-1]
        self.assertNotIn("\n", token)
        self.assertNotIn("TOKEN=", out)
        self.assertNotIn("Bearer", out)
        self.assertNotIn("created", out.lower())

    def test_plaintext_token_absent_from_store(self):
        token, _pk, _err = self._issue()
        with open(self.store_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn(token, raw)

    def test_plaintext_token_absent_from_stderr(self):
        token, _pk, err = self._issue()
        self.assertNotIn(token, err)

    def test_digest_key_equals_token_digest(self):
        token, _pk, _err = self._issue()
        store = self._read_store()
        self.assertIn(tokens_module.token_digest(token), store)

    def test_token_id_is_32_lowercase_hex(self):
        token, _pk, _err = self._issue()
        digest = tokens_module.token_digest(token)
        record = self._read_store()[digest]
        self.assertRegex(record["token_id"], r"^[0-9a-f]{32}$")

    def test_token_id_unique_across_issues(self):
        _t1, pk1, _e1 = self._issue(_make_public_key(0x01))
        _t2, pk2, _e2 = self._issue(_make_public_key(0x02))
        store = self._read_store()
        token_ids = [record["token_id"] for record in store.values()]
        self.assertEqual(len(token_ids), len(set(token_ids)))

    def test_invalid_public_key_rejected(self):
        out, err, rc = _run(self._argv("issue", "not-a-valid-key"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertEqual(self._read_store(), {})

    def test_concurrent_issue_no_lost_update(self):
        results = [None, None]

        def worker(index, seed_byte):
            out, err, rc = _run_subprocess(self._argv("issue", _make_public_key(seed_byte)))
            results[index] = (out.rstrip("\n"), rc)

        t1 = threading.Thread(target=worker, args=(0, 0x11))
        t2 = threading.Thread(target=worker, args=(1, 0x22))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        self.assertFalse(t1.is_alive(), "issue #1 did not complete - possible deadlock")
        self.assertFalse(t2.is_alive(), "issue #2 did not complete - possible deadlock")

        (token1, rc1), (token2, rc2) = results
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertNotEqual(token1, token2)
        store = self._read_store()
        self.assertEqual(len(store), 2)
        digests = {tokens_module.token_digest(token1), tokens_module.token_digest(token2)}
        self.assertEqual(digests, set(store.keys()))


# ============================================================
# REVOKE
# ============================================================
class RevokeTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def test_revoke_active_to_revoked(self):
        token, _pk, _err = self._issue()
        digest = tokens_module.token_digest(token)
        token_id = self._read_store()[digest]["token_id"]

        out, err, rc = _run(self._argv("revoke", token_id))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._read_store()[digest]["status"], tokens_module.REVOKED)

    def test_revoke_already_revoked_is_idempotent(self):
        token, _pk, _err = self._issue()
        digest = tokens_module.token_digest(token)
        token_id = self._read_store()[digest]["token_id"]
        _run(self._argv("revoke", token_id))

        before = self._read_store()
        out, err, rc = _run(self._argv("revoke", token_id))
        self.assertEqual(rc, 0, err)
        self.assertIn("already", out.lower())
        after = self._read_store()
        self.assertEqual(before, after)

    def test_revoke_unknown_token_id_fails_nonzero(self):
        out, err, rc = _run(self._argv("revoke", "a" * 32))
        self.assertNotEqual(rc, 0)

    def test_revoke_malformed_token_id_rejected(self):
        for bad in ("too-short", "G" * 32, "a" * 31, "a" * 33, ""):
            with self.subTest(bad=bad):
                out, err, rc = _run(self._argv("revoke", bad))
                self.assertNotEqual(rc, 0)

    def test_revoke_command_has_no_bearer_token_argument(self):
        # Structural proof, not just behavioral: the revoke subcommand's
        # argparse definition accepts exactly one positional (token_id),
        # nothing that could be a bearer token.
        parser = enrollment_tokens.build_parser()
        subparsers_action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        revoke_parser = subparsers_action.choices["revoke"]
        positional_dests = [a.dest for a in revoke_parser._actions if not a.option_strings]
        self.assertEqual(positional_dests, ["token_id"])


# ============================================================
# LIST / STATUS
# ============================================================
class ListStatusTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def test_list_deterministic_order(self):
        self._issue(_make_public_key(0x01))
        self._issue(_make_public_key(0x02))
        self._issue(_make_public_key(0x03))
        out1, _e1, rc1 = _run(self._argv("list"))
        out2, _e2, rc2 = _run(self._argv("list"))
        self.assertEqual(rc1, 0)
        self.assertEqual(out1, out2)

        store = self._read_store()
        expected_order = sorted(record["token_id"] for record in store.values())
        listed_order = [line.split()[0].split("=", 1)[1] for line in out1.strip().splitlines()]
        self.assertEqual(listed_order, expected_order)

    def test_list_full_digest_absent(self):
        token, _pk, _err = self._issue()
        digest = tokens_module.token_digest(token)
        out, _err, rc = _run(self._argv("list"))
        self.assertEqual(rc, 0)
        self.assertNotIn(digest, out)

    def test_list_plaintext_token_absent(self):
        token, _pk, _err = self._issue()
        out, _err, rc = _run(self._argv("list"))
        self.assertNotIn(token, out)

    def test_status_by_exact_token_id(self):
        token, public_key, _err = self._issue()
        digest = tokens_module.token_digest(token)
        token_id = self._read_store()[digest]["token_id"]
        out, err, rc = _run(self._argv("status", token_id))
        self.assertEqual(rc, 0, err)
        self.assertIn(token_id, out)
        self.assertIn("ACTIVE", out)
        self.assertIn(public_key[:8], out)
        self.assertNotIn(public_key, out)  # prefix only, not the full key

    def test_status_unknown_token_id_fails(self):
        out, err, rc = _run(self._argv("status", "a" * 32))
        self.assertNotEqual(rc, 0)

    def test_duplicate_token_id_corrupted_store_fails_closed_for_list(self):
        shared_id = "c" * 32
        pubkey_a = _make_public_key(0x30)
        pubkey_b = _make_public_key(0x31)
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    tokens_module.token_digest("x1"): {
                        "token_id": shared_id, "expected_public_key": pubkey_a, "status": "ACTIVE"
                    },
                    tokens_module.token_digest("x2"): {
                        "token_id": shared_id, "expected_public_key": pubkey_b, "status": "ACTIVE"
                    },
                },
                handle,
            )
        out, err, rc = _run(self._argv("list"))
        self.assertNotEqual(rc, 0)


# ============================================================
# DURABILITY
# ============================================================
class DurabilityTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def test_temp_file_created_in_same_directory(self):
        seen_dirs = []
        original_mkstemp = tempfile.mkstemp

        def spying_mkstemp(*args, **kwargs):
            result = original_mkstemp(*args, **kwargs)
            seen_dirs.append(kwargs.get("dir"))
            return result

        with mock.patch("enrollment_tokens.tempfile.mkstemp", side_effect=spying_mkstemp):
            self._issue()

        self.assertEqual(seen_dirs, [os.path.dirname(os.path.abspath(self.store_path))])

    def test_fsync_called_before_replace_and_directory_fsync_after(self):
        call_order = []
        real_fsync = os.fsync
        real_replace = os.replace

        def spying_fsync(fd):
            call_order.append("fsync")
            return real_fsync(fd)

        def spying_replace(src, dst):
            call_order.append("replace")
            return real_replace(src, dst)

        with mock.patch("enrollment_tokens.os.fsync", side_effect=spying_fsync), mock.patch(
            "enrollment_tokens.os.replace", side_effect=spying_replace
        ):
            self._issue()

        # fsync(temp file), replace, fsync(directory) - temp-file fsync
        # strictly before replace, directory fsync strictly after.
        self.assertEqual(call_order, ["fsync", "replace", "fsync"])

    def test_write_failure_leaves_prior_store_intact(self):
        self._issue(_make_public_key(0x40))
        before = self._read_store()

        with mock.patch("enrollment_tokens.os.replace", side_effect=OSError("simulated disk failure")):
            out, err, rc = _run(self._argv("issue", _make_public_key(0x41)))
        self.assertNotEqual(rc, 0)

        after = self._read_store()
        self.assertEqual(before, after)
        # No stray temp file left behind either.
        leftovers = [
            name
            for name in os.listdir(os.path.dirname(self.store_path))
            if name.startswith(".enrollment-tokens.")
        ]
        self.assertEqual(leftovers, [])

    def test_no_partial_json_ever_observable_during_concurrent_writes(self):
        stop = threading.Event()
        saw_invalid = []

        def reader():
            while not stop.is_set():
                try:
                    with open(self.store_path, "r", encoding="utf-8") as handle:
                        raw = handle.read()
                    if raw:
                        json.loads(raw)
                except (json.JSONDecodeError, FileNotFoundError, OSError):
                    saw_invalid.append(True)

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        try:
            for i in range(8):
                self._issue(_make_public_key(0x50 + i))
        finally:
            stop.set()
            reader_thread.join(timeout=10)

        self.assertEqual(saw_invalid, [], "a reader observed invalid/partial JSON mid-write")


def _leftover_temp_files(directory):
    return [name for name in os.listdir(directory) if name.startswith(".enrollment-tokens.")]


# ============================================================
# OWNERSHIP / MODE PRESERVATION (fail-closed review corrections)
# ============================================================
class OwnershipModePreservationTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def test_chown_failure_leaves_old_store_unchanged(self):
        token1, _pk1, _err1 = self._issue(_make_public_key(0x80))
        before_bytes = self._raw_store_bytes()
        before_mode = os.stat(self.store_path).st_mode

        with mock.patch("enrollment_tokens.os.chown", side_effect=PermissionError("simulated")):
            out, err, rc = _run(self._argv("issue", _make_public_key(0x81)))

        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "", "no token may be printed when durable publication failed")
        self.assertEqual(self._raw_store_bytes(), before_bytes)
        self.assertEqual(os.stat(self.store_path).st_mode, before_mode)
        self.assertEqual(_leftover_temp_files(self._tmp.name), [])

    def test_chmod_failure_leaves_old_store_unchanged(self):
        token1, _pk1, _err1 = self._issue(_make_public_key(0x82))
        before_bytes = self._raw_store_bytes()
        before_mode = os.stat(self.store_path).st_mode

        with mock.patch("enrollment_tokens.os.chmod", side_effect=PermissionError("simulated")):
            out, err, rc = _run(self._argv("issue", _make_public_key(0x83)))

        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertEqual(self._raw_store_bytes(), before_bytes)
        self.assertEqual(os.stat(self.store_path).st_mode, before_mode)
        self.assertEqual(_leftover_temp_files(self._tmp.name), [])

    def test_unsafe_existing_mode_0644_rejected(self):
        self._issue(_make_public_key(0x84))
        before_bytes = self._raw_store_bytes()
        os.chmod(self.store_path, 0o644)

        out, err, rc = _run(self._argv("issue", _make_public_key(0x85)))

        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertEqual(self._raw_store_bytes(), before_bytes)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o644)
        self.assertEqual(_leftover_temp_files(self._tmp.name), [])

    def test_unsafe_existing_mode_0660_rejected(self):
        self._issue(_make_public_key(0x86))
        before_bytes = self._raw_store_bytes()
        os.chmod(self.store_path, 0o660)

        out, err, rc = _run(self._argv("issue", _make_public_key(0x87)))

        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertEqual(self._raw_store_bytes(), before_bytes)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o660)

    def test_safe_mode_0600_preserved_exactly(self):
        self._issue(_make_public_key(0x88))
        os.chmod(self.store_path, 0o600)

        out, err, rc = _run(self._argv("issue", _make_public_key(0x89)))
        self.assertEqual(rc, 0, err)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o600)

    def test_safe_mode_0640_preserved_exactly(self):
        self._issue(_make_public_key(0x8A))
        os.chmod(self.store_path, 0o640)

        out, err, rc = _run(self._argv("issue", _make_public_key(0x8B)))
        self.assertEqual(rc, 0, err)
        self.assertEqual(os.stat(self.store_path).st_mode & 0o777, 0o640)

    def _raw_store_bytes(self):
        with open(self.store_path, "rb") as handle:
            return handle.read()


# ============================================================
# INIT CONCURRENCY
# ============================================================
class InitConcurrencyTests(EnrollmentTokensTestCase):
    def test_concurrent_init_init_no_corruption(self):
        results = []

        def worker():
            out, err, rc = _run_subprocess(self._argv("init"))
            results.append(rc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        for t in threads:
            self.assertFalse(t.is_alive(), "an init call did not complete - possible deadlock")

        self.assertTrue(all(rc == 0 for rc in results), results)
        with open(self.store_path, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {})

    def test_concurrent_init_preserves_existing_records(self):
        out, err, rc = _run(self._argv("init"))
        self.assertEqual(rc, 0, err)
        token, public_key, _err = self._issue()
        digest = tokens_module.token_digest(token)
        before = self._read_store()

        def worker():
            _run_subprocess(self._argv("init"))

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        after = self._read_store()
        self.assertEqual(before, after)
        self.assertIn(digest, after)

    def test_init_racing_issue_never_loses_or_corrupts_state(self):
        # Neither the lock nor the store exists yet - init and issue are
        # launched together. Every outcome in the docstring's own
        # contract is acceptable EXCEPT a corrupted/partial store or a
        # hung process.
        public_key = _make_public_key(0x90)
        outcomes = {}

        def do_init():
            out, err, rc = _run_subprocess(self._argv("init"))
            outcomes["init"] = rc

        def do_issue():
            out, err, rc = _run_subprocess(self._argv("issue", public_key))
            outcomes["issue"] = (rc, out.strip())

        t_init = threading.Thread(target=do_init)
        t_issue = threading.Thread(target=do_issue)
        t_init.start()
        t_issue.start()
        t_init.join(timeout=15)
        t_issue.join(timeout=15)
        self.assertFalse(t_init.is_alive(), "init did not complete - possible deadlock")
        self.assertFalse(t_issue.is_alive(), "issue did not complete - possible deadlock")

        self.assertEqual(outcomes["init"], 0)
        with open(self.store_path, "r", encoding="utf-8") as handle:
            store = json.load(handle)  # must always be valid JSON - never partial/corrupt

        issue_rc, issue_token = outcomes["issue"]
        if issue_rc == 0:
            # issue cleanly waited for init and then succeeded.
            digest = tokens_module.token_digest(issue_token)
            self.assertIn(digest, store)
            self.assertEqual(store[digest]["expected_public_key"], public_key)
        else:
            # issue cleanly failed before/without initialization ever
            # completing for it - the store must be empty, never a
            # half-written record.
            self.assertEqual(store, {})


# ============================================================
# LOCKING (writer LOCK_EX vs. reader LOCK_SH serialization)
# ============================================================
class LockingTests(EnrollmentTokensTestCase):
    def setUp(self):
        super().setUp()
        self._init()

    def _hold_lock_in_background(self, exclusive, hold_seconds):
        ready = threading.Event()
        released_at = []

        def hold():
            fd = os.open(self.lock_path, os.O_RDWR if exclusive else os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                ready.set()
                time.sleep(hold_seconds)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                released_at.append(time.monotonic())
                os.close(fd)

        thread = threading.Thread(target=hold)
        thread.start()
        assert ready.wait(timeout=5), "background lock holder never acquired its lock"
        return thread, released_at

    def test_writer_uses_lock_ex(self):
        # A held LOCK_EX (even a plain flock from outside this codebase)
        # must block a second LOCK_EX attempt - proves the writer's lock
        # mode is genuinely exclusive, not shared.
        holder, _released = self._hold_lock_in_background(exclusive=True, hold_seconds=0.6)
        start = time.monotonic()
        out, err, rc = _run(self._argv("issue", _make_public_key(0x60)))
        elapsed = time.monotonic() - start
        holder.join(timeout=5)
        self.assertEqual(rc, 0, err)
        self.assertGreaterEqual(elapsed, 0.5, "issue did not wait for the held LOCK_EX")

    def test_active_reader_serializes_writer(self):
        holder, released_at = self._hold_lock_in_background(exclusive=False, hold_seconds=0.6)
        start = time.monotonic()
        out, err, rc = _run(self._argv("issue", _make_public_key(0x61)))
        elapsed = time.monotonic() - start
        holder.join(timeout=5)
        self.assertEqual(rc, 0, err)
        self.assertGreaterEqual(elapsed, 0.5, "writer (LOCK_EX) did not wait for an active LOCK_SH reader")
        self.assertTrue(released_at)
        self.assertGreaterEqual(time.monotonic() - released_at[0], 0)

    def test_active_writer_serializes_reader(self):
        holder, _released = self._hold_lock_in_background(exclusive=True, hold_seconds=0.6)
        start = time.monotonic()
        result = tokens_module.read_store_shared(self.store_path, self.lock_path)
        elapsed = time.monotonic() - start
        holder.join(timeout=5)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(elapsed, 0.5, "reader (LOCK_SH) did not wait for an active LOCK_EX writer")

    def test_bounded_concurrency_cannot_deadlock(self):
        # Two readers and two writers, all launched together, all must
        # finish within a generous bounded timeout - a real deadlock would
        # hang the test indefinitely without join(timeout=...).
        errors = []

        def do_issue(seed):
            try:
                out, err, rc = _run_subprocess(self._argv("issue", _make_public_key(seed)))
                if rc != 0:
                    errors.append(err)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(str(exc))

        def do_read():
            try:
                tokens_module.read_store_shared(self.store_path, self.lock_path)
            except tokens_module.TokenLookupError:
                pass  # store may be briefly absent-of-content race in this synthetic test; not a hang
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(str(exc))

        threads = [
            threading.Thread(target=do_issue, args=(0x70,)),
            threading.Thread(target=do_issue, args=(0x71,)),
            threading.Thread(target=do_read),
            threading.Thread(target=do_read),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        for t in threads:
            self.assertFalse(t.is_alive(), "a thread did not complete - possible deadlock")
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
