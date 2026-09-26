"""B8C1 - narrow tests for the activation/device-entitlement store and
decide_and_bind's core contract. Mirrors gateway/api/tests/test_tokens.py's
structure and gateway/tools/tests/test_enrollment_tokens.py's CLI-level
coverage in one file, since this module owns both halves.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from _fixtures import make_public_key


class ActivationTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "activations.json")
        self.lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.store_path, self.lock_path)
        self.key_a = make_public_key(0x10)
        self.key_b = make_public_key(0x20)


class IssueRevokeStatusTests(ActivationTestBase):
    def test_issue_returns_activation_id_and_never_persists_the_raw_credential(self):
        activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        self.assertRegex(activation_id, r"^[0-9a-f]{32}$")
        self.assertGreater(len(credential), 20)

        with open(self.store_path, "r", encoding="utf-8") as handle:
            raw_store_text = handle.read()
        # item 10: the raw credential must be absent from durable storage.
        self.assertNotIn(credential, raw_store_text)
        stored = json.loads(raw_store_text)
        self.assertIn(activations_module.credential_digest(credential), stored)

    def test_revoke_then_status_reflects_revoked(self):
        activation_id, _credential = activations_module.issue_activation(self.store_path, self.lock_path, 1)
        activations_module.revoke_activation(self.store_path, self.lock_path, activation_id)
        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, activation_id)
        self.assertEqual(record["status"], activations_module.REVOKED)


class DecideAndBindTests(ActivationTestBase):
    def test_valid_activation_first_device_succeeds(self):
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)

    def test_same_activation_same_key_is_idempotent_and_does_not_consume_a_slot(self):
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        first = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        second = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(first.outcome, activations_module.BOUND_NEW)
        self.assertEqual(second.outcome, activations_module.BOUND_EXISTING)
        self.assertEqual(second.reservation_id, "")  # owns nothing (item 5's own-nothing guarantee)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, first.activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)  # not duplicated
        self.assertEqual(record["bound_devices"][0]["public_key"], self.key_a)

    def test_one_device_activation_rejects_a_different_key_once_bound(self):
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        decision = activations_module.decide_and_bind(credential, self.key_b, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.DEVICE_LIMIT)

    def test_revoked_activation_is_rejected(self):
        activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, 1)
        activations_module.revoke_activation(self.store_path, self.lock_path, activation_id)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.REVOKED_OUTCOME)

    def test_expired_activation_is_rejected(self):
        _activation_id, credential = activations_module.issue_activation(
            self.store_path, self.lock_path, max_devices=1, expires_in_days=1,
        )
        far_future = datetime.now(timezone.utc) + timedelta(days=2)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path, now=far_future)
        self.assertEqual(decision.outcome, activations_module.EXPIRED)

    def test_not_yet_expired_activation_still_succeeds(self):
        _activation_id, credential = activations_module.issue_activation(
            self.store_path, self.lock_path, max_devices=1, expires_in_days=30,
        )
        soon = datetime.now(timezone.utc) + timedelta(days=1)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path, now=soon)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)

    def test_invalid_credential_is_rejected(self):
        activations_module.issue_activation(self.store_path, self.lock_path, 1)
        decision = activations_module.decide_and_bind("not-a-real-credential", self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.INVALID)

    def test_unbind_reservation_releases_a_slot_when_owned_and_still_pending(self):
        """item 4: normal provisioning failure, no concurrent same-key
        success in play - the owning request's rollback must actually free
        the slot."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        self.assertNotEqual(decision.reservation_id, "")

        activations_module.unbind_reservation(credential, self.key_a, decision.reservation_id, self.store_path, self.lock_path)

        # After rollback, the SAME key can be bound again as if for the first time.
        retried = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(retried.outcome, activations_module.BOUND_NEW)

    def test_unbind_reservation_with_wrong_owner_is_a_safe_noop(self):
        """A BOUND_EXISTING caller (empty reservation_id) or a stale/foreign
        reservation_id must never remove someone else's pending entry."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)

        activations_module.unbind_reservation(credential, self.key_a, "deadbeefdeadbeefdeadbeefdeadbeef", self.store_path, self.lock_path)
        activations_module.unbind_reservation(credential, self.key_a, "", self.store_path, self.lock_path)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, decision.activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)  # still there

    def test_finalize_after_unbind_reinserts_a_confirmed_entry(self):
        """The 'A rolls back before B finalizes' ordering from the B8C1A
        race analysis: finalize must still (re)record a real successful
        provisioning result even if the original pending entry is gone."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        activations_module.unbind_reservation(credential, self.key_a, decision.reservation_id, self.store_path, self.lock_path)

        result = activations_module.finalize_reservation(credential, self.key_a, self.store_path, self.lock_path)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, activations_module.ACTIVE)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, decision.activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)

    def test_restart_preserves_device_binding(self):
        """item 8: nothing in-process is relied on - a fresh call against
        the same durable store/lock paths (simulating a process restart,
        since decide_and_bind holds no module-level state at all) sees the
        SAME bound_devices."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)

        # Simulate "restart": a brand new call, no shared Python object
        # carried over, only the store_path/lock_path strings.
        decision_after_restart = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision_after_restart.outcome, activations_module.BOUND_EXISTING)

        rejected_after_restart = activations_module.decide_and_bind(credential, self.key_b, self.store_path, self.lock_path)
        self.assertEqual(rejected_after_restart.outcome, activations_module.DEVICE_LIMIT)


class ConcurrencyTests(ActivationTestBase):
    def test_two_concurrent_first_use_different_keys_cannot_both_win(self):
        """item 7: real OS-level flock contention, not a mock - two
        threads each open() their own file description on the same lock
        path and race decide_and_bind concurrently."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)

        results = []
        results_lock = threading.Lock()

        def attempt(key):
            decision = activations_module.decide_and_bind(credential, key, self.store_path, self.lock_path)
            with results_lock:
                results.append(decision.outcome)

        t1 = threading.Thread(target=attempt, args=(self.key_a,))
        t2 = threading.Thread(target=attempt, args=(self.key_b,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(sorted(results), sorted([activations_module.BOUND_NEW, activations_module.DEVICE_LIMIT]))

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)  # never both, never zero

    def test_B8C1A_race_concurrent_same_key_one_succeeds_one_fails_binding_survives(self):
        """items 1+2 - the EXACT reported race, reproduced deterministically
        in the adversarial order (A binds -> B sees existing -> B's
        provisioning succeeds and finalizes FIRST -> A's provisioning fails
        and rolls back SECOND): binding K must survive, and a later
        different key must still be rejected as device_limit_reached."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)

        # Request A: first to bind.
        decision_a = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision_a.outcome, activations_module.BOUND_NEW)

        # Request B: concurrent, same key - sees it already (pending).
        decision_b = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision_b.outcome, activations_module.BOUND_EXISTING)
        self.assertEqual(decision_b.reservation_id, "")

        # B's provisioning succeeds FIRST and finalizes.
        result_b = activations_module.finalize_reservation(credential, self.key_a, self.store_path, self.lock_path)
        self.assertTrue(result_b.confirmed)
        self.assertEqual(result_b.status, activations_module.ACTIVE)

        # A's provisioning THEN fails - A attempts to roll back ITS OWN reservation.
        activations_module.unbind_reservation(credential, self.key_a, decision_a.reservation_id, self.store_path, self.lock_path)

        # item 1: binding K must still be present and CONFIRMED - not wiped by A's rollback.
        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["public_key"], self.key_a)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)

        # item 2: a DIFFERENT key must still be rejected - the slot was never actually freed.
        decision_c = activations_module.decide_and_bind(credential, self.key_b, self.store_path, self.lock_path)
        self.assertEqual(decision_c.outcome, activations_module.DEVICE_LIMIT)

    def test_B8C1B_race_reserved_slot_reused_by_different_key_then_original_finalizes(self):
        """The exact A/B/C interleaving B8C1B reported:
          1. A reserves K1 (pending, R1)
          2. B (same K1) sees existing pending -> BOUND_EXISTING, provisioning in flight
          3. A's provisioning fails -> A rolls back R1 -> K1 entry removed, slot free
          4. C (different key K2) sees capacity available -> reserves K2 (pending, R3)
          5. B's provisioning succeeds -> B calls finalize_reservation(K1)
          Final durable state must contain EXACTLY ONE device (K2), never both -
          finalize must refuse to resurrect K1 past capacity, not blindly reinsert it."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)

        # 1. A reserves K1.
        decision_a = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision_a.outcome, activations_module.BOUND_NEW)

        # 2. B, same K1, sees it already pending.
        decision_b = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
        self.assertEqual(decision_b.outcome, activations_module.BOUND_EXISTING)

        # 3. A's provisioning fails - A rolls back its own reservation.
        activations_module.unbind_reservation(credential, self.key_a, decision_a.reservation_id, self.store_path, self.lock_path)
        record_after_rollback = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record_after_rollback["bound_devices"]), 0)  # slot genuinely free now

        # 4. C, a DIFFERENT key, sees capacity available and reserves it.
        key_c = make_public_key(0x30)
        decision_c = activations_module.decide_and_bind(credential, key_c, self.store_path, self.lock_path)
        self.assertEqual(decision_c.outcome, activations_module.BOUND_NEW)

        # 5. B's provisioning (for K1) succeeds - B finalizes.
        finalize_result_b = activations_module.finalize_reservation(credential, self.key_a, self.store_path, self.lock_path)
        self.assertFalse(finalize_result_b.confirmed)  # MUST refuse - capacity already reused

        # Final durable state: exactly one device (K2/key_c), never both.
        record_final = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record_final["bound_devices"]), 1)
        self.assertEqual(record_final["bound_devices"][0]["public_key"], key_c)
        self.assertLessEqual(len(record_final["bound_devices"]), record_final["max_devices"])

    def test_B8C1A_race_via_real_threads(self):
        """Same invariant as above, proven under genuine OS-level flock
        contention across two threads racing on the SAME key, rather than a
        hand-ordered sequence."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)

        decisions = []
        decisions_lock = threading.Lock()
        start_barrier = threading.Barrier(2)
        decision_barrier = threading.Barrier(2)

        def attempt():
            start_barrier.wait(timeout=10)
            decision = activations_module.decide_and_bind(credential, self.key_a, self.store_path, self.lock_path)
            with decisions_lock:
                decisions.append(decision)

            # Keep the first reservation present until BOTH racing calls
            # have completed decide_and_bind(). Without this barrier, the
            # BOUND_NEW owner may roll back before its peer has decided,
            # turning this test into two sequential BOUND_NEW attempts
            # instead of the same-key race it is intended to prove.
            decision_barrier.wait(timeout=10)

            if decision.reservation_id:
                # This thread owns the reservation - simulate its
                # provisioning FAILING and rolling back.
                activations_module.unbind_reservation(credential, self.key_a, decision.reservation_id, self.store_path, self.lock_path)
            else:
                # This thread doesn't own a reservation - simulate its
                # provisioning SUCCEEDING and finalizing.
                activations_module.finalize_reservation(credential, self.key_a, self.store_path, self.lock_path)

        t1 = threading.Thread(target=attempt)
        t2 = threading.Thread(target=attempt)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(len(decisions), 2)
        outcomes = sorted(d.outcome for d in decisions)
        self.assertEqual(outcomes, sorted([activations_module.BOUND_NEW, activations_module.BOUND_EXISTING]))

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        # Regardless of thread scheduling, the finalizing thread's success
        # must survive the owning thread's rollback.
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)


class CommitUncertainFaultInjectionTests(ActivationTestBase):
    """B67.4 corrective-pass fix, MAJOR BUG #2 - real persistence-boundary
    fault injection: `os.replace()` SUCCEEDS, the FOLLOWING containing-
    directory `os.fsync()` FAILS. This patches `os.fsync` itself (never
    `register_credential`/`_atomic_write_store` wholesale) so the test
    actually exercises the real boundary the bug lives at, not a generic
    stand-in exception."""

    def test_directory_fsync_failure_after_a_successful_replace_raises_commit_uncertain(self):
        credential = "commit-uncertain-boundary-test-credential-1"
        activation_id = "d" * 32
        real_fsync = os.fsync
        call_count = {"n": 0}

        def flaky_fsync(fd):
            call_count["n"] += 1
            if call_count["n"] == 2:
                # The 1st os.fsync() call inside _atomic_write_store is the
                # FILE fsync (before os.replace()) - must succeed, exactly
                # like a real write. The 2nd is the CONTAINING-DIRECTORY
                # fsync, called only AFTER os.replace() has already
                # succeeded - this is the one boundary this fix names.
                raise OSError("simulated containing-directory fsync failure")
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=flaky_fsync):
            with self.assertRaises(activations_module.ActivationCommitUncertainError):
                activations_module.register_credential(
                    self.store_path, self.lock_path, credential, activation_id, max_devices=1,
                )

        # The write DID durably happen from the filesystem's point of view -
        # os.replace() already succeeded before the directory fsync failed -
        # so the record must already be visible on disk, never silently lost.
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(credential),
        )
        self.assertIsNotNone(record, "os.replace() already succeeded - the record must be visible, not silently lost")
        self.assertEqual(record["activation_id"], activation_id)

        # A retry of the SAME (credential, activation_id) - exactly what a
        # real client retry looks like - must be a clean, idempotent
        # no-op: never a duplicate record, never an exception.
        result = activations_module.register_credential(
            self.store_path, self.lock_path, credential, activation_id, max_devices=1,
        )
        self.assertFalse(result.created)
        self.assertEqual(result.activation_id, activation_id)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1, "a retry after a commit-uncertain write must never mint a duplicate record")

    def test_file_fsync_failure_before_replace_is_an_ordinary_store_error_not_commit_uncertain(self):
        """The OTHER boundary, for contrast: a failure BEFORE os.replace()
        (the file's own fsync) means nothing durable happened at all -
        this must stay a plain ActivationStoreError, never
        ActivationCommitUncertainError, and the store must be completely
        untouched."""
        credential = "ordinary-failure-boundary-test-credential-1"
        activation_id = "e" * 32
        real_fsync = os.fsync
        call_count = {"n": 0}

        def flaky_fsync(fd):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated file fsync failure, before os.replace()")
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=flaky_fsync):
            with self.assertRaises(activations_module.ActivationStoreError) as ctx:
                activations_module.register_credential(
                    self.store_path, self.lock_path, credential, activation_id, max_devices=1,
                )
        self.assertNotIsInstance(ctx.exception, activations_module.ActivationCommitUncertainError)

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(credential),
        )
        self.assertIsNone(record, "nothing durable happened before os.replace() - the store must be completely untouched")

    def test_directory_open_failure_after_a_successful_replace_is_commit_uncertain(self):
        """B67.4 THIRD corrective-pass fix - the os.open(directory, ...)
        call itself, not merely its later fsync, is now inside the
        post-replace commit-uncertain boundary. Patches os.open itself
        (never register_credential/_atomic_write_store wholesale), and
        only for the EXACT (directory, O_RDONLY) call _atomic_write_store
        makes - every other os.open call in this same code path (mkstemp's
        own O_CREAT|O_RDWR temp-file open, the lock file's own open) must
        keep working normally, or the write could never reach os.replace()
        in the first place."""
        credential = "open-failure-boundary-test-credential-1"
        activation_id = "9" * 32
        directory = os.path.dirname(os.path.abspath(self.store_path)) or "."
        real_open = os.open

        def flaky_open(path, flags, *args, **kwargs):
            if path == directory and flags == os.O_RDONLY:
                raise OSError("simulated containing-directory open failure, after a successful os.replace()")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=flaky_open):
            with self.assertRaises(activations_module.ActivationCommitUncertainError):
                activations_module.register_credential(
                    self.store_path, self.lock_path, credential, activation_id, max_devices=1,
                )

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(credential),
        )
        self.assertIsNotNone(
            record, "os.replace() already succeeded before the directory-open failure - the record must be visible",
        )
        self.assertEqual(record["activation_id"], activation_id)

        # Retry with the real os.open restored - must reconcile cleanly,
        # never mint a duplicate.
        result = activations_module.register_credential(
            self.store_path, self.lock_path, credential, activation_id, max_devices=1,
        )
        self.assertFalse(result.created)
        self.assertEqual(result.activation_id, activation_id)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1)

    def test_directory_close_failure_after_a_successful_fsync_is_commit_uncertain(self):
        """B67.4 THIRD corrective-pass fix - a close()-time failure on the
        directory fd, occurring AFTER its own fsync() already succeeded,
        must be classified identically to an open or fsync failure -
        never left to escape as a plain, unclassified OSError from a bare
        `finally: os.close(dir_fd)`. Simulates the realistic case where
        close() itself still releases the fd (as it does on Linux) but
        also reports a failure via its return/errno."""
        credential = "close-failure-boundary-test-credential-1"
        activation_id = "8" * 32
        directory = os.path.dirname(os.path.abspath(self.store_path)) or "."
        real_open = os.open
        real_close = os.close
        captured_dir_fd = {}

        def instrumented_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if path == directory and flags == os.O_RDONLY:
                captured_dir_fd["fd"] = fd
            return fd

        def flaky_close(fd):
            if fd == captured_dir_fd.get("fd"):
                captured_dir_fd.pop("fd", None)
                real_close(fd)  # the fd IS actually released, same as a real close() that still reports failure
                raise OSError("simulated containing-directory close failure, after a successful fsync")
            return real_close(fd)

        with mock.patch("os.open", side_effect=instrumented_open), mock.patch("os.close", side_effect=flaky_close):
            with self.assertRaises(activations_module.ActivationCommitUncertainError):
                activations_module.register_credential(
                    self.store_path, self.lock_path, credential, activation_id, max_devices=1,
                )

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(credential),
        )
        self.assertIsNotNone(
            record, "os.replace() and the directory fsync already succeeded - the record must be visible",
        )
        self.assertEqual(record["activation_id"], activation_id)

        result = activations_module.register_credential(
            self.store_path, self.lock_path, credential, activation_id, max_devices=1,
        )
        self.assertFalse(result.created)
        self.assertEqual(result.activation_id, activation_id)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1)


if __name__ == "__main__":
    unittest.main()
