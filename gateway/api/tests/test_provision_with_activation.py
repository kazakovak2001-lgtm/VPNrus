"""B8C1C - narrow tests proving the per-activation lock actually serializes
the external, irreversible run_provision_peer() side effect itself, not
just the JSON store's bookkeeping - using the real fake provisioning
script and wall-clock timing/interval-overlap checks (not just outcome
assertions), so "did two provisioning attempts for the SAME activation
ever run concurrently" is actually proven, not assumed.
"""
import os
import stat
import sys
import tempfile
import threading
import time
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from _fixtures import make_public_key, set_plan, write_fake_provision_script


def write_logging_provision_script(tmp_dir, log_path, sleep_seconds=0.6):
    """A dedicated fake provisioning script (NOT the shared FAKE_SCRIPT_BODY
    fixture, to avoid touching a file many other passing tests depend on)
    that logs the REAL wall-clock start/end of each invocation to
    `log_path` before/after sleeping - this is what lets the tests below
    prove serialization/concurrency of the actual external side effect
    itself, not just Python-level call-issuance timestamps (which include
    lock-wait queueing time and would produce a false "overlap" for a
    correctly-serialized pair - see this file's own history/comments).
    Each `echo` is one small, POSIX-atomic append write, so concurrent
    invocations' START/END lines never interleave mid-line.
    """
    path = os.path.join(tmp_dir, "logging-provision-peer.sh")
    body = (
        "#!/usr/bin/env bash\n"
        f'echo "START $(date +%s.%N)" >> "{log_path}"\n'
        f"sleep {sleep_seconds}\n"
        f'echo "END $(date +%s.%N)" >> "{log_path}"\n'
        "printf 'created\\t10.77.0.2\\n'\n"
        "exit 0\n"
    )
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def read_logged_intervals(log_path):
    """Parses START/END lines into a list of (start, end) float-timestamp
    tuples, one per script invocation, ordered by their own start time."""
    starts, ends = [], []
    with open(log_path, "r", encoding="utf-8") as handle:
        for line in handle:
            kind, ts = line.split()
            (starts if kind == "START" else ends).append(float(ts))
    starts.sort()
    ends.sort()
    assert len(starts) == len(ends), f"mismatched START/END counts: {len(starts)} vs {len(ends)}"
    return list(zip(starts, ends))


def intervals_overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


class ProvisionWithActivationTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "activations.json")
        self.lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.store_path, self.lock_path)

        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path

        self.key_a = make_public_key(0x40)
        self.key_b = make_public_key(0x50)

    def _provision(self, credential, public_key):
        return activations_module.provision_with_activation(
            credential, public_key, self.store_path, self.lock_path,
            self.script_path, subprocess_timeout_seconds=5.0,
        )


class SameActivationSerializationTests(ProvisionWithActivationTestBase):
    def test_concurrent_same_key_requests_serialize_end_to_end(self):
        """item 2: two requests for the SAME activation and the SAME key -
        the ACTUAL provisioning-subprocess execution windows (logged by the
        script itself, not measured around the Python call, which would
        also count lock-wait queueing time and falsely look like overlap
        for a correctly-serialized pair) must never overlap."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        log_path = os.path.join(self._tmp.name, "invocations.log")
        script_path = write_logging_provision_script(self._tmp.name, log_path, sleep_seconds=0.6)

        def provision():
            return activations_module.provision_with_activation(
                credential, self.key_a, self.store_path, self.lock_path, script_path, subprocess_timeout_seconds=5.0,
            )

        t1 = threading.Thread(target=provision)
        t2 = threading.Thread(target=provision)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        logged = read_logged_intervals(log_path)
        self.assertEqual(len(logged), 2, "expected exactly 2 provisioning-script invocations")
        self.assertFalse(intervals_overlap(*logged), f"same-activation provisioning invocations overlapped: {logged}")

    def test_concurrent_different_key_requests_for_max_devices_1_cannot_both_provision(self):
        """item 3 (closes the B8C1C A/B/C race at its root): two DIFFERENT
        keys racing for the same max_devices=1 activation - only ONE may
        ever reach a successful run_provision_peer() call; the other must
        see DEVICE_LIMIT (it can no longer even observe a mid-flight
        pending reservation, because the per-activation lock fully
        serializes the two attempts - the first to acquire it either
        confirms or rolls back BEFORE the second is ever admitted)."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        set_plan(self.plan_path, "SLEEP", "0.3")

        results = []
        results_lock = threading.Lock()

        def attempt(key):
            result = self._provision(credential, key)
            with results_lock:
                results.append(result)

        t1 = threading.Thread(target=attempt, args=(self.key_a,))
        t2 = threading.Thread(target=attempt, args=(self.key_b,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        confirmed = [r for r in results if r.decision.outcome == activations_module.BOUND_NEW and r.provision_outcome is not None]
        rejected = [r for r in results if r.decision.outcome == activations_module.DEVICE_LIMIT]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(len(rejected), 1)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)  # item 1: never both K1 and K2

    def test_provisioning_failure_releases_reservation_safely(self):
        """item 5."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        set_plan(self.plan_path, "EXIT", "1")

        result = self._provision(credential, self.key_a)
        self.assertEqual(result.decision.outcome, activations_module.BOUND_NEW)
        self.assertIsNotNone(result.provision_error)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, _activation_id)
        self.assertEqual(len(record["bound_devices"]), 0)  # slot released

    def test_same_key_retry_after_failure_succeeds(self):
        """item 6."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        set_plan(self.plan_path, "EXIT", "1")
        failed = self._provision(credential, self.key_a)
        self.assertIsNotNone(failed.provision_error)

        set_plan(self.plan_path, "CREATED", "10.77.0.20")
        retried = self._provision(credential, self.key_a)
        self.assertIsNone(retried.provision_error)
        self.assertTrue(retried.finalize_result.confirmed)
        self.assertEqual(retried.provision_outcome.ip, "10.77.0.20")

    def test_revoke_serializes_with_in_flight_provisioning_for_the_same_activation(self):
        """item 7, module-level: revoke_activation must not COMPLETE its
        own revalidate-and-write critical section until AFTER the ACTUAL
        provisioning-script invocation (the real external side effect) has
        finished. Proven via a direct ordering check against the script's
        own logged completion timestamp - not an interval-overlap check
        around the Python call, which would also count revoke's lock-wait
        queueing time as if it were "concurrent work" and produce a false
        positive even for a correctly-serialized pair (see this file's own
        development history)."""
        activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        log_path = os.path.join(self._tmp.name, "invocations.log")
        script_path = write_logging_provision_script(self._tmp.name, log_path, sleep_seconds=0.6)

        revoke_returned_at = {}

        def do_provision():
            activations_module.provision_with_activation(
                credential, self.key_a, self.store_path, self.lock_path, script_path, subprocess_timeout_seconds=5.0,
            )

        def do_revoke():
            time.sleep(0.15)  # let provisioning start and acquire the per-activation lock first
            activations_module.revoke_activation(self.store_path, self.lock_path, activation_id)
            revoke_returned_at["ts"] = time.time()

        t1 = threading.Thread(target=do_provision)
        t2 = threading.Thread(target=do_revoke)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        logged = read_logged_intervals(log_path)
        self.assertEqual(len(logged), 1)
        _provisioning_start, provisioning_end = logged[0]
        self.assertGreaterEqual(
            revoke_returned_at["ts"], provisioning_end,
            f"revoke completed ({revoke_returned_at['ts']}) before in-flight provisioning finished ({provisioning_end})",
        )

    def test_restart_simulation_preserves_slot_and_permits_same_key_recovery(self):
        """item 8: no in-process state - a fresh provision_with_activation
        call against the same durable store/lock paths (simulating a
        process restart) still enforces max_devices and still lets the
        SAME key recover cleanly after an earlier failure."""
        _activation_id, credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        set_plan(self.plan_path, "EXIT", "1")
        self._provision(credential, self.key_a)  # fails, rolls back

        # "restart": nothing carried over except store_path/lock_path/script_path strings.
        set_plan(self.plan_path, "CREATED", "10.77.0.21")
        after_restart = self._provision(credential, self.key_a)
        self.assertTrue(after_restart.finalize_result.confirmed)

        different_key_after_restart = self._provision(credential, self.key_b)
        self.assertEqual(different_key_after_restart.decision.outcome, activations_module.DEVICE_LIMIT)


class DifferentActivationsRemainConcurrentTests(ProvisionWithActivationTestBase):
    def test_different_activations_provision_concurrently_not_serialized(self):
        """item 4: two DIFFERENT activations (different credential digests
        -> different per-activation lock files) must NOT serialize against
        each other - their ACTUAL provisioning-script execution windows
        (logged by the script itself, real wall clock) must overlap."""
        _id_1, credential_1 = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        _id_2, credential_2 = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=1)
        log_path = os.path.join(self._tmp.name, "invocations.log")
        script_path = write_logging_provision_script(self._tmp.name, log_path, sleep_seconds=0.6)

        def attempt(credential, key):
            activations_module.provision_with_activation(
                credential, key, self.store_path, self.lock_path, script_path, subprocess_timeout_seconds=5.0,
            )

        t1 = threading.Thread(target=attempt, args=(credential_1, self.key_a))
        t2 = threading.Thread(target=attempt, args=(credential_2, self.key_b))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        logged = read_logged_intervals(log_path)
        self.assertEqual(len(logged), 2)
        self.assertTrue(intervals_overlap(*logged), f"different activations were serialized against each other: {logged}")


if __name__ == "__main__":
    unittest.main()
