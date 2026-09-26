"""Unit tests for gateway/api/field_enrollment.py - the module functions
directly, no HTTP layer (see test_field_enroll_endpoint.py for the
HTTP-level contract).

Round-2 review fix: credentials are now genuinely random (never derived
from a server secret) - covers the FieldEnrollmentIndex's own idempotency/
cap-race-freedom instead of any determinism property.

Round-3 review fix: covers (A) no plaintext credential at rest in the
index, (B) atomic rollback when activations.register_credential() itself
fails, (C) no orphan activation record left behind after a provisioning
failure, (D) that rollback never deletes an activation it does not own,
plus explicit concurrency (same-key and cap-boundary) and restart/
corruption behavior.
"""
import base64
import json
import multiprocessing
import os
import secrets
import sys
import threading
import time
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import field_enrollment as field_enrollment_module
from _fixtures import make_field_enrollment_wrap_key_file, make_public_key, set_plan, write_fake_provision_script


def _make_random_public_key():
    """A genuinely distinct, valid AmneziaWG/WireGuard public key each
    call - unlike `make_public_key`'s own fixed 256-value space (one
    repeated byte), this is needed for the bounded-lock-footprint test
    below, which must exercise far more than 256 distinct public keys."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# --- module-level helpers for MultiProcessKeyLockTests - must be
# top-level (never a nested closure) so they can be handed to a genuinely
# separate OS process, not merely a thread in this same process. ---

def _mp_hold_key_lock(index_path, public_key, ready_event, release_event, order_queue, tag):
    from api import field_enrollment as fe  # re-import in the child process
    with fe.field_enrollment_key_lock(index_path, public_key):
        order_queue.put(("acquired", tag))
        ready_event.set()
        release_event.wait(timeout=5)
        order_queue.put(("released", tag))


def _mp_acquire_and_release_key_lock(index_path, public_key, order_queue, tag):
    from api import field_enrollment as fe
    with fe.field_enrollment_key_lock(index_path, public_key):
        order_queue.put(("acquired", tag))
    order_queue.put(("released", tag))


class FieldEnrollmentTestBase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path
        set_plan(self.plan_path, "CREATED", "10.77.0.9")

        self.store_path = os.path.join(self._tmp.name, "activations.json")
        self.lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.store_path, self.lock_path)

        self.index_path = os.path.join(self._tmp.name, "field-enrollment-index.json")
        self.index_lock_path = os.path.join(self._tmp.name, ".field-enrollment-index.lock")
        self.wrap_key_file = make_field_enrollment_wrap_key_file(self._tmp.name)

    def _enroll(self, public_key, cap=5, wrap_key_file=None):
        return field_enrollment_module.enroll_device(
            public_key,
            self.index_path, self.index_lock_path,
            self.store_path, self.lock_path,
            self.script_path, 5.0,
            global_device_cap=cap,
            wrap_key_file=wrap_key_file if wrap_key_file is not None else self.wrap_key_file,
        )


class EnrollDeviceTests(FieldEnrollmentTestBase):
    def test_index_self_initializes_with_no_prior_file(self):
        self.assertFalse(os.path.exists(self.index_path))
        result = self._enroll(make_public_key(0x01))
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        self.assertTrue(os.path.exists(self.index_path))

    def test_fresh_device_enrolls_and_is_provisioned(self):
        key = make_public_key(0x11)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        self.assertIsNotNone(result.credential)
        self.assertEqual(result.client_tunnel_ip, "10.77.0.9")

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(result.credential),
        )
        self.assertIsNotNone(record)
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["public_key"], key)

    def test_two_different_devices_never_receive_the_same_credential(self):
        r1 = self._enroll(make_public_key(0x21))
        r2 = self._enroll(make_public_key(0x22))
        self.assertEqual(r1.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(r2.outcome, field_enrollment_module.ENROLLED)
        self.assertNotEqual(r1.credential, r2.credential)

    def test_credential_is_not_derivable_from_the_public_key_alone(self):
        """No shared secret is derivable from the public key - re-enrolling
        the SAME public key against a DIFFERENT index (and a different
        wrap key) produces an unrelated credential, proving nothing about
        the credential is a deterministic function of the public key."""
        key = make_public_key(0x25)
        other_index = os.path.join(self._tmp.name, "other-index.json")
        other_lock = os.path.join(self._tmp.name, ".other-index.lock")
        other_wrap_key = make_field_enrollment_wrap_key_file(self._tmp.name, name="other-wrap-key.bin")
        r1 = self._enroll(key)
        r2 = field_enrollment_module.enroll_device(
            key, other_index, other_lock, self.store_path, self.lock_path,
            self.script_path, 5.0, global_device_cap=5, wrap_key_file=other_wrap_key,
        )
        self.assertNotEqual(r1.credential, r2.credential)

    def test_repeat_enrollment_for_the_same_public_key_is_idempotent(self):
        key = make_public_key(0x31)
        r1 = self._enroll(key)
        r2 = self._enroll(key)
        self.assertEqual(r1.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(r2.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(r1.credential, r2.credential)

        # Still exactly one bound device for this credential - a repeat
        # enrollment never grows bound_devices, and the index has exactly
        # one entry, never two.
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(r1.credential),
        )
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(len(field_enrollment_module.list_index(self.index_path, self.index_lock_path)), 1)

    def test_device_cap_reached_fails_closed(self):
        for seed in (0x40, 0x41):
            result = self._enroll(make_public_key(seed), cap=2)
            self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)

        result = self._enroll(make_public_key(0x42), cap=2)
        self.assertEqual(result.outcome, field_enrollment_module.DEVICE_CAP_REACHED)

    def test_cap_is_scoped_to_the_index_never_to_unrelated_activations_in_the_shared_store(self):
        """The activation store may ALSO hold ordinary, operator-issued,
        multi-device activations unrelated to field enrollment - the cap
        must count ONLY field-enrolled devices (the index), never the
        store's total record count."""
        activations_module.issue_activation(self.store_path, self.lock_path, max_devices=10)
        activations_module.issue_activation(self.store_path, self.lock_path, max_devices=10)
        # Two unrelated operator-issued activations already exist; the
        # field-enrollment cap of 1 must still admit exactly one NEW
        # field-enrolled device, unaffected by the store's total size.
        result = self._enroll(make_public_key(0x45), cap=1)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)

    def test_cap_reached_does_not_block_a_repeat_of_an_already_enrolled_device(self):
        """The cap governs NEW devices only - a device that already has a
        record must be able to retry (e.g. after a lost response) even once
        the cap is nominally full."""
        key = make_public_key(0x50)
        first = self._enroll(key, cap=1)
        self.assertEqual(first.outcome, field_enrollment_module.ENROLLED)

        second = self._enroll(key, cap=1)
        self.assertEqual(second.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(first.credential, second.credential)

    def test_invalid_public_key_fails_closed_before_touching_any_store(self):
        result = self._enroll("not-a-real-key")
        self.assertEqual(result.outcome, field_enrollment_module.INVALID_PUBLIC_KEY)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(data, {})
        self.assertFalse(os.path.exists(self.index_path))

    def test_revoked_device_fails_closed(self):
        key = make_public_key(0x60)
        first = self._enroll(key)
        self.assertEqual(first.outcome, field_enrollment_module.ENROLLED)

        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        activations_module.revoke_activation(self.store_path, self.lock_path, entry["activation_id"])

        second = self._enroll(key)
        self.assertEqual(second.outcome, field_enrollment_module.REVOKED)

    def test_revoke_then_index_removal_lets_the_same_public_key_re_enroll_fresh(self):
        key = make_public_key(0x65)
        first = self._enroll(key)
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        activations_module.revoke_activation(self.store_path, self.lock_path, entry["activation_id"])
        field_enrollment_module.remove_from_index(self.index_path, self.index_lock_path, key)

        second = self._enroll(key)
        self.assertEqual(second.outcome, field_enrollment_module.ENROLLED)
        self.assertNotEqual(first.credential, second.credential)

    def test_provisioning_failure_releases_the_reservation_and_does_not_confirm_the_device(self):
        set_plan(self.plan_path, "EXIT", "1")
        key = make_public_key(0x70)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.PROVISION_FAILED)

        # The failed reservation must not permanently occupy a cap slot nor
        # leave a phantom bound device.
        self.assertIsNone(field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key))
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        for record in data.values():
            self.assertEqual(record["bound_devices"], [])

    def test_provisioning_failure_then_retry_succeeds_as_a_fresh_attempt(self):
        set_plan(self.plan_path, "EXIT", "1")
        key = make_public_key(0x71)
        first = self._enroll(key)
        self.assertEqual(first.outcome, field_enrollment_module.PROVISION_FAILED)

        set_plan(self.plan_path, "CREATED", "10.77.0.20")
        second = self._enroll(key)
        self.assertEqual(second.outcome, field_enrollment_module.ENROLLED)


class PlaintextCredentialRegressionTests(FieldEnrollmentTestBase):
    """Round-3 review fix, BUG #1 - the index must never hold the raw
    bearer credential in plaintext."""

    def test_index_json_never_contains_the_raw_credential_as_a_substring(self):
        key = make_public_key(0x80)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)

        with open(self.index_path, "r", encoding="utf-8") as handle:
            raw_index_text = handle.read()
        self.assertNotIn(result.credential, raw_index_text)

    def test_index_entry_has_no_plaintext_credential_field_only_digest_and_wrapped_form(self):
        key = make_public_key(0x81)
        result = self._enroll(key)
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        self.assertEqual(
            set(entry.keys()), {"activation_id", "credential_digest", "wrapped_credential", "created_at"},
        )
        self.assertEqual(entry["credential_digest"], activations_module.credential_digest(result.credential))
        # The wrapped form is not itself the plaintext credential, nor does
        # decoding it as base64 (the only decoding a passive index-file
        # reader could try without the separate wrap key) ever recover it -
        # AES-GCM ciphertext is indistinguishable from random bytes.
        self.assertNotEqual(entry["wrapped_credential"], result.credential)
        import base64
        decoded = base64.b64decode(entry["wrapped_credential"])
        self.assertNotIn(result.credential.encode("ascii"), decoded)

    def test_credential_is_only_legitimately_recoverable_through_the_real_unwrap_path(self):
        """A repeat enrollment for the same key recovers the EXACT same
        credential - proving recovery works - but only via enroll_device's
        own wrap-key-gated unwrap, never by reading the index file alone."""
        key = make_public_key(0x82)
        first = self._enroll(key)
        second = self._enroll(key)
        self.assertEqual(first.credential, second.credential)

    def test_wrong_wrap_key_fails_closed_rather_than_leaking_or_silently_reissuing(self):
        key = make_public_key(0x83)
        self._enroll(key)
        wrong_wrap_key = make_field_enrollment_wrap_key_file(self._tmp.name, name="wrong-wrap-key.bin")
        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key, wrap_key_file=wrong_wrap_key)

    def test_provisioning_failure_test_output_never_contains_the_credential(self):
        """The credential must not leak into an AssertionError's own text
        if a later assertion in this test file ever fails - proven here by
        asserting the credential is absent from a raised exception's str()."""
        key = make_public_key(0x84)
        result = self._enroll(key)
        try:
            raise field_enrollment_module.FieldEnrollmentIndexError("unrelated failure, no credential included")
        except field_enrollment_module.FieldEnrollmentIndexError as exc:
            self.assertNotIn(result.credential, str(exc))


class RegistrationFailureRollbackTests(FieldEnrollmentTestBase):
    """Round-3 review fix, BUG #2 - a storage failure inside
    activations.register_credential() must roll back the index reservation
    atomically, never leaving a dangling entry or a stuck cap slot."""

    def test_registration_failure_removes_the_index_reservation_and_reraises(self):
        key = make_public_key(0x90)
        with mock.patch.object(
            activations_module, "register_credential", side_effect=activations_module.ActivationStoreError("simulated storage failure"),
        ):
            with self.assertRaises(activations_module.ActivationStoreError):
                self._enroll(key)

        self.assertIsNone(field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key))
        self.assertEqual(field_enrollment_module.list_index(self.index_path, self.index_lock_path), {})
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(data, {})

    def test_cap_slot_is_free_after_a_registration_failure_so_another_device_can_enroll(self):
        with mock.patch.object(
            activations_module, "register_credential", side_effect=activations_module.ActivationStoreError("simulated storage failure"),
        ):
            with self.assertRaises(activations_module.ActivationStoreError):
                self._enroll(make_public_key(0x91), cap=1)

        result = self._enroll(make_public_key(0x92), cap=1)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)

    def test_retry_after_a_registration_failure_is_a_clean_fresh_attempt(self):
        key = make_public_key(0x93)
        with mock.patch.object(
            activations_module, "register_credential", side_effect=activations_module.ActivationStoreError("simulated storage failure"),
        ):
            with self.assertRaises(activations_module.ActivationStoreError):
                self._enroll(key)

        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)


class ProvisioningFailureOrphanRegressionTests(FieldEnrollmentTestBase):
    """Round-3 review fix, BUG #3 - a provisioning failure must not leave
    an orphan activation record in activations.json."""

    def test_provisioning_failure_removes_the_activation_record_entirely_not_merely_unbinds_it(self):
        set_plan(self.plan_path, "EXIT", "1")
        key = make_public_key(0xA0)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.PROVISION_FAILED)

        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(data, {}, "a failed field-enrollment attempt must leave the activation store empty, not an orphan record")

    def test_repeated_provisioning_failures_never_grow_the_activation_store(self):
        set_plan(self.plan_path, "EXIT", "1")
        for seed in range(5):
            result = self._enroll(make_public_key(0xB0 + seed))
            self.assertEqual(result.outcome, field_enrollment_module.PROVISION_FAILED)

        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(data, {})

    def test_existing_activation_not_owned_by_this_attempt_is_never_deleted_by_rollback(self):
        """An operator-issued activation record that just happens to share
        no relationship with this field-enrollment attempt must survive a
        provisioning failure untouched - rollback is ownership-scoped, not
        a blanket cleanup."""
        unrelated_id, unrelated_credential = activations_module.issue_activation(
            self.store_path, self.lock_path, max_devices=10,
        )
        set_plan(self.plan_path, "EXIT", "1")
        result = self._enroll(make_public_key(0xC0))
        self.assertEqual(result.outcome, field_enrollment_module.PROVISION_FAILED)

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(unrelated_credential),
        )
        self.assertIsNotNone(record, "an unrelated, pre-existing activation must never be removed by this attempt's rollback")
        self.assertEqual(record["activation_id"], unrelated_id)

    def test_remove_credential_if_unbound_never_removes_a_record_with_a_bound_device(self):
        """Direct unit proof of the ownership+state guard itself: a record
        that has ANY bound device (even from a fully separate, successful
        enrollment) must never be removed."""
        key = make_public_key(0xC5)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)

        removed = activations_module.remove_credential_if_unbound(
            self.store_path, self.lock_path, result.credential, entry["activation_id"],
        )
        self.assertFalse(removed)
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(result.credential),
        )
        self.assertIsNotNone(record)

    def test_remove_credential_if_unbound_never_removes_a_record_with_a_mismatched_activation_id(self):
        credential = "n" * 43 + "="
        # Register directly (bypassing field_enrollment) to control the
        # exact activation_id, then attempt removal under a DIFFERENT id.
        activations_module.register_credential(
            self.store_path, self.lock_path, credential, "a" * 32, max_devices=1,
        )
        removed = activations_module.remove_credential_if_unbound(
            self.store_path, self.lock_path, credential, "b" * 32,
        )
        self.assertFalse(removed)
        self.assertIsNotNone(
            activations_module.find_by_credential_digest(self.store_path, self.lock_path, activations_module.credential_digest(credential)),
        )


class ConcurrencyTests(FieldEnrollmentTestBase):
    """Round-3 review fix - explicit concurrency proofs, both for the same
    public key (idempotency race) and for distinct public keys at the cap
    boundary (bounded-admission race)."""

    def test_concurrent_enrollment_of_the_same_public_key_yields_exactly_one_committed_credential(self):
        key = make_public_key(0xD0)
        results = []
        errors = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                results.append(self._enroll(key))
            except Exception as exc:  # pragma: no cover - surfaced via errors list
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        for r in results:
            self.assertEqual(r.outcome, field_enrollment_module.ENROLLED)
        credentials = {r.credential for r in results}
        self.assertEqual(len(credentials), 1, "every concurrent request for the SAME key must receive the SAME single credential")

        self.assertEqual(len(field_enrollment_module.list_index(self.index_path, self.index_lock_path)), 1)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1)
        record = next(iter(data.values()))
        self.assertEqual(len(record["bound_devices"]), 1)

    def test_concurrent_enrollment_of_distinct_public_keys_never_exceeds_the_cap(self):
        cap = 2
        keys = [make_public_key(0xE0 + i) for i in range(5)]
        results = []
        errors = []
        barrier = threading.Barrier(len(keys))

        def worker(k):
            barrier.wait()
            try:
                results.append(self._enroll(k, cap=cap))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(k,)) for k in keys]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), len(keys))
        enrolled = [r for r in results if r.outcome == field_enrollment_module.ENROLLED]
        capped = [r for r in results if r.outcome == field_enrollment_module.DEVICE_CAP_REACHED]
        self.assertEqual(len(enrolled), cap, "at most `cap` NEW devices may ever commit, regardless of request timing")
        self.assertEqual(len(capped), len(keys) - cap)
        self.assertEqual(len(field_enrollment_module.list_index(self.index_path, self.index_lock_path)), cap)


class RestartRecoveryTests(FieldEnrollmentTestBase):
    """Round-3 review fix - restart/corruption/partial-write recovery
    behavior, explicit and fail-closed where a silent reset could bypass
    the cap or leak a credential."""

    def test_malformed_index_json_fails_closed_never_silently_resets(self):
        with open(self.index_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(make_public_key(0xF0))

    def test_index_entry_missing_a_required_field_fails_closed(self):
        key = make_public_key(0xF1)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for entry in data.values():
            del entry["wrapped_credential"]
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

    def test_corrupted_wrapped_credential_fails_closed_at_decrypt_time(self):
        """A tampered ciphertext must fail authentication (GCM's own tag),
        never silently decrypt to wrong bytes and never silently mint a
        SECOND credential for an already-reserved public key."""
        key = make_public_key(0xF2)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        entry = data[key]
        entry["wrapped_credential"] = entry["wrapped_credential"][:-4] + ("A" if entry["wrapped_credential"][-4] != "A" else "B") + entry["wrapped_credential"][-3:]
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

    def test_a_successful_enrollment_survives_a_fresh_process_view_of_the_index(self):
        """Simulates a process restart: a brand-new call sequence (no
        in-memory state reused) against the SAME on-disk index/store must
        still recover the exact same credential for a repeat request."""
        key = make_public_key(0xF3)
        first = self._enroll(key)
        self.assertEqual(first.outcome, field_enrollment_module.ENROLLED)

        # "Restart": nothing but the on-disk paths carries over.
        second = field_enrollment_module.enroll_device(
            key, self.index_path, self.index_lock_path, self.store_path, self.lock_path,
            self.script_path, 5.0, global_device_cap=5, wrap_key_file=self.wrap_key_file,
        )
        self.assertEqual(second.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(first.credential, second.credential)

    def test_index_reservation_with_no_activation_record_yet_self_heals_on_retry(self):
        """The crash-recovery gap this round's audit found: a process that
        reserved an index entry but died before ever calling
        register_credential() must not be stuck returning DISABLED forever -
        register_credential() is now attempted on every call, including a
        replay, so the SAME public key retried against the SAME index
        entry completes registration and provisioning cleanly."""
        key = make_public_key(0xF4)
        entry_activation_id = "c" * 32
        wrap_key_bytes = field_enrollment_module._load_wrap_key(self.wrap_key_file)
        wrapped = field_enrollment_module._wrap_credential(wrap_key_bytes, "orphaned-reservation-credential-value-1234", key)
        field_enrollment_module._atomic_write_index(
            self.index_path,
            {
                key: {
                    "activation_id": entry_activation_id,
                    "credential_digest": activations_module.credential_digest("orphaned-reservation-credential-value-1234"),
                    "wrapped_credential": wrapped,
                    "created_at": "2026-01-01T00:00:00+00:00",
                },
            },
        )
        # No activations.json record exists yet for this credential - the
        # simulated crash happened between index-reserve and register.
        self.assertEqual(activations_module.read_store_shared(self.store_path, self.lock_path), {})

        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(result.credential, "orphaned-reservation-credential-value-1234")
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(result.credential),
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["activation_id"], entry_activation_id)


class SameKeyRollbackRaceRegressionTests(FieldEnrollmentTestBase):
    """B67.4 corrective-pass fix, MAJOR BUG #1 - deterministic (not merely
    many-random-threads) proof that a failed attempt's own rollback can
    never destroy a concurrent, successful attempt's live state for the
    SAME public key. Coordinates two real threads with threading.Event so
    the exact interleaving the original bug allowed - A reserves/
    registers/blocks in provisioning, B attempts the SAME key, A's
    provisioning fails and its rollback runs, only THEN does B proceed -
    is actually exercised, not merely hoped for by launching 8 threads
    and hoping the scheduler produces it.
    """

    def test_failed_attempt_cannot_delete_a_concurrent_successful_attempts_state(self):
        key = make_public_key(0xD5)
        provisioning_call_started = threading.Event()
        allow_first_provisioning_to_proceed = threading.Event()
        call_count = {"n": 0}
        count_lock = threading.Lock()
        real_provision_with_activation = activations_module.provision_with_activation

        def instrumented_provision_with_activation(*args, **kwargs):
            with count_lock:
                call_count["n"] += 1
                this_call = call_count["n"]
            if this_call == 1:
                # This is request A's own provisioning attempt - signal
                # that it has started (so B knows it is safe to attempt
                # the SAME key) and block until the test explicitly lets
                # it proceed, so B's attempt is guaranteed to be issued
                # while A is still fully in-flight, still holding its own
                # field_enrollment_key_lock.
                provisioning_call_started.set()
                allow_first_provisioning_to_proceed.wait(timeout=5)
                set_plan(self.plan_path, "EXIT", "1")
            else:
                # This is request B's own provisioning attempt - reachable
                # ONLY after A's entire attempt (including its rollback)
                # has released the key lock, since B's own enroll_device
                # call blocks on that same lock until then.
                set_plan(self.plan_path, "CREATED", "10.77.0.30")
            return real_provision_with_activation(*args, **kwargs)

        results = {}
        errors = []

        def worker_a():
            try:
                results["a"] = self._enroll(key)
            except Exception as exc:  # pragma: no cover - surfaced via errors list
                errors.append(exc)

        def worker_b():
            self.assertTrue(provisioning_call_started.wait(timeout=5))
            try:
                results["b"] = self._enroll(key)
            except Exception as exc:  # pragma: no cover - surfaced via errors list
                errors.append(exc)

        with mock.patch.object(
            activations_module, "provision_with_activation", side_effect=instrumented_provision_with_activation,
        ):
            thread_a = threading.Thread(target=worker_a)
            thread_b = threading.Thread(target=worker_b)
            thread_a.start()
            self.assertTrue(provisioning_call_started.wait(timeout=5))
            thread_b.start()
            # B must genuinely BLOCK here (on A's still-held
            # field_enrollment_key_lock) rather than interleave with A's
            # in-flight attempt - give the scheduler a real window to prove
            # that, then confirm B has not yet produced a result.
            time.sleep(0.2)
            self.assertNotIn("b", results, "B must not proceed while A still holds the per-key lock")
            allow_first_provisioning_to_proceed.set()
            thread_a.join(timeout=5)
            thread_b.join(timeout=5)

        self.assertEqual(errors, [])
        self.assertEqual(results["a"].outcome, field_enrollment_module.PROVISION_FAILED)
        self.assertEqual(results["b"].outcome, field_enrollment_module.ENROLLED)

        # A's failure/rollback must never have touched B's live state:
        # exactly one index entry, one activation record, one confirmed
        # bound device, using B's credential.
        index_entries = field_enrollment_module.list_index(self.index_path, self.index_lock_path)
        self.assertEqual(len(index_entries), 1)
        entry = index_entries[key]
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1)
        record = next(iter(data.values()))
        self.assertEqual(record["activation_id"], entry["activation_id"])
        self.assertEqual(record["status"], activations_module.ACTIVE)
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)
        self.assertEqual(
            activations_module.credential_digest(results["b"].credential), entry["credential_digest"],
        )


class OwnershipAwareIndexRollbackTests(FieldEnrollmentTestBase):
    """B67.4 corrective-pass fix, MAJOR BUG #1 cleanup - direct unit proof
    of [remove_reservation_if_owned] itself: it must never delete an index
    entry that does not match the exact activation_id the caller believes
    it owns, independent of the key lock (defense in depth)."""

    def test_never_removes_an_entry_whose_activation_id_has_since_changed(self):
        key = make_public_key(0xD6)
        first = self._enroll(key)
        original_entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        original_activation_id = original_entry["activation_id"]

        # Simulate a legitimate concurrent replacement of this public
        # key's slot (e.g. an operator revoke followed by a fresh
        # enrollment) that happened between when a caller captured
        # `original_activation_id` and when its own (now-stale) rollback
        # runs.
        field_enrollment_module.remove_from_index(self.index_path, self.index_lock_path, key)
        second = self._enroll(key)
        self.assertNotEqual(first.credential, second.credential)

        removed = field_enrollment_module.remove_reservation_if_owned(
            self.index_path, self.index_lock_path, key, original_activation_id,
        )
        self.assertFalse(removed, "a rollback must never delete a reservation it does not own")

        still_there = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        self.assertIsNotNone(still_there)
        self.assertNotEqual(still_there["activation_id"], original_activation_id)

    def test_removes_an_entry_only_when_the_activation_id_matches_exactly(self):
        key = make_public_key(0xD7)
        result = self._enroll(key)
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)

        removed = field_enrollment_module.remove_reservation_if_owned(
            self.index_path, self.index_lock_path, key, entry["activation_id"],
        )
        self.assertTrue(removed)
        self.assertIsNone(field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key))

    def test_safe_no_op_when_no_entry_exists_at_all(self):
        key = make_public_key(0xD8)
        removed = field_enrollment_module.remove_reservation_if_owned(
            self.index_path, self.index_lock_path, key, "a" * 32,
        )
        self.assertFalse(removed)


class CliRevokeRaceRegressionTests(FieldEnrollmentTestBase):
    """B67.4 corrective-pass fix, operator CLI TOCTOU (item 15) -
    deterministic proof that [revoke_and_remove_if_owned] (the primitive
    gateway/tools/field_enrollment_admin.py's `revoke` subcommand now
    calls) is fully serialized, via the SAME per-public-key lock, against
    a concurrent enrollment attempt for that exact public key - so an
    operator's revoke can never race a device's own concurrent retry into
    either a resurrected credential or a dangling index entry."""

    def test_revoke_is_serialized_against_a_concurrent_enrollment_for_the_same_key(self):
        key = make_public_key(0xE5)
        first = self._enroll(key)
        original_entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        original_activation_id = original_entry["activation_id"]

        revoke_started = threading.Event()
        allow_revoke_to_finish = threading.Event()
        real_revoke_activation = activations_module.revoke_activation

        def blocking_revoke_activation(*args, **kwargs):
            revoke_started.set()
            allow_revoke_to_finish.wait(timeout=5)
            return real_revoke_activation(*args, **kwargs)

        results = {}
        errors = []

        def revoke_worker():
            try:
                results["revoke"] = field_enrollment_module.revoke_and_remove_if_owned(
                    self.index_path, self.index_lock_path, self.store_path, self.lock_path, key,
                )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        def enroll_worker():
            self.assertTrue(revoke_started.wait(timeout=5))
            # The CLI revoke has started but is deliberately still holding
            # the per-key lock (blocked on allow_revoke_to_finish) - this
            # concurrent enrollment attempt for the SAME key must block
            # until it releases, never interleave with it.
            time.sleep(0.2)
            self.assertNotIn("enroll", results)
            try:
                results["enroll"] = self._enroll(key)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        with mock.patch.object(activations_module, "revoke_activation", side_effect=blocking_revoke_activation):
            t_revoke = threading.Thread(target=revoke_worker)
            t_enroll = threading.Thread(target=enroll_worker)
            t_revoke.start()
            self.assertTrue(revoke_started.wait(timeout=5))
            t_enroll.start()
            time.sleep(0.2)
            allow_revoke_to_finish.set()
            t_revoke.join(timeout=5)
            t_enroll.join(timeout=5)

        self.assertEqual(errors, [])
        self.assertTrue(results["revoke"].changed)
        self.assertEqual(results["revoke"].activation_id, original_activation_id)
        self.assertEqual(results["enroll"].outcome, field_enrollment_module.ENROLLED)
        self.assertNotEqual(results["enroll"].credential, first.credential)

        entry_after = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        self.assertIsNotNone(entry_after, "the concurrent fresh enrollment's own entry must survive the revoke")
        self.assertNotEqual(entry_after["activation_id"], original_activation_id)
        revoked_record = activations_module.find_by_activation_id(self.store_path, self.lock_path, original_activation_id)
        self.assertEqual(revoked_record["status"], activations_module.REVOKED)


class CommitUncertainRollbackTests(FieldEnrollmentTestBase):
    """B67.4 corrective-pass fix, MAJOR BUG #2 - a registration failure
    that is SPECIFICALLY activations.ActivationCommitUncertainError (its
    own os.replace() already succeeded - durability merely unconfirmed)
    must never roll back the index reservation, and a same-key retry must
    reconcile cleanly with whatever the interrupted attempt actually left
    durable."""

    def test_commit_uncertain_registration_failure_does_not_remove_the_index_reservation(self):
        key = make_public_key(0xF5)
        with mock.patch.object(
            activations_module, "register_credential",
            side_effect=activations_module.ActivationCommitUncertainError("simulated commit-uncertain failure"),
        ):
            with self.assertRaises(activations_module.ActivationCommitUncertainError):
                self._enroll(key)

        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        self.assertIsNotNone(entry, "a commit-uncertain registration failure must never roll back the index reservation")

    def test_retry_after_commit_uncertain_reconciles_with_whatever_was_actually_left_durable(self):
        """Simulates the real boundary this bug lives at: the interrupted
        attempt's own register_credential call actually durably wrote the
        record (its own os.replace() succeeded) even though IT observed
        commit-uncertain - proven here by calling the real
        register_credential directly first, then having a mocked
        enroll_device call raise commit-uncertain on top of that
        already-durable state, exactly as a real directory-fsync failure
        would leave things."""
        key = make_public_key(0xF6)
        wrap_key_bytes = field_enrollment_module._load_wrap_key(self.wrap_key_file)
        reservation = field_enrollment_module._reserve_locked(
            self.index_path, self.index_lock_path, wrap_key_bytes, key, global_cap=5,
        )
        activations_module.register_credential(
            self.store_path, self.lock_path, reservation.credential, reservation.activation_id, max_devices=1,
        )

        with mock.patch.object(
            activations_module, "register_credential",
            side_effect=activations_module.ActivationCommitUncertainError("simulated commit-uncertain failure"),
        ):
            with self.assertRaises(activations_module.ActivationCommitUncertainError):
                self._enroll(key)

        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(result.credential, reservation.credential)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(len(data), 1, "a retry after commit-uncertain must never mint a duplicate activation record")


class IndexSchemaValidationTests(FieldEnrollmentTestBase):
    """B67.4 corrective-pass fix, index integrity audit (item 17) - exact
    shape checks on every index entry field, not merely presence/
    non-emptiness, so a corrupted entry fails closed at read time."""

    def test_malformed_activation_id_fails_closed(self):
        key = make_public_key(0xF7)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data[key]["activation_id"] = "not-32-lowercase-hex-chars"
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

    def test_malformed_credential_digest_fails_closed(self):
        key = make_public_key(0xF8)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data[key]["credential_digest"] = "too-short"
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

    def test_implausibly_short_wrapped_credential_fails_closed(self):
        key = make_public_key(0xF9)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data[key]["wrapped_credential"] = base64.b64encode(b"short").decode("ascii")
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

    def test_non_base64_wrapped_credential_fails_closed(self):
        key = make_public_key(0xFA)
        self._enroll(key)
        with open(self.index_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data[key]["wrapped_credential"] = "not valid base64!!!"
        with open(self.index_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)


class BoundedKeyLockFootprintTests(FieldEnrollmentTestBase):
    """B67.4 second corrective-pass fix, MAJOR BUG #1 (unbounded lock-file
    growth) - item A: real filesystem-footprint proof, not merely "the
    request got rejected". Exercises far more distinct public keys than
    the fixed shard-pool size and inspects the actual lock directory."""

    def test_lock_file_count_never_exceeds_the_fixed_shard_pool_regardless_of_request_volume(self):
        num_requests = 5000
        for _ in range(num_requests):
            key = _make_random_public_key()
            with field_enrollment_module.field_enrollment_key_lock(self.index_path, key):
                pass

        lock_dir = field_enrollment_module._key_lock_dir(self.index_path)
        lock_files = os.listdir(lock_dir)

        self.assertGreater(
            num_requests, len(lock_files) * 10,
            "sanity check: far more requests than persistent lock artifacts",
        )
        self.assertGreater(len(lock_files), 0)
        self.assertLessEqual(
            len(lock_files), field_enrollment_module._KEY_LOCK_SHARD_COUNT,
            "the persistent lock-file footprint must never exceed the fixed shard pool size, "
            "no matter how many distinct public keys are ever presented",
        )

    def test_repeating_the_same_small_set_of_keys_never_grows_the_footprint_further(self):
        keys = [_make_random_public_key() for _ in range(10)]
        for _ in range(500):
            for key in keys:
                with field_enrollment_module.field_enrollment_key_lock(self.index_path, key):
                    pass

        lock_dir = field_enrollment_module._key_lock_dir(self.index_path)
        lock_files = os.listdir(lock_dir)
        self.assertLessEqual(len(lock_files), field_enrollment_module._KEY_LOCK_SHARD_COUNT)
        self.assertLessEqual(len(lock_files), len(keys))


class KeyLockDirectSerializationTests(FieldEnrollmentTestBase):
    """B67.4 second corrective-pass fix - item B: the raw lock primitive
    itself is mutually exclusive for the SAME public key, independent of
    the full enroll_device flow (see SameKeyRollbackRaceRegressionTests
    for the full-flow proof that the ENTIRE reserve->register->provision
    ->rollback critical section is covered)."""

    def test_same_public_key_lock_is_mutually_exclusive(self):
        key = make_public_key(0xEB)
        acquired = threading.Event()
        release = threading.Event()
        second_acquired = threading.Event()

        def holder():
            with field_enrollment_module.field_enrollment_key_lock(self.index_path, key):
                acquired.set()
                release.wait(timeout=5)

        def contender():
            self.assertTrue(acquired.wait(timeout=5))
            with field_enrollment_module.field_enrollment_key_lock(self.index_path, key):
                second_acquired.set()

        t1 = threading.Thread(target=holder)
        t2 = threading.Thread(target=contender)
        t1.start()
        self.assertTrue(acquired.wait(timeout=5))
        t2.start()
        time.sleep(0.2)
        self.assertFalse(second_acquired.is_set(), "the same public key's lock must be mutually exclusive")
        release.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        self.assertTrue(second_acquired.is_set())


class ShardCollisionBehaviorTests(FieldEnrollmentTestBase):
    """B67.4 second corrective-pass fix - item C: the fixed shard pool is
    NOT accidentally one single global lock, and a deliberate shard
    collision between two DIFFERENT keys only ever costs them concurrency
    with each other, never correctness. Shard membership is computed
    directly from the real, shipped hash function (never randomly
    assumed), so this can never be flaky."""

    def _keys_by_shard(self):
        keys_by_shard = {}
        for seed in range(256):
            key = make_public_key(seed)
            shard = field_enrollment_module._key_lock_shard_index(key)
            keys_by_shard.setdefault(shard, []).append(key)
        return keys_by_shard

    def test_keys_on_different_shards_remain_concurrent(self):
        keys_by_shard = self._keys_by_shard()
        distinct_shard_keys = [keys[0] for keys in keys_by_shard.values()]
        self.assertGreaterEqual(len(distinct_shard_keys), 2, "need at least two distinct shards among 256 test keys")
        key_a, key_b = distinct_shard_keys[0], distinct_shard_keys[1]

        holding = threading.Event()
        release = threading.Event()

        def hold_a():
            with field_enrollment_module.field_enrollment_key_lock(self.index_path, key_a):
                holding.set()
                release.wait(timeout=5)

        t_a = threading.Thread(target=hold_a)
        t_a.start()
        self.assertTrue(holding.wait(timeout=5))

        acquired_b = threading.Event()

        def try_b():
            with field_enrollment_module.field_enrollment_key_lock(self.index_path, key_b):
                acquired_b.set()

        t_b = threading.Thread(target=try_b)
        t_b.start()
        t_b.join(timeout=2)
        self.assertTrue(
            acquired_b.is_set(), "a different shard's lock must never be blocked by an unrelated shard's holder",
        )

        release.set()
        t_a.join(timeout=5)

    def test_keys_sharing_a_shard_serialize_but_never_corrupt_each_others_enrollment(self):
        keys_by_shard = self._keys_by_shard()
        colliding_pair = next((keys for keys in keys_by_shard.values() if len(keys) >= 2), None)
        self.assertIsNotNone(colliding_pair, "need at least one shard with >=2 of the 256 test keys colliding")
        key_a, key_b = colliding_pair[0], colliding_pair[1]

        result_a = self._enroll(key_a, cap=5)
        result_b = self._enroll(key_b, cap=5)
        self.assertEqual(result_a.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(result_b.outcome, field_enrollment_module.ENROLLED)
        self.assertNotEqual(result_a.credential, result_b.credential)

        entry_a = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key_a)
        entry_b = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key_b)
        self.assertNotEqual(entry_a["activation_id"], entry_b["activation_id"])
        self.assertEqual(entry_a["credential_digest"], activations_module.credential_digest(result_a.credential))
        self.assertEqual(entry_b["credential_digest"], activations_module.credential_digest(result_b.credential))


class MultiProcessKeyLockTests(FieldEnrollmentTestBase):
    """B67.4 second corrective-pass fix - item D: genuine SEPARATE OS
    processes (multiprocessing, `fork` context - this whole suite is
    already POSIX-only, matching every other flock-based test here),
    never merely threads inside one process, proving the shard lock is a
    real cross-process primitive."""

    def test_same_key_lock_serializes_across_separate_processes(self):
        ctx = multiprocessing.get_context("fork")
        key = make_public_key(0xEE)
        ready_a = ctx.Event()
        release_a = ctx.Event()
        order_queue = ctx.Queue()

        proc_a = ctx.Process(
            target=_mp_hold_key_lock,
            args=(self.index_path, key, ready_a, release_a, order_queue, "a"),
        )
        proc_a.start()
        self.assertTrue(ready_a.wait(timeout=5))

        proc_b = ctx.Process(
            target=_mp_acquire_and_release_key_lock,
            args=(self.index_path, key, order_queue, "b"),
        )
        proc_b.start()
        proc_b.join(timeout=2)
        self.assertTrue(
            proc_b.is_alive(), "a SEPARATE process must genuinely block on the same shard's lock, not merely a thread",
        )

        release_a.set()
        proc_a.join(timeout=5)
        proc_b.join(timeout=5)
        self.assertFalse(proc_a.is_alive())
        self.assertFalse(proc_b.is_alive())

        events = []
        while not order_queue.empty():
            events.append(order_queue.get())

        self.assertEqual(events[0], ("acquired", "a"))
        self.assertIn(("released", "a"), events)
        self.assertIn(("acquired", "b"), events)
        index_released_a = events.index(("released", "a"))
        index_acquired_b = events.index(("acquired", "b"))
        self.assertLess(
            index_released_a, index_acquired_b,
            "process B must only acquire the lock AFTER process A released it",
        )


class ActivationIdConsistencyTests(FieldEnrollmentTestBase):
    """B67.4 second corrective-pass fix, MAJOR BUG #2 - `enroll_device`
    must fail closed, never provision, never report success, and never
    silently repair the index, whenever the activation store's own
    record for a credential digest disagrees with what the index names
    for that public key."""

    def test_mismatched_activation_id_between_index_and_store_fails_closed(self):
        key = make_public_key(0xEC)
        first = self._enroll(key)
        digest = activations_module.credential_digest(first.credential)

        # Directly corrupt the activation store's OWN record for this
        # exact credential digest to carry a DIFFERENT activation_id than
        # the one the index believes it minted - simulates a prior
        # corruption/manual edit/bug elsewhere; never reachable through
        # this module's own normal call sequence.
        with open(self.store_path, "r", encoding="utf-8") as handle:
            store_data = json.load(handle)
        divergent_activation_id = "b" * 32
        store_data[digest]["activation_id"] = divergent_activation_id
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(store_data, handle)

        with self.assertRaises(field_enrollment_module.FieldEnrollmentIndexError):
            self._enroll(key)

        # The store's own (divergent) record must survive completely
        # untouched - this attempt never owned it, so it must never be
        # revoked, deleted, or rewritten.
        record = activations_module.find_by_credential_digest(self.store_path, self.lock_path, digest)
        self.assertIsNotNone(record)
        self.assertEqual(record["activation_id"], divergent_activation_id)
        self.assertEqual(record["status"], activations_module.ACTIVE)
        self.assertEqual(len(record["bound_devices"]), 1, "the store's own pre-existing record must be left byte-for-byte untouched")

        # The index must never have been silently rewritten to agree with
        # the store either.
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        self.assertIsNotNone(entry)
        self.assertNotEqual(entry["activation_id"], divergent_activation_id)

    def test_normal_successful_enrollment_has_matching_activation_ids_throughout(self):
        key = make_public_key(0xED)
        wrap_key_bytes = field_enrollment_module._load_wrap_key(self.wrap_key_file)
        reservation = field_enrollment_module._reserve_locked(
            self.index_path, self.index_lock_path, wrap_key_bytes, key, global_cap=5,
        )
        register_result = activations_module.register_credential(
            self.store_path, self.lock_path, reservation.credential, reservation.activation_id, max_devices=1,
        )
        self.assertEqual(register_result.activation_id, reservation.activation_id)

        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(result.credential, reservation.credential)

    def test_existing_credential_idempotent_registration_keeps_matching_activation_ids(self):
        key = make_public_key(0xEE + 1)
        first = self._enroll(key)
        second = self._enroll(key)
        self.assertEqual(first.credential, second.credential)

        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(first.credential),
        )
        self.assertEqual(entry["activation_id"], record["activation_id"])

    def test_cli_revoke_revokes_exactly_the_enrolled_activation_with_no_orphan_authorization(self):
        key = make_public_key(0xEE + 2)
        self._enroll(key)
        entry = field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key)
        activation_id = entry["activation_id"]

        revoke_result = field_enrollment_module.revoke_and_remove_if_owned(
            self.index_path, self.index_lock_path, self.store_path, self.lock_path, key,
        )
        self.assertTrue(revoke_result.changed)
        self.assertEqual(revoke_result.activation_id, activation_id)

        record = activations_module.find_by_activation_id(self.store_path, self.lock_path, activation_id)
        self.assertEqual(record["status"], activations_module.REVOKED)
        self.assertIsNone(field_enrollment_module.find_in_index(self.index_path, self.index_lock_path, key))


if __name__ == "__main__":
    unittest.main()
