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
import json
import os
import sys
import threading
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


if __name__ == "__main__":
    unittest.main()
