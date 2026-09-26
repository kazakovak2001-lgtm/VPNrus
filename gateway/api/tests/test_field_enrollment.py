"""Unit tests for gateway/api/field_enrollment.py - the module functions
directly, no HTTP layer (see test_field_enroll_endpoint.py for the
HTTP-level contract).

Round-2 review fix: credentials are now genuinely random (never derived
from a server secret) - the tests below cover the FieldEnrollmentIndex's
own idempotency/cap-race-freedom instead of any determinism property.
"""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import field_enrollment as field_enrollment_module
from _fixtures import make_public_key, set_plan, write_fake_provision_script


class EnrollDeviceTests(unittest.TestCase):
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

    def _enroll(self, public_key, cap=5):
        return field_enrollment_module.enroll_device(
            public_key,
            self.index_path, self.index_lock_path,
            self.store_path, self.lock_path,
            self.script_path, 5.0,
            global_device_cap=cap,
        )

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
        """No shared secret exists anymore - re-enrolling the SAME public
        key must not deterministically reproduce anything computable
        without consulting the index (proven indirectly: two independent
        index files for the same key produce different credentials)."""
        key = make_public_key(0x25)
        other_index = os.path.join(self._tmp.name, "other-index.json")
        other_lock = os.path.join(self._tmp.name, ".other-index.lock")
        r1 = self._enroll(key)
        r2 = field_enrollment_module.enroll_device(
            key, other_index, other_lock, self.store_path, self.lock_path,
            self.script_path, 5.0, global_device_cap=5,
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
        _activation_id, _credential = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=10)
        _activation_id2, _credential2 = activations_module.issue_activation(self.store_path, self.lock_path, max_devices=10)
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


if __name__ == "__main__":
    unittest.main()
