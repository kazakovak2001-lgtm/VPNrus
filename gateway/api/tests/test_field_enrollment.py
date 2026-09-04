"""Unit tests for gateway/api/field_enrollment.py - the module functions
directly, no HTTP layer (see test_field_enroll_endpoint.py for the
HTTP-level contract)."""
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


class DeriveCredentialTests(unittest.TestCase):
    def test_deterministic_for_the_same_key_and_secret(self):
        secret = b"a" * 32
        key = make_public_key(0x01)
        self.assertEqual(
            field_enrollment_module.derive_credential(secret, key),
            field_enrollment_module.derive_credential(secret, key),
        )

    def test_unique_per_public_key(self):
        secret = b"a" * 32
        c1 = field_enrollment_module.derive_credential(secret, make_public_key(0x01))
        c2 = field_enrollment_module.derive_credential(secret, make_public_key(0x02))
        self.assertNotEqual(c1, c2)

    def test_unique_per_secret(self):
        key = make_public_key(0x01)
        c1 = field_enrollment_module.derive_credential(b"a" * 32, key)
        c2 = field_enrollment_module.derive_credential(b"b" * 32, key)
        self.assertNotEqual(c1, c2)

    def test_never_the_public_key_or_secret_verbatim(self):
        secret = b"a" * 32
        key = make_public_key(0x01)
        credential = field_enrollment_module.derive_credential(secret, key)
        self.assertNotIn(key, credential)
        self.assertNotIn(secret.decode("latin-1"), credential)


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
        self.secret = b"s" * 32

    def _enroll(self, public_key, cap=5):
        return field_enrollment_module.enroll_device(
            public_key, self.secret,
            self.store_path, self.lock_path,
            self.script_path, 5.0,
            global_device_cap=cap,
        )

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

    def test_repeat_enrollment_for_the_same_public_key_is_idempotent(self):
        key = make_public_key(0x31)
        r1 = self._enroll(key)
        r2 = self._enroll(key)
        self.assertEqual(r1.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(r2.outcome, field_enrollment_module.ENROLLED)
        self.assertEqual(r1.credential, r2.credential)

        # Still exactly one bound device for this credential - a repeat
        # enrollment never grows bound_devices.
        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(r1.credential),
        )
        self.assertEqual(len(record["bound_devices"]), 1)

    def test_device_cap_reached_fails_closed(self):
        for seed in (0x40, 0x41):
            result = self._enroll(make_public_key(seed), cap=2)
            self.assertEqual(result.outcome, field_enrollment_module.ENROLLED)

        result = self._enroll(make_public_key(0x42), cap=2)
        self.assertEqual(result.outcome, field_enrollment_module.DEVICE_CAP_REACHED)

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

    def test_invalid_public_key_fails_closed_before_touching_the_store(self):
        result = self._enroll("not-a-real-key")
        self.assertEqual(result.outcome, field_enrollment_module.INVALID_PUBLIC_KEY)
        data = activations_module.read_store_shared(self.store_path, self.lock_path)
        self.assertEqual(data, {})

    def test_revoked_device_fails_closed(self):
        key = make_public_key(0x60)
        first = self._enroll(key)
        self.assertEqual(first.outcome, field_enrollment_module.ENROLLED)

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path, activations_module.credential_digest(first.credential),
        )
        activations_module.revoke_activation(self.store_path, self.lock_path, record["activation_id"])

        second = self._enroll(key)
        self.assertEqual(second.outcome, field_enrollment_module.REVOKED)

    def test_provisioning_failure_fails_closed_and_does_not_confirm_the_device(self):
        set_plan(self.plan_path, "EXIT", "1")
        key = make_public_key(0x70)
        result = self._enroll(key)
        self.assertEqual(result.outcome, field_enrollment_module.PROVISION_FAILED)

        record = activations_module.find_by_credential_digest(
            self.store_path, self.lock_path,
            activations_module.credential_digest(field_enrollment_module.derive_credential(self.secret, key)),
        )
        # BOUND_NEW's own reservation was rolled back by provision_with_activation
        # (same discipline /v1/activate already relies on) - never a phantom
        # confirmed device for a failed provisioning attempt.
        self.assertEqual(record["bound_devices"], [])


if __name__ == "__main__":
    unittest.main()
