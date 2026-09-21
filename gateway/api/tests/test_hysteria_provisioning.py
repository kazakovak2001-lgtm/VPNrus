"""B46-4A - narrow tests for hysteria_provisioning.provision_hysteria_identity
and verify_hysteria_auth, mirroring test_xray_provisioning.py's own shape."""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import hysteria_provisioning as hysteria_module
from api import hysteria_store
from _fixtures import make_public_key


class HysteriaProvisioningTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.hysteria_store_path = os.path.join(self._tmp.name, "hysteria-identities.json")
        self.hysteria_lock_path = os.path.join(self._tmp.name, ".hysteria-identities.lock")
        hysteria_store.init_store(self.hysteria_store_path, self.hysteria_lock_path)

        self.key_a = make_public_key(0x10)
        self.key_b = make_public_key(0x20)

    def _bind_and_confirm(self, credential, public_key):
        decision = activations_module.decide_and_bind(
            credential, public_key, self.activation_store_path, self.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        activations_module.finalize_reservation(
            credential, public_key, self.activation_store_path, self.activation_lock_path,
        )

    def _provision(self, credential, public_key, use_obfuscation=False):
        return hysteria_module.provision_hysteria_identity(
            credential, public_key,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
            use_obfuscation,
        )


class EligibilityTests(HysteriaProvisioningTestBase):
    def test_unknown_credential_is_not_eligible(self):
        result = self._provision("not-a-real-credential", self.key_a)
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_UNKNOWN)

    def test_device_never_activated_is_not_eligible(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)

    def test_revoked_activation_cannot_obtain_a_credential_even_for_a_previously_bound_device(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_REVOKED)

    def test_expired_activation_cannot_obtain_a_credential(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1, expires_in_days=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        far_future = datetime.now(timezone.utc) + timedelta(days=2)

        result = hysteria_module.provision_hysteria_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
            use_obfuscation=False, now=far_future,
        )
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_EXPIRED)

    def test_device_mismatch_is_not_eligible(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        # key_b never went through /v1/activate for this credential.
        result = self._provision(credential, self.key_b)
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)


class IssuanceTests(HysteriaProvisioningTestBase):
    def test_eligible_device_is_issued_an_auth_secret(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.ISSUED)
        self.assertRegex(result.auth_secret, r"^[0-9a-f]{64}$")
        self.assertIsNone(result.obfuscation_secret)

    def test_obfuscation_secret_issued_only_when_requested(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        result = self._provision(credential, self.key_a, use_obfuscation=True)
        self.assertEqual(result.outcome, hysteria_module.ISSUED)
        self.assertRegex(result.obfuscation_secret, r"^[0-9a-f]{64}$")
        self.assertNotEqual(result.auth_secret, result.obfuscation_secret)

    def test_raw_secret_is_never_persisted_at_rest(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a)

        with open(self.hysteria_store_path, "r", encoding="utf-8") as handle:
            raw_store_text = handle.read()
        self.assertNotIn(result.auth_secret, raw_store_text)

    def test_retry_for_the_same_device_does_not_mint_a_second_identity(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        first = self._provision(credential, self.key_a)
        second = self._provision(credential, self.key_a)
        self.assertEqual(first.outcome, hysteria_module.ISSUED)
        self.assertEqual(second.outcome, hysteria_module.ISSUED)
        # A retry never re-mints (and cannot recover the original raw
        # secret - see provision_hysteria_identity's own doc); the store
        # itself must still contain exactly one identity for this device.
        digest = activations_module.credential_digest(credential)
        data = hysteria_store.read_store_shared(self.hysteria_store_path, self.hysteria_lock_path)
        self.assertEqual(len(data[digest]), 1)

    def test_two_different_devices_on_the_same_activation_get_independent_secrets(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=2,
        )
        self._bind_and_confirm(credential, self.key_a)
        self._bind_and_confirm(credential, self.key_b)

        result_a = self._provision(credential, self.key_a)
        result_b = self._provision(credential, self.key_b)
        self.assertNotEqual(result_a.auth_secret, result_b.auth_secret)


class AuthVerificationTests(HysteriaProvisioningTestBase):
    def _issue(self, use_obfuscation=False):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a, use_obfuscation=use_obfuscation)
        return credential, result

    def _verify(self, secret, now=None):
        return hysteria_module.verify_hysteria_auth(
            secret,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
            now=now,
        )

    def test_valid_secret_verifies_ok(self):
        _credential, result = self._issue()
        verification = self._verify(result.auth_secret)
        self.assertTrue(verification.ok)
        self.assertTrue(verification.device_id)

    def test_wrong_secret_is_rejected(self):
        self._issue()
        verification = self._verify("0" * 64)
        self.assertFalse(verification.ok)
        self.assertEqual(verification.device_id, "")

    def test_revoking_the_activation_invalidates_an_already_issued_secret_without_reprovisioning(self):
        activation_id, result = self._issue_with_activation_id()
        verification_before = self._verify(result.auth_secret)
        self.assertTrue(verification_before.ok)

        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)
        verification_after = self._verify(result.auth_secret)
        self.assertFalse(verification_after.ok)

    def test_expired_activation_invalidates_an_already_issued_secret(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1, expires_in_days=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.ISSUED)

        far_future = datetime.now(timezone.utc) + timedelta(days=2)
        verification = self._verify(result.auth_secret, now=far_future)
        self.assertFalse(verification.ok)

    def _issue_with_activation_id(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.ISSUED)
        return activation_id, result

    def test_device_id_never_reveals_the_raw_secret(self):
        _credential, result = self._issue()
        verification = self._verify(result.auth_secret)
        self.assertNotIn(result.auth_secret, verification.device_id)


if __name__ == "__main__":
    unittest.main()
