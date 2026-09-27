"""B46-4A - narrow tests for hysteria_provisioning.provision_hysteria_identity
and verify_hysteria_auth, mirroring test_xray_provisioning.py's own shape."""
import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
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

    def _provision(self, credential, public_key):
        return hysteria_module.provision_hysteria_identity(
            credential, public_key,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
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
            now=far_future,
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

    def test_no_per_device_obfuscation_secret_is_ever_minted(self):
        """Review fix (Finding 8) - upstream Salamander obfuscation is a
        listener-level server setting, never per-device; provisioning one
        would be fiction. HysteriaIdentityResult has no obfuscation_secret
        field at all any more - this test documents that removal by name so
        a future reintroduction is a deliberate, reviewed decision."""
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        result = self._provision(credential, self.key_a)
        self.assertFalse(hasattr(result, "obfuscation_secret"))

    def test_raw_secret_is_never_persisted_at_rest(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a)

        with open(self.hysteria_store_path, "r", encoding="utf-8") as handle:
            raw_store_text = handle.read()
        self.assertNotIn(result.auth_secret, raw_store_text)

    def test_retry_for_the_same_device_rotates_to_a_fresh_recoverable_secret(self):
        """Review fix - the previous version of this test (and of
        provision_hysteria_identity itself) treated a retry as a no-op that
        returned an EMPTY auth_secret, permanently stranding a device whose
        first response was lost. Retry must instead be RECOVERABLE: it
        returns a fresh, valid, non-empty secret every time, never an empty
        one - see [RetrySafeRotationTests] below for the full rotation
        contract (old-secret invalidation, new-secret validity, single
        stored record)."""
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        first = self._provision(credential, self.key_a)
        second = self._provision(credential, self.key_a)
        self.assertEqual(first.outcome, hysteria_module.ISSUED)
        self.assertEqual(second.outcome, hysteria_module.ISSUED)
        self.assertTrue(second.auth_secret)
        self.assertRegex(second.auth_secret, r"^[0-9a-f]{64}$")
        # Rotation REPLACES, never appends - the store still contains
        # exactly one identity for this device, not a growing history.
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


class RetrySafeRotationTests(HysteriaProvisioningTestBase):
    """Review fix (Finding 2) - full regression coverage for the corrected
    retry-safe rotation contract: rotation is NOT byte-identical idempotence
    (documented as such), but every legitimate retry recovers a working
    secret and the previous one is durably invalidated."""

    def _issue_activation_and_bind(self, **issue_kwargs):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1, **issue_kwargs,
        )
        self._bind_and_confirm(credential, self.key_a)
        return activation_id, credential

    def _verify(self, secret, now=None):
        return hysteria_module.verify_hysteria_auth(
            secret,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
            now=now,
        )

    def test_initial_provisioning_returns_a_working_secret(self):
        _activation_id, credential = self._issue_activation_and_bind()
        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.ISSUED)
        self.assertTrue(self._verify(result.auth_secret).ok)

    def test_retry_returns_a_different_valid_secret(self):
        _activation_id, credential = self._issue_activation_and_bind()
        first = self._provision(credential, self.key_a)
        second = self._provision(credential, self.key_a)
        self.assertNotEqual(first.auth_secret, second.auth_secret)
        self.assertTrue(self._verify(second.auth_secret).ok)

    def test_old_secret_stops_authenticating_after_rotation(self):
        _activation_id, credential = self._issue_activation_and_bind()
        first = self._provision(credential, self.key_a)
        self.assertTrue(self._verify(first.auth_secret).ok)

        self._provision(credential, self.key_a)  # rotate

        self.assertFalse(self._verify(first.auth_secret).ok)

    def test_new_secret_authenticates_after_rotation(self):
        _activation_id, credential = self._issue_activation_and_bind()
        self._provision(credential, self.key_a)
        second = self._provision(credential, self.key_a)

        self.assertTrue(self._verify(second.auth_secret).ok)

    def test_store_still_contains_no_raw_secret_after_rotation(self):
        _activation_id, credential = self._issue_activation_and_bind()
        first = self._provision(credential, self.key_a)
        second = self._provision(credential, self.key_a)

        with open(self.hysteria_store_path, "r", encoding="utf-8") as handle:
            raw_store_text = handle.read()
        self.assertNotIn(first.auth_secret, raw_store_text)
        self.assertNotIn(second.auth_secret, raw_store_text)

    def test_a_failed_atomic_write_preserves_the_previous_valid_credential(self):
        _activation_id, credential = self._issue_activation_and_bind()
        first = self._provision(credential, self.key_a)
        self.assertTrue(self._verify(first.auth_secret).ok)

        with unittest.mock.patch.object(
            hysteria_module.hysteria_store, "atomic_write_store_or_raise",
            side_effect=hysteria_module.hysteria_store.HysteriaStoreLockError("simulated durable-write failure"),
        ):
            with self.assertRaises(hysteria_module.hysteria_store.HysteriaStoreLockError):
                self._provision(credential, self.key_a)

        # The failed rotation must never have partially applied - the
        # original secret is still exactly as valid as before the attempt.
        self.assertTrue(self._verify(first.auth_secret).ok)

    def test_concurrent_retries_serialize_and_exactly_one_final_secret_survives(self):
        _activation_id, credential = self._issue_activation_and_bind()
        results = []
        lock = threading.Lock()

        def worker():
            result = self._provision(credential, self.key_a)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.outcome == hysteria_module.ISSUED for r in results))
        # Exactly one secret among the five concurrent attempts is the
        # final, durably-stored one - every attempt fully serialized
        # through the per-activation lock, never interleaved/corrupted.
        valid_secrets = [r.auth_secret for r in results if self._verify(r.auth_secret).ok]
        self.assertEqual(len(valid_secrets), 1)
        digest = activations_module.credential_digest(credential)
        data = hysteria_store.read_store_shared(self.hysteria_store_path, self.hysteria_lock_path)
        self.assertEqual(len(data[digest]), 1)

    def test_revoked_activation_cannot_rotate_or_reissue(self):
        activation_id, credential = self._issue_activation_and_bind()
        first = self._provision(credential, self.key_a)
        self.assertTrue(self._verify(first.auth_secret).ok)

        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        result = self._provision(credential, self.key_a)
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_REVOKED)
        self.assertEqual(result.auth_secret, "")
        # The already-issued secret is ALSO invalidated the instant the
        # activation is revoked - live consultation, not just future mints.
        self.assertFalse(self._verify(first.auth_secret).ok)

    def test_expired_activation_cannot_rotate_or_reissue(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1, expires_in_days=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        first = self._provision(credential, self.key_a)
        self.assertEqual(first.outcome, hysteria_module.ISSUED)

        far_future = datetime.now(timezone.utc) + timedelta(days=2)
        result = hysteria_module.provision_hysteria_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.hysteria_store_path, self.hysteria_lock_path,
            now=far_future,
        )
        self.assertEqual(result.outcome, hysteria_module.NOT_ELIGIBLE_EXPIRED)
        self.assertEqual(result.auth_secret, "")


class AuthVerificationTests(HysteriaProvisioningTestBase):
    def _issue(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        result = self._provision(credential, self.key_a)
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
