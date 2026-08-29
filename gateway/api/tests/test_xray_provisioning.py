"""B8K2 - narrow tests for xray_provisioning.provision_xray_identity and
its extension of the existing activation/device-binding model.
"""
import json
import os
import sys
import tempfile
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import xray_provisioning as xray_module
from _fixtures import make_public_key


class XrayProvisioningTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.xray_store_path = os.path.join(self._tmp.name, "xray-identities.json")
        self.xray_lock_path = os.path.join(self._tmp.name, ".xray-identities.lock")
        xray_module.init_store(self.xray_store_path, self.xray_lock_path)

        self.key_a = make_public_key(0x10)
        self.key_b = make_public_key(0x20)

    def _bind_and_confirm(self, credential, public_key):
        """Reproduces the exact same two-step activations.py sequence
        POST /v1/activate's handler uses (decide_and_bind then
        finalize_reservation) - a device is only "eligible" once BOTH have
        run, matching what a real successful /v1/activate call leaves
        behind."""
        decision = activations_module.decide_and_bind(
            credential, public_key, self.activation_store_path, self.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        activations_module.finalize_reservation(
            credential, public_key, self.activation_store_path, self.activation_lock_path,
        )


class EligibilityTests(XrayProvisioningTestBase):
    def test_unknown_credential_is_not_eligible(self):
        result = xray_module.provision_xray_identity(
            "not-a-real-credential", self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result.outcome, xray_module.NOT_ELIGIBLE_UNKNOWN)

    def test_device_never_activated_is_not_eligible(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        # credential is valid, but this exact device was never bound via /v1/activate.
        result = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result.outcome, xray_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)

    def test_revoked_activation_cannot_obtain_a_profile_even_for_a_previously_bound_device(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        result = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result.outcome, xray_module.NOT_ELIGIBLE_REVOKED)

    def test_a_pending_not_yet_confirmed_device_is_not_eligible(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        decision = activations_module.decide_and_bind(
            credential, self.key_a, self.activation_store_path, self.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        # Deliberately do NOT finalize - simulates provisioning still in flight.

        result = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result.outcome, xray_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)


class IssuanceTests(XrayProvisioningTestBase):
    def test_eligible_device_is_issued_a_uuid(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        result = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result.outcome, xray_module.ISSUED)
        self.assertRegex(result.vless_uuid, r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_same_activation_and_device_retry_returns_the_same_uuid(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        first = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        second = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(first.vless_uuid, second.vless_uuid)

    def test_a_different_device_on_the_same_activation_gets_a_different_uuid(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=2,
        )
        self._bind_and_confirm(credential, self.key_a)
        self._bind_and_confirm(credential, self.key_b)

        result_a = xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        result_b = xray_module.provision_xray_identity(
            credential, self.key_b,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertNotEqual(result_a.vless_uuid, result_b.vless_uuid)

    def test_max_devices_is_still_enforced_by_the_existing_activation_semantics(self):
        # max_devices=1: a second device can never even become eligible
        # (activations.py itself rejects the second bind), so this module
        # never needs its own device-count logic at all.
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        decision = activations_module.decide_and_bind(
            credential, self.key_b, self.activation_store_path, self.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.DEVICE_LIMIT)

        result_b = xray_module.provision_xray_identity(
            credential, self.key_b,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        self.assertEqual(result_b.outcome, xray_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)

    def test_the_raw_credential_is_never_persisted_in_the_xray_store(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)
        xray_module.provision_xray_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.xray_store_path, self.xray_lock_path,
        )
        with open(self.xray_store_path, "r", encoding="utf-8") as handle:
            raw_text = handle.read()
        self.assertNotIn(credential, raw_text)


class MalformedStoreTests(XrayProvisioningTestBase):
    def test_malformed_store_fails_closed(self):
        with open(self.xray_store_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")

        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        with self.assertRaises(xray_module.XrayStoreError):
            xray_module.provision_xray_identity(
                credential, self.key_a,
                self.activation_store_path, self.activation_lock_path,
                self.xray_store_path, self.xray_lock_path,
            )

    def test_store_entry_with_duplicate_uuid_fails_closed(self):
        dup_uuid = "11111111-1111-1111-1111-111111111111"
        data = {
            "a" * 64: [
                {"device_public_key": self.key_a, "vless_uuid": dup_uuid, "created_at": "2026-01-01T00:00:00+00:00"},
            ],
            "b" * 64: [
                {"device_public_key": self.key_b, "vless_uuid": dup_uuid, "created_at": "2026-01-01T00:00:00+00:00"},
            ],
        }
        with self.assertRaises(xray_module.XrayStoreError):
            xray_module.parse_store(json.dumps(data))


class ConcurrencyTests(XrayProvisioningTestBase):
    def test_concurrent_same_device_provisioning_creates_exactly_one_identity(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        self._bind_and_confirm(credential, self.key_a)

        results = []
        errors = []

        def worker():
            try:
                results.append(
                    xray_module.provision_xray_identity(
                        credential, self.key_a,
                        self.activation_store_path, self.activation_lock_path,
                        self.xray_store_path, self.xray_lock_path,
                    )
                )
            except Exception as exc:  # pragma: no cover - surfaced via errors list
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        uuids = {r.vless_uuid for r in results}
        self.assertEqual(len(uuids), 1)  # exactly one identity, never two

        stored = xray_module.read_store_shared(self.xray_store_path, self.xray_lock_path)
        digest = activations_module.credential_digest(credential)
        self.assertEqual(len(stored[digest]), 1)

    def test_concurrent_different_device_provisioning_does_not_corrupt_state(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=8,
        )
        keys = [make_public_key(i) for i in range(0x30, 0x38)]
        for key in keys:
            self._bind_and_confirm(credential, key)

        results = []
        errors = []

        def worker(key):
            try:
                results.append(
                    xray_module.provision_xray_identity(
                        credential, key,
                        self.activation_store_path, self.activation_lock_path,
                        self.xray_store_path, self.xray_lock_path,
                    )
                )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(key,)) for key in keys]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        stored = xray_module.read_store_shared(self.xray_store_path, self.xray_lock_path)
        digest = activations_module.credential_digest(credential)
        self.assertEqual(len(stored[digest]), len(keys))  # no lost writes, no corruption
        self.assertEqual({d["device_public_key"] for d in stored[digest]}, set(keys))
        uuids = [d["vless_uuid"] for d in stored[digest]]
        self.assertEqual(len(uuids), len(set(uuids)))  # every device got a distinct uuid


if __name__ == "__main__":
    unittest.main()
