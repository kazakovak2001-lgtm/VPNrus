"""B8K2A - narrow tests for xray_activation: revocation-to-running-process
convergence, recovery/reconcile idempotence, and the "skip if unchanged"
optimization at the module level (not just observed indirectly through
the HTTP endpoint, see test_xray_profile_endpoint.py for that)."""
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
from api import xray_activation as xray_activation_module
from api import xray_provisioning as xray_provisioning_module
from _fixtures import make_public_key, make_xray_app_config, set_plan, write_fake_provision_script


class XrayActivationTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script_path = write_fake_provision_script(self._tmp.name)

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.app_config = make_xray_app_config(
            self._tmp.name, script_path, self.activation_store_path, self.activation_lock_path,
        )
        self.xray_plan_path = os.path.join(self._tmp.name, "xray-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.xray_plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.app_config.xray_staging_config_path
        set_plan(self.xray_plan_path, "ACTIVATE")

        self.key_a = make_public_key(0x50)

    def _issue_bind_confirm(self, max_devices=1):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=max_devices,
        )
        decision = activations_module.decide_and_bind(credential, self.key_a, self.activation_store_path, self.activation_lock_path)
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        activations_module.finalize_reservation(credential, self.key_a, self.activation_store_path, self.activation_lock_path)
        return activation_id, credential


class RevocationConvergenceTests(XrayActivationTestBase):
    def test_revoked_activation_identity_is_excluded_from_the_next_activated_config(self):
        activation_id, credential = self._issue_bind_confirm()
        result = xray_provisioning_module.provision_and_activate_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.app_config.xray_store_path, self.app_config.xray_lock_path,
            activate_fn=lambda: xray_activation_module.activate_if_needed(self.app_config),
        )
        self.assertTrue(result.activated)

        with open(self.app_config.xray_staging_config_path, "r", encoding="utf-8") as handle:
            staged_before = json.load(handle)
        self.assertEqual(len(staged_before["inbounds"][0]["settings"]["clients"]), 1)

        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        # Force re-activation (canonical state changed - revoke - so this
        # must NOT be skipped by the "unchanged" optimization).
        activation_result = xray_activation_module.reconcile(self.app_config)
        self.assertTrue(activation_result.activated)
        self.assertFalse(activation_result.skipped)

        with open(self.app_config.xray_staging_config_path, "r", encoding="utf-8") as handle:
            staged_after = json.load(handle)
        self.assertEqual(staged_after["inbounds"][0]["settings"]["clients"], [])

    def test_reload_failure_during_revoke_convergence_does_not_restore_authorization(self):
        _activation_id, credential = self._issue_bind_confirm()
        activation_id, _ = _activation_id, credential
        result = xray_provisioning_module.provision_and_activate_identity(
            credential, self.key_a,
            self.activation_store_path, self.activation_lock_path,
            self.app_config.xray_store_path, self.app_config.xray_lock_path,
            activate_fn=lambda: xray_activation_module.activate_if_needed(self.app_config),
        )
        self.assertTrue(result.activated)

        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        set_plan(self.xray_plan_path, "FAIL_ACTIVATION_ROLLED_BACK")
        activation_result = xray_activation_module.reconcile(self.app_config)
        self.assertFalse(activation_result.activated)

        # The durable authorization state is what matters here - it must
        # remain REVOKED regardless of the reload failure above. Fail
        # closed: convergence may be retried, but the revoke itself is
        # never undone by a runtime failure.
        record = activations_module.find_by_activation_id(self.activation_store_path, self.activation_lock_path, activation_id)
        self.assertEqual(record["status"], activations_module.REVOKED)


class RecoveryReconcileTests(XrayActivationTestBase):
    def test_reconcile_is_idempotent(self):
        self._issue_bind_confirm()
        first = xray_activation_module.reconcile(self.app_config)
        self.assertTrue(first.activated)
        self.assertFalse(first.skipped)

        second = xray_activation_module.reconcile(self.app_config)
        self.assertTrue(second.activated)
        self.assertTrue(second.skipped)  # nothing changed - the wrapper is not re-invoked

    def test_reconcile_recovers_after_a_prior_reload_failure(self):
        self._issue_bind_confirm()
        set_plan(self.xray_plan_path, "FAIL_ACTIVATION_ROLLED_BACK")
        failed = xray_activation_module.reconcile(self.app_config)
        self.assertFalse(failed.activated)

        set_plan(self.xray_plan_path, "ACTIVATE")
        recovered = xray_activation_module.reconcile(self.app_config)
        self.assertTrue(recovered.activated)
        self.assertFalse(recovered.skipped)


class TlsCandidateTests(XrayActivationTestBase):
    """B8O2 - build_tls_config / activate_if_needed rendering BOTH inbounds
    when TLS is configured, and REALITY-only behavior unaffected when it's
    not (the default self.app_config from setUp has no TLS fields set)."""

    def test_tls_unconfigured_build_tls_config_returns_none(self):
        self.assertIsNone(xray_activation_module.build_tls_config(self.app_config))

    def test_tls_unconfigured_staged_config_has_only_the_reality_inbound(self):
        self._issue_bind_confirm()
        result = xray_activation_module.activate_if_needed(self.app_config)
        self.assertTrue(result.activated)
        with open(self.app_config.xray_staging_config_path, "r", encoding="utf-8") as handle:
            staged = json.load(handle)
        self.assertEqual(len(staged["inbounds"]), 1)

    def test_tls_configured_staged_config_has_both_inbounds(self):
        import dataclasses
        from _fixtures import make_tls_cert_and_key_files
        cert_file, key_file = make_tls_cert_and_key_files(self._tmp.name)
        tls_config = dataclasses.replace(
            self.app_config,
            xray_tls_server_port=2053,
            xray_tls_server_name="203.0.113.1",
            xray_tls_fingerprint="chrome",
            xray_tls_cert_file=cert_file,
            xray_tls_key_file=key_file,
        )

        self._issue_bind_confirm()
        result = xray_activation_module.activate_if_needed(tls_config)
        self.assertTrue(result.activated)

        with open(tls_config.xray_staging_config_path, "r", encoding="utf-8") as handle:
            staged = json.load(handle)
        self.assertEqual(len(staged["inbounds"]), 2)
        self.assertEqual(staged["inbounds"][1]["streamSettings"]["security"], "tls")
        self.assertEqual(staged["inbounds"][1]["port"], 2053)


class ConcurrencyTests(XrayActivationTestBase):
    def test_concurrent_activation_attempts_never_corrupt_the_staged_config(self):
        self._issue_bind_confirm()
        key_b = make_public_key(0x60)
        activations_module.issue_activation(self.activation_store_path, self.activation_lock_path, max_devices=1)

        errors = []

        def worker():
            try:
                xray_activation_module.reconcile(self.app_config)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        with open(self.app_config.xray_staging_config_path, "r", encoding="utf-8") as handle:
            staged = json.load(handle)  # must parse cleanly - never a torn/partial write
        self.assertIsInstance(staged["inbounds"][0]["settings"]["clients"], list)


if __name__ == "__main__":
    unittest.main()
