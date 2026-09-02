"""B25 (task F/G/H/I) - narrow tests for ingress_activation: the render
step points at the pinned upstream EXIT (never freedom), revocation
converges the SAME way xray_activation already proves, and the ingress's
own REALITY private key / the upstream relay uuid never leak."""
import json
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import activations as activations_module
from api import ingress_activation as ingress_activation_module
from api import xray_provisioning as xray_provisioning_module
from _fixtures import make_ingress_config, make_public_key, set_plan


class IngressActivationTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ingress_cfg = make_ingress_config(self._tmp.name)

        self.plan_path = os.path.join(self._tmp.name, "ingress-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.ingress_cfg.ingress_staging_config_path
        set_plan(self.plan_path, "ACTIVATE")

        self.key_a = make_public_key(0x60)

    def _issue_bind_confirm(self, max_devices=1):
        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=max_devices,
        )
        decision = activations_module.decide_and_bind(
            credential, self.key_a, self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)
        activations_module.finalize_reservation(
            credential, self.key_a, self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
        )
        return activation_id, credential


class UpstreamRoutingTests(IngressActivationTestBase):
    def test_activated_config_routes_exclusively_to_the_pinned_upstream_exit_never_freedom(self):
        _activation_id, credential = self._issue_bind_confirm()
        result = xray_provisioning_module.provision_and_activate_identity(
            credential, self.key_a,
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
            self.ingress_cfg.xray_store_path, self.ingress_cfg.xray_lock_path,
            activate_fn=lambda: ingress_activation_module.activate_if_needed(self.ingress_cfg),
        )
        self.assertTrue(result.activated)

        with open(self.ingress_cfg.ingress_staging_config_path, "r", encoding="utf-8") as handle:
            staged = json.load(handle)

        outbound_tags = {o["tag"] for o in staged["outbounds"]}
        self.assertNotIn("freedom", outbound_tags)
        self.assertNotIn("direct", outbound_tags)
        self.assertEqual(len(staged["outbounds"]), 1)
        upstream_outbound = staged["outbounds"][0]
        self.assertEqual(upstream_outbound["settings"]["vnext"][0]["address"], self.ingress_cfg.ingress_upstream_host)
        self.assertEqual(upstream_outbound["settings"]["vnext"][0]["port"], self.ingress_cfg.ingress_upstream_port)
        for rule in staged["routing"]["rules"]:
            self.assertEqual(rule["outboundTag"], upstream_outbound["tag"])

    def test_upstream_relay_uuid_and_ingress_private_key_never_appear_in_the_staged_config_serialization(self):
        # The RAW staged config DOES contain the upstream uuid (xray-core
        # needs it to actually authenticate) - what must never leak is the
        # REDACTED form this module hands to logs/diagnostics/PR text (task
        # M's "no relay/private credentials in diagnostics").
        _activation_id, credential = self._issue_bind_confirm()
        ingress_activation_module.provision_and_activate(credential, self.key_a, self.ingress_cfg)

        from api import xray_ingress_config_renderer as ingress_renderer
        reality = ingress_activation_module.build_reality_config(self.ingress_cfg)
        upstream = ingress_activation_module.build_upstream_config(self.ingress_cfg)
        activations_data = activations_module.read_store_shared(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
        )
        xray_data = xray_provisioning_module.read_store_shared(self.ingress_cfg.xray_store_path, self.ingress_cfg.xray_lock_path)
        redacted = ingress_renderer.render_ingress_server_config_redacted(activations_data, xray_data, reality, upstream)
        redacted_text = json.dumps(redacted)

        with open(self.ingress_cfg.ingress_upstream_uuid_file, "r", encoding="utf-8") as handle:
            raw_upstream_uuid = handle.read().strip()
        with open(self.ingress_cfg.ingress_reality_private_key_file, "r", encoding="utf-8") as handle:
            raw_private_key = handle.read().strip()
        self.assertNotIn(raw_upstream_uuid, redacted_text)
        self.assertNotIn(raw_private_key, redacted_text)


class RevocationConvergenceTests(IngressActivationTestBase):
    def test_revoked_activation_identity_is_excluded_from_the_next_activated_ingress_config(self):
        activation_id, credential = self._issue_bind_confirm()
        result = xray_provisioning_module.provision_and_activate_identity(
            credential, self.key_a,
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
            self.ingress_cfg.xray_store_path, self.ingress_cfg.xray_lock_path,
            activate_fn=lambda: ingress_activation_module.activate_if_needed(self.ingress_cfg),
        )
        self.assertTrue(result.activated)

        with open(self.ingress_cfg.ingress_staging_config_path, "r", encoding="utf-8") as handle:
            staged_before = json.load(handle)
        self.assertEqual(len(staged_before["inbounds"][0]["settings"]["clients"]), 1)

        activations_module.revoke_activation(self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, activation_id)

        activation_result = ingress_activation_module.reconcile(self.ingress_cfg)
        self.assertTrue(activation_result.activated)
        self.assertFalse(activation_result.skipped)

        with open(self.ingress_cfg.ingress_staging_config_path, "r", encoding="utf-8") as handle:
            staged_after = json.load(handle)
        self.assertEqual(staged_after["inbounds"][0]["settings"]["clients"], [])


class ReconcileIdempotenceTests(IngressActivationTestBase):
    def test_reconcile_is_idempotent_when_nothing_changed(self):
        _activation_id, credential = self._issue_bind_confirm()
        first = ingress_activation_module.provision_and_activate(credential, self.key_a, self.ingress_cfg)
        self.assertTrue(first.activated)

        second = ingress_activation_module.reconcile(self.ingress_cfg)
        self.assertTrue(second.activated)
        self.assertTrue(second.skipped)


if __name__ == "__main__":
    unittest.main()
