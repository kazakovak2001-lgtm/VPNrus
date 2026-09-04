"""B31A - the ingress role's own device-binding authority
(xray_provisioning.provision_and_activate_identity_selfbind /
ingress_activation.provision_and_activate). Root cause this closes: the
real Android client's activateIngress() calls POST /v1/ingress-profile
directly, with NO prior POST /v1/activate - but the ingress role reused
provision_and_activate_identity's own CONFIRMED-device eligibility gate,
which only ever became CONFIRMED via activations.finalize_reservation,
called ONLY from POST /v1/activate's own AWG-peer-provisioning flow - a
flow an ingress-only host never runs at all (POCVPN_API_PROVISION_SCRIPT_PATH
is a permanent no-op there). The result: device_not_bound, forever, for
every real device. These tests exercise the FIRST-USE self-binding
authority directly (never pre-binding via a manual decide_and_bind/
finalize_reservation call, and never calling POST /v1/activate first) -
the exact real-world shape the previous test suite never actually covered.
"""
import inspect
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
from api import ingress_activation as ingress_activation_module
from api import xray_provisioning as xray_provisioning_module
from _fixtures import (
    RunningServer,
    make_app_config,
    make_ingress_config,
    make_public_key,
    make_xray_app_config,
    set_plan,
    write_fake_provision_script,
)
from _http import post_activate, post_ingress_profile, post_xray_profile


class SelfBindTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ingress_cfg = make_ingress_config(self._tmp.name)

        self.plan_path = os.path.join(self._tmp.name, "ingress-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.ingress_cfg.ingress_staging_config_path
        set_plan(self.plan_path, "ACTIVATE")

        self.key_a = make_public_key(0x80)
        self.key_b = make_public_key(0x81)

    def _activate_fn(self):
        return ingress_activation_module.activate_if_needed(self.ingress_cfg)

    def _selfbind(self, credential, public_key):
        return xray_provisioning_module.provision_and_activate_identity_selfbind(
            credential, public_key,
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path,
            self.ingress_cfg.xray_store_path, self.ingress_cfg.xray_lock_path,
            activate_fn=self._activate_fn,
        )


# --- 1/2/3/4/5 - first-use binding, idempotency, conflict, invalid/malformed ---

class FirstUseBindingTests(SelfBindTestBase):
    def test_valid_first_request_binds_and_provisions_with_no_prior_activate_call(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        result = self._selfbind(credential, self.key_a)
        self.assertTrue(result.activated)
        self.assertEqual(result.identity_outcome.outcome, xray_provisioning_module.ISSUED)
        self.assertTrue(result.is_new_identity)

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["public_key"], self.key_a)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)

    def test_same_credential_and_key_retry_is_idempotent(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        first = self._selfbind(credential, self.key_a)
        second = self._selfbind(credential, self.key_a)
        self.assertTrue(first.activated)
        self.assertTrue(second.activated)
        self.assertEqual(first.identity_outcome.vless_uuid, second.identity_outcome.vless_uuid)
        self.assertFalse(second.is_new_identity)

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)  # never a second entry

    def test_conflicting_key_for_an_already_bound_credential_fails_closed(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        first = self._selfbind(credential, self.key_a)
        self.assertTrue(first.activated)

        second = self._selfbind(credential, self.key_b)
        self.assertEqual(second.identity_outcome.outcome, xray_provisioning_module.NOT_ELIGIBLE_DEVICE_LIMIT)
        self.assertIsNone(second.activated)  # never even attempted activation for the rejected key

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["public_key"], self.key_a)

    def test_invalid_credential_fails_closed(self):
        result = self._selfbind("this-credential-was-never-issued", self.key_a)
        self.assertEqual(result.identity_outcome.outcome, xray_provisioning_module.NOT_ELIGIBLE_UNKNOWN)
        self.assertIsNone(result.activated)

    def test_revoked_credential_fails_closed(self):
        activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        activations_module.revoke_activation(self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, activation_id)
        result = self._selfbind(credential, self.key_a)
        self.assertEqual(result.identity_outcome.outcome, xray_provisioning_module.NOT_ELIGIBLE_REVOKED)

    def test_malformed_public_key_fails_closed_at_the_http_layer(self):
        # The selfbind function itself trusts its caller's own key
        # validation (same contract as provision_and_activate_identity) -
        # the real fail-closed boundary for a malformed key is the HTTP
        # handler's _parse_and_validate_xray_profile_body, exercised here
        # through the real POST /v1/ingress-profile path.
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        script_path = write_fake_provision_script(self._tmp.name)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(self._tmp.name, "peer-plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")
        app_config = make_app_config(self._tmp.name, script_path)
        server = RunningServer(app_config, ingress_config=self.ingress_cfg)
        self.addCleanup(server.close)

        status, _headers, body = post_ingress_profile(server.port, credential=credential, body_obj={"public_key": "not-a-real-key"})
        self.assertEqual(status, 400)
        self.assertIn(b"invalid_public_key", body)

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 0)  # malformed key never reaches decide_and_bind at all


# --- 6/7/8 - role-boundary isolation from AWG/the regular gateway ---

class RoleBoundaryTests(SelfBindTestBase):
    def test_selfbind_never_references_the_awg_provisioning_script_or_run_provision_peer(self):
        # Structural proof, not merely behavioral: IngressAppConfig has no
        # provision_script_path field at all (see ingress_config.py), and
        # neither xray_provisioning.py nor ingress_activation.py's source
        # ever names provision.run_provision_peer or provision_script_path.
        self.assertFalse(hasattr(self.ingress_cfg, "provision_script_path"))
        # Check the CODE, not the docstring (which deliberately explains,
        # in prose, why this function does NOT do these things) - strip
        # each function's own __doc__ before searching.
        selfbind_source = inspect.getsource(xray_provisioning_module.provision_and_activate_identity_selfbind)
        # The docstring is delimited by the first two `"""` markers - keep
        # only what comes after it (the real code body).
        selfbind_code_only = selfbind_source.split('"""', 2)[-1]
        self.assertNotIn("run_provision_peer(", selfbind_code_only)
        self.assertNotIn(".provision_script_path", selfbind_code_only)
        # Module-level: no import of gateway.api.provision at all.
        self.assertNotIn("from . import provision", inspect.getsource(xray_provisioning_module))
        self.assertNotIn("from . import provision", inspect.getsource(ingress_activation_module))

    def test_ordinary_xray_profile_gate_is_unchanged_still_requires_a_real_activate_binding(self):
        # provision_and_activate_identity (the REGULAR gateway's own
        # function, untouched by B31A) must still reject a device that
        # never went through POST /v1/activate - byte-for-byte the
        # pre-B31A behavior.
        with tempfile.TemporaryDirectory() as gw_tmp:
            activation_store_path = os.path.join(gw_tmp, "activations.json")
            activation_lock_path = os.path.join(gw_tmp, ".activations.lock")
            activations_module.init_store(activation_store_path, activation_lock_path)
            xray_cfg = make_xray_app_config(
                gw_tmp, "/nonexistent/provision-peer.sh", activation_store_path, activation_lock_path,
            )
            _activation_id, credential = activations_module.issue_activation(
                activation_store_path, activation_lock_path, max_devices=1,
            )
            from api import xray_activation as xray_activation_module

            result = xray_provisioning_module.provision_and_activate_identity(
                credential, self.key_a,
                activation_store_path, activation_lock_path,
                xray_cfg.xray_store_path, xray_cfg.xray_lock_path,
                activate_fn=lambda: xray_activation_module.activate_if_needed(xray_cfg),
            )
            self.assertEqual(result.identity_outcome.outcome, xray_provisioning_module.NOT_ELIGIBLE_DEVICE_NOT_BOUND)

    def test_a_device_confirmed_only_via_ingress_selfbind_cannot_satisfy_a_separately_configured_gateways_xray_profile_gate(self):
        # Real-deployment shape: the ingress role's own activation store
        # (self.ingress_cfg's) is a physically DIFFERENT file from a real
        # gateway's own POCVPN_API_ACTIVATION_STORE_PATH-configured store -
        # binding a device against one can never be observed by the other.
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        result = self._selfbind(credential, self.key_a)
        self.assertTrue(result.activated)  # confirmed in the INGRESS store

        with tempfile.TemporaryDirectory() as gw_tmp:
            gw_activation_store_path = os.path.join(gw_tmp, "activations.json")
            gw_activation_lock_path = os.path.join(gw_tmp, ".activations.lock")
            activations_module.init_store(gw_activation_store_path, gw_activation_lock_path)
            xray_cfg = make_xray_app_config(
                gw_tmp, "/nonexistent/provision-peer.sh", gw_activation_store_path, gw_activation_lock_path,
            )
            from api import xray_activation as xray_activation_module

            # SAME credential digest would only collide if issued into the
            # gateway's own store too - it was never issued there at all,
            # so this is the same NOT_ELIGIBLE_UNKNOWN a totally foreign
            # credential would get, proving no leakage across stores.
            gw_result = xray_provisioning_module.provision_and_activate_identity(
                credential, self.key_a,
                gw_activation_store_path, gw_activation_lock_path,
                xray_cfg.xray_store_path, xray_cfg.xray_lock_path,
                activate_fn=lambda: xray_activation_module.activate_if_needed(xray_cfg),
            )
            self.assertEqual(gw_result.identity_outcome.outcome, xray_provisioning_module.NOT_ELIGIBLE_UNKNOWN)


# --- 9/10/11 - concurrency / idempotency / partial-failure recovery ---

class ConcurrencyTests(SelfBindTestBase):
    def test_concurrent_same_identity_requests_are_race_safe(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        results = []
        results_lock = threading.Lock()

        def attempt():
            result = self._selfbind(credential, self.key_a)
            with results_lock:
                results.append(result)

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(results), 4)
        for result in results:
            self.assertTrue(result.activated)
            self.assertEqual(result.identity_outcome.outcome, xray_provisioning_module.ISSUED)
        uuids = {r.identity_outcome.vless_uuid for r in results}
        self.assertEqual(len(uuids), 1)  # one logical binding, same uuid for every winner

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)

    def test_concurrent_conflicting_key_requests_are_fail_closed(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        results = []
        results_lock = threading.Lock()

        def attempt(key):
            result = self._selfbind(credential, key)
            with results_lock:
                results.append(result)

        t1 = threading.Thread(target=attempt, args=(self.key_a,))
        t2 = threading.Thread(target=attempt, args=(self.key_b,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        outcomes = sorted(
            xray_provisioning_module.ISSUED if r.identity_outcome.outcome == xray_provisioning_module.ISSUED
            else r.identity_outcome.outcome
            for r in results
        )
        self.assertEqual(outcomes, sorted([xray_provisioning_module.ISSUED, xray_provisioning_module.NOT_ELIGIBLE_DEVICE_LIMIT]))

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)  # never both, never zero

    def test_partial_activation_failure_does_not_leave_a_false_confirmed_binding_and_is_recoverable(self):
        set_plan(self.plan_path, "FAIL_VALIDATION")
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        failed = self._selfbind(credential, self.key_a)
        self.assertFalse(failed.activated)
        self.assertIsNotNone(failed.activation_error)

        # No false-success state: the pending reservation was rolled back,
        # never left as a phantom CONFIRMED (or even PENDING) entry.
        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 0)

        # Recoverable: a retry after the transient fault clears succeeds
        # as a genuinely fresh first-use attempt (still BOUND_NEW under
        # the hood), never stuck "reserved" against the failed attempt.
        set_plan(self.plan_path, "ACTIVATE")
        retried = self._selfbind(credential, self.key_a)
        self.assertTrue(retried.activated)
        self.assertEqual(retried.identity_outcome.outcome, xray_provisioning_module.ISSUED)

        record = activations_module.find_by_activation_id(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, _activation_id,
        )
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)


# --- HTTP-level: the real POST /v1/ingress-profile path, no prior /v1/activate ---

class IngressProfileHttpFirstUseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ingress_cfg = make_ingress_config(self._tmp.name)

        self.plan_path = os.path.join(self._tmp.name, "ingress-plan.txt")
        os.environ["POCVPN_FAKE_XRAY_PLAN"] = self.plan_path
        os.environ["POCVPN_FAKE_XRAY_STAGING"] = self.ingress_cfg.ingress_staging_config_path
        set_plan(self.plan_path, "ACTIVATE")

        # A deliberately-broken /v1/peers provisioner - proves a real HTTP
        # POST /v1/ingress-profile success never depends on it (item 6, at
        # the HTTP layer): if the ingress path ever accidentally invoked
        # it, this would fail loudly rather than silently succeeding.
        app_config = make_app_config(self._tmp.name, "/nonexistent/provision-peer.sh")
        self.server = RunningServer(app_config, ingress_config=self.ingress_cfg)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x82)
        self.key_b = make_public_key(0x83)

    def test_real_first_ingress_profile_request_succeeds_with_no_prior_activate_call(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        status, _headers, body = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertRegex(payload["uuid"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_real_second_device_over_the_http_layer_gets_device_limit_not_device_not_bound(self):
        _activation_id, credential = activations_module.issue_activation(
            self.ingress_cfg.activation_store_path, self.ingress_cfg.activation_lock_path, max_devices=1,
        )
        status_a, _h_a, _b_a = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status_a, 200)

        status_b, _h_b, body_b = post_ingress_profile(self.server.port, credential=credential, body_obj={"public_key": self.key_b})
        self.assertEqual(status_b, 403)
        self.assertIn(b"device_limit", body_b)
        self.assertNotIn(b"device_not_bound", body_b)


if __name__ == "__main__":
    unittest.main()
