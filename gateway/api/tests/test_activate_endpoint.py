"""B8C1 - HTTP-level test for POST /v1/activate, focused on the one thing
only an end-to-end request can prove: that a provisioning failure AFTER a
new device bind does not leave the activation's device slot silently
consumed (item 9 - see gateway/api/activations.py's unbind_device and the
handler.py call site's own comment).
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
from _fixtures import RunningServer, make_app_config, make_public_key, set_plan, write_fake_provision_script
from _http import post_activate


class ActivateEndpointTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path

        self.activation_store_path = os.path.join(self._tmp.name, "activations.json")
        self.activation_lock_path = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)

        self.app_config = make_app_config(
            self._tmp.name, self.script_path,
            activation_store_path=self.activation_store_path,
            activation_lock_path=self.activation_lock_path,
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.key_a = make_public_key(0x30)

    def test_provisioning_failure_does_not_consume_the_device_slot(self):
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        set_plan(self.plan_path, "EXIT", "1")  # provision-peer.sh fails

        status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 500)

        record = activations_module.find_by_activation_id(
            self.activation_store_path, self.activation_lock_path, activation_id,
        )
        self.assertEqual(record["bound_devices"], [])  # rolled back, not consumed

        # A retry, now with provisioning working, must still succeed as a
        # fresh first-use - not blocked by a phantom consumed slot.
        set_plan(self.plan_path, "CREATED", "10.77.0.5")
        status2, _headers2, _body2 = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status2, 200)

    def test_revoke_completed_before_finalize_is_reported_as_revoked_not_success(self):
        """item 6 - the activation is revoked WHILE this request's
        provisioning subprocess is in flight (simulated here by revoking
        directly between decide_and_bind and the provisioning call, via the
        module functions in the exact order handler.py itself uses): the
        response must not be a plain 200 success once finalize observes the
        activation is no longer ACTIVE."""
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        set_plan(self.plan_path, "CREATED", "10.77.0.7")

        decision = activations_module.decide_and_bind(
            credential, self.key_a, self.activation_store_path, self.activation_lock_path,
        )
        self.assertEqual(decision.outcome, activations_module.BOUND_NEW)

        # Revoke completes strictly BEFORE this request's provisioning
        # subprocess runs (the window handler.py's finalize check covers).
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)

        from api import provision as provision_module
        outcome = provision_module.run_provision_peer(
            self.script_path, self.key_a, self.app_config.subprocess_timeout_seconds,
        )
        self.assertEqual(outcome.state, "created")  # provisioning itself succeeded

        finalize_result = activations_module.finalize_reservation(
            credential, self.key_a, self.activation_store_path, self.activation_lock_path,
        )
        self.assertTrue(finalize_result.confirmed)
        self.assertEqual(finalize_result.status, activations_module.REVOKED)

        # The binding is still durably recorded (device really was
        # provisioned) even though the activation itself is now revoked.
        record = activations_module.find_by_activation_id(self.activation_store_path, self.activation_lock_path, activation_id)
        self.assertEqual(len(record["bound_devices"]), 1)
        self.assertEqual(record["bound_devices"][0]["state"], activations_module.CONFIRMED)

    def test_http_revoke_waits_for_in_flight_provisioning_then_applies_to_next_request(self):
        """item 7 (B8C1C): revoke_activation now takes the SAME
        per-activation lock provision_with_activation holds across the
        provisioning subprocess - so a concurrent revoke can no longer race
        INTO an in-flight request's finalize window at all. It BLOCKS
        instead. The in-flight request (which already legitimately reserved
        the slot before revoke was even issued) completes successfully; the
        revoke, once it finally acquires the lock, applies cleanly
        afterward and correctly rejects the NEXT request."""
        import threading
        activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        set_plan(self.plan_path, "SLEEP", "1")

        result = {}

        def do_request():
            status, _headers, _body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
            result["status"] = status

        t = threading.Thread(target=do_request)
        t.start()
        import time
        time.sleep(0.3)  # let the request pass decide_and_bind and enter the sleeping subprocess

        revoke_start = time.monotonic()
        activations_module.revoke_activation(self.activation_store_path, self.activation_lock_path, activation_id)
        revoke_elapsed = time.monotonic() - revoke_start
        t.join(timeout=10)

        # revoke_activation must have BLOCKED for roughly the remainder of
        # the sleeping provisioning attempt, not returned instantly.
        self.assertGreater(revoke_elapsed, 0.5)
        # The in-flight request, already legitimately in progress, still succeeds.
        self.assertEqual(result.get("status"), 200)

        # Revoke has now cleanly applied - a subsequent request is rejected.
        set_plan(self.plan_path, "CREATED", "10.77.0.11")
        status2, _headers2, _body2 = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status2, 403)

    def test_valid_activation_success_returns_the_same_provisioning_fields_as_v1_peers(self):
        _activation_id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=1,
        )
        set_plan(self.plan_path, "CREATED", "10.77.0.9")

        status, _headers, body = post_activate(self.server.port, credential=credential, body_obj={"public_key": self.key_a})
        self.assertEqual(status, 200)
        import json
        payload = json.loads(body)
        self.assertEqual(payload["client_tunnel_ip"], "10.77.0.9")
        self.assertEqual(payload["gateway_public_key"], self.app_config.gateway_public_key)
        self.assertEqual(payload["endpoint_host"], self.app_config.endpoint_host)
        self.assertEqual(payload["endpoint_port"], self.app_config.endpoint_port)


if __name__ == "__main__":
    unittest.main()
