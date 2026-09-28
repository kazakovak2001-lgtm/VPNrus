"""B47 T1/T2 - the ONE entitlement predicate (activations.entitlement_state)
and every decision point that must use it: store validation, API
authorization (decide_and_bind, Xray eligibility) and Xray config
rendering (EXIT and ingress renderers).

Deliberately stdlib-only (no _fixtures import) so it runs even where the
HTTP stack's optional crypto dependency is unavailable."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import activations as activations_module  # noqa: E402
from api import xray_config_renderer as renderer  # noqa: E402
from api import xray_ingress_config_renderer as ingress_renderer  # noqa: E402
from api import xray_provisioning as xray_provisioning_module  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


def _record(status=activations_module.ACTIVE, expires_at=None, keys=(KEY_A,), activation_id="a" * 32, max_devices=4):
    return {
        "activation_id": activation_id,
        "status": status,
        "max_devices": max_devices,
        "created_at": "2026-09-01T00:00:00+00:00",
        "expires_at": expires_at,
        "bound_devices": [
            {"public_key": key, "reservation_id": "", "state": activations_module.CONFIRMED} for key in keys
        ],
    }


class EntitlementStateTests(unittest.TestCase):
    def test_active_without_expiry_is_active(self):
        self.assertEqual(activations_module.entitlement_state(_record(), NOW), activations_module.ENTITLEMENT_ACTIVE)
        self.assertTrue(activations_module.is_entitled(_record(), NOW))

    def test_revoked_is_revoked_even_if_unexpired(self):
        record = _record(status=activations_module.REVOKED, expires_at=(NOW + timedelta(days=1)).isoformat())
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_REVOKED)

    def test_before_expiry_is_active(self):
        record = _record(expires_at=(NOW + timedelta(seconds=1)).isoformat())
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_ACTIVE)

    def test_exactly_at_expiry_is_expired(self):
        record = _record(expires_at=NOW.isoformat())
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_EXPIRED)

    def test_after_expiry_is_expired_despite_status_active(self):
        record = _record(expires_at=(NOW - timedelta(minutes=1)).isoformat())
        self.assertEqual(record["status"], activations_module.ACTIVE)
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_EXPIRED)
        self.assertFalse(activations_module.is_entitled(record, NOW))

    def test_non_utc_offset_is_compared_as_an_instant(self):
        # 13:30+01:00 == 12:30Z -> still in the future at NOW (12:00Z).
        record = _record(expires_at="2026-09-28T13:30:00+01:00")
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_ACTIVE)
        record = _record(expires_at="2026-09-28T12:30:00+01:00")  # == 11:30Z
        self.assertEqual(activations_module.entitlement_state(record, NOW), activations_module.ENTITLEMENT_EXPIRED)

    def test_naive_expiry_fails_closed(self):
        record = _record(expires_at="2099-01-01T00:00:00")
        with self.assertRaises(activations_module.ActivationStoreError):
            activations_module.entitlement_state(record, NOW)

    def test_malformed_expiry_fails_closed(self):
        for bad in ("not-a-date", "", 12345):
            with self.subTest(bad=bad), self.assertRaises(activations_module.ActivationStoreError):
                activations_module.entitlement_state(_record(expires_at=bad), NOW)

    def test_naive_now_is_rejected(self):
        with self.assertRaises(ValueError):
            activations_module.entitlement_state(_record(), datetime(2026, 9, 28, 12, 0, 0))
        with self.assertRaises(ValueError):
            activations_module.entitlement_state(_record(), None)


class StoreValidationTests(unittest.TestCase):
    def _parse(self, record):
        return activations_module.parse_store(json.dumps({"f" * 64: record}))

    def test_aware_expiry_accepted(self):
        self._parse(_record(expires_at="2026-10-01T00:00:00+00:00"))

    def test_naive_expiry_makes_the_store_invalid(self):
        with self.assertRaises(activations_module.ActivationStoreError):
            self._parse(_record(expires_at="2026-10-01T00:00:00"))

    def test_unparseable_expiry_makes_the_store_invalid(self):
        with self.assertRaises(activations_module.ActivationStoreError):
            self._parse(_record(expires_at="tomorrow"))

    def test_issue_activation_writes_timezone_aware_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "activations.json")
            lock = os.path.join(tmp, ".activations.lock")
            activations_module.init_store(store, lock)
            activation_id, _credential = activations_module.issue_activation(store, lock, 1, expires_in_days=1)
            record = activations_module.find_by_activation_id(store, lock, activation_id)
            parsed = activations_module.parse_expires_at(record["expires_at"])
            self.assertIsNotNone(parsed.utcoffset())


class ApiAuthorizationUsesPredicateTests(unittest.TestCase):
    """decide_and_bind (/v1/activate, field enroll, ingress self-bind) and
    Xray eligibility (/v1/xray-profile) both route through the predicate."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = os.path.join(self._tmp.name, "activations.json")
        self.lock = os.path.join(self._tmp.name, ".activations.lock")
        activations_module.init_store(self.store, self.lock)

    def _issue(self, expires_in_days):
        _activation_id, credential = activations_module.issue_activation(
            self.store, self.lock, 2, expires_in_days=expires_in_days,
        )
        return credential

    def test_decide_and_bind_rejects_expired_and_accepts_unexpired(self):
        credential = self._issue(1)
        later = datetime.now(timezone.utc) + timedelta(days=2)
        self.assertEqual(
            activations_module.decide_and_bind(credential, KEY_A, self.store, self.lock, now=later).outcome,
            activations_module.EXPIRED,
        )
        self.assertEqual(
            activations_module.decide_and_bind(credential, KEY_A, self.store, self.lock).outcome,
            activations_module.BOUND_NEW,
        )

    def test_xray_eligibility_rejects_expired_confirmed_device(self):
        credential = self._issue(1)
        activations_module.decide_and_bind(credential, KEY_A, self.store, self.lock)
        activations_module.finalize_reservation(credential, KEY_A, self.store, self.lock)
        check = xray_provisioning_module._check_device_eligibility
        self.assertIsNone(check(credential, KEY_A, self.store, self.lock, datetime.now(timezone.utc)))
        self.assertEqual(
            check(credential, KEY_A, self.store, self.lock, datetime.now(timezone.utc) + timedelta(days=2)),
            xray_provisioning_module.NOT_ELIGIBLE_EXPIRED,
        )


class RendererEntitlementTests(unittest.TestCase):
    """_active_clients and both public renderers: status AND expiry."""

    UUID_A = "11111111-1111-4111-8111-111111111111"
    UUID_B = "22222222-2222-4222-8222-222222222222"

    def setUp(self):
        self.reality = renderer.RealityServerConfig(
            listen_port=2053, server_names=("www.example.org",), dest="www.example.org:443",
            private_key="C" * 43, short_ids=("ab12",),
        )
        self.upstream = ingress_renderer.UpstreamExitConfig(
            host="203.0.113.10", port=2053, transport="reality", uuid="33333333-3333-4333-8333-333333333333",
            server_name="www.example.org", public_key="D" * 43, short_id="cd34", flow="xtls-rprx-vision",
        )

    def _stores(self, record_a, record_b=None):
        activations_data = {"1" * 64: record_a}
        xray_data = {"1" * 64: [{"device_public_key": KEY_A, "vless_uuid": self.UUID_A, "created_at": "x"}]}
        if record_b is not None:
            activations_data["2" * 64] = record_b
            xray_data["2" * 64] = [{"device_public_key": KEY_B, "vless_uuid": self.UUID_B, "created_at": "x"}]
        return activations_data, xray_data

    def _exit_ids(self, activations_data, xray_data, now):
        config = renderer.render_server_config(activations_data, xray_data, self.reality, flow="xtls-rprx-vision", now=now)
        return [client["id"] for client in config["inbounds"][0]["settings"]["clients"]]

    def _ingress_ids(self, activations_data, xray_data, now):
        config = ingress_renderer.render_ingress_server_config(activations_data, xray_data, self.reality, self.upstream, now=now)
        return [client["id"] for client in config["inbounds"][0]["settings"]["clients"]]

    def test_active_unexpired_included(self):
        stores = self._stores(_record(expires_at=(NOW + timedelta(days=1)).isoformat()))
        self.assertEqual(self._exit_ids(*stores, NOW), [self.UUID_A])
        self.assertEqual(self._ingress_ids(*stores, NOW), [self.UUID_A])

    def test_unlimited_included(self):
        stores = self._stores(_record(expires_at=None))
        self.assertEqual(self._exit_ids(*stores, NOW), [self.UUID_A])

    def test_revoked_excluded(self):
        stores = self._stores(_record(status=activations_module.REVOKED))
        self.assertEqual(self._exit_ids(*stores, NOW), [])
        self.assertEqual(self._ingress_ids(*stores, NOW), [])

    def test_expired_excluded_even_with_status_active(self):
        stores = self._stores(_record(expires_at=(NOW - timedelta(seconds=1)).isoformat()))
        self.assertEqual(self._exit_ids(*stores, NOW), [])
        self.assertEqual(self._ingress_ids(*stores, NOW), [])

    def test_exactly_at_expiry_excluded(self):
        stores = self._stores(_record(expires_at=NOW.isoformat()))
        self.assertEqual(self._exit_ids(*stores, NOW), [])

    def test_unknown_activation_identity_not_rendered(self):
        activations_data, xray_data = self._stores(_record())
        xray_data["9" * 64] = [{"device_public_key": KEY_B, "vless_uuid": self.UUID_B, "created_at": "x"}]
        self.assertEqual(self._exit_ids(activations_data, xray_data, NOW), [self.UUID_A])

    def test_only_the_expired_activation_is_dropped(self):
        stores = self._stores(
            _record(expires_at=(NOW - timedelta(hours=1)).isoformat()),
            _record(expires_at=(NOW + timedelta(hours=1)).isoformat(), activation_id="b" * 32),
        )
        self.assertEqual(self._exit_ids(*stores, NOW), [self.UUID_B])

    def test_render_changes_once_expiry_passes(self):
        expires = NOW + timedelta(minutes=5)
        stores = self._stores(_record(expires_at=expires.isoformat()))
        before = renderer.render_server_config(*stores, self.reality, now=NOW)
        after = renderer.render_server_config(*stores, self.reality, now=expires)
        self.assertNotEqual(json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True))
        # ...and is stable (deterministic) at a fixed instant.
        again = renderer.render_server_config(*stores, self.reality, now=NOW)
        self.assertEqual(before, again)

    def test_static_relay_clients_are_not_subject_to_user_entitlement(self):
        stores = self._stores(_record(status=activations_module.REVOKED))
        relay = renderer.RenderedClient(activation_id="relay", device_public_key="relay", vless_uuid=self.UUID_B)
        config = renderer.render_server_config(*stores, self.reality, static_clients=(relay,), now=NOW)
        self.assertEqual([c["id"] for c in config["inbounds"][0]["settings"]["clients"]], [self.UUID_B])

    def test_naive_now_rejected_by_renderers(self):
        stores = self._stores(_record())
        with self.assertRaises(ValueError):
            renderer.render_server_config(*stores, self.reality, now=datetime(2026, 9, 28))
        with self.assertRaises(ValueError):
            ingress_renderer.render_ingress_server_config(*stores, self.reality, self.upstream, now=datetime(2026, 9, 28))

    def test_malformed_expiry_in_render_input_fails_closed(self):
        stores = self._stores(_record(expires_at="2099-01-01T00:00:00"))
        with self.assertRaises(activations_module.ActivationStoreError):
            renderer.render_server_config(*stores, self.reality, now=NOW)


if __name__ == "__main__":
    unittest.main()
