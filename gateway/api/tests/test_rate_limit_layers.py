"""B57 - rate-limit layers through the real HTTP handler.

Requests carry the X-Real-IP / X-Pocvpn-Edge headers nginx sets (see
gateway/edge/ and client_identity.py). A response other than 429 proves the
request passed every limiter; what happens after them (200/401/403/503) is
covered by each endpoint's own test file.
"""
import dataclasses
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
from api import admission
from api import hysteria_store
from _fixtures import (
    RunningServer,
    make_public_key,
    make_relay_probe_hmac_secret_file,
    make_xray_app_config,
    set_plan,
    write_fake_manifest_artifact,
    write_fake_provision_script,
)
from _http import get_manifest, get_relay_health, raw_request

PER_CLIENT_ACT = admission.PER_CLIENT_LIMITS[admission.CLASS_ACTIVATION]


def nginx_headers(ip, edge="public-443"):
    headers = {"X-Pocvpn-Edge": edge}
    if ip is not None:
        headers["X-Real-IP"] = ip
    return headers


def post_json(port, path, credential, body_obj, headers):
    body = json.dumps(body_obj).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if credential is not None:
        hdrs["Authorization"] = f"Bearer {credential}"
    hdrs.update(headers)
    status, _h, resp = raw_request(port, "POST", path, hdrs, body)
    return status, resp


class RateLimitLayersTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = self._tmp.name
        script = write_fake_provision_script(tmp)
        os.environ["POCVPN_FAKE_PLAN"] = os.path.join(tmp, "plan.txt")
        set_plan(os.environ["POCVPN_FAKE_PLAN"], "CREATED", "10.77.0.9")

        self.activation_store_path = os.path.join(tmp, "activations.json")
        self.activation_lock_path = os.path.join(tmp, ".activations.lock")
        activations_module.init_store(self.activation_store_path, self.activation_lock_path)
        hy_store = os.path.join(tmp, "hysteria2-identities.json")
        hy_lock = os.path.join(tmp, ".hysteria2-identities.lock")
        hysteria_store.init_store(hy_store, hy_lock)

        # REALITY configured, XHTTP deliberately NOT configured (the
        # pre-existing xray_xhttp_not_configured 503 must be unchanged).
        base = make_xray_app_config(tmp, script, self.activation_store_path, self.activation_lock_path)
        self.app_config = dataclasses.replace(
            base,
            hysteria2_store_path=hy_store, hysteria2_lock_path=hy_lock,
            hysteria2_server_port=34443, hysteria2_sni="hy2.example.test",
            manifest_path=write_fake_manifest_artifact(tmp),
            relay_probe_hmac_secret_file=make_relay_probe_hmac_secret_file(tmp),
        )
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)
        self.port = self.server.port

    def issue(self, max_devices=2):
        _id, credential = activations_module.issue_activation(
            self.activation_store_path, self.activation_lock_path, max_devices=max_devices,
        )
        return credential

    def activation_sequence(self, credential, key, headers):
        """The Android client's post-activation sequence (MainViewModel):
        activate, then up to four profile requests, sequentially."""
        body = {"public_key": key}
        return [
            post_json(self.port, "/v1/activate", credential, body, headers)[0],
            post_json(self.port, "/v1/xray-profile", credential, {**body, "transport": "reality"}, headers)[0],
            post_json(self.port, "/v1/xray-profile", credential, {**body, "transport": "reality"}, headers)[0],
            post_json(self.port, "/v1/xray-profile", credential, {**body, "transport": "reality"}, headers)[0],
            post_json(self.port, "/v1/hysteria-profile", credential, body, headers)[0],
        ]

    def activate(self, credential, key, headers):
        return post_json(self.port, "/v1/activate", credential, {"public_key": key}, headers)[0]

    def global_used(self):
        return self.server.srv.global_limiter._windows.get("global", (0, 0))[1]


class ActivationFlowTests(RateLimitLayersTestCase):
    def test_full_activation_sequence_has_no_false_429(self):
        statuses = self.activation_sequence(self.issue(), make_public_key(0x40), nginx_headers("198.51.100.7"))
        self.assertEqual(5, len(statuses))
        self.assertNotIn(429, statuses)
        self.assertEqual(200, statuses[0])

    def test_same_credential_two_devices_both_complete(self):
        credential = self.issue(max_devices=2)
        first = self.activation_sequence(credential, make_public_key(0x40), nginx_headers("198.51.100.7"))
        second = self.activation_sequence(credential, make_public_key(0x41), nginx_headers("198.51.100.8"))
        self.assertNotIn(429, first + second)

    def test_rotating_public_keys_cannot_multiply_one_credentials_budget(self):
        credential = self.issue(max_devices=1)
        per_device = 5
        statuses = []
        for n in range(3):
            key = make_public_key(0x50 + n)
            for i in range(per_device):
                statuses.append(self.activate(credential, key, nginx_headers(f"198.51.100.{10 * n + i + 1}")))
        self.assertNotIn(429, statuses[:10])
        self.assertTrue(all(s == 429 for s in statuses[10:]), statuses)

    def test_one_device_cannot_use_its_siblings_share(self):
        credential = self.issue(max_devices=2)
        key_a, key_b = make_public_key(0x40), make_public_key(0x41)
        burst = [self.activate(credential, key_a, nginx_headers(f"198.51.100.{i + 1}")) for i in range(8)]
        self.assertEqual(429, burst[-1])
        self.assertNotEqual(429, self.activate(credential, key_b, nginx_headers("198.51.100.99")))


class PerClientTests(RateLimitLayersTestCase):
    def test_client_a_burst_hits_its_own_limit_but_not_client_b(self):
        a, b = nginx_headers("198.51.100.7"), nginx_headers("203.0.113.9")
        statuses = [self.activate(f"bogus-{i}", make_public_key(0x40), a) for i in range(PER_CLIENT_ACT + 3)]
        self.assertNotIn(429, statuses[:PER_CLIENT_ACT])
        self.assertEqual([429] * 3, statuses[PER_CLIENT_ACT:])
        self.assertNotEqual(429, self.activate("bogus-b", make_public_key(0x41), b))

    def test_per_client_rejections_do_not_consume_the_global_ceiling(self):
        a = nginx_headers("198.51.100.7")
        for i in range(PER_CLIENT_ACT + 7):
            self.activate(f"bogus-{i}", make_public_key(0x40), a)
        self.assertEqual(PER_CLIENT_ACT, self.global_used())

    def test_cgnat_one_address_two_credentials(self):
        cgnat = nginx_headers("78.80.113.26")
        first = self.activation_sequence(self.issue(), make_public_key(0x40), cgnat)
        second = self.activation_sequence(self.issue(), make_public_key(0x41), cgnat)
        self.assertNotIn(429, first + second)

    def test_ipv6_clients_in_one_slash_64_share_a_budget(self):
        statuses = [
            self.activate(f"bogus-{i}", make_public_key(0x40), nginx_headers(f"2001:db8:1:2::{i + 1:x}"))
            for i in range(PER_CLIENT_ACT + 1)
        ]
        self.assertEqual(429, statuses[-1])
        self.assertNotEqual(429, self.activate("bogus-x", make_public_key(0x40), nginx_headers("2001:db8:1:3::1")))

    def test_ipv4_mapped_ipv6_shares_the_ipv4_budget(self):
        for i in range(PER_CLIENT_ACT):
            self.activate(f"bogus-{i}", make_public_key(0x40), nginx_headers("198.51.100.7"))
        self.assertEqual(429, self.activate("bogus-m", make_public_key(0x40), nginx_headers("::ffff:198.51.100.7")))

    def test_missing_invalid_or_loopback_real_ip_is_limited_as_one_bucket(self):
        # Same edge throughout: the bucket is per (edge, client), and every
        # unusable X-Real-IP maps to the one `unattributed` client.
        variants = [nginx_headers(None), nginx_headers("not-an-ip"), nginx_headers("127.0.0.1"), nginx_headers("::1")]
        statuses = [
            self.activate(f"bogus-{i}", make_public_key(0x40), variants[i % len(variants)])
            for i in range(PER_CLIENT_ACT + 1)
        ]
        self.assertNotIn(429, statuses[:PER_CLIENT_ACT])
        self.assertEqual(429, statuses[-1])

    def test_request_without_any_nginx_headers_is_still_limited(self):
        statuses = [self.activate(f"bogus-{i}", make_public_key(0x40), {}) for i in range(PER_CLIENT_ACT + 1)]
        self.assertNotIn(429, statuses[:PER_CLIENT_ACT])
        self.assertEqual(429, statuses[-1])

    def test_unexpected_edge_value_is_still_limited(self):
        headers = nginx_headers("198.51.100.7", edge="no-limit-please")
        statuses = [self.activate(f"bogus-{i}", make_public_key(0x40), headers) for i in range(PER_CLIENT_ACT + 1)]
        self.assertEqual(429, statuses[-1])

    def test_edge_isolation_for_the_same_address(self):
        for i in range(PER_CLIENT_ACT + 1):
            self.activate(f"bogus-{i}", make_public_key(0x40), nginx_headers("198.51.100.7", edge="cp-loopback"))
        self.assertNotEqual(
            429, self.activate("bogus-p", make_public_key(0x40), nginx_headers("198.51.100.7", edge="public-443"))
        )


class ClassIsolationTests(RateLimitLayersTestCase):
    def test_manifest_flood_cannot_exhaust_activation(self):
        statuses = [get_manifest(self.port, extra_headers=nginx_headers(f"198.51.{n // 250}.{n % 250 + 1}"))[0]
                    for n in range(admission.CLASS_CEILINGS[admission.CLASS_BOOTSTRAP] + 5)]
        self.assertIn(429, statuses)
        self.assertEqual(200, statuses[0])
        self.assertEqual(200, self.activate(self.issue(), make_public_key(0x40), nginx_headers("203.0.113.9")))

    def test_relay_health_flood_cannot_exhaust_activation(self):
        statuses = [get_relay_health(self.port, token="bogus", extra_headers=nginx_headers("198.51.100.7"))[0]
                    for _ in range(admission.CLASS_CEILINGS[admission.CLASS_RELAY_PROBE] + 5)]
        self.assertEqual(401, statuses[0])
        self.assertIn(429, statuses)
        self.assertEqual(200, self.activate(self.issue(), make_public_key(0x40), nginx_headers("198.51.100.7")))

    def test_manifest_stays_anonymous(self):
        status, _h, _b = get_manifest(self.port, extra_headers=nginx_headers("198.51.100.7"))
        self.assertEqual(200, status)
        status, _h, _b = get_manifest(self.port)
        self.assertEqual(200, status)


class OrderingRegressionTests(RateLimitLayersTestCase):
    def test_xhttp_not_configured_503_is_unchanged_and_spends_no_per_device_budget(self):
        credential = self.issue()
        key = make_public_key(0x40)
        status, body = post_json(
            self.port, "/v1/xray-profile", credential, {"public_key": key, "transport": "xhttp"},
            nginx_headers("198.51.100.7"),
        )
        self.assertEqual(503, status)
        self.assertEqual({"error": "xray_xhttp_not_configured"}, json.loads(body))
        self.assertEqual(0, self.server.srv.per_token_limiter.size())
        self.assertEqual(0, self.server.srv.per_credential_limiter.size())
        self.assertEqual(1, self.global_used())

    def test_unconfigured_endpoint_503_spends_no_admission_budget(self):
        status, _body = post_json(self.port, "/v1/ingress-profile", "bogus", {"public_key": make_public_key(0x40)},
                                  nginx_headers("198.51.100.7"))
        self.assertEqual(503, status)
        self.assertEqual(0, self.global_used())


if __name__ == "__main__":
    unittest.main()
