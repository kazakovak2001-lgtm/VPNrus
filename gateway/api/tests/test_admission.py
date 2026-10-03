"""B57 - AdmissionControl layer semantics, with a controllable clock."""
import os
import sys
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import admission, ratelimit
from api.client_identity import ClientIdentity, EDGE_UNKNOWN, UNATTRIBUTED

ACT = admission.CLASS_ACTIVATION
BOOT = admission.CLASS_BOOTSTRAP
RELAY = admission.CLASS_RELAY_PROBE
FIELD = admission.CLASS_FIELD_ENROLL
PER_CLIENT_ACT = admission.PER_CLIENT_LIMITS[ACT]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def client(n, edge="public-443"):
    return ClientIdentity(edge, f"198.51.{n // 256}.{n % 256}/32")


class AdmissionTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.global_limiter = ratelimit.RateLimiter(admission.GLOBAL_LIMIT, admission.WINDOW_SECONDS, clock=self.clock)
        self.ac = admission.AdmissionControl(self.clock, self.global_limiter)

    def global_used(self):
        return self.global_limiter._windows.get("global", (0, 0))[1]


class ValuesTests(unittest.TestCase):
    def test_global_ceiling_value_is_unchanged(self):
        self.assertEqual(60, admission.GLOBAL_LIMIT)
        self.assertEqual(10.0, admission.WINDOW_SECONDS)

    def test_no_layer_exceeds_the_global_ceiling(self):
        for table in (admission.CLASS_CEILINGS, admission.PER_CLIENT_LIMITS, admission.EDGE_CEILINGS):
            for value in table.values():
                self.assertLessEqual(value, admission.GLOBAL_LIMIT)

    def test_activation_keeps_a_reserve_against_manifest_and_relay_floods(self):
        reserved = admission.GLOBAL_LIMIT - admission.CLASS_CEILINGS[BOOT] - admission.CLASS_CEILINGS[RELAY]
        self.assertGreaterEqual(reserved, PER_CLIENT_ACT)

    def test_per_client_activation_fits_a_full_five_request_sequence(self):
        self.assertGreaterEqual(PER_CLIENT_ACT, 5)

    def test_every_class_has_a_ceiling(self):
        self.assertEqual(set(admission.ENDPOINT_CLASSES), set(admission.CLASS_CEILINGS))


class PerClientTests(AdmissionTestCase):
    def test_client_a_cannot_exhaust_client_b(self):
        a, b = client(1), client(2)
        for _ in range(PER_CLIENT_ACT):
            self.assertTrue(self.ac.admit(a, ACT))
        self.assertFalse(self.ac.admit(a, ACT))
        self.assertTrue(self.ac.admit(b, ACT))
        self.assertTrue(self.ac.admit(b, BOOT))

    def test_n_plus_one_is_rejected_and_rejections_consume_no_shared_budget(self):
        a = client(1)
        results = [self.ac.admit(a, ACT) for _ in range(PER_CLIENT_ACT + 5)]
        self.assertEqual([True] * PER_CLIENT_ACT + [False] * 5, results)
        self.assertEqual(PER_CLIENT_ACT, self.global_used())
        self.assertEqual(PER_CLIENT_ACT, self.ac.class_limiters[ACT]._windows[ACT][1])

    def test_window_resets(self):
        a = client(1)
        for _ in range(PER_CLIENT_ACT):
            self.ac.admit(a, ACT)
        self.assertFalse(self.ac.admit(a, ACT))
        self.clock.now += admission.WINDOW_SECONDS
        self.assertTrue(self.ac.admit(a, ACT))

    def test_classes_have_separate_per_client_budgets(self):
        a = client(1)
        for _ in range(PER_CLIENT_ACT):
            self.ac.admit(a, ACT)
        self.assertFalse(self.ac.admit(a, ACT))
        self.assertTrue(self.ac.admit(a, BOOT))

    def test_unattributed_and_unknown_edge_are_still_limited(self):
        for identity in (ClientIdentity(EDGE_UNKNOWN, UNATTRIBUTED), ClientIdentity("public-443", UNATTRIBUTED),
                         ClientIdentity(EDGE_UNKNOWN, "198.51.100.7/32")):
            with self.subTest(identity=identity):
                for _ in range(PER_CLIENT_ACT):
                    self.assertTrue(self.ac.admit(identity, ACT))
                self.assertFalse(self.ac.admit(identity, ACT))

    def test_relay_probe_and_field_enroll_have_no_per_client_layer(self):
        self.assertNotIn(RELAY, admission.PER_CLIENT_LIMITS)
        self.assertNotIn(FIELD, admission.PER_CLIENT_LIMITS)
        a = client(1)
        for _ in range(admission.CLASS_CEILINGS[RELAY]):
            self.assertTrue(self.ac.admit(a, RELAY))
        self.assertFalse(self.ac.admit(a, RELAY))

    def test_unknown_class_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            self.ac.admit(client(1), "nope")


class CeilingTests(AdmissionTestCase):
    def test_manifest_flood_cannot_take_the_activation_budget(self):
        admitted = sum(self.ac.admit(client(n), BOOT) for n in range(100))
        self.assertEqual(admission.CLASS_CEILINGS[BOOT], admitted)
        self.assertTrue(self.ac.admit(client(500), ACT))

    def test_relay_probe_flood_cannot_take_the_activation_budget(self):
        admitted = sum(self.ac.admit(ClientIdentity("public-443", UNATTRIBUTED), RELAY) for _ in range(100))
        self.assertEqual(admission.CLASS_CEILINGS[RELAY], admitted)
        self.assertTrue(self.ac.admit(client(500), ACT))

    def test_manifest_and_relay_floods_together_leave_activation_its_reserve(self):
        for n in range(100):
            self.ac.admit(client(n), BOOT)
            self.ac.admit(client(n), RELAY)
        reserve = admission.GLOBAL_LIMIT - admission.CLASS_CEILINGS[BOOT] - admission.CLASS_CEILINGS[RELAY]
        admitted = sum(self.ac.admit(client(1000 + n), ACT) for n in range(100))
        self.assertEqual(reserve, admitted)

    def test_global_safety_ceiling_still_holds(self):
        admitted = sum(self.ac.admit(client(n), ACT) for n in range(200))
        self.assertEqual(admission.GLOBAL_LIMIT, admitted)
        self.assertFalse(self.ac.admit(client(999), BOOT))
        self.assertEqual(admission.GLOBAL_LIMIT, self.global_used())

    def test_edge_ceiling_isolates_staging_from_production(self):
        cap = admission.EDGE_CEILINGS["cp-loopback"]
        admitted = sum(self.ac.admit(client(n, edge="cp-loopback"), ACT) for n in range(100))
        self.assertEqual(cap, admitted)
        self.assertTrue(self.ac.admit(client(500, edge="public-443"), ACT))
        self.assertLessEqual(self.global_used(), cap + 1)

    def test_same_address_on_two_edges_has_two_per_client_budgets(self):
        staging, public = client(1, edge="cp-loopback"), client(1, edge="public-443")
        for _ in range(PER_CLIENT_ACT):
            self.assertTrue(self.ac.admit(staging, ACT))
        self.assertFalse(self.ac.admit(staging, ACT))
        self.assertTrue(self.ac.admit(public, ACT))


class StateTests(AdmissionTestCase):
    def test_concurrent_requests_from_one_client_admit_exactly_its_budget(self):
        a = client(1)
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(40)

        def worker():
            barrier.wait()
            ok = self.ac.admit(a, ACT)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(PER_CLIENT_ACT, results.count(True))
        self.assertEqual(PER_CLIENT_ACT, self.global_used())

    def test_two_clients_concurrently_each_get_their_budget(self):
        results = {1: [], 2: []}
        barrier = threading.Barrier(2 * 20)

        def worker(n):
            barrier.wait()
            ok = self.ac.admit(client(n), ACT)
            results[n].append(ok)

        threads = [threading.Thread(target=worker, args=(n,)) for n in (1, 2) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(PER_CLIENT_ACT, results[1].count(True))
        self.assertEqual(PER_CLIENT_ACT, results[2].count(True))

    def test_per_client_memory_is_pruned(self):
        limiter = self.ac.per_client_limiters[ACT]
        for n in range(300):
            self.ac.admit(client(n), ACT)
        self.assertEqual(300, limiter.size())
        self.clock.now += 2 * admission.WINDOW_SECONDS
        self.ac.admit(client(10_000), ACT)
        self.assertEqual(1, limiter.size())

    def test_restart_starts_with_empty_process_local_state(self):
        a = client(1)
        for _ in range(PER_CLIENT_ACT):
            self.ac.admit(a, ACT)
        self.assertFalse(self.ac.admit(a, ACT))
        restarted = admission.AdmissionControl(
            self.clock, ratelimit.RateLimiter(admission.GLOBAL_LIMIT, admission.WINDOW_SECONDS, clock=self.clock)
        )
        for limiter in list(restarted.per_client_limiters.values()) + list(restarted.class_limiters.values()):
            self.assertEqual(0, limiter.size())
        self.assertTrue(restarted.admit(a, ACT))


if __name__ == "__main__":
    unittest.main()
