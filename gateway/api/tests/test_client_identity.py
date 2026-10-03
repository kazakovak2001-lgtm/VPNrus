"""B57 - client_identity: nginx-set headers -> normalized client identity."""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import client_identity as ci


class NormalizeClientTests(unittest.TestCase):
    def test_ipv4_is_keyed_as_slash_32(self):
        self.assertEqual("198.51.100.7/32", ci.normalize_client(["198.51.100.7"]))

    def test_distinct_ipv4_addresses_are_distinct_clients(self):
        self.assertNotEqual(ci.normalize_client(["198.51.100.7"]), ci.normalize_client(["198.51.100.8"]))

    def test_ipv6_is_grouped_by_slash_64(self):
        a = ci.normalize_client(["2001:db8:1:2::1"])
        b = ci.normalize_client(["2001:db8:1:2:ffff:ffff:ffff:ffff"])
        self.assertEqual("2001:db8:1:2::/64", a)
        self.assertEqual(a, b)

    def test_different_ipv6_slash_64_are_distinct_clients(self):
        self.assertNotEqual(ci.normalize_client(["2001:db8:1:2::1"]), ci.normalize_client(["2001:db8:1:3::1"]))

    def test_ipv4_mapped_ipv6_is_the_ipv4_client(self):
        self.assertEqual(ci.normalize_client(["198.51.100.7"]), ci.normalize_client(["::ffff:198.51.100.7"]))
        self.assertEqual("198.51.100.7/32", ci.normalize_client(["::ffff:c633:6407"]))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual("198.51.100.7/32", ci.normalize_client([" 198.51.100.7 "]))

    def test_private_tunnel_addresses_are_still_clients(self):
        # AWG clients reaching the public 443 vhost through the tunnel show
        # up as their own tunnel address - distinct, attributable clients.
        self.assertEqual("10.77.0.9/32", ci.normalize_client(["10.77.0.9"]))

    def test_missing_header_is_unattributed(self):
        self.assertEqual(ci.UNATTRIBUTED, ci.normalize_client(None))
        self.assertEqual(ci.UNATTRIBUTED, ci.normalize_client([]))

    def test_duplicate_header_is_unattributed(self):
        self.assertEqual(ci.UNATTRIBUTED, ci.normalize_client(["198.51.100.7", "198.51.100.8"]))

    def test_loopback_and_unspecified_are_unattributed(self):
        for value in ("127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"):
            with self.subTest(value=value):
                self.assertEqual(ci.UNATTRIBUTED, ci.normalize_client([value]))

    def test_invalid_values_are_unattributed(self):
        for value in (
            "", "   ", "not-an-ip", "198.51.100.7.1", "198.51.100.7, 203.0.113.9",
            "198.51.100.7:443", "fe80::1%eth0", "[2001:db8::1]", "1" * 46,
        ):
            with self.subTest(value=value):
                self.assertEqual(ci.UNATTRIBUTED, ci.normalize_client([value]))


class NormalizeEdgeTests(unittest.TestCase):
    def test_known_edges(self):
        self.assertEqual(ci.EDGE_CP_LOOPBACK, ci.normalize_edge(["cp-loopback"]))
        self.assertEqual(ci.EDGE_PUBLIC_443, ci.normalize_edge(["public-443"]))
        self.assertEqual(frozenset({"cp-loopback", "public-443"}), ci.KNOWN_EDGES)

    def test_unknown_missing_or_duplicate_edges_are_unknown(self):
        for values in (None, [], ["Public-443"], ["public-443 "], ["staging"], ["cp-loopback", "public-443"]):
            with self.subTest(values=values):
                self.assertEqual(ci.EDGE_UNKNOWN, ci.normalize_edge(values))

    def test_unknown_is_not_a_known_edge(self):
        self.assertNotIn(ci.EDGE_UNKNOWN, ci.KNOWN_EDGES)


class ClientIdentityTests(unittest.TestCase):
    def test_limiter_key_separates_edge_client_and_class(self):
        a = ci.from_header_values(["198.51.100.7"], ["public-443"])
        b = ci.from_header_values(["198.51.100.7"], ["cp-loopback"])
        self.assertEqual(ci.ClientIdentity("public-443", "198.51.100.7/32"), a)
        self.assertNotEqual(a.limiter_key("activation"), b.limiter_key("activation"))
        self.assertNotEqual(a.limiter_key("activation"), a.limiter_key("bootstrap"))

    def test_garbage_headers_still_yield_a_limitable_identity(self):
        identity = ci.from_header_values(["junk"], ["junk"])
        self.assertEqual(ci.ClientIdentity(ci.EDGE_UNKNOWN, ci.UNATTRIBUTED), identity)
        self.assertTrue(identity.limiter_key("activation"))


if __name__ == "__main__":
    unittest.main()
