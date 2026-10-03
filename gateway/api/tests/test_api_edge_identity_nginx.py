"""B57 - every nginx location that proxies to pocvpn-api hands it a
server-controlled client identity: X-Real-IP $remote_addr and a constant
X-Pocvpn-Edge (client_identity.py). Static template checks only; the
repository's nginx -t harnesses validate syntax separately."""
import os
import re
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import client_identity

_EDGE_DIR = os.path.join(_GATEWAY_DIR, "edge")

TEMPLATE_EDGES = {
    "nginx-pocvpn.conf": "public-443",
    "nginx-pocvpn-stockholm.conf": "public-443",
    "nginx-pocvpn-cp-loopback-stockholm.conf": "cp-loopback",
    "nginx-pocvpn-cp-loopback-frankfurt.conf": "cp-loopback",
}
CP_LOOPBACK_TEMPLATES = ("nginx-pocvpn-cp-loopback-stockholm.conf", "nginx-pocvpn-cp-loopback-frankfurt.conf")

# pocvpn-api roles: exit 8443, ingress 8444, xhttp-ingress 8445, or the
# ingress map that selects between 8444/8445.
_API_UPSTREAM = re.compile(r"proxy_pass http://(127\.0\.0\.1:844[345]|\$pocvpn_ingress_profile_backend);")


def _read(name):
    with open(os.path.join(_EDGE_DIR, name), encoding="utf-8") as handle:
        return handle.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _location_blocks(text):
    """(header, body) for every `location ... { ... }` block; locations in
    these templates never nest braces beyond limit_except, which is
    handled by brace counting."""
    blocks = []
    for match in re.finditer(r"location\s+([^{]+)\{", text):
        depth, i = 1, match.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        blocks.append((match.group(1).strip(), text[match.end():i - 1]))
    return blocks


def _api_locations(name):
    text = _strip_comments(_read(name))
    return [(h, b) for h, b in _location_blocks(text) if _API_UPSTREAM.search(b)]


class EdgeIdentityHeaderTests(unittest.TestCase):
    def test_every_template_has_api_locations(self):
        for name in TEMPLATE_EDGES:
            with self.subTest(name=name):
                self.assertTrue(_api_locations(name))

    def test_every_api_location_sends_server_controlled_real_ip(self):
        for name in TEMPLATE_EDGES:
            for header, body in _api_locations(name):
                with self.subTest(name=name, location=header):
                    self.assertEqual(1, len(re.findall(r"proxy_set_header\s+X-Real-IP\s", body)))
                    self.assertIn("proxy_set_header X-Real-IP $remote_addr;", body)

    def test_every_api_location_sends_the_files_constant_edge(self):
        for name, edge in TEMPLATE_EDGES.items():
            for header, body in _api_locations(name):
                with self.subTest(name=name, location=header):
                    values = re.findall(r"proxy_set_header\s+X-Pocvpn-Edge\s+(\S+);", body)
                    self.assertEqual([f'"{edge}"'], values)

    def test_edge_constants_are_the_ones_the_api_recognizes(self):
        self.assertTrue(set(TEMPLATE_EDGES.values()) <= client_identity.KNOWN_EDGES)

    def test_client_cannot_supply_the_edge_or_address(self):
        # proxy_set_header replaces the client's header; the value must be a
        # literal, never a variable that could carry client input
        # ($http_x_pocvpn_edge, $http_x_real_ip, $http_x_forwarded_for, ...).
        for name in TEMPLATE_EDGES:
            text = _strip_comments(_read(name))
            with self.subTest(name=name):
                self.assertNotIn("$http_x_pocvpn_edge", text.lower())
                self.assertNotIn("$http_x_real_ip", text.lower())
                for value in re.findall(r"proxy_set_header\s+X-Pocvpn-Edge\s+(\S+);", text):
                    self.assertNotIn("$", value)
                self.assertNotIn("proxy_pass_request_headers off", text)


class TrustBoundaryTests(unittest.TestCase):
    def test_cp_loopback_trusts_cf_connecting_ip_only_from_localhost(self):
        for name in CP_LOOPBACK_TEMPLATES:
            text = _strip_comments(_read(name))
            with self.subTest(name=name):
                self.assertEqual(["127.0.0.1"], re.findall(r"set_real_ip_from\s+(\S+);", text))
                self.assertEqual(["CF-Connecting-IP"], re.findall(r"real_ip_header\s+(\S+);", text))
                self.assertIn("real_ip_recursive off;", text)
                self.assertEqual(["127.0.0.1:8081"], re.findall(r"listen\s+(\S+)", text))

    def test_public_vhosts_use_the_tcp_peer_address(self):
        # No real_ip on the public 443 vhosts: $remote_addr is the TCP peer,
        # which a client cannot choose by header.
        for name, edge in TEMPLATE_EDGES.items():
            if edge != "public-443":
                continue
            text = _strip_comments(_read(name))
            with self.subTest(name=name):
                self.assertNotIn("set_real_ip_from", text)
                self.assertNotIn("real_ip_header", text)


if __name__ == "__main__":
    unittest.main()
