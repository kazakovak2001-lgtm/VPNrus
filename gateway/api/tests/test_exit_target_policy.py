"""Exit Target ACL / SSRF protection - the canonical destination policy
(exit_target_policy.py), its Xray `freedom.finalRules` rendering
(xray_config_renderer.py) and the AWG nftables template's sets/rules
(gateway/nftables/pocvpn.nft.template). Static/pure tests only; the
real-kernel behaviour is exercised by
gateway/nftables/tests/run_exit_acl_netns_tests.sh (root, disposable
network namespaces), run here only when root + nft + ip are available."""
import ipaddress
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import exit_target_policy as policy
from api import xray_config_renderer as renderer

_NFT_TEMPLATE = os.path.join(_GATEWAY_DIR, "nftables", "pocvpn.nft.template")
_NETNS_HARNESS = os.path.join(_GATEWAY_DIR, "nftables", "tests", "run_exit_acl_netns_tests.sh")

_MUST_BLOCK = {
    "loopback v4": "127.0.0.1",
    "loopback v4 high": "127.255.255.254",
    "this-network": "0.0.0.0",
    "RFC1918 10/8": "10.0.0.5",
    "AWG tunnel gateway": "10.77.0.1",
    "RFC1918 172.16/12": "172.16.5.5",
    "AWS VPC resolver": "172.31.0.2",
    "Stockholm private IP": "172.31.36.199",
    "RFC1918 192.168/16": "192.168.1.1",
    "CGNAT": "100.64.0.1",
    "CGNAT top": "100.127.255.254",
    "link-local": "169.254.1.1",
    "EC2 metadata": "169.254.169.254",
    "IETF 192.0.0/24": "192.0.0.8",
    "TEST-NET-1": "192.0.2.1",
    "6to4 relay": "192.88.99.1",
    "benchmarking": "198.19.255.1",
    "TEST-NET-2": "198.51.100.7",
    "TEST-NET-3": "203.0.113.9",
    "multicast": "224.0.0.251",
    "multicast top": "239.255.255.250",
    "reserved": "240.0.0.1",
    "broadcast": "255.255.255.255",
    "v6 unspecified": "::",
    "v6 loopback": "::1",
    "v6 ULA": "fd00::5",
    "v6 link-local": "fe80::1",
    "v6 site-local": "fec0::1",
    "v6 multicast": "ff02::1",
    "v6 documentation": "2001:db8::1",
    "NAT64 metadata": "64:ff9b::a9fe:a9fe",
    "v4-mapped metadata": "::ffff:169.254.169.254",
    "v4-mapped loopback": "::ffff:127.0.0.1",
}

_MUST_ALLOW = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9", "16.170.208.231", "152.70.43.1", "100.63.255.255",
    "100.128.0.0", "172.15.255.255", "172.32.0.0", "169.253.255.255", "169.255.0.0", "192.169.0.0",
    "198.17.255.255", "198.20.0.0", "223.255.255.254", "11.0.0.1", "126.255.255.255", "128.0.0.1",
    "2606:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::1", "2600::", "::ffff:1.1.1.1",
)


def _template():
    with open(_NFT_TEMPLATE, "r", encoding="utf-8") as handle:
        return handle.read()


def _template_set(name):
    text = _template()
    block = text.split(f"set {name} {{", 1)[1].split("}\n    }", 1)[0]
    elements = block.split("elements = {", 1)[1]
    return tuple(e.strip() for e in elements.replace("\n", " ").split(",") if e.strip())


def _chain(name):
    text = _template()
    return text.split(f"chain {name} {{", 1)[1].split("\n    }", 1)[0]


def _rules(chain_text):
    return [l.strip() for l in chain_text.splitlines() if l.strip() and not l.strip().startswith("#")]


class PolicyTests(unittest.TestCase):
    def test_every_security_sensitive_destination_is_blocked(self):
        for label, address in _MUST_BLOCK.items():
            self.assertTrue(policy.is_blocked(address), f"{label} {address}")

    def test_public_internet_destinations_remain_allowed(self):
        for address in _MUST_ALLOW:
            self.assertFalse(policy.is_blocked(address), address)

    def test_random_public_unicast_sample_is_allowed(self):
        rng = random.Random(20260927)
        checked = 0
        while checked < 5000:
            ip = ipaddress.IPv4Address(rng.getrandbits(32))
            if ip.is_global and not ip.is_multicast:
                self.assertFalse(policy.is_blocked(ip), str(ip))
                checked += 1

    def test_blocked_ipv4_space_is_bounded(self):
        # 224/4 + 240/4 are 1/8 of the space; everything else is small. A
        # mistake like a /0 or a mapped catch-all would blow straight past this.
        total = sum(n.num_addresses for n in policy.BLOCKED_NETWORKS if n.version == 4)
        self.assertLess(total, 2 ** 32 * 0.16)
        self.assertTrue(all(n.prefixlen >= 4 for n in policy.BLOCKED_NETWORKS if n.version == 4))
        self.assertTrue(all(n.prefixlen >= 7 for n in policy.BLOCKED_NETWORKS if n.version == 6))

    def test_no_ipv4_mapped_catch_all(self):
        for cidr in policy.BLOCKED_IPV6_CIDRS:
            net = ipaddress.ip_network(cidr)
            self.assertFalse(net.overlaps(ipaddress.ip_network("::ffff:0:0/96")), cidr)

    def test_entries_are_canonical_and_non_overlapping(self):
        # nftables interval sets reject overlapping elements.
        for cidr in policy.BLOCKED_IPV4_CIDRS + policy.BLOCKED_IPV6_CIDRS:
            self.assertEqual(str(ipaddress.ip_network(cidr)), cidr)
        for a, b in itertools.combinations(policy.BLOCKED_NETWORKS, 2):
            if a.version == b.version:
                self.assertFalse(a.overlaps(b), f"{a} overlaps {b}")

    def test_metadata_constant(self):
        self.assertTrue(policy.is_blocked(policy.EC2_METADATA_IPV4))


class XrayRenderingTests(unittest.TestCase):
    def setUp(self):
        self.reality = renderer.RealityServerConfig(
            listen_port=2053, server_names=("www.microsoft.com",), dest="www.microsoft.com:443",
            private_key="A" * 43, short_ids=("ab12cd34",),
        )

    def _outbounds(self, **kwargs):
        return renderer.render_server_config({}, {}, self.reality, **kwargs)["outbounds"]

    def test_single_freedom_outbound_carries_the_policy_as_one_block_rule(self):
        outbounds = self._outbounds()
        self.assertEqual(len(outbounds), 1)
        direct = outbounds[0]
        self.assertEqual((direct["tag"], direct["protocol"]), ("direct", "freedom"))
        rules = direct["settings"]["finalRules"]
        self.assertEqual(rules, [{"action": "block", "ip": list(policy.BLOCKED_IPV4_CIDRS + policy.BLOCKED_IPV6_CIDRS)}])

    def test_rule_applies_to_every_network_and_port(self):
        rule = self._outbounds()[0]["settings"]["finalRules"][0]
        self.assertNotIn("network", rule)
        self.assertNotIn("port", rule)
        self.assertNotIn("blockDelay", rule)

    def test_no_allow_rule_precedes_or_follows_the_block(self):
        actions = [r["action"] for r in self._outbounds()[0]["settings"]["finalRules"]]
        self.assertEqual(actions, ["block"])

    def test_same_policy_with_tls_and_xhttp_inbounds(self):
        tls = renderer.TlsServerConfig(listen_port=2083, cert_file="/etc/x/c.pem", key_file="/etc/x/k.pem")
        self.assertEqual(self._outbounds(tls=tls), self._outbounds())

    def test_transport_behaviour_untouched(self):
        outbound = self._outbounds()[0]
        self.assertEqual(set(outbound), {"tag", "protocol", "settings"})
        self.assertEqual(set(outbound["settings"]), {"finalRules"})
        for key in ("domainStrategy", "targetStrategy", "redirect", "fragment", "noises", "ipsBlocked"):
            self.assertNotIn(key, outbound["settings"])

    def test_deterministic_and_json_serializable(self):
        a = json.dumps(renderer.render_server_config({}, {}, self.reality), sort_keys=True)
        b = json.dumps(renderer.render_server_config({}, {}, self.reality), sort_keys=True)
        self.assertEqual(a, b)
        self.assertNotIn("::ffff:", a)


class NftablesTemplateTests(unittest.TestCase):
    def test_sets_equal_the_canonical_policy(self):
        self.assertEqual(_template_set("exit_blocked_v4"), policy.BLOCKED_IPV4_CIDRS)
        self.assertEqual(_template_set("exit_blocked_v6"), policy.BLOCKED_IPV6_CIDRS)

    def test_sets_are_interval_sets_of_the_right_family(self):
        text = _template()
        self.assertRegex(text, r"set exit_blocked_v4 \{\s+type ipv4_addr\s+flags interval")
        self.assertRegex(text, r"set exit_blocked_v6 \{\s+type ipv6_addr\s+flags interval")
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("::ffff:", code)

    def test_forward_order_established_then_acl_then_tunnel_accept(self):
        rules = _rules(_chain("forward"))
        self.assertEqual(rules[0], "type filter hook forward priority filter; policy drop;")
        self.assertEqual(rules[1:], [
            "ct state established,related accept",
            'iifname "__AWG_IFACE__" ip daddr @exit_blocked_v4 reject with icmpx type admin-prohibited',
            'iifname "__AWG_IFACE__" ip6 daddr @exit_blocked_v6 reject with icmpx type admin-prohibited',
            'iifname "__AWG_IFACE__" oifname "__EGRESS_IFACE__" accept',
            'iifname "__EGRESS_IFACE__" oifname "__AWG_IFACE__" accept',
        ])

    def test_acl_matches_only_tunnel_ingress_so_icmp_errors_and_returns_pass(self):
        for rule in _rules(_chain("forward")):
            if "@exit_blocked" in rule:
                self.assertTrue(rule.startswith('iifname "__AWG_IFACE__" '), rule)
                self.assertNotIn("icmp ", rule)

    def test_nat_unchanged_and_after_the_filter(self):
        rules = _rules(_chain("postrouting"))
        self.assertEqual(rules, [
            "type nat hook postrouting priority srcnat; policy accept;",
            'ip saddr __AWG_SUBNET__ oifname "__EGRESS_IFACE__" masquerade',
        ])

    def test_single_table_and_unique_chain_and_set_names(self):
        text = _template()
        self.assertEqual(text.count("table inet __NFT_TABLE__ {"), 1)
        self.assertEqual(text.count("delete table inet __NFT_TABLE__"), 1)
        for name in ("chain forward {", "chain postrouting {", "set exit_blocked_v4 {", "set exit_blocked_v6 {"):
            self.assertEqual(text.count(name), 1, name)

    def test_placeholders_unchanged(self):
        self.assertEqual(
            sorted(set(re.findall(r"__[A-Z_]+__", _template()))),
            ["__AWG_IFACE__", "__AWG_SUBNET__", "__EGRESS_IFACE__", "__NFT_TABLE__"],
        )


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
    and shutil.which("nft") and shutil.which("ip"),
    "needs root + nft + ip (runs only in disposable network namespaces)",
)
class NetnsHarnessTests(unittest.TestCase):
    def test_netns_harness_passes(self):
        result = subprocess.run(["bash", _NETNS_HARNESS], capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
