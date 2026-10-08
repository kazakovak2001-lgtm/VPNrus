"""Frankfurt public TCP/443 SNI split (gateway/edge/nginx-pocvpn-stream-frankfurt.conf).
Static assertions only; the routing itself was validated against a real nginx
(stream + ssl_preread) - see gateway/DEPLOYMENT.md "REALITY Frankfurt on 443"."""
import json
import os
import re
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
_STREAM = os.path.join(_GATEWAY_DIR, "edge", "nginx-pocvpn-stream-frankfurt.conf")
_MANIFEST_V8 = os.path.join(_GATEWAY_DIR, "tools", "production_manifest_2026-10-09_v8.json")


def _directives():
    text = open(_STREAM, encoding="utf-8").read()
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


class FrankfurtStreamSplitTests(unittest.TestCase):
    def setUp(self):
        self.lines = _directives()
        self.text = "\n".join(self.lines)

    def test_is_a_single_top_level_stream_block(self):
        self.assertEqual(self.lines[0], "stream {")
        self.assertEqual(self.text.count("stream {"), 1)
        self.assertNotIn("http {", self.text)

    def test_reality_sni_goes_to_the_proxy_stripping_hop_everything_else_to_https(self):
        block = re.search(r"map \$ssl_preread_server_name \$pocvpn_443_backend \{(.*?)\}", self.text, re.S).group(1)
        entries = dict(line.rstrip(";").split() for line in block.strip().splitlines())
        self.assertEqual(entries, {"www.wikipedia.org": "127.0.0.1:2054", "default": "127.0.0.1:4443"})

    def test_public_listener_is_443_v4_and_v6_with_preread_and_proxy_protocol(self):
        public = re.search(r"server \{(.*?)\}", self.text, re.S).group(1)
        for needle in ("listen 443;", "listen [::]:443;", "ssl_preread on;", "proxy_protocol on;", "proxy_pass $pocvpn_443_backend;"):
            self.assertIn(needle, public)

    def test_xray_hop_accepts_proxy_protocol_and_forwards_plain_tcp_to_2053(self):
        hop = re.findall(r"server \{(.*?)\}", self.text, re.S)[1]
        self.assertIn("listen 127.0.0.1:2054 proxy_protocol;", hop)
        self.assertIn("proxy_pass 127.0.0.1:2053;", hop)
        self.assertNotIn("proxy_protocol on;", hop)

    def test_only_loopback_backends_and_no_extra_public_listeners(self):
        targets = re.findall(r"(\d+\.\d+\.\d+\.\d+):\d+", self.text)
        self.assertTrue(targets)
        self.assertTrue(all(t == "127.0.0.1" for t in targets))
        listens = re.findall(r"listen ([^;]+);", self.text)
        self.assertEqual(sorted(listens), sorted(["443", "[::]:443", "127.0.0.1:2054 proxy_protocol"]))

    def test_manifest_v8_moves_only_frankfurt_reality_to_443(self):
        v8 = json.load(open(_MANIFEST_V8, encoding="utf-8"))
        v7 = json.load(open(os.path.join(_GATEWAY_DIR, "tools", "production_manifest_2026-10-08_v7.json"), encoding="utf-8"))
        self.assertEqual(v8["manifestVersion"], v7["manifestVersion"] + 1)
        changed = []
        for e7, e8 in zip(v7["endpoints"], v8["endpoints"]):
            self.assertEqual(e7["id"], e8["id"])
            for t7, t8 in zip(e7["transports"], e8["transports"]):
                if t7 != t8:
                    changed.append((e8["id"], t8["kindOrdinal"], t7["port"], t8["port"]))
        self.assertEqual(changed, [("frankfurt", 1, 2053, 443)])


if __name__ == "__main__":
    unittest.main()
