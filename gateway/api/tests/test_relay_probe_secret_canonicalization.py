"""Regression tests for the ingress/EXIT relay-probe shared-secret file contract."""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _GATEWAY_DIR not in sys.path:
    sys.path.insert(0, _GATEWAY_DIR)

from api import relay_probe_token as rpt


class RelayProbeSecretCanonicalizationTests(unittest.TestCase):
    def test_trailing_newline_and_no_newline_are_the_same_hmac_key(self):
        secret = b"0123456789abcdef0123456789abcdef"
        token = rpt.mint(
            secret + b"\n",
            "ingress-a:DIRECT_IP:XRAY_REALITY->exit-a:XRAY_REALITY",
            "device-key",
            1000,
            300,
        )
        claims = rpt.verify(secret, token, 1001)
        self.assertEqual(
            claims.history_path_id,
            "ingress-a:DIRECT_IP:XRAY_REALITY->exit-a:XRAY_REALITY",
        )

    def test_trailing_crlf_and_lf_are_the_same_hmac_key(self):
        secret = b"abcdef0123456789abcdef0123456789"
        token = rpt.mint(secret + b"\r\n", "path-a", "device-key", 1000, 300)
        self.assertEqual(rpt.verify(secret + b"\n", token, 1001).history_path_id, "path-a")

    def test_leading_space_is_not_silently_stripped(self):
        secret = b" 0123456789abcdef0123456789abcdef"
        token = rpt.mint(secret, "path-b", "device-key", 1000, 300)
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(secret.lstrip(), token, 1001)


if __name__ == "__main__":
    unittest.main()