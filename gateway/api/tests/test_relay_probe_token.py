"""B26 (task B/C) - unit tests for relay_probe_token.py's mint/verify
round trip and every fail-closed path."""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import relay_probe_token as rpt

_SECRET = b"S" * 32
_OTHER_SECRET = b"T" * 32
_PATH = "ru-ingress-1:XRAY_REALITY->frankfurt:XRAY_REALITY"
_DEVICE_KEY = "device-public-key-abc"


class RelayProbeTokenTests(unittest.TestCase):
    def test_valid_token_round_trips(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        claims = rpt.verify(_SECRET, token, now_epoch_seconds=1050)
        self.assertEqual(claims.history_path_id, _PATH)

    def test_expired_token_fails_closed(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(_SECRET, token, now_epoch_seconds=1300)

    def test_token_exactly_at_expiry_boundary_fails_closed(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(_SECRET, token, now_epoch_seconds=1300)  # exp == 1300, now >= exp fails closed

    def test_wrong_secret_fails_closed(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(_OTHER_SECRET, token, now_epoch_seconds=1050)

    def test_tampered_payload_fails_closed(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        payload_b64, _, signature = token.partition(".")
        tampered = rpt._b64url_encode(b'{"v":1,"path":"attacker-controlled-path","dev":"x","iat":1000,"exp":9999999999}')
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(_SECRET, f"{tampered}.{signature}", now_epoch_seconds=1050)

    def test_malformed_token_shapes_fail_closed(self):
        for bad in ("", "no-dot-here", ".", "abc.", ".def", "abc.not-hex-signature", "a" * 10 + "." + "0" * 63):
            with self.assertRaises(rpt.ProbeTokenError):
                rpt.verify(_SECRET, bad, now_epoch_seconds=1050)

    def test_future_iat_beyond_clock_skew_fails_closed(self):
        token = rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        with self.assertRaises(rpt.ProbeTokenError):
            rpt.verify(_SECRET, token, now_epoch_seconds=100)  # now far before iat

    def test_wrong_path_never_smuggled_in_by_a_client(self):
        """A caller cannot pass their own history_path_id into verify() at
        all - it only ever comes from the signed token itself. This test
        documents that property: two tokens minted for different paths
        never verify to the same claims."""
        token_a = rpt.mint(_SECRET, "path-a", _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        token_b = rpt.mint(_SECRET, "path-b", _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)
        self.assertEqual(rpt.verify(_SECRET, token_a, 1050).history_path_id, "path-a")
        self.assertEqual(rpt.verify(_SECRET, token_b, 1050).history_path_id, "path-b")

    def test_mint_rejects_non_positive_ttl(self):
        with self.assertRaises(ValueError):
            rpt.mint(_SECRET, _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=0)

    def test_mint_rejects_short_secret(self):
        with self.assertRaises(ValueError):
            rpt.mint(b"short", _PATH, _DEVICE_KEY, issued_at_epoch_seconds=1000, ttl_seconds=300)

    def test_device_binding_is_deterministic_and_never_the_raw_key(self):
        binding = rpt.device_binding(_DEVICE_KEY)
        self.assertEqual(binding, rpt.device_binding(_DEVICE_KEY))
        self.assertNotIn(_DEVICE_KEY, binding)
        self.assertEqual(len(binding), 16)


if __name__ == "__main__":
    unittest.main()
