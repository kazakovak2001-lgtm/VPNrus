import base64
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api.wgkey import is_valid_wg_public_key


def _valid_key(byte=0x01):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class WgKeyTests(unittest.TestCase):
    def test_valid_key_accepted(self):
        self.assertTrue(is_valid_wg_public_key(_valid_key()))

    def test_wrong_length_rejected(self):
        self.assertFalse(is_valid_wg_public_key(_valid_key()[:-1]))
        self.assertFalse(is_valid_wg_public_key(_valid_key() + "A"))

    def test_non_string_rejected(self):
        self.assertFalse(is_valid_wg_public_key(None))
        self.assertFalse(is_valid_wg_public_key(12345))
        self.assertFalse(is_valid_wg_public_key([_valid_key()]))

    def test_invalid_base64_alphabet_rejected(self):
        bad = "!" + _valid_key()[1:]
        self.assertFalse(is_valid_wg_public_key(bad))

    def test_internal_whitespace_rejected(self):
        key = _valid_key()
        bad = key[:20] + " " + key[21:]
        self.assertFalse(is_valid_wg_public_key(bad))

    def test_decodes_to_wrong_byte_count_rejected(self):
        # 31 raw bytes also base64-encodes to a 44-char string (with "=="
        # padding instead of a single "=") - same length as a real key, but
        # a different decoded byte count. This specifically exercises the
        # "decoded length != 32" branch, not the length-44 pre-check.
        candidate = base64.b64encode(b"\x01" * 31).decode("ascii")
        self.assertEqual(len(candidate), 44)
        self.assertTrue(candidate.endswith("=="))
        self.assertFalse(is_valid_wg_public_key(candidate))

    def test_empty_string_rejected(self):
        self.assertFalse(is_valid_wg_public_key(""))


if __name__ == "__main__":
    unittest.main()
