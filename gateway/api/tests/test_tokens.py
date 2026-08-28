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

from api import tokens as tokens_module
from _fixtures import make_token_store


class TokenLookupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "enrollment-tokens.json")
        self.lock_path = os.path.join(self._tmp.name, ".tokens.lock")

    def test_active_token_found(self):
        make_token_store(self.store_path, [("tok-a", "pubkey-a", tokens_module.ACTIVE)])
        result = tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)
        self.assertTrue(result.found)
        self.assertEqual(result.status, tokens_module.ACTIVE)
        self.assertEqual(result.expected_public_key, "pubkey-a")

    def test_revoked_token_found_with_revoked_status(self):
        make_token_store(self.store_path, [("tok-r", "pubkey-r", tokens_module.REVOKED)])
        result = tokens_module.lookup_token("tok-r", self.store_path, self.lock_path)
        self.assertTrue(result.found)
        self.assertEqual(result.status, tokens_module.REVOKED)

    def test_unknown_token_not_found(self):
        make_token_store(self.store_path, [("tok-a", "pubkey-a", tokens_module.ACTIVE)])
        result = tokens_module.lookup_token("some-other-token", self.store_path, self.lock_path)
        self.assertFalse(result.found)

    def test_missing_store_raises(self):
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_malformed_json_raises(self):
        with open(self.store_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_non_object_root_raises(self):
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(["a", "list", "not", "an", "object"], handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_missing_status_raises(self):
        digest = tokens_module.token_digest("tok-a")
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({digest: {"expected_public_key": "pubkey-a"}}, handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_invalid_status_value_raises(self):
        digest = tokens_module.token_digest("tok-a")
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({digest: {"expected_public_key": "pubkey-a", "status": "PENDING"}}, handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_missing_expected_public_key_raises(self):
        digest = tokens_module.token_digest("tok-a")
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({digest: {"status": "ACTIVE"}}, handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_store_contains_only_digest_never_plaintext(self):
        make_token_store(self.store_path, [("super-secret-token-value", "pubkey-a", tokens_module.ACTIVE)])
        with open(self.store_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("super-secret-token-value", raw)
        digest = tokens_module.token_digest("super-secret-token-value")
        self.assertIn(digest, raw)


if __name__ == "__main__":
    unittest.main()
