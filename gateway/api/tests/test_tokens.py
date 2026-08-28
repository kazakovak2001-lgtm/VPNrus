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
from _fixtures import make_public_key, make_token_store


class TokenLookupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "enrollment-tokens.json")
        self.lock_path = os.path.join(self._tmp.name, ".tokens.lock")
        self.pubkey_a = make_public_key(0x10)
        self.pubkey_r = make_public_key(0x20)

    def _touch_lock(self):
        os.close(os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600))

    def test_active_token_found(self):
        make_token_store(self.store_path, [("tok-a", self.pubkey_a, tokens_module.ACTIVE)], self.lock_path)
        result = tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)
        self.assertTrue(result.found)
        self.assertEqual(result.status, tokens_module.ACTIVE)
        self.assertEqual(result.expected_public_key, self.pubkey_a)
        self.assertRegex(result.token_id, r"^[0-9a-f]{32}$")

    def test_revoked_token_found_with_revoked_status(self):
        make_token_store(self.store_path, [("tok-r", self.pubkey_r, tokens_module.REVOKED)], self.lock_path)
        result = tokens_module.lookup_token("tok-r", self.store_path, self.lock_path)
        self.assertTrue(result.found)
        self.assertEqual(result.status, tokens_module.REVOKED)

    def test_unknown_token_not_found(self):
        make_token_store(self.store_path, [("tok-a", self.pubkey_a, tokens_module.ACTIVE)], self.lock_path)
        result = tokens_module.lookup_token("some-other-token", self.store_path, self.lock_path)
        self.assertFalse(result.found)

    def test_missing_store_raises(self):
        self._touch_lock()
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_malformed_json_raises(self):
        self._touch_lock()
        with open(self.store_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_non_object_root_raises(self):
        self._touch_lock()
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(["a", "list", "not", "an", "object"], handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def _write_raw_store(self, digest, record):
        self._touch_lock()
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({digest: record}, handle)

    def test_entry_missing_field_raises(self):
        digest = tokens_module.token_digest("tok-a")
        self._write_raw_store(digest, {"expected_public_key": self.pubkey_a, "status": "ACTIVE"})  # no token_id
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_extra_field_raises(self):
        digest = tokens_module.token_digest("tok-a")
        self._write_raw_store(
            digest,
            {
                "token_id": "a" * 32,
                "expected_public_key": self.pubkey_a,
                "status": "ACTIVE",
                "label": "not-allowed",
            },
        )
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_invalid_status_value_raises(self):
        digest = tokens_module.token_digest("tok-a")
        self._write_raw_store(
            digest, {"token_id": "a" * 32, "expected_public_key": self.pubkey_a, "status": "PENDING"}
        )
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_invalid_public_key_raises(self):
        digest = tokens_module.token_digest("tok-a")
        self._write_raw_store(digest, {"token_id": "a" * 32, "expected_public_key": "not-a-key", "status": "ACTIVE"})
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_entry_invalid_token_id_raises(self):
        digest = tokens_module.token_digest("tok-a")
        self._write_raw_store(
            digest, {"token_id": "NOT-HEX-OR-WRONG-LENGTH", "expected_public_key": self.pubkey_a, "status": "ACTIVE"}
        )
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_duplicate_token_id_across_records_raises(self):
        self._touch_lock()
        shared_token_id = "b" * 32
        digest1 = tokens_module.token_digest("tok-1")
        digest2 = tokens_module.token_digest("tok-2")
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    digest1: {"token_id": shared_token_id, "expected_public_key": self.pubkey_a, "status": "ACTIVE"},
                    digest2: {"token_id": shared_token_id, "expected_public_key": self.pubkey_r, "status": "ACTIVE"},
                },
                handle,
            )
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-1", self.store_path, self.lock_path)

    def test_invalid_digest_key_raises(self):
        self._touch_lock()
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({"not-a-valid-hex-digest": {}}, handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)

    def test_store_contains_only_digest_never_plaintext(self):
        make_token_store(
            self.store_path, [("super-secret-token-value", self.pubkey_a, tokens_module.ACTIVE)], self.lock_path
        )
        with open(self.store_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("super-secret-token-value", raw)
        digest = tokens_module.token_digest("super-secret-token-value")
        self.assertIn(digest, raw)

    # --- B8B1C1: reader lock semantics ---
    def test_reader_opens_lock_readonly_not_rdwr(self):
        # A lock file with NO write permission for us at all must still be
        # usable by the reader - if the reader ever tried O_RDWR, this
        # would fail with EACCES even though LOCK_SH only needs read.
        make_token_store(self.store_path, [("tok-a", self.pubkey_a, tokens_module.ACTIVE)], self.lock_path)
        os.chmod(self.lock_path, 0o400)
        try:
            result = tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)
            self.assertTrue(result.found)
        finally:
            os.chmod(self.lock_path, 0o600)  # restore so tempdir cleanup can remove it

    def test_reader_does_not_create_missing_lock(self):
        # Store exists, lock does not - the reader must fail, not silently
        # create the lock and proceed.
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({}, handle)
        self.assertFalse(os.path.exists(self.lock_path))
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)
        self.assertFalse(os.path.exists(self.lock_path), "reader must never create the lock file")

    def test_missing_lock_raises_token_lookup_error(self):
        with open(self.store_path, "w", encoding="utf-8") as handle:
            json.dump({}, handle)
        with self.assertRaises(tokens_module.TokenLookupError):
            tokens_module.lookup_token("tok-a", self.store_path, self.lock_path)


if __name__ == "__main__":
    unittest.main()
