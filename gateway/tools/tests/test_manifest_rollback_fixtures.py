"""The committed TEST-key rollback fixtures (see manifest_rollback_fixtures.py)
must match the current v8/v9 JSON byte-for-byte, and v10 must be exactly
v8's endpoints with no REALITY+XHTTP (kind 7) binding."""
from __future__ import annotations

import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import manifest_rollback_fixtures as fx  # noqa: E402

_XRAY_REALITY_XHTTP = 7


def _kinds(data):
    return [t["kindOrdinal"] for e in data["endpoints"] for t in e["transports"]]


class ManifestRollbackFixturesTest(unittest.TestCase):
    def test_committed_fixtures_are_reproducible_from_current_json(self):
        for name, blob in fx.build().items():
            with open(os.path.join(fx.FIXTURE_DIR, f"test-key-{name}.bin"), "rb") as f:
                self.assertEqual(f.read(), blob, f"{name} fixture is stale - rerun manifest_rollback_fixtures.py")

    def test_v10_is_v8_endpoints_without_xhttp_and_newer_than_v9(self):
        j = fx.fixture_json()
        self.assertEqual(j["v10"]["endpoints"], j["v8"]["endpoints"])
        self.assertNotIn(_XRAY_REALITY_XHTTP, _kinds(j["v10"]))
        self.assertEqual(_kinds(j["v9"]).count(_XRAY_REALITY_XHTTP), 1)
        self.assertGreater(j["v10"]["manifestVersion"], j["v9"]["manifestVersion"])
        self.assertGreaterEqual(j["v10"]["expiresAtEpochMillis"], j["v9"]["expiresAtEpochMillis"])
        self.assertEqual(j["v10"]["signingKeyId"], j["v9"]["signingKeyId"])

    def test_committed_v10_rollback_json_is_exactly_the_derivation(self):
        # The production v10 is signed from this file; the TEST-key chain
        # test covers exactly its content only while the two stay equal.
        path = os.path.join(os.path.dirname(fx.V9_JSON), "production_manifest_2026-10-27_v10_ROLLBACK_DRAFT.json")
        self.assertEqual(fx._load(path), fx.fixture_json()["v10"])


if __name__ == "__main__":
    unittest.main()
