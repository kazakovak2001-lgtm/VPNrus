"""The committed TEST-key rollback fixtures (see manifest_rollback_fixtures.py)
must match the current v7/v9 JSON byte-for-byte; v9 must be the SERVED v7
plus exactly one REALITY+XHTTP binding, and v10 exactly v7's endpoints."""
from __future__ import annotations

import copy
import os
import struct
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import manifest_rollback_fixtures as fx  # noqa: E402
import manifest_signing  # noqa: E402

_XRAY_REALITY = 1
_XRAY_REALITY_XHTTP = 7
_XHTTP_BINDING = {"kindOrdinal": _XRAY_REALITY_XHTTP, "host": "16.170.208.231", "port": 2096, "metadata": {}}


def _kinds(data):
    return [t["kindOrdinal"] for e in data["endpoints"] for t in e["transports"]]


def _reality_ports(data, endpoint_id):
    return [t["port"] for e in data["endpoints"] if e["id"] == endpoint_id
            for t in e["transports"] if t["kindOrdinal"] == _XRAY_REALITY]


class ManifestRollbackFixturesTest(unittest.TestCase):
    def test_committed_fixtures_are_reproducible_from_current_json(self):
        for name, blob in fx.build().items():
            with open(os.path.join(fx.FIXTURE_DIR, f"test-key-{name}.bin"), "rb") as f:
                self.assertEqual(f.read(), blob, f"{name} fixture is stale - rerun manifest_rollback_fixtures.py")

    def test_v7_json_is_the_signed_production_artifact(self):
        # The base is not a hand-written copy: its canonical bytes are exactly
        # what the committed, production-signed v7 artifact carries.
        with open(fx.V7_BIN, "rb") as f:
            blob = f.read()
        _, n = struct.unpack(">ii", blob[:8])
        canonical = manifest_signing.canonical_bytes(manifest_signing.load_manifest_json(fx.V7_JSON))
        self.assertEqual(blob[8:8 + n], canonical)
        self.assertEqual(fx.fixture_json()["v7"]["manifestVersion"], 7)

    def test_v9_is_v7_plus_exactly_one_xhttp_binding(self):
        j = fx.fixture_json()
        expected = copy.deepcopy(j["v7"])
        expected["manifestVersion"] = 9
        expected["issuedAtEpochMillis"] = j["v9"]["issuedAtEpochMillis"]
        [e for e in expected["endpoints"] if e["id"] == "stockholm"][0]["transports"].append(_XHTTP_BINDING)
        self.assertEqual(j["v9"], expected)
        self.assertGreater(j["v9"]["issuedAtEpochMillis"], j["v7"]["issuedAtEpochMillis"])

    def test_frankfurt_reality_stays_on_2053(self):
        # v8's undeployed move of Frankfurt REALITY to 443 must not leak in.
        j = fx.fixture_json()
        for name in ("v7", "v9", "v10"):
            self.assertEqual(_reality_ports(j[name], "frankfurt"), [2053], name)

    def test_v10_is_v7_endpoints_without_xhttp_and_newer_than_v9(self):
        j = fx.fixture_json()
        self.assertEqual(j["v10"]["endpoints"], j["v7"]["endpoints"])
        self.assertNotIn(_XRAY_REALITY_XHTTP, _kinds(j["v10"]))
        self.assertEqual(_kinds(j["v9"]).count(_XRAY_REALITY_XHTTP), 1)
        self.assertGreater(j["v10"]["manifestVersion"], j["v9"]["manifestVersion"])
        self.assertGreaterEqual(j["v10"]["expiresAtEpochMillis"], j["v9"]["expiresAtEpochMillis"])
        self.assertEqual(j["v10"]["signingKeyId"], j["v9"]["signingKeyId"])
        self.assertEqual(j["v9"]["signingKeyId"], j["v7"]["signingKeyId"])

    def test_committed_v10_rollback_json_is_exactly_the_derivation(self):
        # The production v10 is signed from this file; the TEST-key chain
        # test covers exactly its content only while the two stay equal.
        path = os.path.join(os.path.dirname(fx.V9_JSON), "production_manifest_2026-10-27_v10_ROLLBACK_DRAFT.json")
        self.assertEqual(fx._load(path), fx.fixture_json()["v10"])


if __name__ == "__main__":
    unittest.main()
