"""TEST-ONLY fixtures for the REALITY+XHTTP manifest rollback chain
(gateway/DEPLOYMENT.md, "REALITY + XHTTP on Stockholm", rollback B):

    v7   production_manifest_2026-10-08_v7.json, unchanged - the manifest
         production serves (its committed signed artifact
         endpoint-manifest-2026-10-08-v7.bin is what /v1/manifest returns)
    v9   production_manifest_2026-10-27_v9_DRAFT.json, unchanged - v7 plus
         ONE Stockholm REALITY+XHTTP binding
    v10  v7's endpoints, manifestVersion 10, v9's signingKeyId,
         issuedAt = v9 issuedAt + 1, expiresAt = v9 expiresAt

v8 (production_manifest_2026-10-09_v8.json, Frankfurt REALITY on 443) was
never signed or served; nothing here builds on it.

All three are signed with the deterministic TEST key bytes(range(32)) -
never a production key - so they prove manifest CONTENT and client rollback
logic, not a production signature. Ed25519 is deterministic, so the
committed .bin files are byte-reproducible; test_manifest_rollback_fixtures
fails if the JSON drifts from them.

Regenerate after changing either JSON:
    python3 gateway/tools/tests/manifest_rollback_fixtures.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

import manifest_signing  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

TEST_PRIVATE_KEY_BYTES = bytes(range(32))
FIXTURE_DIR = os.path.join(_THIS_DIR, "fixtures", "manifest-rollback")
V7_JSON = os.path.join(_TOOLS_DIR, "production_manifest_2026-10-08_v7.json")
V7_BIN = os.path.join(_TOOLS_DIR, "endpoint-manifest-2026-10-08-v7.bin")
V9_JSON = os.path.join(_TOOLS_DIR, "production_manifest_2026-10-27_v9_DRAFT.json")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fixture_json() -> dict:
    v7, v9 = _load(V7_JSON), _load(V9_JSON)
    v10 = copy.deepcopy(v7)
    v10["manifestVersion"] = 10
    v10["signingKeyId"] = v9["signingKeyId"]
    v10["issuedAtEpochMillis"] = v9["issuedAtEpochMillis"] + 1
    v10["expiresAtEpochMillis"] = v9["expiresAtEpochMillis"]
    return {"v7": v7, "v9": v9, "v10": v10}


def build() -> dict:
    """name -> signed artifact bytes, test key only."""
    key = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY_BYTES)
    out = {}
    for name, data in fixture_json().items():
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f"{name}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            manifest = manifest_signing.load_manifest_json(path)
        out[name] = manifest_signing.pack_signed_manifest(
            manifest_signing.canonical_bytes(manifest), manifest_signing.sign(manifest, key)
        )
    return out


def main() -> int:
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    for name, blob in build().items():
        with open(os.path.join(FIXTURE_DIR, f"test-key-{name}.bin"), "wb") as f:
            f.write(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
