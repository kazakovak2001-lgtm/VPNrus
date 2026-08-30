#!/usr/bin/env python3
"""B11 - offline Endpoint Manifest signing tool.

This is a DEVELOPER/OPERATOR tool, run offline, never deployed to the
production VPS and never invoked by the gateway API at runtime. It holds the
manifest SIGNING key (the "signing key" half of the root/signing separation
documented in EndpointManifestRepository's own docs) and produces a signed
manifest blob the Android client's Ed25519ManifestVerifier can verify.

Encoding: byte-for-byte compatible with
android/app/src/main/java/net/pocvpn/client/reachability/EndpointManifest.kt's
ManifestCanonicalizer - same field order, same 4-byte big-endian
length-prefixed strings, same explicit key/role/transport sort order. If you
change one side, change the other and re-run cross_verify_fixture.py.

Requires the `cryptography` package (not a gateway API runtime dependency -
this script is never imported by gateway/api/*). Install with:
    pip install cryptography
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import struct
import sys
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

FORMAT_VERSION = 1


def _write_string(buf: bytearray, s: str) -> None:
    b = s.encode("utf-8")
    if len(b) > 4096:
        raise ValueError(f"string field too long: {len(b)} bytes")
    buf += struct.pack(">i", len(b))
    buf += b


@dataclasses.dataclass(frozen=True)
class TransportBinding:
    kind_ordinal: int
    host: str
    port: int
    metadata: dict


@dataclasses.dataclass(frozen=True)
class Endpoint:
    id: str
    role_ordinals: list
    region: str
    provider: str
    asn: Optional[int]
    transports: list  # list[TransportBinding]
    relay_to: Optional[str]


@dataclasses.dataclass(frozen=True)
class Manifest:
    manifest_version: int
    issued_at_epoch_millis: int
    expires_at_epoch_millis: int
    endpoints: list  # list[Endpoint]
    signing_key_id: str


def canonical_bytes(m: Manifest) -> bytes:
    """Must stay byte-identical to ManifestCanonicalizer.canonicalBytes (Kotlin)."""
    buf = bytearray()
    buf += struct.pack(">i", FORMAT_VERSION)
    buf += struct.pack(">i", m.manifest_version)
    buf += struct.pack(">q", m.issued_at_epoch_millis)
    buf += struct.pack(">q", m.expires_at_epoch_millis)
    _write_string(buf, m.signing_key_id)

    endpoints_sorted = sorted(m.endpoints, key=lambda e: e.id)
    buf += struct.pack(">i", len(endpoints_sorted))
    for e in endpoints_sorted:
        _write_string(buf, e.id)
        roles_sorted = sorted(e.role_ordinals)
        buf += struct.pack(">i", len(roles_sorted))
        for r in roles_sorted:
            buf += struct.pack(">i", r)
        _write_string(buf, e.region)
        _write_string(buf, e.provider)
        buf += struct.pack(">?", e.asn is not None)
        buf += struct.pack(">i", e.asn or 0)
        transports_sorted = sorted(e.transports, key=lambda t: t.kind_ordinal)
        buf += struct.pack(">i", len(transports_sorted))
        for t in transports_sorted:
            buf += struct.pack(">i", t.kind_ordinal)
            _write_string(buf, t.host)
            buf += struct.pack(">i", t.port)
            meta_sorted = sorted(t.metadata.items(), key=lambda kv: kv[0])
            buf += struct.pack(">i", len(meta_sorted))
            for k, v in meta_sorted:
                _write_string(buf, k)
                _write_string(buf, v)
        buf += struct.pack(">?", e.relay_to is not None)
        _write_string(buf, e.relay_to or "")
    return bytes(buf)


def sign(manifest: Manifest, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(canonical_bytes(manifest))


def pack_signed_manifest(canonical: bytes, signature: bytes) -> bytes:
    """B12 - the SAME binary container SignedManifestCodec.kt encodes/decodes
    on the Android side: [formatVersion:i32BE][canonicalLen:i32BE]
    [canonicalBytes][signatureLen:i32BE][signature]. This is the exact byte
    sequence an operator places at AppConfig.manifest_path for GET
    /v1/manifest to serve verbatim - see gateway/api/handler.py's own docs
    for why that process never signs or parses this itself."""
    buf = bytearray()
    buf += struct.pack(">i", FORMAT_VERSION)
    buf += struct.pack(">i", len(canonical))
    buf += canonical
    buf += struct.pack(">i", len(signature))
    buf += signature
    return bytes(buf)


def load_manifest_json(path: str) -> Manifest:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    endpoints = []
    for e in data["endpoints"]:
        transports = [
            TransportBinding(
                kind_ordinal=t["kindOrdinal"],
                host=t["host"],
                port=t["port"],
                metadata=t.get("metadata", {}),
            )
            for t in e["transports"]
        ]
        endpoints.append(
            Endpoint(
                id=e["id"],
                role_ordinals=e["roleOrdinals"],
                region=e["region"],
                provider=e["provider"],
                asn=e.get("asn"),
                transports=transports,
                relay_to=e.get("relayTo"),
            )
        )
    return Manifest(
        manifest_version=data["manifestVersion"],
        issued_at_epoch_millis=data["issuedAtEpochMillis"],
        expires_at_epoch_millis=data["expiresAtEpochMillis"],
        endpoints=endpoints,
        signing_key_id=data["signingKeyId"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-key", help="Generate a new Ed25519 signing keypair")
    gen.add_argument("--key-id", required=True)

    sign_cmd = sub.add_parser("sign", help="Sign a manifest JSON file")
    sign_cmd.add_argument("--manifest", required=True, help="Path to manifest JSON")
    sign_cmd.add_argument("--private-key-b64", required=True, help="Base64 raw Ed25519 private key (32 bytes)")

    package_cmd = sub.add_parser(
        "sign-and-package",
        help="B12 - sign a manifest JSON file AND write the binary artifact ready for AppConfig.manifest_path",
    )
    package_cmd.add_argument("--manifest", required=True, help="Path to manifest JSON")
    package_cmd.add_argument("--private-key-b64", required=True, help="Base64 raw Ed25519 private key (32 bytes)")
    package_cmd.add_argument("--out", required=True, help="Output path for the binary artifact (e.g. endpoint-manifest.bin)")

    args = parser.parse_args()

    if args.command == "generate-key":
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        print(json.dumps({
            "keyId": args.key_id,
            "privateKeyBase64": base64.b64encode(priv_bytes).decode("ascii"),
            "publicKeyBase64": base64.b64encode(pub_bytes).decode("ascii"),
        }, indent=2))
        return 0

    if args.command == "sign":
        manifest = load_manifest_json(args.manifest)
        priv_bytes = base64.b64decode(args.private_key_b64)
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = sign(manifest, priv)
        print(json.dumps({
            "manifestVersion": manifest.manifest_version,
            "signatureBase64": base64.b64encode(signature).decode("ascii"),
            "canonicalBytesBase64": base64.b64encode(canonical_bytes(manifest)).decode("ascii"),
        }, indent=2))
        return 0

    if args.command == "sign-and-package":
        manifest = load_manifest_json(args.manifest)
        priv_bytes = base64.b64decode(args.private_key_b64)
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        canonical = canonical_bytes(manifest)
        signature = sign(manifest, priv)
        artifact = pack_signed_manifest(canonical, signature)
        with open(args.out, "wb") as f:
            f.write(artifact)
        print(json.dumps({
            "manifestVersion": manifest.manifest_version,
            "artifactPath": args.out,
            "artifactBytes": len(artifact),
        }, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
