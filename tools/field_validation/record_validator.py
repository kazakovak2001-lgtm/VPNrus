#!/usr/bin/env python3
"""B54 repository-safe field observation validator and canonical serializer."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_CLASSES = {"FIELD_MEASURED", "LAB_MEASURED", "SIMULATED", "SOURCE_CONFIRMED", "NOT_TESTED", "BLOCKED"}
RESULTS = {"PASS_END_TO_END", "PASS_CONNECTION_ONLY", "FAIL", "NOT_TESTED", "BLOCKED"}
NETWORK_TYPES = {"WIFI", "CELLULAR", "ETHERNET", "OTHER", "UNKNOWN"}
TRANSPORTS = {"AMNEZIA_WG", "XRAY_REALITY", "XRAY_CDN_XHTTP", "SHADOWSOCKS_2022", "HYSTERIA2", "UNKNOWN"}
RESTRICTIONS = {"OPEN", "UDP_RESTRICTED", "TCP_ONLY", "HARD_WHITELIST_SUSPECTED", "UNKNOWN", "NOT_TESTED"}
PROOF_LEVELS = {"L0_CONNECTION_ONLY", "L1_TUNNEL_ESTABLISHED", "L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE", "UNKNOWN"}
UNKNOWN = {None, "", "UNKNOWN", "NOT_TESTED"}

_SECRET_PATTERNS = (
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
    re.compile(r"(?i)(token|secret|password|credential|api[_-]?key|private[_-]?key)\s*[:=]"),
    re.compile(r"(?i)https?://\S+"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"(?i)\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){3,}\b"),
)
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")


def canonical_json(record: dict[str, Any]) -> str:
    """Stable UTF-8 JSON representation suitable for review and hashing."""
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def _values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _values(child)
    elif isinstance(value, str):
        yield value


def _secret_shaped(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS) or any(
        any(char.islower() for char in match.group(0)) for match in _BASE64.finditer(value)
    )


def validate(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"schemaVersion", "observationId", "evidenceClass", "result", "timestampUtc", "build", "device", "network", "scenario", "path", "proof", "limitations"}
    missing = sorted(required - record.keys())
    if missing:
        errors.append("missing required fields: " + ", ".join(missing))

    evidence = record.get("evidenceClass")
    result = record.get("result")
    network = record.get("network") if isinstance(record.get("network"), dict) else {}
    path = record.get("path") if isinstance(record.get("path"), dict) else {}
    proof = record.get("proof") if isinstance(record.get("proof"), dict) else {}
    device = record.get("device") if isinstance(record.get("device"), dict) else {}
    build = record.get("build") if isinstance(record.get("build"), dict) else {}

    if record.get("schemaVersion") != 1: errors.append("schemaVersion must be 1")
    if evidence not in EVIDENCE_CLASSES: errors.append("invalid evidenceClass")
    if result not in RESULTS: errors.append("invalid result")
    if network.get("type") not in NETWORK_TYPES: errors.append("invalid network.type")
    if network.get("rawRestrictionClass") not in RESTRICTIONS: errors.append("invalid network.rawRestrictionClass")
    if network.get("stabilizedRestrictionClass") not in RESTRICTIONS: errors.append("invalid network.stabilizedRestrictionClass")
    if path.get("transport") not in TRANSPORTS: errors.append("invalid path.transport")
    if proof.get("level") not in PROOF_LEVELS: errors.append("invalid proof.level")

    timestamp = record.get("timestampUtc")
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError
    except (TypeError, ValueError):
        errors.append("timestampUtc must be a timezone-aware UTC ISO-8601 value")

    if evidence == "FIELD_MEASURED":
        if network.get("type") in UNKNOWN: errors.append("FIELD_MEASURED requires a known network.type")
        if network.get("countryCode") in UNKNOWN: errors.append("FIELD_MEASURED requires network.countryCode")
        if device.get("model") in UNKNOWN or device.get("androidVersion") in UNKNOWN: errors.append("FIELD_MEASURED requires device model and Android version")
        if build.get("gitCommit") in UNKNOWN or build.get("versionName") in UNKNOWN: errors.append("FIELD_MEASURED requires build gitCommit and versionName")
    if evidence == "SIMULATED" and record.get("claimScope") == "REAL_NETWORK":
        errors.append("SIMULATED evidence cannot claim REAL_NETWORK scope")

    data_plane = bool(proof.get("dnsRoundTrip") or proof.get("tcpRoundTrip") or proof.get("udpRoundTrip"))
    if result == "PASS_END_TO_END":
        if evidence != "FIELD_MEASURED": errors.append("PASS_END_TO_END real-network claim requires FIELD_MEASURED evidence")
        if proof.get("level") not in {"L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE"} or not data_plane:
            errors.append("PASS_END_TO_END requires measured data-plane proof")
    if result == "PASS_CONNECTION_ONLY" and proof.get("level") in {"L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE"}:
        errors.append("PASS_CONNECTION_ONLY cannot carry end-to-end proof level")

    restricted_context = record.get("scenario", {}).get("restrictedContext") if isinstance(record.get("scenario"), dict) else None
    if restricted_context == "RUSSIA_FIELD":
        if evidence != "FIELD_MEASURED" or network.get("countryCode") != "RU" or network.get("operator") in UNKNOWN:
            errors.append("RUSSIA_FIELD requires FIELD_MEASURED RU evidence with a real operator")

    if path.get("transport") == "HYSTERIA2" and result not in {"NOT_TESTED", "BLOCKED"}:
        errors.append("HYSTERIA2 remains pending production integration and cannot claim validation")

    if any(_secret_shaped(value) for value in _values(record)):
        errors.append("record contains secret/address-shaped repository-unsafe metadata")
    if not isinstance(record.get("limitations"), list) or not record.get("limitations"):
        errors.append("limitations must be a non-empty list")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("--canonical-output", type=Path)
    args = parser.parse_args()
    record = json.loads(args.record.read_text(encoding="utf-8"))
    errors = validate(record)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    rendered = canonical_json(record)
    if args.canonical_output: args.canonical_output.write_text(rendered, encoding="utf-8", newline="\n")
    else: sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
