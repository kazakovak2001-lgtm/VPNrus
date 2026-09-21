#!/usr/bin/env python3
"""B54 repository-safe field observation validator and canonical serializer.

Enum fields that name a real Nova production type (network.type,
network.rawRestrictionClass/stabilizedRestrictionClass, path.transport,
path.gatewaySelectionMode, path.routingMode) are validated against that
production type's actual values, not a second, drifted taxonomy:
  - network.type            -> android NetworkType
  - network.*RestrictionClass -> android smartconnect.RestrictionClass
  - path.transport          -> android transport.TransportKind
  - path.gatewaySelectionMode -> android vpn.config.GatewaySelectionMode
  - path.routingMode        -> android vpn.policy.RoutingMode

Everything else (evidenceClass, result, proofLevel, exitProof, ...) is a
B54-only vocabulary with no production counterpart and is documented as such
in docs/B54_RESTRICTED_NETWORK_FIELD_VALIDATION_MATRIX.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_CLASSES = {"FIELD_MEASURED", "LAB_MEASURED", "SIMULATED", "SOURCE_CONFIRMED", "NOT_TESTED", "BLOCKED"}
RESULTS = {
    "PASS_END_TO_END", "PASS_CONNECTION_ONLY",
    "FAIL_CONNECT", "FAIL_HANDSHAKE", "FAIL_DATA_PLANE", "FAIL_DNS", "FAIL_UDP", "FAIL_EXIT_MISMATCH", "FAIL_CLEANUP",
    "BLOCKED_TEST_ENVIRONMENT", "NOT_TESTED",
}
# Mirrors android NetworkType (network/NetworkType.kt) exactly.
NETWORK_TYPES = {"WIFI", "CELLULAR", "ETHERNET", "OTHER", "NONE"}
# Mirrors android TransportKind (transport/TransportKind.kt) exactly. No HYSTERIA2:
# it is not a production TransportKind yet (see PENDING_TRANSPORTS below).
TRANSPORTS = {"AMNEZIA_WG", "XRAY_REALITY", "QUIC", "TLS_TCP", "XRAY_XHTTP", "SHADOWSOCKS_2022"}
# A transport under evaluation that is NOT a production TransportKind. Recording one
# here never substitutes for path.transport and can never claim field validation.
PENDING_TRANSPORTS = {"HYSTERIA2"}
# Mirrors android smartconnect.RestrictionClass (smartconnect/RestrictionClassifier.kt) exactly.
RESTRICTIONS = {
    "NO_NETWORK", "CAPTIVE_PORTAL", "INTERNET_NOT_VALIDATED", "GATEWAY_HTTPS_UNREACHABLE",
    "POSSIBLE_UDP_OR_AWG_FILTERING", "POSSIBLE_HARD_WHITELIST", "NETWORK_RECOVERING",
    "NO_RESTRICTION_OBSERVED", "UNKNOWN",
}
# Mirrors android vpn.config.GatewaySelectionMode exactly.
GATEWAY_SELECTION_MODES = {"AUTO", "MANUAL_MANAGED", "PRIVATE"}
# Mirrors android vpn.policy.RoutingMode exactly.
ROUTING_MODES = {"FULL_VPN", "ADAPTIVE", "APPS"}
PROOF_LEVELS = {"L0_CONNECTION_ONLY", "L1_TUNNEL_ESTABLISHED", "L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE", "UNKNOWN"}
EXIT_PROOFS = {"MATCHED", "MISMATCHED", "NOT_TESTED", "UNKNOWN"}
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
    if path.get("gatewaySelectionMode") not in GATEWAY_SELECTION_MODES: errors.append("invalid path.gatewaySelectionMode")
    if path.get("routingMode") not in ROUTING_MODES: errors.append("invalid path.routingMode")
    if proof.get("level") not in PROOF_LEVELS: errors.append("invalid proof.level")
    if proof.get("exitProof") not in EXIT_PROOFS: errors.append("invalid proof.exitProof")

    pending_transport = path.get("pendingTransportKind")
    transport = path.get("transport")
    if pending_transport is not None:
        if pending_transport not in PENDING_TRANSPORTS: errors.append("invalid path.pendingTransportKind")
        if transport is not None: errors.append("path.pendingTransportKind and path.transport are mutually exclusive")
        if evidence not in {"LAB_MEASURED", "SIMULATED"}: errors.append("path.pendingTransportKind requires LAB_MEASURED or SIMULATED evidence, never FIELD_MEASURED")
        if result not in {"NOT_TESTED", "BLOCKED_TEST_ENVIRONMENT"}: errors.append("path.pendingTransportKind is not a production TransportKind and cannot claim production field validation")
    elif transport not in TRANSPORTS:
        errors.append("invalid path.transport")

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

    # A substantive application-level flow (TCP or UDP) actually crossing the tunnel.
    # DNS is diagnostic signal only: a resolver round-trip alone is never proof of the
    # VPN's Internet data plane, so it is deliberately excluded here.
    substantive_data_plane = bool(proof.get("tcpRoundTrip") or proof.get("udpRoundTrip"))
    if result == "PASS_END_TO_END":
        if evidence != "FIELD_MEASURED": errors.append("PASS_END_TO_END real-network claim requires FIELD_MEASURED evidence")
        if proof.get("level") not in {"L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE"}: errors.append("PASS_END_TO_END requires L2 or L3 proof.level")
        if not proof.get("connectionEstablished"): errors.append("PASS_END_TO_END requires proof.connectionEstablished")
        if not substantive_data_plane: errors.append("PASS_END_TO_END requires a substantive TCP or UDP application data-plane flow; DNS alone is not sufficient")
        if proof.get("exitProof") != "MATCHED": errors.append("PASS_END_TO_END requires a matched exit proof for a VPN-path claim")
    if result == "PASS_CONNECTION_ONLY" and proof.get("level") in {"L2_DATA_PLANE", "L3_CORRELATED_DATA_PLANE"}:
        errors.append("PASS_CONNECTION_ONLY cannot carry end-to-end proof level")
    if proof.get("exitProof") == "MISMATCHED" and result in {"PASS_END_TO_END", "PASS_CONNECTION_ONLY"}:
        errors.append("exit mismatch cannot produce a passing result (use FAIL_EXIT_MISMATCH)")

    restricted_context = record.get("scenario", {}).get("restrictedContext") if isinstance(record.get("scenario"), dict) else None
    if restricted_context == "RUSSIA_FIELD":
        if evidence != "FIELD_MEASURED" or network.get("countryCode") != "RU" or network.get("operator") in UNKNOWN:
            errors.append("RUSSIA_FIELD requires FIELD_MEASURED RU evidence with a real operator")

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
