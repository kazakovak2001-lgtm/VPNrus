"""B-WL6 - whitelist lab record validator.

One record = ONE measured attempt on ONE concrete network context
(operator + region + date + network type). Records are evidence, never
generalizations: nothing here lets one operator's result stand in for
another's. The validator is deliberately strict and privacy-first: it
rejects anything that looks like an IP address, UUID, URL, key or token,
so a lab file can be shared without leaking endpoints or credentials.

    python3 research/whitelist-lab/lab_record.py records/*.json
"""
import json
import re
import sys

NETWORK_TYPES = ("WIFI", "LTE", "5G", "3G", "OTHER")
TRANSPORTS = (
    "AWG", "HYSTERIA2", "VLESS_REALITY_RAW", "VLESS_REALITY_XHTTP",
    "VLESS_TLS_XHTTP_CDN", "VLESS_TLS_TCP", "SHADOWSOCKS_2022", "PROBE_HTTPS", "PROBE_UDP",
)
ENDPOINT_TYPES = ("DIRECT_FOREIGN", "INGRESS_DIRECT_IP", "INGRESS_CDN_FRONTED", "DOMESTIC_REFERENCE")
RESULTS = ("CONNECTED_SUSTAINED", "EARLY_DROP", "HANDSHAKE_FAILED", "CONNECT_FAILED", "NO_UDP_RESPONSE", "NOT_TESTED")
# Same vocabulary as the Android RestrictionClass (B-WL1), never a stronger claim.
CLASSIFICATIONS = (
    "NO_RESTRICTION_OBSERVED", "POSSIBLE_UDP_OR_AWG_FILTERING", "POSSIBLE_UDP_FILTERING", "POSSIBLE_HARD_WHITELIST",
    "POSSIBLE_EARLY_DROP", "POSSIBLE_FULL_SHUTDOWN", "UNKNOWN",
)
CONFIDENCE = ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT")

REQUIRED = {
    "operator": str, "region": str, "date": str, "networkType": str, "transport": str,
    "endpointType": str, "result": str, "classification": str, "confidence": str,
}
OPTIONAL = {"repetitions": int, "bytesReceivedBeforeStall": int, "notes": str, "appVersion": str}

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_FORBIDDEN_PATTERNS = (
    ("IPv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("IPv6 address", re.compile(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){3,7}\b")),
    ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("URL", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://")),
    ("key/token-like blob", re.compile(r"[A-Za-z0-9_+/=-]{32,}")),
)


def validate(record):
    """Returns a list of human-readable problems; empty means valid."""
    problems = []
    if not isinstance(record, dict):
        return ["record must be a JSON object"]
    unknown = set(record) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        problems.append(f"unknown fields (closed schema): {sorted(unknown)}")
    for name, kind in REQUIRED.items():
        if not isinstance(record.get(name), kind):
            problems.append(f"missing or non-{kind.__name__} required field: {name}")
    for name, kind in OPTIONAL.items():
        if name in record and not isinstance(record[name], kind):
            problems.append(f"optional field {name} must be {kind.__name__}")
    if problems:
        return problems

    for name in ("operator", "region"):
        if not _LABEL.match(record[name]):
            problems.append(f"{name} must be a short plain label")
    if not _DATE.match(record["date"]):
        problems.append("date must be YYYY-MM-DD (each result is tied to a concrete date)")
    for name, allowed in (
        ("networkType", NETWORK_TYPES), ("transport", TRANSPORTS), ("endpointType", ENDPOINT_TYPES),
        ("result", RESULTS), ("classification", CLASSIFICATIONS), ("confidence", CONFIDENCE),
    ):
        if record[name] not in allowed:
            problems.append(f"{name} must be one of {allowed}")
    if record.get("repetitions", 1) < 1:
        problems.append("repetitions must be >= 1")
    if record.get("bytesReceivedBeforeStall", 0) < 0:
        problems.append("bytesReceivedBeforeStall must be >= 0")
    if record["confidence"] == "HIGH" and record.get("repetitions", 1) < 2:
        problems.append("HIGH confidence requires a reproduced result (repetitions >= 2)")

    for name, value in record.items():
        if not isinstance(value, str):
            continue
        for label, pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(value):
                problems.append(f"{name} contains a {label} - lab records must stay privacy-safe")
    return problems


def main(paths):
    failed = False
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        records = data if isinstance(data, list) else [data]
        for index, record in enumerate(records):
            for problem in validate(record):
                failed = True
                print(f"{path}[{index}]: {problem}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
