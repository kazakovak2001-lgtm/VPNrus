# B54 Restricted-Network Field Validation Matrix

## Status

**FIELD VALIDATION FRAMEWORK READY / RESTRICTED-NETWORK EVIDENCE PENDING**

Implementation-time precondition: `adb devices -l` returned an empty device list on 2026-09-21. Therefore field execution is **BLOCKED — NO DEVICE**. This document and the validator create no measured result, do not relabel historical evidence, and make no Russia or hard-whitelist bypass claim.

## Evidence contract

Every observation is independent. Never merge Wi-Fi and cellular, two operators, two timestamps, or two transports into one row. The closed evidence vocabulary is:

| Class | Meaning | May support a real-network outcome? |
|---|---|---|
| `FIELD_MEASURED` | Captured on a named build and physical Android device on the stated real network at the stated UTC time | Yes, subject to proof level |
| `LAB_MEASURED` | Real traffic in controlled infrastructure or a non-field environment | No |
| `SIMULATED` | Synthetic classifier, network-shaping, emulator, or fixture result | No |
| `SOURCE_CONFIRMED` | Confirmed by source/configuration inspection only | No |
| `NOT_TESTED` | Explicitly not executed | No |
| `BLOCKED` | Intended execution prevented, with reason | No |

`evidenceClass`, `result`, `proof.level`, and `proof.exitProof` are B54-only vocabulary with no production counterpart. Every other enum field names a real Nova production type and is validated against that type's actual values (see "Production type parity" below) — never a second, drifted taxonomy with similar-looking labels.

### End-to-end proof requirement

`PASS_END_TO_END` is a claim about the VPN's actual Internet data plane, not about the control channel. The validator requires ALL of:

- `proof.level` is `L2_DATA_PLANE` or `L3_CORRELATED_DATA_PLANE`;
- `proof.connectionEstablished` is `true`;
- at least one **substantive** application flow: `proof.tcpRoundTrip` or `proof.udpRoundTrip` is `true` — a DNS round-trip alone (`proof.dnsRoundTrip`) never satisfies this, because a resolver query proves nothing about the tunnel's data plane;
- `proof.exitProof` is `MATCHED` — an exit-IP mismatch can never produce a passing result;
- `evidenceClass` is `FIELD_MEASURED`.

`proof.dnsRoundTrip` remains its own independent signal and is recorded regardless of the other proofs. Missing server-side correlation (`proof.serverCorrelation: NOT_TESTED`) lowers the achievable proof level (no `L3`) but does not by itself invalidate an otherwise real client-side `L2_DATA_PLANE` result. Czech evidence is never Russia evidence. B49 simulated scenarios remain `SIMULATED`. Hysteria2 remains represented as pending, non-production metadata (`path.pendingTransportKind`, see below) until it has a real `TransportKind`.

### Result vocabulary

`result` is one of: `PASS_END_TO_END`, `PASS_CONNECTION_ONLY`, `FAIL_CONNECT`, `FAIL_HANDSHAKE`, `FAIL_DATA_PLANE`, `FAIL_DNS`, `FAIL_UDP`, `FAIL_EXIT_MISMATCH`, `FAIL_CLEANUP`, `BLOCKED_TEST_ENVIRONMENT`, `NOT_TESTED`. These are typed test-result labels, not a copy of Android's `DiagnosticOutcome`/`DiagnosticFailureReason` runtime vocabulary; where a `FAIL_*` value corresponds to an observed `DiagnosticFailureReason`, record the mapping in `limitations` (e.g. `FAIL_DATA_PLANE` observed alongside `DATA_PLANE_NOT_READY`), but do not rename the diagnostic vocabulary itself.

### Production type parity

The validator mirrors these Android production enums exactly (no invented values, no dropped values):

| B54 field | Production type | Values |
|---|---|---|
| `network.type` | `net.pocvpn.client.network.NetworkType` | `WIFI`, `CELLULAR`, `ETHERNET`, `OTHER`, `NONE` |
| `network.rawRestrictionClass`, `network.stabilizedRestrictionClass` | `net.pocvpn.client.smartconnect.RestrictionClass` | `NO_NETWORK`, `CAPTIVE_PORTAL`, `INTERNET_NOT_VALIDATED`, `GATEWAY_HTTPS_UNREACHABLE`, `POSSIBLE_UDP_OR_AWG_FILTERING`, `POSSIBLE_HARD_WHITELIST`, `NETWORK_RECOVERING`, `NO_RESTRICTION_OBSERVED`, `UNKNOWN` |
| `path.transport` | `net.pocvpn.client.transport.TransportKind` | `AMNEZIA_WG`, `XRAY_REALITY`, `QUIC`, `TLS_TCP`, `XRAY_XHTTP`, `SHADOWSOCKS_2022` |
| `path.gatewaySelectionMode` | `net.pocvpn.client.vpn.config.GatewaySelectionMode` | `AUTO`, `MANUAL_MANAGED`, `PRIVATE` |
| `path.routingMode` | `net.pocvpn.client.vpn.policy.RoutingMode` | `FULL_VPN`, `ADAPTIVE`, `APPS` |

`POSSIBLE_HARD_WHITELIST` is preserved exactly as the classifier emits it and is never renamed into a stronger claim (e.g. "confirmed hard whitelist"). A record with `rawRestrictionClass`/`stabilizedRestrictionClass` of `POSSIBLE_HARD_WHITELIST` does not, by itself, satisfy the `RUSSIA_FIELD` evidence contract below — that still independently requires `FIELD_MEASURED` evidence with a real RU operator/network context.

`PathKind`, `ManifestSourceKind`, `DiagnosticOutcome`, and `DiagnosticFailureReason` have no corresponding B54 schema field today; they are not duplicated here and are listed only so a future field addition is checked against them first.

### Pending, non-production transports (Hysteria2)

Hysteria2 has no production `TransportKind` (`TransportKind.HYSTERIA2` does not exist and is out of scope for B54). A record about Hysteria2 must use `path.pendingTransportKind: "HYSTERIA2"` instead of `path.transport`, and:

- `evidenceClass` must be `LAB_MEASURED` or `SIMULATED` (never `FIELD_MEASURED`);
- `result` must be `NOT_TESTED` or `BLOCKED_TEST_ENVIRONMENT` (it can never claim `PASS_END_TO_END`/`PASS_CONNECTION_ONLY`, because there is no production transport to validate).

B46-3C (PR #110) physically passed full data-plane feasibility in a lab/architecture context; per this rule it is documented as `LAB_MEASURED` evidence with `pendingTransportKind: "HYSTERIA2"`, never as a `path.transport` field result. PR #110 itself is untouched by this correction.

## Matrix

Every cell begins as `NOT_TESTED`; a row is added only after an actual attempt. At minimum run each production-supported transport against each available network context and record failures as carefully as successes.

| Context | Network detail | Required scenarios | Required proof | Current state |
|---|---|---|---|---|
| Czech baseline | Wi-Fi, then cellular; operator/access technology separately | forced transport, Smart Connect, reconnect, disconnect cleanup | handshake duration; DNS; TCP; UDP where supported; exit match; server correlation when authorized | `BLOCKED` — no device |
| Restricted network | exact country, coarse region, operator, access technology and roaming state | same matrix plus classifier raw/stabilized values | same end-to-end proof, with negative results retained | `NOT_TESTED` |
| Russia | physical device actually in RU on a named operator/network | baseline, forced transport, Smart Connect, hard-whitelist candidate | same proof; no proxy/location inference | `NOT_TESTED` |
| Hard whitelist | network independently known to permit only an allowlist | hostname and direct-IP probes, transport attempts, recovery | correlated packet/application evidence | `NOT_TESTED` |

Production-supported rows currently cover the real `TransportKind` values (`AMNEZIA_WG`, `XRAY_REALITY`, `QUIC`, `TLS_TCP`, `XRAY_XHTTP`, `SHADOWSOCKS_2022`) only when their existing signed-profile, credential, ABI, packaging, and endpoint eligibility gates pass. `UNKNOWN` is mandatory when a value cannot be observed; absence is not evidence.

## Record schema and collection procedure

The executable schema is `tools/field_validation/record_validator.py`. Required groups are: schema/version and unique observation ID; evidence class/result/timestamp; exact Git commit and app version; device model/Android/API/ABI; network type/country/operator/access technology/roaming/IP-family/Android validation; raw and stabilized restriction classes; scenario; selection/routing/gateway/transport; proof level and individual DNS/TCP/UDP/exit/server-correlation/cleanup observations; limitations.

1. Confirm consent and authorization for the network and server-side correlation.
2. Record UTC time and immutable build identity before the attempt. Record operator and coarse region manually; never infer them from exit IP.
3. Capture `NetworkProfiler` facts and both `RestrictionClassifier` raw output and `RestrictionStabilizer` output. They describe the observed network; they do not prove censorship or cause.
4. Record the pinned route and transport from the existing attempt/diagnostic authorities. Do not copy credentials, host/IP values, unrestricted logs, subscriber identity, SSID, or browsing data.
5. Distinguish L0 connection attempt, L1 established tunnel, L2 application data plane, and L3 independently correlated data plane. Record each probe as true/false/`NOT_TESTED`; do not turn an unrun check into success.
6. Validate and canonicalize the record. Review it again with the existing support-diagnostics sanitizer/export boundary before commit. Commit only minimal metadata and separately authorized, redacted proof.
7. Restore device/network state and verify cleanup. Record a new observation for every rerun.

Repository-safe retention is metadata-only. Raw packet captures, support bundles, phone numbers, IMSI/IMEI, account names, credentials, endpoint addresses, precise location, SSIDs, and unrestricted `logcat` stay outside Git in an access-controlled evidence store. A committed record may reference an approved opaque evidence ID, never a secret URL or path.

## Historical evidence assessment

B45/B46 physical reports establish valuable Android/lab/real-network behavior for their exact Czech device and test context, but they predate this record contract and do not consistently provide the operator, access technology, UTC observation identity, raw/stabilized restriction classification, and repository-safe per-observation envelope required here. They remain authoritative for their original bounded claims and are **not imported as B54 restricted-network observations**. In particular:

- B45B-5 contains real Czech Wi-Fi/cellular handover evidence, but it is not Russia or hard-whitelist evidence.
- B46-2P contains real Android Hysteria2 harness evidence, but Hysteria2 is not a production-integrated selectable transport; it cannot become a production validation result.
- B49 classifier/network scenarios are simulated evidence, regardless of how realistic their inputs are.

## Claim discipline and next execution gate

No wording may say a transport “bypasses,” “works in Russia,” or “works on restricted networks” unless the exact claim is supported by qualifying `FIELD_MEASURED` observations. Negative and inconclusive outcomes are published with equal fidelity. The next step is to attach an authorized physical Android device, capture Czech baseline observations first, and only then schedule separately authorized restricted-network/Russia runs. B55 may consume accepted observations, but cannot upgrade their evidence class.
