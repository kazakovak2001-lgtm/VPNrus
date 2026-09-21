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

Only `FIELD_MEASURED` plus L2/L3 data-plane proof may produce `PASS_END_TO_END`. A handshake, connected UI, TUN creation, socket reachability, or server port visibility is connection evidence only. Czech evidence is never Russia evidence. B49 simulated scenarios remain `SIMULATED`. Hysteria2 remains `NOT_TESTED`/`BLOCKED` here until B46-3A production integration exists.

## Matrix

Every cell begins as `NOT_TESTED`; a row is added only after an actual attempt. At minimum run each production-supported transport against each available network context and record failures as carefully as successes.

| Context | Network detail | Required scenarios | Required proof | Current state |
|---|---|---|---|---|
| Czech baseline | Wi-Fi, then cellular; operator/access technology separately | forced transport, Smart Connect, reconnect, disconnect cleanup | handshake duration; DNS; TCP; UDP where supported; exit match; server correlation when authorized | `BLOCKED` — no device |
| Restricted network | exact country, coarse region, operator, access technology and roaming state | same matrix plus classifier raw/stabilized values | same end-to-end proof, with negative results retained | `NOT_TESTED` |
| Russia | physical device actually in RU on a named operator/network | baseline, forced transport, Smart Connect, hard-whitelist candidate | same proof; no proxy/location inference | `NOT_TESTED` |
| Hard whitelist | network independently known to permit only an allowlist | hostname and direct-IP probes, transport attempts, recovery | correlated packet/application evidence | `NOT_TESTED` |

Production-supported rows currently cover `AMNEZIA_WG`, `XRAY_REALITY`, `XRAY_CDN_XHTTP`, and `SHADOWSOCKS_2022` only when their existing signed-profile, credential, ABI, packaging, and endpoint eligibility gates pass. `UNKNOWN` is mandatory when a value cannot be observed; absence is not evidence.

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
