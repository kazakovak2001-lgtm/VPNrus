# B47-1P — Physical Android Packet-Capture Baseline

Status: **PROCEDURE READY; PHYSICAL CAPTURE BLOCKED — NO DEVICE ATTACHED**

Prepared: 2026-09-21

Branch baseline: `research/b47-traffic-fingerprint-audit` at `4e5ad508b84ea2d7c4a207892b3843e1842b645c`

## 1. Scope

B47-1P is the physical-evidence follow-up to the source and bounded endpoint audit in `B47_TRAFFIC_FINGERPRINT_AUDIT.md`. It is intended to replace selected `INFERRED` and `NOT TESTED` statements with synchronized evidence from the real Nova Android application.

This preparation pass defines the capture, redaction, synchronization, scenario, and evidence-acceptance procedure. It does not change production transport behavior, Smart Connect, TLS profiles, XHTTP, DNS, ports, certificates, endpoints, credentials, or trust logic.

No physical scenario was executed in this pass. ADB was found at `C:\Users\akaza\AppData\Local\Android\Sdk\platform-tools\adb.exe`, but `adb devices -l` returned no attached devices. The host also had no Wireshark, `tshark`, `dumpcap`, or `tcpdump`. Therefore every physical result section below remains `NOT TESTED`.

Hysteria2 is **PENDING B46-3A** and excluded. PR #99 and its branch are not dependencies of this work.

## 2. Device and build identity

Target device:

| Field | Required value | This pass |
|---|---|---|
| Manufacturer/model | OPPO CPH2173 | NOT OBSERVED — device absent |
| Android | Android 14 / API 34 | SOURCE-CONFIRMED from prior repository evidence; must be re-read on test day |
| Primary ABI | `arm64-v8a` | SOURCE-CONFIRMED from prior repository evidence; must be re-read on test day |
| Expected serial | `c618ee06` | Historical identifier only; do not assume identity until ADB reports it |
| Package | `net.pocvpn.client` | SOURCE-CONFIRMED |
| App commit | exact tested Git SHA | Must be recorded per run |
| APK hash | SHA-256 of installed APK or locally built APK | Must be recorded per run |

Required identity commands, with the device attached and authorized:

```powershell
$adb = 'C:\Users\akaza\AppData\Local\Android\Sdk\platform-tools\adb.exe'
& $adb devices -l
& $adb -s <serial> shell getprop ro.product.manufacturer
& $adb -s <serial> shell getprop ro.product.model
& $adb -s <serial> shell getprop ro.build.version.release
& $adb -s <serial> shell getprop ro.build.version.sdk
& $adb -s <serial> shell getprop ro.product.cpu.abilist
& $adb -s <serial> shell dumpsys package net.pocvpn.client
git rev-parse HEAD
```

Stop if the model, Android version, ABI, package, installed version, or intended Git build cannot be reconciled. A historical device description is not current-run evidence.

## 3. Capture topology

Use at least one packet capture point and prefer two:

1. **Client-adjacent capture (preferred):** a controlled Wi-Fi access point/router captures the OPPO's traffic on the WAN-facing interface, filtered by the device's test IP/MAC. This sees pre-tunnel DNS and all establishment traffic without requiring Android root.
2. **Nova server capture (recommended second point):** `tcpdump` on the authorized Frankfurt/Stockholm host, filtered to the test device's public source IP and exact Nova service ports. This validates arrival timing and direction but cannot alone see failed DNS or traffic blocked before the server.
3. **Android on-device capture:** use only if an approved capture application/VpnService or rooted `tcpdump` is already available and does not conflict with Nova's own VpnService. Do not install an unreviewed capture VPN beside Nova.

The capture-point choice is part of every artifact record. Never describe a server-only trace as proof that no client-side DNS or failed packets occurred.

Recommended packet filter, narrowed further by the current test source address:

```text
host 152.70.43.1 or host 16.170.208.231 or
host 188.114.96.9 or host 188.114.97.9 or
port 53 or port 853 or port 443 or port 2053 or port 2083 or
port 51820 or port 28388
```

Cloudflare addresses must be resolved immediately before each XHTTP run; do not assume the two audit-day A records remain current.

## 4. Capture and redaction policy

### 4.1 Storage boundary

- Raw `pcap`/`pcapng`, full logcat, server logs, screenshots containing credentials, activation envelopes, and provisioning responses stay in an operator-controlled directory **outside every Git worktree**.
- Raw artifacts are not attached to a pull request, issue, chat, or public storage.
- Git may contain only this procedure and later sanitized aggregate tables or narrowly redacted text summaries.
- A retained artifact receives an ID and SHA-256 before analysis. Sanitization creates a separate artifact with its own ID/hash and a written transformation record; it never replaces the raw hash.
- Delete disposable local credential material after revocation and verification. Raw capture retention follows the project owner's security policy; this document does not authorize indefinite retention.

Suggested external layout:

```text
C:\NovaSensitiveEvidence\B47-1P\<run-id>\raw\
C:\NovaSensitiveEvidence\B47-1P\<run-id>\sanitized\
C:\NovaSensitiveEvidence\B47-1P\<run-id>\notes\
```

Before running, resolve the path and confirm it is outside `C:\Users\akaza\Downloads\VPN*` and outside all paths printed by `git worktree list`.

### 4.2 Prohibited Git content

Never commit:

- activation credentials or signed activation envelopes;
- VLESS UUIDs, REALITY private material, Shadowsocks secrets, API/bearer tokens, passwords, or private keys;
- raw Authorization headers or unredacted request/response bodies;
- raw captures merely renamed or compressed;
- server logs containing client identifiers or credentials;
- exact device-owner account data, unrelated device traffic, or third-party application traffic.

### 4.3 Sanitization rules

- Prefer derived packet metadata: timestamp offset, direction, length, IP protocol, destination tuple, TLS handshake fields, DNS qname/type/rcode, HTTP version/method/path when already visible to an authorized endpoint, and flow identifier.
- Replace public client source IP with `CLIENT_PUBLIC_IP`; retain Nova destination IPs because they are already public repository facts.
- Replace device serial with `OPPO_CPH2173_TEST_DEVICE` in committed summaries.
- Remove all payload bytes after extracting the minimum handshake fields needed for reproducibility.
- Do not publish TLS session secrets or use key logging unless separately authorized and protected as raw sensitive evidence.
- Review sanitized output manually for UUIDs, tokens, keys, Authorization headers, cookies, query parameters, and unrelated DNS names before Git staging.

## 5. Synchronization method

Each scenario uses one run ID:

```text
B47-1P-<UTC YYYYMMDDTHHMMSSZ>-<scenario>-R<repetition>
```

Required synchronization sequence:

1. Record workstation UTC (`Get-Date -AsUTC -Format o`).
2. Record device UTC and epoch through ADB (`date -u` and `date +%s%3N`; if milliseconds are unsupported, record seconds and note it).
3. Record authorized server UTC/epoch on every capture host.
4. Calculate and record device/workstation/server offsets. Stop if any clock differs by more than 500 ms unless packet correlation uses a documented offset correction.
5. Clear logcat only after identity/preflight is complete.
6. Start client-adjacent capture, then server capture, then logcat.
7. Write a synchronization marker to logcat containing only the run ID:

   ```powershell
   & $adb -s <serial> shell log -t B47_1P_SYNC <run-id>
   ```

8. Record the exact UTC time immediately before the UI action and immediately after the terminal app state.
9. Stop logcat and captures; hash every raw artifact without opening or rewriting it.
10. Export Nova's sanitized diagnostics, if the tested build supports it, and correlate its attempt records with the same run ID/timestamps. Never treat the diagnostics' hypothetical transport display as the active transport without service/TUN/log evidence.

## 6. Mandatory preflight and fail-closed gates

All gates must pass before a packet can support `MEASURED`:

```powershell
$adb = 'C:\Users\akaza\AppData\Local\Android\Sdk\platform-tools\adb.exe'
& $adb devices -l
& $adb -s <serial> get-state
& $adb -s <serial> shell pidof net.pocvpn.client
& $adb -s <serial> shell dumpsys connectivity
& $adb -s <serial> shell ip addr show
```

Additionally verify:

- only the intended OPPO is selected by explicit serial;
- USB debugging authorization is current;
- the capture point sees a harmless device-generated test flow;
- capture filters contain the test device and Nova endpoints only;
- sufficient disk space and correct UTC clocks;
- Nova is disconnected and no stale Nova/AWG/Xray/Shadowsocks service remains;
- the tested APK/commit and production profile state are documented;
- any failure injection is authorized, bounded, reversible, and has a rollback command recorded before execution;
- server capture filters use the known test source IP, not an unrestricted interface-wide capture;
- raw evidence directory is outside Git;
- disposable activation credentials, when needed, have an owner and revocation method.

If any item fails, mark the scenario `BLOCKED`, retain only non-sensitive preflight output if useful, and do not improvise around the gate.

## 7. Scenario matrix

| ID | Scenario | Minimum repetitions | Required capture points | Current status |
|---|---|---:|---|---|
| S00 | Disconnected baseline | 3 × 60 s | client-adjacent | NOT TESTED — device absent |
| S01 | AWG successful connect/idle/disconnect | 3 | client + Frankfurt/Stockholm server | NOT TESTED |
| S02 | AWG controlled failure -> REALITY | 5 | client + chosen gateway | NOT TESTED; highest priority |
| S03 | REALITY successful connection | 3 | client + chosen gateway | NOT TESTED |
| S04 | TLS/TCP successful connection | 3 | client + chosen gateway | NOT TESTED |
| S05 | Shadowsocks TCP/UDP | 3 each where authorized | client + Frankfurt | NOT TESTED |
| S06 | XHTTP/CDN | 3 | client + authorized origin/logs | NOT TESTED |
| S07 | Manifest retrieval: Frankfurt then Stockholm | 3 each | client + both gateways | NOT TESTED |
| S08 | Activation failure | 3 with non-secret invalid fixture | client + control plane | NOT TESTED |
| S09 | Activation success | 1–3 with disposable credential | client + control plane | NOT TESTED; credential required |
| S10 | DNS before/after each transport | paired with S00–S06 | client-adjacent | NOT TESTED |
| S11 | Idle, screen off/on, reconnect | 3 for AWG; 3 for one Xray path | client + server | NOT TESTED |

Do not average away repetitions. Retain one row per attempt and report median/range only in addition to individual results.

## 8. Evidence artifact table

No physical artifacts exist yet.

Every future artifact row must use this schema:

| Artifact ID | Scenario/run | Device / Android | App commit / APK SHA-256 | Network | UTC start/end | Capture point | Transport | SHA-256 | Sanitization | Git retention |
|---|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — | No artifacts in this preparation pass |

Artifact IDs distinguish roles, for example:

```text
...-CLIENT-PCAP-RAW
...-SERVER-PCAP-RAW
...-LOGCAT-RAW
...-DIAGNOSTICS-SANITIZED
...-PACKET-SUMMARY-SANITIZED
...-TLS-SUMMARY-SANITIZED
```

Hash on Windows:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '<absolute artifact path>'
```

Hash on an authorized Linux capture host:

```bash
sha256sum -- /var/lib/nova-audit/b47-1p/<run-id>/<artifact>
```

## 9. Baseline disconnected traffic procedure

For each S00 run:

1. Confirm no VPN interface/service using `dumpsys connectivity`, `dumpsys activity services net.pocvpn.client`, and `ip addr show`.
2. Force-stop Nova, wait 30 seconds, and capture a 60-second no-app baseline.
3. Launch Nova without connecting; capture 60 seconds.
4. Trigger one explicit manifest refresh only if the UI/current build exposes it; otherwise record that no explicit action exists.
5. Record DNS queries, destination tuples, flow starts, sizes, and cadence. Separate OS traffic from flows attributable to Nova by timestamps/server logs; do not infer attribution from proximity alone.

## 10. AWG measurements

For S01, record every packet from first outbound UDP to terminal connected state, at least 60 seconds idle, one small application flow, and disconnect. Required per-run fields:

- gateway and `UDP/51820` tuple;
- outbound/inbound packet timestamps and UDP payload/frame lengths;
- handshake packet sequence and time to first response;
- app state/log timestamps and active service/TUN evidence;
- first tunneled-data time;
- idle packet times and derived keepalive intervals;
- disconnect packet behavior;
- one bounded network-loss/recovery cycle in S11.

Do not identify encrypted AWG message semantics solely by length unless corroborated by the AWG server observation/log for that timestamp.

Current result: **NOT TESTED**.

## 11. Smart Connect fallback measurements

S02 is the priority scenario. Use an authorized reversible server-side failure affecting only the test peer or a narrowly scoped test endpoint. Do not change client timing/order. Do not block a shared production service or modify PR #99/B46 infrastructure.

For each of at least five repetitions:

1. Record the failure mechanism and proof it is active.
2. Start synchronized client/server/log capture.
3. Initiate one normal Smart Connect request.
4. Record first and last AWG packet, AWG packet count by direction, terminal AWG app state, first REALITY TCP SYN and ClientHello, gateway identity, all DNS between those events, and REALITY outcome.
5. Restore/verify the authorized failure boundary after the run; fully roll it back after the matrix.

Required timing rows:

| Run | First AWG packet UTC | Last AWG packet UTC | AWG packets out/in | AWG terminal-state UTC | First REALITY SYN UTC | First REALITY ClientHello UTC | First-AWG -> first-REALITY | Last-AWG -> first-REALITY | DNS between | Gateway change | Evidence IDs |
|---|---|---|---|---|---|---|---:|---:|---|---|---|
| R1–R5 | NOT TESTED | | | | | | | | | | |

Report each value, median, range, and standard deviation. A stable `~8 s` pattern is `MEASURED` only if packet and app evidence agree across the repetitions.

Current result: **NOT TESTED**.

## 12. REALITY TLS fingerprint

For S03 and the REALITY leg of S02, extract the complete observable ClientHello representation, not merely a hash:

- legacy/version fields and supported versions;
- cipher suites in wire order;
- extension types in wire order;
- GREASE positions/values normalized separately from raw evidence;
- supported groups and key-share groups;
- signature algorithms;
- SNI presence/value visibility;
- ALPN list/order;
- session identifier/ticket/PSK/resumption behavior;
- ClientHello length, TLS record segmentation, retransmission, and timing;
- destination tuple and connection reuse/reconnect behavior.

REALITY may alter what a generic TLS analyzer can decode. Record parser failures and raw handshake lengths instead of forcing a conventional-TLS interpretation.

Current result: **NOT TESTED**. The source-level `fingerprint=chrome` remains an intent, not wire evidence.

## 13. TLS/TCP fingerprint

For S04, collect the same ClientHello fields as section 12 plus:

- negotiated TLS version and ALPN where visible from client/server evidence;
- certificate chain/SAN only from public server data, never private key material;
- application-data record lengths/timestamps/directions;
- first-data latency, idle behavior, reconnect, and destination reuse;
- valid VLESS server acceptance correlated by authorized Xray logs.

Current result: **NOT TESTED**.

## 14. Shadowsocks observations

Run S05 only if the current signed binding, compatible binary, and an authorized valid credential are available. Never print, pass on argv, capture in screenshots, or commit the secret.

Record TCP and UDP separately: initial tuple/packet sequence, packet lengths/timing, first data, session duration, idle packets, reconnect, and server acceptance. Correlate the test source/time against the authorized Shadowsocks log without retaining authentication material.

Current result: **NOT TESTED**.

## 15. XHTTP / CDN observations

For S06:

1. Resolve `edge-sthlm.aknova.pp.ua` immediately before the run and record resolver, qname, qtype, answers, TTL, and chosen address.
2. Capture the app's real ClientHello, SNI, ALPN, TLS version, and destination.
3. Determine actual HTTP version from protocol/server evidence; do not infer h2 from the signed profile or `alt-svc`.
4. At the authorized Cloudflare/origin log boundary, record method, normalized path, header names/order only where the platform preserves order, request/response byte counts, status, connection/stream reuse, and cadence.
5. Measure query/body padding distributions over multiple requests without retaining UUIDs, tokens, or payload.
6. Record whether any UDP/443/QUIC flow occurs. Cloudflare advertising h3 is not usage.

Current result: **NOT TESTED**.

## 16. Manifest and control-plane observations

For S07–S09, record literal-IP versus DNS behavior, ClientHello fields, negotiated HTTP version, header names/order/User-Agent if visible at the authorized edge, connection reuse, route/method, request and response sizes, retry/origin order, and server timestamp/status.

Activation failure may use a clearly invalid non-secret fixture. Activation success requires a disposable test credential whose creation, owner, and revocation are documented outside Git. Start capture only after ensuring UI/logcat will not echo it. Revoke immediately after the successful scenario, verify revocation, and record only a non-secret revocation confirmation/time.

Current results:

- Manifest retrieval: **NOT TESTED**.
- Activation failure: **NOT TESTED**.
- Activation success: **NOT TESTED — disposable credential unavailable in this pass**.

## 17. DNS observations

For S00–S11, extract all DNS attributable to the device during the synchronized window:

- destination resolver IP/port/protocol (`UDP/53`, `TCP/53`, `TLS/853`, identifiable DoH only when endpoint/log evidence supports attribution);
- qname/qtype/rcode and timing;
- queries before establishment, during transport attempt, during fallback, after connected, and after disconnect;
- queries repeated after failure;
- literal-IP paths that cause no lookup;
- XHTTP/CDN lookup and cache/repetition behavior;
- differences across AWG, REALITY, TLS/TCP, Shadowsocks, and XHTTP.

Do not claim an absence of DNS from a server-side-only capture. Do not label arbitrary encrypted `443` traffic as DoH without corroboration.

Current result: **NOT TESTED**.

## 18. HTTP/2 observations

Where the actual Android/Xray connection negotiates h2, extract:

- client and server SETTINGS identifiers/values/order;
- SETTINGS acknowledgement timing;
- initial window and frame sizes;
- stream IDs, concurrency, reuse, multiplexing, GOAWAY, and connection lifetime;
- header names and ordering only at an authorized endpoint or from safely decrypted test traffic;
- request cadence and byte counts.

Desktop curl results from B47 are not Android HTTP/2 evidence.

Current result: **NOT TESTED**.

## 19. JA3 / JA4-style analysis

Compute diagnostics only from complete captured ClientHello data. Store the normalized input beside every hash:

```text
flow ID
raw ClientHello artifact ID/hash
TLS version inputs
cipher suite order
extension order
supported groups
EC point formats where applicable
ALPN/SNI and JA4-relevant fields
tool name and exact version
JA3 string + MD5 (diagnostic only)
JA4 string/hash (diagnostic only)
parser warnings/normalization choices
```

Calculate at least once with a scripted/CLI parser and independently confirm the underlying fields in Wireshark/tshark or an equivalent parser. GREASE normalization must be stated. A matching hash is not a security score, and a mismatch does not alone identify Nova.

Current result: **NOT TESTED — no ClientHello capture or parser tooling available**.

## 20. Idle, screen-off, and reconnect observations

For S11, after a verified connected state:

1. Capture 60 seconds screen-on idle.
2. Record `input keyevent 26` time and capture at least 120 seconds screen-off idle.
3. Wake/unlock using the owner's normal safe method; never record the device PIN.
4. Generate one small authorized data flow.
5. Perform one reversible network interruption and restoration appropriate to the scenario.
6. Record keepalive/reconnect packets, app states, service/TUN identity, recovery time, and whether the endpoint changed.

This is a bounded fingerprint sample, not a long-duration stability claim.

Current result: **NOT TESTED**.

## 21. Correlation against B47 predictions

| B47 prediction | Required physical evidence | Current disposition |
|---|---|---|
| AWG failure is followed by REALITY at an approximately 8-second boundary | S02 R1–R5 synchronized packet/app rows | NOT TESTED |
| AWG shows a 25-second keepalive regime | S01/S11 idle packet intervals plus server observation | NOT TESTED |
| Android platform TLS and Xray/uTLS produce distinguishable fingerprint families | S03/S04/S07 ClientHello comparisons | NOT TESTED |
| XHTTP uses static hostname/path/h2/POST/padding behavior | S06 client + authorized edge evidence | NOT TESTED |
| Direct bootstrap uses literal IP and matching origin behavior | S07 traces against both origins | NOT TESTED |
| XHTTP adds a recognizable DNS lookup during fallback/selection | S06/S10 synchronized DNS | NOT TESTED |
| Reconnect follows the bounded exponential family | S11 repeated interruption timings | NOT TESTED |

## 22. Confirmed and disproved findings

### Confirmed by this slice

None. Tool discovery and an empty ADB device list are environment preflight facts, not network fingerprint evidence.

### Disproved by this slice

None. No physical packet evidence was captured.

## 23. Remaining unknowns

All B47 physical unknowns remain open, including:

- real AWG packet lengths, handshake/keepalive/idle/disconnect cadence;
- real AWG failure-to-REALITY timing and stability;
- Android/Xray ClientHello, TLS fields, JA3/JA4-style diagnostics, records, and resumption;
- valid TLS/TCP, REALITY, Shadowsocks, and XHTTP session patterns;
- Android manifest/activation HTTP version, headers, reuse, sizes, and retry cadence;
- physical pre/post-VPN DNS and fallback DNS sequences;
- actual h2 SETTINGS/streams and any QUIC use;
- screen-off/reconnect traffic;
- synchronized server-log correlation.

## 24. Risk changes

No B47 risk rating changes are justified. The B47 source/endpoint findings remain the current baseline. This preparation pass neither confirms nor reduces them.

## 25. Recommended B47-2 scope

B47-2 should begin only after this matrix produces sanitized, hashed evidence. Its scope should be:

1. parse and compare Android platform TLS, REALITY, TLS/TCP, and XHTTP ClientHello/record behavior;
2. calculate JA3/JA4-style diagnostics with full normalized inputs;
3. quantify Smart Connect attempt timing and DNS sequences from at least five controlled AWG-failure repetitions;
4. analyze HTTP/2 SETTINGS, stream reuse, and header behavior where authorized evidence exists;
5. convert only capture-backed B47 inferences into measured findings and rerank risks if evidence warrants it.

Do not use this procedure-only preparation as input to fingerprint hardening.

## 26. Decision gate

**Decision: BLOCKED for physical evidence; procedure ready.**

The gate opens when:

- the OPPO CPH2173 is physically connected and authorized in ADB;
- a client-adjacent capture point or approved on-device capture method is available;
- authorized server capture/log access is available for the selected scenario;
- the exact APK/commit and test network are recorded;
- controlled AWG failure and rollback are approved;
- disposable test credentials and revocation are available for credentialed scenarios;
- raw evidence storage outside Git is prepared;
- a TLS/HTTP parser (`tshark`/Wireshark or equivalent) with recorded version is available.

Until then, B47 remains **AUDIT BASELINE COMPLETE; HARDENING NOT IMPLEMENTED**, and B47-1P must not be represented as physically complete.
