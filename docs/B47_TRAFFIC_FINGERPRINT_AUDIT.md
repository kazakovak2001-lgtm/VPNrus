# B47 — Traffic Fingerprint Audit

Audit date: 2026-09-21

Repository baseline: `origin/main` at `75cb4b2`

Audit branch: `research/b47-traffic-fingerprint-audit`

## 1. Executive summary

Nova's payload encryption does not make its current network behavior anonymous. The implemented paths expose stable destination, port, protocol, sequencing, HTTP, and infrastructure signals that can distinguish Nova traffic or correlate its ingress paths.

The strongest findings are:

1. **High — direct endpoints and fixed ports are stable classifiers.** The signed production manifest maps the same two public gateway IPs to fixed AWG (`UDP/51820`), REALITY (`TCP/2053`), TLS/TCP (`TCP/2083`), and (Frankfurt only) Shadowsocks 2022 (`TCP/UDP 28388`) bindings. A passive observer does not need to decrypt payloads to classify those tuples.
2. **High — Smart Connect creates a deterministic failure sequence.** Source fixes automatic preference order and the manual-mode failover to exactly `AWG -> REALITY`; AWG gets an 8-second handshake window before eligible failover. TLS/TCP, XHTTP, and Shadowsocks are not part of that manual-gateway fallback. Auto gateway mode advances a pre-ranked, bounded candidate list. Those sequences can be recognizable even when every payload is encrypted.
3. **High — bootstrap/control-plane traffic is conspicuous.** Release builds contain two literal-IP HTTPS manifest URLs. The live endpoints returned the same 1,840-byte manifest over HTTP/1.1 with matching nginx header shape. Activation, profile provisioning, manifest, and health routes share the same gateway HTTPS edge and certificate boundary.
4. **High — the CDN XHTTP path has stable public identifiers.** The signed profile fixes `edge-sthlm.aknova.pp.ua`, `/nova-xhttp/`, TLS 1.3 minimum, ALPN `h2`, a Chrome uTLS fingerprint, POST uplink, packet-up mode, query padding of 1–64 bytes, and Cloudflare. The live edge exposed Cloudflare headers and `alt-svc: h3=":443"`, while malformed GET/HEAD requests to the XHTTP path returned a stable empty `400` response.
5. **Medium — ingress families are correlatable.** Frankfurt services share `152.70.43.1`; Stockholm direct/control/origin services share `16.170.208.231`; the CDN hostname's DNS and headers disclose Cloudflare, while public DNS maps its control/origin names back to Stockholm. Both direct gateways showed closely matching nginx and transport-port behavior.

No production transport behavior was changed. Hysteria2 is **PENDING B46-3A** and was not tested or modified. This audit does not claim fingerprint hardening is implemented.

## 2. Scope

Included:

- AmneziaWG (AWG);
- Xray VLESS + REALITY;
- VLESS + TLS/TCP;
- Shadowsocks 2022;
- XHTTP and the deployed XHTTP/CDN path;
- bootstrap/control-plane HTTPS, manifest, activation, gateway reachability, and relay-health behavior;
- establishment/runtime DNS policy visible in source;
- Smart Connect and automatic candidate progression;
- Nova-owned Frankfurt, Stockholm, and Cloudflare-fronted ingress only;
- bounded unauthenticated and malformed requests to those owned endpoints.

Excluded:

- production configuration or credential changes;
- Internet-wide scanning;
- impersonation of third-party services;
- certificate, manifest-trust, activation-trust, VPN-runtime, or selection-policy changes;
- B46-3A implementation and runtime work;
- active-probing-resistance design (B48).

## 3. Evidence vocabulary

- **MEASURED** — observed during this audit with the command and environment stated.
- **SOURCE-CONFIRMED** — directly established by current repository code/configuration/tests.
- **INFERRED** — a reasoned consequence of measured or source-confirmed facts, not a packet observation.
- **NOT TESTED** — the environment could not produce the required evidence.

Confidence is `High`, `Medium`, or `Low`. `High` never upgrades an inference into a measurement.

## 4. Architecture and path inventory

| Path | Current wire target / shape | Evidence state |
|---|---|---|
| AWG Frankfurt | `152.70.43.1:51820/UDP` | SOURCE-CONFIRMED; malformed datagram behavior MEASURED |
| AWG Stockholm | `16.170.208.231:51820/UDP` | SOURCE-CONFIRMED; malformed datagram behavior MEASURED |
| VLESS + REALITY | gateway IP `:2053/TCP`, Xray `tcp` + `reality`, configured uTLS fingerprint | SOURCE-CONFIRMED; generic TLS/malformed behavior MEASURED |
| VLESS + TLS/TCP | gateway IP `:2083/TCP`, Xray `tcp` + `tls`, certificate validation enabled | SOURCE-CONFIRMED; generic TLS/HTTP behavior MEASURED |
| Shadowsocks 2022 | Frankfurt `:28388`, `2022-blake3-aes-256-gcm` | SOURCE-CONFIRMED; malformed TCP behavior MEASURED |
| XHTTP/CDN | `edge-sthlm.aknova.pp.ua:443`, `/nova-xhttp/`, Cloudflare to Stockholm origin | SOURCE-CONFIRMED and partially MEASURED |
| Manifest | `GET https://152.70.43.1/v1/manifest`, then `16.170.208.231` on origin failure | SOURCE-CONFIRMED and MEASURED |
| Activation | `POST /v1/activate` on the selected control-plane origin | SOURCE-CONFIRMED; valid activation NOT TESTED |
| Profile provisioning | fixed `/v1/xray-profile`, `/v1/xray-tls-profile`, and ingress routes on the same HTTPS edge | SOURCE-CONFIRMED; credentials intentionally not used |
| Gateway restriction probe | bare unauthenticated `HEAD https://152.70.43.1`, 4 s bound | SOURCE-CONFIRMED; equivalent root response MEASURED with curl |
| Diverse restriction probes | HEAD requests to Google, Apple, and Mozilla connectivity endpoints | SOURCE-CONFIRMED; not exercised in this audit because they are not Nova-owned |
| Relay readiness/runtime health | Xray-native delay measurement to the exit's `/v1/manifest`; relayed watchdog reuses it | SOURCE-CONFIRMED; on-device cadence NOT TESTED |
| Hysteria2 | production integration | **PENDING B46-3A**; NOT TESTED |

Transport ordinals and addresses come from `gateway/tools/production_manifest_2026-09-20_v4.json`. Runtime behavior comes from the Android composition, selection, renderer, and controller sources cited in the evidence table.

## 5. Threat and observer model

The audit considers:

- a local network, ISP, transit, or hosting observer that sees packet timing, sizes, directions, destination tuples, DNS, and unencrypted handshake metadata;
- a CDN or ingress operator that sees termination-side TLS/HTTP metadata;
- a bounded active observer that connects to known Nova-owned endpoints without valid credentials;
- a correlating observer that combines public DNS, certificate, IP/ASN, port, and response behavior.

It does not assume the observer can decrypt properly configured TLS, REALITY, AWG, or Shadowsocks payloads. It also does not treat encryption as hiding endpoints, timing, sizes, protocol families, or deterministic fallback.

## 6. Measurement methodology

### 6.1 Source inspection

The audit inspected the signed production manifest, Android transport renderers, Smart Connect/failover code, reconnect policy, DNS/VPN builder policy, control-plane fetch/provisioning code, nginx edge configs, ingress configs, and prior physical-validation documents.

### 6.2 Live bounded probes

Executed from a Windows host in Prague on 2026-09-21:

```text
Resolve-DnsName <Nova hostname> -Type A
curl.exe --connect-timeout 5 --max-time 10 --request <method> --dump-header - <Nova URL>
curl.exe -k --verbose --connect-timeout 4 --max-time 7 https://<Nova IP>:2053/
python socket probes with a 3-second timeout to the manifest-listed Nova ports
```

`-k` was used only to observe how the known REALITY listener handled a generic non-REALITY TLS/HTTP client after ordinary certificate verification correctly rejected the name. Results from that command are not certificate-trust evidence.

Only the exact endpoints and ports in Nova's tracked production manifest/configuration were contacted. No credential was supplied, no high-rate test was run, and no host range was scanned.

### 6.3 Tool limitations

Available: repository source, `curl.exe`, DNS resolver, Python sockets.

Unavailable: `adb`, Android device, `tcpdump`, Wireshark/`tshark`, `dumpcap`, OpenSSL, server SSH/logs, QUIC analysis tooling.

Consequently, this audit did **not** measure Android ClientHello bytes, JA3/JA4, HTTP/2 SETTINGS, Xray packet distributions, AWG handshake packets, DNS packets on a real device, session resumption, or Smart Connect wall-clock traces.

## 7. Per-transport findings

### 7.1 AmneziaWG / AWG

**SOURCE-CONFIRMED (High):** Both gateways use fixed `UDP/51820`. The client uses persistent keepalive 25 seconds and the controller allows 8 seconds for a fresh handshake, polling at 500 ms. AWG protocol recovery is handled by the underlying implementation; app reconnect waits for a fresh handshake rather than redialing a new transport.

**MEASURED (High):** One malformed UDP datagram to each manifest-listed `51820` endpoint produced no response within 3 seconds. This is only malformed-input behavior, not proof of indistinguishability or probing resistance.

**INFERRED (High):** Repeated traffic to two stable IPs on `UDP/51820`, a 25-second keepalive regime, and an approximately 8-second failed-attempt boundary can form a strong metadata classifier. Actual packet sizes and handshake signatures remain NOT TESTED.

### 7.2 Xray VLESS + REALITY

**SOURCE-CONFIRMED (High):** The renderer fixes `network=tcp`, `security=reality`, and carries a configured uTLS `fingerprint`, server name, public key, short ID, and VLESS flow. Production uses `TCP/2053` on both gateway IPs.

**MEASURED (High):** TCP connected to both `:2053` listeners. A generic verified HTTPS attempt failed the name/certificate check. With verification disabled solely for behavior observation, both listeners negotiated the offered HTTP/1.1 ALPN and returned `HTTP/1.1 400 Bad request` to `GET /`. Raw malformed plaintext was closed with EOF (Frankfurt about 47 ms; Stockholm about 125 ms in this single run).

**INFERRED (Medium):** Identical port and similar invalid-client behavior correlate the two deployments. Whether a valid REALITY ClientHello matches the selected browser fingerprint closely enough to evade a sophisticated classifier is NOT TESTED; the configured label alone is not measurement.

### 7.3 VLESS + TLS/TCP

**SOURCE-CONFIRMED (High):** The renderer fixes `network=tcp`, `security=tls`, configured server name/fingerprint, and `allowInsecure=false`. Production uses `TCP/2083` on both gateway IPs.

**MEASURED (High):** Both listeners completed TLS with the audit curl client, accepted its offered HTTP/1.1 ALPN, and closed after an unexpected `GET /` with an empty reply. Raw malformed plaintext closed with EOF (about 47 ms Frankfurt and 94 ms Stockholm in this single run).

**INFERRED (High):** Fixed nonstandard port `2083`, destination reuse, and matching invalid-input behavior are useful classifiers even if the ClientHello imitates a common browser. Valid VLESS record sizes/cadence and the real Android/Xray ClientHello are NOT TESTED.

### 7.4 Shadowsocks 2022

**SOURCE-CONFIRMED (High):** The current signed manifest advertises Frankfurt only at port `28388` with `2022-blake3-aes-256-gcm`. Selection also requires a trusted endpoint binding, stored credential, compatible ABI, and native binary.

**MEASURED (High):** TCP connected to `152.70.43.1:28388`; a short malformed plaintext payload caused a reset in about 46 ms in one run.

**INFERRED (Medium):** A stable Frankfurt-only port plus prompt malformed-input reset is distinguishable from the other Nova listeners. Valid TCP/UDP Shadowsocks packet sizes, replay behavior, salts, and session duration are NOT TESTED.

### 7.5 XHTTP and XHTTP/CDN

**SOURCE-CONFIRMED (High):** The signed CDN profile fixes:

- hostname/SNI/Host: `edge-sthlm.aknova.pp.ua`;
- path: `/nova-xhttp/`;
- port: `443`;
- TLS minimum: 1.3;
- ALPN: `h2`;
- client fingerprint: `chrome`;
- mode: `packet-up`;
- uplink method: `POST`;
- query padding: 1–64 bytes with repeat-`x` obfuscation;
- per-POST maximum body: 524,288 bytes;
- cache bypass and streaming requirements;
- Cloudflare ASN 13335 and Frankfurt as the supported exit.

**MEASURED (High):** DNS returned Cloudflare anycast A records `188.114.97.9` and `188.114.96.9`; the audit connection used Cloudflare IPv6 `2a06:98c1:3120::9`. `GET /` returned a 146-byte `404` with Cloudflare headers. `GET /nova-xhttp/` returned an empty `400`, and `HEAD` returned the same status/header family. Responses included `Server: cloudflare`, `cf-cache-status: DYNAMIC`, `CF-RAY`, NEL/Report-To, and `alt-svc: h3=":443"`.

**INFERRED (High):** The domain, static path, h2-only signed policy, method, and small bounded query padding are stable application-level identifiers at the CDN. Cloudflare's advertised HTTP/3 does not prove Nova uses QUIC: the signed Nova policy explicitly requires `h2`.

## 8. TLS findings

### 8.1 What is source-confirmed

- Xray REALITY, TLS/TCP, and XHTTP explicitly request a named uTLS fingerprint.
- XHTTP fixes minimum TLS 1.3 and ALPN `h2`.
- Direct control-plane `HttpsURLConnection` uses Android platform defaults, normal CA validation, and literal-IP URLs for manifest/reachability.
- Gateway nginx permits TLS 1.2 and 1.3 and serves an IP-address certificate.
- The same gateway HTTPS edge serves multiple bootstrap/provisioning routes.

### 8.2 What was measured

- Both direct `/v1/manifest` endpoints completed verified TLS successfully with the audit host.
- Audit-host curl negotiated HTTP/1.1; this is a measurement of the audit client/server pair, **not** Android.
- Both TLS/TCP listeners accepted the audit curl client's HTTP/1.1 ALPN and then closed on unexpected HTTP.
- Both REALITY ports exposed matching generic-client `400 Bad request` behavior when verification was bypassed for this bounded diagnostic.

### 8.3 What remains unknown

**NOT TESTED:** Android/Xray ClientHello bytes, TLS versions actually negotiated by Android, cipher-suite list and order, extension order, supported groups, signature algorithms, GREASE, session tickets/resumption, record fragmentation, JA3, JA4, and stability across Android/API/core versions.

The configured word `chrome` must not be reported as a measured Chrome fingerprint. It is a source-level intent that needs a device capture.

## 9. HTTP findings

**MEASURED (High):** Both direct manifest origins returned:

```text
HTTP/1.1 200 OK
Server: nginx
Content-Type: application/octet-stream
Content-Length: 1840
Connection: keep-alive
```

`POST /v1/manifest` on Frankfurt returned a 146-byte nginx `403`. `HEAD /` on both gateways returned matching `404`, `Content-Length: 146`, and nginx headers. The HEAD probes timed out waiting for a body the response metadata said existed; this appears to be audit-client/server method behavior and was not reproduced on Android.

**SOURCE-CONFIRMED (High):** The app's reachability probe is a bare `HEAD` with no body, auth header, redirects, or custom User-Agent. Manifest is a bounded GET. Activation/profile operations use stable route names and JSON. Nginx restricts methods and exposes a narrow, repeatable route set. Manifest multi-origin refresh tries configured origins in order.

**INFERRED (High):** Stable paths, methods, response lengths, literal-IP Host/SNI behavior, origin order, and shared nginx response templates make bootstrap traffic classifiable and allow the two gateways to be correlated.

**NOT TESTED:** Android header set/order, platform User-Agent, connection reuse, Android HTTP/2 support/SETTINGS, stream concurrency, actual activation request/response sizes, production retry cadence, or valid XHTTP request cadence.

## 10. QUIC / HTTP/3 findings

**SOURCE-CONFIRMED (High):** Nova's current XHTTP profile requires ALPN `h2`, not `h3`. `TransportKind.QUIC` remains a roadmap/foundation concept. Hysteria2 production integration is **PENDING B46-3A**.

**MEASURED (High):** Cloudflare advertised `alt-svc: h3=":443"` on the CDN edge.

**INFERRED (High):** The advertisement alone does not mean Nova sends QUIC. No currently audited production Nova client path was shown to use HTTP/3.

**NOT TESTED:** QUIC versions, connection IDs, transport parameters, Retry, handshake packets, idle timeout, packet sizes, and migration behavior.

## 11. DNS findings

**SOURCE-CONFIRMED (High):** Before the VPN is established, hostname resolution necessarily uses the device's underlying network. The two default manifest origins and direct gateway transports use literal IPs, so those normal paths do not require DNS. The XHTTP/CDN path requires lookup of `edge-sthlm.aknova.pp.ua`. Xray TUN configurations set DNS servers `1.1.1.1` and `8.8.8.8`; prior AWG validation documents `1.1.1.1` and `1.0.0.1` for that path. Nova excludes its own package from the Xray VPN to avoid recursion.

**MEASURED (High):** Public DNS results were:

- `edge-sthlm.aknova.pp.ua` -> `188.114.97.9`, `188.114.96.9` (Cloudflare);
- `control.aknova.pp.ua` -> `16.170.208.231`;
- `origin-sthlm.aknova.pp.ua` -> `16.170.208.231`.

**INFERRED (High):** Direct AWG/REALITY/TLS and manifest bootstrap avoid hostname-query leakage but reveal literal destination IPs directly. Selecting XHTTP exposes a distinctive CDN hostname lookup before the tunnel unless cached/encrypted by the underlying resolver. A deterministic fallback from direct IP transports to XHTTP could therefore add a recognizable late DNS query.

**NOT TESTED:** Real Android pre/post-establishment DNS packets, Private DNS/DoT interaction, cache state, failed-query repetition, resolver selection per carrier/Wi-Fi, split-tunnel DNS, and per-transport fallback DNS sequences.

## 12. Smart Connect and fallback fingerprint

**SOURCE-CONFIRMED (High):** `SmartConnectDecisionEngine.PREFERRED_ORDER` is deterministic:

```text
AWG -> QUIC -> REALITY -> XHTTP -> TLS/TCP -> Shadowsocks 2022
```

Only available candidates participate. In manual managed-gateway mode, current automatic failover is narrower:

```text
AWG attempt
  -> eligible terminal handshake/backend failure
  -> disconnect AWG
  -> one REALITY attempt
  -> stop; no TLS/XHTTP/Shadowsocks fallback
```

Manual user pinning disables substitution. AWG receives an 8-second fresh-handshake window. Network-loss recovery uses up to eight attempts with exponential delays based at 1, 2, 4, 8, 16, and capped 30 seconds, plus up to 20% positive jitter. Auto gateway mode walks a deterministic pre-ranked candidate list and does not retry the same candidate within that attempt budget; a failed relayed candidate advances to the next ranked candidate.

**INFERRED (High):** A watcher can potentially recognize an AWG `UDP/51820` burst followed about eight seconds later by REALITY `TCP/2053` to the same IP. The exact Auto sequence depends on manifest availability, local credentials, health/history scores, and gateway mode, but is deterministic for a fixed state. Jitter reduces exact reconnect periodicity but does not hide the capped exponential family.

**NOT TESTED:** A real Android packet/time trace of success, AWG timeout -> REALITY, multi-gateway Auto progression, XHTTP fallback, restriction-class changes, or reconnect exhaustion.

## 13. Server / ingress correlation

| Correlation signal | Finding | Class |
|---|---|---|
| Shared IP | All Frankfurt direct transports and HTTPS share `152.70.43.1`; Stockholm direct transports, control, origin, and HTTPS share `16.170.208.231`. | SOURCE-CONFIRMED |
| Fixed ports | Both gateways use `51820`, `2053`, and `2083`; Frankfurt adds `28388`. | SOURCE-CONFIRMED / TCP reachability MEASURED |
| HTTP response shape | Both manifest origins returned the same 1,840-byte body size and matching nginx headers; both roots returned matching 146-byte nginx 404 metadata. | MEASURED |
| Invalid transport behavior | `2053` returned matching generic-client 400 behavior; `2083` closed after unexpected HTTP; plaintext closed promptly on both. | MEASURED |
| DNS linkage | CDN edge resolves to Cloudflare; its published control/origin names resolve to the Stockholm IP. | MEASURED |
| CDN/provider metadata | Signed profile names Cloudflare ASN 13335 and the origin/control hostnames. | SOURCE-CONFIRMED |
| Certificates | Control-plane routes on each IP share that IP vhost's certificate. Cross-host certificate equality/SAN inventory was not extracted. | SOURCE-CONFIRMED / NOT TESTED |
| ASN concentration | Two direct providers are intentionally diverse (Oracle Frankfurt, AWS Stockholm), while CDN is Cloudflare. Current live ASN lookup was not performed. | SOURCE-CONFIRMED / NOT TESTED |

The combined signal makes Nova-owned services readily correlatable. Provider diversity is useful for availability but is not anonymity.

## 14. Active connection behavior

| Input | Endpoint | Observation | Evidence |
|---|---|---|---|
| Valid manifest GET | both gateway `:443` | 200, 1,840 bytes, octet-stream, nginx, HTTP/1.1 | MEASURED |
| Unexpected manifest POST | Frankfurt `:443` | 403, 146-byte nginx body | MEASURED |
| Unknown root HEAD | both gateway `:443` | 404 metadata, 146-byte declared body | MEASURED |
| Generic HTTPS GET | both REALITY `:2053` | verified request rejected name; diagnostic `-k` request got 400 | MEASURED |
| Generic HTTPS GET | both TLS/VLESS `:2083` | TLS/ALPN completed, then empty reply | MEASURED |
| Malformed plaintext | both `:2053` and `:2083` | prompt EOF | MEASURED, single sample |
| Malformed plaintext | Frankfurt Shadowsocks `:28388` | prompt reset | MEASURED, single sample |
| Malformed datagram | both AWG `:51820/UDP` | no response within 3 seconds | MEASURED, single sample |
| Unexpected GET/HEAD | CDN `/nova-xhttp/` | empty 400 with Cloudflare and no-store headers | MEASURED |
| Valid credential | VLESS/REALITY/TLS/SS/XHTTP/activation | not attempted; no audit credential used | NOT TESTED |
| Premature disconnect | transport listeners | socket close occurred, but server-side/log effect unavailable | NOT TESTED |

These observations are fingerprint inputs, not a B48 active-probing-resistance verdict.

## 15. Android-specific findings

**SOURCE-CONFIRMED (High):** Android platform `HttpsURLConnection` is used for manifest and gateway reachability, while Xray's pinned native core produces REALITY/TLS/XHTTP handshakes. These two TLS stacks need separate capture baselines. Xray VPN setup applies explicit DNS servers, excludes Nova itself, routes IPv4 through the TUN, and omits IPv6 configuration so Android blocks that family for the Xray path. AWG uses a separate native backend and its own protocol timers.

**INFERRED (High):** One Nova session may therefore expose more than one client fingerprint family: Android platform TLS for pre-tunnel control plane and Xray/uTLS for the data transport. A fallback can reveal the transition between them.

**NOT TESTED:** OEM/API variation, Android platform User-Agent, ClientHello, IPv6 DNS behavior, captive-portal interaction, cellular/Wi-Fi handover trace, background/Doze timers, and physical Smart Connect sequence. No `adb` or physical device was available.

## 16. Consolidated evidence table

| ID | Component/path | Finding | Class | Evidence source / reproduction | Confidence | Practical significance |
|---|---|---|---|---|---|---|
| E01 | Production endpoints | Fixed gateway IP/port matrix | SOURCE-CONFIRMED | production manifest v4 | High | Strong passive classifier |
| E02 | Manifest | Both origins returned 200 and 1,840 bytes with matching nginx headers | MEASURED | bounded curl GET | High | Correlates control planes |
| E03 | Gateway probe | Bare HEAD to literal Frankfurt IP, 4 s timeout | SOURCE-CONFIRMED | `GatewayReachabilityProbe.kt` | High | Stable pre-connect event |
| E04 | Smart Connect | Preferred order deterministic | SOURCE-CONFIRMED | `SmartConnectDecisionEngine.kt` | High | Stable attempt sequence |
| E05 | Manual fallback | Only eligible AWG failure -> one REALITY attempt | SOURCE-CONFIRMED | `AwgXrayFailoverPolicy.kt`, `MainViewModel.kt` | High | Recognizable UDP-to-TCP transition |
| E06 | AWG timing | 8 s handshake window, 500 ms polling, 25 s keepalive | SOURCE-CONFIRMED | `VpnController.kt`, AWG profile | High | Timing classifier |
| E07 | Reconnect | Exponential capped backoff with 0–20% positive jitter | SOURCE-CONFIRMED | `ReconnectManager.kt` | High | Retry family still recognizable |
| E08 | REALITY | Both `2053` listeners connected; generic client got matching 400/EOF behavior | MEASURED | curl/socket probes | High | Cross-site correlation signal |
| E09 | TLS/TCP | Both `2083` listeners accepted TLS/HTTP1 ALPN, then empty reply | MEASURED | curl probes | High | Nonstandard-port classifier |
| E10 | Shadowsocks | Frankfurt `28388` reset malformed TCP promptly | MEASURED | one bounded socket probe | Medium | Active fingerprint input |
| E11 | XHTTP profile | Static domain/path/h2/Chrome/POST/padding profile | SOURCE-CONFIRMED | signed manifest metadata, renderer | High | Stable CDN-visible signature |
| E12 | XHTTP edge | Cloudflare DNS/headers, path 400, h3 advertisement | MEASURED | DNS + curl | High | Identifies provider/path; not proof of QUIC use |
| E13 | DNS | Direct paths use literal IPs; XHTTP requires public hostname lookup | SOURCE-CONFIRMED / INFERRED | build config, manifest | High | Different transports expose different DNS behavior |
| E14 | Runtime DNS | Xray TUN declares `1.1.1.1`, `8.8.8.8` | SOURCE-CONFIRMED | Xray config/builder source | High | Resolver choice can fingerprint sessions |
| E15 | Android TLS | Actual ClientHello/JA3/JA4 unknown | NOT TESTED | no adb/capture tooling | High | Blocks claims about browser mimicry |
| E16 | QUIC | Cloudflare advertises h3; Nova XHTTP requires h2 | MEASURED / SOURCE-CONFIRMED | curl headers/profile | High | Do not misclassify advertisement as usage |
| E17 | Hysteria2 | Production integration pending B46-3A | NOT TESTED | roadmap/PR boundary | High | Must be revisited after B46-3A |

## 17. Risk register

### Critical

None established by the available evidence. This does not mean none exist; full device captures were unavailable.

### High

1. Fixed gateway IP/port tuples make direct transports easily classifiable and blockable.
2. Deterministic AWG-first selection and AWG-to-REALITY failure transition can fingerprint Smart Connect.
3. Literal-IP bootstrap/control-plane URLs and matching responses correlate both gateways and disclose Nova control-plane contact.
4. Static XHTTP hostname/path/ALPN/method/padding policy gives the CDN and path observer a stable signature.
5. Co-location of transport and control-plane services on shared IPs enables inexpensive cross-correlation.

### Medium

1. Matching invalid-input behavior across Frankfurt and Stockholm strengthens active correlation.
2. Fixed resolver choices may distinguish established Nova tunnels and differ between AWG and Xray paths.
3. Platform TLS for control plane plus Xray/uTLS for transport can reveal a two-stack sequence.
4. Exponential reconnect with bounded jitter remains structurally recognizable.

### Low

1. nginx and Cloudflare product headers reveal infrastructure but are common on the wider Internet.
2. Stable manifest length helps correlation, but will change when signed manifest contents change.

### Informational

1. Cloudflare advertises HTTP/3 even though Nova's signed XHTTP profile uses h2.
2. Malformed AWG datagrams received no reply in one bounded sample.
3. The generic audit curl fingerprint is not representative of Android or Xray.

## 18. Remediation candidates (not implemented)

Candidates must be validated against reliability, compatibility, and trust boundaries before implementation:

1. Add an Android capture harness that records sanitized packet metadata and TLS/HTTP handshake summaries for each transport without logging credentials.
2. Introduce test-only deterministic markers that align app attempt events with packet captures, enabling exact Smart Connect sequence/timing measurement.
3. Evaluate whether bootstrap/control-plane origin concentration can be reduced without weakening manifest or activation trust.
4. Review whether route names, error templates, and response-size parity expose unnecessary correlation; preserve explicit failure and operational debuggability.
5. Measure XHTTP path/method/padding distributions under real traffic before considering any profile variation. Do not randomize blindly.
6. Capture and compare platform TLS and Xray/uTLS across supported Android versions; treat JA3/JA4 as diagnostics, not optimization targets.
7. Measure resolver behavior with Android Private DNS on/off and every transport/fallback combination before changing DNS policy.
8. Feed only measured active-probe observations into B48; avoid protocol mimicry claims unsupported by capture evidence.

## 19. Explicit unknowns

- Android ClientHello, JA3/JA4, cipher/extension order, resumption, and record behavior;
- valid-session packet sizes, bursts, idle traffic, duration, and direction ratios for every transport;
- AWG handshake/keepalive packet-level distribution;
- valid REALITY, TLS/TCP, Shadowsocks, and XHTTP credential behavior;
- HTTP request headers/order/User-Agent and HTTP/2 SETTINGS from the actual app/core;
- QUIC/HTTP3 use and parameters (no current use shown);
- physical DNS leakage and fallback-triggered query sequences;
- real Smart Connect wall-clock sequences under each failure class;
- server-side logs and connection resource behavior after malformed/premature input;
- current certificate SAN/fingerprint reuse across every ingress;
- ASN/BGP concentration beyond tracked provider metadata;
- Hysteria2 production fingerprint, pending B46-3A.

## 20. Dependencies on B46, B48, and B49

- **B46 / B46-3A:** Hysteria2 is explicitly pending. Re-run this audit after production integration using an authorized device and endpoint. This B47 slice did not touch B46-3A files or runtime.
- **B48:** Owns deeper active-probing-resistance analysis and any behavior changes. B47 supplies bounded baseline observations only.
- **B49:** Should consume measured compatibility/fingerprint trade-offs and define validation gates before any camouflage or transport-profile change is shipped.

## 21. Recommended next B47 implementation slices

1. **B47-1P — Android capture baseline (recommended next).** Physical device + authorized endpoints; capture each direct transport, XHTTP/CDN, manifest, activation failure/success in a test account, gateway probe, DNS, and Smart Connect failure paths. Produce pcap hashes and sanitized summaries, not captured credentials.
2. **B47-2 — TLS/HTTP parser report.** Extract ClientHello, ALPN, JA3/JA4-style diagnostics, TLS records, HTTP version/headers, h2 SETTINGS, and connection reuse from B47-1P captures.
3. **B47-3 — Smart Connect timing matrix.** Force bounded failure classes and quantify attempt order, inter-attempt gap, retry distribution, leftover traffic, and DNS sequence.
4. **B47-4 — Server-log correlation.** Correlate the same test run with authorized nginx/Xray/AWG/Shadowsocks/Cloudflare logs and certificate inventory.
5. **B47-5 — Hysteria2 addendum.** Only after B46-3A merges and production integration is available.

## 22. Decision gate

**Decision: audit baseline complete; fingerprint hardening is NOT IMPLEMENTED.**

Proceed to B47-1P only when all of the following are available:

- a physical Android device representative of the supported fleet;
- `adb` and packet capture on an authorized observation point;
- test credentials that may be captured and revoked;
- synchronized app diagnostics and server logs;
- explicit capture handling/redaction rules.

Do not change Smart Connect order, transport profiles, TLS fingerprints, XHTTP padding, DNS, certificates, or gateway behavior based solely on this source audit and single-host probes. Require packet evidence first.

## 23. B47-1P execution status

The deterministic physical-capture procedure is prepared in [`B47_1P_ANDROID_PACKET_CAPTURE_BASELINE.md`](B47_1P_ANDROID_PACKET_CAPTURE_BASELINE.md). On 2026-09-21, ADB was available but reported no attached device, and the workstation had no Wireshark, `tshark`, `dumpcap`, or `tcpdump`. No physical capture was performed, no B47 inference was promoted to `MEASURED`, and no risk rating changed. B47-1P remains blocked until the documented device, capture-point, credential, synchronization, and parsing gates are satisfied.
