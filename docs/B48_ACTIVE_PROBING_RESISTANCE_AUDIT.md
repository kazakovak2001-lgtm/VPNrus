# B48 — Active-Probing Resistance Audit

Audit date: 2026-09-21

Repository baseline: `origin/main` at `75cb4b249da24dc5d13197b0cc016147d79e0a81`

Branch: `research/b48-active-probing-resistance-audit`

## 1. Executive summary

Nova's audited production endpoints generally fail closed at their authentication boundaries. This audit did not obtain protected data without credentials, observe a remote crash, expose a secret, or measure a missing-versus-invalid credential oracle. The control-plane routes returned the same `401` status and byte-identical 25-byte JSON body for missing and deliberately invalid bearer credentials on both gateways.

Active behavior is nevertheless distinguishable:

1. **Medium — REALITY exposes a strong cross-gateway fallback oracle.** Both `TCP/2053` listeners completed a generic TLS 1.3 handshake with the same fallback certificate SHA-256 and returned the same 90-byte HAProxy `400 Bad request` body/header family. The two responses differed only in an upstream cache-node header. This strongly correlates the gateways and distinguishes REALITY from Nova's TLS/VLESS listeners.
2. **Medium — transport families have stable invalid-input signatures.** The same malformed TLS record elicited fatal `unexpected_message` from both REALITY listeners, fatal `internal_error` from both TLS/VLESS listeners, and a reset from Shadowsocks. Idle TCP sockets remained open for the bounded 2.5-second observation.
3. **Medium — XHTTP has a public path oracle.** At Cloudflare, `/nova-xhttp/` returned an empty `400` for GET/HEAD/POST, while a nonexistent path returned a 146-byte nginx `404`; OPTIONS on the expected path returned `403`. Repeated expected-path GETs returned the same empty `400`. Direct-to-origin requests with the expected SNI/Host were rejected `403`, confirming the configured CDN-source boundary was active.
4. **Low — control-plane validation errors are intentionally granular.** Minimal malformed JSON, malformed structure, and wrong content type produce distinct JSON error codes before credential validity is checked. This fingerprints the API parser but did not disclose credential existence.
5. **Low — implementation banners remain visible.** Responses disclose nginx, Cloudflare, and HAProxy product names, though nginx versions are suppressed. No internal path, stack trace, raw token, UUID, private key, or storage path was observed in live responses.
6. **Informational — deployment exposure differed from the signed inventory.** `16.170.208.231:2093`, advertised as the Stockholm direct REALITY ingress, refused all four bounded TCP input classes during this audit. This is a point-in-time reachability observation, not proof that the service is permanently absent.

This is an audit, not hardening. No production behavior, credentials, topology, transport, authentication, or trust logic changed. Hysteria2 runtime probing is **PENDING B46-3A**.

## 2. Scope and authorization boundary

Probed only source-confirmed Nova-owned endpoints:

- Frankfurt/Oracle: `152.70.43.1`;
- Stockholm/AWS: `16.170.208.231`;
- Nova's Cloudflare hostname: `edge-sthlm.aknova.pp.ua`;
- the Stockholm origin at `16.170.208.231`, using the source-confirmed XHTTP SNI/Host through curl `--resolve`.

The audit sent only short deterministic inputs, at low count, to manifest/configured ports and routes. It did not scan address ranges, guess keys, enumerate credentials, use real-user material, trigger sustained rate limits, test configured maximum body sizes live, or attempt resource exhaustion.

No server SSH or log access was used. Findings about server logging are `SOURCE-CONFIRMED`, not live log observations.

## 3. Evidence vocabulary

- **MEASURED:** observed in this audit from the client side.
- **SOURCE-CONFIRMED:** established directly by current tracked code/configuration/tests.
- **INFERRED:** reasoned consequence, not directly observed.
- **NOT TESTED:** evidence was unavailable or the test would exceed the authorized/safe boundary.

Confidence does not change an evidence class.

## 4. Endpoint exposure inventory

| Endpoint class | Address | Protocol / expected protocol | Authentication | Owner | Expected unauthenticated behavior | Environment / authorization | Audit exposure |
|---|---|---|---|---|---|---|---|
| AWG Frankfurt | `152.70.43.1:51820/UDP` | AmneziaWG | cryptographic peer key during protocol | `awg-poc.service` | silently discard invalid datagrams | production / authorized | reachable; no replies to bounded invalid input |
| AWG Stockholm | `16.170.208.231:51820/UDP` | AmneziaWG | cryptographic peer key during protocol | AWG service | silently discard invalid datagrams | production / authorized | reachable; no replies to bounded invalid input |
| REALITY Frankfurt | `152.70.43.1:2053/TCP` | VLESS + REALITY | REALITY/VLESS during handshake/session | Xray | non-REALITY TLS falls through to configured camouflage destination | production / authorized listener | reachable |
| REALITY Stockholm | `16.170.208.231:2053/TCP` | VLESS + REALITY | REALITY/VLESS during handshake/session | Xray | same design | production / authorized listener | reachable |
| TLS/VLESS Frankfurt | `152.70.43.1:2083/TCP` | TLS 1.2/1.3 + VLESS | TLS first, VLESS UUID after handshake | Xray | TLS may complete; invalid/non-VLESS application data rejected/closed | production / authorized | reachable |
| TLS/VLESS Stockholm | `16.170.208.231:2083/TCP` | TLS + VLESS | same | Xray | same | production / authorized | reachable |
| Shadowsocks Frankfurt | `152.70.43.1:28388/TCP+UDP` | Shadowsocks 2022 AES-256-GCM | encrypted session credential at protocol layer | Shadowsocks | reject invalid session prefix | production / authorized | TCP reachable; UDP valid behavior not tested |
| Direct REALITY ingress | `16.170.208.231:2093/TCP` | VLESS + REALITY relay ingress | ingress-issued VLESS identity | `nova-xray-ingress` | reject/fallback invalid clients | production manifest / authorized | TCP connection refused during audit |
| XHTTP/CDN | `edge-sthlm.aknova.pp.ua:443` | TLS 1.3, h2 policy, XHTTP `/nova-xhttp/` | VLESS identity inside XHTTP | Cloudflare -> nginx -> Xray | invalid XHTTP request -> error | production / authorized hostname/path | reachable |
| XHTTP origin | `16.170.208.231:443` with edge SNI/Host | HTTPS origin | Cloudflare-source boundary plus XHTTP identity | nginx -> Xray | deny non-CDN source | production / authorized | direct audit source rejected 403 |
| ACME edge | both gateway IPs `:80` | HTTP ACME challenge only | none | nginx | challenge path or 404 | production / authorized; not actively exercised | SOURCE-CONFIRMED only |
| `/v1/peers` | both gateway IPs `:443`, POST | JSON HTTPS | enrollment bearer token | nginx -> exit API | 401 on missing/invalid token | production / authorized | measured Frankfurt; parity source-confirmed for Stockholm config |
| `/v1/activate` | both `:443`, POST | JSON HTTPS | activation bearer credential | nginx -> exit API | 401 on missing/invalid credential | production / authorized | measured both |
| `/v1/xray-profile` | both `:443`, POST | JSON HTTPS | same activation credential plus bound public key | nginx -> exit API | 401 on missing/invalid credential | production / authorized | measured both |
| `/v1/manifest` | both `:443`, GET | binary HTTPS | intentionally credential-independent; Ed25519 object | nginx -> exit API | public 200 signed artifact | production / authorized | measured both |
| `/v1/relay-health` | Frankfurt `:443`, GET | JSON HTTPS | short-lived HMAC bearer token | nginx -> exit API | 401 on missing/invalid token | production / authorized | measured |
| `/v1/ingress-profile` | Stockholm `:443`, POST | JSON HTTPS | activation bearer credential | nginx -> ingress API (`8444`/`8445` by header) | 401 on missing/invalid credential | production / authorized | measured |
| unknown HTTPS path | both `:443` | HTTPS | none; not routed | nginx | 404 | production / authorized | measured |

`/v1/peers` was found during current source inspection and is included even though it was not in the brief's minimum route list. Loopback API ports `8443`–`8445` are not externally exposed by tracked nginx policy and were not probed.

## 5. Authentication-boundary map

| Component | Enforcement boundary | SOURCE-CONFIRMED behavior | Live result |
|---|---|---|---|
| AWG | protocol handshake | peer key required; no application response surface | invalid datagrams silent |
| REALITY | during TLS-like handshake, then VLESS | invalid REALITY client falls through to configured TLS destination | generic TLS received fallback site response; malformed record got fatal alert |
| TLS/VLESS | TLS then VLESS application handshake | TLS is credential-independent; UUID checked after TLS | TLS completed; unexpected HTTP closed with no reply |
| Shadowsocks | encrypted protocol/session prefix | valid 2022 credential required | invalid TCP input reset; valid credential NOT TESTED |
| XHTTP | TLS/HTTP, then XHTTP/VLESS | public path reaches Xray; VLESS identity inside transport | expected path distinguishable before valid identity |
| manifest | credential-independent | signed artifact intentionally public | 200/1,840 bytes on both |
| peers | HTTP application layer | body framing/content type, bearer syntax, body parse, token lookup | missing/invalid token identical 401 |
| activate | HTTP application layer | framing/content type -> bearer syntax -> body parse -> credential lookup | same; parser errors distinguishable before lookup |
| Xray profile | HTTP application layer | same credential; additionally device binding and transport | missing/invalid identical 401 |
| ingress profile | HTTP application layer | activation credential; self-binding/device cap | missing/invalid identical 401 |
| relay health | HTTP application layer | bearer syntax then HMAC verification/expiry | missing/invalid identical 401 |

Tracked source intentionally maps unknown credentials to the same `401 unauthorized` response. It distinguishes a genuinely matched credential that is revoked, expired, at device capacity, or not device-bound with specific `403` codes. That is a `SOURCE-CONFIRMED` credential-state oracle only for a party already holding a matching high-entropy credential; no disposable valid/revoked/expired credential was used, so it is not `MEASURED`.

## 6. Methodology and probe limits

### 6.1 Source review

Cross-checked current production manifest v4, Android production origins, nginx Frankfurt/Stockholm/CDN-origin configs, API handler/configuration, Xray renderers, AWG/Shadowsocks configs, deployment scripts, and existing readiness documents. Current code/config overrides older narrative documentation.

### 6.2 Live tools

- Windows `curl.exe` with 4-second connect and 7–8-second total bounds;
- Python 3 `socket` and `ssl` with 1.5–3-second receive bounds;
- exact endpoints/ports from the tracked manifest and nginx configuration;
- one request per method/path cell, three repetitions only for replay/timing comparisons;
- no payload larger than a minimal HTTP body or 21-byte invalid transport input.

The invalid bearer literal was a fixed, explicitly non-secret audit string. The syntactically valid WireGuard public key in request bodies was a deterministic 32-byte public test value, not a credential or private key.

### 6.3 Safe omissions

- no real or disposable valid activation, enrollment, VLESS, relay, or Shadowsocks credential;
- no live maximum-size test;
- no deliberate rate-limit trigger;
- no server-side capture/log access;
- no sustained idle/resource test;
- no UDP Shadowsocks session test;
- no Hysteria2 ingress.

### 6.4 Test verification

- Windows targeted unit run: 48 static/config tests passed; three POSIX API modules could not import because Windows lacks `fcntl`.
- WSL/Linux targeted handler, rate-limit, CDN-origin, relay-health, and ingress-profile suite completed successfully.

No audit tooling or production code was added.

## 7. AWG results

**MEASURED (High confidence):** On each gateway, one 1-byte datagram and three repetitions of the same 21-byte invalid datagram produced no response within 1.5 seconds. All eight observations ended at the client timeout (1,500–1,516 ms). No behavior change appeared across repetitions.

**NOT TESTED:** server logs, valid peer comparison, cryptographic replay, longer suppression windows, or resource effects. Silence is compatible with correct fail-closed behavior but is not proof of resistance to all active probing.

## 8. REALITY results

### 8.1 Plain/malformed behavior

| Probe | Frankfurt | Stockholm | Class |
|---|---|---|---|
| plaintext HTTP | EOF at 78 ms total | EOF at 141 ms | MEASURED |
| arbitrary short bytes | EOF at 62 ms | EOF at 125 ms | MEASURED |
| malformed TLS record | `15 03 03 00 02 02 0a` | same bytes | MEASURED |
| idle socket | no response/close within 2.5 s | same | MEASURED |

The malformed response decodes as a fatal TLS `unexpected_message` alert. Three repeated samples returned identical alert bytes: Frankfurt 47, 62, 63 ms; Stockholm 125, 141, 281 ms. No suppression or changed response was observed.

### 8.2 Generic TLS fallback

**MEASURED (High confidence):** A generic non-REALITY TLS client using the Nova IP as SNI completed TLS 1.3 on both ports with `TLS_AES_128_GCM_SHA256`, ALPN `http/1.1`, and the same leaf-certificate SHA-256:

```text
08e0b65df41fb075ec91c1dcd2cacc4e8c7dda53b754806525117b32f7b73253
```

Both returned:

- `HTTP/1.1 400 Bad request`;
- `server: HAProxy`;
- `content-length: 90`;
- identical HTML: “Your browser sent an invalid request.”;
- `x-cache-status: int-tls`;
- differing cache node only (`cp3072` Frankfurt observation, `cp3069` Stockholm observation).

**Security relevance:** this is a stable cross-gateway correlation signal and differentiates REALITY from TLS/VLESS. It also discloses the fallback infrastructure product and common destination. It did not expose Nova credentials or backend state.

## 9. TLS/TCP results

| Probe | Frankfurt | Stockholm | Class |
|---|---|---|---|
| plaintext HTTP | EOF at 78 ms | EOF at 109 ms | MEASURED |
| arbitrary short bytes | EOF at 47 ms | EOF at 94 ms | MEASURED |
| malformed TLS record | `15 03 01 00 02 02 50` | same bytes | MEASURED |
| idle socket | no response/close within 2.5 s | same | MEASURED |
| generic TLS + HTTP GET | TLS succeeds, then EOF | same | MEASURED |

The malformed record produced fatal TLS `internal_error`. Three repetitions returned identical bytes: Frankfurt 46–47 ms; Stockholm 78–94 ms.

Generic TLS negotiated TLS 1.3, `TLS_AES_128_GCM_SHA256`, and ALPN `http/1.1`. Each gateway used its own certificate (different SHA-256), as expected for IP-address certificates. After a generic HTTP GET, both closed without application data.

**NOT TESTED:** valid VLESS, missing versus invalid UUID behavior, application framing after valid VLESS negotiation, or server logs. No credential-validity conclusion is possible for the VLESS layer.

## 10. Shadowsocks results

**MEASURED (Medium confidence):** Frankfurt `TCP/28388` accepted TCP and reset on plaintext HTTP, a malformed TLS prefix, and arbitrary bytes. Three identical invalid inputs each reset at 62–63 ms. An idle connection produced no response or close within 2.5 seconds.

**NOT TESTED:** valid authorized credential, malformed-but-cryptographically-framed input, TCP versus UDP valid sessions, UDP invalid behavior, server logs, or longer replay/suppression behavior. No secret was used.

## 11. XHTTP / CDN results

### 11.1 Public CDN

| Path | GET | HEAD | POST (3-byte body) | OPTIONS |
|---|---|---|---|---|
| `/nova-xhttp/` | 400, empty | 400, empty | 400, empty | 403 nginx HTML |
| `/b48-clearly-nonexistent` | 404 nginx HTML | 404 | 404 nginx HTML | 404 nginx HTML |

All responses carried Cloudflare infrastructure headers; expected-path 400 responses added `Access-Control-Allow-Origin: *` and `Cache-Control: no-store`. Cloudflare advertised `alt-svc: h3=":443"`; this is not evidence that Nova used HTTP/3. Three repeated expected-path GETs remained empty 400 responses with total times 150, 159, and 178 ms.

**MEASURED (High confidence):** the expected XHTTP path is remotely distinguishable from an unknown path without valid VLESS identity.

### 11.2 Direct origin

Using the source-confirmed edge hostname as SNI/Host while resolving it directly to `16.170.208.231`, GET/HEAD/POST/OPTIONS on `/nova-xhttp/` all returned nginx `403` with `Cache-Control: no-store`. The nonexistent path returned `404` for all methods.

**MEASURED (High confidence):** the direct-origin source restriction was active for this audit source. This does not prove every possible origin-bypass path is closed.

## 12. Control-plane results

### 12.1 Method handling

- Both manifests: GET `200` with 1,840 bytes; HEAD `405` at the API boundary.
- Activation, Xray profile, and Stockholm ingress profile: POST reached API; HEAD/OPTIONS were rejected `403` by nginx `limit_except`.
- Frankfurt relay health: GET reached API; HEAD returned `405`.
- Unknown path: GET/HEAD returned nginx `404` on both.

The distinction between nginx `403` and API JSON `405` reveals which method/path pairs reach the application, but no protected data.

### 12.2 Missing versus invalid authentication

**MEASURED (High confidence):** for every live-tested authenticated route, missing and deliberately invalid bearer values produced identical:

```text
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 25
{"error": "unauthorized"}
```

This held for Frankfurt peers, both activation routes, both Xray-profile routes, Stockholm ingress-profile, and Frankfurt relay-health.

### 12.3 Minimal malformed bodies

On `/v1/activate`, both gateways returned byte-identical shapes:

| Input | Status | Body |
|---|---:|---|
| empty JSON body | 400 | `{"error": "malformed_json"}` |
| `{` | 400 | `{"error": "malformed_json"}` |
| structurally incomplete/wrong type | 400 | `{"error": "malformed_request"}` |
| `text/plain` | 415 | `{"error": "unsupported_media_type"}` |

The invalid bearer was syntactically present in these parser probes. Source order confirms content type is checked before bearer syntax, and body structure is checked after bearer syntax but before credential lookup. Thus these are parser/framing oracles, not credential-existence oracles.

### 12.4 Size and rate bounds

**SOURCE-CONFIRMED:** nginx caps bodies at 2 KiB; the API caps at 1,024 bytes and rejects transfer encoding, duplicate/invalid/missing content length, and oversized bodies. `/v1/activate` and `/v1/manifest` have per-source nginx rate/concurrency limits with explicit 429. API routes also have application limiters.

**NOT TESTED live:** exact size boundary and rate-limit transition, to avoid stressing production.

## 13. Replay findings

Low-count identical invalid replays did not change behavior:

- AWG: three identical datagrams per gateway remained silent.
- REALITY: three identical malformed TLS records returned identical fatal `unexpected_message` bytes.
- TLS/VLESS: three identical malformed records returned identical fatal `internal_error` bytes.
- Shadowsocks: three identical payloads reset.
- XHTTP: three identical GETs returned empty 400.

No rate limiting, suppression, challenge, or server-visible state change was observed from the client side. Counts were intentionally too low to test abuse controls.

Credential replay is **NOT TESTED** because no disposable valid credential was available. Real user material was never used.

## 14. Timing observations

Three `/v1/activate` first-byte samples per class:

| Gateway | Missing bearer (ms) | Invalid bearer (ms) | Malformed JSON (ms) |
|---|---|---|---|
| Frankfurt | 103.327, 95.361, 94.343 | 111.760, 90.541, 119.949 | 98.215, 92.131, 104.464 |
| Stockholm | 145.771, 147.039, 172.433 | 171.545, 133.779, 148.240 | 138.203, 140.643, 147.294 |

Ranges overlap materially within each gateway. Three samples are insufficient for subtle timing claims, and no large consistent missing-versus-invalid separation appeared. Result: **no measured credential-validity timing oracle**.

The roughly 40–80 ms inter-gateway latency offset is consistent with network/geographic distance and is not an authentication finding.

## 15. Error-response correlation

| Surface | Correlation | Evidence |
|---|---|---|
| Frankfurt/Stockholm control plane | **Strong** | identical status/body/header shapes for equivalent probes; same nginx banner; predictable geographic timing offset |
| Frankfurt/Stockholm REALITY | **Strong** | identical malformed alert, identical fallback cert, body and HAProxy header family |
| Frankfurt/Stockholm TLS/VLESS | **Strong** | identical malformed alert and empty post-TLS close; endpoint-specific certs |
| Direct transports to each other | **Strongly distinguishable** | different port plus alert/reset/silence behavior |
| XHTTP expected vs nonexistent path | **Strongly distinguishable** | empty 400 vs nginx 404; OPTIONS 403 on expected path |
| CDN vs origin | **Strongly distinguishable** | Cloudflare headers at edge; direct origin 403 and nginx banner |
| Stockholm direct ingress | **Unknown for protocol behavior** | TCP refused during audit; no listener response to compare |

## 16. Information-disclosure findings

### Live responses

Observed product identifiers:

- `Server: nginx` on direct control plane and origin;
- `Server: cloudflare`, `CF-RAY`, NEL/Report-To, cache status, and h3 advertisement at CDN;
- `server: HAProxy`, cache-node name, and cache status through generic REALITY fallback.

No live response contained a stack trace, filesystem/storage path, internal IP, raw credential/token, UUID, private key, database name, or Nova configuration name. Nginx version was suppressed.

### Source-confirmed logging

- nginx combined logging records remote address, request line (including query string), status, bytes, referer, and User-Agent; it does not log Authorization or bodies;
- the API disables `BaseHTTPRequestHandler`'s default logger and logs method, path, status, latency, plus allowlisted prefixes/digests/outcomes;
- API exception logging emits exception type only, not message;
- credential digests and public-key prefixes are truncated in logs;
- the API's `path` field is the raw request target, so attacker/client-supplied query strings can enter logs. Normal Nova credentials are header/body fields and should not be placed in URLs.

Actual production logs were unavailable, so retention, permissions, unexpected downstream logging, and deployed-format parity are **NOT TESTED**.

## 17. Server-log observations

No server log access was available. No claim is made about what a deployed service actually recorded for these probes.

Source and tests support redaction-by-design, but the following remain unverified:

- deployed nginx/API log formats and permissions;
- Xray/AWG/Shadowsocks journal contents for malformed input;
- whether repeated invalid traffic creates noisy or identifying logs;
- whether proxy/CDN logs retain XHTTP query padding or unrelated headers;
- whether any deployment override enables more verbose logging.

## 18. Relationship to B47

B48 strengthens these B47 findings:

- **shared gateway correlation:** equivalent control-plane responses and transport alerts closely match across Frankfurt/Stockholm;
- **listener-port distinguishability:** invalid input produces protocol-specific silence, alert, reset, fallback page, or empty close;
- **REALITY correlation:** both gateway listeners expose the same fallback certificate and HAProxy response family;
- **static XHTTP signature:** the expected path has a stable public error response distinct from unknown paths;
- **matching manifest behavior:** both origins served the same 1,840-byte public artifact and equivalent method errors.

B48 weakens no B47 finding. It adds evidence that the direct XHTTP origin rejects the audit source, which is positive boundary evidence but does not remove the public CDN path oracle.

## 19. Evidence table

| ID | Component | Endpoint class | Probe | Evidence class | Observation | Reproduction tool | Repetitions | Confidence | Security relevance |
|---|---|---|---|---|---|---|---:|---|---|
| B48-E01 | AWG | both UDP/51820 | short + repeated invalid datagram | MEASURED | no response within 1.5 s | Python UDP socket | 4/gateway | High | fail-closed; no active response oracle observed |
| B48-E02 | REALITY | both TCP/2053 | malformed TLS record | MEASURED | identical fatal unexpected-message alert | Python TCP socket | 3/gateway | High | stable cross-site and protocol oracle |
| B48-E03 | REALITY | both TCP/2053 | generic TLS + HTTP | MEASURED | same cert hash, HAProxy 400/body | Python SSL + curl | 1/gateway | High | strong gateway correlation/fallback disclosure |
| B48-E04 | TLS/VLESS | both TCP/2083 | malformed TLS record | MEASURED | identical fatal internal-error alert | Python TCP socket | 3/gateway | High | distinguishes listener family |
| B48-E05 | TLS/VLESS | both TCP/2083 | generic TLS + HTTP | MEASURED | TLS 1.3 then EOF | Python SSL + curl | 1/gateway | High | post-TLS close oracle; UUID states unknown |
| B48-E06 | Shadowsocks | Frankfurt TCP/28388 | invalid inputs/replay | MEASURED | repeatable reset | Python TCP socket | 3 replay + matrix | Medium | active transport fingerprint |
| B48-E07 | ingress | Stockholm TCP/2093 | four TCP input classes | MEASURED | connection refused | Python TCP socket | 4 | High point-in-time | manifest/exposure drift; protocol untested |
| B48-E08 | XHTTP/CDN | expected/unknown path, four methods | MEASURED | expected path distinguishable by 400/403 | curl | 1/cell + 3 replay | High | stable public application signature |
| B48-E09 | XHTTP origin | direct origin with edge SNI/Host | MEASURED | all expected-path methods 403 | curl `--resolve` | 4 | High | positive CDN-source-boundary evidence |
| B48-E10 | control plane | authenticated routes | missing vs invalid bearer | MEASURED | identical 401, 25-byte JSON | curl | route matrix | High | no credential-existence oracle observed |
| B48-E11 | activation parser | both gateways | minimal malformed bodies | MEASURED | stable granular 400/415 codes | curl | 1/class/gateway | High | parser fingerprint; not auth bypass |
| B48-E12 | activation timing | both gateways | missing/invalid/malformed | MEASURED | overlapping 3-sample ranges | curl | 3/class/gateway | Medium | no large timing oracle observed |
| B48-E13 | API credential states | activation/profile/relay | revoked/expired/bound-valid states | SOURCE-CONFIRMED | distinct 403/success states after credential match | handler source/tests | N/A | High | state oracle only with matching high-entropy credential |
| B48-E14 | logging | nginx/API | response/log audit | SOURCE-CONFIRMED | auth/body omitted; raw path/query logged | configs/source/tests | N/A | High | low-risk metadata/log-injection surface |
| B48-E15 | Hysteria2 | runtime | none | NOT TESTED | PENDING B46-3A | N/A | 0 | High | no production listener created |

## 20. Risk table

### Critical

None found.

### High

None found. In particular, no unauthenticated protected data, secret exposure, remote crash, or credential enumeration was measured.

### Medium

| Risk | Evidence | Rationale |
|---|---|---|
| Shared REALITY fallback oracle | B48-E02/E03 | same certificate and HAProxy response strongly correlate both gateways and identify listener behavior |
| Stable per-transport invalid-input signatures | B48-E01/E02/E04/E06 | silence/alerts/reset/close allow active transport classification |
| Public XHTTP expected-path oracle | B48-E08 | unauthenticated requests distinguish the configured path from unknown paths |

### Low

| Risk | Evidence | Rationale |
|---|---|---|
| Granular parser errors before credential lookup | B48-E11 | fingerprints API validation stage but does not reveal credential existence |
| Product/infrastructure banners | live responses | nginx/Cloudflare/HAProxy disclosed without versions/secrets |
| Credential lifecycle distinctions after match | B48-E13 | a holder of a matching credential can distinguish revoked/expired/capacity/binding states |
| Raw request target in logs | B48-E14 | query strings are logged; credentials must remain out of URLs |

### Informational

| Finding | Evidence |
|---|---|
| Stockholm `:2093` refused connections during audit | B48-E07 |
| CDN advertises h3; Nova use not established | B48-E08 |
| Direct XHTTP origin rejected non-CDN audit source | B48-E09 |

## 21. Explicit NOT TESTED items

- any real-user credential or authentication material;
- missing versus invalid VLESS UUID after a valid TLS/REALITY/XHTTP transport setup;
- valid versus invalid Shadowsocks credential and UDP behavior;
- disposable valid/revoked/expired activation, enrollment, ingress, or relay token;
- credential replay and rate-limit behavior;
- exact live request-size boundary or sustained rate/concurrency limits;
- production server/CDN/Xray/AWG/Shadowsocks logs;
- long-idle socket resource behavior or exhaustion resistance;
- malformed input beyond the four minimal classes used;
- `TCP/2093` protocol behavior while a listener is available;
- Hysteria2, PENDING B46-3A;
- remote crash detection beyond client-visible continuity;
- HTTP/2/3 application behavior from the real Android client.

## 22. Recommended remediation slices

No production change should be made silently from this audit. Candidate slices:

1. **B48-1 — REALITY fallback exposure decision.** Decide whether identical fallback infrastructure across gateways is acceptable for compatibility and anti-probing goals; test any proposed change against legitimate REALITY behavior before implementation.
2. **B48-2 — XHTTP error-surface normalization research.** Determine whether expected-path invalid requests can safely converge toward unknown-path behavior at Cloudflare/origin without breaking XHTTP streaming or observability.
3. **B48-3 — authenticated disposable-state matrix.** In a non-user test account, compare valid, revoked, expired, device-bound, and invalid credentials across activation/profile/relay routes; revoke/delete all fixtures and retain sanitized evidence only.
4. **B48-4 — authorized server-log correlation.** Correlate this exact bounded matrix with deployed logs and audit permissions/retention/redaction; do not add credential logging.
5. **B48-5 — ingress exposure reconciliation.** Determine why manifest-advertised `16.170.208.231:2093` refused connections and classify deployment/availability impact separately from probing resistance.

## 23. Recommended B49 dependencies

B49 chaos/simulation should consume:

- the endpoint inventory and exact response/alert classes in this document;
- bounded fixtures for TCP close/reset/alert/no-response and HTTP 400/401/403/404/405/415/429;
- simulation of unavailable advertised ingress (`:2093` refused);
- deterministic comparison of client fail-closed behavior without making external endpoints noisier;
- sanitized server-log assertions once B48-4 exists.

B49 must not treat these Internet measurements as permission to fuzz production or alter authentication. It should reproduce them locally/staging wherever possible.

## 24. Decision gate

**Decision: audit baseline complete; active-probing hardening is NOT IMPLEMENTED.**

Proceed to remediation only after owner decisions on:

- acceptable REALITY fallback correlation versus compatibility;
- whether XHTTP invalid-path normalization is technically safe;
- availability of disposable credentials and a non-user test environment;
- authorized server-log access;
- the operational owner for Stockholm `:2093` reconciliation.

No Critical/High issue requires an emergency production change based on current evidence. Medium fingerprint findings should be handled as explicit, separately reviewed slices. B49 may begin with local/staging fault simulation using this audit's response taxonomy; it need not wait for fingerprint hardening, but it must preserve B48's authorization and rate boundaries.
