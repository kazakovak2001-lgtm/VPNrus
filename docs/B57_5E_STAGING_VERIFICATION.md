# B57-5E - Control-plane loopback staging (Stockholm)

Status: **STAGING VERIFIED (2026-10-03).** Cloudflare -> Tunnel ->
`127.0.0.1:8081` -> nginx -> loopback API works end to end for the staging
hostname `cp-staging.aknova.pp.ua`. This is staging, not a production
migration: no client, manifest, production DNS record, firewall rule or
existing vhost was changed, and no app client uses this path. Open:
section 11.7 (first log rotation). Section 11.9 (rate limits vs CGNAT)
is closed within the scope of section 6: real mobile CGNAT IP keying
and one client-shaped sequence verified; multi-subscriber CGNAT
computed only, not measured.
Since 2026-10-03 17:38 UTC the staging listener also runs B57-5D
(origin HTTPS enforcement, commit `7fbabaf`), deployed and verified on
top of this staging topology (section 5).

```
STAGING  client -> cp-staging.aknova.pp.ua (Cloudflare) -> Tunnel 8290ff1b-... -> http://127.0.0.1:8081 nginx -> 127.0.0.1:8443/8444/8445
LIVE     client -> control.aknova.pp.ua (DNS-only) -> 16.170.208.231:443 nginx -> 127.0.0.1:8443/8444/8445   (unchanged)
```

## 1. Stockholm host changes

| Item | Value |
|---|---|
| Backup (before any change) | `/var/backups/nova-b57-5e-20261003T055634Z/` (`nginx.conf`, `sites-available/`, `sites-enabled/`, `conf.d/`, `nginx-T.before.txt`, `ss-ltnp.before.txt`; root-only, no private key) |
| nginx listener | `/etc/nginx/sites-available/pocvpn-cp-loopback-stockholm` (+ symlink in `sites-enabled/`) = the B57-5A Stockholm template, SHA-256 `371c2e8482bd540e9b8ca92abf92986f649874364eb9f0b75d24fc12b02f1e43`; `nginx -t` PASS on nginx **1.24.0 (Ubuntu)**, graceful reload ~05:57 UTC. Replaced on 2026-10-03 17:38 UTC by the B57-5D version (SHA-256 `2b7562203f09c4f22f86950c01f669c15294fcc7997ee4c9e206ba03f27b024d`, commit `7fbabaf`; see section 5 and `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md` section 6). |
| cloudflared | `2026.9.3` from `pkg.cloudflare.com` (key "CloudFlare Software Packaging 2025", fingerprint `CC94 B39C 77AE 7342 A68B 8962 8A68 2D30 8D4E 5E73`); apt installed only this package |
| Connector | systemd `cloudflared.service`: `/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token`; token file `600 root:root`, not on any command line; metrics `127.0.0.1:20241` (loopback) |
| Logs | `/var/log/nginx/pocvpn-cp-loopback-{access,error}.log` |

Not changed: `pocvpn-stockholm` / `pocvpn-xhttp-stockholm` vhosts (byte-identical
to the backup), the `$pocvpn_ingress_profile_backend` map, any API, Xray,
Hysteria2 or AWG service (start times unchanged), DNS records other than the
new staging one, security group, manifest, APK, Frankfurt.

## 2. Cloudflare (configured by the owner in the dashboard)

- Tunnel `nova-sthlm-control-staging`, ID `8290ff1b-0ff5-4756-a33c-73dab5d281f1`;
  4 QUIC connections (arn02/arn04/arn06). Ingress pushed to the connector:
  `cp-staging.aknova.pp.ua -> http://127.0.0.1:8081`, everything else
  `http_status:404`. No `originRequest` overrides.
- DNS: `cp-staging.aknova.pp.ua` CNAME `8290ff1b-...cfargotunnel.com`
  (proxied; public resolvers return only Cloudflare anycast addresses).
- Cache Rules (Rule 2 after Rule 1):
  1. anonymous cache - `(http.host eq "cp-staging.aknova.pp.ua" and http.request.uri.path eq "/v1/manifest" and http.request.method in {"GET" "HEAD"} and not has_key(http.request.headers, "authorization"))` -> Eligible for cache; Edge TTL "Use cache-control header if present, bypass cache if not"; Browser TTL "Respect origin".
  2. Authorization bypass - `(http.host eq "cp-staging.aknova.pp.ua" and http.request.uri.path eq "/v1/manifest" and has_key(http.request.headers, "authorization"))` -> Bypass cache.
- Lesson: the first version used `any(http.request.headers.names[*] == "authorization")`.
  `http.request.headers.names` keeps the client's original case, so an
  HTTP/1.1 `Authorization` header did not match: the request was served from
  cache (`HIT`, `Age: 1`) and never reached the origin. `http.request.headers`
  map keys are lowercased, so `has_key(..., "authorization")` matches any case.

## 3. Results (B57-5A section 11)

| Check | Status | Evidence |
|---|---|---|
| 1 nginx version | PASS | 1.24.0; `nginx -t` with the template PASS |
| 2 included once, one map | PASS | `nginx -T`: one `listen 127.0.0.1:8081`, `pocvpn_cp_*` zones/maps/log_format once, ingress map once |
| 3 8081 loopback only | PASS | `ss -ltnp`; TCP to `16.170.208.231:8081` from outside fails |
| 4 real client IP via cloudflared | PASS | error log of a Tunnel request: `client: 2a02:8308:...` (the client's ISP IPv6, not 127.0.0.1); per-client nginx keying proven on loopback (client A limited after 21, client B not) |
| 5 cache behaviour | PASS | anonymous GET `MISS` then `HIT` (same edge, 16:13); HTTP/1.1 `Authorization` and `authorization` -> `DYNAMIC`, `private, no-store`, reached the origin; POST manifest 403 / POST activate 401 `DYNAMIC`; a later `EXPIRED` came from a different edge holding a stale copy |
| 6 forwarded scheme | PASS | HTTPS request: nginx received `X-Forwarded-Proto: https`, `CF-Visitor: {"scheme":"https"}`; `$scheme` is `http` (see `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`) |
| 7 logs created, rotated, token-free | PARTIAL | created, token-free (sentinel in no nginx log); first rotation pending (files still `root:root 0644` until logrotate's `create 0640 www-data adm`) |
| 8 error log request line | CONFIRMED | error-level lines (403 `limit_except`, 413) include the request line and query string |
| 9 rate limits vs CGNAT | PASS (scoped) | real mobile CGNAT: nginx keyed on the carrier's public IPv4 `78.80.113.26`; one client-shaped sequence, no 429. MULTI-SUBSCRIBER CGNAT: COMPUTED ONLY / NOT MEASURED. See section 6 |
| manifest identity | PASS | `304afa8ba435febba742a320b99d10e8bbb07853474a041f9b39b779257faebb` on staging = loopback = API = public 443 = file on disk |
| production regression | PASS | `control.aknova.pp.ua` DNS-only -> `16.170.208.231`; raw-IP manifest unchanged; production nginx files unchanged |

Loopback contract (manual matrix + `cp_loopback_staging_check.py --mode
loopback`, 11/11 at the time): anonymous manifest `public, max-age=300`;
Authorization/HEAD/POST/404/413/429 `private, no-store`; `/v1/field-enroll`,
`/v1/peers`, `/v1/relay-health` 404; no Authorization or query string in
the access log.

## 4. Findings

1. **pocvpn-api global limiter (incident).** `pocvpn-api` has one
   process-wide limiter, 60 requests / 10 s shared by every client and
   endpoint (`gateway/api/server.py`). A naive rate-limit test sent 75
   manifest GETs through 8081 at ~05:57:43 UTC and exhausted it: for up to
   ~10-20 s every Stockholm API request could receive 429. The harness now
   keeps proxied requests <= 20 per run and proves nginx limits only with
   requests nginx rejects itself. Behind one shared egress the API limiter
   is global, not per client. Extended in section 6.4 (open follow-up).
2. **Repo != live Stockholm nginx** (pre-existing): live `pocvpn-stockholm`
   has three full-API 443 vhosts (default IP, `control.aknova.pp.ua`,
   `origin-sthlm.aknova.pp.ua`), no B56-3 zones, no `/v1/field-enroll`.
3. **Stockholm TCP 2093** (manifest v6 `stockholm-ingress-1`) is not listening (pre-existing, out of scope).
4. Cloudflare does not redirect plain HTTP for `cp-staging` (B57-5D negative test).

## 5. B57-5D on top of this staging (2026-10-03)

The verified staging topology above was left as it was; only the
listener file changed (B57-5D, `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`
section 6). Through the real Cloudflare -> Tunnel -> nginx path:

- HTTPS anonymous manifest still `200`, `public, max-age=300`,
  cache-eligible, SHA `304afa8b...`; HTTPS with `Authorization` still
  `200`, `private, no-store`, `DYNAMIC` (cache behaviour intact).
- Plain HTTP is now rejected with `403`, `private, no-store`, also when
  the client sends `X-Forwarded-Proto: https` (nginx received `http`).
- Rejected requests did not reach the API (0 requests on 8443 during
  both plain-HTTP requests); cloudflared `request_errors` 0; Tunnel
  ingress unchanged; production unchanged; Frankfurt not touched.

## 6. Section 11.9 - rate limits vs CGNAT (2026-10-03)

Read-only, bounded measurement. No nginx, Cloudflare, API, rate-limit
or device setting was changed; no restart, no parallel requests, no load
test.

### 6.1 Client request model (from code, HEAD `dea3e15`)

No app client uses `cp-staging` today (manifest origins and provisioning
use the gateways' raw IPs); this models a future migration.

| Endpoint | When | Requests | Auto retry | Parallel | Origin / Cloudflare |
|---|---|---:|---:|---|---|
| `GET /v1/manifest` | once per app start (ViewModel init) + debug button | 1 per origin | 0 (8 s timeout) | no (mutex, a concurrent refresh is skipped) | anonymous -> Cloudflare cache (`max-age=300`); origin only on MISS/EXPIRED |
| `POST /v1/activate` | activation only, not on connect | 1 (one trusted origin per gateway) | 0 (10 s connect + 10 s read) | no | always origin (`DYNAMIC`) |
| `POST /v1/xray-profile` (reality/tls/xhttp) | right after a successful activation | up to 3 | 0 | no, sequential | always origin |
| `POST /v1/hysteria-profile` | after activation, only with a Hysteria2 binding | up to 1 | 0 | no | always origin |
| `POST /v1/ingress-profile` | relayed attempt without a fresh stored profile | 1 | 0 | no | always origin (separate ingress backend) |

Direct connect and reconnect (`ReconnectManager`, 8 attempts, 1 s ->
30 s backoff) send no control-plane request from the client's own
address; the Xray confirmation and relay-health probes go through the
tunnel to the gateways' raw IPs. The exception is a relayed attempt
without a fresh stored ingress profile: it can send 1 `POST
/v1/ingress-profile` (table above) and, in zero-touch builds, also
`/v1/field-enroll`, which is not on the cp listener (404). A 429 surfaces as a network error; any retry is
manual and repeats the whole batch.

### 6.2 nginx per-IP model - COMPUTED / MODELLED

Zones key on `$binary_remote_addr` (the client address resolved from
`CF-Connecting-IP`): manifest `120r/m` + burst 60, activate `30r/m` +
burst 20, profile `30r/m` + burst 20 (one shared zone), connections 20.

- The profile zone is the tightest per-IP zone: with 4 profile requests
  per activation, about 5 concurrent activations behind one IP before
  its burst is used up, then about 7.5 such activations per minute
  sustained.
- Activate: about 20 concurrent, then 30 per minute. Connections: each
  client has at most one request in flight, so 20 is not binding.
- Manifest: in practice covered by the Cloudflare cache; the origin sees
  roughly one MISS/EXPIRED per edge per 5 minutes regardless of how many
  clients share an address.

These are computed values, not a measured CGNAT capacity.

### 6.3 Real mobile CGNAT measurement (18:40 UTC)

Setup: the PC was connected only through the OPPO phone's mobile
hotspot (Wi-Fi network `OPPO Find X3 Pro 2`). The phone's mobile
interface `rmnet_data1` had `10.46.140.115/29` (RFC1918); the carrier's
public IPv4 was `78.80.113.26`, as seen by Cloudflare (`/cdn-cgi/trace`,
answered by the edge, not proxied). The hotspot passed no IPv6 path to
the PC.

| # | Request | Result | Proxied |
|---|---|---|---:|
| 1 | `POST /v1/manifest` (deliberately rejected, to get nginx's `client:` field) | 403, `private, no-store`, `DYNAMIC` | 0 |
| 2 | anonymous `GET /v1/manifest` | 200, `public, max-age=300`, `EXPIRED` -> origin revalidation, SHA `304afa8b...` | 1 |
| 3 | `POST /v1/activate`, invalid bearer | 401 | 1 |
| 4 | `POST /v1/xray-profile` reality | 401 | 1 |
| 5 | `POST /v1/xray-profile` tls | 401 | 1 |
| 6 | `POST /v1/xray-profile` xhttp | 503 (see section 6.5) | 1 |
| 7 | `POST /v1/hysteria-profile` | 401 | 1 |

7 staging requests, 6 proxied (budget 20); requests 3-7 sequential
within about 2 s.

Evidence (read from Stockholm afterwards):

- cp error log: `access forbidden by rule, client: 78.80.113.26, server: _, request: "POST /v1/manifest HTTP/1.1", host: "cp-staging.aknova.pp.ua"`.
  So `$remote_addr`, and therefore `$binary_remote_addr`, is the
  client's public CGNAT address, not a shared 127.0.0.1 bucket.
- cp access log: all 7 requests with host `cp-staging.aknova.pp.ua`
  (Cloudflare -> Tunnel -> nginx path confirmed); no 429 in this
  window. cloudflared `request_errors` 0, 4 HA connections.
- API journal: only the 6 proxied requests; the rejected `POST
  /v1/manifest` never reached the API.

Result:

- Real mobile IP keying: VERIFIED.
- Normal client-shaped sequence: VERIFIED without 429 (request shape
  only; the credential was invalid, no real activation).
- MULTI-SUBSCRIBER CGNAT: COMPUTED ONLY / NOT MEASURED. One device
  cannot prove the behaviour of several subscribers sharing one public
  IPv4.
- IPv6 `/128` keying: NOT MEASURED (no IPv6 path through the hotspot).
- No rate-limit value is changed; nothing measured argues for a change.

### 6.4 Separate finding: process-wide API limiter (open follow-up)

This is not a reason to reopen 11.9, and it is separate from the nginx
per-IP limits.

- One `pocvpn-api` process on `127.0.0.1:8443` serves `/v1/manifest`,
  `/v1/activate`, `/v1/xray-profile` and `/v1/hysteria-profile` for the
  staging 8081 listener and the three production 443 control-plane
  vhosts (default IP, `control.aknova.pp.ua`, `origin-sthlm.aknova.pp.ua`).
- Its `global_limiter` is 60 requests / 10 s, shared by all clients
  and endpoints in that process.
- An activation (1 activate + up to 4 profile requests) can use up to 5
  global tokens, so about 12 such batches per 10 s for the whole process
  (worst-case computed value: activate + all 4 possible profile
  requests).
- The per-token limiter (5 / 10 s) can be used up by that same batch
  (same worst case), so an immediate retry with the same credential can
  receive 429.
- All values COMPUTED, NOT LOAD-TESTED. Follow-up before any production
  migration of the control plane behind Cloudflare. No limiter value was
  changed.

**Follow-up status: IMPLEMENTED IN REPO + UNIT-TESTED, NOT DEPLOYED.**
*Update 2026-10-04 (production, not this staging):* only the nginx part
is deployed - `/v1/tunnel-probe` and `X-Pocvpn-Edge "public-443"` on the
public vhosts of Frankfurt and Stockholm, physically verified; the API
limiter and `POCVPN_API_GATEWAY_SELF_ADDRESSES` are still not deployed
(gateway-self source observed: Frankfurt `152.70.43.1`, Stockholm
`16.170.208.231`). The cp-loopback listener this document covers is
unchanged (no `X-Pocvpn-Edge "cp-loopback"` yet). Record:
`gateway/DEPLOYMENT.md` (B57 rate limits, rollout steps 1-3).
The description above stays the record of what was measured and of
what Stockholm still runs. In the repository, `pocvpn-api` now admits
each request in layers (`gateway/api/admission.py`), right after the
endpoint's config check and before any validation, store read or lock:
per client (`X-Real-IP` as /32 or IPv6 /64, plus the constant
`X-Pocvpn-Edge` nginx sets; `gateway/api/client_identity.py`) -> a
cp-loopback edge ceiling -> a ceiling per endpoint class (bootstrap,
activation, relay_probe, field_enroll) -> the unchanged 60 / 10 s
global ceiling. A request rejected by a layer does not spend the later
ones. The global ceiling stays the one shared, process-wide safety
ceiling; the class and edge ceilings are separate fixed-window limiters
whose windows are not aligned with it, so the design does not reserve
any number of global requests for activation. The in-tunnel probes
(Xray connect confirmation and the relayed-session watchdog) are sent by
the Nova app through the user's own tunnel and reach nginx from the
gateway's own address, indistinguishable from other user requests on that
path; current Android code therefore probes `/v1/tunnel-probe`, which
nginx answers itself (static 200, no API, no limiter). Pre-B57 builds
still probe `/v1/manifest`; for them a separate, still limited
`gateway-self` bootstrap scope applies when the nginx-set `X-Real-IP`
exactly matches `POCVPN_API_GATEWAY_SELF_ADDRESSES` (empty by default;
NOT YET OBSERVED on either host) - not a trusted identity. The per-token limit (5 / 10 s) is now per device (credential +
presented public key), with a per-credential cap across devices. The
new values (per-client 10 / 10 s, bootstrap and relay_probe class 20,
cp-loopback edge 20, gateway-self bootstrap scope 20, per-credential 10)
are PROPOSED / NOT YET VERIFIED
and were not derived from measured traffic. No nginx `limit_req` value
was changed; the templates add `X-Pocvpn-Edge` and the static
`/v1/tunnel-probe` location. Not deployed on
Stockholm or Frankfurt, not staging-tested, no load test. Deployment
order and caveats: `gateway/DEPLOYMENT.md` ("pocvpn-api client-isolated
rate limits (B57)").

### 6.5 Observation outside 11.9 scope: XHTTP 503

`POST /v1/xray-profile` with `transport=xhttp` returned 503 in this
measurement. The API journal indicates the API itself returned it
before credential validation (inferred from the absence of an
`activation_digest` and a 0.19 ms latency; the log does not state the
order). It is not a
rate-limit response. Not investigated here; no conclusion about its
cause.

## 7. Rollback

```
sudo systemctl disable --now cloudflared
# Cloudflare dashboard: delete the cp-staging published route/DNS record, the two Cache Rules and the staging tunnel
sudo rm /etc/nginx/sites-enabled/pocvpn-cp-loopback-stockholm
sudo nginx -t && sudo systemctl reload nginx
curl -s https://control.aknova.pp.ua/v1/manifest | sha256sum   # expect 304afa8b...
```

No manifest, APK, Frankfurt, Hysteria2, XHTTP or B46-4A change is needed.
