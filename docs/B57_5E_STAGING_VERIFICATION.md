# B57-5E - Control-plane loopback staging (Stockholm)

Status: **STAGING VERIFIED (2026-10-03).** Cloudflare -> Tunnel ->
`127.0.0.1:8081` -> nginx -> loopback API works end to end for the staging
hostname `cp-staging.aknova.pp.ua`. This is staging, not a production
migration: no client, manifest, production DNS record, firewall rule or
existing vhost was changed, and no app client uses this path. Open:
section 11.7 (first log rotation) and 11.9 (rate limits vs CGNAT).
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
| 9 rate limits vs CGNAT | NOT VERIFIED | needs real client traffic |
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
   is global, not per client.
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

## 6. Rollback

```
sudo systemctl disable --now cloudflared
# Cloudflare dashboard: delete the cp-staging published route/DNS record, the two Cache Rules and the staging tunnel
sudo rm /etc/nginx/sites-enabled/pocvpn-cp-loopback-stockholm
sudo nginx -t && sudo systemctl reload nginx
curl -s https://control.aknova.pp.ua/v1/manifest | sha256sum   # expect 304afa8b...
```

No manifest, APK, Frankfurt, Hysteria2, XHTTP or B46-4A change is needed.
