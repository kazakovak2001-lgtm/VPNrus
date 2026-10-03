# B57-5A - Control Plane Loopback Security Contract (`pocvpn-cp-loopback`)

Status (2026-10-03):

- **Stockholm variant: deployed as STAGING by B57-5E** (runtime verified,
  nginx 1.24.0), reachable only via the Cloudflare Tunnel staging hostname
  `cp-staging.aknova.pp.ua`. B57-5E first deployed this B57-5A template
  (SHA-256 `371c2e84...`); since 2026-10-03 17:38 UTC it runs the B57-5D
  version (`2b756220...`, commit `7fbabaf`). See
  `docs/B57_5E_STAGING_VERIFICATION.md`.
- **Frankfurt variant: repo-only, NOT DEPLOYED** (not touched by B57-5E or
  B57-5D).
- **B57-5D `X-Forwarded-Proto` enforcement: in both repo templates;
  deployed and runtime verified on Stockholm STAGING only.** See
  `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`.

The B57-5A step itself changed nothing in production: no nginx
install/reload, no Cloudflare rule, no DNS record, no tunnel, no
cloudflared, no firewall change, no APK change, no manifest change.

## 1. Purpose

Prepare a hardened nginx listener for the future control-plane edge:

```
client -> Cloudflare -> cloudflared (same host) -> 127.0.0.1:8081 (this template) -> pocvpn-api loopback
```

B57-4 staging proved that anonymous `GET /v1/manifest` is cacheable, that a
request carrying `Authorization` must never be cached, that a Cloudflare
Cache Rule alone is not enough, and that the API sends no `Cache-Control` of
its own. The existing public vhosts have no such policy. This template makes
the origin (nginx) the authority for cache policy before any Cloudflare path
is built.

Files:

| File | Purpose |
|---|---|
| `gateway/edge/nginx-pocvpn-cp-loopback-frankfurt.conf` | Frankfurt variant |
| `gateway/edge/nginx-pocvpn-cp-loopback-stockholm.conf` | Stockholm variant |
| `gateway/api/tests/test_control_plane_loopback_nginx.py` | Static contract tests (no nginx, no network) |

Both `.conf` files are matched by `*.conf` in `.gitignore`, like every other
file in `gateway/edge/`. They must be added with `git add -f` when the owner
decides to commit.

## 2. Frankfurt vs Stockholm

Each file is self-contained (http-level `map`/`limit_*_zone`/`log_format`
plus one `server {}`), is included from inside `http {}`, and must pass
`nginx -t` on its own. **Load exactly one variant per host.** Both declare
the same `pocvpn_cp_*` names, so loading both on one host would be a
duplicate-definition error.

| Route | Method | Frankfurt | Stockholm | Upstream |
|---|---|---|---|---|
| `/v1/manifest` | GET (and HEAD, implied by `limit_except GET`) | yes | yes | `127.0.0.1:8443` |
| `/v1/activate` | POST | yes | yes | `127.0.0.1:8443` |
| `/v1/xray-profile` | POST | yes | yes | `127.0.0.1:8443` |
| `/v1/hysteria-profile` | POST | **no (404)** | yes | `127.0.0.1:8443` |
| `/v1/ingress-profile` | POST | **no (404)** | yes | `$pocvpn_ingress_profile_backend` |
| `/v1/field-enroll`, `/v1/peers`, `/v1/relay-health`, anything else | any | 404 | 404 | none |

### Stockholm ingress map (no duplicate definition)

The existing `nginx-pocvpn-stockholm.conf` already defines, in http context:

```
map $http_x_ingress_transport $pocvpn_ingress_profile_backend {
    default 127.0.0.1:8444;
    xhttp 127.0.0.1:8445;
}
```

The Stockholm loopback variant **references** this variable but **never
defines** it (a second `map` for the same variable is an nginx error).
Consequence: on Stockholm, the loopback file must be loaded in the same
`http {}` as the existing vhost. If it is ever loaded without that vhost,
`nginx -t` fails with an unknown variable, which fails closed rather than
routing wrongly. Tests enforce both halves: the loopback file has no such
`map`, and the existing vhost defines it exactly once.

## 3. Security contract C1-C4

| Rule | Implementation |
|---|---|
| **C1** nginx decides Cache-Control | Every proxied location has `proxy_hide_header` for `Cache-Control`, `Expires`, `Pragma`, `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`, `Surrogate-Control`. The last two matter because Cloudflare honours them **ahead of** `Cache-Control`. A future API change cannot relax cache policy. |
| **C2** public only for anonymous manifest 2xx | `map "$request_method:$pocvpn_cp_auth:$status" $pocvpn_cp_manifest_cache_control`, default `private, no-store`, one anchored rule `~^GET:0:2[0-9][0-9]$` -> `public, max-age=300`. All other locations use the literal `private, no-store`. |
| **C3** Cloudflare rule is secondary | Not configured here. See section 5. |
| **C4** error responses covered | Every location, including the `404` catch-all, uses `add_header Cache-Control ... always`. Each location declares its own `add_header`/`proxy_hide_header`, because nginx does **not** inherit either directive into a location that declares its own. |

## 4. Cache-Control contract

| Request | Result |
|---|---|
| `GET /v1/manifest`, no `Authorization`, 2xx | `public, max-age=300` |
| `GET /v1/manifest` with `Authorization` (any value, any status) | `private, no-store` |
| `HEAD /v1/manifest` | `private, no-store` |
| `/v1/manifest` 3xx/4xx/5xx, including nginx-generated 403/413/429 | `private, no-store` |
| Any POST route (any status) | `private, no-store` |
| Unknown path (404) | `private, no-store` |

**Authorization -> `private, no-store`.** `map $http_authorization
$pocvpn_cp_auth { "" 0; default 1; }` extracts only a presence bit. The
header value never enters a map result, a zone key or a log line. Any
non-empty value, including a malformed one, counts as authenticated and
therefore private (fail closed). The header is still forwarded to the API
unchanged, because `/v1/activate` and the profile routes need it.

`$status` is read only inside `add_header`, i.e. when response headers are
emitted, so the map sees the **final** status (verified locally for 204,
304, 403, 404, 413, 429, 500 and 503).

Note: because of C1, the origin's result wins. An upstream
`Cache-Control: private` on an anonymous 2xx manifest is replaced by
`public, max-age=300`. This is intended: the manifest is a signed public
artifact, and the per-request privacy decision is made from `Authorization`
presence and status, not from the API.

## 5. Why Cloudflare "Ignore cache-control header" is forbidden

The future Cache Rule must use: **Eligible for cache**, Edge TTL **"Use
cache-control header if present, bypass cache if not"**, Browser TTL
**"Respect origin"**.

"Ignore cache-control header" would let Cloudflare apply its own TTL to
responses the origin explicitly marked `private, no-store`, including
responses to requests carrying `Authorization` and error responses. That
defeats C1/C2: one authenticated or error response could be cached at the
edge and served to other clients. The origin header must stay the deciding
layer, and the Cloudflare rule may only narrow caching, never widen it.
This step makes no Cloudflare change at all.

## 6. Rate-limit contract (local to this listener; this is NOT B56-3)

| Zone | Rate | Burst | Used by |
|---|---|---|---|
| `pocvpn_cp_manifest_rl` | 120r/m | 60 nodelay | `/v1/manifest` |
| `pocvpn_cp_activate_rl` | 30r/m | 20 nodelay | `/v1/activate` |
| `pocvpn_cp_profile_rl` | 30r/m | 20 nodelay | `/v1/xray-profile`, `/v1/hysteria-profile`, `/v1/ingress-profile` (shared) |
| `pocvpn_cp_conn` | 20 concurrent | none | every proxied route |

- Rejections return `429` with `private, no-store`.
- Rejections are logged at `warn`, below the server's `error` log level, so a flood does not write request lines into the error log.
- All names are in the `pocvpn_cp_*` namespace and do not collide with the B56-3 zones (`pocvpn_activate_rl`, `pocvpn_manifest_rl`, `pocvpn_bootstrap_conn`) or any existing map. Tests enforce this.
- The profile zone is shared, so a client that provisions Xray, Hysteria2 and ingress in one burst consumes one bucket. At 30r/m + 20 burst this is ample for a single device.

## 7. Real-IP contract

```
set_real_ip_from 127.0.0.1;
real_ip_header CF-Connecting-IP;
real_ip_recursive off;
```

- `CF-Connecting-IP` is trusted only from loopback, which is where cloudflared connects from.
- `X-Real-IP` and `X-Forwarded-For` sent to the API are both set to the resolved `$remote_addr`. A client-supplied `X-Forwarded-For` is discarded, not appended.
- Rate-limit keys use the resolved client address.

**This alone is not sufficient for production.** Any local process on the
host can connect to 127.0.0.1:8081 and set `CF-Connecting-IP`. If
cloudflared does not forward the header, every client resolves to
`127.0.0.1` and shares one rate-limit bucket. Both must be checked in B57-5E.

## 8. Logging

`log_format pocvpn_cp_log escape=json` logs only:
`$time_iso8601 $host "$request_method $uri" $status $body_bytes_sent $request_time`.

It logs no `Authorization` header, request body, query string (`$uri`
excludes it) or any `$http_*`/`$arg_*`/`$cookie_*` value. The client IP is
not logged either, following the B57-5A field list. The owner can add
`$remote_addr` later as a deliberate decision.

## 9. Deliberately excluded

- **`/v1/field-enroll` is not part of this include.** It is not routed in production and must not be added in B57. It returns 404 here like any unknown path. `/v1/peers` and `/v1/relay-health` are excluded the same way.
- **HTTP -> 403 / HTTPS enforcement** was a commented-out proposal here. It is now implemented in the templates by B57-5D (server-level `if ($http_x_forwarded_proto != "https") { return 403; }` plus a server-level `add_header Cache-Control "private, no-store" always;` so the 403 meets C4); deployed on Stockholm STAGING only (2026-10-03), Frankfurt not deployed. See `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`.

## 10. Validation done in B57-5A (local only)

- Static tests: `python -m unittest tests.test_control_plane_loopback_nginx` from `gateway/api`, 74 tests. A mutation check confirmed that each tested property fails the suite when broken.
- `nginx -t` passed for both variants, using WSL Ubuntu nginx **1.28.3** as a non-root user in a throwaway temp dir (deleted afterwards). Stockholm was tested with the existing map copied verbatim from `nginx-pocvpn-stockholm.conf`, with ports pointed at local stubs.
- A local behaviour harness (nginx plus Python stub upstreams on loopback, 92 checks, all PASS) covered:
  - anonymous GET manifest -> `public, max-age=300`
  - upstream `public`/`private` Cache-Control replaced by the nginx value
  - `Expires`/`Pragma`/`CDN-*`/`Surrogate-Control` stripped
  - `Authorization`, HEAD, POST, 3xx/4xx/5xx, 403 (`limit_except`), 413 and 429 -> `private, no-store`
  - unknown paths and `/v1/field-enroll` -> 404 `private, no-store`
  - Stockholm ingress default/`xhttp` routing through the existing map
  - `CF-Connecting-IP` -> `X-Real-IP`, with client `X-Forwarded-For` discarded
  - per-client rate limit
  - no token, body or query string in the access or error logs

## 11. Must be verified in B57-5E (staging) before any production use

1. Actual nginx version on each target host. Frankfurt is documented as 1.24.0 in the repo; Stockholm is **UNKNOWN**. The template uses only directives available since 1.11.8, but it was validated on 1.28.3 only.
2. `nginx -T` on the target host: the loopback file is included once, inside `http {}`. On Stockholm it sits in the same `http {}` as the existing vhost's `$pocvpn_ingress_profile_backend` map, with no duplicate `map`, `zone` or `log_format`.
3. `ss -ltnp`: 8081 is bound to `127.0.0.1` only, never `0.0.0.0` or `[::]`, and is not reachable externally.
4. Through real cloudflared: `CF-Connecting-IP` arrives, `$remote_addr` resolves to the client, and rate limits key per client (not one shared 127.0.0.1 bucket).
5. Through real Cloudflare: the anonymous manifest shows `cf-cache-status: HIT` after warm-up, and a request with `Authorization`, any error response and every POST are never HIT.
6. The header cloudflared forwards for scheme (input for B57-5D). Measured in B57-5E (2026-10-03): `X-Forwarded-Proto: https`, `CF-Visitor: {"scheme":"https"}`; see `docs/B57_5D_ORIGIN_HTTPS_ENFORCEMENT.md`.
7. `/var/log/nginx/pocvpn-cp-loopback-*.log` are created, rotated by logrotate, and free of tokens.
8. Error log: upstream-failure lines (502/504) still print the request line, including any query string. The API uses no query-string secrets today, but this should be confirmed.
9. Rate-limit values against real client retry behaviour, e.g. carrier-grade NAT sharing a single client IP.
