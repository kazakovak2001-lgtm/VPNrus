# B57-5D - Origin-side HTTPS enforcement on the control-plane loopback

Status: **DEPLOYED AND RUNTIME VERIFIED ON STOCKHOLM STAGING (2026-10-03).**
Implemented in commit `7fbabaf`; the Stockholm loopback listener
(`cp-staging.aknova.pp.ua` via the Cloudflare Tunnel) runs it since
2026-10-03 (section 6). Stockholm STAGING only - NOT a production
migration: the production control plane (`control.aknova.pp.ua`, raw-IP
vhosts) is unchanged, and the Frankfurt variant is not deployed and was
not touched or verified in this session. This is defense in depth on the
origin, not a security boundary of its own.

## 1. Change

In both `gateway/edge/nginx-pocvpn-cp-loopback-{stockholm,frankfurt}.conf`,
inside `server {}` before the first `location`:

```nginx
add_header Cache-Control "private, no-store" always;

if ($http_x_forwarded_proto != "https") {
    return 403;
}
```

- **C4 fix.** A server-level `return` runs in the server-rewrite phase,
  before a location is selected, so the response uses only server-level
  directives. Before this change there was no server-level `add_header`,
  so the 403 (and nginx's own 400/414/494 for malformed requests) would
  have carried no `Cache-Control`. Every location declares its own
  `add_header`, which replaces the server-level one, so location
  responses are unchanged.
- **Phase.** The check runs before `limit_req` (PREACCESS) and before any
  `proxy_pass`: a rejected request never reaches the API and is not
  counted by the nginx rate-limit zones.
- **Comparison.** Exact, case-sensitive `"https"`. Missing header, `http`,
  `HTTPS`, and a duplicated header whose first value is not `https` all get
  403 (fail closed; verified locally, section 4).

## 2. Evidence (Stockholm staging, 2026-10-03, no configuration change during any measurement)

Path: client -> Cloudflare -> Tunnel `8290ff1b-...` -> `http://127.0.0.1:8081` -> nginx (`$scheme` = `http`).

| Measurement | Client sent | nginx received (packet capture on `lo:8081`) |
|---|---|---|
| B57-5E section 11.6 (one request, HTTPS) | HTTPS, no `X-Forwarded-Proto` | `X-Forwarded-Proto: https`, `CF-Visitor: {"scheme":"https"}` |
| B57-5D negative test (one request, plain HTTP, FRA edge, `CF-RAY a44d87b0fef507ca-FRA`) | `http://`, **`X-Forwarded-Proto: https`** | `X-Forwarded-Proto: http` (exactly one occurrence), `CF-Visitor: {"scheme":"http"}` |

- Both requests reached the origin: matching `Cf-Ray` in the capture and
  the response, `Cf-Warp-Tag-Id` = the systemd connector, one new nginx
  access-log line each, cloudflared `total_requests` +1 each. The test
  `Authorization` value was a non-secret sentinel (used only to bypass the
  cache) and appears in no nginx log.
- Cloudflare overwrote the client-sent `X-Forwarded-Proto` with the real
  edge scheme, consistently with `CF-Visitor`.
- Cloudflare does **not** redirect plain HTTP for `cp-staging.aknova.pp.ua`:
  the plain-HTTP request was answered 200 through the Tunnel. With 5D
  active it would get 403.
- **Scope: measured once on FRA edge for the tested spoofed header form.**
  Other edges, other header forms (e.g. duplicates or case variants sent
  by a client through Cloudflare) and future Cloudflare behaviour are not
  measured.

## 3. Trust boundary

- Any local process on the host can connect to `127.0.0.1:8081` and send
  `X-Forwarded-Proto: https` (same property as `CF-Connecting-IP`,
  B57-5A section 7). 5D does not and cannot change that.
- Through Cloudflare, the header is trustworthy only to the extent of the
  measurement above.

## 4. Verification in this change (local only)

- `python -m unittest tests.test_control_plane_loopback_nginx` (from
  `gateway/api`): server-level header exactly once and private, no
  server-level `public`, every location keeps its own Cache-Control, the
  `if` exactly once at server level before every location, exact
  `!= "https"` comparison, body exactly `return 403;`, no 301/302/307/308
  and no `rewrite`. Mutation check: removing the server-level header,
  comparing to `"http"`, or returning 301 each fails the suite.
- `nginx -t` for both variants (WSL nginx 1.28.3, throwaway prefix). The
  production host runs 1.24.0; `add_header ... always` and server-level
  `if`/`return` are older than both.
- Behavioural run: the harness (`--mode loopback --scheme-enforcement on`)
  against local nginx with the Stockholm template and a stub API: 13/13
  PASS. No `X-Forwarded-Proto` -> `403` + `private, no-store`;
  `X-Forwarded-Proto: https` -> manifest `200` + `public, max-age=300`
  (location header unaffected, stub's own `Cache-Control` hidden).

## 5. Harness

`gateway/tools/cp_loopback_staging_check.py` takes a required
`--scheme-enforcement {off,on}` that must match the deployed listener. In
`--mode loopback` every normal request carries `X-Forwarded-Proto: https`
and `CF-Visitor: {"scheme":"https"}` (local emulation of cloudflared), and
two probes (no header; the plain-HTTP values) expect 403 + private with
`on` or today's behaviour with `off`. The API budget stays <= 20 per run.
`--mode cloudflare` sends no plain-HTTP request.

## 6. Stockholm staging deployment (2026-10-03, owner-approved)

| Item | Value |
|---|---|
| File | `/etc/nginx/sites-available/pocvpn-cp-loopback-stockholm` = Stockholm template from commit `7fbabaf` |
| Deployed SHA-256 | `2b7562203f09c4f22f86950c01f669c15294fcc7997ee4c9e206ba03f27b024d` (previous: B57-5A `371c2e84...`) |
| Backup | `/var/backups/nova-b57-5d-20261003T173827Z/` (previous file, `nginx -T`, `ss`; root-only, no private key) |
| nginx | 1.24.0 (Ubuntu); `nginx -t` PASS; graceful reload PASS (17:38:27 UTC) |
| Active config | `nginx -T`: the `X-Forwarded-Proto` `if`, `return 403` and the server-level `add_header Cache-Control "private, no-store" always;` once each; `listen 127.0.0.1:8081` only |

Runtime verification through the real path (Cloudflare -> Tunnel -> nginx), one request each:

| Request | Result |
|---|---|
| HTTPS anonymous GET `/v1/manifest` | `200`, `public, max-age=300`, cache-eligible (`EXPIRED`), manifest SHA `304afa8b...` |
| HTTPS GET with a non-secret `Authorization` sentinel | `200`, `private, no-store`, `DYNAMIC` |
| plain HTTP, no `X-Forwarded-Proto` | `403`, `private, no-store` (nginx 403 page) |
| plain HTTP, client-sent `X-Forwarded-Proto: https` | `403`, `private, no-store`; nginx received `X-Forwarded-Proto: http`, `CF-Visitor: {"scheme":"http"}` |

- Rejected requests never reached the API: a packet capture on `lo`
  during both plain-HTTP requests saw exactly 2 requests on 8081 and 0 on
  8443; the nginx access log shows them as `403`.
- cloudflared `request_errors` stayed 0; Tunnel 4 connections; ingress
  still only `cp-staging.aknova.pp.ua -> http://127.0.0.1:8081`.
- Unchanged: production vhosts (byte-identical to the B57-5E backup),
  `control.aknova.pp.ua` (DNS-only -> `16.170.208.231`), the manifest on
  disk, all API/Xray/Hysteria2/AWG services (not restarted), Cloudflare
  and the Tunnel. Frankfurt was not touched and not verified.
- Rollback: restore the backed-up file, `nginx -t`, graceful reload.
- The template's own header comment still says B57-5D is "NOT yet
  deployed"; it was left unedited so the deployed file stays identical to
  commit `7fbabaf`. This section is the deployment record.
