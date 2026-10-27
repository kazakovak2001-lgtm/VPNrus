# VPNrus Admin UI (local dev)

React + TypeScript + Vite + Tailwind client for the `pocvpn-api` `/admin/*` endpoints
(login/logout/status, activation list/detail, revoke).

## Run locally (Windows + WSL)

1. API (WSL, needs `fcntl`): creates `~/.pocvpn-admin-dev` with a random admin password
   (`admin-secret`, mode 0600, never printed) and a few issued activations.

       wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/akaza/Downloads/VPN/gateway && python3 tools/admin_dev_server.py"

2. UI:

       cd admin-ui && npm install && npm run dev

3. Open http://localhost:5173 and sign in with the password from `~/.pocvpn-admin-dev/admin-secret`.

`/admin/*` is proxied to `http://127.0.0.1:8787` (override with `VPN_ADMIN_API`).

## Activation management
- **Create** (`POST /admin/activations`, `{max_devices 1-100, expires_in_days 1-3650 | null}`): the
  credential is returned once (`Cache-Control: no-store`), is shown once in the UI, is stored only as a
  digest, and is never written to logs, the audit log or browser storage.
- **Extend** (`POST /admin/activations/<id>/extend`, `{days 1-3650}`): counted from the later of the
  current expiry and now. Refused with 409 for revoked or never-expiring activations.
- **List**: `GET /admin/activations?q=<hex id fragment>&status=ACTIVE|EXPIRED|REVOKED&limit=1-100&offset=N`.
- All mutations require session + CSRF + same-origin and share the mutation rate limit; each is audited
  (`create`, `extend`, `revoke`) by activation id only.

## Roles
`admin` (the admin secret) can do everything. An optional second secret
(`POCVPN_API_ADMIN_VIEWER_SECRET_FILE`, same 32-char format, must differ from the admin secret and requires
`POCVPN_API_ADMIN_SECRET_FILE`) logs in as read-only `viewer`: list, detail and logout only; every create,
extend and revoke returns 403 `forbidden` after the CSRF/Origin checks. The role is stored in the server-side
session, never taken from the client, and is recorded in the audit log. These are two shared secrets, not
per-person accounts. Locally, create `<state-dir>/viewer-secret` to enable the viewer in the dev launcher.

## Device unbind - decision
Not implemented on purpose. Unbinding a device frees a slot but does not remove the WireGuard/Xray
credential already provisioned on the gateway, so the device would keep working. Until gateway-side
removal exists, the only real cut-off is revoking the whole activation.

## Not implemented
Per-person accounts (roles use two shared secrets), per-device unbind, traffic stats,
production deployment (UI is not served by nginx yet).

## Rate limits
`GET /admin/activations[/<id>]`: 120 requests / 60 s per session; `POST .../revoke`: 30 / 60 s per
session (HTTP 429 `rate_limited`). The limiter is in-memory and per process (not distributed),
keyed by the authenticated session, not by client-supplied forwarding headers.
