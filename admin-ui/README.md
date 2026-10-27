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

## Not implemented
Admin/viewer roles (single shared password), per-device revocation, traffic stats,
production deployment (UI is not served by nginx yet).
