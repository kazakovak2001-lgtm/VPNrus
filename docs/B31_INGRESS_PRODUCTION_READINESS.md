# B31 - production readiness for the first real ingress deployment

Closes the exact server-production-readiness gaps found while attempting to
follow `docs/B26_FIRST_INGRESS_RUNBOOK.md` against the two real, already-
approved hosts (read-only SSH inspection, no mutation): stale deployed
backend code, a missing nginx route on each host, and a port collision the
tracked `ingress.env.example` template did not account for. **Nothing in
this document has been executed. Do not run any step below without the
repository owner's explicit go-ahead, per this repository's merge/infra-
safety rule.**

## Approved architecture (repository owner, 2026-09-03)

| Role | Host | Provider | Notes |
|---|---|---|---|
| EXIT | Germany, `152.70.43.1` | Oracle Cloud | Existing production gateway - unchanged role, code upgraded only |
| INGRESS | Stockholm, `16.170.208.231` | AWS (eu-north-1) | Existing production gateway ALSO gains the ingress role - two separate processes/ports, never merged |

Ingress kind: `DIRECT_IP`. Client-facing ingress transport: VLESS REALITY
over TCP, port **2093** (approved, AWS security group `launch-wizard-1` /
`sg-0bb9db999a9411fc7`, inbound TCP 2093 from `0.0.0.0/0` - added by the
repository owner directly, not by this PR). Ingress -> exit upstream
transport: REALITY on Germany's existing port 2053 (its own EXIT-role
inbound, unchanged).

Why Stockholm-as-ingress, not Germany: colocating INGRESS and EXIT on the
SAME host would collapse "client -> INGRESS -> EXIT" into a same-host
loopback hop, proving nothing about a real two-hop relay and violating this
repository's own "never a fake logical ingress" principle (see the prior
task's STOP report). Stockholm and Germany are physically distinct hosts on
different cloud providers/regions - a genuine network hop exists between
them.

## Exact gaps found (read-only SSH inspection, 2026-09-03)

1. **Both hosts' deployed backend code predates B25-B30.** Germany's
   `/opt/pocvpn/gateway/api/handler.py` (dated 2026-09-01) and Stockholm's
   (dated 2026-08-31) both lack `/v1/relay-health` and `/v1/ingress-profile`
   entirely - `grep -c 'relay.health\|ingress.profile'` on either returned
   `0`. Current `main` (verified at `29394021ff35a829f5524edb5839cef03e733cf0`)
   already implements both handlers fully, fail-closed-by-config (503 until
   the relevant env fields are set) - **no backend Python code changes were
   needed or made by this PR**, only a code deployment gap.
2. **Neither host's tracked nginx template exposed the new routes.**
   `gateway/edge/nginx-pocvpn.conf` (Germany) had no `/v1/relay-health`
   location; `gateway/edge/nginx-pocvpn-stockholm.conf` (Stockholm) had no
   `/v1/ingress-profile` location. Both are added by this PR (exact
   `location =` blocks, GET/POST-gated respectively - see the diff).
3. **Port collision the tracked ingress template did not account for.**
   `gateway/config/ingress.env.example`'s `POCVPN_API_API_PORT` defaulted to
   `8443` - the SAME loopback port Stockholm's existing EXIT-role
   `pocvpn-api.service` already binds. Running the ingress role's OWN
   `pocvpn-api-ingress.service` with that default on the same host would
   fail to bind at startup. Fixed: the template now defaults to `8444`
   (loopback-only either way - never publicly exposed), matching the new
   nginx `/v1/ingress-profile` location's own `proxy_pass`.
4. **`NOVA_INGRESS_SERVER_PORT` template default (`8443`) never matched
   any actually-approved port.** Fixed: now defaults to `2093`, the
   approved and firewalled value, with an explicit non-collision comment
   against Stockholm's existing 2053/2083/51820/8443/8444.
5. **`api.env.example` never documented the two EXIT-side relay fields**
   (`POCVPN_API_STATIC_RELAY_CLIENTS_FILE`, `POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE`)
   that `gateway/api/config.py` already supports - added, blank by
   default (byte-for-byte the pre-B26 behavior until filled in).
6. **No upgrade tooling existed** for moving an already-deployed backend
   forward to a newer `main` without risking currently-live traffic - every
   existing script (`install-ingress-role.sh`, `gateway/DEPLOYMENT.md`)
   only ever describes a FRESH install. Added:
   `gateway/scripts/deploy-backend-update.sh` (backup -> code copy ->
   import-sanity validate -> restart -> loopback smoke test -> printed
   rollback command on any failure; never auto-rolls-back, never touches
   secrets, never restarts an unrelated transport).

## Port map (both hosts, post-deployment)

| Port | Host | Bound to | Exposure |
|---|---|---|---|
| 22 | both | sshd | public (unchanged) |
| 80 | both | nginx (ACME only) | public (unchanged) |
| 443 | both | nginx | public (unchanged) - now also routes `/v1/relay-health` (Germany) / `/v1/ingress-profile` (Stockholm) |
| 2053 | both | existing EXIT-role Xray REALITY | public (unchanged) |
| 2083 | both | existing EXIT-role Xray TLS_TCP | public (unchanged) |
| 51820/udp | both | AmneziaWG | public (unchanged) |
| 8443 | both | existing EXIT-role `pocvpn-api.service` | **loopback-only** (unchanged) |
| **2093** | Stockholm only | **new** ingress-role Xray REALITY inbound (`nova-xray-ingress.service`) | **public - the ONE new inbound rule, already approved and added by the repository owner** |
| **8444** | Stockholm only | **new** ingress-role `pocvpn-api-ingress.service` | **loopback-only - no firewall change needed** |

Nothing on Germany changes its exposure surface at all - `/v1/relay-health`
rides the already-public 443, proxied to the already-loopback-only 8443.

## Deployment procedure (NOT executed by this PR)

Run in this order. Steps 1-2 are code/config-only and safe to rehearse on a
non-production host first if desired; steps 3+ touch live infrastructure.

### 1. Upgrade Germany's backend code (EXIT relay-health)

```bash
# on Germany, as root, with a checkout of this PR's branch (post-merge, at
# whatever commit the owner approves for deployment) at /tmp/nova-vpn-src:
/tmp/nova-vpn-src/gateway/scripts/deploy-backend-update.sh \
    --repo-root /tmp/nova-vpn-src --service pocvpn-api.service --port 8443
```

Then, ONLY after that script reports success:

```bash
sudo nginx -t   # validate BEFORE installing the new vhost file
sudo install -o root -g root -m 0644 \
    /tmp/nova-vpn-src/gateway/edge/nginx-pocvpn.conf \
    /etc/nginx/sites-available/pocvpn
sudo nginx -t   # validate the INSTALLED file too
sudo systemctl reload nginx
curl -s -o /dev/null -w '%{http_code}\n' https://152.70.43.1/v1/relay-health   # expect 503 (relay_health_not_configured) until the fields below are set - NOT connection-refused
```

`POCVPN_API_STATIC_RELAY_CLIENTS_FILE` / `POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE`
in `/etc/pocvpn/api.env` are filled in later, at
`docs/B26_FIRST_INGRESS_RUNBOOK.md` step 5 (exit authorization) - not part
of this code/nginx upgrade.

### 2. Upgrade Stockholm's existing EXIT-role backend code

Same script, same shape, against Stockholm's EXISTING `pocvpn-api.service`
(this does not touch the ingress role at all - that is installed fresh in
step 3):

```bash
/tmp/nova-vpn-src/gateway/scripts/deploy-backend-update.sh \
    --repo-root /tmp/nova-vpn-src --service pocvpn-api.service --port 8443
```

### 3. Install the ingress role on Stockholm

Follow `docs/B26_FIRST_INGRESS_RUNBOOK.md` steps 1-6 verbatim
(`install-ingress-role.sh`, REALITY keypair, `provision_relay_upstream_identity.py`,
`/etc/pocvpn/ingress.env` filled in from this PR's updated
`gateway/config/ingress.env.example` - `NOVA_INGRESS_SERVER_PORT=2093`,
`POCVPN_API_API_PORT=8444` already correct in the template), with Germany
as the pinned EXIT (step 5 there is Germany's own operator action, using
this PR's `POCVPN_API_STATIC_RELAY_CLIENTS_FILE` field).

Then install the new nginx location on Stockholm the same way as step 1:

```bash
sudo nginx -t
sudo install -o root -g root -m 0644 \
    /tmp/nova-vpn-src/gateway/edge/nginx-pocvpn-stockholm.conf \
    /etc/nginx/sites-available/pocvpn
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Post-deployment smoke test (both hosts, no secrets required)

```bash
# Germany - existing routes must be byte-for-byte unaffected:
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://152.70.43.1/v1/peers        # expect same as before (401/415, never connection-refused)
curl -s -o /dev/null -w '%{http_code}\n' https://152.70.43.1/v1/manifest             # expect same as before
curl -s -o /dev/null -w '%{http_code}\n' https://152.70.43.1/v1/relay-health         # expect 401 (unauthorized - no token) once configured, 503 until then

# Stockholm - existing routes unaffected, new route reachable:
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://16.170.208.231/v1/peers
curl -s -o /dev/null -w '%{http_code}\n' https://16.170.208.231/v1/manifest
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://16.170.208.231/v1/ingress-profile   # expect 401/415 (reachable, auth/body checked - never connection-refused, never proxied to 8443)

# Stockholm - new public data-plane port genuinely listening (before any
# real Xray config is even staged, this just proves the firewall rule and
# host are both reachable):
nc -zv -w 5 16.170.208.231 2093 || echo "not yet listening (expected until nova-xray-ingress.service is actually reconciled/started - see B26 runbook step 6)"
```

### 5. Continue with `docs/B26_FIRST_INGRESS_RUNBOOK.md` steps 7-20

Unchanged by this PR - physical Android verification, E2E proof, public-IP
proof, deliberate failure test, etc. Still gated on the repository owner's
explicit approval, per that runbook's own human-approval gate.

## B31A - real deployment-convergence gaps found live, closed here

The actual first Stockholm ingress-role install (performed against this
document's own procedure above) surfaced four real gaps between what
`install-ingress-role.sh`/`docs/B26_FIRST_INGRESS_RUNBOOK.md` documented
and what a real host actually needed - the operator had to correct all
four by hand, live, before the ingress role would run at all. **This PR
does not undo that already-corrected live Stockholm state** (see the
B31A ROADMAP entry) - it makes a FRESH deployment reproduce that corrected
state automatically, closing the gap between the documented procedure and
what was actually required:

1. **`/etc/pocvpn/ingress` directory ownership** - `install-ingress-role.sh`
   created it `root:root`; `pocvpn-api-ingress` (running as the `pocvpn-api`
   service account, never root) could not even traverse into it to reach
   the secret files step 3 places there, regardless of THEIR own
   ownership. Fixed: `root:pocvpn-api`, matching the regular gateway
   role's own already-correct `/etc/pocvpn/xray` convention.
2. **Secret file mode** - the runbook's own step 3/4 said `0600 root:root`;
   `ingress_preflight.py`'s `_check_file_not_world_readable` requires
   STRICT `0600` (any group/other bit at all fails, despite an unrelated
   part of that check's own error text once implying `0640` was also
   fine) and the file must be owned by `pocvpn-api` itself (the reading
   process), not merely root with `pocvpn-api` in its group. Fixed:
   runbook steps 3/4 now `chown pocvpn-api:pocvpn-api`/`chmod 0600`
   explicitly.
3. **Durable state directory ownership** - `/var/lib/pocvpn-provision-ingress`
   and its `xray/` subdirectory were `root:pocvpn-api` (read+traverse
   only); `pocvpn-api-ingress` durably WRITES into both on every real
   request (the activation/xray-identity stores directly, the staged
   candidate Xray config in `xray/`). Fixed: `install-ingress-role.sh`
   now creates both `pocvpn-api:pocvpn-api`, matching the regular gateway
   role's own `/var/lib/pocvpn-activation`/`/var/lib/pocvpn-xray`
   convention. The runbook's own store-init commands (step 6) now also
   run `sudo -u pocvpn-api` rather than plain root, for the same reason -
   a store/lock file `init`-ed as root could not be written by the
   service afterward either, even once the containing directory's own
   ownership was fixed.
4. **Missing activation-global-lock init step** - the runbook's step 6
   never created `NOVA_INGRESS_ACTIVATION_GLOBAL_LOCK_PATH` at all; the
   very first real `/v1/ingress-profile` request failed with "activation
   lock not found - run 'init' first". Fixed: step 6 now calls
   `xray_activation.init_activation_lock(...)`, the same idempotent
   helper `_fixtures.py`'s own test setup already used.
5. **Xray binary path** - `gateway/systemd/nova-xray-ingress.service`
   hardcodes `ExecStart=/opt/pocvpn/xray/v26.7.28/xray`, but neither real
   production host has anything at that path (both predate this pinned-
   path convention - their own EXISTING exit role runs a differently-
   versioned `/usr/local/bin/xray`). A manual `ln -s /usr/local/bin/xray`
   symlink (what the operator actually did live, to unblock testing) would
   silently point the ingress role at an unpinned, unverified binary -
   the project's own pinned-core requirement (`gateway/xray/VERSION`)
   forbids exactly that. Fixed: `install-ingress-role.sh` now runs the
   repository's own real, checksum-and-commit-verified
   `gateway/xray/fetch-xray-server.sh` to converge a genuine, independently-
   fetched, pinned binary at the canonical path - never reusing or
   depending on whatever `/usr/local/bin/xray` a host happens to already
   have for an unrelated role. `ingress_preflight.py` gained a matching
   check (`xray binary matches the pinned commit`) - its own
   `_XRAY_BIN_PATH_EXPECTED_PREFIX` constant existed before this fix but
   was never actually enforced by anything, dead code found live.

None of these five are secrets - only ownership/mode/path facts, safe in
this document. Stockholm's own already-corrected live state was fixed by
hand during the original deployment session, verified working (server-side
relay-health proof passed), and is left as-is; a FUTURE fresh ingress host
now converges to the same corrected state automatically via this PR's
fixes to `install-ingress-role.sh`/`docs/B26_FIRST_INGRESS_RUNBOOK.md`.

## Rollback

- **Code upgrade (steps 1-2):** `deploy-backend-update.sh` prints the exact
  rollback command (`rsync` the timestamped backup back, `chown`, restart
  the service) on any validation/restart/smoke-test failure - never
  auto-executed. If a problem surfaces LATER (not caught by the script's
  own checks), the same backup at `/opt/pocvpn/gateway-backups/gateway-<timestamp>`
  is retained until an operator explicitly removes it.
- **nginx (steps 1, 3):** `nginx -t` gates every install in this document
  before `reload` - a syntax error never reaches a running nginx. To
  revert a semantically-bad-but-syntactically-valid change, reinstall the
  previous `sites-available/pocvpn` content (keep your own copy before
  step 1/3's `install` - this document does not automate an nginx-level
  backup, since `/etc/nginx/sites-available/pocvpn` is a single small
  tracked file already versioned in this repository's own git history).
- **Ingress role (step 3):** `systemctl disable --now pocvpn-api-ingress.service nova-xray-ingress.service`
  removes the new role entirely without touching Stockholm's existing
  EXIT-role `pocvpn-api.service`/`nova-xray.service` at all (separate
  units, separate users, separate config trees - see
  `install-ingress-role.sh`'s own isolation docs).
- **Firewall (AWS security group):** removing the TCP 2093 inbound rule
  the repository owner added is a manual console action, symmetric with
  how it was added - not automated by this repository.

## What this PR does NOT do

- Does not deploy anything to either host (all of the above is a written
  procedure, not executed).
- Does not fold any real ingress descriptor into the signed production
  manifest (`docs/B26_FIRST_INGRESS_RUNBOOK.md` step 8, still gated on
  steps 1-7 physically succeeding first).
- Does not mint or apply any real relay identity/secret (`provision_relay_upstream_identity.py`/
  `apply_relay_upstream_identity.py` remain the B26 runbook's own human
  steps 4-5).
- Does not touch B21/B22 or any existing Direct/AWG/manual transport path.
- Does not verify Russia hard-whitelist bypass - **remains UNVERIFIED**,
  unaffected by this PR either way.
