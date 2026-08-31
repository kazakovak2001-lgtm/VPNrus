# B8B1C3 - production-like local composition

This document records the production filesystem/ownership model, the
systemd unit design, and the empirical results of the local/WSL-only E2E
harness at `gateway/systemd/tests/run_c3_e2e_tests.sh` that proves the full
chain:

```
HTTP -> bearer token auth -> non-root pocvpn-api -> sudo -n boundary
     -> root-owned wrapper -> root fixture provisioning helper
     -> HTTP 201 / 200
```

No Oracle deployment, no HTTPS/nginx/Caddy, and no real AWG mutation are
part of this slice - see `gateway/privileged/README.md` for the C2
privilege-boundary design this slice deploys for real, and B8B1A/B8B0 for
the real AWG mutation semantics this slice deliberately does not re-prove
(the E2E harness uses an isolated fixture helper, not `provision-peer.sh`
or `awg0.conf` - see the harness's own header comment for why).

## 1. Production filesystem / ownership model

```
/opt/pocvpn/gateway/                         root:root   dirs 0755 files 0644
    application code (this repo's gateway/ tree) - NOT writable by pocvpn-api

/usr/local/libexec/pocvpn-provision-peer     root:root   0750
    the one root-owned privileged wrapper (see gateway/privileged/)

/etc/sudoers.d/pocvpn-api                    root:root   0440
    the sudo rule granting pocvpn-api -> the wrapper only (see gateway/privileged/)

/etc/pocvpn/                                 root:root   0755
/etc/pocvpn/api.env                          root:pocvpn-api  0640
    API configuration - pocvpn-api may READ this, never write it
    (see gateway/config/api.env.example for the tracked template)

/var/lib/pocvpn-provision/                   root:pocvpn-api  0750
/var/lib/pocvpn-provision/enrollment-tokens.json   root:pocvpn-api  0640
/var/lib/pocvpn-provision/.tokens.lock             root:pocvpn-api  0640
    durable enrollment-token state - pocvpn-api opens the lock O_RDONLY,
    takes LOCK_SH, and reads the store; it has no write-capable code path
    at all (see gateway/api/tokens.py's own docstring) - directory 0750
    additionally prevents it from even listing/creating siblings

/etc/amnezia/amneziawg/                      root:root   (root-only, no group grant)
/etc/amnezia/amneziawg/awg0.conf             root:root   0600
    pocvpn-api MUST NOT have direct filesystem access here - see
    gateway/privileged/README.md's "What pocvpn-api must NEVER do"
```

`pocvpn-api`'s own OS identity: a `system` user, no interactive shell
(`/usr/sbin/nologin`), no login password, no writable home
(`--no-create-home`). This slice does not install that identity anywhere
real - the E2E harness creates and fully removes a disposable equivalent
(`pocvpn-c3-test`) for every run; see the harness script's own
setup()/cleanup() for the exact idempotent, fail-closed, never-touch-an-
existing-identity sequence a future real installer must reproduce.

## 2. Token store initialization (production sequence)

```
# as operator/root:
python3 gateway/tools/enrollment_tokens.py \
    --store /var/lib/pocvpn-provision/enrollment-tokens.json init
chown root:pocvpn-api /var/lib/pocvpn-provision \
    /var/lib/pocvpn-provision/enrollment-tokens.json \
    /var/lib/pocvpn-provision/.tokens.lock
chmod 750 /var/lib/pocvpn-provision
chmod 640 /var/lib/pocvpn-provision/enrollment-tokens.json \
    /var/lib/pocvpn-provision/.tokens.lock
```

Confirmed by the E2E harness (`test_dac_must_succeed` / `test_dac_must_fail`,
using this exact init -> re-own sequence): the service user can read the
store and take `LOCK_SH`; it cannot write, chmod, delete, or replace the
store or lock, and cannot create a new file anywhere in the directory.
Every denied attempt was re-verified to leave the store's SHA-256 hash
unchanged.

## 3. `gateway/config/api.env.example`

Tracked, no real secrets - see that file directly. Every key maps 1:1 to
`gateway/api/config.py`'s `load_config()`. The bind host is never
configurable from this file (or anywhere) - `gateway/api/server.py` hard-
codes `127.0.0.1`, confirmed still true by the E2E harness's localhost-only
listener check (below).

## 4. systemd unit (`gateway/systemd/pocvpn-api.service`)

`ExecStart=/usr/bin/python3 -m api.server` with
`WorkingDirectory=/opt/pocvpn/gateway` was verified locally against the
real repository layout before being written into the tracked unit (not
assumed): running `python3 -m api.server` with cwd set to `gateway/`
correctly imports the `api` package and binds only `127.0.0.1:<port>`.

### Hardening directives - empirical record

Every directive below was added to the E2E harness's systemd unit (which
carries the identical hardening block to the tracked production template -
only `User`/`Group`/`WorkingDirectory`/`EnvironmentFile`/`ReadWritePaths`
differ) and the FULL HTTP -> sudo -> root-helper chain was re-proven with
it present, not assumed compatible:

| Directive | Kept? | Why |
|---|---|---|
| `NoNewPrivileges=yes` | **Never added** | This service's only privileged operation IS `sudo -n <wrapper>` - sudo's setuid-root re-exec is itself a "new privilege" the kernel would refuse under this flag. Explicitly forbidden by the B8B1C3 requirements; confirmed by design, not by a failing test (adding it would trivially break every provisioning request into `internal_error`, and doing so was not worth the resulting outage of the harness to prove something already structurally certain from how `execve`/`prctl(PR_SET_NO_NEW_PRIVS)` and setuid interact). |
| `CapabilityBoundingSet=` | **Omitted (not emptied)** | An empty bounding set would strip capabilities (`CAP_SETUID`/`CAP_SETGID` etc.) `sudo`'s own setuid-root re-exec needs before it can drop them itself. No minimal non-empty set was derived empirically this slice - omitting it (full bounding set) is the honest "not yet hardened here" state rather than a guessed set that might silently break the chain under a different sudo/PAM build. |
| `RestrictSUIDSGID=yes` | **Omitted** | Would neutralize the setuid bit on `/usr/bin/sudo` itself inside this unit's namespace - directly breaks the one thing this service depends on. |
| `PrivateTmp=yes` | Kept | No interaction with the sudo chain; the E2E harness's own disposable paths deliberately live OUTSIDE `/tmp` (`/opt`, `/etc`, `/var/lib`) specifically because `PrivateTmp` would otherwise hide a host-`/tmp`-based `WorkingDirectory` from the service - this was caught during harness construction, not left implicit. |
| `ProtectHome=yes` | Kept | Chain re-verified working; service never touches any home directory. |
| `ProtectKernelTunables=yes` | Kept | Chain re-verified working. |
| `ProtectKernelModules=yes` | Kept | Chain re-verified working. |
| `ProtectControlGroups=yes` | Kept | Chain re-verified working. |
| `RestrictNamespaces=yes` | Kept | Chain re-verified working; `sudo`/the root child do not need to create new namespaces. |
| `LockPersonality=yes` | Kept | Chain re-verified working. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | Kept | Chain re-verified working; the service only ever needs a TCP listen socket and local subprocess I/O. |
| `MemoryDenyWriteExecute=yes` | **Omitted** | Not proven safe against this CPython build/version this slice - the risk of a false "hardened" claim outweighs the value of guessing; a future slice can add and re-run the E2E harness to confirm before shipping it. |
| `ProtectSystem=strict` + `ReadWritePaths=/etc/amnezia/amneziawg` | Kept, with exactly one path exception | See "ProtectSystem + DAC proof" below - this is the directive the B8B1C3 requirements specifically call out as needing empirical, dual-sided proof. |

## 5. `ProtectSystem=strict` + DAC proof (both statements, simultaneously)

**Claim A** (mount namespace): the root child spawned via `sudo -n` from
inside this unit - despite `ProtectSystem=strict` making the rest of the
filesystem read-only for the unit - CAN still write inside the one
`ReadWritePaths`-exempted directory, because it inherits the unit's mount
namespace and that one path is the explicit writable exception.

**Claim B** (Unix DAC): `pocvpn-api`'s own (non-root) process, running
inside that SAME namespace, CANNOT write there directly - the mount being
writable does not override the directory's `root:root 0700`-equivalent DAC
mode, which grants that process no permission at all.

The E2E harness proves both in one test (`test_protectsystem_and_dac_together`
in `gateway/systemd/tests/run_c3_e2e_tests.sh`), against a disposable
fixture directory standing in for `/etc/amnezia/amneziawg` (see "What this
harness deliberately does NOT touch" below for why a fixture, not the real
path, is used):

1. As the service's own OS user, attempt to write directly into the
   `ReadWritePaths`-exempted fixture directory -> **denied** (DAC).
2. Send a real provisioning HTTP request for a fresh key through the full
   chain -> the sudo root child writes the new peer into that same
   directory -> **succeeds**, and the write is durably visible afterward.

Both held simultaneously in every harness run this slice completed. The
production unit template (`gateway/systemd/pocvpn-api.service`) applies the
identical mechanism to the real `/etc/amnezia/amneziawg` path; validating
that exact path is deferred to real deployment (out of scope here - see
"Global constraints").

## 6. Local deployment / test architecture

`gateway/systemd/tests/run_c3_e2e_tests.sh` (LOCAL/WSL-ONLY, must run as
root):

- Creates a disposable system user (`pocvpn-c3-test`), a disposable copy of
  `gateway/` under `/opt/pocvpn-c3-test/gateway` (root-owned, CRLF-
  normalized into the disposable copy only - see the repo-wide CRLF note
  below, never touching the tracked source tree), a disposable env file, a
  durable token store initialized via the real B8B1C1 operator CLI, a
  disposable root-owned AWG-fixture directory and fixture provisioning
  helper (implementing the exact B8B1A `created`/`existing` contract
  against its own state file only), a test copy of the tracked wrapper
  (only `PROVISION_SCRIPT` substituted - same established pattern as
  `gateway/privileged/tests/run_sudo_tests.sh`), a disposable
  `/etc/sudoers.d/pocvpn-c3-test` drop-in validated with `visudo -cf`
  before install, and a disposable systemd unit carrying the identical
  hardening block as the tracked production template.
- Runs the full proof suite (sections 7-9 below), then tears down
  EVERYTHING via an `EXIT` trap - user, unit (`systemctl disable` +
  `daemon-reload` after removal), sudoers drop-in, wrapper, fixture helper
  and directory, env file, app-code copy, token-store directory - on
  success or failure alike.
- Refuses to run (every check marked `SKIPPED`, exit 0, never a false
  PASS) if not root, if any required tool is missing, if PID 1 is not
  systemd, or if ANY of its disposable paths already exists - it never
  overwrites something it cannot positively identify as its own leftover.

### What this harness deliberately does NOT touch

Per the B8B1C3 constraints: never `/opt/pocvpn`, never
`/etc/amnezia/amneziawg`, never `/usr/local/libexec/pocvpn-provision-peer`,
never `/etc/sudoers.d/pocvpn-api`, never the real `pocvpn-api.service`,
never `provision-peer.sh` itself, never `systemctl reload`s the real
`awg-poc.service`. Every one of those has a `pocvpn-c3-test`-prefixed
disposable stand-in instead. This is the same isolation discipline
`gateway/privileged/tests/run_sudo_tests.sh` (C2) already established -
C3 extends it to a real systemd unit instead of a bare `sudo -n` call.

## 7. Full HTTP -> sudo -> root-helper E2E result

- First request (fresh key, valid token bound to it) -> **HTTP 201**,
  `state=created`, deterministic fixture IP.
- Second, identical request (retry semantics) -> **HTTP 200**,
  `state=existing`, the SAME IP - no second allocation.
- Confirmed the sudo root child, not the API process itself, performed the
  fixture-state write (Unix DAC on the fixture path denies the API process
  entirely - see section 5).

## 8. Token issue / revoke / live-reload result

- Token issued via the real `gateway/tools/enrollment_tokens.py issue`
  command against the durable store.
- Revoked via the same tool's `revoke` command **while the service kept
  running** - no restart.
- The very next request with that token -> **HTTP 401** - proves the
  reader (`gateway/api/tokens.py`) re-reads durable state per request
  rather than caching it in the running process.

## 9. Filesystem permission results

All of section 15's required successes and required failures held; see
section 2 above for the exact operations and the hash-stability
confirmation.

## 10. Localhost-listener proof

`ss -ltn` on the running unit showed exactly one `LISTEN` entry, on
`127.0.0.1:<port>` - zero entries on `0.0.0.0:<port>` or `[::]:<port>`.
A real TCP connect attempt to the WSL VM's own external-facing interface
address on the same port was refused (connection refused, not just
"no source-inspection claim").

## 11. Service restart result

`systemctl restart` on the running unit -> service returns `active`
(and re-confirmed listening on `127.0.0.1` only); the token store's
SHA-256 hash was byte-identical before and after; the already-revoked
token (section 8) was re-confirmed still rejected (401) after the
restart - proving no authorization state ever lived only in the prior
process's memory.

## 12. Failure-path results

Each of the following was independently fault-injected against the
running unit and confirmed to fail closed, never to falsely succeed, with
every temporary mutation restored before the next check ran:

- Missing `EnvironmentFile` -> service never becomes active.
- Malformed config value (non-numeric port) -> `ConfigError` ->
  `SystemExit(1)` before ever opening the listener (checked by polling
  for an actual listening socket, not by racing `systemctl is-active`
  against `Type=simple`'s "active the instant ExecStart forks" semantics -
  see the harness's own comment on this for why the naive check would be
  a false negative).
- Missing token lock -> request fails closed with **500**, never
  misread as 401.
- Unreadable token store (mode `000`) -> **500**.
- Missing privileged wrapper -> provisioning request fails closed with
  **500**, no false success.
- Sudo denied (sudoers drop-in temporarily removed) -> **500**.
- Root fixture helper forced non-zero exit -> **500**, and the fixture
  state file was confirmed to have NO new entry for that key (no partial/
  false state).
- Root fixture helper made to sleep past `SUBPROCESS_TIMEOUT_SECONDS` ->
  **504**.
- Idle restart (section 11) does not corrupt durable state.

## 13. Journal / secret review result

`journalctl -u <unit>` was scanned for: the plaintext bearer token, an
`Authorization:` header, a `PrivateKey` marker, the raw JSON request body,
and the full concatenated token-store contents - **none appeared**.

One expected, non-defect finding: the **full public key** DOES appear once
per provisioning request, in `sudo`'s own root-accountability audit line
(`<user> : PWD=... ; USER=root ; COMMAND=<wrapper> <public-key>`). This is
`sudo` logging its own invocation for accountability - by design, a
security feature, not an application log - emitted with `sudo` as the
syslog identifier, not `pocvpn-api`. It surfaces under `journalctl -u
<unit>` only because the wrapper process runs inside that unit's cgroup.
Confirmed via a standalone diagnostic (`systemd-run` + `sudo -n` outside
the harness) that this is inherent to `sudo` itself, not something
`gateway/privileged/pocvpn-provision-peer` or `gateway/api/handler.py`
introduce - both were re-confirmed to still log only `pubkey_prefix[:8]`/
`token_digest[:8]`, never the raw values, on their own account. A
WireGuard/AmneziaWG public key is not confidential the way a bearer token
or private key is (it is designed to be shared), so this is treated as an
accepted, documented characteristic of the sudo boundary, not a defect -
see "Unresolved risks" for the one case where this framing could still
matter operationally.

## 14. Regression results

All pre-existing suites re-run against this slice's changes (from a
CRLF-normalized throwaway copy for the two suites affected by the repo's
pre-existing, unrelated Windows-checkout CRLF artifact in
`gateway/lib/common.sh` and `gateway/config/awg-profile.env` - see
"CRLF note" below; not touched by this slice):

- API baseline: 122 PASS
- Tools: 48 PASS
- Gateway: 56/56 PASS
- Wrapper: 12/12 PASS
- C2 sudo: 11/11 PASS, 0 skipped
- **New C3 systemd/E2E suite: 18/18 PASS, 0 skipped**

## 15. CRLF note

`gateway/lib/common.sh` and `gateway/config/awg-profile.env` are checked
out with CRLF line endings in this Windows-hosted worktree (no
`.gitattributes` pins line endings repo-wide), which breaks `bash` when
those files are sourced directly from the Windows-mounted path under WSL.
This is a pre-existing, environment-caused artifact unrelated to B8B1C3 -
confirmed by re-running the affected suites against a throwaway,
`sed 's/\r$//'`-normalized copy (never the tracked files), which passes
cleanly. Per the B8B1C3 constraints, this slice does not touch
`.gitattributes` or perform any tracked CRLF cleanup - the E2E harness
applies the same throwaway normalization to its own disposable app-code
copy for the same reason. Recorded here as a separate future repo-hygiene
item, not fixed in this slice.

## Proven locally vs. not yet verified on Oracle

Everything in this document and the E2E harness's results is **PROVEN
LOCALLY** (WSL/Ubuntu, real systemd, real sudo, real DAC) against
disposable, fixture-based stand-ins. **No Oracle deployment has been
performed or attempted as part of this slice** - this repo has not
connected to, modified, or even read the state of the Oracle host at any
point in B8B1C3.

The following are explicitly **NOT YET VERIFIED ON ORACLE** and MUST NOT
be assumed to match this document's templates until checked against the
live host:

- the actual `awg0.conf` peer-block marker placement and content on the
  live gateway (`# --- PEERS BEGIN/END ---`, existing peer entries) -
  `gateway/lib/peer_mutations.sh`'s marker validation fails closed if
  these don't match what B5/B8A/B8B0 actually wrote there
- the exact live systemd service name for the AWG interface (this
  document and `gateway/config/poc.env` assume `awg-poc.service` /
  `awg0` - unconfirmed against the live host's actual unit)
- live filesystem ownership of `/opt/pocvpn`, `/etc/amnezia/amneziawg`,
  and any existing token/config state under them
- live binary locations (`/usr/local/bin/awg`, `/usr/local/bin/awg-quick`,
  `/usr/bin/sudo`, `/usr/bin/python3` and its actual version) - this
  document's paths are the B5/build-awg.sh install targets, not
  independently re-confirmed live
- the live host's actual firewall layout - `gateway/nftables/
  pocvpn.nft.template` assumes nftables; whether the live host runs
  nftables cleanly alongside (or instead of) any pre-existing iptables
  rules is unconfirmed
- the exact AWG versions actually running live vs. the pinned
  `amneziawg-go`/`amneziawg-tools` tags in `gateway/build-awg.sh`
- whether `gateway/systemd/pocvpn-api.service`'s `ReadWritePaths=
  /etc/amnezia/amneziawg` and this document's ownership model are
  actually compatible with whatever is presently on disk at that path on
  the live host - proven here only against a disposable fixture
  directory with the identical mechanism, never against the literal path

**Before any real deployment**, a **read-only** live reconciliation pass
against the Oracle host is required to confirm every item above, BEFORE
any file is installed, any user is created, or any unit is enabled there.
That reconciliation is out of scope for B8B1C3 (which is explicitly
LOCAL/WSL-only) and is not performed by this document, this harness, or
any script in this slice.

## Unresolved risks

- **`CapabilityBoundingSet=`/`RestrictSUIDSGID=` were not tightened** -
  the production unit ships with the full default capability bounding set
  for this service, because no minimal working set was derived
  empirically this slice (see the hardening table). A future slice should
  capability-trace an actual `sudo -n <wrapper>` invocation under this
  unit (e.g. via `capsh`/`getpcaps` on the running child, or iterative
  `CapabilityBoundingSet=` narrowing with the E2E harness as the pass/fail
  oracle) rather than guess.
- **`MemoryDenyWriteExecute=yes` was not evaluated** - omitted rather than
  tested false-safe; a future slice should add it and re-run the E2E
  harness before shipping it.
- **Full public keys appear in `sudo`'s own audit log line** (section 13).
  Accepted here because AmneziaWG/WireGuard public keys are not
  confidential. If this project later provisions peers using an identifier
  the operator wants NEVER logged even in an audit trail (unlikely for a
  public key, but worth flagging), the only real fix is architectural -
  e.g. having the wrapper accept a short-lived opaque handle instead of
  the raw key on its command line - not a logging suppression, which would
  degrade the root-action audit trail itself.
- **`ReadWritePaths=/etc/amnezia/amneziawg` validated against a fixture
  path, not the literal real path** - per the B8B1C3 constraint against
  touching real gateway state. The mechanism (mount-writable exception +
  DAC-restricted directory, both proven to hold together) generalizes
  directly, but the literal path has not itself been exercised under this
  exact unit. Real deployment is the first time it will be.
- **No production installer script yet** - this slice intentionally ships
  templates (`gateway/systemd/pocvpn-api.service`,
  `gateway/config/api.env.example`) plus this document and a tested local
  harness, not an installer, per the B8B1C3 preference for that over a
  premature Oracle-specific script. A real install still requires an
  operator to: create the `pocvpn-api` system user, lay out `/opt/pocvpn`,
  install the wrapper/sudoers/unit/env file with the ownership in section
  1, and run `gateway/tools/enrollment_tokens.py init` - none of which is
  automated by this slice.

## Deploying a second gateway (e.g. Stockholm)

B14 (2026-08-31) - this entire codebase (`gateway/api/*.py`) is already
gateway-agnostic: every gateway-specific fact (its own AWG public key,
port, tunnel IP, REALITY/TLS keys, port numbers, etc.) is read from
`POCVPN_API_*` environment variables (`gateway/api/config.py`) - there is
no Germany-specific hardcoding anywhere in this package (audited as part
of B14; confirmed by a full grep of `gateway/api/`). Supporting a second
gateway - Stockholm, or any future one - therefore needs **zero code
changes here**. It is purely a deployment action:

1. Provision a second VPS (already done for Stockholm - AWS eu-north-1,
   `16.170.208.231` - see `docs/ROADMAP.md`'s Gateway Pool row for its
   physical AWG/REALITY/TLS_TCP validation history).
2. Follow every step in this document exactly as for the first gateway,
   but on that VPS, with `gateway/config/api.env.example` filled in from
   **that gateway's own** facts (its own AWG keypair/tunnel IP, its own
   REALITY keypair, its own TLS certificate) - never Germany's values
   copied over, and never a shared/federated identity between the two.
3. The Android client already has the request-side of this wired (B14):
   `MainViewModel.activateDevice(credential, ProductionGatewayId.STOCKHOLM)`
   posts to `ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost`'s own
   `/v1/activate`/`/v1/xray-profile` - once step 2 is live there, a real
   activation attempt will succeed with no further client-side change.

**As of this writing, step 1 is done and step 2 has NOT been performed
for Stockholm** - no `pocvpn-api` instance is deployed there, so a real
Stockholm activation attempt currently fails closed with a network error
(connection refused/timeout), never a fabricated success. This is a
genuine operator/deployment action, deliberately not performed by any
automated change - see `docs/ROADMAP.md`'s own `multi-provider gateway
infrastructure` row for the current, authoritative status of this gap.
Performing it does not require and must not trigger allocating a new
Elastic IP or any other paid AWS resource unless that has been separately,
deliberately approved - see the Gateway Pool row's own addressing-
stability note for why Stockholm's current address is not yet treated as
durable.

## Deploying the signed manifest (B17, 2026-09-01)

`GET /v1/manifest` is now live on BOTH production gateways, serving the
exact production-signed artifact (`gateway/tools/endpoint-manifest-2026-09-01.bin`,
see `docs/B12_MANIFEST_KEY_CEREMONY.md`'s "Production ceremony (B17)"
section) byte-for-byte, verified externally (HTTPS 200, exact sha256
match on both hosts, valid Ed25519 signature, tampered/wrong-key rejected,
POST rejected at the nginx edge). Deployment steps performed:

1. `sudo install -o root -g pocvpn-api -m 0640 endpoint-manifest-2026-09-01.bin /etc/pocvpn/endpoint-manifest.bin`
   on each VPS (same restrictive ownership as this host's other
   `/etc/pocvpn/*` secrets - the artifact itself is public, but there is
   no reason to widen permissions unnecessarily).
2. `POCVPN_API_MANIFEST_PATH=/etc/pocvpn/endpoint-manifest.bin` appended
   to each host's `/etc/pocvpn/api.env`, then `systemctl restart pocvpn-api`.
3. A `location = /v1/manifest { limit_except GET { deny all; } ... }`
   block added to each host's nginx vhost (see
   `gateway/edge/nginx-pocvpn.conf`/`nginx-pocvpn-stockholm.conf`, now
   tracked with this route), same proxy shape as `/v1/activate`/
   `/v1/xray-profile`, then `nginx -t && systemctl reload nginx`.

**Real drift found during this deployment**: Frankfurt's deployed
`/opt/pocvpn/gateway/api/handler.py`/`config.py` predated this repo's own
B12 manifest support entirely (a plain file copy, not a git checkout - it
has no `.git` directory at all) - zero mentions of "manifest" anywhere in
the running code. Stockholm's deployed copy already had it (deployed more
recently, B15). Rather than replace Frankfurt's entire `gateway/api/*.py`
wholesale against a live server already handling real activation/
xray-profile traffic - a much larger, riskier change - only the minimal
`_PATH_MANIFEST` dispatch branch, `_handle_manifest`/`_write_binary`
methods, and `AppConfig.manifest_path` field were hand-grafted onto
Frankfurt's EXISTING deployed files (backed up alongside the originals as
`handler.py.backup-b17-<timestamp>`/`config.py.backup-b17-<timestamp>` in
place), verified with `python3 -m py_compile` before installing, and
confirmed via `journalctl`/external curl that `/v1/activate`/
`/v1/xray-profile` behavior was unaffected. **Frankfurt's control-plane
code otherwise remains behind this repo's HEAD** - a full, reviewed
redeployment of `gateway/api/*.py` to Frankfurt (bringing it byte-for-byte
current, not just the manifest route) is a distinct, separate future
slice, not performed here.
