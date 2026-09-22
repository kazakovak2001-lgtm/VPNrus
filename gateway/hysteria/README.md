# B46-4P - Nova Hysteria2 server foundation

Repository-side foundation only. **Nothing in this directory has been
deployed to Stockholm.** No SSH, no live server, no real certificate, no
real credentials. This mirrors `gateway/xray/README.md`'s own "foundation
only" framing exactly, adapted for Hysteria2's real architectural
differences (see below) - it does not copy Xray's design where Xray's
design does not apply.

## Layout

```
VERSION                        pinned release asset + verified sha256
fetch-hysteria-server.sh       reproducible download+verify+install (not run yet)
render_server_config.py        deterministic config.yaml renderer (see below)
tests/
  test_fetch_hysteria_server.py   real end-to-end script tests (file:// fake releases)
  test_render_server_config.py    renderer unit tests
```

Server-side Python (in `gateway/api/`, not this directory - see "Auth
backend" below for exactly why): `hysteria_provisioning.py` (identity
mint/rotate), `hysteria_store.py` (salted-hash-only storage),
`hysteria_auth_backend.py` (the auth HTTP handler function itself).
`/v1/hysteria-profile` (client-facing provisioning) is already live in
`gateway/api/handler.py` (B46-4P slice 1). None of that was touched or
duplicated by this slice.

Systemd unit: `gateway/systemd/nova-hysteria2.service` (template, not
installed).

## Why this version

Same upstream commit already pinned for the Android CHILD binary
(`libnovahysteriachild.so` - see
`docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md`'s "Native binary
packaging" section) - `e1366b173ccf5706e1e4630fe8aa654a4b574085`
(`app/v2.12.3`). Verified this pass, directly against GitHub's API (not
assumed from the tag name alone), that this tag really does resolve to
this exact commit - see VERSION's own comment for the two API calls made.

## Why a prebuilt release binary, not a from-source build

Unlike the Android child binary (built from source via
`CGO_ENABLED=0 go build .` - a mobile cross-compile with no upstream
release asset for that target), the pinned commit **does** have a real,
official, checksummed `linux/amd64` release asset
(`hysteria-linux-amd64`) matching Stockholm's actual host architecture
(AWS `eu-north-1`, standard x86_64 instance - confirmed via the B46-4P
read-only audit, not assumed). This pass fetched that asset's officially
published digest (`hashes.txt`, the release's own combined-checksum
file - Hysteria2's release process differs from Xray-core's per-asset
`.dgst` convention, but the verification discipline in VERSION is
identical: the digest is known BEFORE download, never computed-after as
its own "verification"), then independently downloaded the actual binary
and re-computed its sha256 - **it matched exactly**. See VERSION for the
full record.

## GAP - Licensing decision required (server side, newly found this pass)

The official `hysteria-linux-amd64` release asset was **byte-scanned this
pass** and does contain `sing-tun` symbols (`sing-tun.New`,
`sing-tun.NewNat`, ...) - the same GPL-3.0-or-later dependency
`docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md` and
`docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md` already found linked into
Hysteria2's own Android CHILD binary regardless of whether Nova enables
its `tun:` config. **This is the same open question, now confirmed on the
SERVER side too**: this gateway would only ever run `hysteria server`
(never `client`/`tun` mode), but the prebuilt official binary is one
multi-purpose executable that appears to link the GPL code either way.

**This pass does NOT resolve this** - per B46-2B/2C's own still-open
licensing gate for the client-side tun path, the repository owner must
make an explicit, informed decision before this binary is installed on
any production host:

1. Accept the GPL-3.0-or-later linkage as-is (the server process itself
   never invokes tun-related code paths, but the binary still contains
   the code).
2. Build a stripped, server-only binary from this SAME pinned source
   commit without tun build tags/dependencies (mirroring B46-2C's own
   "minimal Hysteria2 SOCKS5-only client" approach, but for
   `app/cmd/server.go` instead) - **not attempted this pass**.
3. Some other licensing-compliant distribution path.

`fetch-hysteria-server.sh` still fetches/verifies/installs the official
pinned asset (that part is real, verified, and reproducible) - this GAP
blocks the DECISION to actually run it in production, not the git-only
fetch/pin mechanism itself.

## Server config (`render_server_config.py`)

**Architecturally NOT the same shape as `xray_config_renderer.py`.** Xray's
REALITY inbound needs a live list of accepted client UUIDs baked directly
into its config, re-rendered on every activation/device change. Hysteria2's
own `auth.type: http` design (see
`docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md`'s "Server auth
architecture") answers with LIVE activation state on every connection
attempt via an outbound HTTP call - the server's own config never needs to
know about individual devices at all. It is a small, static file, rendered
once per infrastructure change (a port, a cert path, the auth backend's own
loopback URL), never on a provisioning-loop cadence.

`render_server_config.py` renders exactly:

```yaml
listen: :<port>

tls:
  cert: <absolute path>
  key: <absolute path>

auth:
  type: http
  http:
    url: <loopback URL>
    insecure: false
```

No `obfs:` block at all (B46-4A Finding 8 - `NONE`-only obfuscation for
this slice; an empty/fabricated Salamander password would be worse than
omitting the block). No `quic:`/`masquerade:`/`acl:`/`outbounds:`/
`resolver:`/`sniff:`/`trafficStats:`/`mimic:`/`congestion:`/`bandwidth:`/
`ech:`/`acme:` block - none of B46-4A's own design docs call for any of
these, and this module does not invent tuning values nobody specified.
`acme:` in particular is deliberately never used - this gateway's existing
Let's Encrypt lifecycle (`gateway/edge/pocvpn-cert-check.sh`) is reused
as-is, never a second, Hysteria2-managed ACME flow.

### Production values NOT decided by this repository

| Env var (deploy-time) | Feeds | Decided by |
|---|---|---|
| `NOVA_HYSTERIA2_LISTEN_PORT` | `listen:` | **#3 below - repository owner, after a real Stockholm port audit** |
| `NOVA_HYSTERIA2_TLS_CERT_FILE` | `tls.cert:` | **#4 below - depends on a real hostname + cert being issued** |
| `NOVA_HYSTERIA2_TLS_KEY_FILE` | `tls.key:` | **#4 below** |

### Values this deployment DOES get to choose (git-only, no infra decision)

| Env var | Value chosen this pass | Why this is safe to decide in git |
|---|---|---|
| `NOVA_HYSTERIA2_AUTH_BACKEND_URL` | `http://127.0.0.1:8446/internal/hysteria-auth` (see "Auth backend" below) | Loopback-only, never exposed publicly, never touches DNS/firewall/TLS - the same class of decision `gateway/xray/README.md` made for Xray's own `2053` port choice. `8446` continues the existing loopback port sequence already used by `pocvpn-api` process variants (`8443` exit, `8444` ingress, `8445` xhttp-ingress - confirmed by grep, not guessed). |

## Auth backend listener - OPEN DESIGN QUESTION (not resolved this pass)

`gateway/api/hysteria_auth_backend.py`'s `handle_auth_request` function is
real, tested, and reachable from Python - but **has no live HTTP route
anywhere**, not even an internal one. This is a genuine, newly-confirmed
GAP (distinct from `/v1/hysteria-profile`, which IS live as of the prior
B46-4P slice). Two architectures are possible; this pass does not choose
one, per the task's own "if the exact mechanism cannot be safely
determined from the repository, do not guess" instruction:

**Option A (recommended, not yet implemented): extend the existing
`pocvpn-api.service` process** with one new internal-only route
(`POST /internal/hysteria-auth`) in `gateway/api/handler.py`. `pocvpn-api`
already binds to `127.0.0.1` only (confirmed: "never public directly" -
see `gateway/xray/README.md`'s own "Current gateway occupancy" table) -
adding a path nginx's vhost never proxies achieves the exact same
"reachable ONLY from the Hysteria2 server process on the same host"
property B46-4A's own doc calls for, with **no new systemd unit, no new
process, no new port** to manage. This is the simpler, more consistent
option, but it was **not implemented this pass** - the task explicitly
scoped this slice away from touching `handler.py` except for a genuinely
necessary contract-mismatch fix, and this is a new capability, not a fix.

**Option B: a separate, dedicated minimal listener unit**, as B46-4A's
own doc's "Server deployment proposal" section originally sketched
("started by its own unit"). This project does NOT currently prepare a
systemd unit for this option - doing so would mean guessing a mechanism
(a whole second process's own shape, env vars, hardening profile) this
pass has no repository evidence to safely determine, exactly what the
task instructions say not to do. If Option B is chosen instead of A, that
unit still needs to be designed from scratch in a future pass.

**Either way**, `nova-hysteria2.service`'s own `config.yaml` merely
assumes SOME loopback URL will exist and answer - it does not depend on
which option is chosen.

## Port choice (#3) - NOT decided by this pass

Historical `34443` (`docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md`)
was a **temporary test-only port**, opened via a temporary AWS Security
Group rule for physical validation, then removed and confirmed closed -
**not** a production port decision, and this pass does not treat it as
one. No project convention was found (grepped) that names a specific
production UDP port for Hysteria2.

Technical candidates only, **not a decision**:
- A fresh, previously-unused UDP port (e.g. continuing in the `344xx`
  range for operational continuity with the one port this project has
  ever tested against) - requires a real audit of Stockholm's current
  UDP occupancy first (this pass has no SSH access - see the prior
  read-only audit's own finding).
- UDP `443` - "do not assume it's free" (B46-4A's own explicit
  instruction); would need to be confirmed genuinely unused (nothing in
  this repo currently binds UDP 443 - AWG uses UDP `51820`, XHTTP/REALITY
  use TCP - but "not found in this repo" is not the same as "confirmed
  free on the live host").

**The repository owner must make this decision after a real port audit
that this environment cannot perform (no SSH access).**

## TLS / SNI (#4) - NOT decided by this pass

Live audit finding (read-only, confirmed this pass and the prior one):
Stockholm's existing production TLS certificate (port 443, the
`pocvpn-api` HTTPS edge) is issued **only for the bare IP**
`16.170.208.231` (`ssl_certificate /etc/letsencrypt/live/16.170.208.231/...`,
`server_name _;` in `gateway/edge/nginx-pocvpn-stockholm.conf`) - not
usable as a DNS-name-shaped SNI target, which Android's own
`Hysteria2ProfileMetadata.isValidSni` (and standard QUIC/TLS SNI
practice) expects.

A SECOND real hostname already exists for Stockholm -
`edge-sthlm.aknova.pp.ua` (`gateway/edge/nginx-pocvpn-cdn-origin-stockholm.conf`),
with its own real Let's Encrypt cert. **This is NOT reusable for
Hysteria2 as-is**: it is a Cloudflare-fronted HTTPS/TCP origin for the
XHTTP ingress role specifically (`Android -> Cloudflare edge -> HTTPS
origin nginx -> loopback Xray XHTTP inbound` - confirmed from that
file's own header comment) - a completely different protocol shape
(TCP/HTTP semantics) from Hysteria2's raw UDP/QUIC, and Cloudflare does
not front arbitrary UDP/QUIC for a custom protocol the way it fronts
XHTTP. Reusing this exact hostname/cert for a second, unrelated protocol
on a different port would also be a confusing identity overload, not a
clean design.

**Technical recommendation only, not a decision**: a NEW, DISTINCT
subdomain under the SAME already-owned zone (`aknova.pp.ua` - confirmed
owned/DNS-managed by this project via the two live hostnames above, plus
`control.aknova.pp.ua`/`origin-sthlm.aknova.pp.ua` found in the live
manifest's own `cdnProviderProfile` metadata) would need to be minted -
e.g. shaped like `hy2-sthlm.aknova.pp.ua` - pointed **directly** at
Stockholm's own IP (no Cloudflare fronting, since Hysteria2 needs a real
UDP/QUIC path to the origin), with its own dedicated Let's Encrypt
certificate (HTTP-01 or DNS-01, whichever this project's existing ACME
tooling already supports - not investigated further this pass).
**No DNS record was created and no certificate was issued or requested -
both are explicitly out of scope for this slice.**

### Certificate file permissions (operational note, not resolved this pass)

Let's Encrypt's `privkey.pem` is root-only-readable by default. Whatever
mechanism eventually issues the Hysteria2 cert will also need to make it
readable by the `nova-hysteria2` service account (e.g. a certbot
deploy-hook, an ACL, or a dedicated `ssl-cert`-equivalent group) - not
something this pass resolves, flagged here so it is not silently assumed
away later.

## Signed manifest (#7) - preparation only, NOT signed this pass

See `docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md`'s own "Manifest"
section for the exact field list the eventual signing ceremony will need.
**No signing was performed, no live manifest was touched.**
