# B46-4P - Nova Hysteria2 server foundation

Repository-side foundation only. **Nothing in this directory has been
deployed to Stockholm.** No SSH, no live server, no real certificate, no
real credentials. This mirrors `gateway/xray/README.md`'s own "foundation
only" framing exactly, adapted for Hysteria2's real architectural
differences (see below) - it does not copy Xray's design where Xray's
design does not apply.

## Corrections this pass

**Real contract bug found and fixed**: `gateway/api/handler.py`'s
`_handle_hysteria_profile_inner` was returning `server_address: cfg.endpoint_host`
- the SAME shared bare-IP field every other transport (Xray REALITY/TLS)
uses. This slice's own "Production endpoint contract" decision (below)
requires Hysteria2 to use a DEDICATED hostname distinct from
`endpoint_host` - had this not been fixed, the very first real deployment
naming that dedicated hostname in the signed manifest would have made
Android's `Hysteria2ProfileProvisioner.provision` reject every response
as `Mismatched` (its own `server_address`-vs-pinned-`host` cross-check
would never agree with the still-bare-IP response). Fixed: `server_address`
is now `cfg.hysteria2_sni` - the SAME value as the `sni` field - since,
unlike REALITY's deliberate camouflage-vs-dial-target split, Hysteria2 has
no camouflage concept and its dial address and TLS SNI are correctly the
same value. Covered by an updated assertion in
`gateway/api/tests/test_hysteria_profile_endpoint.py` (now explicitly
asserts `server_address != endpoint_host`, not just `== hysteria2_sni`,
so a future regression back to the old behavior fails loudly).

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

## Licensing decision gate (server side) - deep audit this pass

Full technical evidence report - **no legal conclusion is drawn**. Every
row below was verified directly against upstream source/release/API at
the exact pinned commit/release, not inferred from a blog post or a
generic "is X GPL" search.

| Item | Evidence |
|---|---|
| Hysteria2 (`app` module) license | **MIT** - `app/LICENSE.md` at commit `e1366b17...`, fetched and read directly: standard MIT text, copyright "Toby" (upstream maintainer), 2023. |
| `sing-tun` license | **GPL-3.0-or-later** - `github.com/apernet/sing-tun` (an apernet-maintained fork of `sagernet/sing-tun`), pinned in `app/go.mod` at `v0.2.6-0.20250920121535-299f04629986`. `LICENSE` fetched directly at that exact pseudo-version's commit (`299f04629986`): full GPLv3-or-later text, copyright nekohasekai/sagernet, 2022. No linking exception clause present in that file. |
| Is the dependency statically linked | **Yes, unconditionally, for the whole binary** - `file` on the downloaded `hysteria-linux-amd64` asset reports "statically linked" (confirmed this pass); Go's own toolchain merges all imported packages into one executable by default (no dynamic `.so` loading for this dependency). |
| Is it used in server runtime | **No, source-level - but yes, binary-level.** `app/cmd/server.go`'s own import list (fetched and read directly) contains NO reference to `tun`/`sing-tun` at all - the `hysteria server` code path this gateway would actually invoke never calls into that dependency. However, `app/cmd/client.go` (fetched and read directly) DOES import `github.com/apernet/hysteria/app/v2/internal/tun` (which wraps `sing-tun`), and registers itself via a package-level `func init() { rootCmd.AddCommand(clientCmd) }` with **no Go build tag** gating that file - Go's linker therefore includes `client`'s (and transitively `sing-tun`'s) compiled code in the SAME single binary as `server`, regardless of which subcommand is ever invoked at runtime. Confirmed directly by byte-scanning the actual downloaded release asset: real `sing-tun.*` symbols are present (`sing-tun.New`, `sing-tun.NewNat`, ...). |
| Official alternative server-only artifact | **Does not exist.** The release's own asset list (`hashes.txt`, fetched directly) offers per-OS/arch variants (`hysteria-linux-amd64`, `hysteria-android-arm64`, ...) but no "server-only"/"no-tun" build variant for any platform - every asset is the same multi-command CLI binary. No build-tag-gated alternative source target was found in `app/cmd/` either. |
| Real impact on Nova VPN | This gateway would run `hysteria server --config ...` exclusively (see `gateway/systemd/nova-hysteria2.service`) - the GPL-covered code path is never executed at runtime by this deployment's own design. The open question is narrower and purely about **distribution**: does shipping/running a single statically-linked binary that CONTAINS GPL-3.0-or-later object code (even though this deployment's own configuration never reaches it) trigger GPLv3's own copyleft/distribution obligations for the surrounding proprietary Nova VPN deployment. This is the exact same shape of question B46-2B/2C already raised and left open for the Android client-side `tun` path - now confirmed to apply symmetrically to the server side. |
| What must be posed to legal/the repository owner | (1) Does running this exact statically-linked multi-command binary, where only the `server` subcommand is ever invoked, constitute "conveying" or "distribution" of a work that would trigger GPLv3 §5/§6 obligations, given Nova's own server-side code (`gateway/api/*.py`) is entirely separate and never linked into this binary. (2) If legal risk is judged unacceptable, whether to invest in option (b) below (a stripped, server-only rebuild) instead. (3) Whether this question has already been resolved by an existing organizational legal opinion covering the Android client-side finding (B46-2B/2C) that could be extended to this server-side finding directly, rather than requiring an independent review. |

**Options, unchanged from the prior pass, still not decided:**

1. Accept the GPL-3.0-or-later linkage as-is (the server process itself never invokes tun-related code paths, but the binary still contains the code) - pending the legal answer above.
2. Build a stripped, server-only binary from this SAME pinned source commit without tun build tags/dependencies (mirroring B46-2C's own "minimal Hysteria2 SOCKS5-only client" approach, but for `app/cmd/server.go` instead) - **not attempted this pass** (would require a Go build environment and a source-level fork/strip, out of this slice's git-only documentation scope).
3. Some other licensing-compliant distribution path.

`fetch-hysteria-server.sh` still fetches/verifies/installs the official pinned asset (that part is real, verified, and reproducible) - this GAP blocks the DECISION to actually run it in production, not the git-only fetch/pin mechanism itself.

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

## Auth backend listener - RESOLVED this pass (Option A implemented)

`gateway/api/hysteria_auth_backend.py`'s `handle_auth_request` function is
now reachable via a real, live, tested route: `POST /internal/hysteria-auth`
in `gateway/api/handler.py`, served by the SAME `pocvpn-api.service`
process `/v1/hysteria-profile` already runs in (Option A - see
`docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md`'s "Auth backend
architecture" section for the full Option A vs. B comparison and its
evidence). `pocvpn-api` already binds to `127.0.0.1` only (hardcoded in
`server.py`, not configurable) - the new route inherits that guarantee
for free, with no new systemd unit, no new process, no new port, and no
additional application-level loopback check needed. Reused, not
duplicated: the same `activation_store_path`/`hysteria2_store_path`
config fields the prior slice's `/v1/hysteria-profile` route already
uses, and the same `global_limiter` every other route shares.

Real, end-to-end tested this pass (`gateway/api/tests/test_hysteria_auth_endpoint.py`,
9 tests, all passing against a real running `ProvisioningServer`):
issuance → provisioning → successful auth, wrong-secret rejection,
revoked-activation rejection (proves live revocation with zero Hysteria2
server reload - the entire reason `auth.type: http` was chosen over
`password`/`userpass`), rotated-secret invalidation of the old value,
malformed-body handling, no-Authorization-header operation, and
not-configured fail-closed behavior.

**Still NOT deployed**: this is a real code change, live only once
`pocvpn-api.service` is actually redeployed with this code and restarted
- no server was touched this pass.

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

## TLS / SNI (#4) - NOT decided by this pass, but design confidence raised

Live audit finding (read-only): the SPECIFIC vhost tracked in
`gateway/edge/nginx-pocvpn-stockholm.conf` (`server_name _;`) uses a TLS
certificate issued **only for the bare IP** `16.170.208.231`
(`/etc/letsencrypt/live/16.170.208.231/...`) - not usable as a
DNS-name-shaped SNI target, which Android's own
`Hysteria2ProfileMetadata.isValidSni` (and standard QUIC/TLS SNI
practice) expects. **This finding still stands for that one vhost file.**

**New this pass - a real, working hostname+cert precedent was found
LIVE on this exact host, not represented in any file tracked in this
repository:** `https://control.aknova.pp.ua/v1/manifest` was probed
read-only and resolves DIRECTLY to `16.170.208.231` (confirmed via
`curl`'s own `%{remote_ip}` - not Cloudflare-proxied, a direct A record),
presents its OWN dedicated, currently-valid Let's Encrypt certificate
(`subject=CN=control.aknova.pp.ua`, `SAN: DNS:control.aknova.pp.ua`,
90-day validity `2026-09-14..2026-12-13` - a NORMAL Let's Encrypt
lifetime, structurally different from the bare-IP vhost's own 160-hour/
~6.6-day short-lived IP-certificate program), and `POST /v1/activate`
through it returns `411` (Length Required) - the SAME real
`gateway/api/handler.py` code path the bare-IP vhost also reaches, not a
different backend. **This means Stockholm already runs a live, working
hostname-based HTTPS vhost that is NOT represented in
`gateway/edge/nginx-pocvpn-stockholm.conf` as tracked in this repository**
- a real documentation/repo-drift finding, not something this pass
attempts to reconcile (no nginx file was edited).

This substantially de-risks the earlier "a new hostname needs to be
minted from scratch" framing: hostname-based TLS on a normal (not
short-lived-IP) Let's Encrypt certificate is **already proven working on
this exact host**, today, live - it is not a hypothetical capability.
`POST /v1/hysteria-profile` and `POST /internal/hysteria-auth` were also
probed through `control.aknova.pp.ua` this pass and both correctly
returned `404` (not yet deployed - confirms zero accidental deployment
happened, consistent with this slice's own constraints).

A SECOND real hostname exists for Stockholm -
`edge-sthlm.aknova.pp.ua` (`gateway/edge/nginx-pocvpn-cdn-origin-stockholm.conf`,
tracked in this repo, unlike `control.aknova.pp.ua` above), with its own
real Let's Encrypt cert. **Neither `edge-sthlm.aknova.pp.ua` nor
`control.aknova.pp.ua` is reusable for Hysteria2 as-is**:
`edge-sthlm.aknova.pp.ua` is a Cloudflare-fronted HTTPS/TCP origin for
the XHTTP ingress role specifically (`Android -> Cloudflare edge ->
HTTPS origin nginx -> loopback Xray XHTTP inbound`) - a completely
different protocol shape (TCP/HTTP semantics) from Hysteria2's raw
UDP/QUIC, and Cloudflare does not front arbitrary UDP/QUIC for a custom
protocol the way it fronts XHTTP. `control.aknova.pp.ua` is this
gateway's own control-plane/API identity - reusing it for an unrelated
raw-UDP protocol on a different port would be a confusing identity
overload, not a clean design, exactly the same reasoning that already
ruled out `edge-sthlm.aknova.pp.ua`.

**Formalized proposal, still NOT a final decision**: a NEW, DISTINCT
subdomain under the SAME already-owned zone (`aknova.pp.ua` - confirmed
owned/DNS-managed by this project via the three live hostnames above,
plus `origin-sthlm.aknova.pp.ua` found in the live manifest's own
`cdnProviderProfile` metadata):

```text
NOVA_HYSTERIA2_HOSTNAME=hysteria-sthlm.aknova.pp.ua
```

Checked this pass: does not currently resolve - DNS `NXDOMAIN`, confirmed
genuinely unclaimed, matches the existing `<role>-sthlm.aknova.pp.ua`
naming convention (`edge-sthlm`, `origin-sthlm`) - would be pointed
**directly** at Stockholm's own IP (no Cloudflare fronting, since
Hysteria2 needs a real UDP/QUIC path to the origin), with its own
dedicated, normal-lifetime Let's Encrypt certificate issued the SAME way
`control.aknova.pp.ua`'s evidently already was (exact issuance mechanism -
HTTP-01 vs. DNS-01, which ACME client/hook - not determinable from this
repository's tracked files alone, since that vhost's own config is not
tracked either). **No DNS record was created and no certificate was
issued or requested - both remain explicitly out of scope for this
slice; final production approval of this exact hostname is its own
decision gate, not something this pass can close unilaterally.**

This SAME value becomes, once decided: the manifest's `hysteria2Profile.sni`,
the `HYSTERIA2_SNI` env var `gateway/api/config.py` reads, AND the
`HYSTERIA2_HOSTNAME` value pointed to by DNS - one source of truth, never
three independently-set values that could drift apart (see
`gateway/api/handler.py`'s own `_handle_hysteria_profile_inner` comment -
`server_address` and `sni` in the client-facing response are BOTH
`cfg.hysteria2_sni`, fixed this pass - see "Corrections this pass"
below).

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
