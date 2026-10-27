# Non-`.pp.ua` client-facing domain - migration plan (DRAFT, nothing executed)

Status: **plan only.** No domain bought, no DNS, certificate, Cloudflare,
nginx, manifest or app change has been made. Every step marked **[owner]**
needs explicit owner approval; purchases and production changes are made by
the owner. Tracks the ROADMAP P0 row "Non-`.pp.ua` Client-Facing Domain"
(execution order item 1).

## Why

On the one measured RU network (home Wi-Fi, 2026-10-07/08) every
`*.aknova.pp.ua` SNI was filtered (`SNI_FILTERED`): `control.`, `edge-sthlm.`
and the Cloudflare XHTTP names. Consequences today:

| Depends on the name | RU effect (observed on that network) |
|---|---|
| B35 CDN/XHTTP ingress `edge-sthlm.aknova.pp.ua` | `CONNECT_FAILED` |
| Direct XHTTP (Xray inbound is loopback-only behind nginx TLS, so it always needs a hostname SNI) | not offered by manifest v8; with a `.pp.ua` name it would fail the same way |
| B57 control-plane edge behind Cloudflare | unusable |
| Hysteria2 SNI `origin-sthlm.aknova.pp.ua` | pre-Salamander run failed; Salamander unmeasured |

Not dependent on the name: AWG, REALITY (third-party SNI), TLS_TCP and the
raw-IP control plane.

A new domain is **not presumed to work**: it gets validated from RU before
anything relies on it (phase 2).

## 1. Choosing the domain [owner]

- Generic, widely used TLD: `.com` / `.net` / `.org`. Avoid country TLDs
  tied to either side (`.ua`, `.ru`) and cheap TLDs common in abuse lists
  (`.xyz`, `.top`, `.click`, ...), which some filters block wholesale.
- Neutral name: no "vpn", "proxy", "nova-vpn", "bypass"; nothing that
  imitates a real brand (architecture principle: no third-party
  impersonation).
- Registrar outside RU, WHOIS privacy on, auto-renew on, 2FA on the account.
- DNS hosted at Cloudflare (the B35 CDN ingress and B57 edge are Cloudflare
  features; the zone has to be there).
- Keep `aknova.pp.ua` running in parallel until phase 5; nothing is turned
  off by this migration.

## 2. Hostname mapping

`<new>` = the chosen registrable domain. Names are proposals.

| Current | Proposed | Used by | Reaches clients via |
|---|---|---|---|
| `edge-sthlm.aknova.pp.ua` | `edge-sthlm.<new>` | B35 CDN XHTTP ingress (Cloudflare proxied) | signed manifest `cdnProviderProfile` |
| `edge.aknova.pp.ua` | `edge.<new>` | Frankfurt CDN origin vhost | signed manifest |
| `origin-sthlm.aknova.pp.ua` | `origin-sthlm.<new>` | Stockholm origin cert, Hysteria2 SNI (DNS-only) | manifest `hysteria2Profile.sni`, `cdnProviderProfile.originHostname` |
| `control.aknova.pp.ua` | `control.<new>` | control-plane name, `cdnProviderProfile.controlPlaneHostname`, field-test probes | manifest + **compiled code** (see 4) |
| `cp-staging.aknova.pp.ua` | `cp-staging.<new>` | B57 staging edge | operator only |
| `activate.aknova.pp.ua` | `activate.<new>` | Android App Link for activation links | **compiled in the APK** (see 4) |
| *(new)* | `xh-fra.<new>` / `xh-sthlm.<new>` | Direct XHTTP (DNS-only to the gateway IP, nginx TLS -> loopback Xray XHTTP inbound) | new manifest binding (phase 3) |

## 3. Server-side changes [owner approval per gateway]

All additive; the `.pp.ua` vhosts stay.

1. DNS records in the new Cloudflare zone (proxied for `edge*`, DNS-only for
   `origin-*`, `xh-*`, `control`).
2. Certificates: Let's Encrypt for DNS-only names on each gateway (same
   certbot flow as `edge-sthlm.aknova.pp.ua`); Cloudflare origin settings for
   proxied names.
3. nginx: add `server_name`s / new vhosts beside the existing ones in
   `gateway/edge/nginx-pocvpn-cdn-origin-{stockholm,frankfurt}.conf`
   (`proxy_set_header Host` per vhost); for Direct XHTTP a vhost on 443 for
   `xh-*.<new>` proxying `location /nova-xhttp/` to the loopback XHTTP
   inbound with `limit_except GET POST`, exactly the proven Stockholm origin
   pattern. Frankfurt: 443 is shared with REALITY via the SNI-split stream
   template (PR #161) - the new name must be added to that split.
4. Hysteria2 (Stockholm): cert for `origin-sthlm.<new>`, `POCVPN_API_HYSTERIA2_SNI`.
   Hysteria2 stays debug/field-test only (legal gate G1 unchanged).
5. API env: `xray_xhttp_client_host/port` for the Direct XHTTP profile
   (`/v1/xray-profile` `transport=xhttp` returns these).
6. Repo: update templates/tests in `gateway/edge`, `gateway/hysteria`,
   `gateway/config/*.example` in one PR; tests that pin hostnames change with them.

## 4. Client-side changes (one APK release)

- `ActivationInput.PRODUCTION_ACTIVATION_HOST` + `AndroidManifest.xml`
  intent-filter host: App Links are compiled in. Add the new host **next to**
  the old one (two `<data android:host>` entries) and publish
  `/.well-known/assetlinks.json` on `activate.<new>`.
- Field-test probe targets (`CensorshipProbe`, `FieldTestRunner.CONTROL_PLANE_HOST`):
  add the new names so the test measures them. Better: derive them from the
  signed manifest so a future rename needs no APK.
- Open question already recorded in ROADMAP: B30 `ControlPlaneOrigin` is
  built from the compiled `ProductionGatewayCatalog`, so a renamed
  control-plane host reaches existing installs only with a new APK. Raw-IP
  origins keep working meanwhile, so this is not a blocker for phases 2-4.

## 5. Rollout

| Phase | What | Gate to continue |
|---|---|---|
| 0 [owner] | buy domain, Cloudflare zone | - |
| 1 [owner] | DNS + certs + nginx vhosts (additive) | CZ: `curl --resolve` to each new name returns the expected vhost; old names unchanged |
| 2 | **RU validation before any client relies on it**: field-test APK with the new names as probe targets; RU home Wi-Fi + each mobile operator separately (B54) | new names are not `SNI_FILTERED`/`DNS_*` on the tested RU networks |
| 3 [owner] | manifest **v9**: v8 content + new CDN ingress entry (`edge-sthlm.<new>`) + Direct `XRAY_XHTTP` bindings (`xh-*.<new>:443`) + Hysteria2 SNI; old `.pp.ua` ingress kept as a second entry | CZ full field test: every offered path `DATA_PLANE_OK` / `DATA_PLANE_CORE_CONFIRMED` |
| 4 | RU field test with v9: the four-transport comparison (XHTTP vs REALITY vs AWG vs TLS_TCP, same gateway, per network) | decision rule for Auto: XHTTP works on a network where AWG and REALITY fail |
| 5 [owner] | APK release with the new App Link host; retire `.pp.ua` names only after installs have moved | - |

## 6. Rollback

- Server: the new vhosts/certs are additive - remove them, reload nginx.
- Manifest: clients enforce rollback protection (`EndpointManifestRepository`,
  `ROLLBACK_OR_NOT_NEWER`), so v8 **cannot** be re-published. Rollback = sign
  **v10** with v8's endpoint content. Prepare and sign that v10 before
  publishing v9, so rollback is one publish.
- Client: nothing to roll back before phase 5; the APK keeps the old App Link host.

## 7. Risks

- The new domain may be filtered in RU too (quickly or later) - phase 2
  exists for this; a manifest-delivered name can be rotated without an APK.
- Cloudflare-proxied names share fate with Cloudflare's RU reachability;
  DNS-only names (`xh-*`, `origin-*`) expose the gateway IP, which REALITY/AWG
  already do.
- Frankfurt 443 is shared with REALITY via SNI split; a misconfigured split
  breaks REALITY on Frankfurt - change it with the PR #161 template and test
  REALITY in the same CZ run.
