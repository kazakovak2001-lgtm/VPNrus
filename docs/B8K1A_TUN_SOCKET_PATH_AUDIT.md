# B8K1A — TUN + outbound socket path proof (source-verified, no code written)

Status: investigation only. `XRAY_REALITY` remains `NOT_IMPLEMENTED`. No
`VpnController`/`TransportOrchestrator`/`VpnTransport` changed. Nothing in
this doc is a design decision until a future slice implements it.

## 1. Checkpoint

B8K0 commit: `3fe6e02a2a06990535c6dd0a45bfc4e97d10355f`
("chore(xray): pin and document vless reality runtime foundation").

## 2. Reference read: exact packet path (v2rayNG @ HEAD, AndroidLibXrayLite @ pinned `c634d1b`, Xray-core @ pinned `v26.7.28`/`5ca6f4b`)

App traffic → `CoreVpnService` (VpnService) TUN fd → **Xray-core's own
`proxy/tun` inbound**, which wraps the raw fd in a gVisor (`gvisor.dev/gvisor`,
Apache-2.0) userspace netstack (`fdbased.New`) inside the same Go runtime →
Xray routing/outbound → underlying physical network socket, opened directly
by Xray-core's Go networking (no separate proxy hop).

There is **no separate/external tun2socks process or library in the default
path.** v2rayNG's only external native tunnel (`libhev-socks5-tunnel.so`,
hev-socks5-tunnel, MIT) is an **optional, alternate** bridge gated by a user
setting (`SettingsManager.isUsingHevTun()`); when that setting is off (the
default), `tunFd` is passed straight to `coreController.startLoop(config,
tunFd)` and Xray's built-in `tun` inbound consumes it. When the setting is
on, `tunFd` is forced to `0` before `startLoop` and `TProxyService`
(`CoreVpnService.kt:305-318`) owns the fd instead, bridging it to a
Xray SOCKS5 inbound over loopback.

Key files/functions read directly (not summarized from docs):
- `V2rayNG/app/.../service/CoreVpnService.kt` — `configureVpnService()`,
  `configurePerAppProxy()`, `runTun2socks()`, `vpnProtect()`.
- `V2rayNG/app/.../core/CoreServiceManager.kt` — `launchCore()` (builds
  `tunFd`, calls `coreController.startLoop(result.content, tunFd)`).
- `V2rayNG/app/.../core/CoreNativeManager.kt` — `newCoreController()`,
  `initCoreEnv()` (no protect/bind wiring here).
- `V2rayNG/app/.../contracts/ServiceControl.kt` / `CoreRootService.kt` /
  `CoreProxyOnlyService.kt` — `vpnProtect()` declared in three
  implementations, **called from zero Kotlin call sites** anywhere in the
  app (verified by full-repo grep). It exists only as an interface method a
  future/alternate native binding could invoke reflectively; the shipped
  gomobile wrapper (`libv2ray_main.go` in AndroidLibXrayLite) never calls
  back into it.
- `AndroidLibXrayLite/libv2ray_main.go` — `StartLoop(configContent string,
  tunFd int32)` just does `setEnvVariable("xray.tun.fd", tunFd)` then
  `doStartLoop(configContent)`. It is a thin env-var passthrough, not a
  packet-forwarding implementation.
- `Xray-core/proxy/tun/tun_android.go` — `NewTun()` reads that same
  `xray.tun.fd`/`XRAY_TUN_FD` env var, `unix.SetNonblock`s it, and
  `newEndpoint()` wraps it with gVisor's `fdbased.New`. This file **is**
  the tun2socks-equivalent; it lives inside xray-core itself.
- `Xray-core/proxy/tun/README.md` (`## ANDROID SUPPORT`) — confirms this
  is the documented, intended Android integration contract: set
  `xray.tun.fd`/`XRAY_TUN_FD`, done.

## 3. Recursion-prevention mechanism (verified, not inferred)

Xray-core's own code has **zero** references to `VpnService`, `protect(`,
or `bindProcessToNetwork` anywhere (grepped the full pinned source tree).
Recursion is prevented **entirely at the Android OS/UID level**, not inside
Xray:

`CoreVpnService.configurePerAppProxy()` (`CoreVpnService.kt:266-299`) always
does exactly one of:
- per-app proxy off, or no apps selected → `builder.addDisallowedApplication(selfPackageName)`
- per-app proxy on, bypass mode → self added to the disallowed set, `addDisallowedApplication` per app
- per-app proxy on, allow/include mode → self removed from the allowed set, `addAllowedApplication` per app (self simply never appears in the allow-list, which is sufficient — Android's default-bypass rule for unlisted apps under an allow-list excludes it)

Never both lists in the same `Builder` — satisfies Android's OS-level
constraint that a `VpnService.Builder` cannot mix `addAllowedApplication`
and `addDisallowedApplication` calls in one configuration.

Because the app's own package UID is always excluded from the routed set,
every socket opened by that UID — including Xray-core's outbound sockets —
bypasses the TUN interface at the Android/kernel routing layer before the
packet ever reaches the tun netfilter hook. This sidesteps the exact
"infinite network loop" failure mode the upstream `proxy/tun/README.md`
warns router/desktop deployers about (§ CONSIDERATIONS) — Android's per-UID
VPN bypass is a materially different (and simpler) mitigation than the
policy-routing/route-table tricks that doc describes for Linux/macOS/Windows.

`vpnProtect()`/`protect(fd)` exists in the three `ServiceControl`
implementations but is dead code in the current wiring — a legacy/optional
hook, not the active mechanism.

## 4. Is Nova self-app exclusion sufficient? — Yes, with one condition proven, one still open

Proven from source:
1. **Xray outbound sockets** run in-process inside the Go runtime loaded via
   JNI (`libgojni.so`) — same Linux process family as the Android app.
2. **tun2socks-equivalent sockets** (the gVisor netstack) are not real
   sockets at all in the non-HevTun default path — they're an in-memory
   virtual link endpoint reading the raw fd; there is no separate socket to
   protect. (If Nova ever enables the alternate `TProxyService`/HevTun path,
   that native process's sockets need the same UID-exclusion coverage —
   confirmed true, see #5.)
3. **Android app-level allowed/disallowed routing applies by package UID**,
   which covers every process spawned under that package — confirmed by
   v2rayNG's own manifest, which runs `CoreVpnService` and the Xray/daemon
   components in a **separate process** (`android:process=":RunSoLibV2RayDaemon"`,
   `AndroidManifest.xml:169-330`) while still relying on the *same*
   `addDisallowedApplication(selfPackageName)` call. A separate manifest
   process of one package is still one Linux UID in Android's app model —
   this is the existing, shipped proof that UID-based exclusion covers a
   split-process architecture, not just a single-process one.
4. **No socket still requires `VpnService.protect()`** in the reference
   app's default (non-root, non-proxy-only) path — see §3, zero live call
   sites.
5. **Native child processes share the app UID** — yes, confirmed by the
   manifest process split above; Android does not give a same-package
   secondary process a different UID (that requires `android:sharedUserId`
   across *different* packages, which is unrelated and deprecated).
6. **Works across all three modes without violating the allow/disallow
   mutual-exclusion rule** — confirmed in §3; the reference implementation
   already threads this correctly for its own equivalent of
   ALL_APPS/BYPASS_SELECTED/VPN_ONLY_SELECTED.

Open condition, not yet proven: this analysis is for Xray-core's **built-in**
`tun` inbound path. It has not been re-verified against the alternate
HevTun/`TProxyService` bridge, which loads a distinct native `.so`
(`libhev-socks5-tunnel.so`) — no evidence yet whether that library's sockets
also stay under the app UID (very likely, since it's loaded via JNI into the
same process, but not read/confirmed at the source level this pass). Nova
does not need this path for B8K1B — the default `tun` inbound is the one
being adopted.

## 5. `StartLoop(tunFd)` semantics — reconciled

- `StartLoop` itself does nothing with the fd except stash it in an env var.
- **Sufficient for full-device TUN by itself**, *provided* the Xray JSON
  config's inbound is configured with `"protocol": "tun"` — the actual
  packet-to-proxy translation is xray-core's own `proxy/tun` module
  (gVisor netstack), not a separate component.
- **No external tun2socks binary/AAR/JNI layer is required** for this path.
  (v2rayNG's `hev-socks5-tunnel` is optional/alternate, not a dependency of
  the `tun` inbound.)
- This corrects the prior B8K0 report's claim that an external tun2socks
  bridge is required — that claim conflated v2rayNG's optional HevTun
  setting with its default path.

## 6. Licensing — concrete obligations for the components actually in the chosen path

- **Xray-core (MPL-2.0)**: file-level copyleft. Modifications to
  Xray-core's own `.go` files must be released under MPL-2.0 if
  distributed; this pin uses xray-core unmodified as a transitive
  dependency of AndroidLibXrayLite, so no Xray-core file is being modified
  by Nova. Nova's own Kotlin/app code is a separate work and is not
  required to be MPL-2.0 merely for depending on an MPL-2.0 library through
  a normal build/link step (this is the standard interpretation multiple
  commercial VPN apps already rely on for this exact dependency — not
  reconfirmed here as legal advice).
- **AndroidLibXrayLite (LGPL-3.0)**: the relinking/replacement obligation
  applies — Nova must allow the user (or itself) to substitute a modified
  version of this specific library (e.g. by keeping it a discrete `.aar`
  dependency rather than statically fusing its object code in a way that
  defeats relinking) and must make LGPL-3.0's required source materials for
  this library (not Nova's own app) available on request. This is the
  concrete reason `third_party/xray/build-xray-wsl.sh` reproduces the
  wrapper build from pinned source rather than vendoring a prebuilt binary
  with no provenance.
- **gVisor (`gvisor.dev/gvisor`, Apache-2.0)**: permissive; requires
  preserving copyright/license notices and a NOTICE-style attribution for
  any redistributed notices file, no source-disclosure obligation. Pulled
  in transitively through xray-core's `proxy/tun`.
- **hev-socks5-tunnel (MIT)**: not part of the path Nova is adopting
  (§4 open condition) — recorded here only because it appears in the
  reference app; no obligation analysis needed unless Nova later adopts it.

No license-driven architecture change is being made here — Xray-core's
built-in `tun` inbound was already the intended path per the B8K0 audit
doc; this slice only confirms it's sufficient and traces the exact
mechanism.

## 7. Per-app routing design — future mapping (not implemented)

Mirrors the B8H invariant (user-facing selection vs. Nova's own
control-plane exclusion stay distinct) and the reference app's proven
pattern:

- **ALL_APPS**: `addDisallowedApplication(novaPackageId)` only. Everything
  else routes through the VPN/Xray tun inbound.
- **BYPASS_SELECTED**: `addDisallowedApplication(novaPackageId)` plus
  `addDisallowedApplication(app)` for each user-selected bypass app — same
  disallow list, Nova's own exclusion and the user's B8H selections both
  live in it without conflating the two concepts (Nova's entry is not
  stored in the saved B8H policy set; it is added at `Builder` config time
  only).
- **VPN_ONLY_SELECTED**: `addAllowedApplication(app)` for each user-selected
  app; Nova's own package is never added to this allow list (equivalent to
  the reference app's `apps.remove(selfPackageName)` when not in bypass
  mode) — Nova is implicitly excluded because unlisted apps bypass an
  allow-list VPN by default, not because it needs an explicit disallow call
  (which would violate the allow/disallow mutual-exclusion rule).

## 8. Runtime build attempt

Attempted in WSL2 Ubuntu using `third_party/xray/build-xray-wsl.sh`
unmodified. Environment found: Go 1.26.0, OpenJDK 17.0.20, Android SDK with
NDK 26.1.10909125 already present under `~/android-sdk`; `gomobile`/`gobind`
were not yet installed and were installed by the script itself per its
existing design.

**Result: failed, environment prerequisite missing — not a script or code
defect.** The script correctly cloned the pinned wrapper commit, verified
its SHA, resolved the full Go module graph (`go mod tidy`), and reached
`gomobile bind`'s actual compile stage — hundreds of packages compiled
successfully (`github.com/xtls/xray-core/...`, `gvisor.dev/gvisor/...`,
etc. all built) before the run started failing with
`fork/exec .../compile: input/output error` on every subsequent package,
then `gomobile: go build ... -o=.../libgojni.so ./gobind failed: exit
status 1`.

Root cause, confirmed by checking the host afterward: the Windows host's
`C:` drive was completely full (`476G size, 475G used, 664M avail` after
the run — essentially 0 bytes free during the run itself). The WSL2 VM's
disk lives on this same host volume; once it filled, every subsequent
`fork/exec` of the Go compiler failed with an I/O error, and after the run
the WSL Ubuntu instance itself stopped being able to start
(`Wsl/Service/CreateInstance/E_FAIL`) until space was freed. This is a
pre-existing host disk-space condition, unrelated to `build-xray-wsl.sh`,
the pinned commit, or this repo — cleaned up this session's own ~46 MB of
scratch clones (`/tmp/v2ng`, `/tmp/alxl`, `/tmp/xray-core`, used only for
source-reading in §2–§6 above) afterward, which freed the WSL instance
enough to run shell commands again, but the host still shows only ~664 MB
free. **No artifact was produced. No checksum. No ABI coverage recorded.**
This is the exact missing prerequisite: meaningful free disk space on the
host `C:` drive (a `gomobile bind` of this dependency graph needs low
gigabytes of Go module cache + build cache headroom, and the host has
none) before this build can be re-attempted.

## 9. Remaining blocker before writing `NovaXrayVpnService`

None on the TUN/socket-protection question — that question is resolved:
Xray-core's built-in `tun` inbound plus Android per-UID
`addDisallowedApplication(self)` is sufficient, matches a real shipped
app's architecture, and needs no `VpnService.protect()` wiring, no
`bindProcessToNetwork`, and no external tun2socks binary.

What is still unstarted (not a blocker on *this* question, just not yet
done): no Kotlin `VlessRealityTransport`/`VpnTransport` adapter exists, no
config-JSON generation for the `tun`+`vless`+`reality` inbound/outbound
pair has been written or tested, and the HevTun alternate path (§4 open
condition) has not been re-verified — none of these block starting
`NovaXrayVpnService` design, since the default `tun` inbound path is now a
proven-sufficient foundation to build it on.

## 10. Smallest safe B8K1B implementation slice

A single new file, `NovaXrayVpnService` (new `VpnService` subclass, not
wired into `VpnController`/`TransportRegistry` yet), that:
1. Establishes a `VpnService.Builder` with `addDisallowedApplication(BuildConfig.APPLICATION_ID)`
   unconditionally (ALL_APPS case only, to start).
2. Calls the pinned AAR's `Libv2ray.newCoreController(...)` /
   `coreController.startLoop(config, tunFd)` with a hand-written, static
   VLESS+REALITY+`tun`-inbound JSON config (no dynamic config generation
   yet).
3. Is manually started/stopped from a test-only entry point (e.g. a debug
   menu item), fully outside `TransportOrchestrator`/Smart Connect.
4. Is verified on a physical device for exactly one thing: outbound Xray
   traffic reaches the real network and does not loop back into the TUN
   (e.g. `curl` through the local SOCKS/HTTP test port with the VPN
   active, confirm egress IP is the VLESS server, confirm no ANR/loop).

`XRAY_REALITY` stays `NOT_IMPLEMENTED` in `TransportRegistry` until that
device verification passes and a real adapter replaces the hand-written
config.
