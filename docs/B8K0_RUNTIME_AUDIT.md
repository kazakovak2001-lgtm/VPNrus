# B8K0 - VLESS/REALITY runtime audit and B8K1 design

Research-only slice. No Android source changed. `TransportKind.XRAY_REALITY`
remains `NOT_IMPLEMENTED`. Every fact below was pulled from the actual
upstream repositories (via the GitHub API against the exact pinned
commits/tags cited) - nothing here is guessed or remembered from general
knowledge of these projects.

## Step 1-2: sing-box/libbox vs Xray-core+wrapper, and the selection

| Axis | A. sing-box / libbox | B. Xray-core + AndroidLibXrayLite |
|---|---|---|
| VLESS support | Yes (`option.VLESSOutboundOptions`) | Yes (VLESS is Xray-core's own protocol; REALITY was invented by Xray-core's author, RPRX) |
| REALITY support | Yes (`option.OutboundRealityOptions`) | Yes (`transport/internet/reality`, native/first-party) |
| Android embedding | First-party, in-tree (`experimental/libbox`), used by SagerNet's own shipped `sing-box-for-android` | No in-tree Android bindings in Xray-core itself; relies on a **community** wrapper (2dust/AndroidLibXrayLite), which is what v2rayNG (a real, widely-shipped app) uses |
| gomobile/AAR support | Yes, but via **SagerNet's own fork** `github.com/sagernet/gomobile`/`gobind` pinned at `v0.1.13` - a maintained fork, not upstream | Yes, via **upstream** `golang.org/x/mobile/cmd/gomobile` - no fork to track |
| Host-provided TUN fd | Yes, first-class: `PlatformInterface.OpenTun(TunOptions) (int32, error)` callback - the Go core calls back INTO Kotlin, which owns `VpnService.Builder`/`establish()` and returns the resulting fd | Yes, but thinner: `CoreController.StartLoop(configContent, tunFd int32)` takes a raw fd as a parameter (env var `xray.tun.fd` internally) - no structured route/DNS/per-app pass-through object |
| Lifecycle/start-stop API | `libbox.NewCommandServer(handler, platformInterface)` → `.start()` → `.startOrReloadService(configJSON, overrideOptions)` → `.closeService()` / `.close()` (all exact names, from `experimental/libbox/command_server.go` + the reference app's `BoxService.kt`) | `libv2ray.NewCoreController(handler)` → `.StartLoop(configJSON, tunFd)` → `.StopLoop()` (exact names, from `libv2ray_main.go`) |
| DNS handling | `TunOptions.GetDNSMode()`/`GetDNSServerAddress()` - DNS mode/servers flow from config into the TUN options object the host consumes when building `VpnService.Builder` | Handled entirely inside the Xray-core JSON config (`dns` section) plus whatever DNS servers the host adds to its own `VpnService.Builder` - no cross-language DNS-mode object |
| IPv4/IPv6 | `TunOptions.GetInet4Address/GetInet6Address/GetInet*RouteAddress/RouteExclude` - explicit, structured, dual-stack aware | Config-only (`inbounds`/`routing` JSON); the host's own `VpnService.Builder` decides what's actually routed, same as Nova already does for AWG |
| Per-app routing | `TunOptions.GetIncludePackage()/GetExcludePackage()` - passed straight through to `VpnService.Builder.addAllowedApplication/addDisallowedApplication` in the reference app's `VPNService.kt` (confirmed byte-for-byte) | No cross-language pass-through found; would be entirely Nova's own `VpnService.Builder` logic, reusing B8H's existing `AppRoutingPolicy`/`resolveAppRoutingLists` untouched - arguably *simpler* to integrate for exactly that reason |
| Socket protection (avoid the app's own upstream connection looping through its own TUN) | First-class, structured: `PlatformInterface.AutoDetectInterfaceControl(fd int32) error` callback, wired automatically by the Go core - confirmed in the reference app (`VPNService.kt`: `override fun autoDetectInterfaceControl(fd: Int) { protect(fd) }`) | **No equivalent hook found in AndroidLibXrayLite's public Go API.** The real shipped app using this exact dependency chain, v2rayNG, solves it via its own `CoreVpnService.vpnProtect(socket) = protect(socket)` plus an external `tun2socks` bridge process - i.e. it is solved at the **Android app layer**, not inside the Xray-core/wrapper API surface. This is a real, open integration item for Nova to design (see "Open item" below), not a blocker - v2rayNG proves it is solvable, but Nova cannot borrow a ready-made cross-language callback for it the way sing-box provides one. |
| Upstream maintenance | Very active (SagerNet/sing-box: 37k+ stars, releases within the last day as of this audit) | Xray-core: very active (41k+ stars, monthly releases). AndroidLibXrayLite: smaller (467 stars) but actively pushed (last commit within days of this audit) and is the dependency v2rayNG itself ships with |
| **Licensing** | **GPL-3.0-or-later, PLUS an explicit extra restriction: "no derivative work may use the name or imply association with this application without prior consent."** Embedding this into a commercial closed-source app's distributed binary is a real legal exposure - the prevailing reading of GPL-3.0 treats a statically/natively-linked combined binary as a derivative work, which would obligate releasing Nova's own source under GPL-compatible terms. | Xray-core core: **MPL-2.0** (file-level copyleft - the license basis many existing commercial VPN products already build on). AndroidLibXrayLite wrapper: **LGPL-3.0** (permits linking from a proprietary app). Materially lower legal risk for a commercial, closed-source product. |
| Binary size / build complexity | Heavier: the pinned build (`cmd/internal/build_libbox`) compiles in `with_gvisor, with_quic, with_wireguard, with_utls, with_naive_outbound, with_clash_api, with_usbip, with_openvpn, with_openconnect, with_tailscale` (+ several `ts_omit_*` trims) - none of which Nova needs for a VLESS/REALITY-only transport. Requires OpenJDK 17 exactly (build tool hard-checks the string `"openjdk 17"`) and the SagerNet gomobile fork. | Lighter: `gomobile bind` against a 4-file Go package with only the Xray-core dependency - no bundled Tailscale/OpenVPN/USB-IP/OpenConnect/Clash-API surface to compile in. |
| Credential/config model | JSON matching `option.Options` (sing-box's own schema); `GenerateConfigSchema()`/`FormatConfig()`/`CheckConfig()` exist for validation | JSON matching Xray-core's own config schema (`coreserial.LoadJSONConfig`) - same "typed JSON blob" shape, just a different schema |
| Full-device TUN without a second Android `VpnService` | Yes - the reference app's `VpnService` is the ONLY one; libbox never creates its own | Yes, by the same reasoning - `CoreController` never touches `VpnService` itself; v2rayNG's own single `CoreVpnService` owns it |

**Selected: Xray-core (core) + the AndroidLibXrayLite wrapper pattern**, overturning
the prior slice's tentative sing-box recommendation. The deciding factor is
licensing, not technical polish: sing-box's Android integration is
genuinely more turnkey (a structured `PlatformInterface` with an explicit
socket-protection callback and per-app pass-through, proven end-to-end by a
shipped app), but its GPL-3.0-plus-restriction terms are a business-level
risk for a commercial closed-source product that outweighs that convenience.
The Xray-core path is real and shippable (v2rayNG proves it end-to-end) but
requires Nova to design and own more of the Android-side plumbing itself -
most importantly, socket protection, which is not exposed as a ready-made
callback the way sing-box provides one. This is flagged explicitly, not
glossed over, per this task's own "do not mark VLESS transport
production-ready unless..." instruction.

### Exact pinned selection

- Wrapper: `github.com/2dust/AndroidLibXrayLite`, commit `c634d1baea97e94320c0bf6a9cf637369c4f11d4` (2026-08-20), license LGPL-3.0.
- Core (pulled transitively via the wrapper's own `go.mod`/`go.sum`): `github.com/xtls/xray-core`, tag `v26.7.28`, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, license MPL-2.0.
- Go toolchain: 1.26 (per both projects' `go.mod`). gomobile: upstream `golang.org/x/mobile/cmd/gomobile` (no fork).
- Android API level: 24 (matches the wrapper's documented build command and Nova's own existing `minSdk` expectations - not independently re-verified against Nova's `build.gradle.kts` in this slice).
- Full provenance/checksum strategy recorded in `third_party/xray/VERSION`.

## Step 3: real API discovered (exact names, from the pinned sources above)

- `github.com/2dust/AndroidLibXrayLite` (package `libv2ray`):
  - `func NewCoreController(handler CoreCallbackHandler) *CoreController`
  - `func (x *CoreController) StartLoop(configContent string, tunFd int32) (err error)` - `tunFd == 0` means "no TUN, proxy-only"
  - `func (x *CoreController) StopLoop() error`
  - `func InitCoreEnv(envPath string, key string)` - asset/cert path + XUDP key setup, called once at process start
  - `func CheckVersionX() string`
  - `type CoreCallbackHandler interface { Startup() int; Shutdown() int; OnEmitStatus(int, string) int }` - the Kotlin-implemented callback
  - `func (x *CoreController) RegisterProcessFinder(finder ProcessFinder)` / `type ProcessFinder interface { FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int }` - UID-based per-app routing input, optional
  - `func (x *CoreController) QueryAllOutboundTrafficStats() string` - traffic stats, semicolon-delimited text
  - **No socket-protection method exists in this package.** (See open item below.)
- Config model (from Xray-core's own `option` package, `option/vless.go` + `option/tls.go` + `option/outbound.go`) - the exact JSON an outbound VLESS+REALITY config needs:
  ```json
  {
    "type": "vless",
    "server": "<host>",
    "server_port": 443,
    "uuid": "<user UUID>",
    "flow": "xtls-rprx-vision",
    "tls": {
      "enabled": true,
      "server_name": "<SNI>",
      "utls": { "enabled": true, "fingerprint": "chrome" },
      "reality": { "enabled": true, "public_key": "<base64>", "short_id": "<hex>" }
    }
  }
  ```
  Every field name above is copied verbatim from the pinned source's Go
  struct tags (`ServerOptions.Server`/`ServerPort`, `VLESSOutboundOptions.UUID`/`Flow`,
  `OutboundTLSOptions.ServerName`, `OutboundUTLSOptions.Fingerprint`,
  `OutboundRealityOptions.PublicKey`/`ShortID`) - none invented.
- v2rayNG's real Android-side wiring (for reference, since it is the proof
  this integration shape actually ships): `CoreVpnService` (a `VpnService`
  subclass) owns `Builder`/`establish()`; `vpnProtect(socket) = protect(socket)`;
  a separate `tun2socks` component bridges the TUN fd to a local Xray-core
  proxy port - a three-component chain (`VpnService`+TUN → tun2socks →
  Xray-core), one more moving part than sing-box's two-component design.

### Open item this audit did NOT resolve

AndroidLibXrayLite's public Go API has no `AutoDetectInterfaceControl`-style
callback. v2rayNG solves outbound-socket protection at its own Android app
layer (`vpnProtect`/`tun2socks`), not through anything the wrapper exposes.
Before any Nova adapter can be trusted not to leak, a follow-up slice must
either (a) confirm the newer `tunFd`-direct-injection path (`StartLoop`'s
`tunFd` parameter) already avoids the loopback problem internally the way
the older tun2socks-based flow needed external protection for, or (b)
design Nova's own protection mechanism (e.g. a `tun2socks` dependency, or a
custom Go `net.Dialer.Control` hook threaded through a small patch/wrapper
layer). This is exactly the kind of gap this task told me to surface rather
than paper over.

## IMPORTANT TUN/VPN SERVICE QUESTION - answered directly against THIS repo's pinned AmneziaWG, not assumed

Re-verified by decompiling the pinned `amneziawg-tunnel-v3.1.20260814-debug.aar`
directly (not relying on the earlier B8G1 audit from memory):

```
public final class org.amnezia.awg.backend.GoBackend implements Backend {
  public GoBackend(Context);
  public static void setAlwaysOnCallback(AlwaysOnCallback);
  public Set<String> getRunningTunnelNames();
  public Tunnel.State getState(Tunnel);
  public Statistics getStatistics(Tunnel);
  public long getLastHandshake(Tunnel);
  public void setStatusCallback(StatusCallback);
  public String getVersion();
  public Tunnel.State setState(Tunnel, Tunnel.State, Config) throws Exception;
}
public class org.amnezia.awg.backend.GoBackend$VpnService extends android.net.VpnService {
  public GoBackend$VpnService();
  public VpnService.Builder getBuilder();
  public void onCreate(); public void onDestroy(); public int onStartCommand(Intent, int, int);
  public void setOwner(GoBackend);
}
```

1. **Can the new transport reuse the existing VpnService ownership?** No. `GoBackend`'s entire public surface is the nine methods above - nothing accepts a `ParcelFileDescriptor`, a raw fd, or any external `VpnService` reference. Its `VpnService` is a fixed inner class, instantiated only because `AndroidManifest.xml` names it directly as a `<service>`; `GoBackend`'s private `vpnService: GhettoCompletableFuture<VpnService>` field is populated only by that one manifest-declared component starting itself.
2. **Does the candidate runtime (Xray-core/AndroidLibXrayLite) create its own VpnService?** No - confirmed above; it expects the host to own `VpnService.Builder`/`establish()` and hand it a fd via `StartLoop`.
3. **Would that conflict with GoBackend's VpnService?** Structurally yes if both were ever "active" - they are two entirely separate Android `VpnService` component classes, and Android grants only one app's VPN interface at a time system-wide.
4. **Can only one transport own the VPN interface at a time?** Yes, confirmed by both Android OS policy and GoBackend's own closed, non-extensible design.
5. **What a controlled switch requires:** an explicit, sequenced teardown-then-establish - `AmneziaWgTransport.disconnect()` (GoBackend `setState(DOWN)`) fully completing before a future Nova-owned `VpnService.Builder().establish()` begins, or vice versa. There is a real window with no VPN interface up unless Android's own Always-on + lockdown is active (`AlwaysOnVpnState`'s own documented caveat) - this must never be hidden or claimed leak-free.

**Common-TUN feasibility conclusion: NOT feasible with the current pinned
AmneziaWG dependency, full stop.** No API exists to inject an external TUN
into `GoBackend`, and forking/patching the pinned AAR is out of scope (never
attempted, never planned without a deliberate separate decision). The
realistic architecture is, and remains, **mutually-exclusive VpnService
implementations with controlled, explicit, non-silent switching** - exactly
the outcome B8K's first audit already concluded, now independently
re-verified against fresh bytecode rather than carried over from memory.

## Step 6: smallest safe B8K1 architecture

Given common-TUN is infeasible, B8K1 should NOT attempt a shared-TUN-owner
refactor. The smallest safe next slice:

1. **A second, Nova-owned `VpnService`** (e.g. `NovaXrayVpnService`), declared
   as its own `<service>` in the manifest, entirely separate from
   `GoBackend$VpnService`. It owns `Builder`/`establish()` for the
   Xray/VLESS path only - AmneziaWG's own manifest entry and `GoBackend`
   instantiation are completely untouched.
2. **A `VlessRealityTransport : VpnTransport`** adapter (mirroring
   `AmneziaWgTransport`'s existing shape) whose `connect()`/`disconnect()`
   drive `NovaXrayVpnService` + a `CoreController` instance, and whose
   `stats()` maps `QueryAllOutboundTrafficStats()` into the existing
   `TransportStats` model - no second stats system.
3. **`VpnController` gains no new "dual-tunnel" concept.** It already owns
   exactly one `VpnTransport` at a time (today: the AWG instance). A future
   Smart-Connect-driven switch is: `disconnect()` the current transport
   (already fully quiesced, per B8G1's own semantics) → `TransportOrchestrator`
   resolves the NEW decision into the other transport → `connect()` it. This
   is ordinary sequential connect/disconnect through the SAME serialized
   `connectMutex` VpnController already has - not a new concurrency model.
4. **Never silent:** the UI must show a real "Reconnecting via a different
   transport" state during that gap (a new `TransportState` case or a
   qualifier on `Reconnecting`), and diagnostics must never claim
   leak-free automatic switching unless `AlwaysOnVpnState` reports
   `CONFIRMED_ENABLED` for this session - matching B8G's existing, accepted
   truthful-UI discipline.
5. **DNS/IPv6/split-tunneling parity must be proven, not assumed**, before
   `VLESS_REALITY`'s `TransportCapabilities` claims `supportsIpv6`/
   `supportsSplitRouting` - each flips to `true` only once a real,
   evidenced test proves it, exactly like `TransportCapabilities.amneziaWg()`'s
   own doc already models ("kept false, not assumed, until each has its own
   verified evidence").
6. **Resolve the socket-protection open item FIRST**, before any of the
   above is implemented - an unprotected outbound socket is a correctness
   bug (the tunnel simply won't connect, looping into itself), not a
   cosmetic gap, so it blocks writing `VlessRealityTransport` at all, not
   just its "production-ready" claim.
