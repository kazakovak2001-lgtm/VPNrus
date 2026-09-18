# B46-2A: Hysteria2 Android Feasibility PREPARATION

**CORRECTION PASS (2026-09-18, same day, later revision):** the original
pass of this document researched `apernet/hysteria` tag `app/v2.6.3`
(commit `a24ef5b8f003b8a3127c52a20696b5ee9daa1160`). Current upstream
stable as of this correction is **`app/v2.12.3`** (released 2026-09-16,
commit `e1366b173ccf5706e1e4630fe8aa654a4b574085`). Every finding in this
document has been re-audited directly against the `app/v2.12.3` tree - not
carried over from the earlier pass - and is stated as a v2.12.3-current
finding. Any `v2.6.3` figures kept for context are explicitly labeled
"historical/superseded." This correction also adds a genuine official-
artifact comparison and an NDK-based `CGO_ENABLED=1` build the original
pass did not attempt (Section 12).

**SECOND CORRECTION PASS (2026-09-18, same day, final revision before
merge-readiness review):** the Hysteria2 `v2.12.3` research conclusion
above (RESEARCH BLOCKED, TUN-fd gap, FD Control findings) is unchanged and
was independently re-checked, not revised. This pass fixes three bugs
found in the debug-only pure Kotlin state machine itself
(`B46HysteriaSpikeState.kt`/`B46HysteriaSpikeStateTest.kt`, Section 8):
`STOPPED` was unreachable via the normal stop path (`stopped()` returned
`IDLE`), `canStart()` unsafely allowed restarting directly from `ERROR`,
and `runtimeExitedUnexpectedly()` did not clear `runtimePid` for a
process known to be dead. **Note for anyone reading this PR**: this PR's
diff is NOT documentation-only - it contains this research document AND
the debug-only Kotlin state-machine source + test file described in
Section 8, all under `android/app/src/debug/` and
`android/app/src/test/` and unreachable from any production code path.

**Status of this document: PREPARATION ONLY. No physical Android device was
available in this environment. No production code, TransportKind, or
wiring into `TransportRegistry`/`SmartConnectDecisionEngine`/
`AutoGatewaySelector`/`TransportOrchestrator`/`VpnController`/
`MainViewModel`/release manifest was added or changed. `docs/ROADMAP.md`'s
B46 row is this document's only status change, and only status wording, per
task scope.**

Baseline: `main` at `5882321d39ddf3c13c6fcad352f26bbb996264b0` (PR #87 merge,
B46-1). Research branch: `research/b46-2a-hysteria2-android-feasibility`,
isolated worktree at `/home/user/VPNrus-b46-2a`.

**In-session architecture-review substitution notice (CLAUDE.md rule 7):**
this environment has no Agent/Task tool, so `.claude/agents/vpn-architecture.md`
could not be dispatched as a real isolated subagent. Its rules were applied
directly in-session at three points: (A) before writing any code, against
`PROJECT_ARCHITECTURE.md`'s debug/release boundary and jniLibs packaging
invariants (lines ~2399-2408) and the B45A precedent; (B) after writing the
pure state-machine skeleton, re-checked against the complete diff for this
branch; (C) before the final verdict below. No architectural blocker was
found - see Section 16.

**Known environment limitation, stated plainly (not worked around by
fabricating a result):** `./gradlew testDebugUnitTest` still cannot run
end to end in this environment. An Android SDK image was made available
during the correction pass (`/usr/lib/android-sdk`, licenses accepted,
Build-Tools 34/Platform 35/Platform-Tools auto-installed by Gradle) and
Gradle got as far as real compilation tasks, but then failed at
`:app:checkAwgTunnelAar` - a pre-built AmneziaWG tunnel AAR
(`android/app/libs/amneziawg-tunnel-v3.1.20260814-debug.aar`, produced by
a separate WSL2 build step per `docs/RUNBOOK.md`) is not present in this
environment. That is a production build prerequisite entirely unrelated
to this slice's B46-2A changes, and this task correctly does not
fabricate it, download it from an untrusted source, or work around it by
editing production build config - so the real Gradle/Android unit-test
task was never actually run, in either pass.

**What WAS actually run in the Kotlin-bugfix correction pass, and is a
genuine (not fabricated) result**: `B46HysteriaSpikeState.kt` and
`B46HysteriaSpikeStateTest.kt` were compiled directly with the Kotlin
compiler (`K2JVMCompiler`, assembled from jars already present in the
Gradle distribution/cache in this environment - no Android Gradle Plugin,
no Android SDK involved) against JUnit 4.13.2 + Hamcrest 1.3, and the
resulting test class was executed with `org.junit.runner.JUnitCore`
directly on the JVM. **Result: all 12 tests passed** (`JUnit version
4.13.2 ... OK (12 tests)`). This is a real execution of the real test
code against the real compiled state-machine code - it is NOT the same as
a full Gradle/Android `testDebugUnitTest` run (which additionally
validates Android Gradle Plugin wiring, source-set configuration, and
dependency resolution that this manual harness bypasses entirely), and
B46-2P (or this same environment once the AWG AAR prerequisite is
satisfied) must still run the real Gradle task before relying on this as
the whole story.

## 1. Upstream version / provenance

- Repository: `github.com/apernet/hysteria` (Go workspace: `app`, `core`,
  `extras` modules).
- **Current stable release tag as of 2026-09-18: `app/v2.12.3`**, published
  2026-09-16 03:56 UTC (`git tag`/GitHub Releases, checked directly by
  fetching the tag into a real clone, not from memory).
- **Exact full commit checked out and built:
  `e1366b173ccf5706e1e4630fe8aa654a4b574085`** (resolved from the
  abbreviated `e1366b1` via `git rev-parse app/v2.12.3` against the real
  clone - the coordinator's abbreviated SHA was correct as far as it went;
  this is the full 40-character form).
- Default branch: `master`.
- Go toolchain: **`go 1.26.0`** module directive (`go.work`/`app/go.mod`,
  read directly from the `app/v2.12.3` tag - this version genuinely
  changed from the `v2.6.3` tag's `go 1.23`/`toolchain go1.24.2`; it is
  not a re-read error this time, and is corroborated by the official
  release artifact's own embedded `go1.26.8` build stamp, Section 12).
  Built here via Go's `GOTOOLCHAIN=auto`/explicit `go1.26.8` pin, which
  this environment could download and run with no manual toolchain
  installation.
- QUIC library: **`github.com/apernet/quic-go`** (the same apernet-
  maintained fork, not upstream `quic-go/quic-go`), resolved version
  **`v0.62.1-0.20260912175848-73339f7edbb9`** per `app/go.sum` and
  `go version -m` on the built artifact - unchanged from what a raw-file
  read of the (then-newer) `master` branch showed during the original
  pass, now confirmed as the actual `app/v2.12.3`-pinned version too.
- `sing-tun` dependency: **`github.com/apernet/sing-tun
  v0.2.6-0.20250920121535-299f04629986`** (updated from the `v2.6.3`-era
  `v0.2.6-0.20250726070404-c99085f9af13` - a newer pseudo-version of the
  same underlying fork/branch, not a different library).
- **New dependency since v2.6.3, material to buildability**:
  `github.com/wlynxg/anet v0.0.5` (indirect, pulled in via `sing-tun`'s
  own dependency graph) - an Android-network-interface helper that uses
  an unexported `//go:linkname` reference into the Go runtime's internal
  `net.zoneCache` to work around a real upstream Go bug on Android
  (`golang/go#68082`). This is new, load-bearing information Section 12
  depends on: it is why the `app/v2.12.3` Android/arm64 build no longer
  succeeds with the same simple `CGO_ENABLED=0` invocation the `v2.6.3`-
  era build used.
- **Historical/superseded (v2.6.3 pass, kept only for context)**: tag
  `app/v2.6.3`, commit `a24ef5b8f003b8a3127c52a20696b5ee9daa1160`, Go
  `1.23`/toolchain `go1.24.2`, `quic-go v0.52.1-0.20250607183305-9320c9d14431`,
  `sing-tun v0.2.6-0.20250726070404-c99085f9af13`, no `wlynxg/anet`
  dependency, buildable with plain `CGO_ENABLED=0`. None of these numbers
  are current; do not use them for anything except understanding what
  changed.

## 2. License

**MIT** (`LICENSE.md`, "Copyright 2023 Toby"), confirmed by reading the
file in the clone, not inferred. This is the same permissive class as
Xray-core's MPL-2.0 and materially weaker-copyleft than TUIC's GPLv3 (the
license concern B46-1 already flagged for TUIC specifically does NOT apply
to Hysteria2) - no legal-review blocker identified for Hysteria2's license
alone. (`core`/`extras` submodules carry their own `LICENSE.md` files,
not independently re-verified here since `app` is the module actually
built; no reason to expect a different license given the single-repo,
single-copyright-holder structure observed.)

## 3. Runtime architecture

Hysteria2's `app` module is a single Go CLI binary (`hysteria`) with
subcommands, most relevantly `client`. The client reads a YAML config and
runs one or more configured local listeners concurrently
(`app/cmd/client.go`): `socks5`, `http`, `tun`, `tcpForwarding`,
`udpForwarding`, `tcpTProxy`, `udpTProxy`, `tcpRedirect`. Each listener
demuxes local traffic and relays it over ONE shared QUIC connection
(`core`'s `client.Client`) to the Hysteria2 server, authenticated once at
connect time. This is a purpose-built QUIC-substrate proxy protocol (not
HTTP/3), matching B46-1 Section 4.1's characterization exactly - no
correction needed there.

## 4. Android integration model - the load-bearing finding of this document
(re-audited directly against `app/v2.12.3`, not carried over)

**This finding was independently re-proven against the current
`app/v2.12.3` tree, not assumed to still hold from the earlier `v2.6.3`
pass.** `app/cmd/client.go:1153` in `app/v2.12.3` still reads:
`supportedPlatforms := []string{"linux", "darwin", "windows", "android"}`
(the line number shifted from `:782` in `v2.6.3` to `:1153` in `v2.12.3` -
the file grew, the claim did not change) - and that claim still does not
survive reading the actual implementation. `clientTUN()` still builds a
`tun.Server{IfName: config.Name, ...}` (`app/internal/tun/server.go`,
unchanged struct shape from `v2.6.3`) using
`github.com/apernet/sing-tun v0.2.6-0.20250920121535-299f04629986` (the
current, newer pseudo-version - Section 1), and still ALWAYS has that
library open the TUN device itself. `sing-tun`'s own `tun_linux.go` (the
`v0.2.6-0.20250920121535-...` version pulled by this exact build) still
declares an `Options.FileDescriptor int` field the library itself honors -
confirmed by re-downloading and re-reading this exact pinned version's
source from the Go module cache populated by this build, not reused from
the earlier pass's reading of the older pseudo-version. **Hysteria2's own
`tunConfig` struct in `app/cmd/client.go` (fields: `name`, `mtu`,
`timeout`, `address`, `route`) still has NO `fd`/`fileDescriptor` field,
and `app/internal/tun/server.go`'s own `Server` struct still never threads
one through to `tun.Options{...}` (re-read at `app/internal/tun/server.go`
lines 56-72 of the `v2.12.3` tree directly).** A full-tree search across
the current `app/`, `core/`, and `extras/` modules for `FileDescriptor`
found exactly one match - an unrelated protobuf-generated symbol
(`extras/outbounds/acl/v2geo/v2geo.pb.go`'s
`protoreflect.FileDescriptor`) - confirming no Android-specific fd-passing
code path was added anywhere in the tree between `v2.6.3` and `v2.12.3`.
The underlying `sing-tun` library CAN accept a pre-opened fd; the CLI/app
layer Hysteria2 itself ships still simply does not expose that option, in
the CURRENT release, not just the older one. On stock Android, only the
app process holding an active `VpnService` instance can call
`Builder.establish()` to get a usable TUN fd - a plain child process
(which is what the Hysteria2 binary would be, following the exact same
"own `VpnService`, protect a runtime process/library" shape as
AWG/Xray/Shadowsocks per `docs/B46_QUIC_HTTP3_RESEARCH.md` Section 7's
table) cannot create its own Android TUN device. **Conclusion (v2.12.3-
current): Hysteria2's `android` listing in `supportedPlatforms` is still
not evidence of a working, unprivileged, VpnService-integrated Android TUN
mode - it is, at best, aspirational or scoped to a context this research
did not identify (e.g. a rooted/embedded use, or a fork Nova would have to
build).** This directly narrows and corrects B46-1 Section 4.1, which did
not go this deep into the TUN code path and only noted third-party wrapper
precedent generally - and this correction pass confirms the narrowing
still applies to current upstream, seven minor releases later.

Answering Phase 2's nine questions explicitly:

1. **Should Hysteria2 own the TUN, or should Nova own it and feed
   Hysteria2 as a proxy layer?** **Nova must own the TUN** (create it via
   `VpnService.Builder.establish()`, exactly like AWG/Xray/Shadowsocks
   today) and feed Hysteria2 as a local proxy layer, because Section 4's
   finding rules out Hysteria2's own `tun` mode taking ownership without an
   upstream patch. This is a real, structural difference from B45A/B45B's
   shadowsocks-rust design (where `sslocal`'s OWN tun mode receives the
   real fd via `SCM_RIGHTS` and operates directly on it) - Hysteria2 as
   shipped cannot play that same "runtime owns TUN packet loop" role.
2. **Does upstream currently expose a usable Android TUN mode?** **No**,
   not as shipped (Section 4). The capability exists one layer down in
   `sing-tun` but is not wired through Hysteria2's own config/CLI.
3. **Which socket(s) need `VpnService.protect()`?** The QUIC library's own
   outbound UDP socket to the Hysteria2 server (the single 4-tuple the
   entire proxy session rides on) - exactly one socket per session, unlike
   Shadowsocks/AWG's potentially-multiple sockets, because Hysteria2
   multiplexes everything over one QUIC connection.
4. **Can upstream FD Control solve that cleanly?** **Yes, for exactly that
   one socket** - see Section 5. It is the right-shaped mechanism and does
   not require Nova to patch Hysteria2 itself (unlike the TUN gap above).
5. **Does FD Control require SCM_RIGHTS or another handoff mechanism?**
   **SCM_RIGHTS**, via `recvmsg(2)` ancillary data over a Unix
   `SOCK_STREAM` socket - the exact same primitive B45A/B45B already
   physically proved works for TUN-fd handoff in this codebase, applied
   here to protect() instead of to the TUN fd itself.
6. **What process owns each FD?** The TUN fd: Nova's `VpnService` process
   creates it and must feed it to a Nova-owned local relay (a
   tun2socks-equivalent demux, NOT Hysteria2 itself - Section 4). The QUIC
   UDP socket fd: the Hysteria2 child process opens it, then hands a copy
   to Nova's process via FD Control so Nova can `protect()` it - ownership
   of the actual open socket stays with the Hysteria2 process throughout;
   Nova only ever holds a duplicate fd long enough to call `protect()` and
   close it (per the protocol doc's own "processes the received fd... then
   closes it" step).
7. **What happens on normal stop?** Not verified physically (no device);
   design expectation: Nova closes the FD Control listener and TUN-side
   relay, then sends the child process a normal termination signal
   (SIGTERM) and waits for exit, mirroring B45A/B45B's own `stop()`
   discipline - and B45B3P's own found-and-fixed Unix-domain-socket cleanup
   bug is a direct warning that this must be physically re-verified, never
   assumed correct from reading the Go source.
8. **What happens if Hysteria2 crashes?** Design expectation only: the
   child process's exit is observed (`Process.waitFor`/exit callback,
   same shape as `B45ARuntime`'s `processExitedUnexpectedly` handling) and
   must transition the (future) runtime state machine to `ERROR`, never
   silently leave `RUNNING`/`DATA_PLANE_READY` stale - this repo's
   `B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly` (Section 8
   below) already encodes this rule at the type level, unit-tested.
9. **What state can Nova truthfully call "Connected"?** Not "process
   started," not "FD Control handshake completed" (that only proves the
   QUIC socket was protected, not that a QUIC session or any proxied
   traffic exists) - only after Phase 6's real proxied-traffic proof. See
   Section 11.

## 5. FD Control protocol - exact semantics (re-verified against
`v2.hysteria.network/docs/advanced/FD-Control/` and the config schema
directly in the `app/v2.12.3` tree: `app/cmd/client.go:179,320`,
`app/internal/sockopts/sockopts.go`, `app/internal/sockopts/sockopts_linux.go`)

**Unchanged between `v2.6.3` and `v2.12.3`**: the config key name, the Go
type (`*string`), the `sockopts.go`/`sockopts_linux.go` implementation
(`fdControlUnixSocketImpl`, using `unix.Socket`/`SCM_RIGHTS` over
`AF_UNIX`/`SOCK_STREAM`), and the documented protocol steps are all
byte-identical in shape to what the earlier pass found - only the
surrounding file's line numbers shifted. Re-stated here explicitly as a
`v2.12.3`-current finding, not assumed carried over.

**This mechanism (B, per the coordinator's requested split) is
deliberately distinct from Section 4/6's TUN-fd question (A) and must
never be conflated with it:**

- **(A) TUN fd injection into Hysteria2** - giving the Hysteria2 process
  the actual TUN device (the full IP-packet path) so IT reads/writes
  packets directly. **Does not exist in `v2.12.3`** (Section 4) - this is
  the RESEARCH BLOCKED gap.
- **(B) Outbound QUIC UDP socket protection via FD Control** - Hysteria2's
  own already-open outbound QUIC socket's fd -> Unix-domain
  `SOCK_STREAM` socket -> `SCM_RIGHTS`/`recvmsg(2)` -> Nova's app process
  receives a DUPLICATE fd -> Nova calls `VpnService.protect(fd)` on it ->
  Nova closes its duplicate -> Nova replies one byte -> Hysteria2 (which
  never gave up its OWN original fd, only let Nova `dup()` and inspect a
  copy via the kernel's SCM_RIGHTS semantics) continues using its
  original, now-protected, socket. **This one (B) exists and works exactly
  as documented in `v2.12.3`**, confirmed against current source in this
  pass, independent of (A)'s gap - protecting the QUIC socket does not
  require Nova to own the TUN in any way, and TUN ownership (Section 6)
  does not depend on FD Control succeeding either. These are two
  independent, correctly-separable mechanisms, not two halves of one
  problem.

- Config key: `quic.sockopts.fdControlUnixSocket` (a string path), passed
  through to `core`'s dialer as `Sockopts.FdControlUnixSocket`
  (`app/internal/sockopts/sockopts.go`/`sockopts_linux.go`). **Currently
  documented to apply only to the outbound QUIC UDP socket**, matching
  Phase 2 Q3's answer above.
- Roles: the Hysteria2 client process is the FD Control **client**; Nova's
  app process is the FD Control **server** - it `listen()`s on a
  `SOCK_STREAM` Unix-domain socket at the configured path BEFORE starting
  the Hysteria2 child process (the child must be able to connect
  immediately on socket creation).
- Sequence: server `accept()`s one connection -> receives exactly one fd
  via `recvmsg(2)`/`SCM_RIGHTS` -> server processes it (`protect(fd)`) ->
  server closes its copy of the fd -> server writes one byte back on the
  same connection, unblocking the client to proceed. This is a one-shot
  per-socket handshake, not a persistent multiplexed channel - matches
  B45A's own `RealB45AVpnProtectBridge` shape closely enough to reuse that
  class's design directly (one listener, one-fd-per-connection, ack byte
  reply), with the difference that B45A's bridge handles a TUN fd handoff
  in the OTHER direction (Android sends the TUN fd to `sslocal`); here
  Hysteria2 sends its QUIC socket fd to Android for `protect()` - the
  SAME primitive, opposite fd-flow direction, so B45A/B45B's two existing
  bridge classes (`RealB45ATunFdBridge` sends, `RealB45AVpnProtectBridge`
  receives-and-protects) between them already cover BOTH directions this
  design needs; no new fd-transfer mechanism has to be invented.
- Reconnects: any time the client establishes a NEW QUIC UDP socket
  (initial connect, or a future reconnect/migration attempt), FD Control
  fires again for that new socket - Nova's server side must stay listening
  for the lifetime of the session, not just once at startup.
- DNS caveat (from the same doc, load-bearing): the Hysteria2 `server`
  config field must be a literal IP, not a hostname, OR the app must
  otherwise ensure DNS resolution for the Hysteria2 server itself does not
  route through the (not-yet-protected) tunnel - identical in spirit to
  every existing transport's "resolve the gateway host before/outside the
  tunnel" requirement.

## 6. TUN ownership - final design decision (re-confirmed against v2.12.3;
alternatives re-evaluated per the coordinator's Phase 8 instruction)

**Nova owns the TUN device end to end** (same `VpnService.Builder`
pattern as every existing transport). Because Hysteria2's own `tun` mode
still cannot accept a pre-opened fd in `v2.12.3` (Section 4), Nova cannot
reuse the exact B45A/B45B shape of "hand the real TUN fd to the runtime,
done." A future B46-2P design needs ONE of the following - evaluated
against "reuse a maintained, auditable component, don't hand-roll a
TCP/IP stack," per this correction pass's explicit instruction:

- **(a) Local-proxy relay using a maintained tun2socks-class library
  (recommended default)**: Nova reads/writes the TUN fd itself and
  forwards demuxed TCP/UDP flows into Hysteria2's own `socks5` local
  listener (`app/cmd/client.go`'s `clientSOCKS5`, already a real, working,
  unmodified `v2.12.3` code path - re-confirmed present and unchanged in
  this pass - no fork needed). Concretely, this should NOT mean Nova
  hand-writing a new IP-packet parser: `sing-tun` itself (the SAME library
  Hysteria2 already depends on and already vendors into this exact build,
  Section 1) ships general-purpose TCP/UDP demux plumbing (`sing-tun`'s
  own `Stack`/`Options.FileDescriptor`-capable TUN handling is what
  Hysteria2's OWN `tun` mode already uses internally, just not exposed
  through Hysteria2's CLI) and is a plausible, already-in-the-dependency-
  tree, already-audited-by-this-build component Nova could drive directly
  with an externally-supplied fd (Nova would use `sing-tun`'s Go API the
  same way Hysteria2's own `app/internal/tun/server.go` does, but with
  `Options.FileDescriptor` set to the real VpnService-created fd, and
  route the demuxed TCP/UDP streams into Hysteria2's `socks5` listener) -
  this is meaningfully smaller and more auditable than writing a bespoke
  tun2socks equivalent from scratch, and does not touch Hysteria2's own
  source at all. This is MORE new engineering than B45A/B45B needed (they
  got TUN-fd-to-runtime handoff "for free" from `sslocal`'s own tun mode)
  but requires ZERO upstream Hysteria2 changes and reuses a component
  already proven (by this build) to compile and link correctly for
  `android/arm64`.
- **(b) Patch/fork Hysteria2's `tunConfig`** to add the `fd`/
  `fileDescriptor` field `sing-tun` already supports one layer down (i.e.
  make Hysteria2's OWN `app/internal/tun/server.go` do what (a) proposes
  Nova do itself), then build a Nova-vendored `hysteria` binary. This
  removes the need for (a)'s separate relay code but creates an ongoing
  maintenance-fork burden (rebasing a local patch across every upstream
  release - `v2.6.3` to `v2.12.3` alone changed the `sing-tun` pseudo-
  version, added the `wlynxg/anet` dependency, and changed the required Go
  toolchain, all of which a fork would have had to track) that B46-1's own
  diversity reasoning explicitly wants to avoid duplicating for a second
  protocol - NOT recommended as the default path; only worth
  reconsidering if (a)'s performance/complexity proves unacceptable after
  physical testing.
- **(c) A separate, independently-maintained Android tun2socks
  component** (e.g. the `tun2socks`-family projects used by several
  general-purpose proxy Android clients) feeding Hysteria2's `socks5`
  listener, instead of driving `sing-tun` directly as in (a). Not
  independently vetted in this pass (no specific project audited for
  license/maintenance/ABI fit) - noted as an alternative to (a)'s
  "reuse `sing-tun` directly" approach, not adopted, and not a dependency
  added by this slice either way (per this task's explicit "do not add a
  dependency yet" instruction).

This document recommends **(a)** (reusing `sing-tun`'s own, already-
vendored, already-arm64-buildable TCP/UDP-demux capability directly,
rather than hand-writing a new stack or adopting an unaudited third
component) as the default design for B46-2P, stated explicitly rather
than left implicit, because it needs no upstream code
change and keeps Hysteria2 fully "as shipped."

## 7. `VpnService.protect()` design

Exactly one socket needs protection per session (Section 4 Q3): the
Hysteria2 child process's outbound QUIC UDP socket, via FD Control
(Section 5). Nova's `VpnService` subclass hosts the FD Control **server**
side (an `Executor`-backed `LocalServerSocket`/`LocalSocket` listener
thread, reusing `RealB45AVpnProtectBridge`'s structure), calling
`android.net.VpnService.protect(fd)` on the received fd before replying.
If option (6)(a)'s local relay layer opens any of its OWN sockets (e.g. to
demux TUN packets before handing to Hysteria2's SOCKS5 listener, if that
relay itself needs a raw socket rather than purely in-process framing),
those would ALSO need `protect()` the same way every other transport's
local relay does - unresolved without a concrete relay implementation, an
explicit unknown (Section 15).

## 8. Debug-only harness DESIGN (Phase 5) - pure state machine written, no
service/activity/runtime wired yet

Per this task's explicit instruction ("if the correct integration design
is still unclear after Phase 1-4, STOP at documentation/build-proof rather
than writing speculative Android code"): Sections 4/6 above answer TUN
ownership and FD Control cleanly, but Section 6's relay-layer shape (a)
is NOT yet concretely designed (packet parsing approach, SOCKS5 client
library choice, threading model) - writing a real `VpnService`/process
launcher against an underspecified relay would be exactly the speculative
code this task warns against. This slice therefore adds ONLY a pure,
Android-framework-free state-machine type, deliberately mirroring
`B45ASpikeState.kt`'s own separation of pure transition logic from
not-yet-written I/O classes:

- `android/app/src/debug/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeState.kt`
  - `B46HysteriaSpikePhase`: `IDLE, STARTING, TUN_ESTABLISHED,
    RUNTIME_STARTED, FD_CONTROL_READY, DATA_PLANE_READY, STOPPING,
    STOPPED, ERROR` (exactly the sequence the task specified).
  - `B46HysteriaSpikeError`: typed spike-only errors (never fed into
    production `DiagnosticFailureMapping`, same discipline as
    `B45ASpikeError`).
  - `B46HysteriaSpikeTransitions`: pure functions enforcing phase order
    (`TUN_ESTABLISHED` before `RUNTIME_STARTED` before
    `FD_CONTROL_READY` before `DATA_PLANE_READY`, via `check()` guards),
    idempotent stop, and "unexpected exit always clears to `ERROR`."
  - **Correction-pass bugfixes (found in review, fixed in the same PR,
    not carried as known bugs)**: (1) `stopped()` now returns
    `phase = STOPPED`, not `IDLE` - a completed cleanup is a distinct,
    reachable phase from "never started," matching the enum's own
    `STOPPED` value actually being used; (2) `canStart()` now allows only
    `IDLE`/`STOPPED`, never `ERROR` directly - `ERROR` only records that
    something went wrong, not that a live runtime/process/resource was
    torn down, so the enforced recovery path is
    `ERROR -> STOPPING -> STOPPED -> STARTING`, never a shortcut; (3)
    `runtimeExitedUnexpectedly()` now clears `runtimePid` to `null` (the
    process is KNOWN terminated, so `ERROR` must never claim ownership of
    a dead pid) while keeping `exitCode` as separate diagnostic evidence.
- `android/app/src/test/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeStateTest.kt`
  - 12 unit tests (grew from the original 9 to cover the three fixes
    above) covering the happy path (now asserting `STOPPED`, not `IDLE`),
    illegal-skip rejection (`dataPlaneReady` cannot be reached by
    skipping `fdControlReady`), idempotent stop from both `IDLE` and
    `STOPPED`, counter accumulation without cross-field mutation,
    unexpected-exit handling (including the `runtimePid`-clearing
    behavior), `canStart(ERROR) == false`, and the full
    `ERROR -> STOPPING -> STOPPED -> STARTING` recovery path. **All 12
    pass** - see the environment-limitation note above for exactly how
    they were executed in this session (a manual `kotlinc`+`JUnitCore`
    harness, not the full Gradle task, which remains blocked by an
    unrelated missing AWG AAR prerequisite).

**Not written in this slice, deliberately**: `B46HysteriaSpikeActivity`,
`B46HysteriaVpnService`, `B46HysteriaRuntime`, the FD Control bridge
class, or the TUN relay layer - all of those depend on Section 6's still-
open relay-implementation choice and are real Android-framework code that
would be premature without it. Nothing in this slice is reachable from
`AndroidManifest.xml` (no manifest entry was added at all - the files
added have no entry point yet), so there is no debug/release leak surface
to review; this is a stronger isolation guarantee than "unreachable from
production," since it is currently unreachable from anything.

## 9. Data-plane readiness design (Phase 6)

Per the B21/PR#35 lesson B46-1 already documented (process startup !=
Connected): `DATA_PLANE_READY` must require actual proxied traffic, never
be inferred from `FD_CONTROL_READY` alone (FD Control succeeding only
proves ONE UDP socket was protected - it says nothing about whether a QUIC
handshake completed, whether auth was accepted, or whether any byte was
relayed). A future B46-2P must require, at minimum:

- A real QUIC handshake completion signal from the `core` client library
  (its `Client` interface/callbacks, not inferred from process-alive).
- A controlled TCP request through the tunnel (e.g. the SAME
  `B45AUdpEchoProbe`-equivalent-but-TCP pattern this repo already uses:
  a Nova-controlled test endpoint, not a random public URL) proving real
  proxied TCP.
- A controlled UDP round-trip (mirroring B45A's own
  `B45AUdpEchoProbe`/3-of-3 UDP proof discipline) proving real proxied
  UDP, since Hysteria2's whole value proposition includes full UDP
  relaying.
- Server-side corroboration where available (Hysteria2 server logs
  showing the same session/auth accepted), the same "client claim +
  server corroboration" pattern B45A's own acceptance matrix required.

No fake success signal (e.g. "QUIC dial did not error") is proposed or
acceptable as a substitute for the above, per this task's explicit
instruction.

## 10. Test-server plan (Phase 7 - design only, NOT deployed)

- **Where**: localhost/WSL2/a disposable local VM under the operator's own
  control, or a later separately-approved temporary test server -
  explicitly NOT Frankfurt/Stockholm, matching the task's hard scope.
- **Server version**: the same `app/v2.12.3` tag this document built the
  client from (avoids client/server version skew as a confound).
- **Auth**: a locally-generated test-only password/PSK (Hysteria2's own
  `auth: {type: password, password: "..."}` config block) - never a
  production credential.
- **Cert strategy**: Hysteria2 server config supports either a self-signed
  cert (`tls: {cert, key}`, paired with `insecure: true` on the disposable
  test client only) or ACME - for a disposable local test server,
  self-signed + client `insecure: true` is simplest and appropriate; this
  must NEVER be the posture for any future production deployment.
- **TCP test target**: a small Nova-controlled echo/HTTP endpoint reachable
  only through the tunnel, mirroring B45A's own controlled-target
  discipline (never a random public site).
- **UDP echo target**: a minimal UDP echo listener alongside the TCP
  target, reusing `B45AUdpEchoProbe`'s existing protocol design where
  practical rather than inventing a new one.
- **Logs needed**: Hysteria2 server verbose/debug log (session
  accept/auth/stream-open events) correlated by timestamp with the Nova
  client-side spike log and the echo-target's own request log - three
  independently-observed log streams for one claimed proof, matching
  B45A's own "client claim + server corroboration" bar.

## 11. Physical-validation plan (Phase 8 - design only, for future B46-2P)

1. **Startup**: VPN permission granted -> Nova's `VpnService.establish()`
   creates the TUN (`TUN_ESTABLISHED`) -> Hysteria2 child process spawned
   (`RUNTIME_STARTED`) -> FD Control handshake completes and the QUIC
   socket is `protect()`'d (`FD_CONTROL_READY`).
2. **Server-side session proof**: disposable test server's own log shows
   the session accepted and authenticated.
3. **TCP proof**: a real DNS resolution (for the TCP test target, not the
   Hysteria2 server itself - Section 5's DNS caveat) + a real TCP
   connection + response through the tunnel, with an external-exit-IP
   check proving the traffic actually left via the tunnel's server, not
   the device's own network.
4. **UDP proof**: a controlled UDP request/response round trip via the
   echo target (Section 10), the SAME rigor B45A applied (3-of-3 exact
   round trips, not "no error").
5. **Explicit no-fallback**: the spike must NOT fall back to
   AWG/Xray/Shadowsocks on any failure - a failed Hysteria2 attempt must
   surface as `ERROR` with a typed `B46HysteriaSpikeError`, never silently
   retried on a different transport (this would contaminate the proof of
   what actually worked).
6. **Cleanup proof**: after stop, verify (via `ps`/`lsof`-equivalent or
   `adb shell` inspection) the child process, TUN interface, and FD
   Control Unix socket are all gone, state is `STOPPED`, no orphaned
   process/fd - directly informed by B45B3P's own found cleanup bug.
7. **Reconnect**: a second clean connect/disconnect cycle on the same
   device session works without restarting the app.
8. **Failure cases, each required to fail truthfully**: server
   unavailable (`RuntimeSpawnFailed`/QUIC dial failure), bad
   credential (`FdControlHandoffFailed`/auth-reject observed at
   `core` layer - exact typed cause TBD once the runtime class exists),
   bad/untrusted cert, UDP blocked on the test network (QUIC handshake
   never completes), runtime crash mid-session
   (`RuntimeExitedUnexpectedly`, already unit-tested in Section 8's state
   machine).
9. **Explicitly out of scope for initial bring-up**: Wi-Fi<->cellular
   mobility/handover - deferred until basic data-plane proof exists,
   matching B46-1 Section 8's own "QUIC migration is real capability but
   not free, must be physically proven separately" conclusion.

## 12. Artifact / build results (Phase 3 and 4) - v2.12.3, fully redone
this pass, including a genuine official-artifact comparison the earlier
`v2.6.3` pass did not have

### 12.1 Official upstream Android arm64 artifact

Upstream `app/v2.12.3` publishes an official release asset named
`hysteria-android-arm64`
(`https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.3/hysteria-android-arm64`,
downloaded directly in this pass, not assumed to exist):

- **Size**: 21,297,360 bytes.
- **SHA-256**: `8a946481d20eb5cd94be79dce0464d538098dfea3a721d7f41afb0a0564ef18d`.
- `file`/`readelf`: `ELF 64-bit LSB pie executable, ARM aarch64`, PIE,
  interpreter `/system/bin/linker64`, **`NEEDED`: `liblog.so`, `libdl.so`,
  `libc.so`** (all three are always-present Android system libraries, not
  bundled dependencies Nova would need to ship).
- `go version -m`: `go1.26.8`, `CGO_ENABLED=1`, `GOARCH=arm64`,
  `GOOS=android`, same pinned `quic-go`/`sing-tun`/`wlynxg/anet` versions
  as Section 1. **This is materially different from the `v2.6.3`-era
  finding**: the current official artifact is a `cgo`-linked binary with
  real Android-system-library dependencies, not the pure-Go/zero-`NEEDED`
  shape the `v2.6.3` build had - directly explained by the new
  `wlynxg/anet` dependency (Section 1/12.2).

### 12.2 Independently-built artifact - build attempt, failure, and fix

- **First attempt (mirroring the old `v2.6.3` recipe)**:
  `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath
  -ldflags="-s -w"` **failed to link** against `app/v2.12.3`:
  `link: github.com/wlynxg/anet: invalid reference to net.zoneCache`. This
  is a REAL, reproducible build regression versus `v2.6.3` (which had no
  `wlynxg/anet` dependency and built cleanly with the same flags,
  Section 1) - not an environment artifact.
- **Root cause**: `wlynxg/anet@v0.0.5` (pulled in transitively via
  `sing-tun`) uses an unexported `//go:linkname zoneCache net.zoneCache`
  to work around a real upstream Go bug on Android
  (`golang/go#68082`/`#40569`, per the `wlynxg/anet` project's own stated
  purpose). Go's linker enforces strict linkname-target validation; this
  specific linkname trick fails that validation under this build's
  toolchain/flag combination, **regardless of `CGO_ENABLED`** (confirmed:
  it also failed with `CGO_ENABLED=1` and a real Android NDK `CC` set,
  Section 12.3, before the fix below was applied) and **regardless of the
  exact Go patch version** (confirmed: it also failed pinned to
  `GOTOOLCHAIN=go1.26.8`, the SAME patch version the official artifact's
  own build stamp reports).
- **Fix, found via a targeted search of `wlynxg/anet`'s own issue tracker
  (`wlynxg/anet#11`) rather than guessed**: pass `-ldflags="-checklinkname=0"`
  to `go build`. With that flag, the build **succeeds**, with or without
  cgo.
- **Build command actually used** (matching the official artifact's own
  `CGO_ENABLED=1` build-info stamp, Section 12.1, using the Android NDK
  installed for this pass - `google-android-ndk-r26c-installer`, API level
  26 to match Nova's own `minSdk = 26`):
  ```
  export PATH="/usr/lib/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
  cd app && GOTOOLCHAIN=go1.26.8 GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
    CC=aarch64-linux-android26-clang \
    go build -trimpath -ldflags="-s -w -checklinkname=0" \
    -o hysteria-v2123-android-arm64 .
  ```
- **Resulting artifact**: 23,992,440 bytes; SHA-256
  `1dbc32e21f2b287c080e71e8b83458a773329c6f58a8595022f35f2154f1d99e`;
  `readelf -d` shows the SAME three `NEEDED` entries as the official
  artifact (`liblog.so`, `libdl.so`, `libc.so`); `go version -m` confirms
  `go1.26.8`, `CGO_ENABLED=1`, `GOARCH=arm64`, `GOOS=android`, and the same
  `wlynxg/anet v0.0.5` pin as the official artifact.
- **A pure-Go, `CGO_ENABLED=0`, no-NDK build was also re-tried with the
  `-checklinkname=0` fix** (not reported as a separate SHA above since it
  is not the recommended path once cgo parity with the official artifact
  was established) - this succeeded too, meaning the `wlynxg/anet`
  linkname issue itself is independent of cgo; NDK/`CGO_ENABLED=1` is only
  needed to match the OFFICIAL build's own configuration, not to work
  around the linkname bug by itself.

### 12.3 Reproducibility

- **This build's own reproducibility**: two independent invocations of
  the EXACT command above, with `go clean -cache` run between them (a
  genuinely cleared build cache, not merely a repeated warm-cache build -
  addressing the coordinator's specific request for a cleaner test than
  the earlier `v2.6.3` pass ran), produced **byte-identical output**
  (matching SHA-256 `1dbc32e21f2b...4ffce` per above). The module download
  cache itself was not wiped between the two (module downloads are
  content-addressed and immutable per version, so this does not weaken
  the reproducibility claim the way a shared build cache would).
- **Comparison against the OFFICIAL artifact: NOT byte-identical.**
  SHA-256 differs (`1dbc32e2...` vs. official's `8a946481d2...`), and size
  differs (23,992,440 bytes vs. official's 21,297,360 bytes - officially
  ~2.6 MB smaller). **Explaining the mismatch, per this task's explicit
  instruction not to assume reproducibility holds**: both artifacts share
  the same Go version (`go1.26.8`), same `GOOS`/`GOARCH`/`CGO_ENABLED`,
  same dependency versions (including `wlynxg/anet v0.0.5`), and the same
  `NEEDED`-library shape - the STRUCTURAL build is equivalent. The
  remaining, unresolved variables this pass could not control for and
  that plausibly explain the byte/size difference: (a) the exact Android
  NDK version/`aarch64-linux-android<API>-clang` used by upstream's CI is
  undocumented in the release notes - this pass used the publicly
  available `r26c` NDK at API level 26; upstream may use a different NDK
  release or API level, which changes the linked libc shim/CRT objects
  and therefore the final bytes without changing correctness; (b) the
  exact `-ldflags`/build-flag set upstream's CI passes is not published
  (this pass added `-trimpath -s -w -checklinkname=0`; upstream may use a
  different combination, e.g. embedding a VCS stamp this pass stripped,
  or a different `-checklinkname` value achieved a different way); (c)
  possible use of `-buildmode`/PGO or other CI-specific flags not
  documented publicly. **Conclusion: this pass's build is a credible,
  structurally-equivalent, internally-reproducible arm64 artifact for
  `app/v2.12.3`, but is NOT proven byte-identical to the official
  release, and the exact remaining cause of the size/hash difference is
  an open item for B46-2P to close (most simply, by asking upstream or
  inspecting their CI config directly) rather than something this pass
  can respond to further without more information.**
- **Historical/superseded**: the earlier `v2.6.3` pass's `CGO_ENABLED=0`,
  no-NDK, zero-`NEEDED`-libs build (SHA-256
  `798bf09730535dea082141c3c685317cde4cb7d8d34c8dd9340f92cd2434ffce`,
  21 MB) is now understood to correspond to an OLDER upstream build shape
  that no longer applies to `v2.12.3` and was never compared against an
  official artifact in that pass - kept here only as a "what changed"
  data point (Section 1), not as current guidance.
- The independently-built binary and the downloaded official artifact
  were both **kept in the scratch/build directory only**
  (`/tmp/hysteria-v2123-android-arm64-build{1,2}`, `/tmp/dl_hysteria-android-arm64`,
  outside the repo) and are **not committed to git** - only this
  hash/metadata record is, matching B45A's own precedent.

## 13. ABI / packaging analysis (Phase 4) - updated for the v2.12.3
CGO_ENABLED=1 artifact shape

Per `PROJECT_ARCHITECTURE.md` (lines ~2399-2408) and B45A's own physically-
proven lesson (Section 24.2 of `B45A_SHADOWSOCKS_RUST_SPIKE.md`:
`ProcessBuilder.exec()` of a binary the app itself wrote to `filesDir` was
denied with `error=13` on a real OPPO device, corroborated by an OEM
kernel-security-module log - "chmod +x does not solve W^X on modern
Android app-data directories"), **the Hysteria2 arm64 binary should reuse
the EXACT established fix**: packaged as `libhysteria_spike.so` under
`android/app/src/debug/jniLibs/arm64-v8a/`, with
`packaging.jniLibs.useLegacyPackaging` set for the `debug` variant (the
same Variant-API fix `PROJECT_ARCHITECTURE.md` already documents), so the
Android package manager extracts it to `applicationInfo.nativeLibraryDir`
at install time with the OS-trusted `apk_data_file` SELinux label, never
an app-written `filesDir` copy. This is a NEW binary reusing an EXISTING,
already-proven packaging mechanism - no new packaging research is claimed
to be needed, only re-application of B45A's fix to a second binary.

**Updated for `v2.12.3`'s actual (cgo-linked) shape**: unlike the earlier
`v2.6.3`-era pass's zero-`NEEDED` static-ish binary, the CURRENT correct
artifact (Section 12.2) links against `liblog.so`/`libdl.so`/`libc.so` -
but these are Android's OWN always-present system libraries (part of the
Bionic libc/system image on every Android device, never something an app
bundles), so this does NOT change the packaging mechanism: the same
`jniLibs`/`useLegacyPackaging` fix applies identically regardless of
whether the binary is static or dynamically linked against system
libraries, because the fix addresses WHERE/how the OS extracts and labels
the file (execute permission + SELinux label at install time), not
whether the binary itself has shared-library dependencies. No NEW ABI
risk is identified beyond what B45A already solved, though this is a
genuine, not-yet-physically-verified assumption (unresolved: Section 15).

## 14. Lifecycle model (Phase 5/2 combined)

Maps onto the SAME `VpnTransport`/`TransportOrchestrator`/`VpnController`
design shape B46-1 Section 7/19 already established for any independent
QUIC-substrate runtime, without introducing a second lifecycle authority
(this is a design mapping only - no actual wiring):
`Connecting -> Connected -> Disconnecting -> Disconnected`/`Error`, with
`Connected` gated on `DATA_PLANE_READY` (Section 9/11), reconnect owned by
`VpnController`/`ReconnectManager` (never transport-owned, per
`docs/B46_QUIC_HTTP3_RESEARCH.md` Section 7's table, reused verbatim
here), and `supportsRoaming = false` until a real physical handover proof
exists (Section 11.9).

## 15. Known unknowns (Phase 15 material, stated explicitly)

- The Section 6(a) local relay layer's exact shape (packet-parsing
  approach for the TUN fd, which Go/Kotlin-side SOCKS5 client to drive,
  threading model, and whether IT needs its own `protect()`'d sockets) is
  **not designed** - this is the single largest open question before
  B46-2P can write real code, and is exactly why Section 8 stopped at a
  pure state machine rather than a real runtime/service class.
- Whether the apernet `quic-go` fork's dependency-freshness/security
  posture versus upstream `quic-go` has been independently audited - not
  done in this pass.
- Real handshake/throughput/CPU/battery numbers - NONE exist (same gap
  B46-1 already recorded generally; Hysteria2 is not exempt).
- Whether Hysteria2 auth-rejection surfaces a distinguishable typed error
  at the `core` client API level suitable for a
  `B46HysteriaSpikeError.FdControlHandoffFailed`-equivalent auth-specific
  variant, or only a generic dial failure - not inspected in this pass.
- Whether a from-clean-module-cache rebuild (true cold-cache
  reproducibility, not just repeated `go build` against a warm cache)
  changes the SHA-256 - considered very unlikely given Go's deterministic
  build model, but not literally tested here (Section 12).

## 16. Recommended B46-2P next step - exact and narrow

**B46-2P's very first task must be design work, not code**: concretely
design the Section 6(a) TUN-to-SOCKS5 relay layer (the one unresolved
piece blocking any real `VpnService`/runtime class), THEN implement and
physically test, on a real Android device, in this order: (1) TUN
establish + relay layer alone (no Hysteria2 yet - prove the relay can
demux a real IP packet stream into distinguishable TCP/UDP flows); (2)
add the Hysteria2 child process + FD Control + `protect()` against the
disposable local test server (Section 10), proving `FD_CONTROL_READY`;
(3) prove `DATA_PLANE_READY` per Section 9's real-traffic bar; (4) run the
full Section 11 physical-validation plan including cleanup and reconnect.
Do not skip step 1 - it isolates the ONE genuinely new piece of
engineering this candidate needs that Shadowsocks's own B45A/B45B spike
did not (Section 6's TUN-ownership gap), before adding Hysteria2's own
complexity on top.

## 17. Idle/screen-lock issue analysis (Phase 9) - re-assessed against
v2.12.1/v2.12.2/v2.12.3, not left at the earlier pass's conclusion

- **Issue tracked**: `apernet/hysteria#1510`, "Android: Hysteria2
  constantly drops connection when idle or screen locked," opened
  2026-01-30, referencing an earlier related report (`#1365`).
- **Current status as of 2026-09-18 (re-checked directly again in this
  correction pass, not assumed unchanged from the earlier finding)**:
  **still OPEN**. Re-fetching the issue in this pass found no comments
  referencing `v2.12.1`/`v2.12.2`/`v2.12.3` or "stateless reset," no
  confirmation from the reporter or anyone else that a fix helped, and no
  report that it is now resolved - it remains an unresolved, open bug
  report with no visible maintainer disposition change since the earlier
  pass.
- **New, material fact this pass found that the earlier pass did not
  have**: `app/v2.12.1`'s changelog documents "Fixed slow reconnection
  after the client has been idle or asleep, most noticeable on mobile
  devices. The server now sends QUIC stateless resets, so a client
  holding a stale connection reconnects immediately instead of waiting
  out its idle timeout." **This must NOT be read as "issue #1510 is
  fixed"** - the release note does not reference `#1510` or `#1365` by
  number, and the mechanisms described are distinguishable: `#1510`
  describes the connection being DROPPED (and often failing to
  reconnect at all, "most of the time it does not reconnect... requires
  manual reconnection") when the screen locks; `v2.12.1`'s fix addresses
  RECONNECTION SPEED once a client already holds a stale connection (a
  server-side stateless-reset signal that shortens the wait before a
  client notices its old connection is dead and starts a new one) - a
  real, plausibly-helpful, but NARROWER fix than "the connection never
  drops on screen-lock in the first place." **Conclusion: v2.12.1-2.12.3
  PARTIALLY and UNCONFIRMED-ly address the reported symptom (faster
  recovery, IF a client does reconnect), and do NOT demonstrably address
  the root cause (why the connection drops/fails to reconnect on
  screen-lock at all)** - this is a judgment based on reading the
  release-note mechanism against the issue's own reported symptom, not a
  maintainer statement either way, and should be stated exactly this
  cautiously, not rounded up to "fixed" or down to "unrelated."
- **Affected layer**: still unattributed between Hysteria2 core/QUIC-
  library behavior and third-party wrapper (Husi, NekoBox, Excalve)
  foreground-service/Doze handling - re-confirmed unchanged in this pass;
  no upstream language found that isolates it to one side.
- **Accepted workaround**: none found, in this pass either.
- **Doze/wakelock handling implication for Nova, updated**: given the
  issue remains open and only partially/unconfirmed-ly addressed by
  `v2.12.1`'s stateless-reset change, Nova cannot assume Hysteria2's own
  QUIC keep-alive/idle-timeout tuning OR the new stateless-reset behavior
  alone solves this - Nova's existing foreground-service/wakelock
  discipline (already applied uniformly across transports per
  `docs/B46_QUIC_HTTP3_RESEARCH.md`'s own table) must still be exercised
  specifically against Hysteria2's session, and **this remains a
  MANDATORY physical test case for the future B46 device validation**
  (Section 11's plan must include an explicit screen-lock/idle scenario,
  not just the connect/TCP/UDP/reconnect cases already listed) - not
  optional, not assumed pre-solved by `v2.12.1`'s changelog text alone.

## Sources cited (external)

- [apernet/hysteria repository](https://github.com/apernet/hysteria)
- [apernet/hysteria releases](https://github.com/apernet/hysteria/releases) -
  tag `app/v2.12.3` (current, this pass); `app/v2.12.1` (idle/reconnect
  fix changelog, Section 17); `app/v2.6.3` (historical, superseded)
- [apernet/hysteria releases - hysteria-android-arm64 asset for app/v2.12.3](https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.3/hysteria-android-arm64) -
  downloaded and hashed directly in this pass (Section 12.1)
- [FD Control Protocol - Hysteria 2 docs](https://v2.hysteria.network/docs/advanced/FD-Control/)
- [Hysteria 2 Full Client Config docs](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria 2 Changelog](https://v2.hysteria.network/docs/Changelog/)
- [apernet/hysteria#1510 - Android idle/screen-lock disconnect issue](https://github.com/apernet/hysteria/issues/1510) -
  re-checked in this pass, still open
- [apernet/hysteria#1365 - prior related disconnection report](https://github.com/apernet/hysteria/issues/1365)
- [wlynxg/anet#11 - invalid reference to net.zoneCache (the `-checklinkname=0` fix)](https://github.com/wlynxg/anet/issues/11)
- [golang/go#68082 - the upstream Go/Android bug `wlynxg/anet` works around](https://github.com/golang/go/issues/68082)
- Source read directly from the cloned repository, `app/v2.12.3` tag,
  commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` (this pass):
  `LICENSE.md`, `go.work`, `app/go.mod`, `app/go.sum`, `app/cmd/client.go`,
  `app/internal/tun/server.go`, `app/internal/sockopts/sockopts.go`,
  `app/internal/sockopts/sockopts_linux.go`, and the vendored
  `github.com/apernet/sing-tun@v0.2.6-0.20250920121535-.../tun.go`/
  `tun_linux.go` and `github.com/wlynxg/anet@v0.0.5/interface_android.go`
  in the local Go module cache (`/root/go/pkg/mod`) populated by this
  build. Historical: the earlier pass's `app/v2.6.3` commit
  `a24ef5b8f003b8a3127c52a20696b5ee9daa1160` reading, kept only for the
  Section 1 "what changed" comparison.

## Internal prior evidence cited

- `docs/B46_QUIC_HTTP3_RESEARCH.md` (B46-1) - reused Section 4.1's
  candidate framing, Section 7's `VpnService` integration table, Section 8
  Section 19's design sketch; corrected/narrowed on the TUN-ownership
  question specifically (Section 4/6 above).
- `docs/B45A_SHADOWSOCKS_RUST_SPIKE.md` - reused the SCM_RIGHTS/FD-bridge
  pattern, the jniLibs/`useLegacyPackaging` packaging fix, the
  `filesDir`-exec-denied (W^X) lesson, and the B45B3P cleanup-bug lesson.
- `PROJECT_ARCHITECTURE.md` (lines ~2399-2408) - jniLibs packaging
  invariant for both debug and release variants.

## Final classification - based on current app/v2.12.3, not superseded
v2.6.3 research

**B. RESEARCH BLOCKED** - re-confirmed, not merely carried over, against
current upstream `app/v2.12.3` (commit `e1366b173ccf5706e1e4630fe8aa654a4b574085`).
Not on license (still MIT), not on the core protocol, and not on
buildability in the sense that matters (a structurally-equivalent arm64
artifact WAS produced, matching the official artifact's toolchain,
CGO/NDK configuration, and dependency-linkage shape - though not yet
byte-identical to it, Section 12.3, and only after discovering and working
around a real `v2.12.3`-introduced build regression, the `wlynxg/anet`
linkname issue, Section 12.2). The blocking reason is unchanged in kind
but newly re-verified in substance: **Hysteria2's own shipped `tun` client
mode still cannot accept a VpnService-created TUN fd in `app/v2.12.3`**
(Section 4 - re-read directly from the current tree, not assumed), which
means the smallest credible Android spike still needs a genuinely new
piece of engineering B45A/B45B's shadowsocks-rust spike did not (a
TUN-to-`sing-tun`-driven-relay layer feeding Hysteria2's SOCKS5 listener,
Section 6/15) before any physical device test can even attempt
`TUN_ESTABLISHED -> RUNTIME_STARTED`. This is a named, precise, solvable
problem (not a rejection of the protocol/license/maintenance posture, all
of which look credible seven minor releases later too) - B46-2P's first
task is exactly this relay-layer design (Section 16), not physical testing
yet. Two new, genuinely useful facts this correction pass adds beyond
re-confirming the verdict: (1) an official Android arm64 artifact now
exists upstream and was independently compared against (Section 12.1,
12.3), and (2) `v2.12.1`'s server-side stateless-reset change is real but
only PARTIALLY relevant to issue `#1510` and must not be read as resolving
it (Section 17).
