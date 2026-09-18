# B46-2A: Hysteria2 Android Feasibility PREPARATION

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
fabricating a result):** this session has no Android SDK
(`ANDROID_HOME`/`sdk.dir`) and no `kotlinc` CLI, so the added
`B46HysteriaSpikeStateTest.kt` could not be executed via
`./gradlew testDebugUnitTest` here (it failed at Gradle's SDK-location
check, before compiling any code - the same failure any Android Gradle
task hits in this container regardless of what code was added). The new
Kotlin was instead verified by hand against the already-merged, already
device-tested `B45ASpikeState.kt`/`B45ARuntimeTest.kt` pattern it
deliberately mirrors line-for-line in structure (pure state/transitions
type with no Android framework import, `require`/`check`-based transition
guards, idempotent stop, error-preserves-prior-fields discipline). B46-2P
(the first slice with a real device or a real Android SDK image) must run
this test suite for real before relying on it.

## 1. Upstream version / provenance

- Repository: `github.com/apernet/hysteria` (Go workspace: `app`, `core`,
  `extras` modules).
- Current stable release tag as of 2026-09-18: **`app/v2.6.3`**, published
  2026-09-12 (`git tag`/GitHub Releases, checked directly, not from memory).
- Exact commit checked out and built:
  **`a24ef5b8f003b8a3127c52a20696b5ee9daa1160`**.
- Default branch: `master`.
- Go toolchain: `go 1.23` module directive, `toolchain go1.24.2` (from
  `go.work`/`app/go.mod`, read directly from the clone - not the stale
  `go 1.26.0` a prior `WebFetch` render of `go.mod` misreported; the
  ACTUAL cloned file is authoritative and is what this section reports).
  Built here with the environment's installed `go1.24.7`, which satisfies
  both constraints.
- QUIC library: **`github.com/apernet/quic-go`** (an apernet-maintained
  fork of `quic-go/quic-go`, not upstream `quic-go` directly), resolved
  version `v0.52.1-0.20250607183305-9320c9d14431` per `go version -m` on
  the built artifact. This fork dependency is itself a supply-chain fact
  worth tracking (upstream `quic-go` security fixes land in the fork on
  its own schedule, not automatically).

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

**Hysteria2's own `tun` mode claims Android support in its own code
(`app/cmd/client.go:782`: `supportedPlatforms := []string{"linux",
"darwin", "windows", "android"}`), but that claim does not survive reading
the actual implementation.** `clientTUN()` builds a
`tun.Server{IfName: config.Name, ...}` (`app/internal/tun/server.go`)
using `github.com/apernet/sing-tun`, and ALWAYS has that library open the
TUN device itself (`sing-tun`'s `tun_linux.go` does support an
already-open `Options.FileDescriptor` - confirmed by reading
`sing-tun@v0.2.6-.../tun_linux.go:48-69`, which is exactly the mechanism a
VpnService-based Android app would need) - **but Hysteria2's own
`tunConfig` struct (`app/cmd/client.go`, fields: `name`, `mtu`, `timeout`,
`address`, `route`) has NO `fd`/`fileDescriptor` field, and
`app/internal/tun/server.go`'s own `Server` struct never threads one
through to `tun.Options` either.** The underlying library CAN accept a
pre-opened fd; the CLI/app layer Hysteria2 itself ships simply does not
expose that option. On stock Android, only the app process holding an
active `VpnService` instance can call `Builder.establish()` to get a
usable TUN fd - a plain child process (which is what the Hysteria2 binary
would be, following the exact same "own `VpnService`, protect a runtime
process/library" shape as AWG/Xray/Shadowsocks per
`docs/B46_QUIC_HTTP3_RESEARCH.md` Section 7's table) cannot create its own
Android TUN device. **Conclusion: Hysteria2's `android` listing in
`supportedPlatforms` is not evidence of a working, unprivileged, VpnService
-integrated Android TUN mode today - it is, at best, aspirational or
scoped to a context this research did not identify (e.g. a rooted/embedded
use, or a fork Nova would have to build).** This directly narrows and
corrects B46-1 Section 4.1, which did not go this deep into the TUN code
path and only noted third-party wrapper precedent generally.

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

## 5. FD Control protocol - exact semantics (verified against
`v2.hysteria.network/docs/advanced/FD-Control/` and the config schema in
the cloned source, `app/cmd/client.go:122`, `app/internal/sockopts/`)

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

## 6. TUN ownership - final design decision

**Nova owns the TUN device end to end** (same `VpnService.Builder`
pattern as every existing transport). Because Hysteria2's own `tun` mode
cannot accept a pre-opened fd (Section 4), Nova cannot reuse the exact
B45A/B45B shape of "hand the real TUN fd to the runtime, done." Instead a
future B46-2P design needs ONE of:

- **(a) Local-proxy relay (recommended default)**: Nova reads/writes the
  TUN fd itself (a small IP-packet-to-`socks5`-relay layer - conceptually
  a minimal tun2socks) and forwards demuxed TCP/UDP flows into Hysteria2's
  own `socks5` local listener (`app/cmd/client.go`'s `clientSOCKS5`,
  already a real, working, unmodified upstream code path - no fork
  needed). This is MORE new engineering than B45A/B45B needed (they got
  TUN-fd-to-runtime handoff "for free" from `sslocal`'s own tun mode) but
  requires ZERO upstream Hysteria2 changes.
- **(b) Patch/fork Hysteria2's `tunConfig`** to add the `fd`/
  `fileDescriptor` field `sing-tun` already supports one layer down, then
  build a Nova-vendored `hysteria` binary. This removes the need for (a)'s
  relay layer but creates an ongoing maintenance-fork burden (rebasing a
  local patch across every upstream release) that B46-1's own diversity
  reasoning explicitly wants to avoid duplicating for a second protocol -
  NOT recommended as the default path; only worth reconsidering if (a)'s
  performance/complexity proves unacceptable after physical testing.

This document recommends **(a)** as the default design for B46-2P, stated
explicitly rather than left implicit, because it needs no upstream code
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
- `android/app/src/test/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeStateTest.kt`
  - 9 unit tests covering the happy path, illegal-skip rejection
    (`dataPlaneReady` cannot be reached by skipping `fdControlReady`),
    idempotent stop, counter accumulation without cross-field mutation,
    and unexpected-exit handling.

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
- **Server version**: the same `app/v2.6.3` tag this document built the
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

## 12. Artifact / build results (Phase 3 and 4)

- **Build command** (run twice from a clean module-cache state was not
  literally repeated - see note below - but two independent build
  invocations against the SAME already-downloaded module cache were run
  and compared):
  ```
  cd app && GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o hysteria-android-arm64 .
  ```
- **CGO decision**: `CGO_ENABLED=0` was sufficient - the build succeeded
  with NO Android NDK present in this environment at all. This matches
  upstream's own release process (Hysteria2's official release binaries
  are pure-Go, no cgo) rather than requiring the NDK-clang cross-compile
  path B45A's Rust build needed.
- **ABI**: `arm64-v8a` (`GOARCH=arm64`), the same single-ABI starting
  choice B45B already made for Shadowsocks-rust.
- **Artifact type**: a standalone ELF executable (`hysteria` CLI with the
  `client` subcommand invoked at runtime), NOT a JNI/gomobile library -
  chosen because upstream itself ships and is primarily used as a CLI
  binary (mirroring B45A's `sslocal` executable-not-library precedent,
  not forced into a JNI shape it doesn't naturally have).
- **`readelf`/`file` results**: `ELF 64-bit LSB pie executable, ARM
  aarch64`, `Type: DYN (Position-Independent Executable file)`,
  interpreter `/system/bin/linker64` present in the program headers, but
  **zero `NEEDED` entries in the dynamic section** (`readelf -d` shows no
  shared-library dependencies) - a self-contained static-ish Go binary,
  the same shape as `sslocal`'s own ABI profile that B45's packaging
  fix already solved for.
- **Size**: 21 MB (20,971,873 bytes) stripped (`-ldflags="-s -w"`).
- **SHA-256**: `798bf09730535dea082141c3c685317cde4cb7d8d34c8dd9340f92cd2434ffce`
  (identical for both build invocations - see reproducibility below).
- **`go version -m`**: confirms `go1.24.7`, module path
  `github.com/apernet/hysteria/app/v2`, pinned dependency versions
  including `github.com/apernet/quic-go v0.52.1-0.20250607183305-9320c9d14431`
  (Section 1).
- **Reproducibility**: two independent `go build` invocations (same
  toolchain, same module cache, same commit, same flags) produced
  **byte-identical output** (matching SHA-256). This was NOT a from-
  bootstrap clean-module-cache rebuild (module downloads were only fetched
  once, then reused for both builds, for time/bandwidth reasons in this
  environment) - a stronger from-scratch-cache reproducibility test is a
  reasonable, cheap thing for B46-2P to redo, but is not expected to
  change the result given Go's own deterministic-build design.
- The binary was **kept in the scratch/build directory only**
  (`/tmp/hysteria-android-arm64-build{1,2}` outside the repo) and is
  **not committed to git** - only this hash/metadata record is, matching
  B45A's own precedent of not committing spike binaries.

## 13. ABI / packaging analysis (Phase 4)

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
to be needed, only re-application of B45A's fix to a second binary. The
binary's own shape (no `NEEDED` shared libs, static-ish PIE, standard
System V ELF) is at least as simple as `sslocal`'s, so no NEW ABI risk is
identified beyond what B45A already solved.

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

## 17. Idle/screen-lock issue analysis (Phase 9)

- **Issue tracked**: `apernet/hysteria#1510`, "Android: Hysteria2
  constantly drops connection when idle or screen locked," opened
  2026-01-30, referencing an earlier related report (`#1365`).
- **Current status as of 2026-09-18 (re-checked directly, not assumed
  fixed from B46-1's text)**: **still OPEN**. No maintainer
  acknowledgment/reproduction, no assigned fix, and no documented
  workaround were found in the issue as read. It is NOT closed and NOT
  marked fixed in any release note reviewed in this pass.
- **Affected layer**: the report is specifically about third-party
  Android WRAPPER clients (Husi, NekoBox, Excalve) rather than a
  Hysteria2-core-only repro with no VpnService/wrapper involved - the
  issue does not cleanly separate "Hysteria2 core protocol/QUIC-library
  bug" from "wrapper's own foreground-service/Doze handling bug," and this
  research pass did not find upstream language that isolates it to one
  side. **Treat as UNATTRIBUTED, not core-confirmed and not
  wrapper-confirmed**, until B46-2P's own physical test either reproduces
  it under Nova's OWN foreground-service/Doze handling (which already has
  real, tested discipline for every other transport) or shows it does not
  reproduce there.
- **Newer releases**: no release note reviewed in this pass (up to
  `app/v2.6.3`) claims a fix for this behavior.
- **Accepted workaround**: none found.
- **Doze/wakelock handling implication for Nova**: given the issue remains
  open and unattributed, Nova cannot assume Hysteria2's own QUIC
  keep-alive/idle-timeout tuning (`maxIdleTimeout`/`keepAlivePeriod` in
  server/client config) alone solves this - Nova's existing
  foreground-service/wakelock discipline (already applied uniformly across
  transports per `docs/B46_QUIC_HTTP3_RESEARCH.md`'s own table) must still
  be exercised specifically against Hysteria2's session, and **this is
  hereby marked a MANDATORY physical test case for the future B46 device
  validation** (Section 11's plan must include an explicit
  screen-lock/idle scenario, not just the connect/TCP/UDP/reconnect cases
  already listed) - not optional, not assumed pre-solved.

## Sources cited (external)

- [apernet/hysteria repository](https://github.com/apernet/hysteria)
- [apernet/hysteria releases](https://github.com/apernet/hysteria/releases) -
  tag `app/v2.6.3`
- [FD Control Protocol - Hysteria 2 docs](https://v2.hysteria.network/docs/advanced/FD-Control/)
- [Hysteria 2 Full Client Config docs](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [apernet/hysteria#1510 - Android idle/screen-lock disconnect issue](https://github.com/apernet/hysteria/issues/1510)
- [apernet/hysteria#1365 - prior related disconnection report](https://github.com/apernet/hysteria/issues/1365)
- Source read directly from the cloned repository at commit
  `a24ef5b8f003b8a3127c52a20696b5ee9daa1160`:
  `LICENSE.md`, `go.work`, `app/go.mod`, `app/cmd/client.go`,
  `app/internal/tun/server.go`, `app/internal/sockopts/sockopts.go`,
  `app/internal/sockopts/sockopts_linux.go`, and the vendored
  `github.com/apernet/sing-tun@v0.2.6-.../tun.go`/`tun_linux.go` in the
  local Go module cache (`/root/go/pkg/mod`) populated by this build.

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

## Final classification

**B. RESEARCH BLOCKED** - not on license, not on the core protocol, and
not on buildability (the arm64 artifact builds cleanly and reproducibly
with zero NDK and zero cgo), but specifically because **Hysteria2's own
shipped `tun` client mode cannot accept a VpnService-created TUN fd
(Section 4)**, which means the smallest credible Android spike needs a
genuinely new piece of engineering B45A/B45B's shadowsocks-rust spike did
not (a TUN-to-SOCKS5 relay layer, Section 6/15) before any physical device
test can even attempt `TUN_ESTABLISHED -> RUNTIME_STARTED`. This is a
named, precise, solvable problem (not a rejection of the protocol/license/
maintenance posture, all of which look credible) - B46-2P's first task is
exactly this relay-layer design (Section 16), not physical testing yet.
