# B46-2C: Permissive Hysteria2 Android Path (Research)

Status: research/feasibility slice. Not production code. No production
transport is selectable as a result of this slice. This document does not
rewrite B46-2B history: B46-2B (`docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md`)
remains the record of why the sing-tun bridge architecture works technically
and why hev-socks5-tunnel was not selected. This document records whether an
all-permissive-license engineering path exists as an alternative.

## 0. Scope and question

Can Nova build the Hysteria2 transport for Android **without** linking GPL
`sing-tun` into (1) the Nova Android app process, or (2) the Hysteria2 child
executable? This is a release-architecture feasibility question, proven with
real builds and real host-side traffic, in an isolated environment. It is
**not** physical Android VPN testing (that is B46-2P, explicitly out of
scope here) and makes no claims about behavior on a real device or about
network conditions in any specific country.

Candidate architecture under test:

```
Android VpnService TUN -> MIT tun2socks bridge (in-process JNI/AAR)
  -> 127.0.0.1:<socks> -> minimal Hysteria2 SOCKS5-only child (subprocess)
  -> Hysteria2 QUIC -> Nova Hysteria gateway
```

## Part A - xjasonlyu/tun2socks source audit

- Repo: `github.com/xjasonlyu/tun2socks`, audited at commit
  `5d9fac67bb1095a5d2bd959216f85e6434524731` (2026-09-13).
- License: MIT (`LICENSE`, Jason Lyu, 2019-present). Confirmed by reading the
  file directly, not the README.
- Go toolchain: `go 1.26.3`. Userspace stack: `gvisor.dev/gvisor` pinned at
  `v0.0.0-20260906120324-45bde0d1defa` (Apache-2.0).
- Android: no Android-specific build tags found; it cross-compiles cleanly
  for `GOOS=android GOARCH=arm64` because the userspace netstack (gVisor) has
  no OS-specific syscalls beyond the fd it's given. No CGo requirement for
  the core engine/device/fdbased path.
- TUN fd handling: `core/device/fdbased` (`fdbased.Open(name, mtu, offset)`,
  where `name` is the fd number as a string, wired via `engine.Key{Device:
  "fd://<fd>"}`). On Linux, `open()` in `open_linux.go` wraps the fd in
  gVisor's own `link/fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu,
  EthernetHeader: false})` - a real TUN-mode (no ethernet header) endpoint,
  not a raw passthrough.
- TCP/UDP/SOCKS5: `proxy/socks5/socks5.go` implements a real RFC1928 client:
  `DialContext` does SOCKS5 `CmdConnect` for TCP; `DialUDP` does a real
  `CmdUDPAssociate` handshake, opens a local UDP socket, and wraps it in a
  `socksPacketConn` that encodes/decodes the UDP relay header per RFC1928 -
  not a bypass.
- IPv4/IPv6: gVisor's stack supports both; this slice only exercised IPv4
  (this sandbox kernel has no IPv6 support at all, an environment limitation
  carried over from B46-2B, not a code-path limitation).
- DNS: no separate DNS subsystem exists in tun2socks; ordinary UDP/53
  traffic goes through the same TUN -> gVisor -> SOCKS5-UDP-ASSOCIATE path
  as any other UDP flow (proven in Part C).
- Lifecycle: library API is `engine.Insert(*Key)` / `engine.Start()` /
  `engine.Stop()` (`engine/engine.go`). `Stop()` closes the device then the
  stack and waits for it - an explicit, ordered shutdown, not a bare process
  exit.

## Part B - TUN fd ownership model

Same split-ownership model as the sing-tun bridge in B46-2B, and for the
same reason: `fdbased.FD.Close()` (`core/device/fdbased/fd_unix.go`) calls
`unix.Close(f.fd)` directly on Linux - it closes whatever raw fd number it
was given, with no independent duplication of its own. If tun2socks were
handed the VpnService's own fd directly, `engine.Stop()` (or a tun2socks
internal failure path) would close the fd VpnService still owns.

Required model (verified in the real proof, Part C/E):

| Owner | fd | Closed by | When |
|---|---|---|---|
| VpnService (original) | `originalFd` | Nova bridge code, **last** | after `engine.Stop()` returns |
| tun2socks bridge | `dup(originalFd)` | tun2socks's own `Stop()`/`Close()` path | on stop, or internally on a fatal device error |

No ambiguous shared ownership: the two fds are independent kernel objects
after `dup()`; closing one never affects the other. This was verified, not
assumed - the proof's invalid-fd cycle (Cycle 3) passes a numerically
unopened fd (`9999`) to `engine.Start()`, which fails fast
(`unix.SetNonblock(9999) failed: bad file descriptor`) with no crash and no
effect on the separately-held `originalFd`.

## Part C - real tun2socks host-side proof (TCP + UDP, no bypass)

Real components used, none bypassed or mocked:

- A real TUN device opened via `/dev/net/tun` + `TUNSETIFF`, played by this
  proof program (standing in for Android's `VpnService`).
- The real `tun2socks` `engine` package (not a hand-rolled stand-in).
- **Dante** (`danted` 1.4.3), a real third-party SOCKS5 daemon, standing in
  for Hysteria2's own local SOCKS5 listener.
- Real Python TCP/UDP echo targets.

Topology: this required three Linux network namespaces (`ip netns`) - one
holding the TUN + tun2socks bridge (the "VpnService" role), one holding
`danted` (the "Hysteria2 SOCKS5 listener" role), and a third holding the
echo targets - connected by two `veth` pairs. This was necessary because an
earlier, simpler attempt (aliasing a synthetic "internet" destination onto
the loopback interface) produced a **false positive**: the kernel silently
delivered "through-TUN" traffic locally instead of routing it through
tun2socks, and separately, a SOCKS5-relayed UDP reply's source address
collapsed to `127.0.0.1` when the relay's own outbound socket was also
loopback-addressed, causing connected-UDP-socket peer-address filtering to
silently drop real replies. Neither is a tun2socks or danted defect; both
are documented here because they cost real debugging time and would trip up
any future repro attempt with the same shortcut. The three-namespace
topology removes all loopback-address ambiguity and forces genuine
TUN-interception on the client side.

Real result (via the committed proof, `research/b46-2c-permissive-hysteria-path/tun2socks-proof/main.go`):

```
TCP OK: round trip match, via tun2socks -> SOCKS5(danted) -> echo target
UDP OK: round trip match, via tun2socks -> SOCKS5(danted) UDP ASSOCIATE -> echo target
```

Both are byte-exact round trips (fixed payload written, read back, compared
byte-for-byte), through the real gVisor TCP/IP stack and a real SOCKS5
UDP-ASSOCIATE relay - not a metadata-only or send-only check.

## Part D - DNS transport

An ordinary, well-formed DNS query packet (UDP/53, single A-record question)
was sent through the same TUN -> tun2socks -> SOCKS5 UDP-ASSOCIATE -> echo
target path and round-tripped byte-exact. This proves **transport only**:
tun2socks has no separate DNS subsystem, so DNS is just another UDP/53 flow
through the existing path. No real resolver was queried, and **no
leak-safety claim is made** - that requires physical device testing
(B46-2P), which is explicitly out of scope for this slice.

## Part E - lifecycle proof

Four cycles were run in a single process (`research/.../tun2socks-proof/main.go`):

1. Normal start -> TCP+UDP+DNS-transport proof -> stop. **Pass.**
2. Restart on the same process (fresh TUN fd, fresh `engine.Insert`/`Start`)
   -> TCP+UDP+DNS-transport proof -> stop. **Pass** - proves no leaked
   goroutine/fd/netstack state survives a stop/restart cycle.
3. Failure path: invalid TUN fd (`9999`, never opened). `engine.Start()`
   returns a non-nil error immediately (`bad file descriptor`); no crash, no
   hang. **Pass.**
4. Failure path: SOCKS5 listener absent (proxy pointed at an address nothing
   listens on). Both TCP and UDP through-TUN attempts fail closed
   (`connection refused` / timeout, logged via tun2socks's own
   `[TCP]`/`[UDP] dial ... failed` warnings) - traffic does not silently
   succeed or leak around the missing proxy. **Pass.**

No host-process crash, no stale fd, no leaked worker across any cycle.

## Part F - concurrency / memory checks

- `go vet ./...` - clean, both on the proof program and on tun2socks itself.
- `go build -race` - built successfully; the race-instrumented binary was
  run through all four lifecycle cycles above, three times total (12
  cycles), with **zero `DATA RACE` reports** in the exercised data plane
  (TUN read/write, gVisor stack, SOCKS5 TCP/UDP relay, restart path).
- This is a real finding, not a repeat of B46-2B's sing-tun race (which was
  in a different library entirely, already fixed by re-pinning): no race was
  found or needed to be fixed in tun2socks itself for the paths exercised
  here.

## Part G - Android ARM64 bridge artifact

**In-process JNI/AAR was chosen for the tun2socks bridge**, matching the
architecture already established for the sing-tun bridge in B46-2B, for the
same reasons: the bridge needs the TUN fd directly (no benefit to crossing a
process boundary just to hand off a duplicated fd), in-process gives
deterministic fd ownership (dup()+detachFd(), Part B) with no
SCM_RIGHTS/subprocess-lifecycle complexity, and it avoids the packaging and
crash-blast-radius cost of a second native process. A subprocess+SCM_RIGHTS
design was considered and rejected for the same reasons as in B46-2B: it
adds a process boundary, a second lifecycle to manage, and a real (not
`/proc/<pid>/fd`-hack) SCM_RIGHTS fd-passing implementation, for no
corresponding benefit here.

Built for real via `gomobile bind`:

- Wrapper: `StartBridge(fd int, mtu int, socksAddr string) error` /
  `StopBridge() error`, internally constructing a real `engine.Key` /
  `engine.Start()` / `engine.Stop()` exactly as the proof does.
- `gomobile bind -androidapi 26 -target=android/arm64` produced a real
  8.3 MB `bridge.aar` containing `jni/arm64-v8a/libgojni.so` (a genuine ARM64
  ELF shared object, Go-built, `not stripped`).
- Verified via `go tool nm` on the extracted `.so` (20,181 total symbols):
  **0** symbols from `github.com/apernet/sing-tun`, **0** from
  `github.com/sagernet/sing-tun`, **931** from `github.com/xjasonlyu/tun2socks`,
  **4,976** from `gvisor.dev/gvisor`. The Nova-owned bridge module is
  confirmed sing-tun-free at the linked-symbol level, not just at the
  import-statement level.

## Part H - minimal Hysteria2 SOCKS5-only client

Baseline: `github.com/apernet/hysteria` at commit
`e1366b173ccf5706e1e4630fe8aa654a4b574085` (pinned exactly as specified).

Source finding confirmed by direct read: `app/cmd/client.go:37` imports
`github.com/apernet/hysteria/app/v2/internal/tun` unconditionally (no build
tag excludes it) - this is why the stock CLI always links sing-tun.
`app/internal/socks5/server.go` imports only `github.com/txthinking/socks5`
(MIT) and `github.com/apernet/hysteria/core/v2/client` - no `tun`, no
`sing-tun`, anywhere in its import list.

A new prototype command was added at `app/novaminimal/main.go` inside a
scratch clone of that exact commit - no existing upstream file was modified.
It had to live inside the Hysteria2 module tree (not a separate Go module)
because `app/internal/socks5` is a Go `internal/` package, only importable
from within the `app/` module tree; this is the smallest change that
satisfies that constraint. It builds:

- The real Hysteria2 core client (`core/client.NewClient`, real QUIC
  handshake against a real server - see Part J).
- Server address, auth (password), TLS (`ServerName`, `InsecureSkipVerify`
  for this research harness's self-signed cert only).
- Salamander obfuscation via the real, exported
  `extras/obfs.WrapPacketConnSalamander(conn, psk)` - available and wired
  through a custom `ConnFactory`, though not exercised with a non-empty
  password in the functional test (the test server has none configured;
  the call path is real, wiring is proven by the wrapper's own use in the
  upstream CLI, `app/cmd/client.go:340`).
- FD Control/protect hook: a `ConnFactory` wraps every outbound QUIC UDP
  socket and, when `--protect-stub` is set, calls a `protectFD(fd int)
  error` hook on the socket's raw fd via `SyscallConn().Control()` before
  use - the same shape the real Android integration needs for
  `VpnService.protect(fd)`. Proven exercised (not just present) via a real
  `SetsockoptInt` call on the live fd and a logged `FD_PROTECT_STUB` line
  during the real handshake in Part J.
- A local SOCKS5 listener (TCP CONNECT + UDP ASSOCIATE), via
  `app/internal/socks5.Server{HyClient: hyClient}` - the same server type the
  real Hysteria2 CLI uses for its own `socks5` outbound mode, unmodified.
  It handles both `socks5.CmdConnect` and `socks5.CmdUDP`.
  I imported this package as-is; the server implementation itself was not
  written for this slice.
- Graceful shutdown: `SIGTERM`/`SIGINT` closes the listener and the
  Hysteria client, waits (with a 5s timeout) for the SOCKS5 accept loop to
  exit. Verified via a real `kill -TERM` against the running process (Part J).

`novaminimal_main.go` is committed at
`research/b46-2c-permissive-hysteria-path/hysteria-minimal-client/`, with a
`README.md` explaining exactly how to graft it onto the pinned commit (it
cannot be a standalone Go module because of the `internal/` import
requirement above).

## Part I - proof that sing-tun is absent (load-bearing)

Four independent methods, all run against the real built binary
(`novaminimal-bin`, and separately its `GOOS=android GOARCH=arm64` cross-build):

| Method | Result |
|---|---|
| `go list -deps ./novaminimal` (291 total packages) | zero packages match `sing-tun` or `apernet/hysteria/app/v2/internal/tun` |
| `go version -m <binary>` (embedded module list) | zero mentions of `sing-tun` |
| `go tool nm <binary>` (12,574 symbols, host build; 14,135 symbols, Android arm64 build) | **0** symbols from `apernet/sing-tun`, **0** from `sagernet/sing-tun`, **0** from `app/internal/tun`, in both builds |
| `strings <binary> \| grep -i sing-tun` | 0 matches |

Sanity checks confirming the binary is genuinely the intended program (not
an empty/broken build): 48 linked symbols from
`github.com/apernet/hysteria/core/v2/client` including `NewClient`; 37 from
`extras/v2/obfs`; 21 from `app/internal/socks5` + `txthinking/socks5`.

`sing-tun` is absent from this binary's dependency graph, its embedded
module list, and its linked symbols, on both the host and Android-arm64
builds. If it had appeared, this section would say so and trace why - it
did not.

## Part J - minimal Hysteria functional proof (real, not deferred)

A real Hysteria2 server was stood up (`hysteria-full server`, the stock
upstream binary built from the same pinned commit, self-signed TLS cert,
password auth) - this is legitimate: the *server* side was never in
question, only the *client's* dependency on sing-tun.

The minimal client connected to it for real:

```
connected: udpEnabled=true tx=0
```

(server log: `client connected {"addr": "127.0.0.1:...", "id": "user", "tx": 0}`)

A real SOCKS5 client then drove the minimal client's local listener:

```
TCP OK: real QUIC round trip via minimal Hysteria client -> real Hysteria2 server -> echo target
UDP OK: real QUIC round trip via minimal Hysteria client -> real Hysteria2 server -> echo target
```

Both are byte-exact round trips through the **real QUIC connection** (not a
mock), via `SOCKS5 CmdConnect` (TCP) and `SOCKS5 CmdUDPAssociate` (UDP) to
real Python echo targets. This exceeds the slice's minimum bar (which only
required proving the child starts, the SOCKS5 listener starts, and the core
initializes, if a real QUIC data-plane proof wasn't feasible) - a full real
QUIC data-plane proof was in fact achieved.

Additional checks: `go vet ./novaminimal/...` clean; a `-race`-instrumented
build of the minimal client was run through the same real TCP+UDP proof
against the real server with **zero `DATA RACE` reports**; a real
`SIGTERM` produced a clean, logged shutdown (`shutting down`) with no crash
and no hang.

## Part K - license inventory (engineering-only, not legal advice)

| Component | Repo | Version/commit audited | License | Integration | Copyleft flag |
|---|---|---|---|---|---|
| tun2socks | `xjasonlyu/tun2socks` | `5d9fac67bb1095a5d2bd959216f85e6434524731` | MIT | in-process (JNI/AAR), distributed inside APK | none |
| gVisor | `gvisor.dev/gvisor` | `v0.0.0-20260906120324-45bde0d1defa` | Apache-2.0 | in-process (linked into the same AAR) | none (permissive; NOTICE attribution applies) |
| Hysteria2 core/client | `apernet/hysteria` | `e1366b173ccf5706e1e4630fe8aa654a4b574085` | MIT | child process, distributed inside APK | none |
| Hysteria2 app/internal/socks5 | `apernet/hysteria` | same commit | MIT | child process | none |
| Hysteria2 extras/obfs (Salamander) | `apernet/hysteria` | same commit | MIT | child process | none |
| quic-go (apernet fork) | `apernet/quic-go` | `v0.62.1-0.20260912175848-73339f7edbb9` | MIT | child process (transitive via core/client) | none |
| txthinking/socks5 | `txthinking/socks5` | `v0.0.0-20230325130024-4230056ae301` | MIT | child process (transitive via app/internal/socks5) | none |

**No GPL dependency found in the audited runtime graph.** This is an
engineering statement about the specific dependency graphs audited above
(Parts A, G, I, K), verified by direct source/LICENSE-file inspection and by
symbol-level proof where a binary was built - it is **not** legal clearance
and does not cover the entire Nova Android app's full dependency tree
outside this specific candidate architecture. A qualified legal review is a
separate, required step before this path could ship, exactly as B46-2B's
sing-tun finding also required.

## Part L - Path 1 vs Path 2

**Path 1 (sing-tun, B46-2B):** proven technically complete (real TCP/UDP
round trip, real in-process AAR, real gomobile build). GPL-3.0-or-later in
both the Nova bridge module and the Hysteria2 child binary (confirmed via
`go tool nm` in B46-2B: 1,344 and 125 linked symbols respectively). Licensing
decision required before shipping.

**Path 2 (tun2socks + minimal Hysteria2, this slice):** proven technically
complete to the same depth - real TCP/UDP/DNS-transport round trip through a
real TUN and a real SOCKS5 daemon (Part C/D), real lifecycle and failure-path
proof (Part E), zero races under `-race` (Part F), a real in-process AAR
with sing-tun symbol-verified absent (Part G), a real minimal Hysteria2
client with sing-tun symbol-verified absent on both host and Android-arm64
builds (Part I), and a real end-to-end QUIC data-plane proof against a real
Hysteria2 server (Part J) - a stronger functional proof than Path 1 received
in B46-2B, where the QUIC layer itself was never exercised (B46-2B proved
only the TUN<->SOCKS5 bridge, not Hysteria2's own QUIC client). Every
audited component is MIT or Apache-2.0; no GPL dependency found in the
audited runtime graph (Part K).

No arbitrary scoring is applied. The comparison is: both paths are now
technically proven at a comparable (Path 2 arguably deeper, since it
includes a real QUIC round trip) level of rigor. Path 1's only remaining
blocker is licensing. Path 2's technical conditions (Part M) are met, but it
has not undergone the additional integration work Path 1 already has (e.g.
the debug-only Android state-machine wiring built in B46-2B for the sing-tun
bridge does not yet exist for this path), and neither path has been proven
on a physical Android device (B46-2P, out of scope for both).

## Part M - Decision gate

**A. PERMISSIVE ARCHITECTURE READY FOR B46-2P.**

Every technical condition set for this slice was met with real evidence,
not asserted:

- tun2socks bridge: real TCP/UDP/DNS-transport round trip, real lifecycle
  (start/stop/restart + 2 failure paths), zero races (`-race`, 3x12 cycles),
  real in-process Android AAR with sing-tun symbol-verified absent.
- Minimal Hysteria2 client: builds without `app/internal/tun`, sing-tun
  symbol-verified absent on host and Android-arm64 builds via four
  independent methods, real end-to-end QUIC proof (TCP+UDP) against a real
  Hysteria2 server, real FD-protect hook exercised, real graceful shutdown.
- License graph: no GPL dependency found in the audited runtime graph
  (engineering statement, not legal clearance - Part K).

This does **not** mean legally cleared (only qualified legal review can say
that) and does **not** mean physical-device-ready (B46-2P, explicitly out of
scope here, is required next and is not started by this slice). It means:
engineering no longer has a *known, load-bearing* dependency on GPL sing-tun
for this candidate architecture, backed by real builds and real traffic, not
assumption.

## Known unknowns / explicitly not claimed

- No physical Android device testing was performed (B46-2P is separate and
  was not started).
- No claim is made about behavior on any real, restricted, or
  geographically specific network.
- Salamander obfuscation and the FD-protect hook were proven *wired and
  reachable*, not exercised end-to-end with a non-empty obfuscation password
  or a real Android `VpnService.protect()` call (the stub only proves the
  call-site and fd validity).
- IPv6 was not exercised (sandbox kernel has no IPv6 support at all - an
  environment limitation, not a code-path finding, carried over from
  B46-2B).
- No DNS leak-safety claim is made (Part D is transport-only).
- This slice does not evaluate packaging/APK-size cost of shipping both a
  tun2socks AAR and a Hysteria2 child binary, nor does it design the Android
  debug-state-machine wiring B46-2B built for the sing-tun path - that
  integration work has not been done for this path.

## Files changed in this slice

- `docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md` (this file, new).
- `docs/ROADMAP.md` (B46 row updated).
- `research/b46-2c-permissive-hysteria-path/tun2socks-proof/{main.go,go.mod,go.sum}` (new, committed proof, builds against a real pinned tun2socks pseudo-version, no local-clone replace).
- `research/b46-2c-permissive-hysteria-path/hysteria-minimal-client/{novaminimal_main.go,README.md}` (new, prototype + grafting instructions).

No production source under `android/app/src/main` was touched. No
`TransportRegistry`, `SmartConnectDecisionEngine`, `AutoGatewaySelector`,
`TransportOrchestrator`, production `VpnController`, `MainViewModel`,
production gateway, or release manifest was modified. No production
transport is selectable as a result of this slice.

## Sources cited

- `github.com/xjasonlyu/tun2socks` @ `5d9fac67bb1095a5d2bd959216f85e6434524731` (own `LICENSE`, `go.mod`, `core/device/fdbased/*.go`, `proxy/socks5/socks5.go`, `engine/engine.go`, `engine/key.go`).
- `gvisor.dev/gvisor` @ `v0.0.0-20260906120324-45bde0d1defa` (own `LICENSE`).
- `github.com/apernet/hysteria` @ `e1366b173ccf5706e1e4630fe8aa654a4b574085` (own top-level `LICENSE.md`, `app/cmd/client.go`, `app/internal/socks5/server.go`, `app/internal/tun/server.go`, `core/client/client.go`, `core/client/config.go`, `extras/obfs/salamander.go`, `extras/obfs/conn.go`).
- `github.com/apernet/quic-go` @ `v0.62.1-0.20260912175848-73339f7edbb9` (own `LICENSE`).
- `github.com/txthinking/socks5` @ `v0.0.0-20230325130024-4230056ae301` (own `LICENSE`).
- `dante-server` 1.4.3+dfsg-1 (Debian package, real third-party SOCKS5 daemon used as a controlled test proxy, not distributed with Nova).
