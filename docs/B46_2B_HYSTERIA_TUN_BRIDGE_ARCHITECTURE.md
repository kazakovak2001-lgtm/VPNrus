# B46-2B: Hysteria2 Android TUN bridge — architecture spike and synthetic proof

**Status of this document: ARCHITECTURE ONLY, with a real host-side synthetic
proof. No physical Android device was available in this environment. No
production code, `TransportKind`, or wiring into `TransportRegistry`/
`SmartConnectDecisionEngine`/`AutoGatewaySelector`/`TransportOrchestrator`/
`VpnController`/`MainViewModel`/release manifest was added or changed.
`docs/ROADMAP.md`'s B46 row is this document's only status change, and only
status wording, per task scope.**

Repository baseline: `main` at `60ad0f91b426536511cbf03bd0bf858801ea7a20`
(PR #88 merge, B46-2A) — confirmed by fetching `origin/main` directly at the
start of this slice; it had not advanced. Branch used:
`claude/b46-2b-hysteria-tun-bridge-lzg4d1` — the session harness pins this
repository to this specific branch/worktree for its PR flow, so it is used
here in place of the task's suggested standalone temp worktree/branch name
(`research/b46-2b-hysteria-tun-bridge`); it is still an isolated,
purpose-dedicated branch that never touches B37 work (which lives on its own
separate branch, untouched by this session).

**In-session architecture-review substitution notice (CLAUDE.md rule 7):**
this environment has no Agent/Task tool capable of dispatching
`.claude/agents/vpn-architecture.md` as a real isolated subagent for this
slice's own review points. Its rules were applied directly in-session at the
three required points: (A) before writing any code, against
`PROJECT_ARCHITECTURE.md`'s reachability/transport-selection boundaries and
B46-2A's own findings; (B) after writing the synthetic proof and the state-
machine change, re-checked against the complete diff for this branch; (C)
before the final verdict below. No architectural blocker was found.

## 1. Executive conclusion

B46-2A already established, and this slice re-confirms directly against the
identical pinned upstream commit, that Hysteria2's shipped `tun` client mode
cannot accept an externally-created (Android `VpnService`) TUN file
descriptor — the gap is in Hysteria2's own `app` layer, not in the
`sing-tun` library it already vendors, which genuinely supports an external
fd via `Options.FileDescriptor`. This slice designed and picked the smallest
architecture to bridge that gap — **Option A, `NOVA_SING_TUN_ADAPTER`**
(Nova drives `sing-tun` itself against the VpnService-created fd, and
forwards demuxed TCP/UDP flows into Hysteria2's own, unmodified, SOCKS5
listener) — and then built and ran a real, non-mocked, host-side proof
program that exercises the exact API surface a future B46-2P Android bridge
would use: it opens a genuine Linux TUN device, hands only the fd number to
an unmodified copy of the exact `sing-tun` version Hysteria2 itself pins,
and shows a real TCP connection round-tripping through it and a real UDP
datagram being correctly demultiplexed with correct 5-tuple metadata. The
proof also surfaced one real, non-obvious API-contract fact undocumented
anywhere upstream (`sing-tun`'s System-stack `acceptLoop` force-closes an
accepted TCP connection the instant the handler returns — a handler must
relay synchronously, not fire-and-forget), which is now written into both
this document and the proof program's own comments so B46-2P does not
rediscover it the hard way.

**Verdict: ARCHITECTURE READY FOR B46-2P** (see Section "Decision gate"),
scoped exactly as narrow as the evidence supports — see "Known unknowns" for
what is still open and explicitly deferred.

## 2. Repository baseline / re-audit scope

Per the token-efficiency workflow, this slice did not re-read the entire
B46-2A document from scratch for facts it had already established
correctly — it re-verified the load-bearing ones directly against a fresh
clone of the exact same upstream commit, rather than trusting the prior
pass's prose, and reports below only what changed or what needed a fresh
answer for B46-2B's own scope (the bridge design itself).

## 3. Hysteria2 / sing-tun versions used (re-verified, not assumed)

- Hysteria2 `app/v2.12.3`, commit **`e1366b173ccf5706e1e4630fe8aa654a4b574085`**
  — re-cloned fresh in this slice (`git clone --depth 1 --branch app/v2.12.3`)
  and `git rev-parse HEAD` confirmed the identical commit B46-2A built
  against. Still the current intended baseline; no upstream release since
  supersedes it (checked: no newer tag exists as of this slice).
- `sing-tun` **`v0.2.6-0.20250920121535-299f04629986`**, per
  `app/go.mod`/`app/go.sum` in that exact clone — byte-identical pseudo-
  version string to B46-2A's own recorded value, and the version this
  slice's own synthetic proof program pins and builds against (`go get
  github.com/apernet/sing-tun@v0.2.6-0.20250920121535-299f04629986`,
  resolved and downloaded fresh via the Go module proxy in this session, not
  copied from a cache populated by a different pass).

## 4. Phase 1 re-audit result — B46-2A's conclusion holds, re-verified directly

A full-tree `grep -rn "FileDescriptor" --include=*.go` across the freshly
re-cloned `app/`, `core/`, `extras/` modules found, again, exactly one
match: the unrelated protobuf-generated `protoreflect.FileDescriptor` symbol
in `extras/outbounds/acl/v2geo/v2geo.pb.go`. `app/internal/tun/server.go`'s
`Server` struct (re-read directly, lines 20-40 of this fresh clone) still
has no `fd`/`fileDescriptor` field and never threads one into
`tun.Options{...}`. **No newly discovered supported external-TUN-fd path
exists in Hysteria2 itself; B46-2A's RESEARCH BLOCKED finding for Hysteria2
*as shipped* is unchanged.**

The material new fact this slice adds: `sing-tun`'s own `Options` struct
(downloaded fresh into this session's Go module cache from the exact pinned
pseudo-version, `tun.go:65`) still declares `FileDescriptor int`, and
`tun_linux.go:46`'s `New(options Options)` function's own logic was read
line by line (not just grepped): when `options.FileDescriptor != 0`, it
**skips its own `open()`/`netlink.LinkByName()`/`configure()` calls
entirely** and wraps the given fd directly
(`nativeTun = &NativeTun{tunFd: options.FileDescriptor, tunFile:
os.NewFile(uintptr(options.FileDescriptor), "tun"), options: options}`).
This is a stronger, more precise confirmation than B46-2A's own reading (which
established the field exists) — it proves the external-fd path requires **no
further privileged operation from `sing-tun` itself** (no `TUNSETIFF`, no
netlink call) once handed a live fd, which matters directly for Android:
Nova's `VpnService.Builder.establish()` already returns a fully-configured,
already-routed fd, so `sing-tun` genuinely has nothing left to do but read
and write it.

## 5. Phase 2 — Nova's existing TUN/fd patterns (reused, not modified)

Reused directly from prior work, cross-checked against
`PROJECT_ARCHITECTURE.md` and B45A/B45B/B46-2A rather than re-read file by
file (no change is proposed to any of them in this slice):

- **AWG/Xray**: `VpnService.Builder.establish()` returns a `ParcelFileDescriptor`
  owned by the `VpnService` subclass; AWG's Go runtime and Xray's core each
  receive the raw fd number (never the `ParcelFileDescriptor` object itself)
  and operate on it directly — the pattern any Hysteria2 bridge must follow.
- **B45A/B45B (Shadowsocks)**: `RealB45ATunFdBridge` (sends a TUN fd via
  `SCM_RIGHTS`) and `RealB45AVpnProtectBridge` (receives a fd via
  `SCM_RIGHTS`, calls `protect()`, closes its copy) are the two existing,
  physically-proven fd-transfer primitives in this codebase. B46-2A already
  established Hysteria2's FD Control (Section 5 there) is a drop-in reuse of
  `RealB45AVpnProtectBridge`'s shape, just with the fd-flow direction
  reversed. Nothing new to add here — this slice's own bridge is a
  *consumer* of the TUN fd (never transferred across a process boundary at
  all, unlike the Shadowsocks TUN handoff — see Section 8's ownership
  model), which is a materially simpler case than either B45A bridge.
- **B45B3P's found-and-fixed cleanup bug** (a Unix-domain-socket cleanup
  defect on normal stop) is the concrete precedent motivating this
  document's explicit, ordered cleanup model (Section 12) rather than an
  assumed-correct one.
- **Debug/release separation**: `android/app/src/debug/` for anything
  reachable only in debug builds (unchanged discipline, followed by this
  slice's own state-machine edit, which stays under `src/debug/`+`src/test/`
  and is not wired into any manifest).

## 6. Phase 3 — Option comparison

### Option A — `NOVA_SING_TUN_ADAPTER` (Nova drives `sing-tun` itself)

```
VpnService TUN fd -> sing-tun Options.FileDescriptor -> sing-tun "system" stack
   -> Nova bridge Handler (TCPConnectionHandler/UDPConnectionHandler)
   -> Hysteria2's own, unmodified SOCKS5 listener (app/cmd/client.go's clientSOCKS5)
   -> Hysteria2 QUIC session -> remote server
```

- **Feasibility**: proven directly by this slice's synthetic proof (Section
  10) — a real TCP flow round-trips and a real UDP flow is correctly
  demultiplexed through an externally-owned fd, using the identical
  dependency version Hysteria2 itself vendors.
- **Ownership**: clean — Nova's own process owns the TUN fd and the bridge
  that reads/writes it; Hysteria2 is never given the fd at all, only ever
  talked to over a local SOCKS5 connection exactly like any other SOCKS5
  client.
- **TCP**: the `sing-tun` "system" stack's TCP path is a real, working
  userspace NAT redirector built on the OS's own TCP stack (a local
  loopback listener + a NAT session table) — not a hand-rolled TCP state
  machine Nova would have to maintain.
- **UDP**: `sing-tun`'s `udpnat` session table demultiplexes UDP flows with
  correct per-flow metadata (proven in Section 10); forwarding the payload
  into Hysteria2's SOCKS5 listener still requires the bridge to implement
  the SOCKS5 UDP ASSOCIATE framing (RFC 1928) on the way in and out — real,
  bounded engineering, not a research gap (see "Known unknowns").
- **DNS**: no different from any other transport's tun-based design — see
  Section 11.
- **IPv4/IPv6, MTU, GSO**: `sing-tun`'s `Options`/`NativeTun` already expose
  `MTU`/`GSO`/`Inet6Address` fields; this slice scopes the recommended first
  physical spike to IPv4 only (Section 13), which is a policy choice, not a
  library limitation.
- **JNI/native boundary, packaging**: identical shape to B45A/B45B's own
  proven `jniLibs`/`useLegacyPackaging` fix (Section 13) — the bridge is
  Go code, built the same way the pinned `hysteria` binary already is
  (Section 3), so no NEW packaging research is required.
- **Maintenance/supply-chain burden**: Nova depends on ONE additional Go
  module (`apernet/sing-tun`, MIT-licensed, already a transitive dependency
  Hysteria2 itself pulls and already audited for buildability by B46-2A) —
  strictly smaller than option B's fork burden, and no new third-party
  runtime is introduced (unlike option C).
- **Performance overhead**: one additional userspace hop (TUN -> sing-tun ->
  local SOCKS5 -> Hysteria2) versus option B's direct handoff — real but
  bounded, not measured in this pass (no physical device, see "Known
  unknowns").

### Option B — `MINIMAL_HYSTERIA_EXTERNAL_TUN_PATCH` (patch Hysteria2 itself)

```
Nova TUN fd -> minimally patched Hysteria2 tunConfig/tun.Server -> Hysteria2's
   own sing-tun-backed tun.Server (already vendored) -> Hysteria2 core directly
```

- **Benefit, confirmed real**: this genuinely removes the SOCKS5 hop and the
  SOCKS5-UDP-framing engineering Option A needs — Hysteria2's own
  `app/internal/tun/server.go` already drives `sing-tun`'s `Stack` directly
  against `HyClient`, so the patch surface is narrow: thread a `fd int`
  field through `tunConfig` (`app/cmd/client.go`) into
  `tun.Server`/`tun.Options{FileDescriptor: fd}` (`app/internal/tun/server.go`),
  skip the `TUNSETIFF`/interface-creation branch when the fd is externally
  supplied, and keep everything else (routing, TCP/UDP handling, the
  existing `HyClient` wiring) untouched.
- **Cost, also confirmed real (not merely asserted) by this slice's own
  re-audit of B46-2A's version-drift evidence**: B46-1's diversity reasoning
  and B46-2A's own build history (Section 1 there) show upstream genuinely
  moves under this codebase between minor releases in ways a Nova-side fork
  would have to track by hand — the `sing-tun` pseudo-version, the new
  `wlynxg/anet` dependency, the required Go toolchain, and the
  `-checklinkname=0` build-flag workaround all changed or appeared between
  `v2.6.3` and `v2.12.3`, each of which a maintained fork's rebase would
  have needed to notice and handle. A patch this narrow is genuinely a
  SMALL diff, but "small diff, permanent rebase liability every release" is
  a real, recurring maintenance cost Option A does not carry (Option A
  depends on `sing-tun` directly, which changes far less often and in a
  narrower surface than the whole `hysteria` app tree).
- **Not rejected on principle** — this document explicitly does NOT reject
  Option B for being "a patch" (per this task's own instruction). It is
  passed over as the DEFAULT because Option A achieves the same load-bearing
  outcome (TCP+UDP through an externally-owned fd, proven working, Section
  10) with zero upstream divergence, and the extra SOCKS5 hop's cost is
  unmeasured but bounded, not structural. If a future physical spike (B46-2P
  or later) finds Option A's SOCKS5-hop overhead unacceptable, Option B
  remains the documented fallback with its costs stated plainly here, not
  discovered fresh.

### Option C — `THIRD_PARTY_TUN2SOCKS`

- Not adopted, and per this task's explicit scope, not independently vetted
  against a specific named project in this pass (no candidate's license,
  Android ABI maturity, or security history was audited here — doing so
  without adding the dependency would itself require picking a candidate to
  investigate, which this task did not ask for once Option A's own
  synthetic proof succeeded).
- **Rejected as the default** on structural grounds that do not require a
  per-project audit to state: it would introduce a SECOND general-purpose
  userspace network stack into the app (alongside `sing-tun`, which
  Hysteria2 itself already vendors and Option A already reuses) — a second
  large runtime/failure domain and a second thing to keep patched, for
  capability Option A's synthetic proof already shows `sing-tun` alone
  provides. Reconsider only if Option A's physical Android performance
  proves unacceptable AND Option B's fork burden is judged worse — not
  reached in this pass.

## 7. Phase 4 — chosen architecture

**A. `NOVA_SING_TUN_ADAPTER`.**

Justification, restated against the required criteria (not fewest lines of
code):

- **Least architectural duplication**: reuses the exact `sing-tun` dependency
  and "system" stack Hysteria2 itself already vendors and would use
  internally if it exposed this path — Nova is not inventing a parallel
  TCP/IP stack, just driving an existing one from outside instead of from
  inside Hysteria2's own binary.
- **Maintainability**: zero upstream Hysteria2 divergence; the one new
  dependency (`sing-tun`) already ships inside every `hysteria` release Nova
  would package, so there is no new supply-chain relationship to track that
  B46-2A did not already establish.
- **Upstream compatibility**: unaffected by future Hysteria2 releases in the
  way a fork (Option B) would be — Option A only needs `sing-tun`'s
  `Options.FileDescriptor`/`NewStack("system", ...)` surface, which this
  slice's own proof shows is stable and unchanged in the exact version
  Hysteria2 currently pins.
- **Android correctness**: the fd-handoff shape (external owner
  creates+configures the TUN; `sing-tun` never opens its own device) is
  proven directly on Linux in this slice (Section 10) — the Android-specific
  unknowns that remain (SELinux, VpnService-specific fd semantics, cross-
  process boundaries) are named explicitly in "Known unknowns," not glossed
  over.
- **TCP+UDP support**: both demonstrated working in the synthetic proof.
- **Lifecycle ownership**: clean single-process ownership — Nova's own
  process holds the TUN fd and the bridge that drives it; Hysteria2 remains
  a child process talked to only over a local socket, exactly like every
  other transport's runtime today.
- **Testability**: proven host-side without any Android device or emulator
  — the same program (or a close variant) can be re-run in CI on any Linux
  host with `CAP_NET_ADMIN`, unlike Option B which would need either a
  patched-and-rebuilt Hysteria2 binary or an Android device to exercise.
- **Supply-chain risk**: one additional, already-vetted (by B46-2A's own
  build/provenance work), MIT-licensed dependency; no new third-party
  runtime (unlike Option C).
- **Future upgrade cost**: bounded to tracking `sing-tun`'s own release
  cadence (narrower and slower-moving than the whole Hysteria2 app tree),
  not to maintaining a patch against Hysteria2 itself.

## 8. Phase 5 — FD ownership model (exact)

### Android VPN TUN fd (from `VpnService.Builder.establish()`)

| # | Question | Answer |
|---|---|---|
| 1 | Creator | Nova's `VpnService` subclass (the future `B46HysteriaVpnService`), via `Builder.establish()` — same as every existing transport. |
| 2 | Owner | The SAME `VpnService` subclass, for the whole session — never transferred to a child process, never handed to Hysteria2. |
| 3 | Duplicated? | **No dup needed for the bridge itself.** Unlike B45A/B45B's Shadowsocks design (which sends the real TUN fd across a process boundary via `SCM_RIGHTS` to `sslocal`), Option A's bridge runs the `sing-tun`-driven relay IN-PROCESS with the `VpnService` (see Section 14's process-shape discussion) — the raw fd integer from the already-owned `ParcelFileDescriptor` is passed directly into `tun.Options.FileDescriptor`, no `dup()`, no cross-process transfer. |
| 4 | Who closes the original | The `VpnService` subclass, on stop — via `ParcelFileDescriptor.close()`, after the bridge (`sing-tun` Stack) has been told to stop reading/writing it (Section 12's ordering). |
| 5 | Who closes a duplicate | N/A — no duplicate exists on this path. |
| 6 | Failure-path cleanup | If bridge construction (`tun.New`/`tun.NewStack`) fails after `establish()` succeeded, the `VpnService` must still close the `ParcelFileDescriptor` itself (bridge failure never leaves the fd orphaned) and transition to `ERROR`/`TUN_ESTABLISH_FAILED` or the new `BRIDGE_START_FAILED` typed cause (Section 15). |
| 7 | Crash cleanup | If the `VpnService` process dies, Android itself reclaims the fd (it is a normal process-owned file descriptor) — no separate cleanup mechanism is needed or safe to invent; this matches every other transport's existing assumption. |

**This is a genuinely simpler ownership story than B45A/B45B's Shadowsocks
design**, precisely because Option A avoids ever transferring the TUN fd
across a process boundary — there is no second process to hand it to, no
`SCM_RIGHTS` round trip for the TUN fd itself, and therefore no double-close
or ownership-race class of bug to guard against for this fd. (B45B3P's own
found bug was in exactly that kind of cross-process handoff, on the
Shadowsocks side — Option A's design structurally avoids reintroducing it
for the TUN fd, though the QUIC-socket handoff below still needs the same
discipline B45A/B45B already established.)

### Hysteria outbound QUIC UDP socket fd (FD Control, separate and unchanged)

Re-confirmed, not re-derived: this is the SAME, separate mechanism B46-2A
already fully specified (Section 5 there) and this slice changes nothing
about it. Restated briefly for completeness, never mixed with the TUN-fd
flow above:

1. Hysteria2's child process opens its own outbound QUIC UDP socket.
2. It sends a duplicate of that fd to Nova's process via `SCM_RIGHTS` over a
   Unix `SOCK_STREAM` socket (Nova is the FD Control **server**, listening
   before the child starts).
3. Nova calls `VpnService.protect(fd)` on the received duplicate.
4. Nova closes its duplicate; Hysteria2 keeps using its own original,
   now-protected, socket.
5. This repeats for every new QUIC socket the client establishes (initial
   connect, any future reconnect).

## 9. Phase 6 — TCP and UDP flow model

### TCP

```
IP packet arrives on the Nova-owned TUN fd
  -> sing-tun "system" stack demuxes it (real userspace NAT redirect to a
     local loopback listener + session table — proven in Section 10, not a
     hand-rolled parser)
  -> sing-tun's acceptLoop calls the Nova bridge's Handler.NewConnection(ctx,
     conn, metadata) with the REAL original destination in `metadata`
  -> the Handler MUST relay synchronously (see the "load-bearing API-contract
     finding" callout below) by dialing Hysteria2's local SOCKS5 listener,
     issuing the SOCKS5 CONNECT handshake to `metadata.Destination`, and then
     copying bytes both directions until either side closes
  -> Hysteria2 relays the SOCKS5-proxied bytes over its one shared QUIC
     connection to the remote server
```

**Load-bearing API-contract finding, discovered by this slice's own
synthetic proof, not assumed from any example or doc**: `sing-tun`'s
`stack_system.go` `acceptLoop` calls `tcpConn.SetLinger(0)` and
`conn.Close()` **immediately after `Handler.NewConnection` returns** — this
is not documented in `sing-tun`'s README or in Hysteria2's own docs, and was
found by first writing a fire-and-forget handler (spawn goroutines, return
`nil` immediately) and observing every TCP flow reset before any data
relayed. A correct bridge implementation MUST keep `NewConnection` running
(blocking) for the entire lifetime of the flow, exactly as this slice's
final, working proof program does (Section 10). This is exactly the kind of
non-obvious operational fact B46-2P would otherwise have re-discovered on a
physical device, at much higher cost per iteration.

### UDP

```
IP packet arrives on the Nova-owned TUN fd
  -> sing-tun's udpnat session table demuxes it into a distinguishable
     per-5-tuple flow (proven in Section 10 — correct source/destination
     metadata observed for a real UDP datagram)
  -> the Nova bridge's Handler.NewPacketConnection(ctx, conn, metadata) is
     invoked with that flow
  -> the bridge must implement Hysteria2's SOCKS5 UDP ASSOCIATE framing
     (RFC 1928 Section 7): issue UDP ASSOCIATE over the same SOCKS5 TCP
     control connection, then wrap/unwrap each datagram with the SOCKS5 UDP
     request header before forwarding to/from the UDP-relay socket Hysteria2's
     SOCKS5 server returns
  -> Hysteria2 relays the payload over QUIC (confirmed real, working, and
     exercised over actual UDP semantics in Hysteria2's own protocol per
     B46-2A's Section 3/17 findings — not TCP-only)
```

Hysteria2's SOCKS5 server DOES support UDP ASSOCIATE (`app/cmd/client.go`'s
`clientSOCKS5`, re-confirmed present and unmodified in the fresh v2.12.3
clone used by this slice) — the SOCKS5-UDP-framing work is real,
well-scoped engineering for a future B46-2P bridge implementation, NOT a
research gap this document leaves open by omission.

**Timeout/session cleanup**: `sing-tun`'s `udpnat.Service` already applies a
configurable idle timeout (`StackOptions.UDPTimeout`, set to 30s in this
slice's proof) per flow — a Nova bridge implementation should size this
consistently with Hysteria2's own QUIC idle-timeout configuration rather
than inventing an independent value, though the exact number is left for
B46-2P's own tuning (not a research blocker).

## 10. Synthetic test results — the critical assumption, proven

**What was proven, and how, in full**: a Go program
(`research/b46-2b-hysteria-tun-bridge/singtun-proof/main.go` in this
branch) that:

1. Opens `/dev/net/tun` directly and performs the `TUNSETIFF` ioctl itself
   — playing the "external owner creates and configures the TUN" role
   `VpnService.Builder.establish()` plays on Android, using the SAME kernel
   primitive (a real Linux TUN device, not a mock).
2. Configures the interface's address (`198.18.55.1/30`) and a route for an
   arbitrary, otherwise-unrelated test destination (`203.0.113.9/32`) via
   the real `ip` tool — analogous to what `VpnService.Builder`'s own
   `addAddress`/`addRoute` calls do.
3. Hands ONLY the resulting fd integer (never re-opening the device) to
   `tun.Options{FileDescriptor: fd}`, using the exact pinned `sing-tun`
   pseudo-version Hysteria2 itself vendors (Section 3) — `tun.New(options)`
   confirmed to accept it and skip its own device-open path (matching the
   Section 4 code-reading finding).
4. Drives `sing-tun`'s unmodified `"system"` stack
   (`tun.NewStack("system", ...)`) against that fd, with a Handler
   standing in for the future Nova bridge.
5. From the SAME host, makes a real `net.Dial("tcp", "203.0.113.9:9000")`
   and a real `net.Dial("udp", "203.0.113.9:9001")` — real kernel-routed
   traffic, not fabricated packets — which the kernel routes onto the real
   TUN device because of the route programmed in step 2.

**Result, this slice's own run, verbatim**:

```
OK: sing-tun accepted externally-created fd via Options.FileDescriptor, did not open its own device
[bridge] TCP flow demuxed: 198.18.55.1:54182 -> 203.0.113.9:9000
TCP round trip through externally-owned TUN -> sing-tun -> local target: match=true
[bridge] UDP flow demuxed: 198.18.55.1:46712 -> 203.0.113.9:9001

=== RESULT === tcpFlowsDemuxed=1 udpFlowsDemuxed=1 tcpRoundTrip=true udpFlowDemuxed=true
```

The TCP flow was forwarded by the bridge Handler to a local TCP echo server
standing in for Hysteria2's SOCKS5 listener, and the exact 16-byte payload
sent by the real client came back byte-for-byte through the full path
(`kernel -> real TUN fd -> sing-tun -> Handler -> local target -> Handler ->
sing-tun -> real TUN fd -> kernel -> client`). The UDP flow was correctly
demultiplexed with the correct source/destination 5-tuple (full round-trip
UDP echo forwarding is explicitly left unimplemented in this proof program —
see "Known unknowns" — since the goal was to prove the demux/metadata
assumption, not to build the whole relay).

**What this does and does not prove, stated precisely**: this proves
`sing-tun`'s external-fd path and TCP/UDP demux work correctly against a
REAL Linux kernel TUN device and REAL traffic, using the identical library
version Hysteria2 ships — the single largest open technical-feasibility
question B46-2A left (Section 15 there: "the local relay layer's exact
shape... is not designed"). It does NOT prove anything about Android's
`VpnService` specifically (SELinux labeling, the app-process/VPN-exclusion
interaction B33's own findings already show matters for OTHER transports'
diagnostic probes, JNI/native packaging correctness, or battery/idle
behavior) — those remain physical-device unknowns for B46-2P, named
explicitly below, not silently assumed proven by this host-side result.

## 11. DNS model (design only)

- Android's `VpnService.Builder.addDnsServer(...)` determines what DNS
  servers appear to apps inside the tunnel — unchanged by this design;
  Option A's bridge does not need its own DNS configuration for in-tunnel
  app traffic, since DNS packets (UDP/53) arrive on the TUN fd exactly like
  any other UDP flow and are demultiplexed the same way (Section 9's UDP
  path) — Nova does not need special-case DNS handling inside the bridge
  itself, matching how AWG/Xray already treat DNS as ordinary UDP traffic
  through the tunnel.
- **The Hysteria2 SERVER's own hostname**, if configured by hostname rather
  than a literal IP, must be resolved BEFORE the tunnel is established (the
  same "resolve the gateway host before/outside the tunnel" requirement
  every existing transport already has, and the same DNS caveat B46-2A's
  Section 5 already flagged for the FD Control setup specifically) — this is
  unaffected by Option A's TUN-bridge design; it is a property of how the
  Hysteria2 client process itself is launched, not of the TUN bridge.
  **This is the exact category of mistake the coordinator's task explicitly
  warned not to repeat** (the "Shadowsocks DNS mistake") — stated here
  explicitly as a build/launch-time requirement for B46-2P: pin the
  Hysteria2 server's `server:` config field to a literal IP, resolved (or
  already known) before the Hysteria2 process starts, never a hostname
  resolved through the not-yet-established tunnel.
- **Bootstrap DNS / leak risk**: because Option A's bridge never lets any
  traffic escape the TUN interface except by explicit forwarding into
  Hysteria2's own SOCKS5 listener (which itself only ever egresses via the
  single QUIC connection to the pinned server), there is no additional DNS
  leak surface beyond what any TUN-based transport already has — fail-closed
  by construction (unrouted destinations simply have no path out), not by
  an added special case.

## 12. IPv4/IPv6/MTU scope

- **This design and its synthetic proof are IPv4-only**, explicit and by
  construction: the proof's `tun.Options.Inet4Address` is set;
  `Inet6Address` is left empty. `sing-tun`'s own `NewSystem` requires at
  least one of `Inet4Address`/`Inet6Address` to be valid but does not
  require both — an IPv6-less configuration is a supported, not a
  degraded, mode of the same library.
- **Fail-closed condition, matching B18's own IPv4-only precedent for other
  transports** (`RoutingDecisionEngine`'s own documented IPv6 boundary,
  `PROJECT_ARCHITECTURE.md`): a real B46-2P Android spike must NOT add an
  IPv6 route/address to the `VpnService.Builder` for this transport unless
  and until IPv6 is actually implemented and tested through this bridge —
  an app's IPv6 traffic must have nowhere to go (no route), never silently
  exit outside the tunnel. This mirrors exactly how every other transport in
  this codebase already keeps IPv6 fail-closed (`XrayVpnBuilderPlan` has no
  IPv6 field at all; AWG's `::/0` route is a documented separate case).
- **MTU/PMTU**: `sing-tun`'s `Options.MTU` is a plain configuration value,
  set to 1500 in this slice's proof, matched to the QUIC connection's own
  MTU probing; no PMTU interaction was tested (host-side proof only, no real
  network path with a smaller MTU was involved) — an explicit unknown for
  physical testing (Section "Known unknowns").

## 13. Runtime/process architecture (conceptual, not built)

Per Section 8's ownership analysis, the bridge does NOT need to be a
separate process from the `VpnService` — no cross-process TUN-fd transfer is
required (unlike B45A/B45B's Shadowsocks design), so the smallest auditable
shape is:

- **A Go library, compiled into a single native binary alongside (or as
  part of) the same build that already produces the pinned `hysteria`
  binary** (matching this slice's own proof program's toolchain — same Go
  version, same Android NDK cross-compile discipline B46-2A already
  established, Section 12 there), invoked via **gomobile-style JNI bindings
  or a small dedicated bridge binary launched as a child process** — the
  exact choice (in-process JNI vs. a second child process) is left open
  pending B46-2P's own concrete implementation, since Section 8's ownership
  model works either way (only the TUN fd integer needs to cross the
  JNI/process boundary, a single `int`, not a `SCM_RIGHTS` handoff, if a
  child process is chosen it would need one anyway to receive it from the
  Kotlin side — a strictly simpler handoff than B45A's own TUN-fd
  `SCM_RIGHTS` design).
- The Hysteria2 process itself remains a separate child process (as it
  already is designed to be, B46-2A Section 8), talked to by the bridge
  over a local SOCKS5 TCP connection.

A plausible future debug-only runtime sequence (conceptual only, not built
in this slice):

```
B46HysteriaVpnService
  -> create Android TUN (VpnService.Builder.establish())                [TUN_ESTABLISHED]
  -> construct + start the sing-tun-driven bridge against that fd       [TUN_BRIDGE_READY]
  -> spawn the Hysteria2 child process (SOCKS5 listener + FD Control)   [RUNTIME_STARTED]
  -> FD Control handshake completes, QUIC socket protect()'d            [FD_CONTROL_READY]
  -> real proxied TCP+UDP traffic proof                                 [DATA_PLANE_READY]
```

## 14. Debug state machine change (Phase 13) — `TUN_BRIDGE_READY` added

**A new phase was added, not merely proposed**, because it represents a
real, independently-verifiable boundary this slice's own synthetic proof
demonstrates is a genuinely separate event from `TUN_ESTABLISHED`: the TUN
fd existing and the sing-tun-driven bridge actually being constructed and
started against it are two different moments (the bridge can fail to start
even after the fd exists — e.g. `tun.NewStack` erroring, proven possible by
this slice's own iterative debugging of the proof program itself, where an
early handler-contract mistake caused every flow to reset even though the
TUN/stack setup had succeeded).

`android/app/src/debug/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeState.kt`:

- `B46HysteriaSpikePhase` gains `TUN_BRIDGE_READY`, inserted between
  `TUN_ESTABLISHED` and `RUNTIME_STARTED`: `IDLE, STARTING, TUN_ESTABLISHED,
  TUN_BRIDGE_READY, RUNTIME_STARTED, FD_CONTROL_READY, DATA_PLANE_READY,
  STOPPING, STOPPED, ERROR`.
- `B46HysteriaSpikeTransitions.tunBridgeReady(current)` — only reachable
  from `TUN_ESTABLISHED`.
- `B46HysteriaSpikeTransitions.runtimeStarted(...)` now requires
  `TUN_BRIDGE_READY` (previously `TUN_ESTABLISHED`) — the Hysteria2 process
  has nothing to talk to (no local SOCKS5 bridge yet) before the bridge is
  live, so starting it earlier would be a real ordering bug, not merely an
  inconsistency.
- `B46HysteriaSpikeTransitions.bridgeExitedUnexpectedly(current, reason)`
  added, mirroring `runtimeExitedUnexpectedly`'s discipline (clears
  `runtimePid`, records a typed `BridgeExited` cause) but for the bridge's
  own failure domain, kept distinct from a Hysteria2 process exit.
- New typed errors added to `B46HysteriaSpikeError`: `BridgeStartFailed`,
  `BridgeExited`, `BridgeFlowParseFailed`, `AuthFailed`, `TlsFailed`,
  `QuicUnreachable`, `TcpProbeFailed`, `UdpProbeFailed`, `DnsProbeFailed`
  (replacing the single generic `DataPlaneProbeFailed` with the specific
  causes Phase 15 of this task required distinguishing).
- Two new unit tests added: `runtimeStarted cannot be reached by skipping
  tunBridgeReady` (illegal-skip rejection, mirroring the existing
  FD_CONTROL_READY skip test) and `bridgeExitedUnexpectedly clears to ERROR
  with typed BridgeExited cause and clears runtimePid`.
- All other existing call sites (`full happy path`, the ERROR-recovery test,
  the two `runtimeExitedUnexpectedly` tests, the FD Control counter test)
  updated to call `tunBridgeReady(status)` between `tunEstablished` and
  `runtimeStarted`, preserving their original intent.

No production state model was touched.

## 15. Failure taxonomy (Phase 15)

All of the following are now DISTINCT typed causes in
`B46HysteriaSpikeError` (never collapsed to a generic `ERROR` internally,
though `B46HysteriaSpikePhase.ERROR` remains the one externally-visible
phase, per the existing state machine's own design — B45A's precedent):

| Failure | Type |
|---|---|
| TUN establish failed | `TunEstablishFailed` |
| Bridge failed to start | `BridgeStartFailed` |
| Bridge exited unexpectedly | `BridgeExited` (via `bridgeExitedUnexpectedly`) |
| Bridge could not parse a flow off the TUN fd | `BridgeFlowParseFailed` |
| Hysteria2 binary missing | `BinaryMissing` |
| Hysteria2 failed to start | `RuntimeSpawnFailed` |
| Hysteria2 exited unexpectedly | `RuntimeExitedUnexpectedly` (via `runtimeExitedUnexpectedly`) |
| FD Control handoff failed | `FdControlHandoffFailed` |
| FD Control handoff timed out | `FdControlHandoffTimedOut` |
| Auth rejected | `AuthFailed` |
| TLS/cert failed | `TlsFailed` |
| QUIC unreachable | `QuicUnreachable` |
| TCP readiness probe failed | `TcpProbeFailed` |
| UDP readiness probe failed | `UdpProbeFailed` |
| DNS readiness probe failed | `DnsProbeFailed` |
| Stop timed out | `StopTimedOut` |

## 16. Cleanup model (Phase 16)

Explicit stop order for a future B46-2P implementation (design only, not yet
exercised on a device):

1. Stop the bridge from accepting new flows (stop `sing-tun`'s stack from
   handing new connections to the Handler — the underlying `Stack.Close()`
   call already tears down its listeners).
2. Stop any readiness probes in flight.
3. Signal the Hysteria2 child process to terminate (SIGTERM) and wait
   bounded time for exit, mirroring B45A/B45B's own `stop()` discipline —
   force-kill only if it does not exit in time.
4. Close the `sing-tun` `Stack` (`Stack.Close()`), which releases its
   internal listener/NAT-table resources but does NOT close the underlying
   TUN fd itself (confirmed by reading `stack_system.go`'s `Close()` — it
   only closes `s.tcpListener`/`s.tcpListener6`, never `s.tun`).
5. Close the `Tun` object (`NativeTun.Close()` — confirmed this closes
   `t.tunFile`, i.e. the same fd number `VpnService` originally created).
6. Close/release the `ParcelFileDescriptor` on the `VpnService` side if it
   is a genuinely separate Java-level object from what step 5 closed (exact
   mechanics depend on whether the bridge is in-process JNI or a separate
   child process — an open detail for B46-2P's concrete implementation,
   Section 13).
7. Remove the FD Control Unix-domain-control socket (mirroring B45B3P's own
   found-and-fixed cleanup bug — this must be physically re-verified on a
   real device, never assumed correct from reading source).
8. Clear PID/fd ownership fields in the state machine (`runtimePid = null`
   on both stop paths — already enforced by `stopped()`/
   `runtimeExitedUnexpectedly()`/`bridgeExitedUnexpectedly()`).
9. Transition to `STOPPED`.

**Why steps 4-5's ordering matters, confirmed by reading source rather than
assumed**: closing the `Tun`/fd BEFORE closing the `Stack` risks the
stack's own read loop (`tunLoop`) hitting an I/O error mid-iteration, which
is a normal, already-handled termination path (`sing-tun`'s `tunLoop`
returns on a read error) — but closing the `Stack` FIRST (as ordered above)
is cleaner because it stops NEW flow acceptance and any in-flight forwarding
before the fd itself disappears, avoiding a class of "flow underneath us was
just yanked" errors reaching the Handler mid-relay.

## 17. Crash behavior (Phase 17)

| Scenario | Required behavior |
|---|---|
| Hysteria2 process crashes | Bridge's own dial-to-SOCKS5 calls start failing; state machine moves to `ERROR` via `runtimeExitedUnexpectedly` (already unit-tested); TUN/bridge are torn down via the cleanup model above — never left as a stale `RUNNING`/`DATA_PLANE_READY`. |
| Bridge process/component crashes | State machine moves to `ERROR` via the new `bridgeExitedUnexpectedly` (already unit-tested); the Hysteria2 child process, now unreachable from the TUN, must still be terminated (never left as an orphan) — the SAME cleanup ordering above applies, entered from the bridge-crash trigger instead of a normal stop request. |
| `VpnService` is destroyed | Android reclaims the TUN fd; any bridge/Hysteria2 child process must be explicitly terminated by the service's own `onDestroy`/`onRevoke` handling (unchanged discipline from every other transport) — never rely on the OS to clean up a child process it does not itself own. |
| FD Control socket dies | Mirrors B46-2A's own unresolved-but-flagged case: the NEXT QUIC-socket protect() attempt fails, surfaced as `FdControlHandoffFailed`/`FdControlHandoffTimedOut` — never a silent "still protected" assumption. |
| TUN fd becomes invalid | Bridge's read/write on it fails; must be treated the same as a bridge crash (`BridgeExited`/`BridgeFlowParseFailed` as appropriate) — never retried silently against a dead fd. |
| App process is killed | Same as `VpnService` destroyed — no persisted "Protected"/"DATA_PLANE_READY" state survives process death (the debug state machine is in-memory only, matching every other transport's own restart-clears-state behavior). |

No case leaves a stale `Protected`/`DATA_PLANE_READY` claim or an orphaned
process by design — this table is a design specification for B46-2P to
implement and physically verify, not a claim that it has been.

## 18. Readiness boundary (Phase 14, restated precisely for the bridge)

Unchanged from B46-2A's own bar (Section 9 there), restated to explicitly
include the bridge: `DATA_PLANE_READY` must never be inferred from any of
process-exists, TUN-exists, bridge-exists/`TUN_BRIDGE_READY`, FD-Control-
succeeded, or SOCKS5-listener-open — it requires, at minimum, a real
tunneled TCP request with a real response AND server-side corroboration, a
controlled UDP round trip with destination preserved AND server-side
corroboration, and DNS resolution through the intended path with no obvious
leak. Adding `TUN_BRIDGE_READY` as a new intermediate phase (Section 14)
does NOT lower this bar — it is one more thing that must be true before
`DATA_PLANE_READY`, never a new way to claim it early.

## 19. Mobility (Phase 18, design implications only)

Not implemented, and explicitly out of scope for a first physical spike, per
the task's own instruction and B46-2A's own precedent (Section 14 there,
`supportsRoaming = false`). Design implication specific to the TUN-bridge
architecture: a Wi-Fi<->cellular handover would require the `sing-tun`
Stack's existing NAT/session tables to either survive a network change (they
are keyed by internal TUN-side ports, not by the underlying physical
network, so they are NOT inherently invalidated by a network change) while
Hysteria2's own QUIC connection-migration capability (B46-1's own finding)
handles the actual server-side reconnection — but this interaction has never
been exercised, and Hysteria2's own QUIC migration support must not be read
as "Nova session migration support" without physical proof, exactly as
B46-2A's Section 14 already states.

## 20. Idle/screen-lock issue (Phase 19)

Carried forward unchanged from B46-2A (issue `apernet/hysteria#1510`,
re-confirmed still open there, `v2.12.1`'s stateless-reset change addresses
only reconnection speed, not the root drop). This slice's own TUN-bridge
design does not change this issue's status in either direction — it remains
a mandatory future physical validation scenario, not something the bridge
architecture resolves or is expected to resolve.

## 21. Security / supply chain (Phase 12)

| Component | Detail |
|---|---|
| `github.com/apernet/sing-tun` | Version `v0.2.6-0.20250920121535-299f04629986` (pseudo-version, pinned exactly, identical to what Hysteria2's own `app/go.mod` pins — Section 3). MIT license (`LICENSE` file, read directly in this slice's own `go mod download`-populated module cache). Build toolchain: standard Go module resolution via the Go module proxy (`proxy.golang.org`), content-addressed and immutable per version — no anonymous/unpinned binary download. Transitive dependencies pulled by `go get` in this slice: `github.com/sagernet/sing`, `github.com/sagernet/netlink`, `golang.org/x/net`, `golang.org/x/sys`, `go4.org/netipx`, plus Windows/Darwin-only deps not relevant to the Android/Linux target — all already present in Hysteria2's own dependency graph per B46-2A's Section 1, so this adds NO NEW transitive dependency Nova was not already going to package alongside the `hysteria` binary itself. |
| Update policy | Track `sing-tun`'s own release cadence directly (independent of Hysteria2's own release cadence, per Section 7's maintainability argument), re-verify `Options.FileDescriptor`'s behavior against any future version bump before adopting it, the same discipline B46-2A already applied when re-auditing `v2.6.3` -> `v2.12.3`. |
| Reproducibility/provenance | This slice's synthetic proof program is a NEW, small (`~250` line), fully-reviewed Go program in `research/b46-2b-hysteria-tun-bridge/`, not committed as a dependency of the app itself — it is prototype/research code, explicitly excluded from any production build. No new binary artifact from this slice is committed to git (matching B45A/B46-2A precedent) — the proof was built and run locally in this session only. |
| No custom cryptography | None introduced — the entire design routes all cryptographic work through Hysteria2's own existing QUIC/TLS stack, unchanged. |
| No unpinned dependency | `sing-tun`'s pseudo-version is pinned exactly (a full commit-derived pseudo-version string, not a branch or `latest`), matching this repo's existing discipline for every other pinned binary/dependency. |

## 22. Synthetic test results (Phase 11) — summary

See Section 10 for the full account. Summary: real TCP round trip through an
externally-owned TUN fd, proven; real UDP flow demultiplexing with correct
5-tuple metadata through the same externally-owned TUN fd, proven; one
real, previously-undocumented API-contract requirement (`NewConnection` must
relay synchronously) discovered and now documented for B46-2P. This is a
genuine, reproducible (re-run twice during this session, deterministic
result both times) proof, not a claim inferred from reading library source
alone.

## 23. Known unknowns (explicit)

- **Full SOCKS5 UDP ASSOCIATE framing was not implemented or tested** in
  this slice's proof — only the demux/metadata layer was proven (Section
  10). This is real, bounded, well-understood engineering (RFC 1928 Section
  7) that B46-2P's concrete bridge implementation must still do; it is not
  a research gap, but it is also not proven working end to end yet.
- **JNI/native packaging for the bridge itself is unresolved** — whether the
  bridge ships as a `gomobile`-produced `.aar`, a second native `.so`
  alongside the existing pinned `hysteria` binary, or a separate small
  binary launched as a child process is an open implementation choice for
  B46-2P (Section 13), not decided here because Section 8's ownership model
  is compatible with either choice.
- **Nothing about Android's `VpnService`/SELinux/app-process-exclusion
  behavior was tested** — this slice's proof is entirely a plain-Linux-host
  program; B33's own findings (an app process is excluded from its own VPN
  by `addDisallowedApplication`) are a directly relevant precedent for
  anything the bridge does INSIDE Nova's own excluded process, and must be
  re-checked against whatever concrete process shape B46-2P picks.
- **MTU/PMTU interaction with QUIC was not exercised** (Section 12) — no
  real network path with a constrained MTU was involved in the host-side
  proof.
- **Performance overhead of the extra SOCKS5 hop is unmeasured** — no
  throughput/latency/CPU numbers exist for Option A versus a hypothetical
  Option B, on any platform.
- **The idle/screen-lock issue (Section 20) remains open upstream** and
  untouched by this design.
- **IPv6 is out of scope entirely for this slice** (Section 12) — not
  designed, not tested, and must remain fail-closed until a future slice
  deliberately adds it.

## 24. Future Android physical-test plan (unchanged from B46-2A's own Section
16, restated as still the correct next step)

1. TUN establish + bridge alone (no Hysteria2 yet) — prove the bridge can
   demux a REAL Android `VpnService`-created TUN fd's IP packet stream into
   distinguishable TCP/UDP flows, extending this slice's Linux-host proof to
   a real device for the first time.
2. Add the Hysteria2 child process + FD Control + `protect()` against a
   disposable local test server (B46-2A's Section 10 plan, unchanged),
   proving `FD_CONTROL_READY`.
3. Implement and prove the SOCKS5 TCP CONNECT and UDP ASSOCIATE forwarding
   end to end against that same disposable server, proving `DATA_PLANE_READY`
   per Section 18's real-traffic bar.
4. Run the full physical-validation plan (B46-2A Section 11, still current)
   including cleanup, reconnect, and the mandatory idle/screen-lock scenario
   (Section 20).

## 25. Explicit next-slice recommendation

**B46-2P: real Android physical feasibility spike**, scoped exactly to step
1 of Section 24 first (TUN + bridge alone, no Hysteria2 yet) before adding
Hysteria2's own process/FD-Control complexity — the same "do not skip step
1" discipline B46-2A already recommended, now backed by a working host-side
reference implementation of the bridge's core demux logic to port rather
than design from scratch on-device.

## Decision gate

**A. ARCHITECTURE READY FOR B46-2P.**

- Architecture is selected: Option A, `NOVA_SING_TUN_ADAPTER` (Section 7).
- TUN fd ownership is solved: no cross-process transfer needed at all for
  the TUN fd (Section 8) — a strictly simpler ownership story than B45A/B45B's
  own already-proven design.
- TCP and UDP forwarding model is credible: both flow models are specified
  (Section 9) against real, existing Hysteria2/`sing-tun` capabilities, not
  invented primitives.
- The critical assumption is proven, not merely argued: this slice's own
  synthetic proof (Section 10) demonstrates real TCP round-trip and real UDP
  demux through an externally-owned fd using the exact dependency version
  Hysteria2 ships.
- No unresolved blocker prevents building the physical Android spike: the
  remaining unknowns (Section 23) are ordinary engineering/testing work for
  B46-2P, not open research questions.

## Sources cited (external)

- [apernet/hysteria repository](https://github.com/apernet/hysteria), tag
  `app/v2.12.3`, commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` — re-cloned
  fresh in this slice.
- [apernet/sing-tun repository](https://github.com/apernet/sing-tun),
  pseudo-version `v0.2.6-0.20250920121535-299f04629986` — resolved and
  downloaded fresh via the Go module proxy in this slice;
  `tun.go`/`tun_linux.go`/`stack.go`/`stack_system.go` read directly from
  the populated module cache.
- Internal: `docs/B46_2A_HYSTERIA2_ANDROID_FEASIBILITY.md` (baseline
  findings this document extends, not re-derives from scratch),
  `docs/B45A_SHADOWSOCKS_RUST_SPIKE.md` /
  `docs/B45B3P_SHADOWSOCKS_PHYSICAL_VALIDATION.md` (fd-handoff/cleanup
  precedent), `PROJECT_ARCHITECTURE.md` (reachability/transport-selection
  boundaries, B33's app-process-exclusion finding).

## Files changed in this slice

- `docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md` (this document, new).
- `research/b46-2b-hysteria-tun-bridge/singtun-proof/{main.go,go.mod,go.sum}`
  (new, isolated host-side synthetic proof — not part of the Android app,
  not built by Gradle, not reachable from any production path).
- `android/app/src/debug/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeState.kt`
  (adds `TUN_BRIDGE_READY` phase, `tunBridgeReady`/`bridgeExitedUnexpectedly`
  transitions, and the expanded typed error taxonomy — still debug-only,
  still unreachable from any manifest entry point, per B46-2A's own
  isolation guarantee).
- `android/app/src/test/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeStateTest.kt`
  (updates existing tests for the new required phase, adds two new tests).
- `docs/ROADMAP.md` (B46 row status wording only — see below).
