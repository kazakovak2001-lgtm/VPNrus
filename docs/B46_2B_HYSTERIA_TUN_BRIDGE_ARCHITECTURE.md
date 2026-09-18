# B46-2B: Hysteria2 Android TUN bridge — architecture spike and synthetic proof

**CORRECTION PASS (same day, following a direct review of PR #89 against the
pinned `sing-tun` source):** the original pass's TUN-fd ownership model was
insufficiently precise (it did not account for `sing-tun`'s `NativeTun.Close()`
closing whatever raw fd number it is given, which risked a double-close if
the original `ParcelFileDescriptor`'s fd were handed to it directly), the
synthetic proof's UDP path was demux-only and its pass/fail result did not
actually depend on the handler having observed anything (a `Write()` +
`sleep` was wrongly treated as success), the proof carried unsynchronized
shared-state reads/writes across goroutines, the bridge/Hysteria2-process
boundary was left ambiguous while still claiming the "no cross-process fd
transfer" advantage, and `bridgeExitedUnexpectedly` incorrectly cleared
`runtimePid` for a Hysteria2 process the bridge's own failure never actually
proved had terminated. All five are fixed in this pass — see Sections 6, 8,
9, 10, 13, 14, 17, and 21 below, each now re-derived from a real *host-side
re-run* and, for Option C, a real *audit of two candidates' current source*,
not carried over from the first pass's prose. The verdict was re-decided from
scratch after the fixes (Section "Decision gate"), not preserved by default.

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
(Nova drives `sing-tun` itself, IN-PROCESS with the `VpnService` — Section
13's now-pinned boundary — against a DEDICATED DUPLICATE of the
VpnService-created fd — Section 8's corrected ownership model — and
forwards demuxed TCP/UDP flows into Hysteria2's own, unmodified, SOCKS5
listener) — and then built and ran a real, non-mocked, host-side proof
program that exercises the exact API surface a future B46-2P Android bridge
would use: it opens a genuine Linux TUN device, duplicates the fd (never
sharing the original with `sing-tun`), hands only the duplicate to an
unmodified copy of the exact `sing-tun` version Hysteria2 itself pins, and
shows a real TCP connection round-tripping through it and a real, FULL UDP
round trip (payload out and back, not merely a demuxed flow) through it,
both deterministically observed via channel synchronization. The proof
surfaced two real, non-obvious API-contract facts undocumented anywhere
upstream (`sing-tun`'s System-stack `acceptLoop` force-closes an accepted
TCP connection the instant the handler returns — a handler must relay
synchronously, not fire-and-forget; and `WritePacket`'s `destination`
argument must be the original virtual destination, not the source, or a
UDP reply silently vanishes) plus one genuine, currently-open internal data
race inside the pinned `sing-tun` dependency itself (found via
`go build -race`, reported honestly, not worked around) — all now written
into this document and the proof program's own comments so B46-2P does not
rediscover them the hard way.

**Verdict: ARCHITECTURE READY FOR B46-2P** (see Section "Decision gate" —
re-decided from scratch in a same-day correction pass following a direct
review of PR #89, not preserved by default), scoped exactly as narrow as
the evidence supports — see "Known unknowns" for what is still open and
explicitly deferred.

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

**Correction pass: this section previously dismissed Option C on purely
structural grounds without auditing a specific candidate — that did not
satisfy the task's explicit requirement to evaluate at least one real,
current alternative. Two credible, actively-maintained candidates were
cloned fresh and audited directly in this pass** (shallow clones,
`LICENSE`/`go.mod`/source read directly — not inferred from README claims
alone):

**Candidate 1 — `github.com/xjasonlyu/tun2socks`** (cloned fresh, HEAD commit
2026-09-13):

| Fact | Value |
|---|---|
| License | MIT (`LICENSE`, read directly) |
| Language/runtime | Go; `core/` is a `gVisor`-netstack-based userspace TCP/IP stack (`go.mod` pins `gvisor.dev/gvisor v0.0.0-20260906120324-45bde0d1defa` directly) |
| Maintenance | Active — most recent commit is 5 days before this audit |
| TUN-fd compatibility | **Confirmed real and direct**: `core/device/fdbased/open_unix.go`'s `open(fd int, mtu uint32, offset int) (device.Device, error)` wraps an externally-supplied fd exactly the way this slice's own proof wraps one for `sing-tun` (`os.NewFile(uintptr(fd), ...)` then builds an endpoint on it) — no re-derivation needed, read directly from source. |
| TCP/UDP/IPv6 | All three supported — it is a general-purpose tun2socks built specifically to be protocol-complete (used as the core of several GUI proxy clients). |
| Android usage precedent | Real — this project (or its lineage) underlies multiple existing Android GUI proxy clients. |
| Integration/runtime burden vs. `sing-tun` | **This is the material finding that changes the comparison from purely structural to factual**: adopting it would add a SECOND, independently-versioned, gVisor-based full TCP/IP stack alongside `sing-tun` (which itself optionally offers a gVisor-backed `"mixed"`/`"gvisor"` stack mode — `stack.go`'s own `WithGVisor` branch) — not a smaller footprint than Option A, and not obviously more Android-proven than `sing-tun` (which every Hysteria2 Android build already carries and links). |

**Candidate 2 — `github.com/heiher/hev-socks5-tunnel`** (cloned fresh, HEAD
commit 2026-09-17, one day before this audit — the most active of any
candidate examined in this document):

| Fact | Value |
|---|---|
| License | MIT (`LICENSE`, read directly — NOT LGPL, correcting an assumption this slice initially had reason to expect for a C networking project) |
| Language/runtime | C, ~5,000 LOC (`find src -name '*.c' \| xargs wc -l`) — its own small, purpose-built lwIP-style TCP/IP stack, not gVisor-based |
| Maintenance | Extremely active (commit the day before this audit) |
| TUN-fd compatibility | Designed for exactly this use case — consumes an externally-created TUN fd and redirects TCP/UDP through a SOCKS5 upstream, per its own README/config shape |
| TCP/UDP/IPv6 | All three, explicitly, including "Fullcone NAT, UDP-in-UDP and UDP-in-TCP" framing options for the SOCKS5 UDP relay — more UDP-framing flexibility than this slice's own Option A design currently specifies (Section 9) |
| Android usage precedent | **Strong, and notable**: its own README credits real production Android VPN apps as users, including **Orbot** (the Guardian Project's widely-deployed Tor VPN client) — a materially stronger existing-Android-production track record than `sing-tun`'s own (which is proven only via Hysteria2's own non-Android-integrated `tun` mode and general sing-box usage, per B46-2A). |
| Integration/runtime burden vs. `sing-tun` | Real trade-off, stated plainly: it is genuinely SMALLER and more Android-proven than adding `tun2socks`/gVisor, but it is C code requiring its own JNI boundary and its own small independent TCP/IP stack implementation — still a second stack Nova would maintain/patch/update on its own schedule, distinct from `sing-tun`, and not something Hysteria2 itself already vendors (unlike `sing-tun`). |

**Conclusion, Option C not adopted, for a stated factual reason rather than
a structural dismissal**: both real candidates would add a genuinely
separate, independently-maintained network-stack dependency alongside
`sing-tun` — one (`tun2socks`) duplicating the SAME class of capability
(gVisor-based userspace TCP/IP) `sing-tun` optionally already offers, the
other (`hev-socks5-tunnel`) a smaller, C-native, more Android-battle-tested
alternative that is a genuinely close call on Android-maturity grounds but
still does not reuse anything already in Hysteria2's own dependency tree
the way Option A does. Option A remains preferred because it needs ZERO new
runtime dependency beyond what Hysteria2 already ships and links for
Android (Section 3) — not because Option C's candidates are deficient.
**`hev-socks5-tunnel` is recorded here as the strongest fallback candidate**
if a future physical spike finds `sing-tun`'s own Android TCP/UDP behavior
unacceptable, given its real Orbot production precedent — stronger than
Option B's fork-maintenance fallback for a scenario where the problem is
`sing-tun` itself rather than the extra SOCKS5 hop.

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
  creates+configures the TUN; `sing-tun` never opens its own device, only
  ever a dedicated duplicate per Section 8) is proven directly on Linux in
  this slice (Section 10). The process boundary itself is pinned (Section
  13), not an open unknown; the remaining Android-specific unknowns
  (SELinux, the real `ParcelFileDescriptor.dup()`/`detachFd()` behavior on
  a device) are named explicitly in "Known unknowns," not glossed
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

**Correction pass (load-bearing fix).** The original pass of this section
claimed the raw fd integer could be passed directly into
`tun.Options.FileDescriptor` with "no dup needed," reasoning that in-process
delivery alone made ownership safe. That reasoning was incomplete: it did
not account for `sing-tun`'s own close behavior. Read directly from the
pinned `tun_linux.go`, `NativeTun.Close()` is:

```go
func (t *NativeTun) Close() error {
    ...
    return E.Errors(t.unsetRoute(), t.unsetRules(), common.Close(common.PtrOrNil(t.tunFile)))
}
```

`t.tunFile` is `os.NewFile(uintptr(options.FileDescriptor), "tun")` — i.e.
`sing-tun` closes the EXACT fd NUMBER it was given, unconditionally, when
its own `Tun`/`Stack` is torn down. If that fd number were the SAME one
`VpnService`'s `ParcelFileDescriptor` also believes it owns, both
`sing-tun`'s `Close()` and a later `ParcelFileDescriptor.close()` would
independently believe they alone are responsible for closing it — a
double-close is then possible by construction, not merely by a
implementation bug. This is exactly the ambiguity the review flagged, and it
is real, not theoretical: this pass's own synthetic proof (Section 10)
reproduces the exact failure mode and its fix on a real Linux TUN fd.

**Corrected model: split ownership via `dup()`, never share one fd number
across two independent owners.**

```
VpnService.Builder.establish()
  -> original ParcelFileDescriptor            (stays owned by VpnService, whole session)
  -> ParcelFileDescriptor.dup()                (Android's own supported public API — see below)
     -> duplicate ParcelFileDescriptor.detachFd()   (ownership-transfer point)
        -> raw bridge fd (int)                 -> tun.Options.FileDescriptor
                                                -> sing-tun exclusively owns/closes THIS fd
```

**Android API shape chosen, and why**: `ParcelFileDescriptor.dup()` is a
supported, non-reflection public Android API — it performs a real `dup(2)`
under the hood, producing a genuinely independent fd number that refers to
the SAME underlying open-file description (so both fds remain valid and
usable, and closing one never invalidates the other). `detachFd()` is then
called on that DUPLICATE (never on the original) — Android's own documented
semantics for `detachFd()` are exactly the ownership-transfer contract this
design needs: the `ParcelFileDescriptor` object's own `close()`/finalizer
becomes a no-op after `detachFd()`, and the caller (here: the bridge/JNI
boundary) becomes solely responsible for eventually closing the returned raw
fd exactly once. This avoids the "invent unsafe reflection just to extract
an integer" trap entirely — no reflection is used anywhere in this design;
`getFd()` alone would have been insufficient because it does NOT transfer
ownership (the Java object would still believe it owns and might close the
fd later), which is precisely the ambiguity being eliminated.

This slice's own host-side proof program (Section 10) implements the exact
Linux equivalent of this model — `unix.Dup(originalFd)` in place of
`ParcelFileDescriptor.dup()`+`detachFd()` — since there is no Android
runtime available in this environment, and confirms it works end to end.

### Android VPN TUN fd (from `VpnService.Builder.establish()`) — corrected ownership table

| # | Question | Answer |
|---|---|---|
| 1 | Original creator | Nova's `VpnService` subclass (the future `B46HysteriaVpnService`), via `Builder.establish()` — same as every existing transport. |
| 2 | Original owner | The SAME `VpnService` subclass, for the whole session. |
| 3 | Duplicate creator | The `VpnService` subclass, via `original.dup()` immediately before starting the bridge. |
| 4 | Duplicate owner (after transfer) | The bridge component exclusively, from the moment `detachFd()` returns the raw fd until the bridge's own `Tun.Close()` runs. The `VpnService`/Kotlin side never touches this fd number again after the transfer point. |
| 5 | Ownership-transfer point | `duplicate.detachFd()` — the single, explicit, non-reflective API call after which exactly one component (the bridge) owns the duplicate. |
| 6 | Who closes the original | The `VpnService` subclass, via `ParcelFileDescriptor.close()`, and ONLY AFTER the bridge (`sing-tun` `Stack`/`Tun`) has been confirmed stopped (Section 16's ordering) — never before, and never assumed-safe to close early just because a duplicate exists. |
| 7 | Who closes the duplicate | `sing-tun`'s own `NativeTun.Close()`, called from the bridge's own stop path — never the Kotlin/`VpnService` side, which no longer holds a live reference to that fd number after `detachFd()`. |
| 8 | Bridge-start failure | If `tun.New`/`tun.NewStack` fails against the duplicate, the bridge itself must close the duplicate it was given (it is the sole owner from the transfer point on); the `VpnService` still separately closes the ORIGINAL — each side closes only the fd it owns, never the other's. |
| 9 | Bridge crash | If the in-process bridge worker fails after successfully starting (Section 14's `bridgeFailed`), the duplicate's fate depends on whether `sing-tun`'s own objects are still reachable — the design requirement is that cleanup (Section 16) always reaches `Tun.Close()` for the duplicate exactly once, whether via the failure path or the ordinary stop path, and the `VpnService` still separately owns and closes the original regardless of the bridge's outcome. |
| 10 | `VpnService` destruction | Android reclaims BOTH fd numbers (they are ordinary process-owned descriptors) — no separate cleanup mechanism is needed or safe to invent, matching every other transport's existing assumption; this is a backstop, not a substitute for the explicit close ordering above under normal/error stop. |
| 11 | App-process death | Same as `VpnService` destruction — the OS reclaims both fds; no state is expected to survive process death (the debug state machine is in-memory only). |

**No object ever believes it owns the same close responsibility as
another, by construction**: after the transfer point, the original and the
duplicate are two independent kernel-level fd numbers, each closed by
exactly one owner. This is a genuinely simpler ownership story than B45A/
B45B's Shadowsocks design in one respect — the duplicate never crosses a
process boundary via `SCM_RIGHTS` (see Section 13's confirmed in-process
boundary decision) — while being MORE careful than the original pass of
this document about not conflating "same process" with "safe to share one
fd number." B45B3P's own found cross-process cleanup bug remains the
motivating precedent for verifying this ordering physically on a real
device in B46-2P, never assumed correct from reading source alone.

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

**Correction pass: the `WritePacket` destination argument, verified by
running a real round trip, not just reading source.** This slice's
corrected synthetic proof (Section 10) implements the RESPONSE direction
for real, which required reading `stack_system.go`'s
`systemUDPPacketWriter4.WritePacket` line by line: the `destination
M.Socksaddr` argument passed to `conn.WritePacket(buffer, destination)`
becomes the reply packet's FABRICATED SOURCE IP (`ipHdr.SetSourceIP(destination.Addr)`)
— i.e. it must be set to the ORIGINAL virtual destination
(`metadata.Destination`, e.g. the Hysteria2 server's own address as the
app believes it), never `metadata.Source` and never the real local target's
address, or the real client socket receives a reply that appears to come
from the wrong peer and silently drops it (UDP has no equivalent of a
TCP RST to signal the mismatch — it just looks like packet loss). This is a
second genuine, non-obvious API-contract fact this slice's proof surfaced
by actually exercising the write-back path, not merely reading the
`WritePacket` interface signature.

**Timeout/session cleanup**: `sing-tun`'s `udpnat.Service` already applies a
configurable idle timeout (`StackOptions.UDPTimeout`, set to 30s in this
slice's proof) per flow — a Nova bridge implementation should size this
consistently with Hysteria2's own QUIC idle-timeout configuration rather
than inventing an independent value, though the exact number is left for
B46-2P's own tuning (not a research blocker).

## 10. Synthetic test results — the critical assumption, proven, corrected pass

**This section fully supersedes the original pass's proof, not merely
extends it** — the original proof's UDP path was demux-only, its pass/fail
result did not depend on the handler actually having been invoked, it
shared the original TUN fd directly with `sing-tun` (the double-close risk
Section 8 corrects), and it had unsynchronized shared-state access. All four
are fixed in the version described below and committed to this branch.

**What was proven, and how, in full**: a Go program
(`research/b46-2b-hysteria-tun-bridge/singtun-proof/main.go` in this
branch) that:

1. Opens `/dev/net/tun` directly and performs the `TUNSETIFF` ioctl itself
   — playing the "external owner creates and configures the TUN" role
   `VpnService.Builder.establish()` plays on Android, using the SAME kernel
   primitive (a real Linux TUN device, not a mock).
2. **Duplicates that fd (`unix.Dup`) before handing anything to `sing-tun`**
   — the Linux equivalent of Section 8's `ParcelFileDescriptor.dup()`+
   `detachFd()` model. The ORIGINAL fd is retained by `main()` (the
   "VpnService" role) and closed LAST; only the DUPLICATE is ever given to
   `sing-tun`.
3. Configures the interface's address (`198.18.55.1/30`) and a route for an
   arbitrary, otherwise-unrelated test destination (`203.0.113.9/32`) via
   the real `ip` tool — analogous to what `VpnService.Builder`'s own
   `addAddress`/`addRoute` calls do.
4. Hands ONLY the duplicate fd integer (never the original, never re-opening
   the device) to `tun.Options{FileDescriptor: bridgeFd}`, using the exact
   pinned `sing-tun` pseudo-version Hysteria2 itself vendors (Section 3) —
   `tun.New(options)` confirmed to accept it and skip its own device-open
   path (matching the Section 4 code-reading finding).
5. Drives `sing-tun`'s unmodified `"system"` stack
   (`tun.NewStack("system", ...)`) against that duplicate fd, with a Handler
   standing in for the future Nova bridge. The Handler reports every
   `NewConnection`/`NewPacketConnection` invocation over a buffered CHANNEL
   (`tcpSeen`/`udpSeen`) — never a shared counter/slice read without
   synchronization — so the main goroutine can deterministically wait for,
   and assert on, a real observed flow instead of sleeping and hoping.
6. From the SAME host, makes a real `net.Dial("tcp", "203.0.113.9:9000")`
   and a real `net.Dial("udp", "203.0.113.9:9001")` — real kernel-routed
   traffic, not fabricated packets — which the kernel routes onto the real
   TUN device because of the route programmed in step 3.
7. For TCP, the Handler relays synchronously to a local echo target and the
   test asserts the exact byte payload returns AND that a channel receive
   observed the expected destination — a send/receive success alone is not
   treated as sufficient (mirroring the stronger bar now applied uniformly
   to both protocols).
8. For UDP, the Handler now performs the FULL round trip: it reads the real
   inbound datagram off the tun-side flow (`conn.ReadPacket`), forwards the
   exact payload to a local UDP echo target, reads the echo response, and
   writes it back through `conn.WritePacket(outBuf, metadata.Destination)`
   — the corrected destination-argument semantics from Section 9. The test
   asserts, IN ORDER: (a) a channel receive observed `NewPacketConnection`
   within a bounded timeout (never proceeding on a bare `Write()`), (b) the
   observed destination string is EXACTLY `"203.0.113.9:9001"`, (c) the
   observed source is non-empty, and (d) the real client socket receives
   the exact original payload back, byte for byte, through the tun.

**Result, this slice's corrected run, verbatim** (re-run twice,
deterministic both times — no flake observed):

```
OK: split ownership — original fd=5 (VpnService role, closed last), bridge fd=6 (sing-tun role, closed by NativeTun.Close())
OK: sing-tun accepted the duplicate fd via Options.FileDescriptor, did not open its own device
TCP OK: round trip match=true, handler observed source=198.18.55.1:47142 destination=203.0.113.9:9000
UDP OK: handler observed source=198.18.55.1:52476 destination=203.0.113.9:9001, round trip match=true

=== RESULT === tcpObserved=true(&{source:198.18.55.1:47142 destination:203.0.113.9:9000}) tcpRoundTrip=true udpObserved=true(&{source:198.18.55.1:52476 destination:203.0.113.9:9001}) udpRoundTrip=true
```

Exit code `0` on both runs — the program's own exit code is now driven
strictly by the observed conditions above (`os.Exit(1)` if the TCP round
trip fails, if the UDP handler observation times out, if the observed UDP
metadata mismatches, or if the UDP round trip fails), never by a
send-only heuristic.

**`go vet ./...`**: clean, no findings.

**Race-enabled run (`go build -race`), a genuine, honest finding about the
pinned dependency, not about this proof's own code**: running the
race-instrumented binary surfaced **3 real data-race warnings, all inside
`sing-tun`'s own `stack_system_nat.go` `TCPNat.LookupBack`/`Lookup`**, not in
this proof program's code. Read directly:

```go
func (n *TCPNat) LookupBack(port uint16) *TCPSession {
    n.portAccess.RLock()
    session := n.portMap[port]
    n.portAccess.RUnlock()
    if session != nil {
        session.LastActive = time.Now() // <- written OUTSIDE the lock
    }
    return session
}
```

`session.LastActive` is written here AFTER `n.portAccess.RUnlock()` — a real,
pre-existing, unsynchronized concurrent write, racing against
`checkTimeout`'s own read of the same field under `portAccess.Lock()`
elsewhere in the same file, and against concurrent `LookupBack` calls from
different goroutines (this proof's real TCP flow triggered concurrent calls
from `acceptLoop`'s goroutine and `processIPv4TCP`'s reverse-NAT check on
the tun-read goroutine). **This is a genuine defect in the pinned `sing-tun`
version Hysteria2 itself vendors** (Section 3's exact pseudo-version), not
an artifact of this proof's own design — the proof's own TCP/UDP result was
still correct in the race-instrumented run (the race is on a
best-effort "last active" timestamp used only for idle-timeout eviction,
not on any value that reached the wire), but it is recorded honestly here
as a real finding for Section 21's supply-chain assessment, not glossed
over because the functional result still passed.

**What this does and does not prove, stated precisely**: this proves (a)
`sing-tun`'s external-fd path works correctly against a REAL Linux kernel
TUN device using a REAL, independently-owned duplicate fd (never the
original), (b) TCP and now FULL-ROUND-TRIP UDP work correctly through it,
deterministically observed via channel synchronization, and (c) the
dependency itself has at least one real, currently-unfixed internal data
race worth tracking. It does NOT prove anything about Android's
`VpnService` specifically (SELinux labeling, `ParcelFileDescriptor.dup()`/
`detachFd()`'s exact behavior on a real device, the app-process/VPN-
exclusion interaction B33's own findings already show matters for OTHER
transports' diagnostic probes, JNI/native packaging correctness, or
battery/idle behavior) — those remain physical-device unknowns for B46-2P,
named explicitly below, not silently assumed proven by this host-side
result.

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

## 13. Runtime/process architecture — process boundary PINNED (corrected pass)

**Correction pass: the original pass left the bridge's process boundary
open ("in-process JNI or a small dedicated bridge binary launched as a
child process") while simultaneously claiming Option A's ownership
advantage rested on "no cross-process TUN-fd transfer." Those two claims
cannot both remain true unresolved — an ambiguous boundary is not a
decided architecture. This is now pinned.**

**Decision: the Nova sing-tun bridge runs IN-PROCESS with the
`VpnService`. Hysteria2 remains a separate child process.**

```
Android app / VpnService process:
  - ParcelFileDescriptor (original, VpnService-owned)
  - TUN duplicate (bridge-owned, via dup()+detachFd(), Section 8)
  - sing-tun-driven bridge (in-process JNI)
  - FD Control server (Unix-domain socket listener)
  - VpnService.protect()

Separate child process:
  - Hysteria2 executable
  - SOCKS5 listener
  - Hysteria QUIC runtime
```

**Justification, from REAL precedent already in this codebase, not a fresh
guess**: Nova already has both boundary shapes proven in production for
different transports, and the choice between them is not arbitrary —
`XrayCoreRuntime.kt`'s own doc states its real implementation "loads a
native `.so` via JNI" (the pinned AndroidLibXrayLite AAR, `libgojni.so`,
loaded IN-PROCESS with the app/`VpnService`), while
`ShadowsocksProcessLauncher.kt` launches `sslocal` via a real
`ProcessBuilder` as a SEPARATE CHILD PROCESS. Xray's Go core is a
`gomobile`-bind-style library exactly like what this bridge would be — the
SAME precedented pattern applies directly: a Go library (this bridge,
built with the SAME toolchain/NDK discipline B46-2A already established for
the `hysteria` binary itself, Section 12 there) compiled via `gomobile bind`
into an `.aar`, loaded via JNI into the `VpnService`'s own process, exactly
as Xray's core already is. This is not a new pattern for Nova to invent or
validate — it is reuse of an already-shipped mechanism.

**This decision is what makes Section 8's ownership model correct**: only
because the bridge is in-process does "the duplicate fd never crosses a
process boundary" hold — had a child-process bridge been chosen instead,
the "no cross-process TUN-fd transfer" advantage would evaporate and an
explicit `SCM_RIGHTS`-style handoff (like B45A's own `RealB45ATunFdBridge`)
would be required for the TUN duplicate, exactly as the review flagged.
Choosing in-process removes that requirement rather than leaving it
implicit.

Hysteria2 itself remains a SEPARATE child process (as B46-2A Section 8
already established, and as `ShadowsocksProcessLauncher`'s own precedent
confirms Nova already knows how to run and manage), talked to by the
in-process bridge over a local SOCKS5 TCP connection — this boundary is
unaffected by the bridge's own boundary decision above.

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
- `B46HysteriaSpikeTransitions.bridgeFailed(current, reason)` added
  — **corrected in this review pass, renamed from the original
  `bridgeExitedUnexpectedly`/`BridgeExited`**. The original version
  unconditionally cleared `runtimePid`, which was wrong: a bridge failure
  (Section 13's chosen in-process worker/stack) is a SEPARATE failure
  domain from the Hysteria2 CHILD PROCESS, and never itself proves that
  child process terminated. `bridgeFailed` now preserves `runtimePid`
  exactly as it was — only `runtimeExitedUnexpectedly` (backed by real
  evidence the runtime process itself exited) may clear it. The renamed
  error type `BridgeFailed` (from `BridgeExited`) reflects that this is an
  in-process worker/stack failure, not a process "exit" the way a child
  process exiting is a process exit.
- New typed errors added to `B46HysteriaSpikeError`: `BridgeStartFailed`,
  `BridgeFailed`, `BridgeFlowParseFailed`, `AuthFailed`, `TlsFailed`,
  `QuicUnreachable`, `TcpProbeFailed`, `UdpProbeFailed`, `DnsProbeFailed`
  (replacing the single generic `DataPlaneProbeFailed` with the specific
  causes Phase 15 of this task required distinguishing).
- Four unit tests added/kept covering this boundary precisely:
  `runtimeStarted cannot be reached by skipping tunBridgeReady`
  (illegal-skip rejection), `bridgeFailed clears to ERROR with typed
  BridgeFailed cause but does NOT clear runtimePid before Hysteria2 has
  started`, `bridgeFailed does NOT falsely clear a still-owned Hysteria
  runtimePid` (starts the runtime first, THEN fails the bridge, and asserts
  the pid survives — this is the review's exact required regression test),
  and `runtimeExitedUnexpectedly is the ONLY transition that clears
  runtimePid - proven by contrast with bridgeFailed` (runs both transitions
  from the identical starting state and asserts they diverge).
- All other existing call sites (`full happy path`, the ERROR-recovery test,
  the two `runtimeExitedUnexpectedly` tests, the FD Control counter test)
  updated to call `tunBridgeReady(status)` between `tunEstablished` and
  `runtimeStarted`, preserving their original intent.
- `TUN_BRIDGE_READY`'s own doc comment tightened (Section 6 above,
  restated in-code) to explicitly state what it does NOT mean: not that
  Hysteria2 is running, not that SOCKS5 forwarding works, not that QUIC
  works, not that any data plane exists.

16 tests total, all passing (compiled and run via the same manual
`kotlinc`+`JUnitCore` harness B46-2A used, since the full Gradle
`testDebugUnitTest` task remains blocked by the unrelated missing AWG AAR
prerequisite in this environment).

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
| Bridge (in-process worker/stack) failed | `BridgeFailed` (via `bridgeFailed` — never clears `runtimePid`, see Section 14) |
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
   `t.tunFile`, i.e. the DUPLICATE fd number the bridge was given, per
   Section 8's corrected ownership model — never the original).
6. Close the original `ParcelFileDescriptor` on the `VpnService` side —
   now unambiguous per Section 13's pinned in-process boundary: this is a
   genuinely separate fd number (the original, never handed to the bridge)
   closed by the `VpnService` itself, always AFTER step 5, never before and
   never assumed to be the same close call as step 5.
7. Remove the FD Control Unix-domain-control socket (mirroring B45B3P's own
   found-and-fixed cleanup bug — this must be physically re-verified on a
   real device, never assumed correct from reading source).
8. Clear the state machine's `runtimePid` ONLY on the normal-stop path
   (once the Hysteria2 process is confirmed terminated by this same
   cleanup sequence, step 3) or via `runtimeExitedUnexpectedly()` — NEVER
   via `bridgeFailed()`, which (per Section 14's correction) must preserve
   whatever `runtimePid` value it found, since a bridge failure alone never
   proves the runtime process terminated.
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
| Hysteria2 process crashes | Bridge's own dial-to-SOCKS5 calls start failing; state machine moves to `ERROR` via `runtimeExitedUnexpectedly` (already unit-tested, clears `runtimePid` — evidence-backed); TUN/bridge are torn down via the cleanup model above — never left as a stale `RUNNING`/`DATA_PLANE_READY`. |
| Bridge (in-process worker/stack) fails | State machine moves to `ERROR` via `bridgeFailed` (already unit-tested) — **`runtimePid` is preserved, not cleared**, because a bridge failure never proves the Hysteria2 child process terminated (Section 14's correction). Cleanup must still explicitly terminate the still-possibly-running Hysteria2 child process (never left as an orphan just because the bridge died) — the SAME cleanup ordering above applies, entered from the bridge-failure trigger instead of a normal stop request; `runtimePid` is only cleared once that termination is confirmed, via the same evidence-backed path `runtimeExitedUnexpectedly` uses. |
| `VpnService` is destroyed | Android reclaims BOTH the original and duplicate TUN fds; any bridge/Hysteria2 child process must be explicitly terminated by the service's own `onDestroy`/`onRevoke` handling (unchanged discipline from every other transport) — never rely on the OS to clean up a child process it does not itself own. |
| FD Control socket dies | Mirrors B46-2A's own unresolved-but-flagged case: the NEXT QUIC-socket protect() attempt fails, surfaced as `FdControlHandoffFailed`/`FdControlHandoffTimedOut` — never a silent "still protected" assumption. |
| TUN fd becomes invalid | Bridge's read/write on it fails; must be treated the same as a bridge failure (`BridgeFailed`/`BridgeFlowParseFailed` as appropriate, `runtimePid` preserved per the row above) — never retried silently against a dead fd. |
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
| **Known defect in the pinned dependency (new finding, this correction pass)** | `sing-tun`'s own `stack_system_nat.go` `TCPNat.LookupBack` has a real, reproducible internal data race (Section 10 — found via `go build -race`, not read speculatively): `session.LastActive = time.Now()` is written outside the `portAccess` lock it was just read under. This is upstream's own defect, not something this design introduces or can silently work around. It does not block adopting `sing-tun` (the raced field is a best-effort idle-timeout timestamp, not anything that reaches the wire, and Hysteria2 itself already ships this exact code on Android via its own `tun` mode's internal use of the same library) but it is recorded here as a genuine, currently-open upstream quality concern to track — a candidate for a small upstream bug report/PR rather than a Nova-side workaround, since patching it locally would reintroduce exactly the fork-maintenance cost Option B was passed over for. |

## 22. Synthetic test results (Phase 11) — summary

See Section 10 for the full account, corrected in this pass. Summary: real
TCP round trip through an externally-owned, PROPERLY-DUPLICATED TUN fd
(never the original), proven; a FULL real UDP round trip (not merely demux)
through the same duplicated fd, proven, with both the source/destination
metadata and the returned payload verified deterministically via channel
synchronization (never a sleep-and-hope pattern); two real,
previously-undocumented API-contract requirements discovered and now
documented for B46-2P (`NewConnection` must relay synchronously;
`WritePacket`'s `destination` argument must be the original virtual
destination, not the source); one real, reproducible internal data race in
the pinned `sing-tun` dependency itself, found via `go build -race` and
recorded honestly rather than glossed over. Re-run twice (plain build) plus
once under the race detector, deterministic functional result all three
times — not a claim inferred from reading library source alone.

## 23. Known unknowns (explicit)

- **Full SOCKS5 UDP ASSOCIATE framing (the hop between the bridge and
  Hysteria2's own SOCKS5 listener) was not implemented or tested** in this
  slice's proof — the proof's UDP round trip goes through a controlled
  local echo target standing in for that listener, not through a real
  Hysteria2 process. This is real, bounded, well-understood engineering
  (RFC 1928 Section 7) that B46-2P's concrete bridge implementation must
  still do; it is not a research gap, but it is also not proven working
  against a real Hysteria2 SOCKS5 server yet.
- **`ParcelFileDescriptor.dup()`+`detachFd()`'s exact behavior on a real
  Android device is unverified** — Section 8's ownership model is designed
  against Android's own documented API contract and validated on Linux via
  the equivalent `unix.Dup()` call, but no Android runtime was available in
  this environment to exercise the real API.
- **JNI/native packaging mechanics for the in-process bridge are
  unresolved** — Section 13 pins the PROCESS BOUNDARY (in-process JNI,
  matching Xray's own precedent) but the exact `gomobile bind`
  invocation/`.aar` structure is not yet built or tested, only argued from
  precedent.
- **Nothing about Android's `VpnService`/SELinux/app-process-exclusion
  behavior was tested** — this slice's proof is entirely a plain-Linux-host
  program; B33's own findings (an app process is excluded from its own VPN
  by `addDisallowedApplication`) are a directly relevant precedent for
  anything the bridge does INSIDE Nova's own excluded process, and must be
  re-checked against the now-pinned in-process boundary.
- **MTU/PMTU interaction with QUIC was not exercised** (Section 12) — no
  real network path with a constrained MTU was involved in the host-side
  proof.
- **Performance overhead of the extra SOCKS5 hop is unmeasured** — no
  throughput/latency/CPU numbers exist for Option A versus a hypothetical
  Option B, on any platform.
- **The `sing-tun` internal data race (Section 21) has not been reported
  upstream** in this pass — recorded here, not yet acted on beyond
  documentation.
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

**Re-decided from scratch in this correction pass, not preserved by
default** (per the explicit instruction not to keep the prior verdict merely
because it was the prior verdict). Weighing the state AFTER the fixes, not
before:

- **TUN fd ownership**: previously stated but NOT actually deterministic
  (Section 8's original "no dup needed" reasoning had a real double-close
  risk once `sing-tun`'s own `Close()` behavior was read correctly). NOW
  genuinely deterministic: split ownership via `dup()`+`detachFd()`, two
  independent fd numbers, one owner each, no object believing it owns the
  same close responsibility as another. This was the single load-bearing
  gap the review identified, and it is now closed by a real design, not
  patched over.
- **Process boundary**: previously left ambiguous while relying on the
  boundary implicitly. NOW pinned to a specific, precedented shape
  (in-process JNI, matching Xray's own already-shipped pattern) — no
  remaining internal contradiction between "no cross-process fd transfer"
  and "the boundary is undecided."
- **UDP proof**: previously demux-only with a send-and-sleep pass condition
  that did not depend on the handler having been invoked at all. NOW a full
  round trip (payload forwarded to a real target and returned byte-for-byte
  through `sing-tun`'s own `WritePacket` path), gated on a genuine channel
  observation of the handler with exact-match metadata assertions — the
  proof's pass/fail result is now driven by real observed conditions,
  never a heuristic.
- **Determinism**: previously relied on an unsynchronized shared-counter/
  slice read after a fixed sleep. NOW channel-synchronized throughout, and
  additionally exercised under the race detector (which correctly found
  ZERO races in this proof's OWN code, and separately surfaced one honestly
  disclosed pre-existing race inside the pinned dependency itself).
- **Bridge/runtime ownership separation**: previously conflated (a bridge
  failure incorrectly cleared a Hysteria2 runtime pid it had no evidence
  about). NOW correctly separated in the state machine and unit-tested
  directly (`bridgeFailed does NOT falsely clear a still-owned Hysteria
  runtimePid`).
- **Option C**: previously dismissed structurally without auditing a real
  candidate. NOW backed by a real audit of two current, credible candidates
  (`xjasonlyu/tun2socks`, `heiher/hev-socks5-tunnel`), with one
  (`hev-socks5-tunnel`) recorded honestly as a genuinely close call on
  Android-maturity grounds and kept as the documented fallback if `sing-tun`
  itself proves inadequate on a real device.

**None of the fixes above changed the underlying technical facts that
originally justified Option A** — `sing-tun`'s external-fd path still
works (re-proven, more rigorously, in this pass), Hysteria2's SOCKS5
listener is still real and unmodified, and no new blocker was discovered
that prevents building the physical spike. What changed is that the design
is now actually SOUND where it previously only looked sound — which is what
this correction pass exists to verify.

**A. ARCHITECTURE READY FOR B46-2P.**

- Architecture is selected: Option A, `NOVA_SING_TUN_ADAPTER` (Section 7),
  re-affirmed after a real Option C audit (Section 6).
- TUN fd ownership is solved DETERMINISTICALLY, not merely asserted: split
  via `dup()`+`detachFd()`, no double-close possible by construction
  (Section 8), verified on Linux via the direct `unix.Dup()` equivalent.
- The process boundary is PINNED, not left open: in-process JNI for the
  bridge, matching Nova's own existing Xray precedent; Hysteria2 stays a
  separate child process (Section 13).
- TCP and UDP forwarding models are credible AND now both proven with a
  real round trip, deterministically observed (Sections 9-10) — UDP is no
  longer demux-only.
- Bridge and Hysteria2-runtime ownership are correctly separated in the
  debug state machine, with a direct regression test proving a bridge
  failure never falsely clears a still-owned runtime pid (Section 14).
- No unresolved blocker prevents building the physical Android spike: the
  remaining unknowns (Section 23) are ordinary engineering/testing work for
  B46-2P (SOCKS5 UDP-ASSOCIATE framing against a real Hysteria2 process,
  the real Android `dup()`/`detachFd()`/JNI mechanics, MTU/PMTU, and
  performance measurement) — none are open research questions about
  whether the architecture can work at all.

## Sources cited (external)

- [apernet/hysteria repository](https://github.com/apernet/hysteria), tag
  `app/v2.12.3`, commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` — re-cloned
  fresh in this slice.
- [apernet/sing-tun repository](https://github.com/apernet/sing-tun),
  pseudo-version `v0.2.6-0.20250920121535-299f04629986` — resolved and
  downloaded fresh via the Go module proxy in this slice;
  `tun.go`/`tun_linux.go`/`stack.go`/`stack_system.go`/`stack_system_nat.go`
  read directly from the populated module cache (the last one specifically
  in this correction pass, to trace the data race Section 10/21 report).
- [xjasonlyu/tun2socks repository](https://github.com/xjasonlyu/tun2socks) —
  cloned fresh in this correction pass (Option C candidate 1, Section 6);
  `LICENSE`/`go.mod`/`core/device/fdbased/open_unix.go` read directly.
- [heiher/hev-socks5-tunnel repository](https://github.com/heiher/hev-socks5-tunnel) —
  cloned fresh in this correction pass (Option C candidate 2, Section 6);
  `LICENSE`/`README.md` read directly.
- Internal: `docs/B46_2A_HYSTERIA2_ANDROID_FEASIBILITY.md` (baseline
  findings this document extends, not re-derives from scratch),
  `docs/B45A_SHADOWSOCKS_RUST_SPIKE.md` /
  `docs/B45B3P_SHADOWSOCKS_PHYSICAL_VALIDATION.md` (fd-handoff/cleanup
  precedent), `PROJECT_ARCHITECTURE.md` (reachability/transport-selection
  boundaries, B33's app-process-exclusion finding),
  `android/app/src/main/java/net/pocvpn/client/vpn/xray/XrayCoreRuntime.kt`
  and `android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksProcessLauncher.kt`
  (read directly in this correction pass to confirm Nova's own real
  in-process-JNI vs. child-process precedent, Section 13).

## Files changed in this slice

- `docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md` (this document; created,
  then corrected in a same-day follow-up pass per direct PR review).
- `research/b46-2b-hysteria-tun-bridge/singtun-proof/{main.go,go.mod,go.sum,.gitignore}`
  (new, isolated host-side synthetic proof — not part of the Android app,
  not built by Gradle, not reachable from any production path; rewritten in
  the correction pass for the fd-ownership split, the full deterministic
  UDP round trip, and race-free synchronization).
- `android/app/src/debug/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeState.kt`
  (adds `TUN_BRIDGE_READY` phase, `tunBridgeReady`/`bridgeFailed`
  transitions (renamed from `bridgeExitedUnexpectedly` and corrected to
  preserve `runtimePid`), and the expanded typed error taxonomy — still
  debug-only, still unreachable from any manifest entry point, per
  B46-2A's own isolation guarantee).
- `android/app/src/test/java/net/pocvpn/client/debug/b46hysteria/B46HysteriaSpikeStateTest.kt`
  (updates existing tests for the new required phase; adds four new tests
  covering the `TUN_BRIDGE_READY` gate and the corrected bridge/runtime
  ownership separation).
- `docs/ROADMAP.md` (B46 row status wording only — see below).
