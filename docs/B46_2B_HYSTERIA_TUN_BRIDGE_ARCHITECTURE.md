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

**SECOND CORRECTION PASS (same day, following a direct review of the
race-enabled run the FIRST correction pass introduced):** that pass's own
race-enabled proof run found a REAL, reproducible internal data race inside
`apernet/sing-tun@299f04629986` (Hysteria2's own pinned commit) —
`TCPNat.LookupBack` writes `session.LastActive` outside its own lock. This
pass resolves it by re-pinning the Nova BRIDGE's own `sing-tun` dependency
(never Hysteria2's, which stays untouched) to current
`github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`,
which fixes the race structurally upstream, and porting the proof to that
dependency's changed API (Handler interface, buffer headroom semantics) —
see the new dedicated Section 10.5, and updated Sections 1, 3, 7, 21, 22,
23, and "Decision gate". Re-decided the verdict again after this fix, not
preserved by default. No Kotlin state-machine change was needed for this
pass (the dependency swap invalidates no state-machine invariant).

**THIRD CORRECTION PASS (same day, following a direct license audit of
PR #89) — the single most consequential correction in this document:**
every prior pass incorrectly stated `sing-tun` (both the `apernet` and
`sagernet` forks) is MIT-licensed. **Both are GPL-3.0-or-later**, verified
directly from each fork's own `LICENSE` file — the earlier error came from
reading Hysteria2's own top-level `LICENSE.md` (genuinely MIT) and wrongly
attributing that license to the separate `sing-tun` Go module. This pass:
(1) corrects every MIT claim about `sing-tun` in this document (Sections
7, 21); (2) adds a dedicated licensing-audit section (10.6) establishing
that Nova's repository has no `LICENSE` file and that no owner decision on
GPL-compatible distribution exists; (3) replaces the prior pass's
overstated "Android executable cross-build" claim with a REAL, verified
in-process JNI/AAR artifact — a `gomobile bind`-produced `.aar` whose
native library was confirmed (via `go tool nm`) to contain 1,344 linked
`sing-tun` symbols (Section 10.7); (4) audits, with objective binary
evidence, whether Hysteria2's own child-process executable also links
GPL-3.0-or-later `sing-tun` code (Section 10.8 — yes, 125 symbols,
confirmed via `go tool nm` on a freshly built binary); (5) performs a deep
audit of a credible, all-MIT alternative, `heiher/hev-socks5-tunnel`
(Section 10.9), including a real successful native Android `.so` build;
and (6) re-decides the verdict from **ARCHITECTURE READY FOR B46-2P** to
**TECHNICALLY READY — LICENSING DECISION REQUIRED** (Section "Decision
gate"), since a technical success on a GPL-3.0-or-later dependency is not
the same claim as "cleared to ship," and this pass is not positioned to
make that licensing call. No repository license was added or changed by
this pass — that is an owner decision.

**FOURTH CORRECTION PASS (same day) — completing the prior pass's own
recommended next step, and finding a reason NOT to select it:** a real
host-side data-plane proof for `heiher/hev-socks5-tunnel` (Section 10.9's
MIT-licensed candidate) was attempted, using a real third-party SOCKS5
server (`danted`) and real TCP/UDP echo targets, with a C harness calling
HEV's own public `hev_socks5_tunnel_main`/`hev_socks5_tunnel_quit` API.
Two independent, reproducible crashes were found and confirmed via `gdb`
backtraces into HEV's own library code: an invalid external TUN fd
crashes the process (`double free or corruption`, inside HEV's own
task-system cleanup), and a SOCKS5-client outbound-socket failure crashes
it a second way (`munmap_chunk(): invalid pointer`, inside HEV's own
coroutine-stack cleanup) — the latter triggered in this sandbox by a
kernel with no IPv6 support at all interacting with HEV's own hardcoded
`AF_INET6` socket usage, but landing in the same class of unhandled-
early-failure defect as the first, Android-realistic one. Per the task's
own instruction not to force HEV selection merely for being MIT-licensed,
**`hev-socks5-tunnel` is NOT selected** — see the new dedicated Section
10.10. `sing-tun` remains the sole candidate with a complete, crash-free,
race-checked proof; the verdict remains **TECHNICALLY READY — LICENSING
DECISION REQUIRED**, now for a more decisive reason (no crash-free
MIT alternative currently exists) rather than merely "not yet proven."
HEV's real Android AAR/JNI build success (Section 10.10) and its clean
MIT license tree (Section 10.9) remain accurate, unaffected facts — only
its runtime crash-safety on early-failure paths is now known to be
deficient. No repository license was added or changed by this pass.

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
`sing-tun`-class library it already vendors, which genuinely supports an
external fd via `Options.FileDescriptor`. This slice designed and picked
the smallest architecture to bridge that gap — **Option A,
`NOVA_SING_TUN_ADAPTER`** (Nova drives its OWN `sing-tun`-class dependency,
IN-PROCESS with the `VpnService` — Section 13's pinned boundary — against a
DEDICATED DUPLICATE of the VpnService-created fd — Section 8's ownership
model — and forwards demuxed TCP/UDP flows into Hysteria2's own,
unmodified, SOCKS5 listener) — and then built and ran a real, non-mocked,
host-side proof program that exercises the exact API surface a future
B46-2P Android bridge would use.

**The proof's own pinned dependency changed across this document's
revisions, for a real, load-bearing reason, not preference**: it was
originally built against the exact `apernet/sing-tun` commit Hysteria2
itself vendors, until a race-enabled (`go build -race`) run found a real,
reproducible internal data race in that dependency's own TCP session table.
Because the Nova bridge and Hysteria2 never share a process (Section 13),
they were never required to share a dependency version either — so the
Nova bridge's OWN pin was moved to
**`github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`**,
current upstream `dev` HEAD at the time of this pass, which fixes that race
structurally (per-session locking, verified by reading source, not
assumed) and additionally exposes a purpose-built
`EXP_ExternalConfiguration` flag and explicit Android-path awareness the
`apernet` fork lacks. Full remediation comparison in the dedicated "sing-tun
concurrency/race resolution" section (10.5).

Against this final, race-clean dependency: the proof opens a genuine Linux
TUN device, duplicates the fd (never sharing the original with `sing-tun`),
hands only the duplicate to the selected library, and shows a real TCP
connection round-tripping through it and a real, FULL UDP round trip
(payload out and back, not merely a demuxed flow) through it, both
deterministically observed via channel synchronization, and BOTH re-run
twice under the race detector with ZERO race reports. A real `GOOS=android
GOARCH=arm64 CGO_ENABLED=0` build of the same program succeeds with no NDK
and no linkname workaround. The proof surfaced three real, non-obvious
API-contract facts undocumented anywhere upstream — two specific to the
now-selected dependency's own API shape (its `NewConnectionEx`/
`NewPacketConnectionEx` handler methods no longer force-close the
connection after returning, a genuine improvement over the superseded
fork's "must relay synchronously or get RST'd" behavior; and its
`WritePacket` requires the caller to pre-reserve buffer headroom or it
panics) plus one — `WritePacket`'s `destination` argument must be the
original virtual destination, not the source, or a UDP reply silently
vanishes — confirmed on both dependencies audited. All now written into
this document and the proof program's own comments so B46-2P does not
rediscover them the hard way.

**A fourth correction pass found the single most consequential error yet:
both `sing-tun` forks this document evaluated are GPL-3.0-or-later, not
MIT as earlier passes incorrectly stated** (a direct read of each
`LICENSE` file, not carried over from an unverified assumption) — and this
pass proved, with a real `gomobile bind`-produced Android AAR containing
1,344 linked `sing-tun` symbols, that the selected architecture genuinely
links this GPL code in-process into Nova's own `VpnService`. Nova's
repository carries no `LICENSE` file establishing a compatible
distribution policy, and no such policy decision has been made — an
engineering pass cannot make that decision.

**A fifth correction pass then attempted to complete that recommended next
step — `hev-socks5-tunnel`'s own live round-trip proof — and found two
independent, reproducible crash defects in HEV's own error-handling paths
instead** (Section 10.10): an invalid external TUN fd crashes the calling
process (`double free or corruption`, confirmed via `gdb`, inside HEV's own
task-system cleanup), and a SOCKS5-client outbound-socket failure crashes
it a second, distinct way (`munmap_chunk(): invalid pointer`, also
confirmed via `gdb`, also inside HEV's own coroutine-stack cleanup). Both
reproduced in a plain, non-instrumented build, ruling out sanitizer false
positives. Per this task's own explicit instruction ("do not force HEV
selection merely because it is MIT"), **`heiher/hev-socks5-tunnel` is NOT
selected** — an in-process bridge that crashes the host process on a
plausible, Android-realistic failure input (an invalid fd) is a genuine
safety concern, not merely an incomplete proof. `sing-tun` remains the
only candidate with a complete, crash-free, race-checked round-trip proof.

**Verdict: TECHNICALLY READY — LICENSING DECISION REQUIRED** (see Section
"Decision gate" — re-decided from scratch in each of this document's
correction passes following direct reviews of PR #89, never preserved by
default). The `sing-tun`-based bridge is technically sound (deterministic
fd ownership, real TCP+UDP round trip, race-clean, a real in-process
JNI/AAR artifact built and verified) but gated on an explicit owner
licensing decision before any release-track physical integration.
`hev-socks5-tunnel` remains a credible MIT-licensed alternative on every
axis EXCEPT the two crash defects just found — a future pass could revisit
it once those are understood/fixed upstream, but this pass does not
recommend it as ready. See "Known unknowns" for what is still open and
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
- Hysteria2's OWN `sing-tun` dependency, unchanged and untouched by this
  pass: **`github.com/apernet/sing-tun@v0.2.6-0.20250920121535-299f04629986`**,
  per `app/go.mod`/`app/go.sum` in that exact clone — byte-identical
  pseudo-version string to B46-2A's own recorded value. **This is a
  separate fact from the Nova bridge's OWN `sing-tun` dependency choice**
  (see the dedicated "sing-tun concurrency/race resolution" section below)
  — Hysteria2 itself is a separate child process (Section 13) and this pass
  does not patch, fork, or re-pin anything inside it.

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
  module (`apernet/sing-tun`, already a transitive dependency Hysteria2
  itself pulls and already audited for buildability by B46-2A) — strictly
  smaller than option B's fork burden, and no new third-party runtime is
  introduced (unlike option C). **License correction (fourth correction
  pass, licensing audit): `apernet/sing-tun`'s own `LICENSE` file, read
  directly, is GNU General Public License v3 "or (at your option) any
  later version" — NOT MIT.** An earlier pass of this document incorrectly
  stated MIT here, conflating Hysteria2's OWN top-level `LICENSE.md` (which
  genuinely is MIT) with `sing-tun`'s separate, independent `LICENSE` file.
  See the dedicated "sing-tun / bridge-dependency licensing audit" section
  for the full correction and its consequences.
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
**`hev-socks5-tunnel` was recorded here as the strongest fallback
candidate** given its real Orbot production precedent — **a later pass
(Section 10.10) completed its live proof and found two reproducible crash
defects in its own error-handling code, so it is NOT currently selected**;
this structural comparison (smaller, C-native, more Android-battle-tested
than `tun2socks`) remains accurate as a structural assessment, just not as
a current recommendation.

## 7. Phase 4 — chosen architecture

**A. `NOVA_SING_TUN_ADAPTER`.**

Justification, restated against the required criteria (not fewest lines of
code):

- **Least architectural duplication**: reuses a `sing-tun`-class dependency
  and "system" stack of the SAME shape/lineage Hysteria2 itself vendors and
  would use internally if it exposed this path — Nova is not inventing a
  parallel TCP/IP stack, just driving one from outside instead of from
  inside Hysteria2's own binary. **Note (dependency-selection correction
  pass, Section 10.5): the Nova bridge's OWN pin
  (`sagernet/sing-tun@fbc0c3dff312...`) is no longer byte-identical to what
  Hysteria2 itself vendors (`apernet/sing-tun@299f04629986`)** — a
  deliberate, justified divergence made safe by Section 13's process
  boundary (the two never share a build), chosen specifically because the
  `apernet` fork had a real data race the `sagernet` lineage fixes
  upstream. This is a smaller duplication claim than the original design
  made, stated honestly rather than left overstated.
- **Maintainability**: zero upstream Hysteria2 divergence (still no fork of
  Hysteria2 itself, per Option B's cost analysis); Hysteria2's own pinned
  `apernet/sing-tun` dependency already ships inside every `hysteria`
  release Nova would package regardless of this design. The Nova bridge's
  OWN `sagernet/sing-tun` pin IS a new supply-chain relationship (honestly
  counted, not hidden) — but tracking one additional, independently-pinned,
  actively-developed dependency is a materially smaller ongoing cost than
  owning a patch/fork of either `sing-tun` fork or of Hysteria2 itself
  (Option B's/R1's costs, Sections 6/10.5).
- **Upstream compatibility**: unaffected by future Hysteria2 releases in the
  way a fork (Option B) would be — Option A only needs a `sing-tun`-class
  library's `Options.FileDescriptor`/`NewStack("system", ...)` surface,
  which this slice's own proof shows is stable across BOTH forks audited,
  pinned independently of whatever version Hysteria2 itself happens to
  ship.
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
- **Supply-chain risk**: one additional, already-vetted-for-buildability (by
  B46-2A's own work) dependency; no new third-party runtime (unlike Option
  C). **This bullet no longer says "MIT-licensed" — corrected: the
  dependency is GPL-3.0-or-later (see the dedicated licensing-audit section
  below). Supply-chain risk here is therefore not just build/version risk
  but a real licensing-architecture question, addressed on its own terms
  in that section rather than folded into this bullet's original,
  incorrect framing.**
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
original), and (b) TCP and FULL-ROUND-TRIP UDP work correctly through it,
deterministically observed via channel synchronization. **This TCP/UDP
result above was re-proven a second time in this document's next
correction pass against a DIFFERENT, race-clean `sing-tun` dependency —
see the dedicated "sing-tun concurrency/race resolution" section
immediately below, which supersedes which exact dependency/commit these
numbers were measured against.** It does NOT prove anything about
Android's `VpnService` specifically (SELinux labeling,
`ParcelFileDescriptor.dup()`/`detachFd()`'s exact behavior on a real
device, the app-process/VPN-exclusion interaction B33's own findings
already show matters for OTHER transports' diagnostic probes, JNI/native
packaging correctness, or battery/idle behavior) — those remain
physical-device unknowns for B46-2P, named explicitly below, not silently
assumed proven by this host-side result.

## 10.5. sing-tun concurrency/race resolution (dedicated section, third correction pass)

**What race was found.** Section 10's race-enabled (`go build -race`) run
of this proof's TCP path, built against
`github.com/apernet/sing-tun@v0.2.6-0.20250920121535-299f04629986` (the
exact version Hysteria2 itself vendors, Section 3), surfaced 3 real data-race
warnings, all inside that dependency's own `stack_system_nat.go`
`TCPNat.LookupBack`:

```go
func (n *TCPNat) LookupBack(port uint16) *TCPSession {
    n.portAccess.RLock()
    session := n.portMap[port]
    n.portAccess.RUnlock()
    if session != nil {
        session.LastActive = time.Now() // written OUTSIDE the lock
    }
    return session
}
```

`session.LastActive` is written here after `portAccess.RUnlock()` — a real,
unsynchronized concurrent write, racing against `checkTimeout`'s own read
of the same field elsewhere in the same file, and against concurrent
`LookupBack` calls from different goroutines (this proof's own TCP flow
triggered exactly this: `acceptLoop`'s goroutine and `processIPv4TCP`'s
reverse-NAT check on the tun-read goroutine, both touching the same
`*TCPSession`).

**Exact affected version**: `github.com/apernet/sing-tun` commit
`299f04629986` (pseudo-version `v0.2.6-0.20250920121535-299f04629986`) —
the exact commit Hysteria2's own `app/v2.12.3` pins (Section 3). Verified
directly by re-reading `stack_system_nat.go` from that exact clone, not
inferred.

**Why it matters.** This is a data race on a mutable field of a value
reachable from more than one goroutine with no exclusive lock protecting
the write — real, undefined-behavior-eligible under the Go memory model
(a torn or stale read of `LastActive` is possible on some architectures),
not a benign "logically fine, technically racy" case. The field only drives
idle-timeout eviction (never anything that reaches the wire), so this
proof's own functional TCP/UDP result was unaffected in practice — but
"the race never caused a visible symptom in one test run" is not the same
claim as "the race is safe," and the review that triggered this pass
correctly declined to accept the former as sufficient.

**Whether current upstream fixes it.** Yes, independently verified by
cloning `github.com/SagerNet/sing-tun` fresh at commit
`fbc0c3dff312e91f512756ad843af74dd209577c` (current `dev` HEAD as of this
pass, dated 2026-09-17) and reading its `stack_system_nat.go` directly:
`TCPSession` now embeds `sync.Mutex`, `LookupBack` calls a synchronized
`session.refresh()` (`s.Lock(); ...; s.Unlock()`), and `checkTimeout` also
locks each session before reading `LastActive`. This is a structural fix
(per-session locking), not a narrower band-aid — the same shape this
section's own R1 patch design (below) would have had to introduce by hand.

**Two remediation paths were compared, per the task's explicit requirement
to evaluate both rather than jump to the more convenient one:**

**Option R1 — patch the pinned apernet fork.** The minimal correct patch
(designed, NOT implemented, since R2 below was selected) would add a
`sync.Mutex` to the fork's own (structurally older, non-keyed-by-struct)
`TCPSession`, guard the `LastActive` write inside `LookupBack` under that
lock, and guard `checkTimeout`'s read the same way — a narrow, ~15-line
diff mirroring the shape SagerNet's own fix already takes, adapted to the
older `addrMap[netip.AddrPort]uint16` (not `tcpNatKey`) shape this specific
fork commit still uses. Consumption would require ONE of: a Nova-owned
fork (a real git fork, pinned by commit, never a floating branch) referenced
via a Go module `replace` directive, or a vendored local copy — either way,
a genuinely Nova-owned artifact requiring manual re-application across any
future rebase onto a newer `apernet/sing-tun` release. **Advantages**: the
exact same API surface this document's Section 8/9/13 designs were already
proven against; the exact version Hysteria2 itself currently vendors,
avoiding any version-skew question. **Costs**: Nova would own a patch/fork
with an ongoing maintenance burden (track and re-apply across every future
apernet release, exactly the fork-maintenance cost Option B was passed over
for in Section 6 — the irony of avoiding a Hysteria2-side fork while
accepting a `sing-tun`-side one was not lost on this review); the apernet
fork's own commit cadence appears materially slower than SagerNet's current
`dev` branch (a data point, not a value judgment, but relevant to how
quickly a NEXT defect would be found/fixed upstream vs. requiring another
Nova-side patch).

**Option R2 — port the proof to current `SagerNet/sing-tun`, pinned to a
specific commit — SELECTED, implemented, and verified.** Audited directly
against `fbc0c3dff312e91f512756ad843af74dd209577c`:

- `Options.FileDescriptor` — present, unchanged in effect: `tun.New`
  (`tun_linux.go`) still skips its own device-open path entirely when set,
  confirmed by re-reading the function (identical branch shape to the
  apernet fork, Section 4).
- **`EXP_ExternalConfiguration`** (new, not present in the apernet fork) —
  a real, first-class `Options` field (used in this exact commit's own
  integration test) meaning "an external owner already configured this
  TUN's address/route," gating `NativeTun.Close()`'s route/address-teardown
  logic and equivalent logic on darwin/windows. This is a MATERIALLY better
  fit for Android's `VpnService.Builder` ownership model (which already
  owns address/route configuration) than anything the apernet fork exposed
  — the proof sets it explicitly (`EXP_ExternalConfiguration: true`).
- **Android-specific awareness** (new): `tun_linux.go`'s own `init()`
  detects `/dev/tun` as an `androidTunPath` distinct from the standard
  `/dev/net/tun` — evidence of real, existing Android consideration in this
  codebase that the apernet fork's corresponding code does not have.
- **Handler interface changed materially, verified directly**:
  `NewConnection(...)  error`/`NewPacketConnection(...) error` are now
  `// Deprecated`, replaced by `NewConnectionEx(ctx, conn, source,
  destination M.Socksaddr, onClose N.CloseHandlerFunc)`/
  `NewPacketConnectionEx(...)` — both `void`, invoked by the caller in
  their OWN goroutine, with an `onClose` callback replacing the old
  force-close-after-return contract this document's Section 9 previously
  had to document as a non-obvious gotcha. **This gotcha no longer exists**
  in the current API — verified by reading `acceptLoop`/`UDPNat`'s own
  caller code directly: neither calls `Close()`/`SetLinger(0)` on the
  handler's behalf anymore. A genuine simplification, not just a rename.
  `Handler` also gained `JudgeFlow`/`NewDNSPacket` (flow-admission/DNS-hook
  methods this proof implements minimally — `ActionAccept`/no-op
  respectively — since neither capability is exercised by this proof's
  scope).
- **A second, separate non-obvious API fact found by actually exercising
  the write-back path** (not by reading the interface alone):
  `systemUDPPacketWriter4.WritePacket` now calls `buffer.ExtendHeader()` IN
  PLACE on the CALLER's own buffer (the apernet fork instead allocated its
  own internal buffer and copied the caller's payload in) — a caller must
  pre-reserve front headroom before writing its payload, or the call
  panics (`buffer overflow: capacity 16384, start 0, need 28` — reproduced
  directly by this pass, then fixed by reserving 128 bytes of headroom via
  `buf.NewSize`/`Buffer.Resize` before writing the UDP echo response).
  Nothing in the returned `N.PacketConn` (`*UDPNatConn`, verified by
  reading `udp_nat.go`) exposes a queryable `FrontHeadroom()` — the fixed
  128-byte reservation is a documented, generous-but-not-provably-exact
  choice for this proof, not a value read from an API-advertised minimum.
- **Dependency surface, factually larger, and honestly assessed**: current
  SagerNet `sing-tun`'s own `go.mod` additionally requires
  `sagernet/gvisor`, `sagernet/nftables`, `mdlayher/netlink`,
  `florianl/go-nfqueue/v2`, and `sagernet/fswatch` — none of which the
  apernet fork's `go.mod` needs. Read directly: the gVisor-backed stack is
  gated behind a `with_gvisor` build tag (NOT compiled by default, and not
  used by this proof, which passes `"system"` to `NewStack`), and the
  nftables/nfqueue-backed redirect code is gated behind `//go:build linux`
  — which does NOT match `GOOS=android` (Go treats `android` and `linux` as
  distinct GOOS identifiers), so an ANDROID BUILD of this dependency does
  NOT compile that code in at all. A `GOOS=linux` build (e.g. this proof
  itself, run on this host) DOES compile the linux-tagged files as part of
  the same package, which is a real, larger LOCAL build/compile surface for
  host-side testing, but does not translate into a larger ANDROID artifact
  — confirmed empirically (below) by successfully producing a real
  `GOOS=android GOARCH=arm64` binary with `CGO_ENABLED=0` and no NDK.

**Race-test result for R2 (the selected path)**: this proof, rebuilt
against `github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`
(resolved pseudo-version `v0.9.4-0.20260917142847-fbc0c3dff312`, pinned
exactly in `go.mod`/`go.sum`, never a floating `dev` dependency), produced
the SAME TCP round-trip and FULL UDP round-trip results as Section 10's
original run — and under `go build -race`, run TWICE: **zero race reports,
both times**. `go vet ./...` is also clean.

**Final selected remediation: R2.** No Nova-owned patch/fork is required.
The bridge's pinned dependency is now
**`github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`**
— an independent, justified, exactly-pinned version choice from whatever
Hysteria2 itself vendors (Section 13's in-process/child-process boundary is
exactly what makes this safe: the bridge and Hysteria2 never share a
process, so they were never required to share a dependency version either).
Chosen over R1 because: concurrency correctness is fixed UPSTREAM (not by a
Nova-owned patch Nova would have to rebase forever); SagerNet's `dev`
branch shows materially more active development including real
Android-specific code (`androidTunPath`, `EXP_ExternalConfiguration`) the
apernet fork lacks; the API migration cost (Handler interface, buffer
headroom semantics) was real but was paid ONCE, in this pass, and is now
fully documented; and the larger dependency graph does not translate into a
larger Android build artifact (confirmed, not assumed) because of Go's own
build-tag exclusion for the linux-only/`with_gvisor`-gated code paths.

**Android build feasibility — corrected scope (fourth correction pass).**
An earlier pass of this document ran `GOOS=android GOARCH=arm64
CGO_ENABLED=0 go build` on the proof program and presented the resulting
executable as evidence "for the bridge's own eventual `gomobile bind`
packaging." **That conflated two different things: it proves the Go code
can cross-compile to `android/arm64` as a standalone EXECUTABLE — it does
NOT prove the actual selected architecture's real boundary
(`Kotlin/VpnService -> JNI/gomobile -> in-process Go bridge`).** No
`gomobile bind`, Android AAR, or JNI shared library was actually built in
that pass. This is corrected in the dedicated "in-process JNI/AAR binding"
section below, which reports what WAS actually built and proven for the
real boundary — a materially stronger and narrower-scoped result than the
executable cross-build alone ever established.

## 10.6. sing-tun / bridge-dependency licensing audit (fourth correction pass — load-bearing)

**A direct review of PR #89 checked the actual `LICENSE` files of both
`sing-tun` forks this document discusses, rather than trusting the earlier
passes' unverified "MIT" claims. Both are wrong as previously stated.**

**Verified directly, this pass, by reading the files themselves:**

- `github.com/apernet/sing-tun` (Hysteria2's own pin, commit
  `299f04629986`) — `LICENSE` file: **GNU General Public License, version
  3, "or (at your option) any later version"** (GPL-3.0-or-later),
  copyright "nekohasekai". NOT MIT.
- `github.com/sagernet/sing-tun` (the Nova bridge's own pin, commit
  `fbc0c3dff312e91f512756ad843af74dd209577c`) — identical `LICENSE` file
  text, same GPL-3.0-or-later, same copyright holder. NOT MIT. (Unsurprising
  once found: the `apernet` repository is a fork of `SagerNet/sing-tun`,
  and evidently kept the same `LICENSE` file verbatim across the fork.)

**Root cause of the earlier error, stated plainly**: earlier passes of this
document read Hysteria2's own top-level `LICENSE.md` (genuinely MIT,
"Copyright 2023 Toby") and incorrectly attributed that license to the
SEPARATE `sing-tun` Go module Hysteria2 depends on, without opening
`sing-tun`'s own `LICENSE` file. This was a real documentation error, not a
minor imprecision — it materially misstated the licensing architecture this
whole design rests on, and is corrected here in full rather than patched
inline.

### VPNrus repository license state (verified directly)

The Nova VPN (VPNrus) repository has **no root `LICENSE` file** (checked
directly: `ls`/`find` at the repository root return nothing matching
`LICENSE*`). This means:

- **Do NOT assume** the application is intentionally structured for
  GPL-compatible distribution.
- **Do NOT conclude** that in-process linking of GPL-3.0-or-later code into
  Nova's `VpnService` process is legally acceptable — that is a real,
  substantive question this engineering audit is not positioned to answer.
- **Do NOT conclude the opposite** either — that it is categorically
  impossible. Whether and how GPL-3.0 copyleft obligations apply to an
  Android app that dynamically loads a JNI `.so` built from GPL-3.0
  sources, versus one that merely bundles it as a separate executable, is a
  real question with real nuance (dynamic linking, "mere aggregation," the
  GPL's own "derivative work" boundary) that competent legal counsel, not
  an engineering pass, must resolve for Nova's specific distribution model.
- This is recorded as an **explicit product-licensing gap requiring an
  owner decision**, not resolved, not worked around, and not defaulted in
  either direction by this pass.

### Why the in-process boundary makes this MORE material, not less

Section 13 pinned the Nova bridge to run **in-process, via JNI**, inside
the same `VpnService` process/APK component Nova ships. This is a
materially different distribution shape from shipping Hysteria2 as an
independent child-process executable communicating over a socket — the
in-process bridge's compiled code (a `.so` built from GPL-3.0-or-later
Go source, confirmed in the next section to actually link `sing-tun`
symbols) is loaded directly into, and executes within, the same process
Nova's own application code runs in. This is exactly the shape of
integration GPL-3.0's copyleft terms are most commonly read to reach most
strongly (as opposed to separate executables communicating via IPC, which
is the shape Hysteria2's own child-process relationship already has, and
where GPL's reach is more commonly argued to be weaker, though still not
uncontested). **This document does not resolve that legal question** — it
states the fact (in-process linking of GPL-3.0-or-later code is the
current selected shape) so the owner's licensing decision is made with the
right architectural fact in hand, not a wrong one.

## 10.7. In-process JNI/AAR binding — actually built and verified (not merely argued)

**Corrects the earlier pass's overstated Android-build claim (Section
10.5's own correction note above).** This pass built and verified the
REAL boundary: `Kotlin/VpnService -> JNI (gomobile-produced .aar) ->
in-process Go bridge (linking `sagernet/sing-tun`)`.

**Toolchain required, stated accurately**: `gomobile bind` requires a real
Android SDK (platform + build-tools, for `aapt`/Java stub generation) AND
an Android NDK (for the native `.so` cross-compile) — NOT merely a Go
toolchain. Neither was present in this environment at the start of this
pass (confirmed: `gomobile bind` failed immediately with `could not locate
Android SDK`). Both were installed for this pass specifically to produce
real evidence rather than assume the result: Android commandline-tools
(`commandlinetools-linux-11076708`), platform `android-34`, build-tools
`34.0.0`, and NDK `26.1.10909125` — all via Google's own `sdkmanager`,
standard, publicly documented components, not an unofficial mirror.

**A minimal gomobile-safe wrapper package was written** (`bridge.go`, not
committed to the repository — this was a throwaway feasibility check, per
the task's own "do not implement the full Android bridge yet" scope),
exposing ONLY primitive-typed functions across the boundary
(`StartBridge(fd int, mtu int, inet4Address string) (handle int, err
error)`, `StopBridge(handle int) error`) — no `sing-tun` type (`Options`,
`Handler`, `Stack`, etc.) crosses the exported surface directly, per the
review's explicit requirement, since gomobile cannot export Go interfaces
with unexported methods or arbitrary structs across the Java boundary.
Internally, `StartBridge` DOES construct real `sing-tun` objects
(`tun.Options`, `tun.New`, `tun.NewStack("system", ...)`) — proving
gomobile can bind a package that genuinely depends on `sing-tun`, not
merely an empty stub that would prove nothing about the real dependency.

**Result, run twice for different scope, both real successes**:

1. Empty-stub wrapper (no `sing-tun` import): `gomobile bind -androidapi 26
   -target=android/arm64 -o bridge.aar ./bridge` succeeded, producing a
   real `.aar` (`AndroidManifest.xml`, `classes.jar`, `R.txt`,
   `jni/arm64-v8a/libgojni.so`).
2. The SAME wrapper, with `StartBridge` actually calling
   `sagernet/sing-tun`'s real `Options`/`New`/`NewStack` APIs internally:
   the SAME `gomobile bind` command succeeded again, producing a LARGER
   `.aar` (`libgojni.so` grew from ~2.7MB to ~8.8MB, consistent with
   `sing-tun`'s own weight). **Verified objectively, not assumed**: `go tool
   nm` on the extracted `jni/arm64-v8a/libgojni.so` finds **1,344 symbols**
   from `sagernet/sing-tun` actually linked into this real, JNI-loadable,
   `ARM aarch64` shared object targeting API 26 — the exact library Nova's
   `VpnService` process would `System.loadLibrary()` in this architecture.

**This is a real, verified, in-process JNI/AAR artifact — not a claim
inferred from the earlier executable cross-build.** It directly answers
the review's requirement ("prove actual in-process Android binding
feasibility, not merely an Android executable build") with actual
evidence rather than a narrower proxy. It does NOT prove: production
packaging correctness (ProGuard/R8 interaction, `useLegacyPackaging`
behavior for this specific `.so`, physical-device loading), a real
`StartBridge`/`StopBridge` implementation with correct fd-ownership/error
handling wired to the real `dup()`/`detachFd()` model (this wrapper is a
feasibility stub, not the real bridge), or anything about the licensing
question the previous section raises — a technically successful build
does not resolve whether shipping it is a licensing decision Nova is
ready to make.

## 10.8. Hysteria2 child-binary dependency/license audit

**A separate, real question from the Nova bridge's own dependency**:
does the actual Hysteria2 client EXECUTABLE Nova intends to package (as a
separate child process, Section 13) itself contain the GPL-3.0-or-later
`apernet/sing-tun` code, given that `app/cmd/client.go` imports
`internal/tun`, which imports `apernet/sing-tun` (Section 4)?

**Verified with objective binary evidence, not assumed from `go.mod`
alone**, per the review's explicit instruction: the actual pinned
Hysteria2 `app/v2.12.3` client binary (commit
`e1366b173ccf5706e1e4630fe8aa654a4b574085`) was built fresh in this pass
(host build, for evidence purposes — not the Android cross-build), and
`go tool nm` was run against the real resulting executable:

```
$ go tool nm hysteria | grep -c "apernet/sing-tun"
125
```

**125 real symbols from `apernet/sing-tun`** (`NativeTun.Close`,
`.BatchRead`, `.BatchWrite`, `.Read`, `.Write`, etc.) are objectively
present, statically linked, in the actual compiled `hysteria` client
binary. This is not merely "listed in `go.mod`" — these are functions the
Go linker determined are REACHABLE from `main()` and therefore compiled
into the final executable.

**Why this is reachable regardless of runtime configuration, verified by
reading the call graph, not assumed**: `app/cmd/client.go`'s `runClient`
dispatches to `clientTUN(...)` via a plain runtime `if config.TUN != nil`
branch (line 917/1152 of that file) — there is NO build tag gating this
import or this function. Go's linker performs dead-code elimination based
on whether a function is reachable from `main` through the STATIC call
graph, not on whether a particular config value is ever set at runtime —
`clientTUN` is reachable (it is called from a function `main` itself
transitively reaches via cobra command wiring) regardless of whether any
real deployment ever configures `tun:` in its YAML. **This means Nova's
planned Hysteria2 child-process binary, exactly as it would ship (running
only the SOCKS5 listener, never enabling the `tun:` config block), still
contains linked GPL-3.0-or-later object code from `apernet/sing-tun`.**

**Whether a Hysteria2 build limited to Nova's actual needs (SOCKS5/QUIC
only) can exclude `sing-tun` — investigated, not assumed**: no existing
build tag, compile-time flag, or `//go:build` constraint in the current
`app/v2.12.3` source excludes `internal/tun`'s import (confirmed: `grep -rl
"go:build" cmd/*.go internal/tun/*.go` finds only IPv6-check platform
files, nothing gating the tun import itself). **The only way to produce a
Hysteria2 binary without `sing-tun` linked in would be a SOURCE
modification to Hysteria2 itself** (removing or build-tag-gating the
`clientTUN`/`internal/tun` import) — which this task explicitly scopes out
("Do not modify Hysteria yet. This is an audit only."). This is recorded
as a finding for a future slice to act on if Nova wants a `sing-tun`-free
Hysteria2 binary, not attempted here.

**Consequence, stated within engineering scope, not as a legal
conclusion**: the Hysteria2 executable Nova intends to bundle as a child
process has its own, separate source-distribution obligations arising from
the GPL-3.0-or-later code linked into it — this is true independent of
anything about Nova's own bridge design, and independent of whether
bundling a separate GPL-licensed executable as a child process (rather
than linking it in-process) carries different copyleft implications for
Nova's own application than the in-process bridge case does. **This
document does NOT conclude that these obligations extend to, or exclude,
the rest of the Nova Android app merely because the executable runs as a
separate child process** — that determination requires the same competent
legal review as the in-process case, and is out of scope for this
engineering audit.

**`FORMAL LICENSE/LEGAL REVIEW REQUIRED BEFORE RELEASE`** — recorded here
explicitly, covering BOTH the in-process Nova bridge (Section 10.6) and
the separate Hysteria2 child-process executable (this section), as two
related but distinct questions the same review should address.

## 10.9. Option L2 audit — `heiher/hev-socks5-tunnel` (MIT, purpose-built TUN→SOCKS5)

Given the licensing finding above, this pass performed the deep audit of
`heiher/hev-socks5-tunnel` the earlier pass's Option C comparison only
sketched structurally. Cloned fresh, submodules initialized
(`git submodule update --init --recursive`), all facts below verified from
source/build, not from README claims alone.

| Fact | Value |
|---|---|
| Exact current commit | `21a784a6702e5f1b1b87c63c38a314234d956e55`, dated 2026-09-17 — titled "Build: Bundle Java JNI binding into android AAR (#331)", i.e. upstream added Android AAR/JNI packaging within the last day of this audit. |
| License | MIT (`LICENSE`, read directly — "Copyright (c) 2022 hev"). All four git submodules this project depends on (`hev-task-system`, `yaml`, `lwip` fork, `hev-socks5-core`) were cloned and checked independently: `hev-task-system`/`yaml`/`hev-socks5-core` are MIT (same "Copyright (c) 2022 hev" text); `lwip` (heiher's fork) is BSD-style ("Copyright (c) 2001, 2002 Swedish Institute of Computer Science"). **No GPL code anywhere in this dependency's tree**, verified, not assumed. |
| External Android TUN-fd support | **Real, first-class, verified at the source level** — `src/hev-jni.c` registers `hev.htproxy.TProxyService.TProxyStartService(String config_path, int fd)` as a JNI native (confirmed: `android/hev/htproxy/TProxyService.java`, shipped inside the project itself); the SAME underlying `hev_socks5_tunnel_main(config_path, tun_fd)` C entry point is used by both the JNI path and (with `tun_fd=-1`, meaning "open my own") the CLI binary. |
| **Fd ownership semantics — read directly, exactly matching this design's own requirement** | `src/hev-socks5-tunnel.c`'s `tunnel_init(extern_tun_fd)`: `if (extern_tun_fd >= 0) { ...; tun_fd = extern_tun_fd; return 0; }` — sets only `O_NONBLOCK` via `ioctl(fd, FIONBIO, ...)` and otherwise touches nothing else; `tun_fd_local` (the flag controlling whether `tunnel_fini()` ever calls `close()` on the fd) is left `0` in this branch. `tunnel_fini()`'s own guard, read directly: `if (!tun_fd_local) return;` — **an externally-supplied fd is never closed by this library**, by construction, with no Nova-side ownership-split engineering required (unlike `sing-tun`, where Section 8's `dup()`/`detachFd()` design was necessary specifically because `sing-tun`'s own `Close()` DOES close whatever fd it is given). This is a materially SIMPLER, more conservative ownership contract than either `sing-tun` fork's. |
| TCP support | Yes — `hev-socks5-client-tcp.c`/`hev-socks5-session-tcp.c`, real SOCKS5 CONNECT client logic against the configured upstream. |
| UDP support | Yes, and explicitly configurable — `conf/main.yml`'s `socks5.udp: 'udp'|'tcp'` selects SOCKS5 UDP-ASSOCIATE-over-UDP or the (RFC-nonstandard but some servers require it) UDP-over-TCP relay mode; `hev-socks5-client-udp.c`/`hev-socks5-session-udp.c` implement it. Not exercised end-to-end in this pass (see "known unknowns" below) but the source-level implementation is real, not aspirational. |
| IPv4/IPv6 | Both, per `conf/main.yml`'s `tunnel.ipv4`/`tunnel.ipv6` fields and `hev_tunnel_set_ipv4`/`hev_tunnel_set_ipv6` — a real dual-stack path, unlike this document's own Option A design (Section 12), which deliberately scopes to IPv4-only for its first physical spike. |
| Lifecycle | `hev_socks5_tunnel_init`/`hev_socks5_tunnel_run`/`hev_socks5_tunnel_stop`/`hev_socks5_tunnel_fini` — a plain, synchronous init/run/stop/fini shape, no hidden background threads outside its own cooperative task system (`hev-task-system`, a real coroutine-style scheduler, also audited above). |
| Android JNI/library build path | **Actually built in this pass, for real**: `ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk APP_ABI=arm64-v8a APP_PLATFORM=android-26` (the SAME NDK installed for the gomobile check above) succeeded cleanly, producing a real `libhev-socks5-tunnel.so` (`ELF 64-bit LSB shared object, ARM aarch64`, confirmed via `file`, with a real exported `JNI_OnLoad` symbol confirmed via `nm -D`). |
| arm64 buildability | Confirmed directly (above) — real NDK build, real `.so`, no patch needed. |
| Thread/concurrency model | Cooperative task-based (`hev-task-system`, the same author's own coroutine library, MIT, audited above) — not raw OS-thread-per-connection; not independently race-tested in this pass (no `-race`-equivalent tool exists for C the way `go build -race` does for Go; a real audit would need a C sanitizer build, e.g. ThreadSanitizer, not attempted here — a known unknown, see below). |
| Also built and confirmed on this host, for context | The plain Linux daemon build (`make`, no NDK) also succeeded cleanly, producing a real `hev-socks5-tunnel` executable — useful for a future host-side round-trip proof (see "known unknowns"), though the CLI binary's own `main()` hardcodes `tun_fd=-1` (always opens its own device by name) — reaching the external-fd path on a host requires calling the library's C API directly (`hev_socks5_tunnel_main(config, fd)`), not the CLI binary as shipped. |

**Superseded by Section 10.10 below**: a following pass DID complete a real
host-side proof attempt with a custom C harness calling
`hev_socks5_tunnel_main` directly — and found two confirmed, reproducible
crash defects in HEV's own error-handling paths, which is why HEV is NOT
selected. The source-level evidence in the table above (external-fd
semantics, non-owning close behavior, real native build success, clean MIT
tree) remains accurate and stands; it does not extend to "safe to run,"
which the next section addresses directly with real, negative evidence.

## 10.10. HEV final bridge proof (fifth correction pass) — two confirmed crash defects found; HEV NOT selected

**A real host-side data-plane proof, structurally equivalent to Section
10's `sing-tun` proof, was attempted**: a genuine external TUN fd (opened
and configured exactly as in Section 10, then `dup()`'d per this design's
ownership model), a REAL third-party SOCKS5 server (`danted` 1.4.3, a
mature, independently-developed SOCKS4/5 daemon — not a hand-rolled stand-in
— installed via the distribution's own package manager) standing in for
Hysteria2's own SOCKS5 listener, and real TCP/UDP echo targets reachable
only through it. **Before wiring up HEV, the SOCKS5 leg itself was verified
independently and directly** (a raw Python SOCKS5 client): a real SOCKS5
CONNECT round trip and a real SOCKS5 UDP-ASSOCIATE round trip both worked
byte-exact against the echo targets — proving the test harness's SOCKS5
server leg is genuine and correctly configured before any HEV code is
involved.

**A C test harness was written** (`hev_proof.c`, throwaway scratch, not
committed) implementing the required cycle shape: `start -> TCP+UDP proof
-> stop -> start again -> TCP+UDP proof -> stop`, plus dedicated failure-
path cycles (invalid fd, SOCKS5 listener absent), calling
`hev_socks5_tunnel_main(config_path, dup_fd)` in a `pthread` and
`hev_socks5_tunnel_quit()` to stop it — the exact public API shape the
task asked to prove (`start(fd, ...)`/`stop()`).

**Two independent, reproducible crashes were found, confirmed via `gdb`
backtraces into HEV's own library code (never into this harness's own
code):**

1. **Invalid external TUN fd crashes the calling process.** Per Section
   10.9's own fd-ownership table, `tunnel_init(extern_tun_fd)` is documented
   (by this pass's own prior reading) to fail cleanly (`return -1`) when
   `ioctl(fd, FIONBIO, ...)` fails on a bad fd. **Verified this is NOT what
   actually happens**: calling `hev_socks5_tunnel_main(config, 9999)` (an
   unopened, invalid fd) produces `double free or corruption (out)` and a
   `SIGABRT`, confirmed via `gdb bt`:
   ```
   #6  malloc_printerr (str="double free or corruption (out)")
   #7  _int_free_merge_chunk
   #9  __libc_free
   #10 hev_task_system_fini ()  <-- from libhev-task-system.so
   #11 hev_socks5_tunnel_main_inner ()  <-- from libhev-socks5-tunnel.so
   ```
   Root cause, at the level this pass could confirm without a full upstream
   bug-hunt: `hev_task_system_fini()` is called on a task system that was
   `hev_task_system_init()`'d but never `hev_task_system_run()`'d (because
   `hev_socks5_tunnel_init()` failed before reaching `hev_task_system_run`)
   — a state HEV's own cleanup path does not handle safely. **This directly
   fails the task's own explicit requirement for the invalid-fd failure
   path: "No crash of the host proof process."**
2. **A real SOCKS5-client outbound-socket failure also crashes the
   process**, via a genuinely different code path: this host sandbox's
   kernel has NO IPv6 support at all (confirmed: no `/proc/net/if_inet6`,
   `socket(AF_INET6, ...)` itself fails with `EAFNOSUPPORT` at the kernel
   level, no `modprobe` even available to load an ipv6 module). HEV's own
   `hev_socks5_socket()` (`core/src/hev-socks5-misc.c`) unconditionally
   creates an `AF_INET6` socket (with `IPV6_V6ONLY=0`, a standard
   dual-stack pattern) for EVERY outbound SOCKS5 connection, including pure
   IPv4 targets — there is no config option to force IPv4-only sockets.
   When that `socket()` call fails, `hev_socks5_client_connect` logs
   `"socks5 client socket"` and returns -1 — but the resulting cleanup
   crashes with `munmap_chunk(): invalid pointer`, confirmed via `gdb bt`
   pointing into `hev_task_executer()` (HEV's own coroutine-stack cleanup)
   in `libhev-task-system.so`, freeing what appears to be task stack
   memory incorrectly. This reproduced identically in BOTH a plain build
   and an ASan/UBSan-instrumented build (ASan itself additionally warned
   `"ignoring requested __asan_handle_no_return"` — a known, documented
   ASan limitation for hand-written coroutine stack-switching code that
   never calls ASan's fiber-switch annotation API, meaning ASan cannot be
   trusted for a clean verdict on this codebase without upstream adding
   those annotations; but the PLAIN, non-instrumented build crashing
   identically proves this is a REAL bug, not an ASan false positive).

**Assessment, stated precisely**: defect (2)'s trigger (a kernel with zero
IPv6 support) is very unlikely to occur on real Android hardware — Android
devices are effectively guaranteed to support `AF_INET6` socket creation
regardless of actual network IPv6 reachability. But the SAME crash class
this trigger exposes (an unhandled early-failure path inside HEV's task-
system/coroutine cleanup) is exactly what defect (1) ALSO exposes, via a
completely different, Android-realistic trigger (an invalid fd — plausible
from an ownership bug, a race, or a caller error) with no dependency on the
IPv6 quirk at all. Two independent triggers landing in the same class of
unhandled-early-failure crash is a meaningfully stronger signal than either
alone: **this reads as a real, load-bearing gap in HEV's error-handling
robustness around early startup failure, not an artifact of this one
sandbox.** An in-process JNI bridge that crashes the whole host process
(Nova's own `VpnService`, since Section 10.7 already proved this pattern
of dependency links in-process) on a plausible, Android-realistic failure
input is a genuine, serious concern — more serious than "the round-trip
proof wasn't completed," because it is now KNOWN to fail unsafely rather
than merely unverified.

**Per the task's own decision framework** ("If HEV fails TCP/UDP/lifecycle
requirements: keep sing-tun as technically-proven candidate... Do not force
HEV selection merely because it is MIT"): **HEV is NOT selected.** The
full `start -> proof -> stop -> restart -> proof -> stop` cycle and the
live TCP/UDP round-trip proof could not be safely completed, because the
harness's own required failure-path test (invalid fd) already crashes the
host process before any of the success-path cycles can be trusted to run
without risking the same class of corruption. This is recorded as a
concrete, evidence-based "fails," not a time-boxed "not yet proven."

**What remains true and unaffected by this finding**: `heiher/hev-socks5-tunnel`'s
license (MIT, clean tree), its documented fd-ownership semantics (as
literally read from source in Section 10.9), and its real Android AAR/JNI
build success (this section's own build below) are all still accurate,
independently-verified facts — this finding is specifically about runtime
crash-safety on early-failure paths, not about licensing or static build
feasibility. A future re-audit, after upstream fixes are confirmed (or
after re-testing on a normal IPv6-capable host to isolate whether defect
(1) alone — the more Android-realistic one — is fixed), could revisit this
verdict; this pass does not foreclose that.

**Android AAR/JNI artifact — built successfully, using upstream's own
official CI recipe, not an ad hoc guess**: `.github/workflows/build.yaml`'s
own `android` job (read directly) does exactly:
`ndk-build APP_MODULES=hev-socks5-tunnel` (the module containing
`hev-jni.c`, distinct from the `hev-socks5-tunnel-bin` CLI module) then
packages `libhev-socks5-tunnel.so` + a `javac`-compiled `classes.jar` (from
the project's own shipped `TProxyService.java`) + a manifest + proguard
rules into a zip. This exact recipe was reproduced in this pass (NDK
`26.1.10909125`, `APP_PLATFORM=android-26` — adapted from upstream's own
`android-29` to match Nova's actual `minSdk=26`, confirmed to build
cleanly at the lower API level too):

- `libhev-socks5-tunnel.so`: `ELF 64-bit LSB shared object, ARM aarch64`,
  stripped, exports `JNI_OnLoad` (`nm -D`), **SHA-256:
  `986f0e5e372a107efe5cea04b931b742de0e42deaea16839822df62b95cf83c6`**.
  `readelf -d` shows exactly three `NEEDED` entries: `libc.so`, `libm.so`,
  `libdl.so` — all Android system libraries, always present, no bundled
  dependency required. Fully self-contained.
- `hev-socks5-tunnel.aar` assembled per the exact upstream recipe:
  `classes.jar` (987 bytes, compiled from the unmodified
  `android/hev/htproxy/TProxyService.java`), `proguard.txt`,
  `AndroidManifest.xml` (`minSdkVersion=26`), `jni/arm64-v8a/libhev-socks5-tunnel.so`
  — **SHA-256 of the assembled AAR:
  `17ca3cbb4c2e58d34d95943153a5f34b8e4cdb4778cf430799103f6a10da7aaf`**
  (this pass's own build; will not match upstream's official release
  artifact byte-for-byte, since upstream targets `minSdkVersion=29` and a
  newer NDK r27d — the SAME kind of non-byte-identical-but-structurally-
  equivalent result B46-2A already documented for the Hysteria2 binary
  itself).
- Neither artifact is committed to this repository (matching every prior
  pass's own binary-provenance discipline) — hashes/metadata recorded here,
  binaries discarded after inspection.

This confirms the JNI/native-library BUILD path for HEV is real and
credible — the crash findings above are about RUNTIME behavior on specific
inputs, not about whether the artifact can be produced.

## 10.11. Option L3 — `xjasonlyu/tun2socks` (secondary permissive fallback, re-confirmed only)

Per the task's own instruction ("do not implement a full proof unless L2
fails or evidence makes L3 clearly preferable"), L2's audit above did not
fail and no evidence surfaced making L3 clearly preferable — so L3 is
re-confirmed only at the level Section 6 already established (MIT, Go,
`gVisor`-based, real external-fd support via `core/device/fdbased.open(fd
int, ...)`, real TCP/UDP/IPv6 support, real Android usage precedent via
several GUI proxy clients) and not re-audited further or proven in this
pass. It remains the secondary MIT fallback if L2's own UDP/concurrency
unknowns (above) turn out to be blocking in a future pass.

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

**Correction pass (fourth pass): the bridge's own pinned `sing-tun` dependency
changed — see the dedicated "sing-tun concurrency/race resolution" section
above for the full remediation. The table below reflects the FINAL selected
dependency, not the superseded one.**

| Component | Detail |
|---|---|
| `github.com/sagernet/sing-tun` (Nova bridge's race-clean dependency choice — see the dedicated licensing-audit section for why this is NO LONGER unconditionally "selected") | Commit `fbc0c3dff312e91f512756ad843af74dd209577c` (resolved pseudo-version `v0.9.4-0.20260917142847-fbc0c3dff312`), pinned exactly in `go.mod`/`go.sum` — never a floating `dev` branch. **License, corrected in this pass: GNU General Public License v3 "or (at your option) any later version" (`LICENSE` file, read directly from a fresh clone) — NOT MIT**, a stale claim in an earlier pass of this document. Build toolchain: standard Go module resolution via the Go module proxy, content-addressed and immutable per version — no anonymous/unpinned binary download. This is an INDEPENDENT dependency choice from Hysteria2's own `apernet/sing-tun` pin (Section 3) — the process boundary means the two never need to share a build, but it does NOT mean the license question is avoided: an in-process JNI/AAR bridge genuinely links this GPL-3.0-or-later code into the same binary artifact loaded by Nova's `VpnService` process. |
| Larger transitive dependency surface than the superseded pin, stated honestly | `sagernet/gvisor`, `sagernet/nftables`, `mdlayher/netlink`, `florianl/go-nfqueue/v2`, `sagernet/fswatch` are now part of the module graph (none needed by the superseded `apernet` pin). Confirmed NOT to inflate the Android build artifact: the gVisor-backed stack is gated behind a `with_gvisor` build tag (not compiled by default, not used here), and the nftables/nfqueue redirect code is gated behind `//go:build linux`, which does not match `GOOS=android` — verified empirically by a successful `GOOS=android GOARCH=arm64 CGO_ENABLED=0` build. This is still a real, larger dependency GRAPH (more modules to track for CVEs/license changes) even where it doesn't inflate the compiled artifact — an honest, not-fully-eliminated cost of the R2 choice. |
| Hysteria2's OWN `sing-tun` pin (unchanged, untouched, a separate fact) | `github.com/apernet/sing-tun@v0.2.6-0.20250920121535-299f04629986` — still exactly what Hysteria2's own `app/go.mod` pins (Section 3); this pass does not patch, fork, or otherwise touch Hysteria2 or its dependencies, per the task's explicit scope freeze. |
| Update policy | Track `sagernet/sing-tun`'s own commit history directly (independent of both Hysteria2's release cadence AND the apernet fork's), re-verify `Options.FileDescriptor`/`EXP_ExternalConfiguration`/the `NewConnectionEx`/`NewPacketConnectionEx` contract against any future version bump before adopting it — this dependency's API has already been shown to move (Handler interface, buffer headroom semantics) between the version audited here and whatever version existed before it, so a future bump is not assumed compatible by default. |
| Reproducibility/provenance | The synthetic proof program (`research/b46-2b-hysteria-tun-bridge/singtun-proof/main.go`) is prototype/research code, explicitly excluded from any production build. No new binary artifact from this slice is committed to git (matching B45A/B46-2A precedent) — the proof was built and run locally in this session only, including the Android arm64 compile-check binary (discarded after inspection, not committed). |
| No custom cryptography | None introduced — the entire design routes all cryptographic work through Hysteria2's own existing QUIC/TLS stack, unchanged. |
| No unpinned dependency | The selected `sing-tun` commit is pinned exactly (a full commit-derived pseudo-version string, not a branch or `latest`), matching this repo's existing discipline for every other pinned binary/dependency. |
| **Data race in the superseded dependency — RESOLVED, not merely tracked** | The apernet fork's `TCPNat.LookupBack` race (Section 10/10.5) is no longer part of this design's dependency graph at all — Nova's bridge no longer depends on that code path. Not reported upstream to `apernet/sing-tun` in this pass (that fork is no longer Nova's own dependency, though still Hysteria2's — a report may still be worth filing for the ecosystem's sake, not required by this design). |

## 22. Synthetic test results (Phase 11) — summary

**Final result, against the SELECTED dependency
(`github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`
— see the dedicated race-resolution section above)**: real TCP round trip
through an externally-owned, PROPERLY-DUPLICATED TUN fd (never the
original), proven; a FULL real UDP round trip (not merely demux) through
the same duplicated fd, proven, with both the source/destination metadata
and the returned payload verified deterministically via channel
synchronization (never a sleep-and-hope pattern); three real,
previously-undocumented API-contract requirements discovered across this
document's revisions and now documented for B46-2P (the superseded
`apernet` fork's `NewConnection` had to relay synchronously or be RST'd —
no longer true on the selected dependency; `WritePacket`'s `destination`
argument must be the original virtual destination, not the source;
`WritePacket` on the selected dependency requires the caller to
pre-reserve front headroom on its own buffer or it panics). Re-run twice
(plain build) against the selected dependency, PLUS twice under the race
detector: **zero race reports both times** — a genuine improvement over
the superseded dependency, which reproducibly showed 3 race warnings under
the identical test. `go vet ./...` clean. A real `GOOS=android
GOARCH=arm64 CGO_ENABLED=0` build of the same program succeeded, no NDK, no
linkname workaround.

## 23. Known unknowns (explicit)

- **The product-licensing decision itself is the single largest known
  unknown** (Section 10.6) — whether Nova can/should ship GPL-3.0-or-later
  code (either `sing-tun` fork) in-process is an owner decision, not
  resolved by this pass and not something further engineering evidence
  alone can resolve.
- **`hev-socks5-tunnel`'s two confirmed crash defects (Section 10.10) have
  not been root-caused to the exact upstream source line, nor reported
  upstream** — this pass confirmed WHERE they crash (via `gdb` backtraces
  into HEV's own `hev_task_system_fini`/`hev_task_executer`) but not
  WHY at the level of a fixable upstream patch; a future pass or an
  upstream issue report would need that depth.
- **Whether defect (1) (invalid external fd) is reproducible outside this
  session's specific sandbox is unverified** — it did not depend on the
  IPv6 quirk that triggered defect (2), so it is plausibly a general HEV
  defect, but this was not independently re-confirmed on a second,
  differently-configured host or a physical Android device.
- **Full SOCKS5 UDP ASSOCIATE framing (the hop between the `sing-tun`
  bridge and Hysteria2's own SOCKS5 listener) was not implemented or
  tested** in this slice's proof — the proof's UDP round trip goes through
  a controlled local echo target standing in for that listener, not
  through a real Hysteria2 process. This is real, bounded, well-understood
  engineering (RFC 1928 Section 7) that a future bridge implementation must
  still do; it is not a research gap, but it is also not proven working
  against a real Hysteria2 SOCKS5 server yet. (`hev-socks5-tunnel` needs no
  equivalent work — it already speaks SOCKS5 CONNECT/UDP-ASSOCIATE
  natively, per Section 10.9.)
- **`ParcelFileDescriptor.dup()`+`detachFd()`'s exact behavior on a real
  Android device is unverified** — Section 8's ownership model is designed
  against Android's own documented API contract and validated on Linux via
  the equivalent `unix.Dup()` call, but no Android runtime was available in
  this environment to exercise the real API.
- **The real in-process JNI/AAR artifact (Section 10.7) is a feasibility
  stub, not the real bridge** — `StartBridge`/`StopBridge`'s actual
  fd-ownership/error-handling wiring to the real `dup()`/`detachFd()` model
  and to a real Handler implementation remains to be built; production
  packaging correctness (ProGuard/R8, `useLegacyPackaging` for this
  specific `.so`, physical-device loading) is untested.
- **`hev-socks5-tunnel`'s C code WAS built with ASan/UBSan (Section
  10.10), but the result is not fully trustworthy** — HEV's own coroutine
  stack-switching code (`hev-task-execute`) has no ASan fiber-switch
  annotations, so ASan itself warned it was "ignoring requested
  `__asan_handle_no_return`" and produced at least one likely-false-positive
  "bad-free" report distinct from the two REAL crashes (which reproduced
  identically in a plain, non-instrumented build). No ThreadSanitizer or
  Valgrind run was attempted — Valgrind was judged, given the two crashes
  already found by simpler means, not the best use of further time in this
  pass; a future pass revisiting HEV would benefit from it.
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
- **The superseded `apernet/sing-tun` fork's internal data race has not been
  reported upstream to `apernet`** in this pass — no longer Nova's own
  dependency (Section 21), so not required by this design, though still
  relevant to Hysteria2's own use of that fork.
- **The Nova bridge's now-larger transitive dependency graph
  (`sagernet/gvisor`/`nftables`/`netlink`/`go-nfqueue`) has not been
  independently vetted module-by-module** for license/CVE history in this
  pass — confirmed not to inflate the Android build artifact (Section
  21/10.5), but the graph itself is real and larger than the superseded
  dependency's.
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

**Corrected again in this pass — the previously-recommended `hev-socks5-tunnel`
round-trip proof was completed, and found disqualifying (Section 10.10).**
Two credible next steps remain, not mutually exclusive:

1. **A bounded follow-up investigating HEV's two confirmed crash defects**
   (Section 10.10): reproduce defect (1) (invalid external fd) on a normal
   IPv6-capable host or a physical Android device, to isolate it from
   defect (2)'s IPv6-specific trigger; check whether either is already
   fixed on HEV's current `main` branch by the time of that follow-up;
   and/or file the findings upstream. If defect (1) — the genuinely
   Android-realistic one — is confirmed fixed or was itself an artifact of
   this session's own harness (not yet ruled out with full confidence,
   though the `gdb` evidence points into HEV's own library code), HEV could
   be reconsidered as the MIT path with no Nova licensing decision needed.
2. **Only if the owner explicitly resolves the licensing question in favor
   of the GPL-3.0-or-later `sing-tun` path**: B46-2P proceeds as originally
   scoped (step 1 of Section 24 - TUN + bridge alone, no Hysteria2 yet),
   backed by the real, working host-side proof and the real in-process
   JNI/AAR artifact this pass already built (Sections 10.5/10.7).

Either way, Hysteria2's own child-process GPL question (Section 10.8) is a
separate, parallel item the same licensing review should cover before
release, regardless of which bridge path is chosen.

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

**Fourth correction (after the above five were already fixed): the pinned
`apernet/sing-tun` dependency had a real, reproducible internal data
race** (Section 10/10.5), found only because the race-enabled proof from
THIS pass's own fixes was actually run. Resolved by re-pinning the Nova
bridge's OWN `sing-tun` dependency (never Hysteria2's) to current
`github.com/sagernet/sing-tun@fbc0c3dff312e91f512756ad843af74dd209577c`,
which fixes the race structurally upstream — not by a Nova-owned patch.
Re-proven TCP+UDP round trip, race-clean under `go build -race`, run
twice.

**Fifth correction (a separate, direct license audit of PR #89): the
"MIT" license claimed for BOTH `sing-tun` forks throughout this document
was wrong.** Both `apernet/sing-tun` (Hysteria2's own pin) and
`sagernet/sing-tun` (the Nova bridge's own pin, selected in the fourth
correction) are **GPL-3.0-or-later** (Section 10.6, verified directly from
each `LICENSE` file). This is load-bearing, not cosmetic: the selected
architecture links this GPL-3.0-or-later code in-process into Nova's own
`VpnService` (Section 10.7 now proves this really happens — 1,344
`sing-tun` symbols confirmed linked into a real, working `gomobile
bind`-produced `.aar`'s native library), and Nova's own repository carries
no `LICENSE` file establishing a compatible distribution policy. This
changes the verdict below — a technical success is not the same claim as
"safe to ship," and this pass does not conflate the two.

**A separate MIT-licensed, purpose-built TUN→SOCKS5 alternative
(`heiher/hev-socks5-tunnel`, Section 10.9) was found and deeply audited —
and then a following pass completed the live proof this section originally
deferred, finding it disqualifying.** Real external-fd support with even
simpler, already-correct, non-owning close semantics than `sing-tun`
requires; a real native `.so` built successfully via the same NDK for
`arm64-v8a`/API 26; a clean, verified all-MIT/BSD dependency tree — all
still true. But the live TCP/UDP round-trip proof (Section 10.10) found
**two independent, reproducible crashes in HEV's own error-handling code**
(an invalid external fd, and a SOCKS5-client outbound-socket failure, both
confirmed via `gdb` backtraces into HEV's own library, not this session's
harness): a plausible, Android-realistic invalid-fd input crashes the
entire host process. Per this task's own explicit instruction not to force
HEV selection merely for being MIT, **`hev-socks5-tunnel` is NOT selected**
— it sidesteps the licensing question but does not yet meet the bar of "no
critical memory/lifecycle blocker."

**Separately, Hysteria2's own child-process binary (Section 10.8) was
verified, with objective `go tool nm` evidence, to contain 125 linked
symbols from GPL-3.0-or-later `apernet/sing-tun`, regardless of whether
Nova's deployment ever enables Hysteria2's own `tun:` config** — a second,
independent GPL question this pass surfaces but does not resolve, since it
concerns Hysteria2's own executable, not the Nova-authored bridge.

**B. TECHNICALLY READY — LICENSING DECISION REQUIRED.**

Not A, because a real, unresolved product-licensing gap exists and this
pass is correctly not the one to close it:

- The in-process `sing-tun`-based bridge (Option A / `NOVA_SING_TUN_ADAPTER`)
  is technically fully proven: TUN fd ownership is deterministic
  (`dup()`+`detachFd()`, Section 8, unaffected by any of the above), the
  external-fd path works, TCP round trip passes, UDP round trip passes, the
  race-enabled proof has ZERO races (Section 10.5), and a REAL in-process
  JNI/AAR artifact was built with `sing-tun` genuinely linked into it
  (Section 10.7 — not merely an executable cross-build, which was itself a
  claim this pass had to correct).
- **But its selected dependency (either `sing-tun` fork) is
  GPL-3.0-or-later, Nova's own repository license is unestablished, and no
  owner decision endorsing GPL-compatible in-process distribution has been
  made** (Section 10.6). Proceeding to real physical Android integration
  as a RELEASE architecture on this dependency, before that decision is
  made, would risk building real product surface on a licensing
  foundation nobody has actually approved.
- Hysteria2's own child-process binary carries a parallel, separate GPL
  question (Section 10.8) needing the same kind of review, independent of
  whatever is decided about the Nova bridge.
- A credible permissively-licensed alternative (`hev-socks5-tunnel`,
  Sections 10.9/10.10) was deeply investigated specifically to let a
  future slice reach verdict A without any Nova licensing-policy decision
  — but its live proof found two real, reproducible crash defects in its
  own error-handling paths (Section 10.10), so it is NOT selected this
  pass, not merely deferred.

**Do not proceed to B46-2P as a release-track physical integration on the
GPL-3.0-or-later `sing-tun` path until the repository owner has made an
explicit, informed licensing decision.** No crash-free, fully-proven
MIT-licensed alternative currently exists — `hev-socks5-tunnel` remains
the closest candidate but needs its two confirmed crash defects understood
and fixed (upstream, or independently re-verified as unreachable in a
normal environment) before it can be reconsidered. Until then, `sing-tun`
is the only technically-complete candidate, and it is licensing-gated.

## Sources cited (external)

- [apernet/hysteria repository](https://github.com/apernet/hysteria), tag
  `app/v2.12.3`, commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` — re-cloned
  fresh in this slice.
- [apernet/sing-tun repository](https://github.com/apernet/sing-tun),
  pseudo-version `v0.2.6-0.20250920121535-299f04629986` — the SUPERSEDED
  dependency this document's proof was originally built against; resolved
  and downloaded fresh via the Go module proxy;
  `tun.go`/`tun_linux.go`/`stack.go`/`stack_system.go`/`stack_system_nat.go`
  read directly from the populated module cache (the last one specifically
  to trace the data race Section 10.5 reports). Still Hysteria2's OWN
  dependency (Section 3), untouched by this pass.
- [SagerNet/sing-tun repository](https://github.com/SagerNet/sing-tun),
  commit `fbc0c3dff312e91f512756ad843af74dd209577c` — the SELECTED
  dependency (Section 10.5), cloned fresh (full clone, not shallow, to
  reach this specific historical commit) and separately `go get`-resolved
  into the proof's own module cache; `tun.go`/`tun_linux.go`/`stack.go`/
  `stack_system.go`/`stack_system_nat.go`/`udp_nat.go`/`flow.go`/`go.mod`
  read directly.
- [xjasonlyu/tun2socks repository](https://github.com/xjasonlyu/tun2socks) —
  cloned fresh in an earlier correction pass (Option C/L3 candidate,
  Section 6/10.10); `LICENSE`/`go.mod`/`core/device/fdbased/open_unix.go`
  read directly.
- [heiher/hev-socks5-tunnel repository](https://github.com/heiher/hev-socks5-tunnel),
  commit `21a784a6702e5f1b1b87c63c38a314234d956e55` — cloned fresh with
  submodules in this pass (Option L2, Section 10.9); `LICENSE`,
  `src/hev-socks5-tunnel.c`, `src/hev-jni.c`, `src/hev-main.c`,
  `android/hev/htproxy/TProxyService.java`, `conf/main.yml`, `Android.mk`,
  `Application.mk` read directly; its four submodules
  (`heiher/hev-task-system`, `heiher/yaml`, `heiher/lwip`,
  `heiher/hev-socks5-core`) each cloned and their own `LICENSE` files
  checked independently.
- `github.com/apernet/sing-tun`'s and `github.com/sagernet/sing-tun`'s own
  `LICENSE` files — read directly in this pass (both from the module
  caches/clones already used in earlier passes), the source of the
  license correction (Section 10.6).
- `golang.org/x/mobile` (`gomobile`) — used in this pass, per its own
  standard public toolchain, to build the real in-process JNI/AAR artifact
  (Section 10.7); Android SDK components (`platform-tools`,
  `platforms;android-34`, `build-tools;34.0.0`) and NDK `26.1.10909125`
  installed via Google's own `sdkmanager` specifically for this check.
- `heiher/hev-socks5-tunnel`'s own `.github/workflows/build.yaml` — read
  directly in the fourth correction pass to reproduce its official Android
  AAR build recipe exactly (Section 10.10).
- `dante-server` (`danted`) 1.4.3 — the real, independently-developed
  third-party SOCKS4/5 daemon installed (via the host distribution's own
  package manager) and used as the controlled SOCKS5 server in the HEV
  proof attempt (Section 10.10); its own SOCKS5 CONNECT/UDP-ASSOCIATE
  behavior was independently verified with a raw Python client before any
  HEV code was involved.
- `gdb`/`strace` — used directly in this pass to obtain real backtraces and
  syscall traces confirming both HEV crash defects originate inside HEV's
  own library code, not in this session's test harness (Section 10.10).
- Internal: `docs/B46_2A_HYSTERIA2_ANDROID_FEASIBILITY.md` (baseline
  findings this document extends, not re-derives from scratch),
  `docs/B45A_SHADOWSOCKS_RUST_SPIKE.md` /
  `docs/B45B3P_SHADOWSOCKS_PHYSICAL_VALIDATION.md` (fd-handoff/cleanup
  precedent), `PROJECT_ARCHITECTURE.md` (reachability/transport-selection
  boundaries, B33's app-process-exclusion finding),
  `android/app/src/main/java/net/pocvpn/client/vpn/xray/XrayCoreRuntime.kt`
  and `android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksProcessLauncher.kt`
  (read directly in an earlier correction pass to confirm Nova's own real
  in-process-JNI vs. child-process precedent, Section 13).

## Files changed in this slice

- `docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md` (this document; created,
  then corrected in four same-day follow-up passes per direct PR review —
  the second re-pinning the bridge's `sing-tun` dependency for a race fix,
  the third correcting the sing-tun license claim and adding the licensing/
  JNI-AAR/L2/Hysteria2-binary audit sections, the fourth completing and
  reporting HEV's own live proof attempt and its two confirmed crash
  defects, Section 10.10).
- `research/b46-2b-hysteria-tun-bridge/singtun-proof/{main.go,go.mod,go.sum,.gitignore}`
  (new, isolated host-side synthetic proof — not part of the Android app,
  not built by Gradle, not reachable from any production path; rewritten
  twice: once for the fd-ownership split/full deterministic UDP round
  trip/race-free synchronization, and again to port from the superseded
  `apernet/sing-tun` to the race-clean `sagernet/sing-tun` commit, including
  the Handler-interface and buffer-headroom API migration this port
  required). Unchanged in this fourth pass — the licensing/JNI-AAR/L2/HEV
  proof work was done in throwaway scratch locations outside the repository
  (per the task's own "do not implement the full Android bridge yet"
  scope), not committed.
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
