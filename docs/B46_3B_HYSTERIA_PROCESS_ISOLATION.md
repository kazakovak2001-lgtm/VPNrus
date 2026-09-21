# B46-3B - Hysteria2 process-isolated tun2socks bridge

Status: **`B46-3B PROCESS-ISOLATED ARCHITECTURE PHYSICALLY PASSED`** for
process isolation, load-order regression, lifecycle/restart, controlled
child death, and cleanup - all confirmed on real hardware (Part 9/10/15/16/18).
A follow-up review found three real lifecycle gaps in that first pass
(unexpected child death not propagated, a duplicated-TUN-fd leak on
pre-handoff failures, and a false "parent death is handled" doc claim with
no actual mechanism behind it) - all three are now fixed, tested (17 JVM
unit tests, up from 11), and physically re-confirmed on the same OPPO
device, including a NEW real parent-death/orphan-prevention proof. See
Part 24 ("Lifecycle hardening pass") for the full audit, fixes, and
physical evidence - it does not erase or contradict the original Part
9/10/15/16/18 evidence, which remains true; it adds ownership/crash-
resilience the first pass had not yet proven.
Live Hysteria2 data-plane proof (DNS/TCP/UDP through a real server,
protect boundary, exit correlation, screen-off) was NOT attempted in this
pass (Part 21) - this verdict covers architecture feasibility only, not
production integration, restricted-network behavior, or legal clearance.
See `docs/ROADMAP.md`'s B46 row for the authoritative status line.

Branch: `research/b46-3b-hysteria-process-isolation`
Worktree: `C:\Users\akaza\Downloads\VPN-B46-3B`
Baseline: `origin/main` @ `75cb4b249da24dc5d13197b0cc016147d79e0a81`
(unchanged since B46-2P/PR #98; B46-3A's own PR #99 remains a separate,
unmerged, rejected branch - reused here only as reference/evidence, never
as a starting point for this branch's own history)

## Part 1 - B46-3A failure root cause / evidence (recap)

See [`B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md`](B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md)
Part E/F for the full record. Summary: loading Xray's gomobile-produced
`libgojni.so` and an independent Go `-buildmode=c-shared` `libnovatun2socks.so`
into the SAME Android process crashed it with a genuine Go runtime fatal
error, reproduced twice with two DIFFERENT internal errors (`fatal error:
bad flushGen`, `fatal error: addspecial on invalid pointer`) - both real Go
GC/heap invariant violations occurring at library-load time, never a Java
exception, never anything either slice's own validation code caused.

## Part 2 - why load ordering is not an acceptable mitigation

B46-3A found the reverse load order ("tun2socks first") did not crash in
one clean run. That is NOT treated as a fix, for three reasons argued in
B46-3A's own Part F and restated here as this slice's starting premise:

1. **Non-deterministic symptom variation is itself the red flag.** Two runs
   of the SAME (failing) order produced two DIFFERENT internal Go runtime
   errors. A logic bug fails the same way every time; memory/GC corruption
   does not. One clean run of the reverse order is not evidence that order
   is safe - it is exactly as likely to be "hasn't corrupted anything
   visible yet."
2. **A production app cannot control or guarantee load order.** Xray's own
   session lifecycle (start/stop/reconnect), Android process lifecycle
   (process death and respawn, low-memory kills), and a future Hysteria
   session's own start/stop are all real events that can reorder which Go
   runtime touches the process first, at any point during the app's
   lifetime - not just at cold start.
3. **The failure mechanism is structural, not order-specific.** Both
   crashes happened at library-LOAD time, before any tun2socks-specific
   logic ran - consistent with two copies of the Go runtime corrupting
   shared process-global GC/scheduler state the moment both are resident,
   regardless of which one arrived first. A future crash in the
   "safe-looking" order remains entirely plausible.

## Part 3 - candidate isolation architectures compared

| Option | Verdict |
|---|---|
| A. `android:process=":hysteria_bridge"` bound Service + JNI | Adds Binder/service-process/AIDL complexity to reach the same goal (separate process) that a plain child executable achieves more simply. Considered but not selected - see Part 4. |
| B. Standalone native child executable (selected) | Plain OS process boundary, no Binder, no service lifecycle to manage beyond `ProcessBuilder`/signals this codebase already uses for B45A/B46-2P's own child processes. |
| C. Keep everything in-process, try to "fix" the Go runtime collision | Not attempted: this is exactly what B46-3A's crash evidence rules out - the collision is a structural property of two Go runtimes sharing an address space, not a bug in either runtime's own code that this project could patch. |

## Part 4 - selected architecture

**Standalone native child executable**, per the task's own stated
preference, confirmed rather than assumed: a genuine OS-process boundary
gives complete address-space isolation (the actual property B46-3A's
crash proved necessary) without adding a second IPC layer
(Binder/AIDL/`:process` service lifecycle) merely to host a Go runtime that
has no need for any Android framework API at all - it only needs a TUN fd
and a SOCKS5 address. This project already has two independent,
real-device-proven precedents for exactly this shape (a native binary
`exec()`'d as a child process, with fd handoff over a Unix-domain socket):
B45A's `sslocal` spike and B46-2P's own minimal Hysteria2 child. No
technical blocker was found that would favor a bound `:process` service
instead.

```
Nova app process (":main"/default)          tun2socks-child OS process
+----------------------------------+         +--------------------------+
| Xray gomobile Go runtime          |         | plain Go runtime          |
| (libgojni.so, existing, unchanged)|         | (xjasonlyu/tun2socks/v2,  |
|                                    |         |  gvisor - same pins as    |
| Tun2SocksProcessIsolatedSpikeVpn  |  fork/exec|  B46-2P/2C/3A)            |
| Service (debug-only VpnService)   | -------> |                            |
|   - VpnService.Builder.establish()|         | main() (research/b46-3b-  |
|   - owns ORIGINAL TUN              |  UDS +  |  hysteria-process-        |
|     ParcelFileDescriptor           | SCM_RIGHTS| isolation/tun2socks-    |
|   - dup()s a DUPLICATE fd          | -------> |  child/main.go)          |
|   - Tun2SocksChildRuntime          |         |   - receives dup TUN fd  |
|     orchestrates spawn+handoff     | <------ |   - engine.Insert/Start  |
|                                    |  JSON ack|   - blocks for SIGTERM   |
+----------------------------------+ (pid,ok) +--------------------------+
```

Never two Go runtimes in one process, by construction: the plain executable
is `exec()`'d, never `dlopen()`'d - there is no code path in this design
that could load `libnovatun2sockschild`'s Go runtime into the app process.

## Part 5 - FD ownership

Reused verbatim from B46-2C/B46-2P/B46-3A, with one additional hop (the
duplicate now crosses a process boundary via SCM_RIGHTS instead of being
handed to a same-process JNI call):

1. `VpnService.Builder.establish()` returns the ORIGINAL
   `ParcelFileDescriptor`. `Tun2SocksProcessIsolatedSpikeVpnService` is its
   sole owner and closes it exactly once, on `handleStop`/`onDestroy`/
   `onRevoke`.
2. A DUPLICATE (`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`)
   is created - the original is never sent anywhere.
3. `Tun2SocksChildRuntime.start` hands that duplicate's raw fd number to
   `RealTun2SocksChildControlChannel.sendStartRequestAndAwaitAck`, which
   wraps it in `ParcelFileDescriptor.adoptFd(fd)` (taking ownership for
   exactly the duration of the send) and transmits it via
   `LocalSocket.setFileDescriptorsForSend` - the kernel duplicates the fd
   again onto the receiving (child) process; this process's own copy is
   closed immediately after sending (`.use { }`).
4. The child (`main.go`'s `receiveStartRequest`) receives its own kernel
   copy via `syscall.Recvmsg`/`syscall.ParseUnixRights` and passes it
   straight to `engine.Insert`/`engine.Start` - the real tun2socks engine
   owns and closes it on `engine.Stop()`, exactly as in every prior B46
   slice.

No double-close: each of the three fd "copies" (original, the
app-process-local duplicate, the child's own kernel-duplicated copy) has
exactly one owner and exactly one close site. No stale reused fd number:
each `start()` call creates a fresh duplicate; the app-process-local copy
used for sending is discarded (closed) immediately after the successful
`sendmsg`, never reused.

## Part 6 - build/toolchain provenance

| Field | Value |
|---|---|
| Go version | `go1.26.5 windows/amd64` (cross-compiling `GOOS=android GOARCH=arm64`) |
| CGO | `CGO_ENABLED=0` - **no NDK, no cgo, at all** for this artifact (unlike B46-3A's `c-shared` build, a plain executable needs no C ABI export layer) |
| Build command | `go build -trimpath -o libnovatun2sockschild.so .` (see `research/b46-3b-hysteria-process-isolation/scripts/build-child.sh`) |
| Artifact | `libnovatun2sockschild.so` (17,062,117 bytes) |
| SHA-256 | `e457c1810cd1e5da147a9b4f8d6987c12d0c52cdac0dbdecb00d3ea95e9c6ce3` |
| ELF type | `ET_DYN` (PIE), `EM_AARCH64`, dynamically linked, interpreter `/system/bin/linker64` (confirmed via `file`/`llvm-readelf -h`) |
| Dynamic dependencies | **none** beyond the PT_INTERP entry itself (`llvm-readelf -d` shows zero `NEEDED` entries) - `CGO_ENABLED=0` produces an essentially self-contained binary |
| Symbol audit | 906 real `xjasonlyu/tun2socks` symbols, 4,720 real `gvisor.dev/gvisor` symbols, 0 `sing-tun` symbols (either fork) - via `llvm-nm` |

Pins unchanged from B46-2P/B46-2C/B46-3A: `github.com/xjasonlyu/tun2socks/v2`
commit `5d9fac67bb1095a5d2bd959216f85e6434524731` /
`v2.0.0-20260913205830-5d9fac67bb10`; `gvisor.dev/gvisor`
`v0.0.0-20260906120324-45bde0d1defa`. The tun2socks engine call shape
(`engine.Insert`/`engine.Start`/`engine.Stop`) is byte-for-byte unchanged
from `bridge.go`/B46-3A's own `main.go` - only the process/export boundary
around it changed.

## Part 7 - executable packaging

Reuses B45A's own real, physically-proven packaging route (Section 26 of
`docs/B45A_SHADOWSOCKS_RUST_SPIKE.md`), not reinvented: the plain
executable is placed at `android/app/src/debug/jniLibs/arm64-v8a/libnovatun2sockschild.so`
(the `lib*.so` naming AGP's `jniLibs` packager expects, even though the
file is an ELF executable, not a shared object - AGP does not validate ELF
type, it only copies files matching that path pattern) and relies on the
SAME pre-existing debug-only `packaging.jniLibs.useLegacyPackaging` Variant
API fix `android/app/build.gradle.kts` already sets for the `debug`
variant (proven, in B45A's own physical pass, to make the Android package
manager itself extract the file to `applicationInfo.nativeLibraryDir` at
install time with the OS-trusted `apk_data_file` SELinux label) - no new
Gradle configuration was needed for this slice.

`Tun2SocksChildBinaryResolver` (mirrors `B45ANativeBinaryResolver`
verbatim) is the single place that resolves `nativeLibraryDir` + validates
the file exists/is readable/is executable before
`Tun2SocksChildProcessLauncher` ever calls `ProcessBuilder` on it.

Real APK packaging confirmed (build-time, this pass):

```
lib/arm64-v8a/libgojni.so                (35,299,504 bytes - Xray, unchanged)
lib/arm64-v8a/libnovatun2sockschild.so   (12,070,856 bytes - this slice, post-strip)
lib/armeabi-v7a/libgojni.so
lib/x86/libgojni.so
lib/x86_64/libgojni.so
```

`:app:checkDebugDuplicateClasses` and `:app:assembleDebug` both
`BUILD SUCCESSFUL` with both artifacts present (69/69 tasks, no cache
reuse on a cold Gradle daemon - see Part 9's exact log).

## Part 8 - host-level wire-protocol proof (before physical device testing)

Before touching the real device (round-trips are much slower to debug
there), the SCM_RIGHTS control-channel protocol implemented in
`research/b46-3b-hysteria-process-isolation/tun2socks-child/main.go` was
proven end-to-end on a real Linux host (WSL2 Ubuntu, root, a real
`/dev/net/tun` device) via a throwaway harness
(`research/b46-3b-hysteria-process-isolation/proof/host_proof.go`, source
only - not shipped, not built into the app):

```
real TUN device open: fd=4 name=b46b3proof0
spawned child, launcher-side pid=682
sent header+fd: 38 payload bytes, 24 oob bytes
B46_3B_CHILD_STARTED: pid=682 mtu=1500 socksAddr=127.0.0.1:1
PROOF_ACK: ok=true pid=682 error=""
PROOF_REAL_CHILD_PID=682 LAUNCHER_PID=682 SAME_PROCESS=true
sending SIGTERM to child pid=682
B46_3B_CHILD_STOPPING: pid=682
B46_3B_CHILD_STOPPED: pid=682
PROOF_CHILD_EXIT: err=<nil>
```

This proves, on a real kernel: SCM_RIGHTS fd transfer works; the JSON
control header parses; `engine.Insert`/`engine.Start` succeed against a
REAL TUN device; the child's own `os.Getpid()` is correctly reported over
the wire and matches the launcher's own view of the spawned pid; SIGTERM
triggers the real, ordered `engine.Stop()` then a clean `exit(0)`
(`cmd.Wait()` returned `nil`).

## Part 9 - process isolation proof (physical)

**Device:** OPPO CPH2173, Android 14, SDK 34, arm64-v8a (same device
B46-2P/B46-3A used).

The device reconnected after a mid-session gap. Both `app-debug.apk`
(SHA-256 `18fb843135438f3e4cc53bb51f3f08b73cce630771a91d42270195202e6cd43b`)
and `app-debug-androidTest.apk` were installed. On-device extraction
confirmed (`run-as net.pocvpn.client ls -la .../lib/arm64/`): both
`libgojni.so` and `libnovatun2sockschild.so` present, both `rwxr-xr-x`,
same directory.

**One real environment wrinkle, diagnosed rather than worked around
blindly:** the first physical run of `Tun2SocksIsolatedProcessMapsInstrumentedTest`
failed with `Builder.establish() returned null`, identical to B46-3A's own
unresolved gap on this device. `appops get net.pocvpn.client ACTIVATE_VPN`
already showed `allow`, and a dedicated diagnostic (`Tun2SocksIsolatedConsentActivity`,
debug-only, calls `VpnService.prepare()` directly) confirmed
`B46_3B_CONSENT_ALREADY_PREPARED` - so this was NOT a missing-consent
problem. After foregrounding the app once via `am start` on `MainActivity`,
the SAME test passed cleanly and repeatably for the rest of this pass -
consistent with a one-time ColorOS-side state settle after a fresh
`adb install -r` rather than a real consent gap. Recorded here as an
observed environment quirk, not as a structural blocker.

**`Tun2SocksIsolatedProcessMapsInstrumentedTest` - PASSED.** Real logcat
evidence (`am instrument -w -e class ...`, `Tests run: 1, Failures: 0`):

```
D/VpnJni: Address added on tun0: 10.205.48.1/24
D/Vpn: setting state=CONNECTING, reason=establish
I/ConnectivityService: registerNetworkAgent NetworkAgentInfo{... ni{VPN CONNECTING} ...
    lp{{InterfaceName: tun0 LinkAddresses: [ 10.205.48.1/24 ] ... Routes: [ 10.205.48.0/24 -> 0.0.0.0 tun0 ...
    TransportInfo: <VpnTransportInfo{... sessionId=B46-3B process-isolated tun2socks spike ...}>
I/Vpn: Established by net.pocvpn.client on tun0
E/OPLUS_KEVENT_RECORD: OPLUS_KEVENT payload:10668,path@@/data/app/.../lib/arm64/libnovatun2sockschild.so
I/B46_3B_Maps: child maps: 58cf330000-58cf749000 r-xp 00000000 fd:4f 5669159   /data/app/.../lib/arm64/libnovatun2sockschild.so
I/B46_3B_Maps: child maps: 58cf750000-58cfcca000 r--p 00420000 fd:4f 5669159   /data/app/.../lib/arm64/libnovatun2sockschild.so
I/B46_3B_Maps: child maps: 58cfcd0000-58cfe42000 r--p 009a0000 fd:4f 5669159   /data/app/.../lib/arm64/libnovatun2sockschild.so
I/B46_3B_Maps: child maps: 58cfe50000-58cfeb3000 rw-p 00b20000 fd:4f 5669159   /data/app/.../lib/arm64/libnovatun2sockschild.so
D/Vpn: setting state=DISCONNECTED, reason=agentDisconnect
```

This is the core acceptance gate, physically confirmed: the app process's
own `/proc/self/maps` contains `libgojni.so` (Xray, real, via
`LibXrayCoreRuntime.ensureCoreEnvInitialized`) and does NOT contain
`libnovatun2sockschild` (it is never `dlopen()`'d there); the CHILD
process's own `/proc/<childPid>/maps`, read directly from the app process
(same UID, no `run-as`/root needed), contains `libnovatun2sockschild.so`
mapped as its own executable and does NOT contain `libgojni.so` - both
assertions passed. Real, kernel-level, same-process-vs-separate-process
evidence, not an inference from symbol tables alone.

## Part 10 - load-order regression

**Both orderings PASSED, two clean cycles each, in fresh processes
(`am force-stop` before each `am instrument` invocation):**

- `xray_first_then_child_two_cycles` - `Tests run: 1, Failures: 0` (`Time:
  1.312`)
- `child_first_then_xray_two_cycles` - `Tests run: 1, Failures: 0` (`Time:
  0.746`)

Real logcat evidence, distinct child PIDs per cycle, zero Go fatal errors,
zero crashes anywhere in either run:

```
D/Tun2SocksChildProcess: [stderr] B46_3B_CHILD_STARTED: pid=9030 mtu=1500 socksAddr=127.0.0.1:41999
D/Tun2SocksChildProcess: [stderr] B46_3B_CHILD_STARTED: pid=9123 mtu=1500 socksAddr=127.0.0.1:41999
```

(`9030` and `9123` are the two distinct child processes each cycle of one
ordering spawned - genuinely fresh processes, not a reused/cached one.)
This directly confirms Part 2's own prediction: since the tun2socks Go
runtime never loads into the app process at all in either order, there is
no shared in-process Go runtime state left to corrupt - B46-3A's crash
class is structurally gone, not merely avoided by luck of ordering.

## Part 11 - TUN mechanics proof

Host-level proof (Part 8) already confirms `engine.Insert`/`engine.Start`
succeed against a REAL TUN device through this exact wire protocol. A real
Android `VpnService`-established TUN, handed through the same code path
physically on-device, has NOT yet been exercised (see Part 9). No TCP/UDP
application-level round trip through a live SOCKS5 endpoint was attempted
in this pass (see Part 21's limitations) - this is explicitly the
"mechanics" bound the task itself distinguishes from a full data-plane
proof, and even the mechanics half is not yet physically confirmed.

## Part 12 - protect boundary

Not attempted in this pass. The existing `VpnService.protect(fd)` /
SCM_RIGHTS pattern (`RealShadowsocksVpnProtectBridge`,
`B46HysteriaVpnProtectBridge`) is the intended reuse target for a future
pass once a real Hysteria2 child + real outbound QUIC socket exists in
this architecture - this slice only built and (partially) proved the
TUN<->tun2socks-child boundary, not the tun2socks-child<->Hysteria2-child
boundary.

## Part 13 - DNS/TCP/UDP proof

Not attempted - no live data plane exists in this pass (see Part 11).

## Part 14 - exit/server correlation

Not attempted - requires a live authorized Hysteria2 server; B46-2P's own
temporary Stockholm test server was already decommissioned (see that
doc's own closure). Provisioning new server infrastructure requires
explicit repository-owner approval per this repository's own standing
rules and was not requested or performed in this pass.

## Part 15 - lifecycle/restart

**PASSED, physically** - covered by Part 10's own two-cycles-per-ordering
runs (four full start-then-stop cycles total across both orderings, each
with a genuinely distinct child PID). No leaked/reused fd numbers, no
hung stop.

## Part 16 - controlled child death

**PASSED, physically.** `Tun2SocksIsolatedChildDeathInstrumentedTest` -
`Process.sendSignal(childPid, 9)` (SIGKILL, same-UID, no root/run-as
needed) against a real running child (`pid=9334`, confirmed via
`B46_3B_CHILD_STARTED` log line), then confirmed `/proc/9334` genuinely
stops existing, the app process (`pid=9283`) survives completely
unaffected (same pid before and after), and a subsequent `ACTION_STOP` is
still a harmless no-op that reaches `Idle` normally. Real result: `run
finished: 1 tests, 0 failed, 0 ignored`.

## Part 17 - screen-off result

Not attempted - requires a live data plane to meaningfully observe
"traffic still works" across a screen-off interval (see Part 13's own
gap).

## Part 18 - cleanup

Covered structurally by `Tun2SocksChildRuntime.stop()`
(graceful-then-forceful child termination, control-channel close+delete,
original TUN fd close) and exercised by the JVM unit tests (11/11 green -
see Part 20). **Physically confirmed** after the full test pass: `adb
shell ps -A | grep novatun2sockschild` - no output (no orphan child
process); `ip link show | grep tun` - no output (no stale TUN interface);
`netstat -an | grep 34443` - no output (AWS UDP 34443 confirmed still
closed, untouched by this pass).

## Part 19 - license audit

Unchanged from B46-2C/B46-2P/B46-3A: `tun2socks` MIT, `gvisor` Apache-2.0,
0 `sing-tun` (either fork) confirmed via symbol audit (Part 6). Engineering
finding only, explicitly not legal clearance, per this task's own
instruction and every prior B46 slice's own wording.

## Part 20 - security/secret handling

- No secrets on argv: the child's only argv is a Unix-domain socket path
  (not a credential). MTU and the local SOCKS5 address travel over the
  wire, not argv, and neither is a credential either.
- No secrets in the child's own logging (`B46_3B_CHILD_*` log lines carry
  only pid/mtu/socksAddr, matching the Go child's own logging discipline
  reused from B46-2P's minimal Hysteria2 client).
- No `TransportKind.HYSTERIA`, no production transport-selection code, no
  production server/firewall/manifest change - confirmed by `git diff`
  scope (Part 22).
- Secret scan performed on every new/changed file before commit (grep for
  password/secret/api-key/private-key/BEGIN-RSA/token patterns) - none
  found beyond the word "secret" appearing in a doc-comment description of
  what is NOT being handled.

## Part 21 - limitations

This pass delivers real, physically-confirmed evidence for the core
architectural question (does process isolation avoid B46-3A's crash? -
**yes**, confirmed via `/proc/<pid>/maps` on real hardware, two load
orders, two cycles each, plus a controlled `SIGKILL` child-death test) but
does NOT yet deliver:

- any live data-plane proof (the second half of Part 11 - a real TCP/UDP
  application-level round trip through a live SOCKS5 endpoint - plus
  Parts 13/14/17) - no authorized Hysteria2 test server was available or
  provisioned in this pass
- protect-boundary physical proof (Part 12) - no real Hysteria2 child/
  outbound QUIC socket exists in this architecture yet to protect

These are the concrete, named remaining gaps - not hidden inside a broader
claim. Everything else this document's own acceptance checklist asked for
(Part 9's process-isolation proof, Part 10's load-order regression, Part
15's lifecycle/restart, Part 16's controlled child death, Part 18's
cleanup) is real, physical, and PASSED.

## Part 22 - remaining production-integration work

Unchanged from every prior B46 slice's own list: production transport
design/wiring, signed profile schema, credential provisioning, release
packaging, legal review, long-idle/mobile stability, restricted-network
field evidence - all still fully out of scope until a production
integration slice. `TransportKind.HYSTERIA` was NOT added in this pass;
`TransportRegistry`/`VpnController`/`SmartConnectDecisionEngine`/production
selection logic were not touched (`git diff` against `origin/main` touches
only `android/app/src/debug/**`, `android/app/src/testDebug/**`,
`android/app/src/androidTest/**`, `research/b46-3b-hysteria-process-isolation/**`,
`docs/**`, `.gitignore`).

## Part 23 - decision gate

**`B46-3B PROCESS-ISOLATED ARCHITECTURE PHYSICALLY PASSED`** (architecture
feasibility only - see the precise scope below).

Real, physical evidence, on the same OPPO CPH2173 device B46-2P/B46-3A
used:

- Process isolation: the app process's own `/proc/self/maps` contains
  `libgojni.so` and does NOT contain `libnovatun2sockschild`; the child
  process's own `/proc/<pid>/maps` contains `libnovatun2sockschild.so`
  and does NOT contain `libgojni.so` - genuine, disjoint address spaces,
  confirmed via kernel-level evidence, not inferred.
- Load-order regression: BOTH orderings (Xray-first, tun2socks-first),
  two cycles each, in fresh processes, zero crashes, zero Go fatal
  errors, genuinely distinct child PIDs per cycle - directly disproving
  the load-order-dependent instability B46-3A found in the in-process
  design.
- Controlled child death: `SIGKILL` against a live child process leaves
  the app process completely unaffected and cleanup still completes
  normally.
- Cleanup: no orphan child process, no stale TUN interface, AWS UDP 34443
  confirmed still closed.

What this verdict does NOT claim (per this task's own explicit
instruction, honored even on a full pass): production Hysteria transport
integration, Smart Connect wiring, restricted-network/Russia field
behavior, legal clearance, or any live data-plane proof (DNS/TCP/UDP
through a real server, the protect boundary, exit/server correlation,
screen-off behavior - see Part 21's own named gaps). This is an
architecture-feasibility result: the specific failure B46-3A found is
structurally eliminated, not merely avoided by luck.

## Part 24 - Lifecycle hardening pass (post-physical-pass review)

A follow-up code review of the first physical pass (Parts 1-23 above)
found three real lifecycle gaps - none of them affect the process-
isolation result itself (Part 9's own evidence is unchanged and still
true), but all three matter for whether this architecture is actually
production-feasible, not merely "doesn't crash once."

### Gap 1 - unexpected child death was not propagated

**Finding:** `RealTun2SocksChildProcess` already had a working
`onExit(callback)` watcher-thread mechanism, but `Tun2SocksChildRuntime`
never registered a callback on it. If the child died on its own (crash,
OOM-kill, external signal), the app process survived (already proven
physically) but the runtime/service state could still say `Started`, the
original TUN fd was never closed, and the session only ever became
`Failed` after a LATER, EXPLICIT `ACTION_STOP` - never automatically. The
original `Tun2SocksIsolatedChildDeathInstrumentedTest` only proved "SIGKILL
child -> app survives -> explicit STOP still works," which is not
sufficient lifecycle ownership.

**Fix:** `Tun2SocksChildRuntime.start()` now registers
`launched.onExit { code -> handleChildExit(code) }` on every successful
start. A new `terminalClaimed` boolean, guarded by a dedicated
`stateLock`, is the single source of truth for "exactly one terminal
transition per session": whichever of `stop()` or `handleChildExit()`
reaches the guarded block FIRST clears `process`/`childPid` and performs
real cleanup; the other sees the claim already taken and no-ops. This
makes the classic race (a `stop()` call and a genuinely unexpected child
death happening at nearly the same moment) safe by construction rather
than by luck of scheduling. `Tun2SocksChildRuntime.onUnexpectedExit`
exposes this to the owning service; `Tun2SocksProcessIsolatedSpikeVpnService`
registers it once (in `init`) and runs the SAME real cleanup `handleStop`
does (close the original TUN fd, clear ownership, report a terminal
`Failed` status) - all under a new `tunFdLock` shared with the normal
`handleStart`/`handleStop` paths, so an explicit stop and an automatic
unexpected-exit detection can never race on closing/nulling the same TUN
fd field either.

### Gap 2 - duplicated TUN fd leaked on pre-handoff failures

**Finding:** The service always did
`ParcelFileDescriptor.dup(...).detachFd()` then called
`runtime.start(dupFd, ...)`. The intended contract said the duplicate
becomes the child's responsibility after a successful SCM_RIGHTS handoff -
but `controlChannel.bind()` failure and `launcher.launch()` failure both
return `Failed` from `start()` BEFORE `sendStartRequestAndAwaitAck` (the
only place that actually closes the fd) is ever called, and the service
never closed the duplicate on a `Failed` result either. Real fd leak.

**Fix:** Ownership is now structurally unambiguous, exactly per the
task's own preferred model: `Tun2SocksChildRuntime.start()` owns the
supplied duplicated fd from the INSTANT it is called. A new injectable
`Tun2SocksDupFdCloser` seam (`RealTun2SocksDupFdCloser`, backed by
`ParcelFileDescriptor.adoptFd(fd).close()`) is called on every failure
path BEFORE `sendStartRequestAndAwaitAck` is reached (already-running,
invalid mtu, empty socks address, bind failure, launch failure - an
already-invalid `fd < 0` is the one exception, since it was never a real
fd to own). Once `sendStartRequestAndAwaitAck` is called, it alone owns
closing the fd (unchanged - `ParcelFileDescriptor.adoptFd(fd).use { }`
already closed it exactly once on every one of its own internal branches).
The caller (`Tun2SocksProcessIsolatedSpikeVpnService`) never needs to
guess whether handoff happened and no longer touches the duplicate fd at
all after calling `start()`.

The interface seam (`Tun2SocksDupFdCloser`) exists specifically because
`ParcelFileDescriptor` is an Android framework class this project's
`testOptions.unitTests.isReturnDefaultValues` stubs to `null`/defaults
rather than throw - a `FakeTun2SocksDupFdCloser` records calls instead, so
JVM unit tests can assert exactly which fds were closed and how many
times without touching any real OS resource.

**Test coverage added** (all 9 branches the task asked for, each proving
no double-close and no leak):

| # | Scenario | Assertion |
|---|---|---|
| 1 | bind failure | `closer.closedFds == [fd]`, launcher never called |
| 2 | process launch failure | `closer.closedFds == [fd]`, control channel closed |
| 3 | child never connects | folded into the "ack failure" test (`Tun2SocksChildAck.Failed`) - `closer.closedFds` stays empty (already closed by the control-channel call itself) |
| 4 | header send failure | same as #3 |
| 5 | ack timeout after handoff | same as #3 |
| 6 | child returns failure ack | separate test, engine-level rejection reason passed through |
| 7 | successful start | `closer.closedFds` stays empty - the runtime itself never double-closes a successfully-handed-off fd |
| 8 | normal stop | already-covered idempotency/graceful-then-forceful tests, now also asserting `onUnexpectedExit` is never fired |
| 9 | unexpected death | new tests - notified exactly once, state cleared, idempotent `stop()` afterward, a fresh `start()` is possible again |

### Gap 3 - parent-death/orphan contract was falsely documented

**Finding:** `main.go`'s own doc comment claimed "if the control connection
itself closes first (parent process died), that is treated the same as a
stop signal" - this was never actually implemented. Both control
connections close long before the child reaches `waitForStopSignal()`
(which only listens for `SIGTERM`/`SIGINT`), so there was no real
parent-death detection at all, and a Linux child CAN outlive its parent.

**Design decision:** `prctl(PR_SET_PDEATHSIG, SIGTERM)` - evaluated first,
not blindly implemented: this is a standard Linux kernel mechanism (since
Linux 2.1.57), and Android's kernel is Linux, so no Android-specific
unavailability was expected - confirmed rather than assumed, by an actual
build + two real tests (host-level and physical, both below). A
persistent liveness socket (the task's other named option) was not
selected: it would need a THIRD long-lived connection (the two existing
ones are both deliberately short-lived, per this file's own protocol doc)
with its own teardown/ownership design, for a problem the kernel already
solves natively and more directly.

**Implementation** (`research/b46-3b-hysteria-process-isolation/tun2socks-child/main.go`):
`parentPidAtStartup := os.Getppid()` is captured as a package-level
variable initializer - the earliest point Go itself runs any code, before
`main()`. `installParentDeathSignal()` is the FIRST statement inside
`main()` (before `flag.Parse()`, before anything else): it issues the raw
`prctl(PR_SET_PDEATHSIG, SIGTERM)` syscall via `syscall.RawSyscall`, then
immediately re-checks `os.Getppid()` against `parentPidAtStartup` - if they
differ, the real parent already exited in the gap between this process's
own exec and the `prctl()` call landing (reparented to init/zygote), so no
future `SIGTERM` will ever arrive for an event that already happened; this
is treated as fatal (the child logs
`B46_3B_CHILD_PARENT_DEATH_GUARD_FAILED` and exits) rather than silently
trusting a signal that cannot come. The false doc-comment claim was
corrected to describe the REAL mechanism instead.

**Host-level proof** (WSL2 Ubuntu, before ever touching the device - a
throwaway harness, `research/b46-3b-hysteria-process-isolation/proof/parent_death_proof.sh`,
source only, not committed as a binary/shipped artifact): spawns the
child under a `setsid`-wrapped parent shell, confirms the child is alive,
`SIGKILL`s the parent, and polls for the child's own disappearance:

```
parent(setsid) pid=525  child pid=529
PROOF_RESULT: child GONE after 23ms - PASS
```

**Physical proof** (same OPPO CPH2173): a purpose-built harness (NOT a
self-contained instrumentation pass/fail test - the task's own instruction
is explicit that a test cannot observe its own process's death from the
inside; `Tun2SocksIsolatedParentDeathHarnessInstrumentedTest` only starts a
real session and then ends, letting `am instrument` completion's own real
`ActivityManager` kill of the app process BE the real parent-death event,
observed from a SEPARATE, external `adb shell` session afterward):

```
D/Tun2SocksChildProcess: [stderr] B46_3B_CHILD_STARTED: pid=19046 mtu=1500 socksAddr=127.0.0.1:41999
I/ActivityManager: Force stopping net.pocvpn.client appid=10668 user=0: finished inst
I/ActivityManager: Killing 19012:net.pocvpn.client/u0a668 (adj 0): stop net.pocvpn.client due to finished inst

$ adb shell pidof net.pocvpn.client
(empty - app process confirmed gone)

$ adb shell ls -la /proc/19046
ls: /proc/19046: No such file or directory

$ adb shell ps -A | grep novatun2sockschild
(no output - zero matching processes anywhere on the device)
```

The real app process (pid `19012`) died; the real child process (pid
`19046`) - which was never told to stop, never received an explicit
`ACTION_STOP`, and had no other mechanism watching it - died automatically
and left no orphan. This is the load-bearing physical proof for Gap 3's
fix.

### Physical re-confirmation after all three fixes

All fixes were re-verified on the SAME OPPO CPH2173 device, on the SAME
`:app:checkDebugDuplicateClasses`/`:app:assembleDebug`-green build
(`app-debug.apk` SHA-256
`ac490798d54825902963f5607110e1305a64ccabc0db9a82312667e1d4a85a1d`;
`libnovatun2sockschild.so` SHA-256
`3ee51b0bbfec55f3b1f05c7b55057110fda1d9b64187822b6efeb9621349621f`):

- **`Tun2SocksIsolatedProcessMapsInstrumentedTest`** - still `OK (1 test)`,
  no regression from the runtime refactor.
- **`Tun2SocksIsolatedLoadOrderInstrumentedTest`** - still `OK (2 tests)`,
  both orderings, no regression.
- **`Tun2SocksIsolatedChildDeathInstrumentedTest` (rewritten "V2" -
  no longer calls `ACTION_STOP` right after the kill)** - `OK (1 test)`.
  Real logcat evidence of the FULL automatic chain, no manual stop
  involved until the final idempotency check:

  ```
  D/Tun2SocksChildProcess: [stderr] B46_3B_CHILD_STARTED: pid=18387 mtu=1500 socksAddr=127.0.0.1:41999
  I/Tun2SocksChildRuntime: child started: pid=18387
  W/Tun2SocksChildRuntime: child exited unexpectedly: code=137
  W/Tun2SocksIsolatedSpike: tun2socks child exited unexpectedly: code=137
  D/Vpn: setting state=DISCONNECTED, reason=agentDisconnect
  ```

  (`code=137` = `128 + 9` = the real `SIGKILL` exit status, confirming the
  runtime's own unexpected-death detection fired for the REAL reason, not
  a coincidental timeout.) The test itself additionally asserted, and
  confirmed true: the TUN interface (`ip link show` no longer contains
  `tun0`) and the control socket file are both gone BEFORE any
  `ACTION_STOP` was sent - genuinely automatic teardown, not merely a
  later explicit cleanup.
- **Parent-death/orphan test** - PASSED, see above.
- **JVM unit tests** - 17/17 green (`Tun2SocksChildRuntimeTest`, up from
  11 - 6 new tests covering Gap 1/Gap 2 exactly per the task's own
  required list).

### Remaining risks

- The parent-death proof used `am force-stop`-via-instrumentation-teardown
  as the real kill mechanism (a genuine, uncontrolled process kill) rather
  than a raw `SIGKILL` directly on the app's own PID - both are real
  process-death events the kernel treats identically for `PR_SET_PDEATHSIG`
  purposes, but a direct-`SIGKILL` variant was not separately exercised in
  this pass.
- `terminalClaimed`'s correctness rests on Kotlin's `synchronized` block
  being a real reentrant JVM monitor (true for the HotSpot/ART VM this
  project targets) - documented as a structural assumption, not proven
  with a dedicated concurrency stress test beyond the deterministic
  fake-triggered race test.
- No change in this pass to the live-data-plane gaps already named in
  Part 21 (DNS/TCP/UDP/protect/exit-correlation/screen-off) - still fully
  out of scope until B46-3C.
