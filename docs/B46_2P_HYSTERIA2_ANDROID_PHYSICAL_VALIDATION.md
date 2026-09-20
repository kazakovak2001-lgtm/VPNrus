# B46-2P: Physical Android Validation of the Permissive Hysteria2 Path

Status: **PHYSICAL ANDROID ARCHITECTURE FEASIBILITY PASSED**, for the
B46-2C-selected permissive architecture (`xjasonlyu/tun2socks` in-process
AAR + minimal Hysteria2 SOCKS5-only child, real `VpnService.protect(fd)` via
SCM_RIGHTS), on a real physical Android device.

**This is explicitly NOT the same claim as:**

```
PHYSICAL ANDROID FEASIBILITY  ≠  PRODUCTION TRANSPORT IMPLEMENTATION
```

and, separately and just as importantly:

```
NOT YET INTEGRATED INTO THE NOVA `:app` PROCESS/CLASSPATH
```

The harness that produced this evidence is a **separate, standalone Android
application** (`net.pocvpn.b46harness`), not code inside Nova's own `:app`.
See "Why a separate module" below for the real, physically-discovered
reason this was necessary, and "Remaining work" for exactly what a future
slice would still need to do to get this into `:app` itself.

## Baseline

- `origin/main` at the start of this slice: `e2d453cf7e81449f008de5617b1106fe7eae6545` (verified via `git rev-parse origin/main` before any change).
- Isolated worktree: `C:\Users\akaza\Downloads\VPN-B46-2P`, branch `validation/b46-2p-hysteria-android-physical`, created from that exact SHA. The `field-test/b37-awg31-upgrade` worktree was never touched.

## Device

- Serial `c618ee06`, model `CPH2173` (OPPO), Android 14, SDK 34, ABI `arm64-v8a` - matches the historical device exactly, confirmed via `adb shell getprop`, not assumed.

## Why a separate module (real, physically-found finding)

B46-2C's own architecture doc assumed the tun2socks AAR would be added to
`:app`'s existing `debug` source set, alongside the already-integrated Xray
(`AndroidLibXrayLite`) AAR. Building that combination for real found a
genuine, previously-undocumented Android/gomobile packaging limit:

- **Xray's AAR is also gomobile-bound.** `AndroidLibXrayLite` is built with
  `gomobile bind`/`gobind`, exactly like this slice's own tun2socks bridge.
  Every gomobile bind emits the same fixed runtime support classes
  (`go.Seq`, `go.Universe`, `go.error`, with real native methods -
  confirmed via `javap -p bridge.Bridge`/`javap -p go.Seq`, which showed
  `native void init()`, `native void incGoRef(...)`, etc.) and the same
  fixed native library name, `libgojni.so`.
- Linking `:app`'s existing Xray AAR and a new tun2socks AAR together
  produced two real failures: `checkDebugDuplicateClasses` failed on
  identical `go.Seq`/`go.Universe`/`go.error` class names from two
  different AARs, and (had that been bypassed) both AARs ship a
  `jni/arm64-v8a/libgojni.so` - a native-library filename collision; only
  one file can occupy that path in the merged APK, and it is not the
  same Go binary as the other AAR's, so whichever one is *not* packaged
  would fail with `UnsatisfiedLinkError` at runtime.
- Verified this is Xray-specific, not a general "any two AARs" problem:
  AWG's own tunnel AAR (`amneziawg-tunnel`) was checked and does **not**
  collide - it is built with `go build -buildmode=c-shared` (custom
  `libwg-go.so`/`libwg.so`/`libwg-quick.so` names), never gomobile/gobind.
- `-javapkg` (gomobile bind's own package-relocation flag) was tried and
  confirmed, by direct inspection of the generated `.class` files, to
  relocate only the user package (`bridge.Bridge` -> a prefixed package);
  the shared `go.Seq`/`go.Universe`/`go.error` runtime classes and the
  `libgojni.so` name are hardcoded and unaffected by it.
- Excluding Xray's AAR from `:app` instead was tried and rejected:
  `XrayCoreRuntime.kt` (production `:app` source) imports Xray's generated
  Go-bound classes directly at compile time, so removing the AAR breaks
  compilation of already-existing, unrelated production code - not an
  acceptable fix under this task's "do not modify Xray" constraint.

**Decision (repository owner, mid-slice):** build B46-2P as its own
standalone Android application module (`b46harness/`, `build.gradle.kts`,
own `AndroidManifest.xml`, `applicationId net.pocvpn.b46harness`) with zero
Gradle dependency on `:app` and no Xray AAR at all, rather than patch
either AAR's bytecode/native symbols. This is architecturally clean and
low-risk, but it is a real deviation from the task's original
same-`:app`-process framing, so every claim in this document that depends
on "the same app UID/process" (the own-UID-included full-tunnel proof, the
protect-failure proof) is about `net.pocvpn.b46harness`'s own UID/process,
not Nova's `net.pocvpn.client`. The mechanism proven - real TUN, real
tun2socks bridge, real `VpnService.protect(fd)` via SCM_RIGHTS, real
Hysteria2 QUIC - is identical either way; only the specific APK/UID it
runs under differs from the original framing.

`:app`'s `build.gradle.kts`, manifest, and source tree are byte-for-byte
unchanged from baseline (`git diff` against `origin/main` on those paths is
empty) - confirmed explicitly before commit.

## Source pins (unchanged from B46-2C)

- `xjasonlyu/tun2socks` `v2.0.0-20260913205830-5d9fac67bb10` (commit `5d9fac67bb1095a5d2bd959216f85e6434524731`), MIT.
- `gvisor.dev/gvisor` `v0.0.0-20260906120324-45bde0d1defa`, Apache-2.0.
- `apernet/hysteria` commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` (`app/v2.12.3` lineage), MIT.

## tun2socks AAR - built and audited

Built via `gomobile bind -target=android/arm64 -androidapi 26` from
`research/b46-2p-android-physical/tun2socks-bridge/` (new wrapper source,
`StartBridge(fd, mtu, socksAddr) error` / `StopBridge() error`, real
`engine.Insert`/`engine.Start`/`engine.Stop` - no custom IP stack).

- AAR SHA-256: `28ae4bfb09f5d9bdd02cf52fc94c0c1f96f7a6d64fc07513cbf70a2b7df6efa4` (8,050,045 bytes).
- `jni/arm64-v8a/libgojni.so` SHA-256: `d87fa852465fa933ae00921b6f4fe4d9e8820f97b6fd1aa9e5bae53c0e56e654` (real ARM64 ELF, NDK r27, not stripped).
- `go tool nm`: 20,186 total symbols, **0** `sing-tun`/`sagernet` matches, **931** real `xjasonlyu/tun2socks` symbols, **4,976** real `gvisor` symbols - matches the B46-2C proof exactly, now on the real Android build.
- `grep -a` binary text scan: 0 "sing-tun" matches.
- Real gobind-generated Java API (confirmed via `javap`, NOT assumed as
  `StartBridge`/`StopBridge` PascalCase - this assumption was wrong and
  caused a real physical failure, see "Bugs found" below): `bridge.Bridge`
  with `public static native void startBridge(long, long, String) throws Exception`,
  `stopBridge()`, `isStarted()`.

Not committed (gitignored, `b46harness/local-libs/b46-tun2socks.aar`).

## Minimal Hysteria2 child - built, extended, audited

Grafted onto a clean clone of `apernet/hysteria` at the pinned commit (no
upstream file modified), extending B46-2C's prototype
(`research/b46-2c-permissive-hysteria-path/hysteria-minimal-client/novaminimal_main.go`)
additively with two new real capabilities, committed at
`research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go`:

- `--protect-path <unix-socket-path>`: real `VpnService.protect(fd)` analog
  via SCM_RIGHTS, reusing the exact wire protocol already physically proven
  by production's `RealShadowsocksVpnProtectBridge`
  (`android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksVpnProtectBridge.kt`):
  connect, send 1 payload byte + 1 ancillary fd via `net.UnixConn.WriteMsgUnix`/`syscall.UnixRights`,
  read 1 response byte (`0x00` = success, else fail closed).
- `--config-file <path>`: JSON config (server/auth/sni/insecure/obfsSalamander/socksListen/protectPath)
  so the auth password never appears in argv/env/process-title/logcat. Used
  exclusively on Android - `--auth`/`--protect-stub`/`--fwmark` remain for
  host-research reproducibility only.

Audits (host + `GOOS=android GOARCH=arm64 CGO_ENABLED=0` builds):

- `go list -deps`: 288-290 packages, **0** `sing-tun`/`internal/tun` matches on both builds.
- `go version -m` (Android binary): **0** sing-tun mentions.
- `go tool nm` (Android binary, 12,292 symbols): **0** sing-tun/sagernet, 189 real `apernet/hysteria/core` symbols, 35 real `internal/socks5` symbols.
- `grep -a` binary scan: 0 matches.
- Android binary: real ARM64 PIE ELF, `interpreter /system/bin/linker64` (Android-compatible), SHA-256 `63056e02b1fadce75baaa5423d84f61d27bbfc41684d1f154eeafbaed0109e64` (13,538,360 bytes; the binary itself was never rebuilt after the Kotlin-side bug fixes below - only the harness's Kotlin/Gradle code changed).
- **Real Go-level test of the SCM_RIGHTS protocol** (`novaminimal_main_test.go`, run natively on Linux via WSL, since Windows lacks AF_UNIX/SCM_RIGHTS): 4/4 pass - success (real fd transfer + ack), negative-ack fails closed, RPC timeout fails closed, no-listener fails closed. This exercises the real `protectViaUnixSocket` function against a real `net.Listen("unix", ...)` peer, not a mock.

Not committed (gitignored, `b46harness/src/main/jniLibs/arm64-v8a/libnovahysteria.so`,
packaged as a `.so` so the Android package manager extracts it to
`nativeLibraryDir` with real executable permissions - same convention as
production's `libsslocal.so`; verified real and executable on-device via
`run-as ... libnovahysteria.so --help`, which printed the real flag usage
text).

## Android harness (`b46harness/`)

New standalone module, `net.pocvpn.b46harness`, minSdk 26/targetSdk 35,
`packaging.jniLibs.useLegacyPackaging = true`. Classes:
`B46HysteriaActivity`, `B46HysteriaVpnService`, `B46HysteriaRuntime`,
`B46HysteriaVpnProtectBridge`/`RealB46HysteriaVpnProtectBridge`,
`B46NativeBinaryResolver`, `B46Tun2SocksBridgeAdapter`/`RealB46Tun2SocksBridge`,
`B46HysteriaProcessLauncher`/`RealB46HysteriaProcessLauncher`,
`B46HysteriaProbeRunner`, `B46HysteriaChildConfig`, `B46HysteriaDataPlaneConfig`,
`B46HysteriaTunNetworkConfig`. Reuses (moved, not duplicated)
`B46HysteriaSpikeState.kt`'s already-reviewed phase/error/status/transition
types from the pre-existing prep scaffold, additively extended with
`quicHandshakeConnected`/`socksListenerReady` observability fields and a
`withChildLogObservation` transition. Outdated "sing-tun-driven" comments
in that file were corrected to truthfully describe the tun2socks bridge.

- Real `VpnService` TUN: `10.203.46.1/24`, MTU 1400, DNS `1.1.1.1`/`1.0.0.1`
  (same values as production `VpnDnsPolicy`, duplicated rather than
  imported since the harness has zero dependency on `:app`), IPv4-only,
  `0.0.0.0/0` route (full tunnel).
- **`addDisallowedApplication` is never called** - confirmed by source
  inspection of `B46HysteriaVpnService.kt`'s `Builder` construction. The
  harness's own ordinary sockets (every in-app probe) are captured by this
  TUN exactly like any other app's traffic; only the Hysteria2 child's QUIC
  socket is excluded, and only via the real `protect(fd)` call.
- TUN ownership: `VpnService` owns the original `ParcelFileDescriptor` and
  closes it last; `tun2socks` receives only `ParcelFileDescriptor.dup(...).detachFd()`
  - a real duplicate raw fd, ownership transferred, never the original.
- Protect protocol: `RealB46HysteriaVpnProtectBridge` is a debug-owned
  re-implementation of the exact same protocol
  `RealShadowsocksVpnProtectBridge` already proves in production (Android
  `LocalServerSocket` listener, `ParcelFileDescriptor.dup()` on receipt,
  never reflection, never `/proc/<pid>/fd`).

## Bugs found and fixed during this physical run (real, not hypothetical)

1. **Wrong reflection method signature.** Assumed gobind would expose
   `StartBridge`/`StopBridge` (PascalCase, `int, int, String`). The real
   generated Java API is `startBridge`/`stopBridge` (camelCase,
   `long, long, String`, `throws Exception`) - confirmed via `javap` against
   the real committed AAR. First physical run failed with
   `NoSuchMethodException`. Fixed in `B46Tun2SocksBridgeAdapter.kt`.
2. **Log-line prefix mismatch.** The child's Go `log` package prefixes
   every line with a timestamp (`"2026/09/20 05:31:03 connected: ..."`).
   `SAFE_LOG_PATTERNS`'s `^`-anchored regexes and
   `B46HysteriaRuntime.onChildLogLine`'s `startsWith(...)` checks never
   matched, so `quicHandshakeConnected`/`socksListenerReady` silently
   stayed `false` in the UI despite the real events having happened (proven
   independently via logcat). Fixed by switching to unanchored
   `contains`/`containsMatchIn` matching; a realistic timestamped line was
   added to the regression test.
3. **Log-line/exit-code delivery race.** `RealB46HysteriaProcessLauncher`
   started its stdout/stderr drain threads synchronously in `init {}`, but
   callbacks were registered by the caller afterward - a fast child (this
   one logs "connected"/"SOCKS5_LISTENING" within ~100ms) could emit lines
   before a callback existed, silently dropping them (same class of bug for
   process-exit delivery). Fixed with a buffer-then-replay pattern for both
   log lines and the exit code.
4. **`android.system.Os.chmod` unreliable under the module's own unit-test
   stub jar** (`RuntimeException` from `toString()` on the framework stub),
   discovered while getting the harness's own unit tests green. Replaced
   with plain `java.io.File.setReadable`/`setWritable` (works identically
   on real Android and in plain JVM tests) for the config file's mode-600
   restriction.
5. **`org.json.JSONObject.toString()` silently returns `null` under the
   same stub-jar/`isReturnDefaultValues` setting.** Replaced `toJson()`
   with a small hand-built/escaped JSON string builder - simpler, and
   removes the whole class of stub-jar issues for this fixed schema.
6. **Severe: double-start orphaned an entire session (real leak, physically
   observed).** `B46HysteriaVpnService.handleStart()` constructed a **new**
   `B46HysteriaRuntime` unconditionally and only then checked
   `newRuntime.canStart()` - always `true` for a freshly-constructed
   instance, regardless of whether a previous session was still fully
   running. A stray extra tap of Start silently replaced `runtime` with a
   new instance, orphaning the first session's real child process, TUN dup
   fd, protect socket, and config file - `stop()` on the *new* instance had
   no reference to any of them. Physically observed: after a "clean" Stop,
   the real child process (`pgrep -af libnovahysteria`) was still running
   and the config/socket files were still present. Fixed by checking the
   **existing** `runtime` (if any) before constructing a new one, mirroring
   `B45ASpikeVpnService`'s own established pattern. Re-verified clean after
   the fix (see "Cleanup verification" below).

All of these are DEBUG/RESEARCH-only fixes inside `b46harness/` and
`research/b46-2p-android-physical/`; no production `:app` file was touched
to fix any of them.

## Temporary server-side infrastructure

- Preferred gateway (Frankfurt, Oracle Cloud): a temporary Hysteria2 test
  server was stood up, but **UDP reachability to a new ephemeral port
  (34443) failed** - `tcpdump` proved packets to an already-allow-listed
  port (51820, AWG) arrived while packets to 34443 never did, on an
  otherwise-correct setup. Classified as `B46_2P_GATEWAY_UDP_REACHABILITY_BLOCKED`
  (a cloud security-list block, not an Android/network defect), per the
  task's own explicit failure classification. Cleaned up fully (process
  killed, temp directory removed) before moving to the fallback.
- Fallback gateway (Stockholm, AWS, `16.170.208.231`): identical block
  initially reproduced (same tcpdump comparison method). The repository
  owner added a **temporary** inbound Security Group rule (UDP 34443,
  source `86.49.237.32/32`) - re-confirmed reachable via a fresh `tcpdump`
  capture showing the phone's real UDP packet arriving. **This AWS rule is
  still in place and must be removed after this document is read** - see
  "Owner follow-up required" below.
- Temporary server: stock upstream `hysteria` binary (server mode only,
  never the client architecture under test), same pinned commit, built
  fresh on the gateway. Ephemeral self-signed ECDSA P-256 cert (an initial
  Ed25519 cert caused a real `tls: handshake failure` - ECDSA P-256 was
  used instead, a real, physically-found TLS compatibility note for future
  reference), random `openssl rand -base64 24` auth password, mode-700
  temp directory, mode-600 key/config. Auth password was never printed to
  any terminal/log visible in this session - generated, consumed, and
  transferred entirely via redirected files and `scp`. Server fully
  stopped and its temp directory removed at the end of this slice;
  confirmed via `ps aux`/`ls` that nothing was left running or on disk.

### Pre-merge hardening correction (secret-delivery anti-pattern, found in review)

The physical run above originally staged the temporary server's `auth`
password into `b46harness/b46-hysteria-dataplane.properties`, which
`build.gradle.kts` then compiled directly into
`BuildConfig.B46_HYSTERIA_AUTH` - i.e. **the secret was baked into the
built debug APK**, not merely held in memory as an earlier draft of this
document incorrectly claimed. That the specific credential was disposable
and the temporary server has since been torn down does not make the
pattern acceptable to merge: a `BuildConfig` field is compiled into every
build using that properties file, and would resurface the same problem for
any future disposable-credential test run.

**This was corrected before merge, not after physically re-validating end
to end from scratch.** `BuildConfig` now carries only public/non-secret
values (server host, port, SNI, insecure flag, expected exit IP - see
`build.gradle.kts`). `auth` (and any future obfuscation secret) is instead
read at **runtime** from a single app-private file,
`<filesDir>/b46-secret/credential.properties`, that the operator provisions
**after install** via `adb push` to `/data/local/tmp` followed by a
`run-as net.pocvpn.b46harness` copy into app-private storage (mode 600) -
see `B46HysteriaRuntimeCredential.kt` for the exact protocol and
`B46HysteriaDataPlaneConfig.kt` for how it's merged with the public
`BuildConfig` values. The file is deleted on every stop path (normal and
failure), matching the same "provisioned once per session, deleted on
cleanup" discipline already used for the per-session child config file and
protect socket. `B46HysteriaChildConfig.toString()`/`redactedSummary()`
remain redacted as before - unaffected by this change, since the secret
was already never logged, only ever compiled in.

A short physical sanity cycle (new disposable credential, new temporary
server, one start/protect/QUIC/probe/stop cycle) was **attempted** to
re-validate the new runtime-provisioned credential path end to end, but
**not completed** - see "Post-hardening physical sanity cycle: BLOCKED"
below. The full two-cycle/restart/protect-failure/screen-lock evidence
above is unaffected by this change (it exercises the data plane and
protect(fd) mechanism, not credential delivery) and was not re-run.

### Pre-merge manual-review corrections (round 3, no live server needed)

A manual review (CodeRabbit remained stalled/unresponsive throughout this
round) found four further narrow issues, all fixed in this same PR before
any merge, none requiring a live server or re-running the physical
evidence above:

1. **Runtime credential consumption was best-effort, not verified.**
   `B46HysteriaDataPlaneConfig.resolve()` called a plain `delete()` and
   returned `Valid` regardless of whether the file was actually gone
   afterward - the stated "successful parse -> credential consumed ->
   file no longer exists -> only then Valid" invariant wasn't actually
   enforced. Replaced with `B46HysteriaRuntimeCredential.consumeDelete()`,
   which attempts deletion AND verifies the file is genuinely absent
   before allowing `resolve()` to return `Valid`; if verification fails,
   `resolve()` returns `Invalid` with a typed, non-secret reason and the
   caller never reaches TUN/bridge/child startup for that attempt. The
   same fix extends to `B46HysteriaRuntime.onProcessExitedUnexpectedly()`,
   which now deletes the generated per-child config file and protect
   socket immediately on an unexpected child exit (previously they could
   survive until an explicit Stop).
2. **Unknown child stderr/stdout content was still written to logcat**
   at `Log.d` level, despite the code's own comment already admitting it
   was "never assumed to contain no secret." Only a known-safe,
   allowlisted event shape is now ever passed to `Log.*` - all other
   content is delivered ONLY to the internal state machine, never to
   logcat, via a small pure decision function (`B46ChildLogFilter`) kept
   deliberately separate from `android.util.Log` so it is directly unit
   tested without Robolectric.
3. **`obfsSalamander` was never redacted in the Go child.** Only
   `authSecret` was stripped out of logged error text; `obfsSecret` is now
   tracked and redacted the same way, from both `--config-file` and (for
   host-research use) the `--obfs-salamander` flag.
4. **The standalone harness module still had AGP's implicit `release`
   build variant/type**, despite being documented everywhere as
   DEBUG/RESEARCH ONLY. Disabled via `androidComponents.beforeVariants`
   (`ApplicationVariantBuilder.enable = false`) - `:b46harness:assembleRelease`
   no longer exists as a task at all for this module, so no release
   harness APK can ever be produced, accidentally or otherwise. `:app`'s
   own release variant is completely unaffected (this module is never a
   dependency of `:app`).

None of these four required re-running the physical QUIC/data-plane
evidence recorded above - they are credential-lifecycle, logging, and
build-configuration corrections, verified by 20 new unit/Go tests (70
total Kotlin tests, 8 total Go tests, all passing) rather than a live
server.

### Post-hardening physical sanity cycle: BLOCKED (rule already removed, not reopened)

Before attempting to provision a new disposable credential and temporary
server, the existing UDP 34443 reachability to the Stockholm gateway
(`16.170.208.231`) was re-checked first, per explicit instruction not to
reopen that port without confirming the owner-added AWS Security Group
rule was still present: a bounded `tcpdump` was started on the gateway and
a real UDP packet was sent from the phone. **No packet arrived** - the
temporary AWS Security Group rule (UDP 34443, source `86.49.237.32/32`)
added earlier in this task has evidently already been removed (either by
the repository owner directly, or it was never as persistent as assumed -
either way, this session did not add or remove any cloud firewall rule at
any point in this pass).

Per explicit instruction, this session **did not reopen the rule** and
**stopped before the server-side physical sanity cycle**. The reachability
check's own temporary artifacts (a `tcpdump` capture directory) were
cleaned up on the gateway; nothing else was touched there.

**What this means:**

- The credential-hardening code change itself (BuildConfig field removal,
  `B46HysteriaRuntimeCredential`, the deletion-on-cleanup wiring, and the
  10 new focused tests) is complete, reviewed by its own test suite, and
  believed correct by construction (no live server was needed to prove the
  file-based credential resolution/fail-closed/cleanup logic - those are
  pure Kotlin/`java.io.File` unit tests, all passing).
- What is **not** re-proven by a fresh physical run is the specific
  end-to-end claim "the harness can read a runtime-provisioned credential
  file and successfully complete a real QUIC handshake with it" - that
  still rests on the ORIGINAL physical evidence earlier in this document,
  which used the (now-corrected) BuildConfig-based credential path, not
  this file-based one. The two mechanisms differ only in *where the secret
  string comes from* (a `BuildConfig` constant vs. a `Properties` file read
  at the same point in the same code path); nothing about the TUN/
  tun2socks/protect(fd)/QUIC mechanics changes.
- Completing this specific re-validation requires either the repository
  owner temporarily reopening the AWS Security Group rule again, or
  choosing an already-open port/gateway for a fresh disposable test.

## Physical run evidence

Two full successful cycles plus a controlled failure cycle plus a
screen-lock smoke test were run against the phone, in order:

**Cycle 1** (PID `18227`, started `2026-09-20T05:36:13Z`):
`FD_CONTROL_READY` reached with `protect requests=1, failures=0`; child
stderr showed the real chain `FD_PROTECT_SCM_RIGHTS: protect() succeeded`
-> `connected: udpEnabled=true tx=0` -> `SOCKS5_LISTENING addr=127.0.0.1:41080`.
In-app probes (DNS via `InetAddress.getByName`, HTTPS via `HttpsURLConnection`,
direct-IP TCP, raw UDP DNS query to `1.1.1.1:53` with transaction-ID/response-bit/RCODE
checks) all passed: `overall: ALL PASS`, exit IP `16.170.208.231` (exactly
matching the server's own real public egress IP, independently confirmed
via `curl https://api.ipify.org` run directly on the server). Live
server-side `tcpdump` during a probe re-run captured 70 real bidirectional
UDP packets (both `In`/phone->server and `Out`/server->phone), proving
genuine data-plane traffic, not just a handshake. `DATA_PLANE_READY`
reached only after this real probe success, never inferred from
process/protect alone. First clean stop verified: no orphaned child
process, no stale `10.203.46.1` TUN interface, empty working directory.

**Cycle 2** (PID `18608`, started `2026-09-20T05:37:08Z`, `18608 != 18227`):
identical full sequence repeated - `FD_CONTROL_READY`, real QUIC connect,
real SOCKS5 listener, all four probes pass (`ALL PASS`, same exit IP),
`DATA_PLANE_READY`, clean second stop verified the same way. Proves
restartability, not just a one-shot success.

**Controlled protect-failure test** (started `2026-09-20T05:37:47Z`, using
the harness's "CONTROLLED PROTECT-FAILURE TEST" action, which swaps in a
protector that returns `false` **without calling the real
`VpnService.protect()`** - production protect code itself was never
touched): real evidence chain - `B46HysteriaProtectBridge: protect() returned false`
-> child received `ack=0xff` -> child logged
`hysteria client construction/handshake failed: protect fd: protect() rejected: ack=0xff`
-> child exited with code 1 -> `RuntimeExitedUnexpectedly(exitCode=1)` ->
phase `ERROR`. `quicHandshakeConnected` stayed `false` throughout - no QUIC
session, no data-plane access, proving the child genuinely obeys the
FD-control result rather than ignoring a rejection. Explicit Stop from
`ERROR` cleaned up completely (no child process, no stale TUN, no leaked
files) - the required `ERROR -> STOPPING -> STOPPED` recovery path.

**Screen-lock smoke test** (real protector restored; started
`2026-09-20T05:38:25Z`, screen locked at `05:38:46Z`, woken at
`05:41:02Z`, ~136s elapsed): the real child PID (`19202`) was confirmed
still running immediately after wake (`pgrep`), the app phase was still
`DATA_PLANE_READY` with no intervening state change, and a fresh probe run
immediately post-wake passed all four checks again with no reconnect and
no new PID. This is a short physical smoke test only - it does **not**
claim the upstream long-idle Hysteria2 QUIC-idle issue is resolved, only
that ~136s of screen-lock did not visibly disrupt this session.

**Crash/ANR/leak scan**: `logcat` searched for
`FATAL EXCEPTION|ANR|SIGSEGV|SIGABRT|fdsan|double free|panic:|fatal error:`
scoped to `net.pocvpn.b46harness` across the entire run - zero matches
(only unrelated Play Protect app-scan and window-manager log lines
contained the package name).

**Optional cellular test**: not performed in this slice (time-bounded;
explicitly optional per the task). Classified `NOT TESTED`, not `FAIL`.

## DNS leak boundary

This slice verifies DNS works through the intended
TUN -> tun2socks -> SOCKS5 -> Hysteria2 path (real `InetAddress` resolution
and a real raw UDP query both succeeded through the tunnel). It makes **no
universal DNS-leak-safety claim** - that would require dedicated leak
testing (e.g. confirming no direct-path DNS query ever escapes the tunnel
under any condition), which is out of scope here.

## APK size observation (diagnostic only, not a release claim)

Harness debug APK: `10,783,234` bytes (~10.3 MB) with both native
libraries (`libgojni.so` 12.1 MB uncompressed, `libnovahysteria.so` 9.7 MB
uncompressed) packaged. This is a standalone single-purpose debug APK, not
comparable to Nova's own release APK size - no release-size claim is made.

## Cleanup verification (final)

- Real child process: none running (`pgrep -af libnovahysteria` empty)
  after the final stop.
- TUN: no `10.203.*` interface present.
- App-private working directory: empty (config file and protect socket
  both deleted).
- Temporary Stockholm Hysteria2 server: process killed, temp directory
  removed, port 34443 confirmed free again.
- No generated binary artifact (AAR, `.so`, server binary, TLS key, auth,
  temp config, pcap) is committed - all covered by `.gitignore`.

## Owner follow-up required

**AWS Security Group rule status, re-checked during the credential-hardening
pass:** a fresh reachability check (bounded `tcpdump` + a real UDP packet
from the phone) found the temporary rule (Stockholm, `16.170.208.231`, UDP
34443, source `86.49.237.32/32`) **no longer passing traffic** - it appears
to already be gone. This session did not remove it (nor did it ever add or
remove any cloud firewall rule at any point). If it is still present in the
AWS console for some other reason (e.g. reachability failed for an
unrelated cause), it should still be removed since it is not needed with
the temporary server already stopped; if it is already gone, no action is
needed. Re-opening it is required only if a future physical sanity cycle
for the runtime-credential-file path (see "Post-hardening physical sanity
cycle: BLOCKED" above) is wanted.

## Production safety (verified, not merely claimed)

- `git diff origin/main` touches only: `docs/`, `research/b46-2p-android-physical/`,
  `b46harness/` (new module), `android/settings.gradle.kts` (one `include`
  line + `projectDir`), `.gitignore`. `android/app/**` is byte-for-byte
  unchanged.
- No `TransportKind.HYSTERIA` was added. `TransportRegistry`,
  `SmartConnectDecisionEngine`, `AutoGatewaySelector`, `TransportOrchestrator`,
  production `VpnController`, `MainViewModel`, the production endpoint
  manifest, Frankfurt Shadowsocks, AWG, Xray, and B56 are all untouched.
- No firewall/security-group rule was modified without explicit owner
  action (the one AWS rule above was added by the repository owner
  themselves, not by this session).
- `field-test/b37-awg31-upgrade` was never touched.

## Remaining work (explicitly not done here)

- Production transport design/wiring (`TransportKind.HYSTERIA` does not
  exist; this harness is not reachable from any production code path).
- **Resolving the AAR-coexistence finding** if Hysteria2 is ever to run
  inside Nova's own `:app` process - either relocate one AAR's gomobile
  runtime classes/native symbols to a unique namespace, or accept running
  a Hysteria2-capable component in a genuinely separate app/process
  long-term.
- Signed public profile schema, credential provisioning, release
  packaging, legal review.
- Long-idle/mobile stability beyond the ~136s smoke test here (upstream
  issue `#1510` remains open, per B46-2B's own record).
- Restricted-network/Russia field evidence.
- Cellular network-diversity test (optional, not performed this slice).

## Files changed in this slice

- `docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md` (this file, new).
- `docs/ROADMAP.md` (B46 row updated).
- `research/b46-2p-android-physical/tun2socks-bridge/{bridge.go,go.mod,README.md}` (new).
- `research/b46-2p-android-physical/hysteria-minimal-client/{novaminimal_main.go,novaminimal_main_test.go,README.md}` (new).
- `b46harness/` (new standalone Android module: `build.gradle.kts`, `src/main/AndroidManifest.xml`, `src/main/java/net/pocvpn/b46harness/*.kt`, `src/test/java/net/pocvpn/b46harness/*.kt`).
- `android/settings.gradle.kts` (adds the `:b46harness` module include).
- `.gitignore` (adds `b46harness`/`research/b46-2p-android-physical` local-artifact entries).

No file under `android/app/` was modified.
