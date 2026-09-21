# B46-3C - Hysteria2 process-isolated data-plane physical validation

Status: **`B46-3C PROCESS-ISOLATED HYSTERIA2 DATA PLANE PHYSICALLY PASSED`**
(architecture/data-plane feasibility only - see Part 26's own precise
scope). All items in the full acceptance matrix passed with real,
physical evidence on the OPPO CPH2173. See `docs/ROADMAP.md`'s B46 row for
the authoritative status line.

Branch: `research/b46-3c-hysteria-process-isolated-dataplane`
Worktree: `C:\Users\akaza\Downloads\VPN-B46-3C`
Baseline: `origin/main` @ `75cb4b249da24dc5d13197b0cc016147d79e0a81`

## Part 1 - purpose

Prove the COMPLETE process-isolated Hysteria2 architecture end to end,
physically, including the real data plane - not merely process startup or
Android's own `Protected` UI state. B46-3B already proved process
isolation itself (no shared Go runtime, no crash); this slice proves that
architecture can actually carry real application traffic: DNS, TCP,
direct-IP TCP, UDP, correct exit identity, and server-side correlation,
with the real `protect(fd)` boundary physically exercised.

## Part 2 - B46-3A/B46-3B inheritance

- **B46-3A** (PR #99, unmerged): in-process Go `c-shared` + JNI bridge -
  `B46_3A_MULTI_GO_RUNTIME_COEXISTENCE_FAILED` (real Go GC/heap
  corruption when two independent Go runtimes shared one process).
- **B46-3B** (PR #109, unmerged): process-isolated tun2socks child (plain
  Go executable, `exec()`'d, never `dlopen()`'d) -
  `B46-3B PROCESS-ISOLATED ARCHITECTURE PHYSICALLY PASSED`, including a
  lifecycle-hardening pass (unexpected-child-death propagation,
  duplicated-fd ownership fix, `PR_SET_PDEATHSIG` parent-death
  protection).
- **B46-3C** (this slice) branches fresh from `origin/main` (NOT from
  B46-3B's branch, per the task's own instruction) and REUSES B46-3B's
  proven `Tun2SocksChild*` implementation by copying the files into this
  independently-reviewable branch (byte-identical `tun2socks-child`
  binary, SHA-256 confirmed matching - see Part 5), adding a THIRD
  process-isolated child (the minimal Hysteria2 client, reused unmodified
  from B46-2P/B46-2C) and the real data-plane proof this slice exists for.

## Part 3 - architecture

```
Android app process ("Xray process")
  - Xray gomobile Go runtime (loaded via LibXrayCoreRuntime, real, in at
    least one test - see Part 15)
  - Tun2SocksHysteriaDataPlaneSpikeVpnService (debug-only VpnService)
      - owns the ORIGINAL VpnService TUN ParcelFileDescriptor
      - RealHysteriaProtectBridge (wraps the real, already-production
        RealShadowsocksVpnProtectBridge - reused, not reimplemented)

tun2socks child (separate OS process)
  - plain Go executable, CGO_ENABLED=0, exec()'d - unchanged from B46-3B
  - receives a DUPLICATE TUN fd via SCM_RIGHTS
  - proxies TUN traffic to 127.0.0.1:41080 (the Hysteria child's own
    SOCKS5 listener)

minimal Hysteria2 child (separate OS process)
  - plain Go executable, reused UNMODIFIED from B46-2P/B46-2C
    (research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go)
  - listens on 127.0.0.1:41080 (SOCKS5)
  - dials the real Hysteria2 server over QUIC
  - protects its own outbound QUIC socket via the real protect(fd) bridge
    above (SCM_RIGHTS, same wire protocol RealShadowsocksVpnProtectBridge
    already proves in production)
```

No process ever contains two independent Go runtimes - confirmed
structurally (the tun2socks and Hysteria children are plain `exec()`'d
executables, never `dlopen()`'d) and physically re-confirmed with Xray
loaded in the app process during real data-plane traffic (Part 15).

## Part 4 - server provenance

| Field | Value |
|---|---|
| Provider | AWS, Nova-owned Stockholm instance (the SAME production gateway host B46-2P/B13 use - a NEW, isolated, temporary process was run on it, no production Xray/AWG/nginx config was touched) |
| Instance ID | `i-0a34c6a87e1dba4aa` |
| Region | `eu-north-1` (Stockholm) |
| Public IP | `16.170.208.231` |
| Hysteria version/commit | stock upstream `apernet/hysteria`, pinned commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` (same pin as B46-2P/B46-2C), built with `CGO_ENABLED=0 go build .` - unmodified |
| Server binary SHA-256 | `f36e6ac456532d6cc1a0ad9052eb9678ab46747964ff3298d4f2fdd135d7d026` |
| Config shape (secrets redacted) | `listen: :34443`, `tls: {cert: cert.pem, key: key.pem}` (self-signed, 2-day validity, `CN=b46-3c-test.local`), `auth: {type: password, password: <redacted, 32 hex chars, openssl rand -hex 16>}` |
| UDP test port | `34443` (same port B46-2P used, per the task's own suggestion) |
| Start timestamp | `2026-09-21T19:01:17Z` |
| Server PID | `8297` |
| Firewall/Security Group change | temporary inbound UDP 34443 rule, source `86.49.237.32/32` (the phone's own real public IP at test time - identical to B46-2P's own precedent source) - added by the repository owner directly (the agent has no AWS API/console credentials in this environment); removed by the owner after testing, independently reverified closed (see Part 22) |
| Credential handling | generated via `openssl rand -hex 16` entirely server-side, in a file the agent never `cat`'d to any terminal output; copied once to the agent's local scratchpad (never the repo), pushed to the phone's app-private storage via `adb shell run-as ... cat > files/b46-3c-auth.txt` (never argv, never an `adb -e` extra, never logcat); deleted from server, scratchpad, and device after testing (Part 22) |

## Part 5 - Android artifact provenance

| Field | Value |
|---|---|
| Git commit | `eaa9673fee11bd5326f7faeb3feac048353a9bf7` (`research/b46-3c-hysteria-process-isolated-dataplane`) |
| APK SHA-256 (debug) | `62cef2c506d6f2ebf6ed483ab679ec1638dffb0c88ed02fac0a3a6c19dd9ec4f` |
| Target ABI | `arm64-v8a` |
| `tun2socks-child` artifact | `libnovatun2sockschild.so`, SHA-256 `3ee51b0bbfec55f3b1f05c7b55057110fda1d9b64187822b6efeb9621349621f` - **byte-identical** to B46-3B's own hardened artifact (same source, same pins, same build command - confirmed by direct hash comparison, not merely "should be the same") |
| Hysteria child artifact | `libnovahysteriachild.so`, SHA-256 `ed3d020aa193f8cf9f097d9e7996636f772bb1e2450460a23b4d5eb740e3048b` - built from the unmodified B46-2P/B46-2C source against the pinned `e1366b17...` commit; verified zero `sing-tun`/`internal/tun` in `go list -deps`, zero `sing-tun`/`sagernet` symbols via `go tool nm`, zero `sing-tun` matches via `strings` |
| Xray AAR | `libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar`, SHA-256 `078578b99aa419d197fda35474ef49742329b8762f3073e40d1c0f54a2149084` - reused verbatim from B46-3A/B46-3B (same pin, same build, unmodified, never repacked) |
| AWG tunnel AAR | `amneziawg-tunnel-v3.1.20260814-debug.aar`, SHA-256 `2d5a241094bca8943eecadce746d77b51a335cf5adbc5f916767e20829165ee5` - unrelated to this slice, present only because it's a normal `:app` build dependency |

`:app:checkDebugDuplicateClasses` and `:app:assembleDebug`: both
`BUILD SUCCESSFUL` with all three native artifacts (Xray + tun2socks-child
+ hysteria-child) staged simultaneously. APK native-library inventory
confirmed via `unzip -l`: exactly one `libgojni.so` per ABI (four total),
plus `libnovatun2sockschild.so` and `libnovahysteriachild.so` (arm64-v8a
only, this research pass's own scope).

## Part 6 - process isolation

Confirmed the same way B46-3B already proved it, plus a third boundary:
`ps -A -o PID,ARGS` on the physical device during a live session shows
THREE distinct OS processes for the app, the tun2socks child, and the
Hysteria child, each with its own real PID (see Parts 16/17 for the exact
PIDs recorded per cycle). Neither child ever calls `dlopen()` on
`libgojni.so` - structurally impossible, since both are plain `exec()`'d
executables with no code path that could load it.

## Part 7 - TUN ownership

Unchanged from B46-3B's own proven fd-ownership contract:
`Tun2SocksProcessIsolatedSpikeVpnService`'s successor,
`Tun2SocksHysteriaDataPlaneSpikeVpnService`, is the SOLE owner of the
original `VpnService`-issued `ParcelFileDescriptor`; only a duplicate
(`ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`) is ever
handed to `Tun2SocksChildRuntime.start()`, which owns it from that instant
(B46-3B's own Gap 2 fix, reused verbatim - see that PR's own Part 24).
TUN config for this slice is a REAL full tunnel (unlike B46-3A/B46-3B's
own narrow, safety-only routes): `10.206.49.1/24`, MTU 1400, DNS
`1.1.1.1`/`1.0.0.1`, `0.0.0.0/0` - identical values to B46-2P's own real
physical validation. `addDisallowedApplication` is deliberately never
called (same B46-2P precedent): this app's own in-app test traffic (the
DNS/TCP/UDP probes below) is captured by the TUN exactly like any other
app's traffic - only the Hysteria child's own QUIC socket is excluded, and
only via the real `protect(fd)` call (Part 8).

## Part 8 - protect boundary

**PASSED, physically, with positive evidence - not inferred from
successful traffic.** Real logcat line from the Hysteria child's own
stderr, captured during Cycle 1:

```
FD_PROTECT_SCM_RIGHTS: protect() succeeded via /data/user/0/net.pocvpn.client/files/b46-3c-hysteria/b46-3c-hysteria-protect.sock for fd=3
```

This confirms the full real chain: the Hysteria child requested
protection for its own outbound QUIC socket fd -> the real
`RealShadowsocksVpnProtectBridge` (reused unmodified, not reimplemented)
received it over SCM_RIGHTS -> `VpnService.protect(fd)` was called and
returned `true` -> the child received a positive ack -> the QUIC handshake
then proceeded and succeeded (`connected: udpEnabled=true`, same log
burst, ~100ms later). The negative-protect controlled-failure test (task's
own optional item) was NOT separately run in this pass - the positive
proof above, combined with B46-2P's own prior controlled-negative-protect
evidence (same wire protocol, same fail-closed behavior already proven
there), was judged sufficient given this pass's already-large scope; not
re-litigating an already-proven protocol path.

## Part 9 - DNS proof

**PASSED.** `httpGetThroughTunnel("https://icanhazip.com")` performs a
REAL hostname resolution (`icanhazip.com`) through the tunnel's own
configured DNS servers (`1.1.1.1`/`1.0.0.1`, reached via TUN -> tun2socks
-> Hysteria's SOCKS5 UDP path) followed by a real HTTPS connection to the
resolved address - not merely inspecting `LinkProperties`. Result:
`exitIp=16.170.208.231` returned successfully on every cycle (Cycle 1,
Cycle 2, post-screen-off) - the resolution AND the subsequent connection
both had to succeed for this string to come back at all.

## Part 10 - TCP proof

**PASSED.** The same `https://icanhazip.com` request above is also the
real TCP (HTTPS/TLS) proof - a full TCP handshake, TLS handshake, HTTP
request/response cycle, through the tunnel, on every cycle.

## Part 11 - direct-IP proof

**PASSED.** `directIpTlsConnect("1.1.1.1", 443, "one.one.one.one")` -
connects directly to Cloudflare's well-known IP by raw IP (no DNS
resolution for the destination itself - only route resolution through the
already-established TUN/tun2socks/SOCKS chain), performs a real TLS
handshake, and confirms a valid TLS session. This distinguishes DNS-path
failure from general TCP/data-plane failure per the task's own
requirement. Exercised in Cycle 1.

## Part 12 - UDP proof

**PASSED - a real, distinctly-UDP application-level round trip, not
inferred from DNS or from QUIC merely existing between client and
server.** `ntpRoundTrip("time.cloudflare.com")` implements a minimal
RFC 5905 NTP client: sends a real 48-byte NTP request datagram to
`time.cloudflare.com:123` and receives a real 48-byte response - this
genuinely traverses TUN -> tun2socks -> SOCKS5 UDP ASSOCIATE -> Hysteria's
own QUIC datagram/UDP-over-QUIC transport -> the real NTP server ->
return path. Exercised in Cycle 1, Cycle 2, and the post-screen-off probe
- passed every time.

## Part 13 - exit proof

**PASSED.** Every `icanhazip.com` fetch across every cycle returned
EXACTLY `16.170.208.231` - the authorized Stockholm server's own real
public IP, confirming egress genuinely happens via that server (a direct
dial, no further relay), never a different/unexpected path.

## Part 14 - server correlation

**PASSED.** A bounded `tcpdump -ni any udp port 34443` capture was run
server-side DURING Cycle 2 (25s window, port-scoped, no unrelated
payload/user traffic captured): **279 packets**, real bidirectional QUIC
traffic (large 1250/1280-byte UDP datagrams typical of QUIC, both
`ens5 In` from `86.49.237.32` and `ens5 Out` back to it) correlating
exactly with the client-side test window and the two distinct QUIC
sessions Cycle 2 established. Representative captured lines:

```
19:18:40.585663 ens5  Out IP 172.31.36.199.34443 > 86.49.237.32.17067: UDP, length 61
19:18:41.306970 ens5  In  IP 86.49.237.32.17034 > 172.31.36.199.34443: UDP, length 1250
19:18:41.308095 ens5  Out IP 172.31.36.199.34443 > 86.49.237.32.17034: UDP, length 1280
```

(`172.31.36.199` is the instance's own private IP, NAT'd to its public
`16.170.208.231` - the same host.)

## Part 15 - Xray coexistence

**PASSED.** Cycle 1 (`cycle1_full_dataplane_proof`) explicitly loads the
real Xray Go runtime in the app process FIRST
(`LibXrayCoreRuntime().ensureCoreEnvInitialized(context)` - the same real,
no-network, no-VPN production entry point B46-3A/B46-3B already used) and
confirms `xray.isRunning == false` both before AND after the full
Hysteria data-plane session. No Go runtime fatal error of any kind
appeared anywhere in logcat throughout (grepped for `bad flushGen`,
`addspecial on invalid pointer`, `fatal error:`, `FATAL EXCEPTION`, ANR,
native crash/tombstone signatures - zero matches across the entire test
run). This is the direct, physical answer to the reason B46-3A/B46-3B/
B46-3C exist at all: Xray's Go runtime and the two child Go runtimes
coexisted, with real Hysteria2 data-plane traffic actively flowing,
without incident. Independently re-verified via a full-session `logcat -d`
grep for the exact B46-3A fatal-error signatures plus general crash
signatures (`bad flushGen`, `addspecial on invalid pointer`,
`FATAL EXCEPTION`, `ANR in`, `tombstone`, `SIGSEGV`, `SIGABRT`) across the
ENTIRE test session (all cycles, both child-death tests, the screen-off
test) - zero matches.

## Part 16 - Cycle 1

Real evidence, in order:

```
FD_PROTECT_SCM_RIGHTS: protect() succeeded via .../b46-3c-hysteria-protect.sock for fd=3
connected: udpEnabled=true tx=0
SOCKS5_LISTENING addr=127.0.0.1:41080
B46_3B_CHILD_STARTED: pid=27747 mtu=1400 socksAddr=127.0.0.1:41080
cycle1: tun2socksPid=27747 appPid=27675 quicConnectedAtStart=true
cycle1: exitIp=16.170.208.231
```

- App pid: `27675`
- tun2socks child pid: `27747`
- Hysteria child: started, real QUIC connection established
  (`udpEnabled=true`), real SOCKS5 listener ready
- Direct-IP TLS proof: passed (part of the same test's own assertions)
- UDP (NTP) proof: passed
- Xray coexistence: loaded, healthy throughout
- Result: `Tests run: 1, Failures: 0`, clean disconnect afterward

## Part 17 - Cycle 2

Real evidence:

```
connected: udpEnabled=true tx=0        (first sub-session)
SOCKS5_LISTENING addr=127.0.0.1:41080
B46_3B_CHILD_STARTED: pid=28128 mtu=1400 socksAddr=127.0.0.1:41080
connected: udpEnabled=true tx=0        (second sub-session, after an explicit stop+restart)
SOCKS5_LISTENING addr=127.0.0.1:41080
B46_3B_CHILD_STARTED: pid=28234 mtu=1400 socksAddr=127.0.0.1:41080
cycle2: firstPid=28128 secondPid=28234
```

- First tun2socks child pid: `28128`; second (fresh, after a real
  stop+restart): `28234` - **genuinely distinct pids, assertion enforced
  in the test itself, not merely observed**
- Both sub-sessions independently re-proved exit IP (`16.170.208.231`) and
  the NTP UDP round trip
- Server-side correlation (Part 14) captured during this exact cycle: 279
  real bidirectional QUIC packets
- Result: `Tests run: 1, Failures: 0`

## Part 18 - tun2socks child death (during real data-plane traffic)

**PASSED - the strongest lifecycle gate, stronger than B46-3B's own
mechanics-only version.** A real session was established, the real
data-plane proof (`exitIp=16.170.208.231`) was confirmed FIRST, THEN the
tun2socks child was killed:

```
child exited unexpectedly: code=137
tun2socks child exited unexpectedly: code=137 - tearing down the whole session
```

`code=137` = `128 + 9` = the real `SIGKILL` exit status - not a timeout,
not a coincidence. The test then confirmed, automatically (no manual
`ACTION_STOP` involved until the very end): the service reached a terminal
`Failed` status, and the TUN interface (`ip link show`) was genuinely torn
down. Result: `Tests run: 1, Failures: 0`.

## Part 19 - Hysteria child death (during real data-plane traffic)

**PASSED.** Same shape as Part 18, this time killing the Hysteria child
mid-session (found via `ps -A -o PID,ARGS` matching the binary's own
resolved filename, per the task's own allowance since the unmodified
upstream binary reports no pid over any wire protocol):

```
hysteria child pid=28822
hysteria child exited unexpectedly: code=137
hysteria child exited unexpectedly: code=137 - tearing down the whole session
```

Again `code=137` (real `SIGKILL`), automatic whole-session teardown (both
the Hysteria child's own runtime AND the still-alive tun2socks child were
stopped together - `handleUnexpectedExit` in
`Tun2SocksHysteriaDataPlaneSpikeVpnService` tears down BOTH runtimes
regardless of which one died, per this slice's own design). Result:
`Tests run: 1, Failures: 0`.

## Part 20 - screen-off

**PASSED - smoke test only, per the task's own instruction; no
long-duration stability claim.** Real session established, real
data-plane proof confirmed, screen turned off via
`input keyevent KEYCODE_SLEEP`, held off for the full ~130 seconds, screen
turned back on via `input keyevent KEYCODE_WAKEUP`, then the SAME
DNS/TCP/exit and UDP (NTP) probes were repeated:

```
screen-off smoke: exitIpAfter=16.170.208.231
```

Total test wall-clock time: `133.3s` (130s sleep + real setup/probe
overhead). The tunnel was still fully usable - same exit IP, real UDP
round trip still succeeding - after the screen-off interval. Result:
`Tests run: 1, Failures: 0`.

## Part 21 - device cleanup

**PASSED, physically verified after the final test:**

```
$ adb shell am force-stop net.pocvpn.client
$ adb shell ps -A | grep -E "novatun2sockschild|novahysteriachild"
(no output - zero matching processes)
$ adb shell ip link show | grep -i tun
(no output - no stale TUN interface)
$ adb shell run-as net.pocvpn.client ls -la files/b46-3c-hysteria/
total 6  (only . and .. - config file and protect socket both deleted by
          the app's own real cleanup logic, not manually)
```

The `b46-3c-auth.txt` credential file (pushed manually before testing, not
part of the app's own runtime artifacts) was explicitly deleted afterward:
`adb shell run-as net.pocvpn.client rm -f files/b46-3c-auth.txt`, then
re-verified absent.

## Part 22 - server/firewall cleanup

**PASSED, physically verified:**

1. Temporary Hysteria2 server process stopped:
   `pkill -f 'hysteria-server-linux-amd64 server'`; `pgrep -af hysteria-server`
   returned empty; `ss -ulnp | grep 34443` returned empty (no longer
   listening).
2. All disposable server material removed:
   `rm -rf ~/b46-3c-test` (binaries, config.yaml, the disposable auth
   credential, the self-signed cert/key, the pinned `hysteria` source
   checkout, server logs) - `ls ~/ | grep b46-3c` confirmed empty
   afterward.
3. The local scratchpad copy of the disposable credential was deleted
   immediately after use (never committed, never part of this repo's
   working tree at any point).
4. **The temporary AWS Security Group rule (inbound UDP 34443, source
   `86.49.237.32/32`) was removed by the repository owner directly** (the
   agent has no AWS API/console credentials in this environment - the
   owner both added and removed this rule, matching B46-2P's own
   established precedent for this exact class of action).
5. **Independent reachability re-check after removal - PASSED, run
   twice:** the same probe technique used earlier to confirm the rule was
   OPEN (`sudo tcpdump -ni any udp port 34443 -c 1 -w probe.pcap`
   server-side while sending a real UDP packet from the phone via
   `adb shell nc -u -w1 16.170.208.231 34443`) now captures **zero
   packets** (`0`-byte pcap file, both times) - the earlier-open rule
   genuinely no longer passes traffic. `ss -ulnp | grep 34443` also
   confirms nothing is listening on that port any more (the server
   process itself was already stopped in step 1). All leftover debug
   `.pcap` files removed from the server afterward.

## Part 23 - security/secret handling

- The disposable Hysteria auth credential was generated with
  `openssl rand -hex 16` entirely on the remote server - never typed,
  generated, or echoed on the local agent machine.
- The credential was copied exactly once, machine-to-machine (`scp`), into
  the agent's LOCAL SCRATCHPAD directory (outside this repository's
  working tree) - never into any file under `research/`/`android/`/`docs/`.
- The credential reached the phone via `adb shell run-as net.pocvpn.client
  sh -c 'cat > files/b46-3c-auth.txt'`, fed from the local scratchpad file
  via stdin - never as an `adb -e` Intent-extra command-line argument
  (which WOULD have been visible in shell history), never as an argv
  parameter to any process.
- The instrumentation test reads the credential from app-private storage
  at runtime and passes it to the service via `Intent.putExtra` from
  Kotlin code running in-process - Android does not log Intent extra
  values by default, and none of this agent's own tool calls ever printed
  the credential's contents to this conversation's transcript.
- The Hysteria child's own `--config-file` mechanism (B46-2P's own
  established design) keeps the credential out of argv/process-title on
  the Android side too - `--auth` is never passed.
- A secret scan (grep for password/secret/api-key/private-key/BEGIN-RSA/
  token patterns) was run across every new/changed file before commit -
  see Part 25 for the exact result.
- No credential appears in this document, in any commit message, in any
  logcat line quoted above, or in the PR body.

## Part 24 - licensing

Unchanged from B46-2C/B46-2P/B46-3A/B46-3B: `xjasonlyu/tun2socks` (MIT),
`gvisor.dev/gvisor` (Apache-2.0), the minimal Hysteria2 client (built from
`apernet/hysteria`'s own MIT-licensed `core`/`app` packages, reusing only
`app/internal/socks5`, never `app/internal/tun`), the QUIC stack
(`quic-go`, MIT, transitively). Symbol audit for THIS pass's own two new
artifacts (Part 5) confirms zero `sing-tun` (either fork) in both. This is
an ENGINEERING finding only - explicitly not legal clearance, per every
prior B46 slice's own standing wording.

## Part 25 - limitations

- The negative-protect controlled-failure test (task's own OPTIONAL item)
  was not separately re-run in this pass - B46-2P's own prior evidence for
  the identical wire protocol already covers it; not re-litigated here
  given this pass's already-large real scope.
- The screen-off test is a smoke test only (~130s) - no claim of
  long-duration (multi-hour/multi-day) mobile stability is made or implied.
- Server correlation (Part 14) was captured for Cycle 2 only, not every
  cycle - one clean, bounded, port-scoped capture was judged sufficient
  evidence per the task's own "packet count and timing only as needed"
  guidance, rather than repeating an already-proven capture.
- This remains a RESEARCH-ONLY, debug-only spike
  (`Tun2SocksHysteriaDataPlaneSpikeVpnService`) - no production Hysteria
  transport exists; `TransportKind.HYSTERIA` was not added (Part 26).
- The Stockholm test instance is Nova's real production gateway host - the
  temporary Hysteria2 process and Security Group rule were fully isolated
  from and did not touch any production Xray/AWG/nginx configuration, but
  this pass did run real (if disposable, if temporary) additional
  infrastructure on a production host, per the repository owner's explicit
  authorization for this specific task.

## Part 26 - decision gate

**`B46-3C PROCESS-ISOLATED HYSTERIA2 DATA PLANE PHYSICALLY PASSED`.**

All 17 items of the task's own full acceptance matrix passed with real
physical evidence: real Android `VpnService` TUN; process-isolated
tun2socks child; process-isolated Hysteria2 child; `protect(fd)` positive
proof; real QUIC connection; DNS application proof; TCP application proof;
direct-IP TCP proof; UDP application proof; expected exit proof;
server-side correlation; clean disconnect; no orphan processes; no stale
TUN; no stale UDS/control socket; no stale credential/config file; a
second independent successful connection cycle with genuinely fresh PIDs.
Plus: real Xray coexistence during live data-plane traffic, real
mid-traffic child-death recovery for BOTH children independently, and a
real ~130s screen-off smoke test.

This does NOT mean: works in Russia or against real-world restricted
networks (never tested); bypasses hard whitelists; production ready (this
remains a debug-only research spike); legal clearance (Part 24's own
wording); long-duration stable (Part 25's own limitation). Those all
remain separate, future gates.

Per the task's own explicit instruction: **stopping here.** No production
integration (`TransportKind.HYSTERIA`, Smart Connect wiring, production
manifest, production user provisioning) was performed or will be without a
separate, explicit instruction.
