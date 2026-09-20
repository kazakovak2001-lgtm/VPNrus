# B45B-4P — Shadowsocks 2022 Selection Wiring: Physical Validation Attempt

## Status: NOT PASSED — data-plane proof still failing; the disconnect/ownership bug found in the first attempt is now fixed (§5b); the DNS fix is physically proven (§7) and the real root cause of the data-plane failure is now identified (§7)

This is a truthful record of a real physical validation attempt of the B45B-4
selection wiring, run end to end through the production pipeline (Smart
Connect -> TransportOrchestrator -> VpnController -> real `ShadowsocksTransport`
-> real `sslocal`) on a real OPPO CPH2173 device (`c618ee06`) against the
real Frankfurt production gateway (`152.70.43.1`). It is **not** a pass
record - see "What failed" below. Recorded now anyway (truthfully, not as a
pass) because the reproducible-artifact provenance and the newly found bug
are both real, useful facts for whoever continues this.

## 1. Reproducible `sslocal` artifact (toolchain-pinned, not byte-identical to the historical B45A/B45B-3P artifact)

The B45B3P historical artifact's exact original compiler/toolchain version
was never recorded, so it cannot currently be reproduced from first
principles. This is a **separate, newly-established** reproducible build,
built twice from a clean `target/` with the identical toolchain both times
and producing an identical hash both times:

- Source: `shadowsocks/shadowsocks-rust`, tag `v1.25.0`, commit
  `ab388c7466d21f979430e33cc9ef10e22fb05955` (verified exact against upstream
  before building)
- Build command (unmodified from the pinned B45B3P command):
  `cargo ndk -t arm64-v8a -P 26 -- build --release --bin sslocal --no-default-features --features "local,local-tun,aead-cipher-2022"`
- Toolchain: `rustc 1.98.1` (48a229cea, 2026-09-01), `cargo 1.98.1`,
  `cargo-ndk 4.1.2`, Android NDK r27 (27.0.12077973), Linux prebuilt
- Resulting binary: 2,872,464 bytes (pre-strip-adjacent as produced; already
  stripped by the release profile), ELF 64-bit LSB PIE executable, ARM
  aarch64, Android API 26, `NEEDED`: only `libc.so`/`libdl.so`
- **SHA-256 (this toolchain tuple): `b8c8526055586d0175d12cdc9432a78146eff986b68aac3dc6d85dfd82716e79`**
  - Confirmed **reproducible**: two independent clean builds from the same
    checkout produced this exact hash both times.
  - This does **not** match, and is not claimed to match, the historical
    B45A/B45B-3P artifact hash below - different compiler version, not a
    different source or build command.

## 2. Historical artifact (kept as historical evidence, never overwritten)

- **SHA-256: `333eafee26e5e7fdad91892bdb7400ad397e7d7f99d42f26b37c8ca92bc2c1f6`**
- Same source/commit/build command as above; original exact `rustc`/NDK-clang
  patch version was never recorded at the time, which is why it cannot be
  reproduced from this session. See `B45B3P_SHADOWSOCKS_PHYSICAL_VALIDATION.md`
  for its own full provenance.

## 3. What was verified working, with real evidence

- **Live Frankfurt Shadowsocks test service** (`b45a-ssserver.service`,
  read-only-inspected via SSH): present, active, listening TCP+UDP on port
  `28388`, method `2022-blake3-aes-256-gcm`, mode `tcp_and_udp`.
- **Real activation credential issuance**: `gateway/tools/activation_tokens.py issue`,
  run on the live host against the live `/var/lib/pocvpn-activation/activations.json`
  store, issued a real, time-boxed (`max_devices=1`, 1-day expiry) activation
  credential through the normal operator path - no fabricated record.
- **Real device activation**: entered through the app's own normal
  activation screen; persisted on-device (`client_identity.bin`,
  `provisioned_profile.bin`, `client_tunnel_identity.txt`,
  `xray_profile_frankfurt-*.bin` all present under the app's `no_backup`
  storage after activation).
- **Real matching Shadowsocks credential**: the actual live `password` field
  was read from Frankfurt's own `/etc/b45a-shadowsocks/server.json` over SSH
  (piped straight to a local file, never printed/logged to any terminal or
  transcript) and provisioned into the real, endpoint-scoped
  `Shadowsocks2022CredentialRepository` for `frankfurt`, replacing the
  earlier synthetic test credential, via the existing debug validation
  harness (`ShadowsocksAdapterValidationActivity`) - reused as designed, no
  second credential mechanism.
- **Real runtime evidence of registry/selection** (not filesystem inference):
  the live Diagnostics dialog's "Transport scores" line showed
  `SHADOWSOCKS_2022=20`, on par with every other real transport for this
  gateway, and forcing `Manual(SHADOWSOCKS_2022)` via the (newly added, see
  below) debug control and connecting genuinely invoked the real adapter -
  never AWG/Xray.
- **Real `sslocal` process**: PID `18820`, full command line captured
  (`libsslocal.so -c .../runtime_config.json --protocol tun --tun-device-fd-from-path .../tun_fd_path --tun-interface-address 10.202.46.1/24 --vpn -U`).
- **Real SCM_RIGHTS TUN fd handoff**: `ShadowsocksTunFdBridge` logged
  `handed off tun fd to .../tun_fd_path`; the OS's own `registerNetworkAgent`
  log line independently confirms `tun0` with `10.202.46.1/24`, matching.
- **Real protect-bridge socket**: `protect_path` UDS present alongside
  `tun_fd_path` in the app's own private storage.
- **State reached Connected/Protected**, with the OS-level VPN network
  capabilities correctly naming the session (`VpnTransportInfo{sessionId=Nova
  Shadowsocks 2022 ...}`) - genuinely the Shadowsocks adapter, not a fallback.

## 4. What failed - the actual data-plane proof

Real TCP attempts through the tunnel (to `152.70.43.1:80`, `152.70.43.1:443`,
and an unrelated `1.1.1.1:443` control) all showed the same pattern: the
local connection appeared to "connect" (SYN-ACK observed by `curl`), then no
application data ever returned, timing out after 8s every time. Cross-checked
directly against the real server: **`journalctl -u b45a-ssserver.service`
on Frankfurt showed zero new log entries during the entire connection
window** - the real server never received a single inbound connection from
this device during any of these attempts.

**Conclusion: the data-plane proof did not pass.** "Protected" in the UI and
"VALIDATED" in Android's own network capabilities are not sufficient proof by
themselves (this file explicitly does not count them as such, per this
task's own instruction) - independent, server-side evidence contradicts
them. The most likely explanation, not yet root-caused, is that `sslocal`'s
own outbound connection to the real server (which must be `protect()`-ed to
avoid being captured by its own `tun0`) never actually leaves the device -
but this is a hypothesis, not a confirmed diagnosis, and is explicitly left
for a follow-up investigation rather than guessed at further here.

UDP proof and the restart/second-connect proof were **not attempted**, since
they would only be meaningful once the TCP data-plane proof itself passes.

## 5. A second, independent bug found: UI/ownership divergence after failure

After the failed data-plane attempt, the app's own UI transitioned to
"Disconnected" on its own (without any disconnect being tapped) - but the
real `sslocal` process (PID `18820`) and the real `tun0` interface were
**still alive** at that point, confirmed directly (`ps -A`, `ip addr show
tun0`), several seconds after the UI already reported "Disconnected". This
is a genuine ownership/cleanup gap: the app's own state model diverged from
the actual OS-level VPN/process ownership it should have already torn down.
An `am force-stop` was required to actually clean up the orphaned process
and interface. This is a real bug for the Shadowsocks adapter's failure path,
separate from the data-plane connectivity issue above, and is recorded here
for a future fix - not something this task attempted to diagnose or repair.

## 5b. Fix slice 1 — the disconnect/ownership cleanup bug (§5) is fixed

Root cause, traced through the real production classes (`ShadowsocksTransport`,
`ShadowsocksVpnService`) - two compounding bugs, both in the disconnect path,
never in `ShadowsocksRuntime` itself (already correct and already covered by
`ShadowsocksRuntimeTest`):

- **Bug A**: `ShadowsocksTransport.disconnect()` had an early-return shortcut -
  whenever `state` already reported `TransportState.Error`, it set
  `Disconnected` directly and returned **without ever sending
  `ShadowsocksVpnService.ACTION_STOP`**, wrongly assuming Error always means
  the service/process/TUN were already torn down. They are not guaranteed to
  be.
- **Bug B**: even on the normal path, `ShadowsocksVpnService.teardown()` set
  its companion `status` flow straight to `null` on a genuine stop -
  `ShadowsocksTransport`'s own status collector explicitly ignores a `null`
  status, so a real, successful teardown never reported back to the
  transport's own `state`, which would then get stuck on `Disconnecting`
  forever. `teardown()` also ran synchronously on the calling thread
  (`onStartCommand`, always the main thread for a Service), blocking up to
  ~4s on `ShadowsocksRuntime.stop()`'s own bounded wait - a latent ANR risk.

Fix: `disconnect()` now always sends `ACTION_STOP` unless `state` is already
genuinely `Disconnected` (the one case that IS safe to skip), and
deterministically waits (bounded, forced-Disconnected on timeout) for a real
terminal state rather than firing-and-forgetting. `teardown()` now publishes
a real `ShadowsocksRuntimePhase.STOPPED` status (mapped to
`TransportState.Disconnected`) instead of `null`, and is dispatched off the
main thread. No changes to `ShadowsocksRuntime`, `TransportOrchestrator`, or
AWG/Xray lifecycle behavior.

**Physically re-verified end to end on the same device**, using the same
real Frankfurt activation and the same real matching Shadowsocks credential
from §3 (nothing re-provisioned):

- Connect 1: `sslocal` PID `23564`, TUN `10.202.46.1/24`, both bridge sockets
  present, UI Protected.
- Disconnect 1: UI Disconnected; `sslocal` process **gone**, `tun0` **gone**,
  both bridge sockets **gone** - no `am force-stop` needed this time.
- Connect 2: forced `Manual(SHADOWSOCKS_2022)` again, **new** `sslocal` PID
  `24795` (confirmed different from PID `23564`), same real TUN config, UI
  Protected again.
- Disconnect 2: clean teardown again - process gone, TUN gone, sockets gone,
  UI Disconnected.
- No crash, no ANR, at any point (checked directly against logcat for
  `FATAL EXCEPTION`/`ANR in`/`Force finishing activity` - none found).

The lifecycle/ownership bug from §5 is fixed and physically confirmed twice.
**This does not touch or claim anything about §4** (the TCP data-plane
proof) - that failure is unchanged and still open.

## 6. What remains explicitly UNVERIFIED (unchanged from B45B-4)

- Wi-Fi/cellular handover (Q7)
- Russia/restricted-network behavior
- Hard-whitelist behavior
- ~~The actual root cause of the data-plane failure in §4~~ — now identified, see §7
- The ownership/cleanup bug in §5 — fixed, see §5b

## 7. DNS fix physically re-verified; the real data-plane root cause is now identified (this session)

Re-run on the same PR head plus one small, non-secret diagnostic-logging
commit (`1138851116d9cc1df50c99cb208772a43b017ec3` — no behavior change),
device OPPO CPH2173 (`c618ee06`, arm64-v8a, Android 14), reusing the exact
pinned `sslocal` artifact (SHA-256
`b8c8526055586d0175d12cdc9432a78146eff986b68aac3dc6d85dfd82716e79`,
independently rebuilt bit-for-bit reproducible in this session too).

**DNS fix (`VpnDnsPolicy.servers.forEach { builder.addDnsServer(it) }`)
is physically proven at the Android network layer.** With the Shadowsocks
tunnel up, `dumpsys connectivity`'s `NetworkAgentInfo` for the
`Nova Shadowsocks 2022` VPN network showed real, non-empty
`DnsAddresses: [ /1.1.1.1,/1.0.0.1 ]` on `LinkProperties{InterfaceName: tun0}`
— configuration-level proof the fix reaches Android's real VPN interface.
This alone does not prove resolution works end to end (see below - the
underlying data plane is still broken), but it closes the specific gap the
fix targeted (an interface with a route but no DNS server of that family).

**Selection, process, TUN, and protect bridge are all real and working.**
Two full connect/disconnect cycles were run through the real production
pipeline (Diagnostics → "Force SHADOWSOCKS_2022 on next connect" [a
one-shot preference, consumed by the very next connect attempt — must be
re-set before every connect] → Home power button):
- First cycle: `sslocal` PID 5092 (rebuilt-artifact PID: 7078/9060 across
  re-attempts), `tun0` = `10.202.46.1/24`, `--protocol tun
  --tun-device-fd-from-path ... --tun-interface-address 10.202.46.1/24
  --vpn -U` confirmed via `/proc/<pid>/cmdline`.
- Second cycle: `sslocal` PID 10630 — a genuinely new PID, confirming a
  fresh process per connection, not a reused/stale one.
- Both disconnects (normal Home power button, never `force-stop`) left:
  no `sslocal` process, no `tun0` interface, and an empty
  `files/shadowsocks/` working directory (`protect_path`/`tun_fd_path`/
  `runtime_config.json` all gone) — the §5b cleanup fix holds under two
  independent real cycles.
- No `FATAL EXCEPTION`, `ANR in`, or `Force finishing activity` anywhere
  in the session's logcat.
- A quick post-test AmneziaWG connect/disconnect confirmed Shadowsocks
  left no stale VPN ownership blocking another transport.

**The data plane still fails — zero bytes ever reach the real server —
and the root cause is now proven, not merely observed.** Server-side
`tcpdump -i any port 28388` (two independent 180s windows, one per
connect cycle) captured **zero packets** on both TCP and UDP, and
`journalctl -u b45a-ssserver.service --since <test-start>` showed **no
entries** for either window. On-device: a domain HTTPS request
(`https://icanhazip.com`) and a direct-IP request (`https://1.1.1.1`)
both failed (DNS resolution timeout / TCP connection timeout) — ruling
out a DNS-only failure (Case B) in favor of a wider data-plane failure
(Case C), consistent with the server-side silence.

Minimal non-secret diagnostic logging was added to
`ShadowsocksVpnProtectBridge` (`accept loop started`, `accepted a peer
connection`, `protect() result=<bool>`) and proved **`sslocal` was
actively and repeatedly reaching the protect bridge, with
`protect()` returning `true` every single time** (~15 successful
protect calls observed across one ~15s curl attempt) — ruling out the
protect path, the TUN handoff, and `VpnService.protect()` itself as the
cause. A baseline test with the Shadowsocks tunnel disconnected
confirmed the phone's own WiFi network can reach `152.70.43.1:28388`
directly (`nc -4 -w 6 152.70.43.1 28388` connected) — ruling out a
network/firewall/server-reachability problem.

**Root cause (code-read, deterministic): `sslocal` is being told to
connect to the wrong port.** In
`VpnController.kt`'s `TransportConfig.Shadowsocks` builder:

```kotlin
TransportConfig.Shadowsocks(
    endpointId = pendingConnectEndpointId,
    host = config.endpointHost,
    port = config.endpointPort,
    routingMode = routingMode,
)
```

`config.endpointHost`/`config.endpointPort` come from
`GatewayConfigSnapshot`, built by `AutoGatewaySelector.snapshotFor`,
whose own docstring says: *"this snapshot's `endpointHost`/`endpointPort`
are ONLY ever consumed by `VpnController`'s AWG execution path
(`GatewayConfigSnapshotValidator`/`TransportConfig.Awg`)"* — i.e. these
fields carry the AmneziaWG peer's UDP port (`51820` for Frankfurt, per
this same session's own Diagnostics dump: `Gateway: 152.70.43.1:51820`),
never a Shadowsocks port. Frankfurt's signed manifest does not declare a
`SHADOWSOCKS_2022` transport binding at all (Diagnostics:
`Endpoint frankfurt: ... transports=[AMNEZIA_WG, XRAY_REALITY, TLS_TCP]`),
so there is no manifest-derived Shadowsocks port to fall back to either.
`Shadowsocks2022Credential` (`identity/Shadowsocks2022Credential.kt`)
only carries `method` + `key` — no host/port — so the credential
repository (correctly populated by this session's own provisioning,
`host=152.70.43.1 port=28388`) is never consulted for the connection
address at all. The result: `sslocal` is launched with
`--tun-interface-address` correct but dials `152.70.43.1:51820` (or
whatever the AWG binding resolves to), not `152.70.43.1:28388` — a
silent, deterministic misconfiguration that explains the exact symptom
observed (real process, real TUN, real protect bridge, zero server-side
bytes) on every attempt so far, including the original B45B-4P attempt
and this session's re-run.

**No fix was implemented in this session.** This is a genuine
architectural gap - there is currently no Shadowsocks-specific host/port
authority anywhere in the codebase (not the manifest, not the credential
repository) - not a one-line bug. A correct fix requires a real design
decision (e.g. extend `Shadowsocks2022Credential`/its on-disk store
format to carry host+port, with a migration, mirroring what the debug
`ShadowsocksAdapterValidationActivity` staging JSON already informally
assumes; or add a genuine manifest-driven Shadowsocks transport binding)
that is out of scope for a same-session "smallest fix" per this task's
own discipline. Only the non-secret diagnostic logging that helped prove
this (commit `1138851116d9cc1df50c99cb208772a43b017ec3`) was pushed to
this PR.

**B45 is not complete. B45B-4P selection/runtime/data-plane integration is
not proven end to end.** The reproducible-artifact provenance (§1), the
selection-wiring runtime evidence (§3), the DNS-fix LinkProperties proof
(§7), and the disconnect/cleanup fix under two independent real cycles
(§5b, §7) are established facts. The data-plane failure now has a proven,
specific, deterministic root cause (§7) rather than an unknown one - the
next slice's job is the host/port design fix, not further diagnosis.
