# B45B-4P — Shadowsocks 2022 Selection Wiring: Physical Validation Attempt

## Status: NOT PASSED — data-plane proof still failing; the disconnect/ownership bug found in the first attempt is now fixed (§5b)

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
- The actual root cause of the data-plane failure in §4
- The ownership/cleanup bug in §5

**B45 is not complete. B45B-4P selection/runtime/data-plane integration is
not proven end to end.** Only the reproducible-artifact provenance (§1) and
the selection-wiring runtime evidence (§3, up to but not including a working
data plane) are established facts from this session.
