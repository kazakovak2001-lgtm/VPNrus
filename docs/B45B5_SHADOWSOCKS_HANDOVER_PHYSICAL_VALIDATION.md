# B45B-5 / Q7 — Shadowsocks 2022 Wi-Fi ↔ Cellular Handover: Physical Validation

## Status: PHYSICALLY PASSED

Real physical validation of `ShadowsocksTransport.underlyingNetworkRecovery
== RESTART_SESSION` against a genuine Wi-Fi ↔ cellular underlying-network
handover, on a real OPPO CPH2173, against the real production Frankfurt
`b45a-ssserver.service` and the real, live, production-deployed signed
manifest v4 (see `B45B4P_SHADOWSOCKS_SELECTION_PHYSICAL_VALIDATION.md` §8/§9
for the manifest/binding architecture this test builds on - not repeated
here).

## 1. Baseline

- Starting `main` SHA: `1da9cc06ab337823f22366dad1c421a37e9c89b7` (includes
  merged PR #86, B45B-4P PHYSICALLY PASSED)
- Isolated worktree: `C:\Users\akaza\Downloads\VPN-B45B5-HANDOVER`, branch
  `validation/b45b5-shadowsocks-handover-physical`, HEAD verified equal to
  the exact starting SHA before any change
- Device: OPPO CPH2173, serial `c618ee06`, Android 14 (SDK 34), `arm64-v8a`
- `sslocal` SHA-256 (same reviewed artifact, reused - not rebuilt):
  `b8c8526055586d0175d12cdc9432a78146eff986b68aac3dc6d85dfd82716e79`
- Manifest v4 preflight (read-only, before testing): both Frankfurt
  (`152.70.43.1`) and Stockholm (`16.170.208.231`) served the exact
  expected artifact, SHA-256
  `304722f23ed2c97f94cb0af5122c3bfd4c5d47e3188bb1e991fcd25b1be8a9ad`
- Frankfurt `b45a-ssserver.service`: active, TCP+UDP listeners on `28388`
  confirmed
- Frankfurt credential file confirmed present on-device (never displayed);
  app data never cleared, `firstInstallTime` unchanged across install

## 2. Architecture read/confirmed (no code changed)

- `ReconnectManager.kt` / `AndroidReconnectManager`: filters
  `NET_CAPABILITY_INTERNET` + `NET_CAPABILITY_NOT_VPN`; on API 31+
  (device is API 34) additionally registers
  `registerBestMatchingNetworkCallback` as the sole authoritative-identity
  source - first value is a baseline, a later *different* value is the
  handover signal (`ReconnectAvailabilityLifecycle.onAuthoritativeAvailable`).
- `VpnController.handleUnderlyingNetworkChanged()`: only acts on a
  Connected session, only when `activeTransport.underlyingNetworkRecovery
  == RESTART_SESSION`, and calls `startReconnect(restartImmediately =
  true)`.
- `ShadowsocksTransport.underlyingNetworkRecovery ==
  UnderlyingNetworkRecovery.RESTART_SESSION` - confirmed in source.
- AWG's own in-place recovery path is untouched/unaffected by this slice -
  confirmed both by reading the code (a completely separate branch) and
  physically (the post-test AWG sanity check, §7).

## 3. Original phone network state (recorded before testing, restored after)

- Wi-Fi: enabled, connected to SSID "Vodafone-7914" (home network),
  Net ID 82
- Mobile data: enabled (`settings get global mobile_data` = `1`)
- Cellular service: SIM already `IN_SERVICE`, LTE, carrier T-Mobile CZ,
  network already `VALIDATED` and coexisting with Wi-Fi (Android network id
  `160`) - cellular precondition was already satisfied with no action
  needed (`B45B5_CELLULAR_PRECONDITION_UNAVAILABLE` did not apply)
- Active default network before testing: `161` (WIFI, "Vodafone-7914")

## 4. Wi-Fi baseline session

- Pre-clean: `am force-stop`, confirmed no `sslocal`, no `tun0`, no stale
  runtime files.
- Diagnostics → Force `SHADOWSOCKS_2022` on next connect → Home connect
  button (never the debug harness).
- **PID_WIFI_1 = `25059`**
- Log line (public facts only): `starting: endpointId=frankfurt
  host=152.70.43.1 port=28388 method=2022-blake3-aes-256-gcm`
- VPN `UnderlyingNetworks: [161]` - the WIFI network recorded in §3.
- DNS LinkProperties: `[/1.1.1.1,/1.0.0.1]`.
- Hostname HTTPS (`icanhazip.com`) exit IP: **`152.70.43.1`**.
- **WIFI_OUTER_SOURCE_IP (server tcpdump) = `86.49.237.32`**.

## 5. Phase A — Wi-Fi → Cellular

- Confirmed mobile data still enabled; logcat cleared beforehand.
- **Wi-Fi disabled at `2026-09-20 03:23:23 UTC`** (`adb shell svc wifi
  disable`). Cellular (never airplane mode) was the only underlying change.
- Within ~1s: `Active default network: 160` (the cellular LTE network
  already recorded in §3).
- **PID_CELLULAR = `25664`** - a genuinely new process.
- **PID_WIFI_1 (`25059`) confirmed dead** (`ps -A` no longer lists it);
  exactly one `sslocal` process present throughout.
- New log line: `starting: endpointId=frankfurt host=152.70.43.1
  port=28388 method=2022-blake3-aes-256-gcm` - **same signed target, never
  `51820`, no fresh Smart Connect decision, no endpoint drift**.
- VPN `UnderlyingNetworks: [160]`.
- New `tun0` (fresh interface index), fresh `protect_path`/`tun_fd_path`
  timestamps matching the new session only.
- Hostname HTTPS exit IP: **`152.70.43.1`**.
- Direct-IP TCP (`https://1.1.1.1`): `HTTP 301`, 0.19s.
- UDP/DNS round-trip (raw query via toybox `nc -u` to `1.1.1.1:53`):
  matching transaction id, response bit set, RCODE=0, 2 answers.
- Server-side: real TCP handshakes/data/teardowns AND real UDP/28388
  traffic observed from a **new** source address.
- **CELLULAR_OUTER_SOURCE_IP = `109.183.23.52`** - differs from
  `WIFI_OUTER_SOURCE_IP` (`86.49.237.32`), strong corroborating evidence
  the outer transport genuinely migrated (Android's own underlying-network
  identity evidence in §5 remains the primary authority, per this task's
  own instruction not to rely on IP equality alone).
- Measured recovery: Wi-Fi disabled `03:23:23 UTC` → new session's
  `starting:` log line at the same second (sub-second observed delay,
  effectively immediate) → first successful hostname HTTPS confirmed by
  `03:23:56 UTC` (includes the adb/curl round-trip itself, not just
  session restart).

## 6. Phase B — Cellular → Wi-Fi

- **Wi-Fi re-enabled at `2026-09-20 03:24:38 UTC`** (`adb shell svc wifi
  enable`).
- Wi-Fi reconnected to the SAME original SSID ("Vodafone-7914") on a new
  Android network id `176` (fresh association, real reconnection - not
  merely "radio on"); confirmed `Transports: WIFI`, `VALIDATED`.
- `Active default network: 176` shortly after.
- **PID_WIFI_2 = `26094`** - distinct from both `25059` and `25664`.
- **PID_CELLULAR (`25664`) confirmed dead**; exactly one `sslocal` process
  present.
- Log line unchanged: `starting: endpointId=frankfurt host=152.70.43.1
  port=28388 method=2022-blake3-aes-256-gcm` - no fallback, no drift, no
  fresh gateway selection, at `03:24:40 UTC` local device time.
- VPN `UnderlyingNetworks: [176]`.
- Hostname HTTPS exit IP: **`152.70.43.1`**.
- Direct-IP TCP: `HTTP 301`, 0.24s.
- UDP/DNS round-trip: matching transaction id, response bit set, RCODE=0,
  2 answers.
- Server-side: real TCP+UDP/28388 traffic resumed from
  **`86.49.237.32`** - matching the original WIFI_OUTER_SOURCE_IP
  (same home NAT gateway), as expected.
- Measured recovery: Wi-Fi enabled `03:24:38 UTC` → new session's
  `starting:` log at `03:24:40 UTC` local device time (~2s, includes
  Wi-Fi association/DHCP) → hostname HTTPS confirmed working immediately
  after.

## 7. Stability window, final disconnect, cleanup, AWG sanity

- 60-second steady-state window on the restored Wi-Fi session: 4 bounded
  hostname-HTTPS probes, all `HTTP 200`; `sslocal` PID `26094` **never
  changed** across the window; exactly 3 `starting:` log lines exist in
  the ENTIRE session (baseline + 2 handovers) - **no reconnect storm**.
- Normal final disconnect (Home button): `sslocal` gone, `tun0` gone,
  `files/shadowsocks/` runtime artifacts gone, UI Disconnected.
- Crash/ANR scan across the whole session: **none found**.
- Original phone network state confirmed restored exactly: Wi-Fi enabled
  and connected to "Vodafone-7914" (unchanged), mobile data enabled
  (unchanged) - nothing was left in a different configuration than
  recorded in §3.
- AWG sanity (normal Home Auto/manual connect, after Shadowsocks fully
  disconnected): connected cleanly (`tun0=10.77.0.12/32`, AWG's own
  address) and disconnected cleanly - no stale Shadowsocks/reconnect
  ownership.
- Server: bounded `tcpdump` (900s cap) left to expire naturally; no
  server-side config/service/firewall change made at any point.

## 8. Failure-case classification

Not applicable - no failure occurred. Handover worked correctly on the
first attempt in both directions; no client bug was found, no code change
was made.

## 9. Conclusion

All acceptance conditions in the task specification were physically
demonstrated: a real, active Shadowsocks session on Wi-Fi cleanly
restarted with a genuinely new process when the underlying network changed
to cellular (never airplane mode, a real replacement network throughout),
preserved its exact pinned signed destination
(`152.70.43.1:28388`/`2022-blake3-aes-256-gcm`) on every restart, proved a
real data plane (TCP, UDP, DNS, exit IP, independent server-side evidence
including a changed outer source IP) on cellular, then repeated the same
clean restart/pinning/data-plane proof when Wi-Fi returned, remained
stable for 60s with no reconnect storm, and left no orphaned
process/TUN/socket at any point. Original phone network configuration was
restored exactly.

**B45B-5 / Q7 Wi-Fi ↔ cellular handover: PHYSICALLY PASSED.**

Not claimed and out of scope for this slice: Russia/restricted-network
validation, hard-whitelist bypass validation, non-arm64 ABI parity. B45 as
a whole remains NOT complete.
