# B46-4P: Hysteria2 OPPO CPH2173 Physical Acceptance Test Plan

**Status: NOT YET RUN.** This plan exists to be executed only after the [deployment readiness checklist](B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md#deployment-readiness-checklist-detailed-sequence)'s all 14 items are genuinely green - real Stockholm deployment, real signed manifest, real device provisioning. Running any part of this plan against fabricated, partial, or non-production infrastructure produces evidence this project's own discipline explicitly rejects (see `docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md`'s own item #10 "BLOCKED" status) - do not represent a partial run as validation.

**Device**: OPPO CPH2173, Android 14, SDK 34, arm64-v8a (the same physical device B46-2P/B46-3B/B46-3C already validated other transports against).

Every step below must produce reproducible, storable evidence (screenshots, `adb logcat` excerpts, `tcpdump` captures, exact timestamps) - mirroring the evidence discipline `docs/B46_3C_HYSTERIA_PROCESS_ISOLATED_DATAPLANE.md` and `docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md` already established for this exact protocol on this exact device.

## 1. Provisioning

```text
activate
  -> POST /v1/activate succeeds, device bound (existing, unchanged mechanism)
  -> receive manifest
    -> GET /v1/manifest returns the NEW signed manifest containing the HYSTERIA2 binding
    -> Ed25519ManifestVerifier accepts it (EndpointManifestRepository.trusted() now includes it)
  -> receive Hysteria2 credential
    -> activateDevice()'s automatic post-AWG-activation provisioning call reaches
       POST /v1/hysteria-profile and Hysteria2ProfileProvisioner.provision() returns Saved
    -> hysteria2ProfileProvisioningState surfaces "Saved" in the Diagnostics dialog
       (the exact line B46-4P's UI slice added)
    -> hysteria2AvailableEndpoints now contains the Stockholm endpoint id
```

**Evidence to capture**: Diagnostics dialog screenshot showing "Hysteria2 provisioning: Saved"; `adb logcat` excerpt around the provisioning call (non-secret fields only - see `hysteria_provisioning.py`'s own no-secret-in-logs discipline, must hold on the client side too).

## 2. Connection

```text
select Stockholm
  -> isHysteria2AvailableFor(stockholm) now returns true (all three conditions met:
     ABI/binary eligibility, provisioned credential, trusted signed binding)
Hysteria2 transport
  -> tap "Force HYSTERIA2 on next connect" (Diagnostics dialog) OR let Smart Connect
     select it once it participates in ranking - record which path was used
  -> VpnController.buildTransportConfig's HYSTERIA2 branch resolves host/port/sni/
     obfuscationMode EXCLUSIVELY from the trusted signed binding (never a hardcoded
     value - see MainViewModel.kt's own docs)
TLS/SNI validation
  -> Hysteria2ChildRuntime.start() with insecure=false (hard production gate,
     B46-4A) - confirm the child does NOT refuse to start (it would if
     config.insecure were ever true, which it structurally cannot be)
  -> confirm via a packet capture or the child's own log line that the QUIC
     handshake presents the correct SNI and the certificate validates
UDP transport
  -> Hysteria2 child reports SOCKS5_LISTENING and a successful QUIC connect
  -> tun2socks child ACKs the SCM_RIGHTS TUN-fd handoff with its own PID
VPN tunnel established
  -> Hysteria2Transport reports Connected only once BOTH children's own
     readiness signals are true (never merely "TUN exists" - see
     hysteria2TransportStateFor's own docs)
```

**Evidence to capture**: `tcpdump` on the Stockholm host (or a local capture proving destination IP/port) showing the real QUIC handshake; screenshot of the app reporting Connected; the two child processes' PIDs from `adb shell ps`.

## 3. Traffic

- [ ] Tunnel established (per above).
- [ ] External IP matches Stockholm's known public IP (`https://api.ipify.org` or equivalent, through the tunnel) - same check style as `docs/B10_LEAK_VALIDATION_PLAN.md`.
- [ ] DNS behavior: resolves through the tunnel per `VpnDnsPolicy`'s canonical resolvers (same as every other transport - not Hysteria2-specific).
- [ ] Normal HTTPS connectivity: a real browser page load succeeds through the tunnel.
- [ ] Reconnect: disconnect and reconnect once - a fresh `sessionId`, no stale-session cross-talk (mirrors B46-3C's own "two clean reconnect cycles" proof).
- [ ] App restart: force-stop and relaunch the app while connected - confirm clean re-detection of state (no orphaned child process, no leaked TUN - mirrors B46-3C's own leak-check discipline).
- [ ] VPN restart (toggle off/on from Android's own VPN settings, not just the app): confirm both children tear down and a fresh connect attempt starts cleanly.

## 4. Credential lifecycle

- [ ] Valid credential → accepted (covered by section 1-2 above).
- [ ] Revoked credential → rejected: revoke the test activation server-side (`activations.revoke_activation`), confirm the NEXT connection attempt fails auth at `/internal/hysteria-auth` (already proven server-side in `gateway/api/tests/test_hysteria_auth_endpoint.py::test_revoked_activation_secret_stops_authenticating` - this step re-confirms it against a REAL device/server pair, not just the test harness) with NO Hysteria2 server reload needed.
- [ ] Rotated credential → new credential accepted: trigger a second `/v1/hysteria-profile` call (re-activate), confirm the NEW secret authenticates.
- [ ] Old credential → rejected: confirm the PRE-rotation secret no longer authenticates (already proven server-side in `test_rotated_secret_invalidates_the_old_one` - re-confirm physically).

## 5. Failure cases

- [ ] Wrong auth: manually corrupt the stored credential (debug-only path) and confirm `Hysteria2VpnService` fails closed with a typed, non-secret `Hysteria2RuntimeError` - never a crash, never a silent hang.
- [ ] Missing auth: confirm the absent-credential path (`Hysteria2CredentialGetResult.Absent`) fails closed before any child is spawned (already unit-tested - `Hysteria2CredentialRepositoryTest` - this step confirms the same fail-closed UX physically, e.g. the transport simply stays unavailable rather than attempting a doomed connection).
- [ ] Wrong SNI: if feasible, temporarily point a test binding at a mismatched SNI and confirm the connection fails at the TLS layer, never falls back to `insecure=true` (structurally impossible - confirm this holds physically too).
- [ ] Blocked UDP: simulate by blocking the chosen UDP port at the client's own network (e.g. a restrictive Wi-Fi/firewall) and confirm a clean, typed failure - never a silent hang or crash - matching this transport's own `suitableForRestrictiveNetworks = false` capability (expected to fail here; this proves the failure is clean, not that the transport should work).
- [ ] Backend unavailable: stop `pocvpn-api.service` briefly and confirm `/v1/hysteria-profile`/`/internal/hysteria-auth` failures are handled cleanly (existing connections unaffected per the auth-backend architecture's own reliability analysis - a NEW connection attempt during this window should fail cleanly, not crash the app).
- [ ] Server restart: restart `nova-hysteria2.service` while a session is active - confirm the client detects the child's unexpected exit and tears down cleanly (`onUnexpectedExit`, already unit-tested; confirm physically).
- [ ] App restart: covered in section 3 above.

## Evidence package

Store all captures (screenshots, logcat excerpts, tcpdump captures, exact pass/fail per checkbox above, device/build info, manifest version used) under a new `artifacts/b46-4p/` directory following this repository's own existing convention (see `artifacts/b45a/`, `artifacts/repairs/` for the established format) - a dated subdirectory per run, a summary markdown file, never raw secrets in any captured file.

## Decision gate

Only once every checkbox above is genuinely green may B46-4P item #10 move from `BLOCKED` to `DONE`, and only then may this project's documentation call Hysteria2 physically validated on production infrastructure.
