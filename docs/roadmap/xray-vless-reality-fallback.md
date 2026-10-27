# XRay / VLESS REALITY fallback

<!-- Moved verbatim from docs/ROADMAP.md (2026-10-27): the full table row. -->

## Capability

XRay / VLESS REALITY fallback

## Status

**IMPLEMENTED**

## Notes

Client and gateway both real and live-wired. Client: `XrayProfileStore`/`XrayProfileRepository` persist a provisioned profile, `VlessRealityTransport`/`NovaXrayVpnService`/`XrayCoreController` execute it through `VpnController` (B8I6-B8I7), which registers `TransportKind.XRAY_REALITY` as available whenever a real profile repository is wired - production always does. Gateway: Xray profile provisioning/activation is real (`gateway/api/xray_activation.py`, `xray_provisioning.py`, B8K1-B8K4), with its `/v1/activate`/`/v1/xray-profile` routes now exposed at the nginx edge (B8K5A, PR #10). `AwgXrayFailoverPolicy` (B8I8) automatically falls back a failed AWG attempt to Xray, and the REALITY key validation bug is fixed (same commit, PR #9). AWG->Xray automatic failover **VERIFIED** end-to-end on a real VPS (AWG peer removed, AWG failed, automatic Xray fallback executed, live Xray traffic and a matching exit IP confirmed on the server). **B30B physical-validation fix (2026-09-03)**: real Oppo CPH2173 hardware testing found a genuine, confirmed total connectivity loss (airplane mode + WiFi disabled, ~70s, zero `NetworkAgentInfo`) left a TLS_TCP session showing "Protected" the whole time - root cause: `AndroidReconnectManager` used `registerDefaultNetworkCallback`, which reports THIS APP'S OWN default network - once this app's VpnService establishes its own tun interface, that IS the VPN network itself, not the real underlying WiFi/cellular transport beneath it, so `onLost` essentially never fired and `VpnController.handleNetworkLost()`/`reconnectLoop()` (the EXISTING AWG-proven bounded-retry health authority, not AWG-specific by construction - it triggers on any `TransportState.Connected`) was simply never invoked for the TLS_TCP session. AWG itself was never affected (WireGuard's own UDP send failures detect loss independently of this class). Fixed by switching to `registerNetworkCallback` with an explicit `NET_CAPABILITY_NOT_VPN` request (the documented Android pattern for a VPN app to observe real underlying connectivity), tracking the full set of currently-available matching networks (`NetworkAvailabilitySet`, a small pure/testable helper) so a WiFi<->cellular handover with a usable network throughout never spuriously reports "network lost." No new health system, no second polling loop - purely a same-interface fix to `AndroidReconnectManager`'s network-observation scope; `VpnController`/`ReconnectManager`'s contract/`SupportDiagnosticsRecorder`'s existing generic `sessionHealth` backstop are unchanged and now correctly receive the real signal.
