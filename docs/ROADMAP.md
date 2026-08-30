# Product roadmap - approved capabilities and current status

This document records the approved long-term capability set for the VPN
product. **It is documentation only.** Nothing in this file implements,
enables, or wires up any of the PLANNED/BLOCKED items - see each item's
status for what actually exists in the repository today, and see
`docs/AWG_GENERATION.md` / `gateway/README.md` for the one capability that
is real.

## Status legend

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Real, working code exists and does what the name says. |
| **FOUNDATION** | Real, tested code exists (types, pure decision logic, an observer), but it is either not wired into the live product flow, or only covers part of the eventual capability. |
| **PLANNED** | Approved for the roadmap. No code exists yet. |
| **BLOCKED** | Approved, but cannot start/complete because of an external precondition (currently: no paid VPS exists). |
| **UNVERIFIED** | Not a feature - a *claim* about the running system (e.g. "no DNS leak") that has not yet been proven with real evidence, and must not be asserted as true until it is. |

A capability's status here is not a promise about when it ships - it is a
truthful snapshot, updated as each gate (B6, B8B, B9, B10, and beyond)
actually lands.

## Mandatory runtime sequence (unchanged)

```
B6  - real VPS provisioning
B8B - public AWG handshake
B9  - full-tunnel external IP validation
B10 - DNS / IPv4 / IPv6 leak validation
```

No runtime implementation of any new transport (QUIC, TLS/TCP fallback,
Shadowsocks, or any other P1/P2 item) begins before B10 is complete on a
real VPS. XRay/REALITY was the first exception to this rule: its full
client and gateway runtime was built and live-wired ahead of B10, and its
AWG->Xray automatic failover has since been **verified** end-to-end on a
real VPS (see the XRay / VLESS REALITY fallback row below) - this
document is updated to reflect that reality rather than continue
asserting it hasn't happened. Phase 2A (transport architecture
foundation) remains the only architecture work done ahead of sequence
for the transports that are still PLANNED - see [Phase 2A's own report]
in the project history for that boundary.

**As of B10-1 (2026-08-30), the B6->B8B->B9->B10 sequence above is
itself complete** - see the "Current verification status" table below:
public AWG handshake, public VPS NAT behavior, external IP change, and
DNS/IPv4/IPv6 leak protection are all now VERIFIED with real physical-
device evidence (B6, real VPS provisioning, has been implicitly true
throughout this document's B8I/B8K/B8L/B8M/B8N history - the gateway at
`152.70.43.1` this evidence was gathered against is that same real VPS).
This means the sequencing GATE itself - not merely an exception granted
to one transport - no longer blocks QUIC/TLS/TCP-fallback/Shadowsocks
runtime work on process grounds; any decision to start one is now a
scope/priority choice, not a blocked one. `Real restrictive-network/
Russia behavior` (the verification table's final row) remains
**UNVERIFIED and separate** - B10's leak validation says nothing about
behavior on an actually-restrictive network, and must not be conflated
with it.

## Architecture principles this roadmap commits to

1. **Routing decision and transport selection stay separate.** "Should this
   traffic use the VPN at all" (`RoutingDecisionEngine`) is never the same
   question as "which transport carries it" (`SmartConnectDecisionEngine`).
   Do not merge these two concerns as the roadmap items below are built.

2. **Target Smart Connect pipeline:**

   ```
   NetworkProfiler
     -> RestrictionClassifier
     -> RoutingDecisionEngine
     -> SmartConnectDecisionEngine
     -> TransportOrchestrator
     -> Gateway selection
   ```

   Today, `NetworkProfiler -> RestrictionClassifier ->
   SmartConnectDecisionEngine -> TransportOrchestrator` all exist and are
   live-wired into the real connect path (`MainViewModel.connect()` /
   `smartConnectDecision()`) - not merely Phase 2A foundation code.
   `RestrictionClassifier`'s output is carried through as
   `ConnectionScore.restrictionClass` for truthful diagnostics (principle
   10 below), but does not yet change WHICH candidate is selected -
   `RoutingDecisionEngine` wired into this pipeline, and gateway
   selection, still do not exist.

3. **Distinct failure conditions.** A connection attempt that fails must be
   attributable to one of (at minimum):

   - `PROTOCOL_BLOCKED` - the transport protocol itself appears filtered.
   - `GATEWAY_UNREACHABLE` - this specific gateway/endpoint is down or
     unreachable, independent of protocol.
   - `NETWORK_UNAVAILABLE` - the device has no usable network at all
     (already modeled: `NetworkProfile.isUsable`,
     `TransportSelectionDecision.NetworkUnavailable`).
   - `HARD_WHITELIST` - the network appears to only permit a fixed set of
     allowlisted destinations (see Hard Whitelist Detection below).

   These must never be collapsed into one generic "connection failed"
   state - each implies a different remediation (retry, switch gateway,
   switch transport, or something structurally different for hard
   whitelists).

4. **Hard Whitelist Detection must never impersonate a real third-party
   service.** Detecting that a network only allows traffic to a fixed
   allowlist (e.g. a bank, Yandex, VK) must not be implemented by
   pretending to *be* one of those services, spoofing their traffic
   signature, or otherwise misrepresenting the client as that service.
   Detection is passive/observational only.

5. **Adaptive Direct Routing** means genuine `DIRECT` routing (the
   underlying network, unmodified) for explicitly allowed/local traffic,
   and VPN routing for everything else classified as needing protection.
   It is an extension of the existing `RoutingDecisionEngine` /
   `ClientRoutingPolicy` model (FOUNDATION today, static policies only),
   driven by a future `RestrictionClassifier` rather than a fixed policy -
   not a new routing primitive.

6. **Transport selection uses capability/health scoring, not hardcoded
   if/else.** `TransportCapabilities` and `TransportHealth` (Phase 2A,
   FOUNDATION) exist for exactly this reason: as more transports become
   real, `SmartConnectDecisionEngine` must be extended to score across
   these typed fields, never to grow a chain of per-protocol conditionals.

7. **Public gateway infrastructure must span multiple providers/ASNs.**
   Relying on a single provider (e.g. Hetzner alone) for all gateways is
   not the target architecture - see Gateway Pool / multi-provider gateway
   infrastructure below, both currently BLOCKED on having any real VPS at
   all.

8. **Signed Offline Bootstrap** must let the client retain a
   cryptographically verified last-known-good gateway/control
   configuration for use when the primary control API is unreachable - not
   an unauthenticated cached blob.

9. **Private Gateway Mode is a first-class capability, not a fallback.**
   A user may connect through the managed gateway network *or* their own
   compatible VPS running the same pinned AmneziaWG gateway
   (`gateway/provision.sh`) - both are supported product modes.

10. **Privacy claims stay truthful.** Nothing in this product may claim
    "untraceable," a guaranteed censorship bypass, or a guaranteed
    hard-whitelist bypass. Every capability below is described by what it
    actually does, not by an outcome no software can promise.

## P0 - core anti-censorship

| Capability | Status | Notes |
|---|---|---|
| AmneziaWG 3.1 | **IMPLEMENTED** | Client + gateway both real, pinned `v3.1.20260814`/`v3.1.20260812`. Local Android<->WSL2 handshake **VERIFIED** (B8A); public-network handshake remains UNVERIFIED until B8B. |
| XRay / VLESS REALITY fallback | **IMPLEMENTED** | Client and gateway both real and live-wired. Client: `XrayProfileStore`/`XrayProfileRepository` persist a provisioned profile, `VlessRealityTransport`/`NovaXrayVpnService`/`XrayCoreController` execute it through `VpnController` (B8I6-B8I7), which registers `TransportKind.XRAY_REALITY` as available whenever a real profile repository is wired - production always does. Gateway: Xray profile provisioning/activation is real (`gateway/api/xray_activation.py`, `xray_provisioning.py`, B8K1-B8K4), with its `/v1/activate`/`/v1/xray-profile` routes now exposed at the nginx edge (B8K5A, PR #10). `AwgXrayFailoverPolicy` (B8I8) automatically falls back a failed AWG attempt to Xray, and the REALITY key validation bug is fixed (same commit, PR #9). AWG->Xray automatic failover **VERIFIED** end-to-end on a real VPS (AWG peer removed, AWG failed, automatic Xray fallback executed, live Xray traffic and a matching exit IP confirmed on the server). |
| QUIC transport/fallback | PLANNED | No code. |
| TLS/TCP fallback | **IMPLEMENTED** | B8O2 built the full real path end-to-end (gateway TLS inbound, provisioning/activation, Android persistence, runtime wiring - see the B8O2 slice's own detailed notes in git history) and B8O2-ops deployed it to the real production VPS and **physically VERIFIED** it end-to-end on 2026-08-30 (see the verification table below): gateway TLS inbound live on its own port alongside REALITY's own, reusing the existing publicly-trusted Let's Encrypt cert via a group-readable copy (`/etc/nova-xray-tls/`, refreshed by a certbot deploy-hook) since the Xray runtime user has no direct access to certbot's own `live`/`archive` directories; a real physical Android device (ADB-connected, Oppo CPH2173) completed a genuine VLESS+TLS handshake and carried real browser traffic, confirmed via server-side `nova-vless-tls-in` connection logs (not merely "Connected" UI text). REALITY and AWG were both re-verified working immediately after (non-regression). **Smart Connect safety boundary (deliberately still unchanged):** `SmartConnectDecisionEngine`'s Auto path still always prefers `AMNEZIA_WG` and `AwgXrayFailoverPolicy` still only ever names `XRAY_REALITY` - `TLS_TCP` being selectable at all still depends entirely on `UserTransportPreference.Manual(TLS_TCP)`, a real, fully-supported code path in `SmartConnectDecisionEngine`/`TransportRegistry` today, but **no product UI exposes transport selection yet** - there is no in-app way for a user to actually set that preference. The temporary debug-only diagnostics override used to force `Manual(TLS_TCP)`/`Manual(XRAY_REALITY)` for the physical verification below was removed before this slice merged (see that table's own note) - it is not present in the final code. Promoting `TLS_TCP` to an automatic failover candidate, and building a real transport-selection UI, both remain separate, deliberate future decisions. `docs/B8O1A_TLS_GATEWAY_INBOUND_AUDIT.md` documents why REALITY and TLS require two separate xray-core inbounds. |
| Smart Connect | **FOUNDATION** | `SmartConnectDecisionEngine` (Phase 2A) is real, pure, and unit-tested, and IS live-wired as of B8I1/B8I8 - `MainViewModel.connect()` calls `smartConnectDecision()` (via `SmartConnectCandidateSelector`) for every real attempt, and `AwgXrayFailoverPolicy` consults its outcome for AWG->Xray fallback. Kept at FOUNDATION: the full target pipeline (architecture principle 2) is still incomplete - `RoutingDecisionEngine` wired into this pipeline and gateway selection do not exist yet. |
| Network Profiler | **FOUNDATION** | `NetworkProfiler` (Phase 2A) uses real `ConnectivityManager` callbacks, instrumented-test-verified, and IS consumed by the live connect path (wired into `MainViewModel`'s `Factory`, feeds `smartConnectDecision()`/`RestrictionClassifier`). Kept at FOUNDATION: it only covers device-level connectivity facts, not the rest of architecture principle 2's target pipeline. |
| Restriction Classifier | **FOUNDATION** | `RestrictionClassifier` (B8J) is real and unit-tested (`RestrictionClassifierTest`), classifying from real evidence (`NetworkProfiler`, `VpnController` state, connection outcomes, gateway HTTPS probes) - conservative, evidence-only classes, no DPI/TSPU/country-level claims. Live-wired: `MainViewModel.restrictionClass()` feeds it into `smartConnectDecision()` (`ConnectionScore.restrictionClass`) and the diagnostics UI. Kept at FOUNDATION, not IMPLEMENTED: it does not yet drive an adaptive decision - it never changes which candidate is selected (see Adaptive Direct Routing row). |
| Hard Whitelist Detection | **FOUNDATION** | `DiverseReachabilityEvaluator` (B8M) is real and unit-tested: a strict-majority read over several diverse, unrelated, real HTTPS destinations (standard OS/browser connectivity-check endpoints - Google/Apple/Mozilla, each already probed for exactly this purpose by its own platform, so this is an honest reachability check, never an impersonation - architecture principle 4). Live-wired: `RestrictionMonitor` (B8J) probes them on the SAME trigger as the existing gateway probe; `RestrictionClassifier` gained a new `POSSIBLE_HARD_WHITELIST` case (validated internet, the gateway itself confirmed unreachable via BOTH HTTPS and AWG - a confirmed-reachable HTTPS control-plane is treated as positive evidence AGAINST a whitelist claim, not ignored - AND a majority of the diverse set also unreachable). Kept at FOUNDATION, not IMPLEMENTED: this is a narrow, conservative signal ("possible", same discipline as `POSSIBLE_UDP_OR_AWG_FILTERING`), not a confirmed detector, and - like `RestrictionClassifier`'s other classes - it is carried through truthfully into diagnostics only, never yet decision-driving. |
| Adaptive Direct Routing | PLANNED | `ClientRoutingPolicy`/`RoutingDecisionEngine` (FOUNDATION) provide the static-policy substrate; the *adaptive*, classifier-driven behavior itself does not exist yet. |
| Gateway Pool | PLANNED | No code; single hardcoded local-dev gateway only. |
| Gateway Health / Reachability | **FOUNDATION** | `TransportHealth` (Phase 2A) is a real typed model (`UNKNOWN`/`HEALTHY`/`DEGRADED`/`UNREACHABLE`/`NOT_IMPLEMENTED`), now populated with real, transport-level evidence: `TransportHealthCalculator` (B8L1) derives it from `ConnectionOutcomeStore`'s real per-attempt history, wired into `smartConnectDecision()`'s `health` parameter and a diagnostics UI line. Kept at FOUNDATION: `SmartConnectDecisionEngine` still doesn't act on `health` for selection (same "carried through truthfully, not yet decision-driving" boundary as `RestrictionClassifier`), and gateway-level (as opposed to transport-level) reachability - the real `GatewayReachabilityProbe`/`RestrictionMonitor` (B8J) probe a fixed control-plane endpoint, not per-gateway health for a real Gateway Pool - is still separate, unmerged into this model. |
| multi-provider gateway infrastructure | **BLOCKED** | Pending real VPS (B6). Cannot meaningfully start with zero provisioned gateways. |
| Private Gateway Mode | PLANNED | No code. Architecture principle 9 applies once designed. |
| Signed Offline Bootstrap | PLANNED | No code. |
| Alternative Control Routing | PLANNED | No code. |
| automatic gateway failover | PLANNED | No code; requires Gateway Pool first. |

## P1

| Capability | Status | Notes |
|---|---|---|
| Connection Memory | **FOUNDATION** | `ConnectionOutcomeStore`/`FileConnectionOutcomeStore` (B8I) are real: durable (`connection_outcomes.bin`, survives app restart), bounded, tested, and already wired into every real connect attempt (`VpnController.recordConnectionOutcome`) - "did AWG/Frankfurt tend to work, and how fast," exactly this row's own description. Kept at FOUNDATION, not IMPLEMENTED: it is pure storage - nothing yet reads it to change a Smart Connect decision (see Transport Scoring below, and `SmartConnectCandidateSelector`'s own "genuinely UNUSED for a single-candidate decision today" doc). |
| Transport Scoring | **FOUNDATION** | `TransportScorer` (B8N) is real and unit-tested: a deterministic score combining each transport's real `TransportHealth` (B8L1, dominant signal - a NOT_IMPLEMENTED transport always scores lowest) with its declared `TransportCapabilities.maturity` (tie-break only). Live-wired: `MainViewModel.transportScores()` computes it from the real registry/health on every read and surfaces it in the diagnostics UI. Kept at FOUNDATION, not IMPLEMENTED: deliberately NOT passed into `smartConnectDecision()` - same "real evidence, truthfully surfaced, not yet decision-driving" boundary as `RestrictionClassifier`/`TransportHealth` - `SmartConnectDecisionEngine` still picks by its own fixed `PREFERRED_ORDER`, not this score. |
| Emergency Gateway Rotation | PLANNED | No code; requires Gateway Pool first. |
| Shadowsocks fallback | PLANNED | No code. |
| multi-hop | PLANNED | No code. |
| shared exit pools | PLANNED | No code. |
| RAM-only / diskless gateway infrastructure | PLANNED | No code; today's gateway provisioning writes to disk (`/etc/amnezia/amneziawg/`), by design, for the local-test POC. |
| Traffic Pattern Defense / DAITA-like defense | PLANNED | No code. |
| automatic tunnel-key rotation | PLANNED | No code. Client identity today (B4) is a single long-lived AndroidKeyStore-backed keypair. |
| per-device keys and revocation | PLANNED | No code. Today's identity model is single-device, non-revocable. |
| DNS tracker/malware protection | PLANNED | No code. DNS itself is out of scope until B10. |

## P2 - advanced

| Capability | Status | Notes |
|---|---|---|
| hybrid post-quantum protection | PLANNED | No code. |
| rotating exit IP | PLANNED | No code; requires Gateway Pool. |
| Tor-over-VPN where appropriate | PLANNED | No code. |
| custom DNS / DoH / DoT | PLANNED | No code. |
| self-hosted/private VPS mode improvements | PLANNED | Builds on Private Gateway Mode (PLANNED). |
| quotas / abuse protection | PLANNED | No code. |
| advanced routing controls | PLANNED | Builds on `ClientRoutingPolicy` (FOUNDATION). |

## Current verification status (not features - claims about the running system)

| Claim | Status |
|---|---|
| Local Android<->WSL2 AmneziaWG handshake | **VERIFIED** (B8A) |
| Public-network AWG handshake | **VERIFIED** (B10-1, 2026-08-30) - real physical Android device (ADB-connected, `net.pocvpn.client` debug build), real mobile/Wi-Fi network, real gateway `152.70.43.1:51820`; logcat: `Sending handshake initiation` -> `Received handshake response`; `dumpsys`/`ip addr` confirm `GoBackend$VpnService` running with `tun0 10.77.0.5/32`. |
| Public VPS NAT behavior | **VERIFIED** (B10-1, 2026-08-30) - tunnel exit IP (`152.70.43.1`, the gateway's own address) confirmed via two independent third-party services (icanhazip.com, dnsleaktest.com) from a real device browser tab, differing from the device's real baseline IP. |
| External public IP change through the tunnel | **VERIFIED** (B10-1, 2026-08-30) - baseline `86.49.236.33` (icanhazip.com, disconnected) -> connected `152.70.43.1` (icanhazip.com AND dnsleaktest.com independently agree), all via real browser traffic, not shell-UID traffic. See `docs/B10_LEAK_VALIDATION_PLAN.md`'s Results section for the full evidence. |
| DNS leak protection | **VERIFIED** (B10-1, 2026-08-30) - dnsleaktest.com Standard Test: exactly 1 resolver found, Cloudflare (`172.71.140.49`, Frankfurt am Main), zero trace of the device's real carrier DNS (`62.141.16.181`/`.151`, confirmed present via `dumpsys connectivity` while disconnected). |
| IPv4/IPv6 leak protection | **VERIFIED** (B10-1, 2026-08-30) - IPv4: exit IP matched the gateway only, in two independent real-browser checks, never the device's real ISP IPv4. IPv6: a real-ISP IPv6 baseline was confirmed to exist first (`2a02:8308:...`), then while connected an IPv6-only hostname failed to resolve (`ERR_NAME_NOT_RESOLVED`) AND a raw IPv6 literal (no DNS involved) timed out (`ERR_CONNECTION_TIMED_OUT`) - the device's real ISP IPv6 never reached any external destination through either path. |
| Real restrictive-network/Russia behavior | **UNVERIFIED** - no restrictive-network probing exists (by design, see Phase 2A scope freeze) |
| VLESS+TLS/TCP handshake and tunneled traffic | **VERIFIED** (B8O2-ops, 2026-08-30) - real physical Android device (ADB-connected, Oppo CPH2173, debug build from merged `main`), manually forced to `UserTransportPreference.Manual(TLS_TCP)` via a temporary debug-only diagnostics override built specifically for this verification (no automatic failover was changed). **That override was removed immediately after verification and is not present in the merged code** - `Manual(TLS_TCP)` itself remains a real, supported preference in `SmartConnectDecisionEngine`, just with no product UI to set it yet (see this capability's own roadmap row above). `NovaXrayVpnService` logcat: `Xray core started`; `tun0` present at `172.19.0.1/30` (the Xray adapter's own plan, not AWG's). Server-side `nova-xray` journal shows real accepted connections tagged `[nova-vless-tls-in >> direct]` for this exact device's identity - authoritative proof of a genuine VLESS+TLS session, not merely "Connected" UI text. |
| TLS/TCP exit IP / DNS / IPv6 leak behavior | **VERIFIED** (B8O2-ops, 2026-08-30) - baseline `86.49.236.33` (icanhazip.com, disconnected) -> connected `152.70.43.1`, confirmed via THREE independent real-browser checks (icanhazip.com, ifconfig.me, dnsleaktest.com's own "Hello 152.70.43.1 from Frankfurt am Main, Germany"). DNS: dnsleaktest.com Standard Test found exactly 2 resolvers, both Cloudflare (`172.71.245.154`/`.155`), zero trace of the device's real T-Mobile CZ carrier DNS. IPv6: an IPv6-only hostname failed with `ERR_NAME_NOT_RESOLVED` while connected (same fail-closed signature as REALITY's own B10-1 IPv6 result). |
| AWG/REALITY non-regression after TLS/TCP deployment | **VERIFIED** (B8O2-ops, 2026-08-30) - immediately after the TLS/TCP test above, the SAME device was manually forced to `Manual(XRAY_REALITY)` (via the same temporary debug-only override described above - also removed before merge) and reconnected: server-side `nova-xray` journal shows real accepted connections tagged `[nova-vless-reality-in >> direct]` for the same identity/UUID as before the deployment. AWG's own process (`amneziawg-go`, pid unchanged throughout) and both `awg-quick@awg0`/`awg-firewall` units were never restarted or touched by this deployment. |

Do not cite any UNVERIFIED row above as if it were proven. Each becomes
VERIFIED only when its corresponding gate (B8B/B9/B10) produces real
on-the-wire evidence, the same way B8A did for the local handshake and
B10-1 did for the five rows above.
