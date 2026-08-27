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

No runtime implementation of any new transport (XRay/REALITY, QUIC,
TLS/TCP fallback, Shadowsocks, or any P1/P2 item) begins before B10 is
complete on a real VPS. Phase 2A (transport architecture foundation) is
the only architecture work done ahead of that sequence, and it is
explicitly not wired into the live connect path - see
[Phase 2A's own report] in the project history for that boundary.

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

   Today, only `NetworkProfiler -> SmartConnectDecisionEngine ->
   TransportOrchestrator` exist (Phase 2A, FOUNDATION, unwired).
   `RestrictionClassifier`, `RoutingDecisionEngine` wired into this
   pipeline, and gateway selection do not exist yet.

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
| XRay / VLESS REALITY fallback | PLANNED | No code. |
| QUIC transport/fallback | PLANNED | No code. |
| TLS/TCP fallback | PLANNED | No code. |
| Smart Connect | **FOUNDATION** | `SmartConnectDecisionEngine` (Phase 2A) is real, pure, and unit-tested, but NOT live-wired into `VpnController`. |
| Network Profiler | **FOUNDATION** | `NetworkProfiler` (Phase 2A) uses real `ConnectivityManager` callbacks, instrumented-test-verified; not consumed by any live flow yet. |
| Restriction Classifier | PLANNED | No code. Target position: between `NetworkProfiler` and `RoutingDecisionEngine` (see pipeline above). |
| Hard Whitelist Detection | PLANNED | No code. See architecture principle 4 - detection only, never impersonation. |
| Adaptive Direct Routing | PLANNED | `ClientRoutingPolicy`/`RoutingDecisionEngine` (FOUNDATION) provide the static-policy substrate; the *adaptive*, classifier-driven behavior itself does not exist yet. |
| Gateway Pool | PLANNED | No code; single hardcoded local-dev gateway only. |
| Gateway Health / Reachability | **FOUNDATION** | `TransportHealth` (Phase 2A) is a real typed model (`UNKNOWN`/`HEALTHY`/`DEGRADED`/`UNREACHABLE`/`NOT_IMPLEMENTED`); no real probing loop or gateway-level (as opposed to transport-level) health exists yet. |
| multi-provider gateway infrastructure | **BLOCKED** | Pending real VPS (B6). Cannot meaningfully start with zero provisioned gateways. |
| Private Gateway Mode | PLANNED | No code. Architecture principle 9 applies once designed. |
| Signed Offline Bootstrap | PLANNED | No code. |
| Alternative Control Routing | PLANNED | No code. |
| automatic gateway failover | PLANNED | No code; requires Gateway Pool first. |

## P1

| Capability | Status | Notes |
|---|---|---|
| Connection Memory | PLANNED | No code. |
| Transport Scoring | PLANNED | `TransportCapabilities`/`TransportHealth` (FOUNDATION) give the typed fields a future scorer would read; no scoring algorithm exists. |
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
| Public-network AWG handshake | **UNVERIFIED** - pending B8B |
| Public VPS NAT behavior | **UNVERIFIED** - pending B8B |
| External public IP change through the tunnel | **UNVERIFIED** - pending B9 |
| DNS leak protection | **UNVERIFIED** - pending B10 |
| IPv4/IPv6 leak protection | **UNVERIFIED** - pending B10 |
| Real restrictive-network/Russia behavior | **UNVERIFIED** - no restrictive-network probing exists (by design, see Phase 2A scope freeze) |

Do not cite any UNVERIFIED row above as if it were proven. Each becomes
VERIFIED only when its corresponding gate (B8B/B9/B10) produces real
on-the-wire evidence, the same way B8A did for the local handshake.
