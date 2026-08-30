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
   `RoutingDecisionEngine` wired into this pipeline, and real gateway
   selection, still do not exist.

   **B11 (2026-08-30)** added the substrate for that missing gateway
   selection step as its own pipeline, deliberately observational and NOT
   yet spliced into the line above:

   ```
   NetworkProfiler -> RestrictionClassifier -> ReachabilityEngine ->
     PathCandidateBuilder -> PathScorer -> (future) SmartConnectDecisionEngine
     -> TransportOrchestrator
   ```

   `ReachabilityEngine`/`PathCandidateBuilder`/`PathScorer` are real and
   unit-tested (see the Endpoint / Path Reachability Fabric row below) and
   ARE live-wired as a read-only diagnostics accessor
   (`MainViewModel.reachabilityDiagnostics()`), but their output is not yet
   consumed by `SmartConnectDecisionEngine` - promoting the winning
   `PathCandidate` into the real decision is deliberately left to a future
   slice (see that row's own "what remains" note), matching this same
   "carried through truthfully, not yet decision-driving" boundary already
   established for `RestrictionClassifier`/`TransportHealth`/`TransportScorer`.

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
   infrastructure below. A real, physically-verified production VPS has
   existed since B10-1/B8O2 (2026-08-30), so this is no longer BLOCKED on
   "zero provisioned gateways" - it is now a scope/priority choice (PLANNED),
   the same reconciliation already applied to the B6->B10 sequencing gate
   above. `EndpointDescriptor.provider`/`.asn` (B11) exist as typed fields
   precisely so a real multi-provider pool can be added without a model
   change - no second provider is actually deployed yet.

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
| TLS/TCP fallback | **FOUNDATION** | B8O2 completes the full real path end-to-end - gateway TLS inbound, provisioning/activation, Android persistence, and runtime wiring - but is NOT yet claimed IMPLEMENTED because it has zero physical-device verification. Gateway: `xray_config_renderer.TlsServerConfig`/`render_server_config(..., tls=...)` render a SECOND, independent Xray inbound (`security: "tls"`, its own port, reusing the same publicly-trusted Let's Encrypt cert already provisioned for the control-plane API) alongside REALITY's own inbound, unchanged - both share the same active-client list (same device identity, no second identity system) and the SAME activation/validate/stage/publish/rollback boundary (`xray_activation.build_tls_config`/`activate_if_needed`) REALITY already uses. `POST /v1/xray-profile` gained an optional `transport: "tls"` field (default `"reality"`, so every pre-B8O2 caller is unaffected) returning only the fields TLS needs (`server_address`/`server_port`/`uuid`/`server_name`/`fingerprint` - no flow/realityPublicKey/shortId). Android: `XrayTlsProfile`/`XrayTlsProfileStore`/`XrayTlsProfileRepository` persist a provisioned TLS profile (its own encrypted file/AndroidKeyStore alias, independent of REALITY's); `XrayCoreController.requestStart(kind)` and `NovaXrayVpnService` (via a new `EXTRA_TRANSPORT_KIND` intent extra, defaulting to REALITY) dispatch to the TLS resolver/renderer while reusing the EXISTING `NovaXrayVpnService`/TUN/self-UID-protection shell verbatim - no second VpnService, no duplicated runtime stack; `VlessTlsTransport` mirrors `VlessRealityTransport` and registers under `TransportKind.TLS_TCP`. `VpnController`/`MainViewModel.buildTransportRegistry()` register `TLS_TCP` AVAILABLE only once a real TLS profile exists, and `TransportHealth`/`ConnectionOutcomeStore`/`TransportScorer` include it automatically (all already generic over `TransportKind`) - kept at FOUNDATION rather than IMPLEMENTED specifically because none of this has run against a real VPS/physical device yet. `docs/B8O1A_TLS_GATEWAY_INBOUND_AUDIT.md` documents why REALITY and TLS require two separate xray-core inbounds (one listener/streamSettings block each), never a shared one. REALITY's own config/renderer/runtime/registration behavior is unchanged (non-regression tests on both sides prove it). **Smart Connect safety boundary (deliberately unchanged in this slice):** `SmartConnectDecisionEngine`'s Auto path still always prefers `AMNEZIA_WG` (always AVAILABLE, first in `PREFERRED_ORDER`) and `AwgXrayFailoverPolicy` still only ever names `XRAY_REALITY` - `TLS_TCP` being AVAILABLE does not, by itself, create any new automatic selection or failover path; it is reachable only via an explicit `UserTransportPreference.Manual(TLS_TCP)` today. |
| Smart Connect | **FOUNDATION** | `SmartConnectDecisionEngine` (Phase 2A) is real, pure, and unit-tested, and IS live-wired as of B8I1/B8I8 - `MainViewModel.connect()` calls `smartConnectDecision()` (via `SmartConnectCandidateSelector`) for every real attempt, and `AwgXrayFailoverPolicy` consults its outcome for AWG->Xray fallback. Kept at FOUNDATION: the full target pipeline (architecture principle 2) is still incomplete - `RoutingDecisionEngine` wired into this pipeline and gateway selection do not exist yet. |
| Network Profiler | **FOUNDATION** | `NetworkProfiler` (Phase 2A) uses real `ConnectivityManager` callbacks, instrumented-test-verified, and IS consumed by the live connect path (wired into `MainViewModel`'s `Factory`, feeds `smartConnectDecision()`/`RestrictionClassifier`). Kept at FOUNDATION: it only covers device-level connectivity facts, not the rest of architecture principle 2's target pipeline. |
| Restriction Classifier | **FOUNDATION** | `RestrictionClassifier` (B8J) is real and unit-tested (`RestrictionClassifierTest`), classifying from real evidence (`NetworkProfiler`, `VpnController` state, connection outcomes, gateway HTTPS probes) - conservative, evidence-only classes, no DPI/TSPU/country-level claims. Live-wired: `MainViewModel.restrictionClass()` feeds it into `smartConnectDecision()` (`ConnectionScore.restrictionClass`) and the diagnostics UI. Kept at FOUNDATION, not IMPLEMENTED: it does not yet drive an adaptive decision - it never changes which candidate is selected (see Adaptive Direct Routing row). |
| Hard Whitelist Detection | **FOUNDATION** | `DiverseReachabilityEvaluator` (B8M) is real and unit-tested: a strict-majority read over several diverse, unrelated, real HTTPS destinations (standard OS/browser connectivity-check endpoints - Google/Apple/Mozilla, each already probed for exactly this purpose by its own platform, so this is an honest reachability check, never an impersonation - architecture principle 4). Live-wired: `RestrictionMonitor` (B8J) probes them on the SAME trigger as the existing gateway probe; `RestrictionClassifier` gained a new `POSSIBLE_HARD_WHITELIST` case (validated internet, the gateway itself confirmed unreachable via BOTH HTTPS and AWG - a confirmed-reachable HTTPS control-plane is treated as positive evidence AGAINST a whitelist claim, not ignored - AND a majority of the diverse set also unreachable). Kept at FOUNDATION, not IMPLEMENTED: this is a narrow, conservative signal ("possible", same discipline as `POSSIBLE_UDP_OR_AWG_FILTERING`), not a confirmed detector, and - like `RestrictionClassifier`'s other classes - it is carried through truthfully into diagnostics only, never yet decision-driving. |
| Adaptive Direct Routing | PLANNED | `ClientRoutingPolicy`/`RoutingDecisionEngine` (FOUNDATION) provide the static-policy substrate; the *adaptive*, classifier-driven behavior itself does not exist yet. |
| Gateway Pool | **FOUNDATION** | B12 - the typed multi-endpoint model is real and proven end-to-end: `EndpointManifest` already accepted multiple `EndpointDescriptor`s since B11, and B12's `GatewayPoolIntegrationTest` proves a manifest naming two DISTINCT endpoint IDs/providers/ASNs flows correctly through canonicalization, `ReachabilityEngine`, `PathCandidateBuilder`, and `PathScorer` together (not just each stage in isolation). Kept at FOUNDATION, not IMPLEMENTED: exactly ONE real production endpoint exists (`frankfurt`) - a second real gateway needs a real second VPS from a different provider/ASN, an explicit operator action out of scope for an automated change (see `docs/B12_ENDPOINT_IDENTITY_AUDIT.md` for what that would additionally require on the credential/activation side). No fabricated second endpoint is embedded in production data. **B13 - the credential/activation-side design question that audit raised is now partly answered in code**: `XrayProfileRepository`/`XrayTlsProfileRepository`'s backing files are now endpoint-scoped (`FileXrayProfileStore`/`FileXrayTlsProfileStore` key by `EndpointId`, option (a) from that audit - independent per-gateway credentials, never a shared/federated identity), with a one-time, safe migration of the single pre-B13 unscoped file into the production endpoint's own scoped slot (`XrayProfileRepositoryFactory.create(..., migrateFromLegacyUnscopedFile = true)`, the composition root's only call site for it) and isolation/migration regression tests (`XrayProfileRepositoryTest`/`XrayTlsProfileRepositoryTest`) proving two endpoints' credentials in the same directory never collide. Still only ONE repository instance is actually constructed/wired (there is nothing to select between yet) - this is storage-layer readiness for a second gateway, not a second gateway. **B13 (2026-08-30 correctness audit)** - the RUNTIME layer now genuinely threads endpoint identity too, closing a gap the audit found where the storage layer above was endpoint-scoped but the actual Xray execution path (`VlessRealityTransport`/`VlessTlsTransport`/`NovaXrayVpnService`) still silently read one repository fixed at construction time: `VpnController.buildTransportConfig` now resolves via a new `XrayProfileRepositoryResolver`/`XrayTlsProfileRepositoryResolver` keyed by the CURRENT attempt's real endpointId (never `ProductionGateway.ID` hardcoded at the selection site), that endpointId is threaded into `TransportConfig.Xray/XrayTls`, `VlessRealityTransport`/`VlessTlsTransport` resolve their own pre-flight repository from it and pass it to `NovaXrayVpnService` via a new `EXTRA_ENDPOINT_ID` intent extra, and `NovaXrayVpnService` rebuilds its `XrayCoreController` only when the requested endpoint actually changes (`VpnControllerXrayEndpointResolverTest`, `NovaXrayVpnServiceEndpointParsingTest`). An endpoint with no configured repository fails closed (`XrayProfileNotReadyException`), never silently substituting a different endpoint's credential. Zero behavior change for today's single production endpoint - every new default derives from it. **B13 (2026-08-30, second real gateway)** - a real, independently-provisioned second AWG gateway now exists (AWS, Stockholm, `16.170.208.231`, different provider/ASN from the Oracle/Frankfurt gateway) and is a genuine, user-selectable product option: `ProductionGatewayCatalog` (Germany/Stockholm, each with its OWN AWG connection facts and its OWN AWG obfuscation profile - see that class's own docs for why a single global `PocAwgProfile` was a real bug, not a simplification), `SelectedGatewayStore`/`SelectedProductionGatewaySource` (persisted, deterministic manual selection - a real UI picker replaces the old static "Germany / Frankfurt" placeholder), and `SmartConnectCandidateSelector.productionGatewayCandidates` now attributes `ConnectionOutcome`/`PathHistory` to whichever gateway is ACTUALLY selected, never a hardcoded default. AWG on Stockholm is physically handshake- AND data-plane-verified (real device, real 8-second timeout window, ping to the gateway's own tunnel address, exit IP `16.170.208.231` confirmed). AWG on Germany's handshake is unaffected (still real/verified), but a same-day physical re-check found Germany's OWN data plane (post-handshake traffic - ping/curl to the gateway itself) timing out while Stockholm's succeeds on the SAME device/network/build - an operator-side Oracle gateway issue under investigation, not a code regression (see the session's own notes). Kept at FOUNDATION, not IMPLEMENTED: REALITY/TLS are still Germany-only (Stockholm's Xray stack is not yet deployed), and Germany's own data-plane blocker must clear before a truthful two-gateway IMPLEMENTED claim. |
| Gateway Health / Reachability | **FOUNDATION** | `TransportHealth` (Phase 2A) is a real typed model (`UNKNOWN`/`HEALTHY`/`DEGRADED`/`UNREACHABLE`/`NOT_IMPLEMENTED`), now populated with real, transport-level evidence: `TransportHealthCalculator` (B8L1) derives it from `ConnectionOutcomeStore`'s real per-attempt history, wired into `smartConnectDecision()`'s `health` parameter and a diagnostics UI line. Kept at FOUNDATION: `SmartConnectDecisionEngine` still doesn't act on `health` for selection (same "carried through truthfully, not yet decision-driving" boundary as `RestrictionClassifier`). B11 adds the genuinely PER-ENDPOINT counterpart this row used to lack - see Endpoint / Path Reachability Fabric below, kept as its own row rather than merged into this one because `EndpointReachability` answers a materially different question than `TransportHealth` (this endpoint, this transport, this network - vs this transport in general). B12 further splits per-endpoint evidence itself: `ReachabilityEvidenceSummary.controlPlaneReachable` (the gateway's HTTPS API - manifest/activation/provisioning) is now a field DISTINCT from `endpointSpecificReachable` (a real data-plane attempt outcome for that exact endpoint+transport, now derived from `ConnectionOutcomeStore`'s own per-attempt `gatewayId`/`transport` fields rather than reusing the control-plane probe for both) - the task's own "do not collapse control-plane/endpoint/transport signals" requirement. **B13** - this evidence is now actually surfaced in the debug diagnostics UI (`AppRoot.reachabilityDiagnosticsLines`, `DiagnosticsDialog`): manifest version/source/expiry, per-endpoint id/roles/region/provider/ASN/transports, per-(endpoint,transport) reachability state with control-plane and endpoint-specific evidence and their independent ages, and ranked `PathCandidate`s with type/eligibility/score/reasons - built generically by iterating `ReachabilityDiagnosticsSnapshot`'s own lists, so it already renders N endpoints correctly even though only one real one exists today. No secret/credential field is ever included (the underlying types structurally carry none). |
| Endpoint / Path Reachability Fabric | **FOUNDATION** | B11 - the first real endpoint/path model. `EndpointDescriptor`/`EndpointRole`/`EndpointManifest` (typed, provider/ASN-neutral, no hardcoded commercial infrastructure) are signed (Ed25519) and verified (`Ed25519ManifestVerifier`: signature, expiry, clock-skew, monotonic-version rollback protection - `ManifestRollbackGuard`) via `EndpointManifestRepository`, which is backed by a durable last-known-good store (`FileLastKnownGoodManifestStore`) that falls back to a REAL, cryptographically signed embedded bootstrap manifest (`EmbeddedBootstrapManifest`, signed offline by `gateway/tools/manifest_signing.py` - never an unsigned fallback) whenever no valid LKG exists yet - `EndpointManifestRepository.trustedState()` fails closed (`TrustedManifestState.NoneTrusted`) if NEITHER verifies, never silently trusting an unverified manifest merely because it's embedded in the APK. `ReachabilityEngine` derives per-(endpoint, transport) `EndpointReachability` from evidence this codebase already collects - deliberately distinct from `TransportHealth` (see that row's own note) and deliberately conservative (stale evidence and no-network both fall back to UNKNOWN, never a stronger claim). `PathCandidateBuilder` builds `Direct` (today's real shape - see Gateway Pool below for the B12 multi-endpoint proof) and `Relayed` (Client->INGRESS->EXIT, modeled but NOT a working relay protocol) candidates from the manifest's own role/`relayTo` relationships. `PathScorer` ranks them with reachability as the dominant, order-of-magnitude-separated factor (transport health, this-network local history, capability maturity, then small latency/failure/diversity adjustments - each tier's dominance analytically re-derived, not merely asserted, after a real gap was found and fixed in review - see that object's own docs). Network-specific local connection memory (`FilePathHistoryStore`, keyed `networkFingerprint x endpointId x transportKind`) uses an app-local, per-install AndroidKeyStore-HMAC network fingerprint (`NetworkFingerprinter`, deduped/order-independent over coarse signals) - never SSID/BSSID/IMSI/DNS-query history, and not a globally reusable id. **B13 re-audited this and found no violation** - `NetworkProfiler` only ever reads `ConnectivityManager`/`LinkProperties` (network type, resolver IPs, no `WifiInfo`/`TelephonyManager`), `CoarseNetworkSignals` itself never reaches disk (only its derived fingerprint string does, via `PathHistoryStore`), and a new regression test (`NetworkFingerprinterTest`) proves the on-disk `path_history.bin` bytes contain the derived fingerprint but never the raw resolver address that produced it. B12 adds a REAL manifest distribution channel: `GET /v1/manifest` (`gateway/api/handler.py`) serves an operator-deployed, already-signed artifact byte-for-byte - this gateway process never signs or holds a private key - and Android's `HttpsRemoteManifestFetcher`/`ManifestDistributionClient` fetch+`offer()` it through the SAME verification/rollback boundary any other candidate uses (see `docs/B12_MANIFEST_KEY_CEREMONY.md`). Both ends are unconfigured by default (`POCVPN_API_MANIFEST_PATH`/`BuildConfig.MANIFEST_URL` blank) - no production key ceremony has been performed, so nothing live actually serves a real manifest yet. Endpoint-specific data-plane evidence (`ReachabilityEvidenceSummary.endpointSpecificReachable`) now carries its OWN freshness (`endpointSpecificReachableAgeMillis`, independent of `transportHealthAgeMillis`) and expires against an explicit TTL (`ReachabilityEngine.assess`'s `endpointEvidenceStaleAfterMillis`) - an old outcome falls back to the transport-wide health mapping rather than continuing to override current reachability forever (fixed during PR #24 review; see `ReachabilityEngineTest`'s staleness cases). **`PathScorer`'s provider/ASN diversity bonus is real and tested at the `PathScorer` level (`PathScorerTest`) but is currently DISABLED at the one live call site** (`MainViewModel.reachabilityDiagnostics()` passes `diverseProviderOrAsnSeenElsewhere = false` unconditionally) - the batch-wide Boolean it computed before PR #24's review gave every candidate the identical bonus, which has no effect on ranking; a correct per-candidate diversity reference needs a future slice, not an invented provider preference. **Live-wired, OBSERVATIONAL ONLY**: `MainViewModel.reachabilityDiagnostics()` computes real, fresh data on every call. `refreshManifest()` is now ACTUALLY invoked in production - fixed during PR #24's second review, which found it was constructed (`ManifestDistributionClient`) but never triggered, so a configured `MANIFEST_URL` alone did nothing. `MainViewModel`'s `init{}` block now fires it exactly once per ViewModel instance (the same one-time-startup pattern already used for `xrayProfileRepository`'s own init check - never a timer, never re-triggered by Compose recomposition), guarded by a `Mutex` so a concurrent/repeated signal is skipped rather than causing a fetch storm; a failure leaves LKG/bootstrap untouched (`EndpointManifestRepository.offer()`'s own unchanged contract) and nothing here gates or delays `connect()`. Both remain unconfigured by default (`POCVPN_API_MANIFEST_PATH`/`BuildConfig.MANIFEST_URL` blank), so in practice nothing fetches yet - but the trigger itself is real, not merely constructed-and-idle. Nothing in `SmartConnectDecisionEngine`/`AwgXrayFailoverPolicy`/automatic transport selection reads either accessor - kept at FOUNDATION rather than IMPLEMENTED specifically because promoting a winning `PathCandidate` into the real decision boundary is left to a deliberate future promotion slice. `reachabilityDiagnostics()` now builds `Relayed` candidates too whenever the trusted manifest actually expresses an INGRESS->EXIT `relayTo` relationship (fixed alongside an unsafe `as PathCandidate.Direct` cast found in PR #24's second review - the scoring loop is now an exhaustive `when` over both variants, with local path history explicitly deferred/`null` for `Relayed` rather than guessing a key for a multi-hop chain), proven with a real dedicated regression test (`MainViewModelTest`). Only `Direct` candidates over the single real pinned gateway exist in PRODUCTION DATA today, since no real manifest declares a relay relationship yet - `Relayed` is exercised by tests, not real traffic. |
| multi-provider gateway infrastructure | PLANNED | A real, physically-verified production VPS has existed since B10-1/B8O2 (2026-08-30) - this is no longer BLOCKED on "zero provisioned gateways" (see architecture principle 7's own reconciliation). No second provider is deployed; `EndpointDescriptor.provider`/`.asn` (B11) exist as typed fields for when one is, and B12's Gateway Pool row above proves the multi-endpoint CODE path works - only the real second VPS/provider itself is the missing piece, an explicit operator action (see `docs/B12_ENDPOINT_IDENTITY_AUDIT.md` for the credential/activation-model design questions a second gateway would also raise). |
| Private Gateway Mode | PLANNED | No code. Architecture principle 9 applies once designed. |
| Signed Offline Bootstrap | **FOUNDATION** | B11 built the real trust primitives: `EndpointManifest`/`ManifestCanonicalizer` (deterministic, dependency-free binary encoding), `Ed25519ManifestVerifier` (signature + expiry + clock-skew + rollback checks), `FileLastKnownGoodManifestStore` (durable, atomic-write LKG persistence surviving app restart), and a REAL cryptographically-signed `EmbeddedBootstrapManifest`. B12 adds the REAL distribution channel those primitives were missing: `GET /v1/manifest` (`gateway/api/handler.py`, unit- and integration-tested via `gateway/api/tests/test_manifest_endpoint.py` - 245/245 gateway tests green on a real POSIX run) serves an operator-deployed artifact verbatim (this process holds no signing key), and `HttpsRemoteManifestFetcher`/`ManifestDistributionClient` (Android) fetch and `offer()` it through the unchanged verification/rollback boundary. Kept at FOUNDATION, not IMPLEMENTED: `POCVPN_API_MANIFEST_PATH` and `BuildConfig.MANIFEST_URL` are both blank by default - nothing is actually deployed/configured in production, and the embedded trust key remains B11's own placeholder, not a production key-ceremony root. `docs/B12_MANIFEST_KEY_CEREMONY.md` documents the real procedure/rotation path for when that ceremony is actually performed - an explicit operator step, not simulated or claimed complete here. |
| Alternative Control Routing | PLANNED | No code. |
| automatic gateway failover | PLANNED | No code; requires Gateway Pool first. |

## P1

| Capability | Status | Notes |
|---|---|---|
| Connection Memory | **IMPLEMENTED** (recording only - see caveat) | `ConnectionOutcomeStore`/`FileConnectionOutcomeStore` (B8I) are real: durable (`connection_outcomes.bin`, survives app restart), bounded, tested, and already wired into every real connect attempt (`VpnController.recordConnectionOutcome`) - "did AWG/Frankfurt tend to work, and how fast," exactly this row's own description. B11 adds a genuinely NETWORK-SPECIFIC counterpart: `FilePathHistoryStore`, keyed `networkFingerprint x endpointId x transportKind` (an app-local, per-install HMAC fingerprint over coarse network signals - see Endpoint / Path Reachability Fabric's own privacy note), durable and bounded the same way, and B12 proves per-endpoint separation holds under a real multi-endpoint manifest (`GatewayPoolIntegrationTest` - success recorded for endpoint A never credits endpoint B). B12 also derives real per-endpoint DATA-PLANE evidence (`reachabilityDiagnostics()`'s `endpointSpecificReachable`) straight from `ConnectionOutcomeStore`'s own `gatewayId`/`transport` fields - real evidence, no new recording path, no change to `VpnController`. **B13 - `FilePathHistoryStore.record()` is now genuinely wired into the real connect path**: `VpnController.recordPathHistory()` (additive, no-op unless `pathHistoryStore`/`fingerprintKeyProvider`/`networkProfileProvider` are all wired - production always wires them, via the SAME instances `reachabilityDiagnostics()` already reads) is called from the exact same authoritative-outcome sites `recordConnectionOutcome` already uses - one write per real completed attempt (AWG success, AWG handshake timeout, any-kind backend-start failure, one write for a whole exhausted-reconnect cycle) - never for a merely "Connecting" state, never a fabricated candidate, never twice for the same attempt (`VpnControllerPathHistoryTest`). The endpoint this writes against is now the REAL `SmartConnectCandidateSelector`-chosen `GatewayCandidate.id`, threaded through `TransportOrchestrator.Resolution.Resolved.endpointId` and `VpnController.pendingConnectEndpointId` - never a hardcoded `ProductionGateway.ID` literal at the write site (it merely still defaults to it, since only one real endpoint exists). Kept at IMPLEMENTED for the recording mechanism only, NOT for decision-making: neither store yet changes a live Smart Connect decision (see Transport Scoring below, and `SmartConnectCandidateSelector`'s own "genuinely UNUSED for a single-candidate decision today" doc) - B14's own scope, not this one. |
| Transport Scoring | **FOUNDATION** | `TransportScorer` (B8N) is real and unit-tested: a deterministic score combining each transport's real `TransportHealth` (B8L1, dominant signal - a NOT_IMPLEMENTED transport always scores lowest) with its declared `TransportCapabilities.maturity` (tie-break only). Live-wired: `MainViewModel.transportScores()` computes it from the real registry/health on every read and surfaces it in the diagnostics UI. Kept at FOUNDATION, not IMPLEMENTED: deliberately NOT passed into `smartConnectDecision()` - same "real evidence, truthfully surfaced, not yet decision-driving" boundary as `RestrictionClassifier`/`TransportHealth` - `SmartConnectDecisionEngine` still picks by its own fixed `PREFERRED_ORDER`, not this score. |
| Emergency Gateway Rotation | PLANNED | No code; requires Gateway Pool first. |
| Shadowsocks fallback | PLANNED | No code. |
| multi-hop | PLANNED | No code. |
| shared exit pools | PLANNED | No code. |
| RAM-only / diskless gateway infrastructure | PLANNED | No code; today's gateway provisioning writes to disk (`/etc/amnezia/amneziawg/`), by design, for the local-test POC. |
| Traffic Pattern Defense / DAITA-like defense | PLANNED | No code. |
| Traffic Adaptation / DPI Resilience | PLANNED | No code. Purpose: let Nova choose a safe, transport-specific traffic adaptation profile when real evidence suggests DPI/protocol interference, rather than only choosing WHICH transport/endpoint to use (that decision stays `ReachabilityEngine`/`PathScorer`'s job - B11, FOUNDATION). Future decision key: `networkFingerprint x endpointId x transportKind x adaptationProfile -> observed connection outcome` - the SAME `networkFingerprint x endpointId x transportKind` key `FilePathHistoryStore` (B11, Connection Memory row above) already uses today, extended with one more dimension rather than a new, parallel memory model. Safe future adaptation candidates: `NONE` (always the default), TLS handshake/write fragmentation, bounded transport padding, safe transport-level segmentation. Architecture rules for whenever this is actually built: adaptation is always transport-specific (never a global packet mangler shared across transports), `NONE` is always the default and every other profile requires real reachability/failure evidence before ever being selected, outcomes integrate with local Connection/Path Memory and a future `PathScorer` extension (never a separate, disconnected scoring path), retry/strategy rotation must be bounded (no unbounded profile-cycling loop), and no third-party service is ever impersonated (same architecture principle 4 discipline as Hard Whitelist Detection). This does NOT solve a destination-IP hard whitelist (`POSSIBLE_HARD_WHITELIST` - see `RestrictionClassifier`) - DPI/protocol-signature adaptation and a fixed-destination allowlist are different failure modes with different remediations, and must not be conflated. Explicitly NOT adopted from zapret2 or any similar tool, now or later: no root/NFQUEUE dependency, no fake packet injection, no bad-checksum tricks, no TTL manipulation, no TCP sequence/ACK deception, no arbitrary OS-level packet reordering, and zapret2 itself is never embedded or copied into Nova. |
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

Do not cite any UNVERIFIED row above as if it were proven. Each becomes
VERIFIED only when its corresponding gate (B8B/B9/B10) produces real
on-the-wire evidence, the same way B8A did for the local handshake and
B10-1 did for the five rows above.
