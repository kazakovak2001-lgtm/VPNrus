# Nova VPN (VPNrus) - architecture summary

Compact, factual reference for STABLE invariants and CURRENT runtime boundaries only.
This is not a history and not a replacement for `docs/ROADMAP.md` - it exists so a
slice touching one part of the system doesn't require re-reading the whole repo or
the whole ROADMAP. Update it only when stable architecture actually changes (a new
boundary, a new gateway, a genuinely cross-cutting refactor) - not for every slice,
and not for ROADMAP status-only edits.

## Reachability / Smart Connect pipeline (fixed order, do not reorder or bypass)

```
NetworkProfiler
  -> RestrictionClassifier
  -> ReachabilityEngine
  -> PathCandidateBuilder / PathScorer   (live-wired for BOTH manual and auto gateway mode - B16)
  -> SmartConnectDecisionEngine           (picks a TRANSPORT, never a gateway)
  -> TransportOrchestrator
```

- `SmartConnectDecisionEngine`/`AwgXrayFailoverPolicy` still operate WITHIN one
  gateway only (transport choice/intra-gateway AWG->Xray failover) - unchanged by B16.
- **B16 - automatic multi-GATEWAY selection/failover is real, above that
  boundary**: `AutoGatewaySelector` (`smartconnect/AutoGatewaySelector.kt`)
  promotes the SAME `ReachabilityEngine`/`PathCandidateBuilder`/`PathScorer`
  pipeline (reused verbatim, never a parallel scorer) into a ranked
  `GatewayAttemptCandidate` list. Only engaged when
  `MainViewModel.gatewayAutoMode` is true (persisted, default `false`/Manual -
  every pre-B16 install/test is unaffected). Manual gateway selection
  (`SelectedGatewayStore`/`selectGateway()`) is byte-for-byte unchanged and
  always wins when active - selecting a gateway manually also turns Auto off.
- **B17 - runtime authority for Auto DISCOVERY AND execution-time endpoint
  address moved to the signed manifest, superseding B16's own shortcut**:
  `AutoGatewaySelector.buildCandidates` takes `manifestEndpoints: List<EndpointDescriptor>`
  - the caller (`MainViewModel.buildAutoGatewayCandidates`) supplies
  `manifestRepository?.trusted()?.endpoints` (empty when nothing verifies -
  `TrustedManifestState.NoneTrusted` or `manifestRepository` unwired - which
  always yields zero candidates, never a fallback). WHICH endpoints even
  exist as candidates is gated by the trusted manifest, never
  `ProductionGatewayCatalog` enumerated directly.
  **Four distinct fact tiers, never conflated (B17-2 fix)**:
  1. **Manifest-owned public facts** - endpoint id/roles/region/provider AND,
     critically, each transport binding's `host`/`port`. `snapshotFor()`'s
     `endpointHost`/`endpointPort` are now read from the manifest transport
     `binding` carried alongside each scored candidate (`Triple<ProductionGatewayDescriptor, EndpointTransportBinding, PathScoreResult>`
     in `buildCandidates`'s internal map) - NEVER from
     `gateway.awg.endpointHost`/`endpointPort` (the catalog). A signed
     manifest advertising a rotated AWG address now genuinely changes what
     the next candidate's pinned `GatewayConfigSnapshot` dials -
     `AutoGatewaySelectorTest`/`MainViewModelAutoGatewayTest` prove this
     with a manifest host deliberately DIFFERENT from the catalog's,
     confirmed all the way to the executed `AwgConfig.peer.endpointHost`.
  2. **Catalog compatibility facts** (`ProductionGatewayCatalog`, via
     `gatewayFactsFor: (EndpointId) -> ProductionGatewayDescriptor?`,
     invoked ONLY for an endpoint id the manifest already named) - AWG
     server public key, gateway tunnel IP, and obfuscation profile, which
     the manifest model does not carry today (a real, honest scope
     boundary - `EndpointTransportBinding.metadata` deliberately never
     holds key material, see that type's own docs).
  3. **Local per-device identity** (`ClientTunnelIdentityStore`, via
     `provisioned`/`clientTunnelIp`) - this device's own peer address,
     never manifest- or catalog-owned, unchanged.
  4. **Xray/TLS execution address - still SEPARATE, still catalog/manifest-independent**:
     `VpnController.buildTransportConfig`'s XRAY_REALITY/TLS_TCP branches
     resolve the connect-time server host/port from the endpoint-scoped
     `XrayProfileRepository`/`XrayTlsProfileRepository` (populated by real
     control-plane activation), never from `GatewayConfigSnapshot` at all -
     `GatewayConfigSnapshot` is consumed ONLY by the AWG execution path
     (`TransportConfig.Awg`). Every `GatewayAttemptCandidate` still carries
     one (the "Candidate identity" invariant applies uniformly), and an
     XRAY_REALITY/TLS_TCP candidate's snapshot is now ALSO manifest-derived
     for consistency, but changing that snapshot has NO effect on where an
     Xray/TLS attempt actually connects - a signed manifest does not yet
     control Xray/TLS execution addressing, and this PR does not claim it
     does (no unsafe migration of Xray profile ownership was performed to
     force this scope).
  Local per-device provisioning (`provisioned`/`clientTunnelIp`, plus
  `xrayAvailableFor`/`xrayTlsAvailableFor` gating which of the manifest's
  declared transport bindings this device can actually use) still combines
  with the manifest facts exactly as before - a manifest naming an endpoint
  never implies this device is provisioned for it.
  The embedded bootstrap (`EmbeddedBootstrapManifest`, version 1) and the
  production trust root are the SAME real Ed25519 key (see
  `docs/B12_MANIFEST_KEY_CEREMONY.md`'s "Production ceremony (B17)"
  section); the bootstrap names BOTH real gateways (frankfurt, stockholm).
  Live `GET /v1/manifest` is deployed on BOTH production gateways and now
  serves a REAL, strictly-newer **version 2** (same key, no rotation - see
  `docs/B12_MANIFEST_KEY_CEREMONY.md`'s versioning section), deliberately
  kept ahead of the embedded v1 bootstrap so a real device actually adopts
  it into LKG rather than rejecting it as "not newer".
  **B20 - multi-origin fetch, same trust boundary**: `BuildConfig.MANIFEST_URLS`
  (plural, comma-separated) defaults to BOTH real production origins -
  Frankfurt `https://152.70.43.1/v1/manifest` and Stockholm
  `https://16.170.208.231/v1/manifest` - in both `debug`/`release` builds
  (`android/app/build.gradle.kts`'s `PRODUCTION_MANIFEST_ORIGIN_URLS`,
  overridable via a developer's own gitignored `gateway-dev.properties`,
  `manifestUrls=...`; the pre-existing single-URL `manifestUrl=...` override
  still works). `ManifestOriginConfig.parse` rejects blank/malformed entries
  and deduplicates. `MultiOriginManifestDistributionClient` (replacing the
  single-origin wiring in `MainViewModel.Factory`) tries every configured
  origin, in order, on EVERY refresh (never stops early on the first
  accepted origin) - each origin's fetched bytes go through the SAME
  `EndpointManifestRepository.offer` signature/expiry/rollback boundary
  `ManifestDistributionClient` always used (reused internally per origin,
  not reimplemented); an origin is transport availability only, NEVER a
  trust authority. Because `offer()` re-checks rollback against whatever is
  CURRENTLY trusted at each call, trying every origin every refresh is what
  makes "highest valid version wins" correct for free - a later origin
  returning a strictly newer valid manifest is still adopted even after an
  earlier origin's (also-valid, older) candidate was already accepted in the
  same refresh. **PR #34 follow-up fix (2026-09-01) - typed classification,
  not string parsing**: `ManifestFetchResult.Failed` carries a typed
  `ManifestFetchFailureKind` (`NETWORK_ERROR`/`TLS_ERROR`/`HTTP_ERROR`/
  `MALFORMED`), and `ManifestVerificationResult.Invalid`/`ManifestUpdateResult.Rejected`
  each carry a typed `ManifestVerificationFailureKind`/`ManifestUpdateRejectionKind`
  (`UNKNOWN_SIGNING_KEY`/`CLOCK_SKEW`/`EXPIRED`/`INVALID_SIGNATURE`, plus
  `ROLLBACK_OR_NOT_NEWER` added by `EndpointManifestRepository.offer` itself)
  - set at the exact point each result is produced (`Ed25519ManifestVerifier`,
  `EndpointManifestRepository.offer`, `HttpsRemoteManifestFetcher`), never
  inferred afterwards from `reason`/`detail` text. `ManifestOriginOutcomeKind`
  is a presentation-layer AGGREGATION of those typed categories via two
  small EXHAUSTIVE `when` mappings (`ManifestFetchFailureKind.toOriginOutcomeKind`/
  `ManifestUpdateRejectionKind.toOriginOutcomeKind` in `ManifestOrigin.kt`) -
  a compile error, not a silent misclassification, if either underlying enum
  ever gains a category this one doesn't cover yet.
  `MultiOriginManifestDistributionClient` never inspects a `reason`/`detail`
  string to decide anything - genuinely one typed vocabulary reused at a
  presentation layer, not a second independently-inferred one.
  `MainViewModel`'s one
  logical startup refresh and `manifestRefreshMutex` bounded-concurrency
  behavior are both unchanged; `refreshManifest()`'s return type is now
  `MultiOriginRefreshResult`. Control-plane isolation is unchanged/hard: no
  type in `ManifestOrigin.kt` references `EndpointReachability`/
  `TransportHealth`/`PathScorer` - manifest-origin fetch failure can never
  feed B19 path eligibility. A debug-only "Refresh manifest" button
  (Diagnostics dialog, `MainViewModel.debugRefreshManifest`) calls the EXACT
  same production `refreshManifest()` path for manual/deterministic
  physical validation - no parallel test client.
  **Physically verified on a real device (B17-2, 2026-09-01)**: a clean
  restart genuinely fetched the live v2 manifest over HTTPS, and it was
  genuinely ACCEPTED (`Last manifest refresh: accepted version 2`,
  `Manifest version: 2 (source=LAST_KNOWN_GOOD)`) - a REAL populated LKG,
  not merely the embedded bootstrap; both endpoints/6 ranked Auto
  candidates present with REACHABLE evidence; a real Auto connect reached
  Protected/Germany. Under a reversible, client-side-only airplane-mode
  fault (no production VPS touched, no route altered), a force-restart
  produced `Last manifest refresh: rejected: network error: ConnectException`
  while `Manifest version: 2 (source=LAST_KNOWN_GOOD)` and the full
  6-candidate list SURVIVED - proving the genuinely-populated LKG persists
  across both a restart and a subsequent remote-fetch failure, not just the
  embedded-bootstrap fallback path. Restoring network and reconnecting in
  Auto reached Protected/Germany again; the airplane-mode fault was
  restored immediately. Signed Offline Bootstrap is now **IMPLEMENTED**,
  no remaining caveat on the LKG path (see ROADMAP's own row for the full
  evidence trail). The "no LKG, embedded v1 bootstrap accepted" migration
  case remains proven at the unit level only (`EmbeddedBootstrapManifestTest`,
  `EndpointManifestRepositoryTest`) - sufficient per this slice's own scope,
  since a real device with a real v2 LKG can no longer exercise a genuinely
  empty-LKG state without wiping real provisioning.
  **Physically verified on a real device (B20, 2026-09-01)**: baseline - both
  configured origins (`152.70.43.1`, `16.170.208.231`) genuinely attempted on
  every refresh (startup AND the new debug manual button), diagnostics shows
  per-origin evidence (`Last manifest refresh: 152.70.43.1=...;
  16.170.208.231=... | final: ...`), trusted manifest stays v2/LKG, all 6
  Auto candidates (both gateways x 3 transports) present, Auto connect
  reaches Protected/Frankfurt. Fault injection (reversible, client-side-only,
  debug-build `gateway-dev.properties` override pointing ONLY the Frankfurt
  origin slot at an unreachable `127.0.0.1:1` - no production server
  touched, no route/DNS/airplane-mode change, so unlike B17-2's airplane-mode
  fault this leaves the rest of the device's internet and the VPN data plane
  completely unaffected): Frankfurt origin genuinely failed
  (`127.0.0.1=NETWORK_ERROR`), Stockholm was genuinely still attempted and
  its real signed artifact verified through the SAME trust boundary
  (`16.170.208.231=ROLLBACK_OR_NOT_NEWER`, i.e. valid-but-not-newer-than-v2 -
  proving verification succeeded), LKG/v2 remained trusted throughout, Auto
  candidates stayed fully populated, and a real Auto connect still reached
  Protected/Frankfurt (control-plane manifest-origin failure never touched
  the AWG data plane). Restoring `gateway-dev.properties` and rebuilding
  confirmed both origins reachable again. The "highest valid version wins"
  and "bad-origin crypto candidate never poisons LKG" scenarios are proven
  at the unit level (`MultiOriginManifestDistributionClientTest`, 13 cases)
  rather than physically, per this slice's own scope (a safe physical
  mechanism to make ONE production origin serve a differently-versioned or
  tampered-but-still-HTTPS artifact would require touching a production
  server or standing up new infrastructure, both explicitly out of scope).
- **Candidate identity/execution (hard invariant, consolidated review fix)**:
  each `GatewayAttemptCandidate` carries its own already-resolved
  `configSnapshot`. `AutoGatewaySelector`'s candidate is threaded verbatim -
  `MainViewModel.attemptAutoCandidate` passes it to
  `TransportOrchestrator.resolve(..., gatewayConfigSnapshot = candidate.configSnapshot)`,
  which carries it into `TransportOrchestrator.Resolution.Resolved.gatewayConfigSnapshot`.
  `VpnController.connect()` pins that value (`pendingConnectConfig`) for the
  WHOLE attempt, including across a VPN-permission-prompt round-trip;
  `doConnectAttempt()` and `gatewayStatus()` both resolve through this SAME
  pinned value (via `GatewayConfigSnapshotValidator`, the extracted validator
  `DefaultGatewayConfigurationRepository` also uses) whenever it is set -
  `gatewayConfigurationRepository`/`SelectedGatewayStore`/
  `ProductionGatewayCatalog`/`ClientTunnelIdentityStore` are NEVER
  re-consulted once a candidate is pinned. `VpnControllerPinnedGatewayConfigTest`
  proves this directly (mutating the repository/identity store after pinning,
  including across the permission-resume gap, cannot change what executes).
  Manual mode never carries a snapshot, so `doConnectAttempt`/`gatewayStatus()`
  fall through to `gatewayConfigurationRepository` exactly as before B16.
- **Bounded cross-gateway failover, and its exact relationship to
  `AwgXrayFailoverPolicy` (consolidated review fix)**: `armFailoverWatch()`
  branches on whether the retained attempt carries an `autoContext` BEFORE
  it ever reaches the `AwgXrayFailoverPolicy` check. During an Auto sequence,
  `AwgXrayFailoverPolicy` is NOT consulted at all - on a genuine terminal
  failure (`AutoGatewayFailoverPolicy.isEligibleForNextCandidate`, the same
  enumerated HandshakeTimeout/BackendStartFailure categories
  `AwgXrayFailoverPolicy` itself uses), the collector advances to the next
  candidate in the ONE globally-ranked gateway×transport list
  (`AutoGatewaySelector.nextCandidate`) - a failed AWG attempt on one gateway
  can be followed by ANY higher-ranked remaining candidate (that same
  gateway's own Xray/TLS, or the OTHER gateway's AWG), purely by rank, never
  a hardcoded per-gateway chain. Bounded by `MAX_ATTEMPTS=4`, never retrying
  an already-attempted (gateway, transport) pair; exhausting the ranked set
  fails closed (`VpnError.NoCandidateAvailable`). `AwgXrayFailoverPolicy`'s
  own intra-gateway AWG->Xray fallback (`maybeFailoverToXray`) is completely
  unchanged and governs ONLY Manual mode (`autoContext == null`) - it does
  NOT additionally run "within" an Auto sequence's current gateway.

## Health-aware Auto ranking (B19)

- `AutoGatewaySelector`/`PathScorer` remain the SINGLE decision authority for
  automatic gateway+transport ranking (unchanged architecture, B16) - B19 only
  fixes/extends what feeds that one scorer, never adds a second one.
  `SmartConnectDecisionEngine.decideAuto` (Manual-gateway-mode's own transport
  picker) deliberately still ignores `TransportHealth` - the two authorities
  are never merged (architecture principle 1).
- **Diversity bonus fix**: `PathScorer.score`'s `diverseProviderOrAsnSeenElsewhere`
  is now a genuine PER-CANDIDATE signal computed by `AutoGatewaySelector` (a
  pre-pass identifies provider/ASN keys with fresh negative evidence in the
  current batch; only a candidate on a different, non-troubled provider/ASN
  gets the bonus, and only when a troubled alternative actually exists) -
  never an identical batch-wide Boolean (the B12-era bug this replaces).
- **Bounded failure cooldown**: `PathHistoryEntry.consecutiveFailures` (the
  RECENT streak, distinct from the lifetime `failureCount`) drives a capped,
  time-decaying penalty in `PathScorer.score` (`FAILURE_COOLDOWN_WINDOW_MILLIS`) -
  resets to 0 on the next success, expires on its own after the window, never
  a permanent blacklist, never a second persistence system (same
  `FilePathHistoryStore` file, format version bumped 1->2).
- **Typed reasons**: `PathScorer.Reason` (`ENDPOINT_REACHABLE`/`TRANSPORT_HEALTHY`/
  `FAILURE_COOLDOWN`/`DIVERSITY_BONUS`/etc) are appended to `PathScoreResult
  .reasons` alongside the pre-existing free-text summaries - never replacing
  them, so no pre-B19 reader breaks.
- Precedence (unchanged, B11-established, re-verified this pass): fresh
  endpoint-specific reachability > transport-wide health > this-network
  history > capability maturity > small latency/failure/cooldown/diversity
  adjustments - enforced by `PathScorer`'s own order-of-magnitude tiering,
  never a flat weighted sum.
- **Eligibility (B19-3, a separate concern from ranking, checked first in
  `PathScorer.isEligible`/`ineligibilityReason` - the ONE place, never a
  second filtering layer in `AutoGatewaySelector`/`MainViewModel`/
  `TransportOrchestrator`)**: fresh endpoint-specific `ReachabilityState
  .UNREACHABLE` -> ineligible regardless of transport health (the strongest,
  most specific signal); `TransportHealthState.NOT_IMPLEMENTED` ->
  ineligible; transport-wide `TransportHealthState.UNREACHABLE` ->
  ineligible UNLESS some hop is fresh-confirmed `REACHABLE` (fresh
  endpoint-specific evidence is never overridden by a coarser transport-wide
  claim); `DEGRADED`/`UNKNOWN` on either signal remain eligible, penalized
  only by scoring. Stale evidence never needs a second freshness check here -
  `ReachabilityEngine.assess` already decays it to `UNKNOWN` before
  `PathScorer` ever sees it. An ineligible `PathScoreResult` (`score =
  Long.MIN_VALUE`) never becomes an executable `GatewayAttemptCandidate` -
  `AutoGatewaySelector` already only promotes `eligible == true` results, so
  an ineligible candidate structurally never consumes a `MAX_ATTEMPTS` slot.
- **Physically verified end to end (2026-09-01)**: on the real test device,
  in real Auto mode, two real `FAILURE` outcomes for Frankfurt AWG (written
  via a minimal debug-only Diagnostics button - `MainViewModel
  .debugRecordConnectionFailure` - through the EXACT SAME `ConnectionOutcomeStore`/
  `FilePathHistoryStore` a real failed attempt already writes to, no server
  config touched) demoted Frankfurt AWG to last place
  (`ENDPOINT_UNREACHABLE`/`TRANSPORT_UNREACHABLE`/`FAILURE_COOLDOWN`,
  score=-1080) and promoted Frankfurt XRAY_REALITY to first
  (score=2020000); connecting genuinely executed XRAY_REALITY and reached
  `Protected`. A real-shaped `SUCCESS` write plus a real (non-simulated) AWG
  connection restored AWG to first place
  (`RECENT_SUCCESS_THIS_NETWORK`, score=3030975) and executed AWG again.
  Transport preference stayed `Auto` throughout - the reordering came
  entirely from ranking evidence, never from `AwgXrayFailoverPolicy` or a
  manual override. Device left clean (Auto/Auto, no fault, `Protected`).

## Routing decision vs transport/gateway selection (hard invariant, B18)

- `RoutingDecisionEngine.decideAdaptiveRoute` (`smartconnect/RoutingDecisionEngine.kt`)
  is the ONE live authority for DIRECT vs VPN at the destination-route level -
  never merged with `SmartConnectDecisionEngine` (transport) or
  `AutoGatewaySelector` (gateway). Input: a top-level, persisted, device-local
  `RoutingMode` (`FULL_VPN`/`ADAPTIVE`/`APPS`, default `FULL_VPN`,
  `vpn/policy/RoutingMode.kt`), a route-prefix-only `DestinationClass`
  (`LOCAL_PRIVATE` - RFC1918/loopback/link-local, computed by the
  provably-correct `Ipv4RouteExclusion` CIDR-subtraction utility - vs
  `PROTECTED`, everything else; never per-packet/hostname/domain
  inspection), and `RestrictionClass` (`RestrictionClassifier`'s output,
  wired into a routing decision for the first time here). Conservative by
  construction: only `RestrictionClass.NO_NETWORK` ever changes the
  outcome (-> `Block`); every "possible filtering" class NEVER routes
  `PROTECTED` traffic DIRECT - no hard-whitelist bypass exists or is
  claimed.
- Precedence rule: `AppRoutingPolicy` (B8H, unchanged) decides WHICH APPS'
  traffic reaches the VPN interface at all; `RoutingMode`/
  `RoutingDecisionEngine` decides, only for traffic that does, whether its
  destination goes DIRECT or through the tunnel. `RoutingMode.APPS` is
  byte-for-byte identical to `FULL_VPN` at the destination-route layer -
  Adaptive mode can never broaden which apps bypass the VPN.
  `routingModeStore` is read fresh only at the start of a real `connect()`
  attempt (`VpnController.appliedRoutingMode`) - same "no live mid-session
  rebuild, reconnect to apply" discipline as `AppRoutingPolicy`.
- Live enforcement is consistent across every currently-live transport
  (B18-2). `VpnController.resolveAdaptiveAllowedIps` (AWG) and
  `net.pocvpn.client.vpn.xray.buildXrayVpnPlan` (XRAY_REALITY/TLS_TCP) both
  resolve their IPv4 route list through the ONE shared
  `RoutingDecisionEngine.resolveIpv4Routes` function - never a second CIDR
  computation, never a parallel routing decision. `RoutingMode` reaches the
  Xray/TLS path via `TransportConfig.Xray/XrayTls.routingMode` ->
  `NovaXrayVpnService.EXTRA_ROUTING_MODE` (same intent-extra pattern as
  `EXTRA_TRANSPORT_KIND`/`EXTRA_ENDPOINT_ID`), defaulting to `FULL_VPN` at
  every hop so every pre-B18-2 call site is byte-for-byte unaffected. Only
  the IPv4 entries are ever touched: AWG's AllowedIPs keeps its `::/0` entry
  verbatim in every mode; `XrayVpnBuilderPlan` structurally has no IPv6
  field at all (unchanged) - IPv6 stays fail-closed on every transport, in
  every `RoutingMode`. `RestrictionClass` is NOT live-threaded into the
  Xray/TLS path (defaults `UNKNOWN`) - a documented, safe simplification:
  only `RestrictionClass.NO_NETWORK` changes `resolveIpv4Routes`'s output,
  and `UNKNOWN` yields the identical route set AWG yields for every other
  class, so both transports' ADAPTIVE route sets are provably identical for
  every reachable live case. **Physically verified end to end (2026-09-01) -
  IMPLEMENTED**: a real device's live `dumpsys connectivity` route table for
  `tun0` was checked directly before/after switching `RoutingMode` - Full
  VPN shows plain `0.0.0.0/0`/`::/0`; Adaptive shows the exact
  `Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES` complement. **Xray/TLS
  consistency is physically proven**: a genuinely minimal debug-only
  trigger (`MainViewModel.debugSetTransportPreference`, one button in the
  existing `isDebugBuild`-gated Diagnostics dialog) pins
  `UserTransportPreference.Manual(XRAY_REALITY)` for the next `connect()` -
  a real mechanism `SmartConnectDecisionEngine`/`AutoGatewaySelector`
  already read but no product UI could reach - driving the REAL connect
  path end to end (never a second Xray connection path). The resulting live
  Xray `tun0` session's route table matched AWG's Adaptive session
  entry-for-entry, with `::/0 unreachable` confirming IPv6 fail-closed at
  the OS level for Xray specifically.
  **Live AWG traffic/DNS - root-caused and fixed.** `tun0` RX stuck at zero
  bytes (TX climbing normally, identically on WiFi and cellular) was
  diagnosed via read-only SSH to the Frankfurt gateway: server-side data
  plane (forwarding/NAT/FORWARD chain) was fully healthy throughout - the
  defect was a stale `ClientTunnelIdentityStore[GERMANY]` value on this one
  test device (`10.77.0.2`) that no longer matched the server's actual peer
  registration for this device's public key (`10.77.0.5/32`, uniquely
  assigned - `10.77.0.2` had since been reassigned to a different, active
  peer). WireGuard's cryptokey routing silently drops decrypted packets
  whose source doesn't match the peer's AllowedIPs, inside the kernel WG
  module, before netfilter - exactly matching the symptom. Fixed by
  re-provisioning through the REAL control-plane flow (a fresh activation
  credential issued via the gateway's own operator tool, submitted through
  the unmodified `MainViewModel.activateDevice`/`/v1/activate` path - never
  a hand-edited store), reached via one more minimal debug-only Diagnostics
  button ("Re-activate Germany") that opens the existing `ActivationScreen`
  for an already-provisioned gateway (mirrors B15's own mechanism for an
  unprovisioned one). After re-provisioning: `tun0` RX climbs normally, a
  real request to `cdn-cgi/trace` returned `ip=152.70.43.1`/`loc=DE` in both
  Full VPN and Adaptive modes - conclusive proof public/protected traffic
  genuinely exits through the Frankfurt gateway in both modes, with DNS
  validated through the tunnel (`ValidatedPrivateDnsAddresses`) and IPv6
  unaffected. Device restored to Full VPN/Auto preference/clean afterward.

## Per-device identity (hard invariant)

- Client tunnel IP is per-device, per-endpoint, PROVISIONED identity - lives only in
  `ClientTunnelIdentityStore`. Never hardcoded into `ProductionGatewayCatalog`.
- Missing identity for an endpoint -> fail closed. Never borrow another endpoint's
  identity, never guess, never mark that endpoint usable anyway.
- A control-plane response (live activation or legacy persisted profile) is mapped to
  a gateway id via `ProductionGatewayCatalog.matchGatewayId` (host+port+key+
  gatewayTunnelIp together, never host alone, never inferred from current UI
  selection). A response matching no known gateway, or a DIFFERENT gateway than the
  one requested, is rejected outright - never accepted-but-ignored.

## Control-plane vs data-plane

- `gateway/api/*.py` (`pocvpn-api`) is fully env-var-driven per instance - zero
  gateway-specific hardcoding in the Python code itself. A second gateway's
  control-plane is a pure deployment action (see `gateway/DEPLOYMENT.md`'s "Deploying
  a second gateway" section), not a code change.
- Client-side: `ProvisioningClient.activate/fetchXrayProfile/fetchXrayTlsProfile` have
  endpoint-aware overloads that POST to the REQUESTED gateway's own edge
  (`ProductionGatewayCatalog.<GATEWAY>.awg.endpointHost`).
  `MainViewModel.activateDevice(credential, targetGatewayId)` routes to that
  gateway's own activation client and its own `XrayProfileProvisioner`/
  `XrayTlsProfileProvisioner` pair, writing only that gateway's
  `ClientTunnelIdentityStore` entry and only that gateway's own endpoint-scoped
  `XrayProfileRepository`/`XrayTlsProfileRepository`.
- Xray/TLS availability (`buildTransportRegistry`) is per-endpoint
  (`xrayAvailableEndpoints`/`xrayTlsAvailableEndpoints`, `Set<EndpointId>`) - one
  endpoint's profile can never make a different endpoint appear available.

## Current gateway state (verify against `docs/ROADMAP.md`'s Gateway Pool row before
relying on this for anything user-facing - this table is a snapshot, ROADMAP is truth)

| | Germany / Frankfurt | Stockholm / Sweden |
|---|---|---|
| Provider | Oracle Cloud | AWS eu-north-1 |
| AWG data plane | physically validated | physically validated |
| REALITY / TLS data plane | physically validated | physically validated (operator/debug-provisioned credentials) |
| Self-service control-plane (`/v1/activate`) | deployed, live | deployed, live (B15) - 443 edge externally reachable (security-group fix applied by operator), real physical-device activation completed successfully |
| AWG client identity provisioning | real, self-service | real, self-service (B15) - physically verified: real device activation, real AWG handshake, exit IP `16.170.208.231` |
| Public IP addressing | stable | AWS auto-assigned, NOT durable/reserved |

Gateway Pool remains **FOUNDATION** (see ROADMAP's own Gateway Pool row for
why - Stockholm's non-durable IPv4 addressing is unrelated to and unresolved
by B16). Automatic multi-gateway selection/failover is now **IMPLEMENTED**
(real candidate construction/ranking/bounded failover, unit-proven AND
physically validated on a real device 2026-09-01: real Auto connect to
Germany, a real on-device fault excluding Germany, real Auto failover to
Stockholm with a confirmed real `16.170.208.231` data-plane connection,
restore, confirmed normal reconnect) - see ROADMAP's own B16 row for the
exact scope, including its one honest caveat (a genuine mid-connect()
AWG-handshake-timeout retry trigger remains unit-test-only, not physically
reproduced - root/server access would be required).

## Production vs debug boundary

- `XrayDiagnosticsActivity` (and any future manual/debug provisioning helper) lives in
  the `debug` Gradle source set only - must stay absent from the release manifest.
- Normal product UI (picker/LocationCard/Home) shows geography only - no provider/ASN
  names. Provider metadata is diagnostics/debug-only.

## Infrastructure safety

Never allocate/purchase paid cloud resources (including Elastic IPs) or make
destructive production changes without explicit owner approval - this applies to any
change, not just gateway-related ones.

## QUIC transport (B21) - a third Xray adapter, not a new architecture

`TransportKind.QUIC` is real QUIC/HTTP-3 via xray-core's XHTTP transport
(`network: "xhttp"`, `mode: "stream-one"`, TLS ALPN `h3`) - the pinned
xray-core `v26.7.28`'s standalone `"quic"` network value is a removed,
hard config-load error (see `docs/B21_QUIC_TRANSPORT_AUDIT.md` for the
pinned-source citation and local `xray run -test` empirical validation).
It is a THIRD instance of the exact same pattern REALITY/TLS_TCP already
established - same `NovaXrayVpnService`/`XrayCoreController`/tun-inbound
shell, same VLESS UUID identity model (no REALITY key material - QUIC/UDP
has no defined REALITY behavior), its own endpoint-scoped profile
repository/listener/port. `AutoGatewaySelector`/`PathScorer`/
`TransportHealth`/`ReachabilityEngine` needed zero QUIC-specific code -
they already generalize over `TransportKind`. Kept at FOUNDATION: real
client+server code, unit-tested and locally `-test`-validated against the
real pinned binary, but no production UDP port exists yet on either
gateway (opening one is a firewall/security-group change requiring
explicit operator approval, not performed in B21) and no physical device
has executed a real QUIC session.

**B21 continuation - production port opened on Frankfurt, real client-side
defect found (hard invariant gap, not QUIC-specific)**: with explicit
operator approval, `2087/udp` was opened on Frankfurt and the QUIC/XHTTP
inbound deployed through the existing `xray_reconcile.py` stage/validate/
publish path - `xray run -test` passed, all four listeners
(`2053/tcp`/`2083/tcp`/`2087/udp`/`51820/udp`) confirmed live, `pocvpn-api`
confirmed to accept `{"transport":"quic"}`. A real, previously-missed
wiring bug was found and fixed: `NovaXrayVpnService`'s own
`XrayCoreController(...)` construction never actually passed a
`quicRepository` (the parameter existed with a safe null default, wired
everywhere else, but never at the one real production call site) - fixed,
full suite re-verified green. **After the fix, physical validation
revealed a deeper, real architectural gap**: a real device reported
`Protected`/`Current transport: QUIC` after a real activation and real
connect(), but Frankfurt's own firewall packet counter for `2087/udp`
stayed at exactly 0 across every attempt, and real browser traffic through
the tunnel failed (`DNS_PROBE_FINISHED_NO_INTERNET`) - the client never
sent a single UDP packet toward the server. Root cause not yet isolated
(a build-time gap between the pinned commit's official Linux server binary,
independently `-test`-validated for the identical config, and the
`AndroidLibXrayLite` gomobile AAR built from the same commit, is the
leading candidate, unverified). **The gap this exposes is real and applies
to the whole Xray transport family, not just QUIC**: unlike
`AmneziaWgTransport.awaitFreshHandshake` (a genuine post-connect
handshake-freshness check before AWG reports `Connected`), no Xray-family
transport (`XRAY_REALITY`/`TLS_TCP`/`QUIC`) verifies any data-plane
handshake at all before reporting `Connected` -
`XrayCoreController.requestStart` returning `Started` only means
`coreRuntime.startLoop()` did not throw (the Go runtime's goroutines
launched), never that a real proxied session succeeded. REALITY/TLS_TCP
are not newly suspected of failing the same way (both have independent
prior physical proof of real proxied traffic), but the verification gap
itself was previously undocumented and is now a known, real limitation -
closing it (an active data-plane liveness check for Xray-family
transports, analogous to AWG's) is a real, separate future slice, not
performed here. QUIC remains at FOUNDATION - not one real completed
proxied session exists yet.

**B21 continuation 2 - Android binary audit (rules out the AAR itself),
false-positive Connected closed for the whole Xray family**: direct
string/symbol inspection of the shipped `libv2ray-androidlibxraylite-
c634d1b.aar`'s native `libgojni.so` (all four ABIs) confirms XHTTP/H3/
quic-go ARE linked in - `"listening QUIC for XHTTP/3 on"`,
`"XHTTP stream-one H2 & H3"`, and the full quic-go/http3 symbol set are
present. The AAR is not the gap. `javap` against the AAR's own
`classes.jar` shows its Java API exposes no separate socket/protect
callback at all (`newCoreController(CoreCallbackHandler)`,
`registerProcessFinder`, `measureDelay` - nothing protect-shaped) - the
per-app-UID `addDisallowedApplication` bypass this shell already uses for
REALITY/TLS_TCP is the AAR's only bypass mechanism, unchanged for QUIC, so
it is not a differential suspect either. The two real, fixed gaps: (1)
`XrayCoreRuntime`'s `CoreCallbackHandler` was a `NoopCoreCallbackHandler`
that discarded every xray-core startup/shutdown/status line - the ONE
channel the Go runtime had for reporting a config-load or dial failure was
thrown away client-side before this fix; it is now `XrayCoreDiagnostics`
(DEBUG-only, bounded, sanitized). (2) `XrayCoreController.requestStart`
now requires a real `XrayDataPlaneReadinessCheck` (wraps the AAR's own
`CoreController.measureDelay(url)` - the one genuine "outbound actually
passes traffic" signal this AAR exports - with a bounded timeout) to
succeed before ever reporting `Started`/`Connected`, for REALITY/TLS_TCP/
QUIC alike; a timeout or dial failure now stops the just-started core,
closes the tun, and reports a typed `DataPlaneNotReady` failure instead.
QUIC's own client-side root cause (why zero packets left the device) is
still not physically isolated - this fix makes that failure visible and
non-Connected instead of silently false-positive; a physical Frankfurt
retest with the new diagnostics attached is the next real step and has
not been performed from this environment (no physical device attached
here).

## Config resolution atomicity

`SelectedProductionGatewaySource.snapshot()` resolves the selected gateway id exactly
once per `GatewayConfigurationRepository.get()` call - a concurrent selection change
mid-resolution can never combine one gateway's host with a different gateway's key/
identity/profile. `GatewayConfigSource.snapshot()` is the one method
`DefaultGatewayConfigurationRepository` actually calls; the six individual getters
exist for direct testability but must not be relied on for atomicity by new callers.

---
Last updated: 2026-09-01 (B19 - added the "Health-aware Auto ranking" section
above: fixed the disabled provider/ASN diversity bonus and added a bounded,
time-decaying failure cooldown to PathScorer, both consumed only by
AutoGatewaySelector - the single, unchanged Auto decision authority. Physically
validated end to end on a real device this pass (baseline, controlled
dynamic reordering via debug-injected real evidence, restore) - see this
section's own closing paragraph. Existing suite (878 tests) unaffected.)

Last updated: 2026-09-01 (B18/B18-2 - added the "Routing decision vs transport/
gateway selection" section above: RoutingMode/RoutingDecisionEngine
.decideAdaptiveRoute is the real, live DIRECT-vs-VPN authority, route-prefix-
level only, with RestrictionClassifier wired in conservatively. B18-2 extended
live enforcement from AmneziaWG-only to ALL currently-live transports
(AMNEZIA_WG/XRAY_REALITY/TLS_TCP) through one shared resolver
(RoutingDecisionEngine.resolveIpv4Routes) - no second routing engine, no
duplicated CIDR math. Physical validation completed 2026-09-01 after fixing
an unrelated stale-client-identity issue on the test device (see this
section's own closing paragraph) - Adaptive Direct Routing is now
IMPLEMENTED. Everything below this line predates B18 and is unaffected by it.)

Last updated: 2026-09-01 (B17 - Auto gateway/path DISCOVERY runtime authority
moved from `ProductionGatewayCatalog` to the verified `TrustedManifestState`;
the production Ed25519 key ceremony was performed (real keypair, private key
never printed/committed, stored offline outside the repo) and the embedded
bootstrap now names both real gateways under that same production key. Live
`/v1/manifest` serves a real, strictly-newer version 2 (same key, no
rotation) on both production VPSes, `BuildConfig.MANIFEST_URL` wires the
real fetch in both build types, `AutoGatewaySelector`'s pinned
`GatewayConfigSnapshot` now sources its AWG `endpointHost`/`endpointPort`
from the manifest's own transport binding (never the catalog) - and a real
device fetch->accept->LKG->restart->fetch-failure->LKG-survives->reconnect
cycle was physically proven end to end. Signed Offline Bootstrap is now
IMPLEMENTED with no remaining LKG-path caveat (see ROADMAP's own row).
Builds on B16's
consolidated review fix - the pinned `GatewayAttemptCandidate.configSnapshot`
is threaded verbatim through `TransportOrchestrator`/`VpnController.connect()`
and actually EXECUTED for the whole attempt, never reconstructed from
`SelectedGatewayStore`/`ClientTunnelIdentityStore`/`ProductionGatewayCatalog`;
the Auto-vs-`AwgXrayFailoverPolicy` relationship is documented accurately; and
same-day B16 physical validation - real Auto failover from Germany to
Stockholm, real data-plane confirmation, restore, normal reconnect confirmed.
If this file's "Current gateway state" table conflicts with `docs/ROADMAP.md`,
ROADMAP wins - update this file to match rather than trusting the stale copy.
