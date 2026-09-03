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

## Restricted-Network / Whitelist Bridge Runtime Foundation (B23) - FOUNDATION

Turns the B11 `PathCandidate.Relayed` (client -> INGRESS -> EXIT) model from
observational-only into a real, evidence-scored EXECUTABLE CANDIDATE MODEL -
still **FOUNDATION**, not IMPLEMENTED, and deliberately **not described as
decision-integrated**: no real RU ingress is deployed, client->ingress->exit
data-plane forwarding does not exist, and nothing in the live connect path
calls this model yet (see the explicit "not consumed" note below). Real
restrictive-network/Russia whitelist bypass remains **UNVERIFIED**.

- **`IngressKind` (`reachability/Endpoint.kt`)** - `DIRECT_IP`/`CDN_FRONTED`,
  stored through `EndpointTransportBinding.metadata`'s existing reserved-key
  extensibility (`ingressKind()`/`withIngressKind()`), never a new
  `EndpointDescriptor`/`ManifestCanonicalizer` binary field - this keeps
  every already-signed manifest, including the embedded production bootstrap
  (`EmbeddedBootstrapManifest`), verifying byte-for-byte with zero re-signing
  ceremony (`ManifestVerifier.verify` re-canonicalizes the decoded manifest
  and checks the signature against THOSE bytes - any wire-schema change
  would have broken it). Never encodes a named third-party provider.
- **Independent per-hop transports (PR #37 review fix)** - `PathCandidate
  .Relayed` never assumes the client<->ingress hop and the ingress<->exit
  hop share one `TransportKind`. `PathHop` now carries its own exact,
  immutable `EndpointTransportBinding` (`binding`) - the SPECIFIC binding
  each hop was pinned against, not merely re-derivable from the endpoint
  after the fact. `Relayed.transport` is the client-facing (ingress)
  transport; the new `Relayed.exitTransport` is the SEPARATE ingress<->exit
  upstream transport - a real future topology may legitimately dial the
  ingress over XRAY_REALITY while the ingress's own upstream to the exit
  speaks TLS_TCP. `PathCandidateBuilder.buildRelayed` takes independent
  `ingressTransport`/`exitTransport` parameters and now also requires the
  EXIT endpoint to actually support `exitTransport` (a real tightening - the
  pre-fix version never checked this at all).
- **`PathCandidate.historyPathId`** - the key `PathHistoryStore` local
  connection memory is read/recorded under. `Direct` keeps the pre-B23 key
  (`endpoint.id.value`, byte-for-byte unchanged); `Relayed` gets its own
  composite key encoding BOTH hop endpoint ids AND both hop transports
  (`"ingressId:ingressTransport->exitId:exitTransport"`) - never conflated
  with either hop's own Direct history, never shared between two relays
  through the same ingress to different exits, and never collided across two
  paths that share both endpoints but differ in either hop's transport.
  `PathHistoryStore.get/record` widened from a raw `EndpointId` parameter to
  this `pathId: String` (same on-disk format, only the acceptable
  string-length bound grew to fit a composite id).
  `MainViewModel.reachabilityDiagnostics()`'s Relayed candidates now get real
  local history credit (previously deliberately `null` - "deferred, not
  invented" - see that call site's own prior note in git history).
- **`AutoGatewaySelector.buildRelayedCandidates`** - an executable candidate
  model / scoring foundation for relayed paths: a real, callable function on
  the SAME object `buildCandidates` lives on, reusing
  `PathCandidateBuilder.buildRelayed` / `ReachabilityEngine` / `PathScorer`
  verbatim - never a parallel engine. Scores every (ingress transport, exit
  transport) PAIR the manifest actually supports independently (PR #37
  review fix): `ingressTransport` is filtered by a `UserTransportPreference
  .Manual` pin the same way Direct candidates already are (it is what the
  CLIENT dials); every `exitTransport` the exit endpoint declares is tried
  regardless, since the client never dials the exit directly and a transport
  preference has no meaning for that hop. Discovery is manifest-only (an
  INGRESS endpoint absent a `relayTo` EXIT/GATEWAY target in the SAME
  trusted manifest is never a candidate - same fail-closed discipline as
  `buildCandidates`). Unlike `buildCandidates`, it consults no
  `ProductionGatewayCatalog`/per-device AWG provisioning - an ingress has no
  such catalog entry (no RU ingress exists), so eligibility rests entirely
  on the manifest's own facts plus real reachability/health/history
  evidence. UNKNOWN ingress evidence is never treated as reachable
  (`PathScorer`'s existing reachability tier already ranks it strictly below
  REACHABLE), so a healthy proven Direct candidate is never displaced by an
  unproven relay just because it is relayed; a hard-whitelist network's own
  evidence naturally makes Direct ineligible/low-scored while a proven-
  reachable ingress stays eligible, so no separate "prefer relay under
  restriction" rule was invented - the SAME reachability-first tiering
  produces the right outcome from real evidence alone. **PR #37 review fix,
  round 2**: `RelayAttemptCandidate` also carries `ingressBinding`/
  `exitBinding` - the EXACT, immutable `EndpointTransportBinding` each hop
  was pinned against at candidate-build time, copied straight off
  `PathCandidate.Relayed.ingress.binding`/`.exit.binding` - never
  re-looked-up by endpointId/TransportKind. Without this, a future execution
  layer dialing a `RelayAttemptCandidate` would have had to re-resolve
  host/port facts from the manifest/catalog after the fact, which a manifest
  rotation mid-attempt could have silently redirected - the same B16
  attempt-pinning invariant `GatewayAttemptCandidate.configSnapshot` already
  enforces for Direct.
- **Superseded by B24 below** - this bullet originally said
  `buildRelayedCandidates` was not yet consumed by the live connect path.
  B24's "Real Ingress Runtime / Server-Side Relay Execution Foundation"
  section (immediately below) wires it into `connectAuto()`/
  `attemptCombined()` for real - a `RelayAttemptCandidate` CAN now be the
  winner of a real Auto connect() request, and its resolution converges into
  the SAME `TransportOrchestrator`/`VpnController` dial path Direct uses
  (see `RelayIngressResolver`'s own docs, PR #38 round 3) - though the ONLY
  production resolver never leaves `NotProvisioned`, so a tunnel is never
  actually established there today. Preferred eventual topology remains: Android -> encrypted
  transport to INGRESS -> ingress-controlled encrypted upstream to EXIT ->
  Internet, through the SAME single Android VPN ownership path
  (`VpnController`) - never a nested VpnService stack.
- Existing Direct gateway behavior (`buildCandidates`, `GatewayAttemptCandidate`,
  `connectAuto()`/`attemptAutoCandidate()`) is unchanged - only the
  `historyFor` callback's parameter type widened (`EndpointId` -> `String`),
  every call site still passes the identical value for a Direct candidate.

## Real Ingress Runtime / Server-Side Relay Execution Foundation (B24) - FOUNDATION

Turns B23's relay CANDIDATE model into a real execution contract on both
sides - client execution wiring AND a real server-side ingress runtime -
still **FOUNDATION**, not IMPLEMENTED: no real RU ingress is deployed, so
none of this has been physically exercised end to end. **Russia
hard-whitelist bypass remains UNVERIFIED** until tested on an actually
restricted Russian network.

**Real supported relay transport matrix** - client<->ingress and
ingress<->exit are INDEPENDENT (never collapsed to one shared
`TransportKind` - B23's own PR #37 fix, reused verbatim here):

| Client -> INGRESS | INGRESS -> EXIT | Status |
|---|---|---|
| XRAY_REALITY | XRAY_REALITY or TLS_TCP | server config real (`xray_ingress_config_renderer`), client dial not provisioned |
| TLS_TCP | XRAY_REALITY or TLS_TCP | server config real, client dial not provisioned |
| AMNEZIA_WG (client<->ingress) | any | capability-not-implemented this slice - AWG upstream chaining was not attempted (task's own "if AWG upstream is significantly harder to implement safely, do not fake it") |

**Client execution wiring** (`android/.../relay/RelayExecution.kt`,
`smartconnect/AutoGatewaySelector.kt`, `MainViewModel.kt`):

- `RelayedExecutionPlan` - the real, immutable per-attempt contract, built
  ONLY via `.from(RelayAttemptCandidate)` - copies `ingressEndpointId`/
  `ingressBinding`/`ingressTransport`/`exitEndpointId`/`exitBinding`/
  `exitTransport`/`historyPathId` straight off the already-ranked
  candidate, never re-resolving from the manifest/catalog mid-attempt (task
  requirement 2).
- `RelayReadinessStage` (`INGRESS_REACHABLE`/`INGRESS_HANDSHAKE_OK`/
  `UPSTREAM_EXIT_HANDSHAKE_OK`/`END_TO_END_DATA_PLANE_OK`) and
  `RelayFailureCategory` (`INGRESS_UNREACHABLE`/`INGRESS_HANDSHAKE_FAILED`/
  `UPSTREAM_EXIT_UNREACHABLE`/`UPSTREAM_EXIT_HANDSHAKE_FAILED`/
  `RELAY_AUTH_FAILED`/`END_TO_END_DATA_PLANE_FAILED`/
  `EXECUTION_NOT_IMPLEMENTED`) are the typed vocabulary task requirements
  10/12 asked for. `RelayAttemptOutcome.Success` is constructible ONLY at
  `END_TO_END_DATA_PLANE_OK` - fail-closed by TYPE CONSTRUCTION (a `Failure`
  literally cannot claim that stage - `init{}` enforces it), not by
  convention.
- **`RelayIngressResolver` - a PREPARATION boundary, never a second VPN
  execution/state owner (PR #38 review fix, round 3).** An earlier version
  of this had `RelayIngressDialer.dial()` itself return the TERMINAL
  attempt outcome (including a `Success` case) - meaning a real
  implementation would have had to independently drive a tunnel to
  `END_TO_END_DATA_PLANE_OK` and report back, becoming a SECOND VPN
  execution authority beside `TransportOrchestrator`/`VpnController`/the
  real `VpnService` (violating "one Android VpnService owner, no second
  connection controller"). Fixed before any real implementation was built
  on the wrong seam: `RelayIngressResolver.resolve(plan)` now returns a
  `RelayIngressResolution` - either `Resolved(transport, kind)` (a real,
  already-constructed `VpnTransport` for the client<->ingress hop, reusing
  the EXISTING Xray transport/service stack - task requirement 4/7, never a
  bespoke networking path) or `NotProvisioned(category, detail)` (no real
  credential exists to prepare one). `RelayIngressResolution` carries NO
  state of its own - existing purely as data, never starting anything.
  `MainViewModel.attemptRelayedAttempt` is what feeds a `Resolved` result
  into the SAME `TransportOrchestrator.resolve`/`VpnController.connect`/
  `PendingFailoverAttempt`/`armFailoverWatch` path a Direct candidate
  already goes through - a fresh per-attempt `TransportRegistry` naming
  only the resolved transport/kind, exactly mirroring how Direct already
  builds a fresh registry per candidate. `PendingFailoverAttempt.relayPlan`
  (non-null only for a relayed attempt) lets `armFailoverWatch`'s SAME real
  `controller.state` observation - never this attempt's own belief, never
  a resolver return value - govern both what gets recorded and whether the
  combined sequence advances (task requirement 8). Critically: even when
  `controller.state` genuinely reaches `TransportState.Connected` for the
  resolved ingress transport (a REAL handshake, not faked), this branch
  NEVER constructs `RelayAttemptOutcome.Success` - a client<->ingress
  handshake alone only proves `RelayReadinessStage.INGRESS_HANDSHAKE_OK`,
  never `UPSTREAM_EXIT_HANDSHAKE_OK`/`END_TO_END_DATA_PLANE_OK` (no
  server-side upstream readiness signal channel exists yet - see that
  enum's own docs), so it is recorded as a `Failure` instead, every time,
  by construction (`RelayAttemptOutcome.Failure` cannot even represent
  `END_TO_END_DATA_PLANE_OK` - its own `init{}` forbids it).
  `NotProvisionedRelayIngressResolver` is the ONLY implementation wired
  into production today: it reports `NotProvisioned(EXECUTION_NOT_IMPLEMENTED)`
  for every plan, honestly, because preparing a real ingress transport over
  XRAY_REALITY/TLS_TCP needs a real per-ingress-provisioned Xray client
  profile that cannot exist without a real ingress and a real per-device
  activation against it (out of scope - "no new infrastructure"). **Known,
  named remaining gap** (explicitly not closed by this fix, since closing
  it would mean redesigning shared, Direct-affecting `VpnController`/UI
  code well beyond this task's narrow scope): `VpnController`'s OWN
  pre-existing generic `recordPathHistory` also fires for a resolved
  relay's `controller.connect()` call, writing a real but SEPARATE,
  single-hop record keyed by the bare ingress endpoint id (never the
  composite `historyPathId` relay scoring actually reads - harmless to
  scoring, but see `MainViewModelRelayAttemptTest`'s own note). More
  importantly, `TransportState.Connected` still drives the generic
  `"Protected"` UI text application-wide (`ProductFlowPresentation
  .toHomeStatusText`) with no awareness that an attempt was relayed - so a
  FUTURE real `RelayIngressResolver` reaching genuine ingress-handshake
  `Connected` would show "Protected" in the UI even though this codebase's
  own relay-outcome bookkeeping correctly refuses to call it healthy. Since
  `NotProvisionedRelayIngressResolver` never reaches that branch, this has
  no production impact today - but a future slice wiring a real resolver
  MUST also teach `VpnController`/the UI layer to distinguish a relayed
  attempt before claiming "Protected" for one.
- `AutoGatewaySelector.AutoConnectAttempt` (sealed `DirectAttempt`/
  `RelayedAttempt`) + `buildCombinedAttempts`/`nextCombinedAttempt` - ONE
  combined, real, ranked attempt list built from `buildCandidates` +
  `buildRelayedCandidates` together (task requirement 4), sharing ONE
  `MAX_ATTEMPTS` budget across both types. `MainViewModel.connectAuto()`
  picks its winner from this combined list via `attemptCombined` - the ONE
  bounded-progression authority for the whole request. A **Direct** winner
  is DIALED through the completely unchanged `TransportOrchestrator`/
  `VpnController`/`PendingFailoverAttempt` machinery - the same pinned
  `GatewayAttemptCandidate.configSnapshot`, the same AWG->Xray intra-gateway
  failover, byte-for-byte (task requirement 7/8: no duplicated Direct
  execution logic, no second connection controller). A **Relayed** winner is
  resolved via `attemptRelayedAttempt`/`relayIngressResolver`, and on
  `Resolved` is ALSO dialed through that SAME `TransportOrchestrator`/
  `VpnController` path (see the `RelayIngressResolver` bullet above); its
  outcome is recorded under the FULL `historyPathId` (task requirement 11 -
  never poisons either hop's own Direct history). **PR #38 review fix**: on
  EITHER shape's terminal failure - `attemptAutoCandidate`'s own
  `NotSelectable` branch, `armFailoverWatch`'s async observation of a real
  Direct OR relayed failure, or `attemptRelayedAttempt`'s own
  `NotProvisioned`/`NotSelectable` branches - control returns to
  `attemptCombined` with the SAME `(attempts, attemptedKeys)` state, so the
  VERY NEXT globally-ranked unattempted candidate is chosen regardless of
  shape. An earlier version of this row wrongly had a Direct winner
  delegate to a REORDERED DIRECT-ONLY LIST that then owned the rest of the
  Direct sub-sequence on its own - silently skipping any higher-ranked
  Relayed candidate ranked in between, and defeating the shared
  `MAX_ATTEMPTS` budget the row already (incorrectly) claimed. Fixed before
  merge, never shipped to `main`: `PendingAutoGatewayContext` now carries
  the combined `(attempts, attemptedKeys)` shape instead of a Direct-only
  one, and `attemptAutoCandidate` takes exactly ONE candidate to dial (never
  a list to "own"). One candidate consumes exactly one combined attempt
  slot, added to `attemptedKeys` the moment `attemptCombined` chooses it -
  never re-chosen. `AutoGatewayDiagnostics` itself stays Direct-only (its
  existing public shape is unchanged - every pre-B24 reader is unaffected);
  a Relayed attempt is currently reflected there only via
  `lastFailureReason` once it
  fails.

**Server-side ingress runtime** (`gateway/api/xray_ingress_config_renderer.py`)
- reuses the EXISTING Xray server machinery (task requirement 7 - no new
daemon, no sing-box/Hysteria):

- Client-facing inbound rendering (REALITY/TLS) and client authorization
  are the SAME functions `xray_config_renderer` already uses for a real
  gateway (`_active_clients`/`_render_reality_inbound`/`_render_tls_inbound`,
  imported and called verbatim, never duplicated) - an ingress has NO
  second/parallel identity system (task requirement 8); a revoked/expired
  activation is excluded here exactly as it already is for a real gateway.
- The genuinely NEW piece is the OUTBOUND: instead of `freedom` (what every
  existing gateway config renders - direct to the open Internet), the
  ingress's outbound is a real, authenticated VLESS connection
  (`UpstreamExitConfig` - REALITY or TLS, independently chosen from the
  client-facing inbound's own transport) to the pinned EXIT, carrying its
  own dedicated relay UUID credential (task requirement 9 - "do not assume
  source IP == trusted ingress"; never a shared/global plaintext
  credential, never committed to this repository - always caller-supplied
  at render time). Routing rules bind EVERY client-facing inbound
  EXCLUSIVELY to that one upstream outbound, and no `direct`/`freedom`
  outbound exists in the rendered config AT ALL - an ingress rendered this
  way is structurally incapable of becoming an open relay or the public
  Internet exit by accident (task requirement 6/L), not merely by
  convention. `render_ingress_server_config_redacted` never serializes the
  ingress's own REALITY private key or the upstream relay UUID (task
  requirement 9/M).
- Malformed upstream inputs (bad UUID, blank host, unsupported transport,
  malformed REALITY key/short-id) fail closed with `IngressConfigRenderError`
  rather than rendering a config that would silently misroute.
- **Not done this slice**: no systemd unit/deployment script for an ingress
  role (`gateway/systemd/nova-xray.service` is EXIT-shaped only), no
  ingress-specific provisioning/activation HTTP endpoint, no reload
  wiring. These are genuinely deployment/control-plane concerns that
  require an actual ingress host to design against meaningfully - adding
  them now, untested against a real host, would risk exactly the kind of
  premature/undemonstrated infrastructure this task explicitly warns
  against.

**Ingress role**: `IngressKind.DIRECT_IP` has the real runtime path above
(a plain host:port the client dials directly). `IngressKind.CDN_FRONTED`
remains typed-but-FOUNDATION - no legitimate operator-controlled CDN was
available to validate against this slice, and this codebase's own
principle 3 forbids ever impersonating a named third-party service to fake
one.

## Relay Readiness / Protected Gating + Ingress Provisioning Control Plane (B25) - FOUNDATION

Closes every remaining CLIENT/control-plane blocker B24 named - still
**FOUNDATION**, no real RU ingress deployed, **Russia hard-whitelist bypass
remains UNVERIFIED**.

- **Typed session identity**: `net.pocvpn.client.relay.VpnAttemptContext`
  (`Direct`/`Relayed(plan)`) is pinned once per attempt onto
  `TransportOrchestrator.Resolution.Resolved.attemptContext` (default
  `Direct`) and carried into `VpnController.pendingAttemptContext` - never
  guessed from transport kind/endpoint name.
- **Real Protected gating**: `net.pocvpn.client.vpn.VpnSessionHealth`
  (pure `computeSessionHealth(state, attemptContext, relayStage)`),
  exposed as `VpnController.sessionHealth`/`MainViewModel.sessionHealth`
  and read by `ProductFlowPresentation`'s new `VpnSessionHealth` overloads
  in `AppRoot`'s Home screen instead of the raw `TransportState` ones.
  Direct: `DirectProtected` fires under the exact same condition
  `TransportState.Connected` always did (byte-for-byte unaffected).
  Relayed: `TransportState.Connected` alone (ingress handshake) is
  `RelayHandshake`, NEVER `RelayProtected`, until
  `RelayReadinessStage.END_TO_END_DATA_PLANE_OK` is reported via
  `VpnController.reportRelayStage` - which only ever happens after a real
  `RelayEndToEndProbe` success.
- **Real end-to-end proof contract**: `RelayEndToEndProbe`
  (`HttpRelayEndToEndProbe` - a real authenticated HTTPS GET to
  `IngressClientProfile.endToEndProbeUrl`, over whatever route the OS
  resolves, i.e. genuinely through the just-established tunnel; fail-closed
  `NotConfiguredRelayEndToEndProbe` is the production default).
  `MainViewModel.armFailoverWatch`'s relay branch calls this probe on a
  real ingress-handshake `Connected` observation: `Success` promotes
  `END_TO_END_DATA_PLANE_OK` (the only way `RelayAttemptOutcome.Success` is
  ever constructed) and leaves the session Connected/`RelayProtected`;
  `Failure` records the typed category under the full `historyPathId` and
  advances `attemptCombined()` - no stale Connected/Protected UI can
  survive a failed probe, since `_relayStage` never advances past
  `INGRESS_HANDSHAKE_OK` on that path. No real server-side relay-health
  endpoint exists yet on any EXIT for this probe to call - see the closing
  paragraph below.
- **Path-history ownership fixed**: `VpnController`'s generic
  `recordConnectionOutcome`/`recordPathHistory` (the connect()-throw catch
  block - the only place that could still fire for a relayed attempt) now
  skip entirely when `pendingAttemptContext is VpnAttemptContext.Relayed` -
  the single-hop write B24 documented as a known, harmless gap is closed.
  `MainViewModel.recordRelayOutcome` remains the ONE writer for a relayed
  attempt, always under the full composite `historyPathId`.
- **Typed persisted ingress profile**:
  `net.pocvpn.client.relay.IngressClientProfile` (endpoint/binding/
  transport-scoped, wraps the EXISTING `XrayProfile`/`XrayTlsProfile`
  shapes, plus version/validity-window/probe coordinates; structurally
  excludes the ingress's own REALITY private key, the upstream relay uuid,
  and the signing key - those fields do not exist on this type), persisted
  via `FileIngressProfileStore` (its own AndroidKeyStore alias/file, one
  per ingress endpoint id).
- **Real `RelayIngressResolverImpl`**: loads the endpoint-scoped profile,
  validates `IngressClientProfile.matches(plan)` and non-expiry (typed
  `PROFILE_NOT_PROVISIONED`/`PROFILE_MISMATCH`/`PROFILE_EXPIRED`
  `RelayFailureCategory` additions), writes the matched credential into the
  SAME per-endpoint `XrayProfileRepository`/`XrayTlsProfileRepository`
  `VlessRealityTransport`/`VlessTlsTransport` already read from, and
  returns `RelayIngressResolution.Resolved(transport, kind, profile)` -
  never starts/owns VPN state. `VpnController` gained a separate, additive
  `relayXrayProfileRepositoryResolver`/`relayXrayTlsProfileRepositoryResolver`
  pair (consulted only when `pendingAttemptContext is Relayed`; also fixed
  `supportedKinds` to widen for a relay-only composition root, a real gap
  found during this slice). `NotProvisionedRelayIngressResolver` remains
  the ONLY resolver wired into production (no real ingress deployment
  exists to activate against).
- **Control-plane**: `POST /v1/ingress-profile`
  (`gateway/api/handler.py`, gated by an additive
  `ProvisioningServer.ingress_config`, `None`/zero-behavior-change for
  every ordinary gateway) reuses `activations.py`'s entitlement decision
  and `xray_provisioning.provision_and_activate_identity` VERBATIM via the
  new `gateway/api/ingress_activation.py` (renders through
  `xray_ingress_config_renderer.render_ingress_server_config`, never
  `xray_config_renderer`'s freedom-outbound path). Own env-var-driven
  config (`gateway/api/ingress_config.py`, `NOVA_INGRESS_*`, absent by
  default, all-or-nothing) - a separate deployment instance, never a field
  on the shared `AppConfig`. Response is client-safe only.
- **Ingress->exit relay identity contract**:
  `xray_config_renderer.render_server_config` gained an additive
  `static_clients=()` parameter - entries authorized on an EXIT
  unconditionally, deliberately never cross-referenced against
  `activations_data`/revocation (an infra-level host-to-host trust
  relationship, not a per-user entitlement), redacted like any other
  client uuid. `gateway/tools/provision_relay_upstream_identity.py` mints
  the identity and writes two secret-handling output files (never
  stdout/logs) for the ingress host and the EXIT operator respectively -
  applying the EXIT-side fragment to a live host remains a deliberate,
  human-reviewed, unautomated step.
- **Deployment tooling**: `gateway/systemd/nova-xray-ingress.service` (a
  reviewed template, not installed), `gateway/tools/ingress_reconcile.py`,
  `gateway/tools/ingress_status.py` (read-only, secret-safe).

**Remaining condition to exercise any of this physically, in order**: (1) a
real ingress host (DIRECT_IP first) running the ingress-role
`pocvpn-api`/Xray-core pair this slice built; (2) a real per-device
activation against it via `POST /v1/ingress-profile`, populating a real
`IngressProfileStore` entry on a real device; (3) a real
`RelayIngressResolverImpl` wired into that device's composition root; (4) a
real server-side relay-health endpoint on the EXIT for
`HttpRelayEndToEndProbe` to call - not built this slice, the named
remaining gap; (5) the dedicated ingress->exit relay identity actually
applied to a live EXIT's own activation wiring via `static_clients` (a
deliberate, human-reviewed step, not automated). None of these five exist
yet - no new infrastructure was purchased or deployed by this slice.

## First Real DIRECT_IP Ingress Deployment Readiness (B26) - software/repo side only

Closes B25's remaining named client/server prerequisites for a real
DIRECT_IP ingress deployment. **Still no real ingress is deployed - Russia
hard-whitelist bypass remains UNVERIFIED.** See `docs/ROADMAP.md`'s B26 row
for the full evidence trail and `docs/B26_FIRST_INGRESS_RUNBOOK.md` for the
exact remaining physical-deployment sequence (human-approval-gated).

- **Composition root wired for real**: `MainViewModel.Factory` now
  constructs `FileIngressProfileStore` -> `RelayIngressResolverImpl` ->
  `HttpRelayEndToEndProbe`, plus per-endpoint `XrayProfileRepositoryResolver`/
  `XrayTlsProfileRepositoryResolver` lambdas (the same `{ id -> Factory.create(context, id, ...) }`
  shape the pre-existing Stockholm wiring already used), and passes all of
  it into `MainViewModel`'s constructor. `NotProvisionedRelayIngressResolver`/
  `NotConfiguredRelayEndToEndProbe` remain only as class-level defaults for
  tests/unwired callers - production no longer uses them. No Robolectric/
  instrumentation test proves this wiring mechanically (this repo's Kotlin
  suite has no such dependency) - reviewed by hand instead; a real gap, not
  claimed otherwise. `./gradlew compileDebugKotlin`, the full
  `testDebugUnitTest` suite (all pre-existing tests plus this slice's own),
  and `assembleDebug` all pass with this wiring in place (verified this
  slice against JDK 21/Gradle 8.10).
- **Real EXIT-side end-to-end health endpoint**: `GET /v1/relay-health`
  (`gateway/api/handler.py`), authenticated by a short-lived, self-verifying
  HMAC token (`gateway/api/relay_probe_token.py`) - minted by the INGRESS at
  `/v1/ingress-profile` time, verified by the EXIT using only a shared
  secret file (`POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE`/
  `NOVA_INGRESS_PROBE_HMAC_SECRET_FILE`, provisioned together by
  `gateway/tools/provision_relay_upstream_identity.py`). No shared live
  store between ingress and exit at verification time - the response is
  bound to the token's own signed `historyPathId` claim, computed
  server-side with the SAME `"ingressId:transport->exitId:transport"`
  format `PathCandidate.Relayed.historyPathId` already uses, so
  `HttpRelayEndToEndProbe.probe`'s existing `body.contains(plan.historyPathId)`
  check needed no change. A stolen probe token authenticates ONLY this one
  bound health GET, never VPN traffic (task C's own scoping requirement).
- **Android ingress activation client**: `ProvisioningClient.fetchIngressProfile`
  + `net.pocvpn.client.relay.IngressProfileProvisioner` -
  `MainViewModel.activateIngress(...)` is the real, production-wired
  control-plane path: POST `/v1/ingress-profile` -> cross-check the
  response's own `ingress_endpoint_id`/`server_address`/`server_port`
  against the CALLER's already-pinned facts (never re-derived from the
  response) -> `IngressClientProfile` -> `FileIngressProfileStore`
  (endpoint-scoped, so this can never overwrite a different ingress
  endpoint's profile). `ensureFreshProfile` is the bounded refresh policy:
  reuse a still-valid stored profile as-is, re-activate (at most one
  attempt) only when nothing usable is stored - no retry loop. No product
  UI screen invokes this yet (`ingressActivationState` is exposed but
  unwired to any Composable) - a real, named remaining gap.
- **EXIT relay identity apply/revoke**: `gateway/api/relay_identity_store.py` -
  an operator-maintained, atomically-written JSON file
  (`POCVPN_API_STATIC_RELAY_CLIENTS_FILE`) feeding `xray_config_renderer
  .render_server_config`'s pre-existing `static_clients` parameter (B25),
  applied/revoked via `gateway/tools/apply_relay_upstream_identity.py`.
  Proven by direct unit test to be idempotent and to never touch/be touched
  by ordinary per-user `activations_data` - a genuinely separate trust
  domain, not merely documented as one.
- **Ingress deploy tooling**: `gateway/scripts/install-ingress-role.sh`
  (idempotent bootstrap: users/dirs/perms/wrapper/sudoers/systemd units,
  installs no secret), `gateway/systemd/pocvpn-api-ingress.service`,
  `gateway/privileged/nova-xray-ingress-reload` +
  `gateway/config/xray-ingress.env`. These reuse the EXISTING
  `gateway/scripts/xray-activate.sh` validate/`xray run -test`/stage/atomic-
  replace/reload/rollback pipeline verbatim via one new, additive seam
  (`XRAY_ACTIVATE_ENV_FILE`, defaulting to the pre-B26 fixed path so every
  existing gateway deployment is byte-for-byte unaffected) - never a
  duplicated implementation.
- **Preflight/doctor**: `gateway/tools/ingress_preflight.py` - read-only,
  PASS/FAIL, no secret output.
- **Deployment descriptor**: `docs/ingress_deployment_descriptor.example.json`
  - secret-free, explicitly NOT folded into the signed production manifest
  by this slice (see `docs/B26_INGRESS_DEPLOYMENT_DESCRIPTOR.md`).
- **Review fix (PR #40, round 1) - real product activation entry point**:
  an earlier version of this slice wired `activateIngress` as a callable
  function with no product UI ever invoking it - fixed before merge.
  `AppRoot` reuses the EXISTING `ActivationScreen` composable verbatim
  (the same single "activation credential" text field every other
  endpoint's activation already uses - never a UUID/REALITY-key/probe-
  token paste field; `IngressClientProfile`'s fields are never exposed to
  any UI layer).
- **Review fix (PR #40, round 2) - pause/resume, not "call connect()
  again"**: round 1's own "on success, call `connect()` again" retry design
  was itself a blocker - a fresh `connect()` rebuilds/re-ranks a brand new
  combined candidate list, so the post-activation retry could silently
  resolve to a DIFFERENT ingress/exit/transport/historyPathId than the one
  that actually failed, violating the B23/B24/B25 attempt-pinning
  invariant. Replaced with a real PAUSE/RESUME design:
  `attemptRelayedAttempt`'s `NotProvisioned` branch, on its candidate's
  FIRST encounter with an activation-fixable `RelayFailureCategory`
  (`PROFILE_NOT_PROVISIONED`/`PROFILE_EXPIRED`/`PROFILE_MISMATCH` - see
  `RelayActivationRequest.ACTIVATION_FIXABLE_CATEGORIES`), PAUSES the
  combined Auto sequence entirely - it stores the FULL resume context
  (`MainViewModel.PendingRelayActivation`: the exact already-ranked
  `RelayAttemptCandidate` plus the `attempts`/`attemptedKeys` `attemptCombined`
  was mid-sequence with) and does NOT call `attemptCombined` - so nothing
  else (Direct or Relayed) starts while a human decision is pending. A
  bounded, UI-observable `MainViewModel.relayActivationNeeded` (a display-
  only projection) surfaces the prompt. On a successful
  `activateIngress()`, the BYTE-FOR-BYTE IDENTICAL paused candidate is
  retried via the SAME `attemptRelayedAttempt` function
  (`isActivationRetry = true`) - never a fresh ranking - which is what
  guarantees the retry's plan/binding/transport/historyPathId are
  unchanged; `isActivationRetry = true` also means this retry can never
  pause a second time (bounded to exactly one retry per activation), so
  its own failure just resumes `attemptCombined` with the ORIGINAL
  `attempts`/`attemptedKeys`. Any non-Saved activation outcome
  (unauthorized/revoked/mismatched/unavailable/unsupported-transport) and
  an explicit `dismissRelayActivationPrompt()` both take the SAME resume
  path - the paused candidate is NEVER retried without a real profile, and
  the original combined list/budget resumes exactly once, never re-ranked.
- **Review fix (PR #40, round 3) - atomic single-owner claim**: round 2's
  `activateIngress`/`dismissRelayActivationPrompt` each read
  `pendingRelayActivation` and only cleared it AFTER a suspending call
  (network I/O, or nothing at all for dismiss) - a second `activateIngress`
  call, or a `dismissRelayActivationPrompt` racing an in-flight activation,
  could observe the SAME non-null pending context and independently
  resume/retry it, causing duplicate/concurrent Auto progression. Fixed
  with one atomic claim: `MainViewModel.claimPendingRelayActivation()`
  reads `pendingRelayActivation` and nulls it out (together with its
  display projection, `relayActivationNeeded`) in one synchronous,
  non-suspending call. `activateIngress`/`dismissRelayActivationPrompt`
  both call it SYNCHRONOUSLY, at the very top, strictly before either does
  anything suspending - so two calls arriving back to back are processed
  in order on the same thread (the same single-dispatcher/`Dispatchers
  .Main.immediate` confinement `pendingFailoverAttempt`/`xrayAvailableEndpoints`
  already rely on without an explicit lock elsewhere in this class), and
  whichever call claims a non-null value is the ONLY one that may ever
  resume/retry it - every other caller gets `null` and does nothing
  further (never provisions, never resumes, never retries).
- **Review fix (PR #40) - real composition-root test**: an earlier version
  built the relay/ingress dependency graph inline inside
  `MainViewModel.Factory.create`, which ALSO eagerly constructs unrelated
  `AndroidKeyStore`-backed repositories at construction time - incompatible
  with this project's Robolectric version (a real, pre-existing
  incompatibility, confirmed by testing it directly: `KeyStoreException`/
  `NoSuchAlgorithmException`). Fixed by extracting
  `net.pocvpn.client.relay.RelayCompositionFactory.build(context,
  ingressProfileStore)` - the ONE function `Factory.create` now delegates
  relay composition to, which never touches `AndroidKeyStore`/crypto at
  all (every object it builds either takes an already-constructed store as
  input or defers Keystore-backed work into a lambda that only runs
  later, inside a real `resolve()`/`provision()` call).
  `RelayCompositionFactoryTest` (Robolectric, a real `Context`) proves this
  function selects `RelayIngressResolverImpl`/`HttpRelayEndToEndProbe`/a
  real `IngressProfileProvisioner`, never the `NotProvisionedRelayIngressResolver`/
  `NotConfiguredRelayEndToEndProbe` stand-ins.
- **Not done this slice**: the Frankfurt/Stockholm read-only SSH
  suitability audit could not be completed (no working credential
  available in this session for either host - see this PR's own report,
  no SAFE/NOT_SAFE verdict asserted).

## CDN_FRONTED Ingress Support (B27) - FOUNDATION

Threads B23's `IngressKind` (`DIRECT_IP`/`CDN_FRONTED`) - a real type since
B23, but never consumed anywhere until now - through real candidate
construction, execution, and provisioning, so both ingress strategies can
coexist in one ranked relay fabric. **Still FOUNDATION, no real ingress of
either kind is deployed, and Russia hard-whitelist bypass remains
UNVERIFIED** - CDN_FRONTED is an ingress TRANSPORT STRATEGY, never a
guarantee of whitelist reachability, and this slice claims neither.

- **What CDN_FRONTED actually means here (architecture principle 3's own
  "never impersonate a third party" - re-affirmed, not weakened)**: an
  operator-controlled backend legitimately reachable through a CDN/origin
  architecture the OPERATOR configured - never a spoof of a named
  third-party service's identity, never a hardcoded trust relationship
  with Yandex/VK/Beeline/Selectel/a bank/any other real organization (none
  of those names appear anywhere in this codebase, and none should). From
  the CLIENT's own socket-level point of view, dialing a CDN-fronted
  ingress is MECHANICALLY IDENTICAL to dialing a DIRECT_IP one - a normal
  XRAY_REALITY/TLS_TCP handshake against `EndpointTransportBinding.host`/
  `.port` - which is exactly why execution needed almost no new code (task
  D's "no second VPN service or second transport core" - satisfied
  structurally, not by discipline: there is no kind-specific branch
  anywhere in `RelayIngressResolverImpl`/`VlessRealityTransport`/
  `VlessTlsTransport`).
- **Typed strategy, no inference (task A)**: `IngressKind` and
  `EndpointTransportBinding.ingressKind()`/`.withIngressKind()` (B23,
  `reachability/Endpoint.kt`) are the ONE place a binding's kind is
  read/written - stored in the binding's own `metadata` map (already part
  of the signed manifest wire format, zero re-signing ceremony needed - see
  B23's own docs). A binding with no declared kind (every pre-B27 manifest)
  defaults to `DIRECT_IP` - never inferred from host/provider/ASN.
- **Candidate construction (task C)**: `AutoGatewaySelector.RelayAttemptCandidate`
  gained an explicit `ingressKind` field, copied straight off the winning
  `PathCandidate.Relayed.ingress.binding.ingressKind()` at candidate-BUILD
  time inside `buildRelayedCandidates` - never re-derived later. A
  DIRECT_IP and a CDN_FRONTED ingress candidate (two distinct
  `EndpointDescriptor`s, each with their own `relayTo`) coexist in the SAME
  ranked `PathScorer.rank` output and share the SAME `MAX_ATTEMPTS`
  combined budget - proven directly in `AutoGatewaySelectorTest`. Every
  other pinned fact (`ingressEndpointId`/`ingressBinding`/`ingressTransport`/
  `exitEndpointId`/`exitBinding`/`exitTransport`/`historyPathId`) is
  unaffected - `historyPathId`'s own format is unchanged (still
  `ingressId:transport->exitId:transport`), since `IngressKind` is already
  uniquely determined by (endpoint id, transport) for any one manifest
  snapshot (`EndpointDescriptor.init` already forbids two bindings sharing
  one `TransportKind`).
- **Execution (task D)**: `RelayedExecutionPlan` and `RelayActivationRequest`
  both gained the SAME explicit `ingressKind` field, copied verbatim from
  the candidate at `.from(...)` construction time - `RelayIngressResolverImpl`
  itself needed NO new branch (it already dispatches purely on
  `ingressTransport`, which fully determines which real `VpnTransport`
  gets constructed regardless of kind).
- **Provisioning and security (task E)**: `IngressClientProfile` gained an
  explicit, PERSISTED `ingressKind` field (deliberately NOT derived from
  `ingressBinding`'s own metadata at read time - the validated value from
  the provisioning transaction itself is the one source of truth, so a
  test/caller binding that happens to lack the metadata can never silently
  read back a different kind than what was actually cross-checked).
  `IngressClientProfile.matches(plan)` checks it explicitly alongside
  endpoint/binding/transport (task requirement F.3's own "every pinned fact
  named explicitly"). Server-side: `/v1/ingress-profile`'s response gained
  an optional `ingress_kind` field (`gateway/api/ingress_config.py`'s new
  `NOVA_INGRESS_KIND` env var, `"direct_ip"`/`"cdn_fronted"`, defaulting to
  `"direct_ip"` for every pre-B27 deployment) -
  `IngressProfileProvisioner.provision` cross-checks the server's OWN claim
  against the caller's pinned expectation and fails closed as `Mismatched`
  on any disagreement (task requirement E's own "frontend host/origin/
  backend confusion must fail closed") - exactly the same fail-closed
  discipline B26 already applied to `server_address`/`server_port`/
  `ingress_endpoint_id`, now covering kind too. No secret was added to any
  wire format - `ingress_kind` is a label, structurally incapable of
  carrying key material (it is a 2-value enum name).
- **Health/proof (task F) - unchanged, and that is the point**: B25's real
  end-to-end proof contract (`RelayReadinessStage`/`HttpRelayEndToEndProbe`/
  `VpnSessionHealth`) has no kind-specific branch anywhere - a CDN_FRONTED
  session reaches `RelayProtected` through EXACTLY the same
  `END_TO_END_DATA_PLANE_OK`-only gate a DIRECT_IP one does. Deliberately
  NOT weakened or special-cased for CDN_FRONTED - task F's own "not only
  successful TCP/TLS connection to the CDN edge" is satisfied by construction,
  not by a new check.
- **Reachability/history (task G) - review fix: `IngressKind` IS a pinned
  component of relay history identity**: an earlier version of this section
  claimed history could stay unchanged because `historyPathId` already
  scopes by (ingress endpoint, transport) - insufficient, since the SAME
  endpoint+transport reclassified or redeployed from DIRECT_IP to
  CDN_FRONTED (or vice versa) would otherwise silently reuse the OLD
  strategy's success/failure/cooldown evidence for the NEW one - a
  DIRECT_IP ingress's own proven reachability says nothing real about a
  CDN edge that happens to share its endpoint id, and vice versa. Fixed:
  `PathCandidate.Relayed.historyPathId` (`reachability/PathCandidate.kt`)
  now encodes `ingressKind` explicitly - the real, current format is
  `"<ingressId>:<ingressKind>:<ingressTransport>-><exitId>:<exitTransport>"`
  (was `"<ingressId>:<ingressTransport>-><exitId>:<exitTransport>"` before
  this fix). `AutoGatewaySelector.RelayAttemptCandidate.historyPathId`
  copies this value verbatim (unchanged mechanism - B24's own "a pure
  formula over the already-pinned fields, never a second/independent
  encoding"). **Migration rule**: no pre-B27 relay history exists on any
  real device (no ingress of either kind has ever been deployed - see this
  file's own B26/B27 sections), so this format change orphans nothing;
  `PathHistoryStore.get()` already treats an unmatched key as "no
  evidence" (never "trust it anyway"), the same fail-open-to-neutral
  behavior a first-ever lookup already has - no explicit migration code
  was needed or written. Direct's own `historyPathId` (`gateway.endpoint.id.value`,
  B11/B19, unaffected by this class - `PathCandidate.Direct` has no
  `IngressKind` concept at all) is completely untouched by this change.
  B19's existing bounded, time-decaying failure cooldown
  (`PathHistoryEntry.consecutiveFailures`/`FAILURE_COOLDOWN_WINDOW_MILLIS`)
  still applies uniformly to whichever kind-scoped key it is recorded
  under - no CDN-specific "permanently healthy" shortcut exists or would be
  consistent with this codebase's own architecture. Proven directly:
  `PathCandidateBuilderTest`/`AutoGatewaySelectorTest` (the SAME
  endpoint+transport reclassified between kinds produces two genuinely
  distinct `historyPathId` strings; stale evidence recorded under one
  kind's key never influences `PathScorer.score` for the other kind's
  candidate at the identical endpoint+transport) and
  `MainViewModelRelayActivationTest` (a bounded activation retry keeps the
  IDENTICAL kind-aware `historyPathId`, never re-ranked into a different
  identity).
- **Not done this slice**: no real CDN-fronted ingress host exists to
  validate against (matches B23's own original caveat on `CDN_FRONTED`,
  never claimed resolved here); no product UI distinguishes ingress kind in
  its display text (Home/LocationCard stay geography-only per this
  codebase's own production-vs-debug boundary - provider/kind metadata is
  diagnostics-only); the deployment/preflight/runbook tooling B26 built for
  DIRECT_IP (`install-ingress-role.sh`, `ingress_preflight.py`, the
  first-deployment runbook) was not extended for a CDN-fronted rollout
  sequence - a real CDN account/configuration would be needed to design
  that meaningfully, and none is available.

## Restricted-Network Decision Authority (B28) - FOUNDATION

Architecture principle: `RestrictionClass` (B18/B23) becomes decision-driving
for the first time - real restriction evidence now influences automatic
DIRECT vs RELAY path ranking, without a second decision authority, without
country/provider hardcoding, and without physically validating a real
restrictive network. No deployment, no device dependency. **Russia
hard-whitelist bypass remains UNVERIFIED** - nothing in this slice proves a
real fixed-allowlist network actually gets bypassed; it proves the scoring
fabric would PREFER a reachable relay over a direct path once such evidence
exists.

- **Where the decision is made (single authority, requirement 7)**:
  `PathScorer.score` (`reachability/PathScorer.kt`) gains ONE new tier,
  `RESTRICTION_TIER = 700`, sandwiched strictly between `HISTORY_TIER=1000`
  and `MATURITY_TIER=200` (tier-algebra re-verified in the class doc comment
  for all five tiers). `AutoGatewaySelector` and `MainViewModel` are
  UNCHANGED - the restriction value is read directly off data ALREADY
  present on `candidate.hops[0].reachability.evidence.restrictionClass`
  (every hop of one candidate carries the SAME class, since
  `MainViewModel.restrictionClass()` computes it once per read and threads
  it into every `ReachabilityEngine.assess` call for that read). No second
  selector, no new parameter threading through `AutoGatewaySelector`.
- **The exact rule (requirements 1-3)**: `restrictionRank(candidate,
  restrictionClass)` is nonzero ONLY for `RestrictionClass
  .POSSIBLE_HARD_WHITELIST` - every other class (`UNKNOWN`,
  `NO_RESTRICTION_OBSERVED`, `POSSIBLE_UDP_OR_AWG_FILTERING`, etc.)
  contributes exactly 0, so ordinary healthy-direct behavior under
  NORMAL/UNKNOWN evidence is byte-for-byte unaffected (requirement 1).
  Under `POSSIBLE_HARD_WHITELIST`: `+1` (bonus) for `PathCandidate.Relayed`,
  `-1` (penalty) for `PathCandidate.Direct` - symmetric, so the same
  tier-width proof covers both directions. The bonus depends only on
  candidate TYPE, never on `IngressKind` - `DIRECT_IP` and `CDN_FRONTED`
  relayed candidates get the IDENTICAL +1, so neither ingress kind is ever
  globally preferred; their relative order among themselves is still
  decided entirely by the higher `REACHABILITY_TIER`/`HEALTH_TIER`/
  `HISTORY_TIER` (requirement 3). `POSSIBLE_UDP_OR_AWG_FILTERING` gets NO
  dedicated branch (requirement 2) - it is itself derived from a real
  `awgHandshakeFresh == false` `ConnectionOutcome`, which already penalizes
  `AMNEZIA_WG` via the pre-existing `HEALTH_TIER`
  (`TransportHealthCalculator`); a second protocol-specific branch here
  would be exactly the redundant nested if/else the task asked not to add.
- **Eligibility is untouched (requirement 4)**: `PathScorer.isEligible`/
  `ineligibilityReason` gained ZERO new logic. Restriction only affects
  SCORE among already-eligible candidates - a relay candidate that is
  ineligible (fresh `ReachabilityState.UNREACHABLE`, no valid
  `IngressClientProfile`, transport not implemented) can never be promoted
  by the restriction bonus, structurally, not by a runtime check.
- **Evidence stays distinct (requirement 5)**: endpoint reachability
  (`ReachabilityEngine`/`ReachabilityState`), transport handshake/health
  (`TransportHealth`/`TransportHealthCalculator`), real end-to-end proof
  (B25/B26's `RelayReadinessStage`/`END_TO_END_DATA_PLANE_OK`), and
  restriction classification (`RestrictionClass`) remain four SEPARATE
  fields feeding four SEPARATE `PathScorer` tiers - never collapsed into one
  boolean. `RestrictionClassifier.classify` itself is unchanged in its own
  evidence-only discipline (still conservative, still never infers a
  country/operator claim - see the enum's own doc comment, unchanged since
  B18).
- **Hysteresis/TTL (requirement 8)**: `RestrictionMonitor` now stamps
  `lastProbeEpochMillis`/`lastDiverseReachabilityEpochMillis` (real wall
  clock via an injectable `nowProvider`, defaulting to
  `System::currentTimeMillis`) alongside its existing
  `lastProbeResult`/`lastDiverseReachabilityResult` StateFlows - still
  triggered ONLY by a real transport-state/network-type transition, never a
  timer (unchanged B8J discipline). `RestrictionEvidence` gained two
  matching optional fields, `gatewayProbeEpochMillis`/
  `diverseProbeEpochMillis` (both default `null`). `RestrictionClassifier
  .classify` gained `nowEpochMillis`/`staleAfterMillis` parameters (default
  `Long.MAX_VALUE`/`DEFAULT_STALE_AFTER_MILLIS = 30 * 60 * 1000L`, the SAME
  window `ReachabilityEngine` already uses) and a private `freshOrTrusted`
  helper: once a probe's own timestamp is older than `staleAfterMillis` (or
  future-dated - the same clock-skew guard `ReachabilityEngine.assess`
  already applies), that probe's value is treated as unknown (null) rather
  than trusted indefinitely, decaying `POSSIBLE_HARD_WHITELIST`/
  `POSSIBLE_UDP_OR_AWG_FILTERING` back toward `UNKNOWN`/
  `GATEWAY_HTTPS_UNREACHABLE` once its own evidence has expired. Backward
  compatible by design: an UNDATED value (no timestamp supplied - every
  pre-B28 caller) is legacy-trusted as-is, never treated as immediately
  stale, so no existing call site's classification changed.
  `MainViewModel.restrictionClass()` now passes the real `now` and both
  probe timestamps into `classify()` in production.
- **B26/B27 guarantees preserved (requirement 9)**: `AutoGatewaySelector`,
  `PathCandidate`, `RelayIngressResolverImpl`, `IngressProfileProvisioner`,
  and every activation/pause/resume/atomic-claim mechanism in
  `MainViewModel` are UNTOUCHED by this slice - restriction scoring is
  orthogonal to (runs strictly before) candidate ranking and pinning; once a
  candidate is selected and activated, restriction evidence has no further
  effect on it. Full `testDebugUnitTest`/`assembleDebug` re-run confirms no
  regression.
- **Diagnostics (requirement 10)**: `MainViewModel.combinedAutoRankingDiagnostics()`
  (new, `CombinedAutoRankingDiagnostics{restrictionClass, ranked:
  List<CombinedAttemptDiagnostic{kind, score, reasons}>}`) maps the
  ALREADY-public, already-ranked `combinedAutoAttempts()` output - never a
  second ranking pass. `kind` is one of `"DIRECT"`/`"CHAIN_DIRECT"`/
  `"CHAIN_CDN"` (derived from `RelayedAttempt.candidate.ingressKind`).
  `reasons` is filtered to the stable `PathScorer.Reason` token vocabulary
  only (`RESTRICTION_FAVORS_RELAY`/`RESTRICTION_PENALIZES_DIRECT` are the
  two new tokens) - no endpoint host/IP, UUID, activation credential, probe
  token, or key ever appears (closed field set, proven by
  `MainViewModelAutoGatewayTest`'s dedicated no-leak test). Deliberately a
  NEW surface, not a change to the existing Direct-only
  `AutoGatewayDiagnostics` (B16), which stays untouched.
- **Not done this slice**: no physical validation on any real restrictive
  network (this remains FOUNDATION-only, exactly like B23/B24/B25's own
  caveats); `RestrictionClass` is still never inferred from country/ASN/
  provider identity anywhere in this codebase; no new UI surface renders
  `combinedAutoRankingDiagnostics()` (diagnostics-only, same boundary as
  every prior diagnostics addition); the gateway/Python control plane is
  completely untouched (this slice is Android/Kotlin reachability-decision
  logic only).

### B28 review fix (PR #42) - correct no-viable-relay semantics + real hysteresis

Two blockers found on first review, both fixed within the SAME single
decision authority (no redesign):

- **Blocker 1 - endpoint reachability must never silently override
  restriction classification.** The original slice let `buildCombinedAttempts`
  offer a Direct attempt whenever ITS OWN endpoint happened to be reachable,
  even while `POSSIBLE_HARD_WHITELIST` was suspected and no eligible relay
  existed - collapsing two distinct evidence layers (requirement 5) back
  into one. Fixed: `AutoGatewaySelector.buildCombinedAttempts` gained a
  `restrictionClass` parameter (threaded from `MainViewModel`'s already-
  computed value, no new evidence source) and ONE inline gate, applied right
  where Direct and Relayed are already merged (still the one existing
  authority, never a second selector): `directAllowed = restrictionClass !=
  POSSIBLE_HARD_WHITELIST || relayed.isNotEmpty()`. When no eligible relay
  exists under `POSSIBLE_HARD_WHITELIST`, EVERY Direct candidate is excluded
  - the combined list becomes empty regardless of how reachable any single
  Direct endpoint's own probe says it is - producing genuine, truthful
  exhaustion rather than a silent fallback. When an eligible relay DOES
  exist, Direct is NOT excluded; it re-enters the same ranked list, where
  `RESTRICTION_TIER` already biases the ranking toward relay (requirement 3's
  "rank normally with relay preference"). A companion pure function,
  `AutoGatewaySelector.isRestrictedNetworkExhaustion(attempts,
  restrictionClass)`, is `true` exactly when this specific gate produced the
  empty result - used ONLY for truthful error labeling, never for
  ranking/eligibility. `MainViewModel.connectAuto()` uses it to report the
  new `VpnError.RestrictedNetworkNoViableRelay` (distinct from the generic
  `NoCandidateAvailable`) and sets `AutoGatewayDiagnostics.lastFailureReason
  = "RestrictedNetworkNoViableRelay"` - both purely presentational, no
  decision logic lives outside `buildCombinedAttempts` itself. Proven by
  `AutoGatewaySelectorTest`'s four new required cases (zero-eligible-relay
  exhaustion excludes Direct entirely; one-eligible-relay lets it execute
  and Direct still participates ranked; UNKNOWN-evidence-zero-relay stays
  ordinary Direct; a reachable Direct across MULTIPLE healthy gateways still
  cannot override the decision with zero relay candidates in the manifest at
  all) and one real end-to-end `MainViewModelAutoGatewayTest` case (a real
  manual handshake failure produces real `POSSIBLE_HARD_WHITELIST` evidence;
  switching to Auto afterward never dials a second candidate and reports
  `RestrictedNetworkNoViableRelay`).
- **Blocker 2 - TTL alone is not hysteresis.** `RestrictionClassifier`'s
  30-minute staleness window (requirement 8's first half) only EXPIRES old
  evidence - it does nothing to stop two back-to-back FRESH, genuinely
  differing probe results from flipping the DIRECT/RELAY ranking on every
  single read (e.g. `HARD_WHITELIST -> UNKNOWN -> HARD_WHITELIST` inside a
  few seconds). Fixed with a new, small, pure, O(1)-state object,
  `smartconnect/RestrictionStabilizer.kt` (option (b) from the task's own
  two choices - a minimum-RESIDENCE hold window, not "N consistent
  observations": a hold window needs only the single most-recent pending
  observation and its own timestamp, never an unbounded observation
  history). `State{establishedClass, establishedAtEpochMillis, pendingClass?,
  pendingSinceEpochMillis?}`; `advance(state, rawClass, now,
  minResidenceMillis = DEFAULT_MIN_RESIDENCE_MILLIS = 90_000L)` is the one
  pure transition function: a raw class differing from `establishedClass`
  only gets PROMOTED once it has been observed continuously (never reverting
  back to `establishedClass` or switching to a THIRD differing class in
  between - either resets its own residency timer) for at least
  `minResidenceMillis`; `RestrictionClass.NO_NETWORK`/`CAPTIVE_PORTAL` are
  exempt entirely (requirement's own "should not be hidden behind long
  hysteresis") and take effect immediately in both directions, entering AND
  leaving. The very FIRST observation any session ever makes is trusted
  immediately too (`initial()`) - hysteresis only guards CHANGES away from an
  already-established value, never an artificial startup delay.
  `MainViewModel` holds the one piece of state this needs
  (`restrictionStabilizerState: RestrictionStabilizer.State?`, its own
  session-scoped var) behind a NEW function, `stabilizedRestrictionClass()`
  - deliberately SEPARATE from the existing `restrictionClass()`, which
  stays the raw, immediate value every pre-B28 consumer (routing's
  `NO_NETWORK` check, `reachabilityDiagnostics()`'s own "OBSERVATIONAL ONLY"
  contract, and existing tests asserting a probe result is reflected right
  after it completes) keeps reading unchanged. ONLY
  `buildCombinedAutoAttempts()` - the one function that actually merges and
  ranks Direct against Relayed, feeding `connectAuto()`'s real execution -
  reads the stabilized value; `buildAutoGatewayCandidates()` (Direct-only,
  no relay comparison ever happens there) keeps reading the raw value.
  Proven by `RestrictionStabilizerTest` (single transient flip absorbed;
  sustained change eventually establishes in both directions - entering AND
  recovering out of `POSSIBLE_HARD_WHITELIST` are bounded by the identical
  window, never permanent; `NO_NETWORK`/`CAPTIVE_PORTAL` stay immediate;
  alternating short-lived evidence never accumulates enough continuous
  residency to oscillate the established value; a custom
  `minResidenceMillis` is honored).
- **Full re-run**: `compileDebugKotlin`/`testDebugUnitTest`/`assembleDebug`
  all green after both fixes, zero regressions across the existing suite.

### B28 review fix #2 (PR #42) - one consistent ranking/diagnostics snapshot

Third and final blocker: `combinedAutoRankingDiagnostics()` could report a
DIFFERENT `RestrictionClass` than the one that actually drove the ranking it
described - it called `combinedAutoAttempts()` (which internally reads
`stabilizedRestrictionClass()`) and then SEPARATELY called the raw
`restrictionClass()` for its own `restrictionClass` field. During
`RestrictionStabilizer`'s ~90s hold window these two reads could genuinely
disagree (e.g. raw already flipped to a new class while the established,
decision-driving class was still pending), producing diagnostics that lied
about why Auto made the decision it made.

Fixed with ONE shared internal snapshot, never a second/independent
recomputation: `buildCombinedAutoAttempts()` (private) is renamed
`buildCombinedAutoRankingSnapshot()` and now returns a private
`CombinedAutoRankingSnapshot{restrictionClass, attempts}` - `stabilizedRestrictionClass()`
is called EXACTLY ONCE inside it, and that SAME value both drives every
hop's `ReachabilityEngine.assess` call feeding `PathScorer`'s ranking AND is
returned alongside the ranked `attempts`. Every consumer of one combined
ranking now projects from this ONE call: `connectAuto()` (execution),
`combinedAutoAttempts()` (public attempt list, `= buildCombinedAutoRankingSnapshot().attempts`),
and `combinedAutoRankingDiagnostics()` (`= buildCombinedAutoRankingSnapshot()`'s
two fields directly). The raw, immediate `restrictionClass()` function
itself is unchanged and stays available separately for routing/observational
use (requirement 3 of the review) - only the COMBINED-RANKING surfaces were
ever at risk of disagreeing, and now cannot.

To make this deterministically testable without a real 90-second sleep, a
narrow test seam was added: `MainViewModel`'s new `nowProvider: () -> Long`
constructor parameter (defaults to `System::currentTimeMillis`, so every
production/existing call site is byte-for-byte unaffected - the exact same
additive-seam pattern `RestrictionMonitor`'s own `nowProvider` already
established in this codebase), used by both `restrictionClass()` and
`stabilizedRestrictionClass()`. Proven by three new
`MainViewModelAutoGatewayTest` cases, exercised through the REAL evidence
pipeline (a real handshake failure produces real `POSSIBLE_HARD_WHITELIST`
evidence; a second real probe round with diverse-reachability now true
produces a genuinely differing `GATEWAY_HTTPS_UNREACHABLE` classification -
substituting for a literal `...->UNKNOWN->...` sequence, which is
structurally unreachable once a real probe has run since
`RestrictionMonitor`'s probe StateFlows never revert to null; that exact
literal sequence is already proven in isolation by `RestrictionStabilizerTest`):
diagnostics reports the ESTABLISHED class (not the transient raw one) while
pending; once sustained past the hold window, diagnostics reports the
promoted class and the `RestrictedNetworkNoViableRelay` failure mode no
longer applies; two immediate back-to-back reads of
`combinedAutoAttempts()`/`combinedAutoRankingDiagnostics()` agree
byte-for-byte.

Full `compileDebugKotlin`/`testDebugUnitTest`/`assembleDebug` re-run green.

## Field Diagnostics / Support Bundle (B29) - FOUNDATION

Architecture goal: a connection/support incident produces ONE bounded,
sanitized, structured diagnostic bundle a non-technical tester can export/
share with one tap - captured AUTOMATICALLY during the real connect flow,
never requiring developer mode/ADB/logcat. No deployment, no physical
device required to build/test this slice. **FOUNDATION only** - this has
not been field-tested with a real user/support workflow; it does NOT prove
Russia whitelist bypass, which remains UNVERIFIED.

- **Model (task A/B/C, `diagnostics/support/DiagnosticTypes.kt`)**:
  `DiagnosticSession` (sessionId - a locally-generated opaque UUID grouping
  id, never a device/tunnel identity; started/ended timestamps; app version;
  coarse network facts; `rawRestrictionClass`/`stabilizedRestrictionClass`;
  `routingMode`/`gatewaySelectionMode`; `selectedPathKind`
  (`DIRECT`/`CHAIN_DIRECT`/`CHAIN_CDN`/`PRIVATE`/`NONE` - the SAME three
  relay labels `combinedAutoRankingDiagnostics()` already uses, from B28);
  `selectedTransportKind`; a bounded `events: List<DiagnosticEvent>`
  (`MAX_EVENTS_PER_SESSION = 200`, enforced by the type's own `init{}`);
  `outcome`/`failureReason`) - deliberately carries NO endpoint host/IP,
  only stable enum labels and
  `net.pocvpn.client.reachability.NetworkFingerprinter`'s existing coarse,
  per-install, non-exportable fingerprint id. `DiagnosticEventType` (task
  B's 19 categories, verbatim) is a LABELING vocabulary over this
  codebase's own already-real state (`RestrictionClassifier`/
  `RestrictionStabilizer`, `AutoGatewaySelector`, `VpnSessionHealth`,
  `RelayReadinessStage`, `IngressActivationOutcome`) - never a second,
  independently-driven connection state machine. `DiagnosticFailureReason`
  (task C's 17 categories) is populated by pure mapping functions
  (`diagnostics/support/DiagnosticFailureMapping.kt`:
  `mapVpnErrorToFailureReason`/`mapRelayFailureCategoryToFailureReason`/
  `mapIngressActivationOutcomeToFailureReason`/
  `mapRestrictionClassToFailureReason`) from the EXISTING `VpnError`/
  `RelayFailureCategory`/`IngressActivationOutcome`/`RestrictionClass`
  types - those types are never replaced, only re-labeled for this one
  consumer.
- **Automatic capture (task D, `SupportDiagnosticsRecorder.kt`)**: the ONE
  place a session is assembled. Every `record*`/`finish*` function is
  narrow and typed - EVERY `record*` function has zero raw `String`
  parameters, with no exception (`DiagnosticTypesTest`'s reflection check
  enforces this structurally, not by convention) - so nothing secret-shaped
  can enter `DiagnosticEvent.tags` through this API at all.
  `recordManifestSourceSelected` takes the closed `ManifestSourceKind`
  enum (`LAST_KNOWN_GOOD`/`EMBEDDED_BOOTSTRAP`/`NONE`, mirroring
  `reachability.ManifestSource`'s own two real values plus "no trusted
  manifest") - never a free-text source label (PR #43 review fix; the
  earlier revision passed a raw `String` here and the structural test
  carried a one-method exception for it). Two-tier event
  model: NON-TERMINAL `record*` functions (`recordCandidateAttemptStarted`,
  `recordPathFailed`, `recordControlPlaneFailure`, etc.) append to the
  still-open session - a multi-candidate Auto failover sequence is ONE
  session, ONE timeline, not one session per candidate; TERMINAL
  `finish*` functions (`finishProtected`/`finishFailed`/
  `finishRestrictedNetworkExhaustion`/`finishDisconnected`) close it and
  hand it to the store - idempotent (a second `finish*` call once already
  closed is a safe no-op), so a generic backstop and a precise typed call
  can never double-record or corrupt one session. Wired into
  `MainViewModel` as an additive, nullable constructor param (every
  pre-B29 caller/test unaffected): `connectAuto`/`connectManual`/
  `connectPrivate` each `startSession(...)`; `attemptCombined`'s dispatch
  records `CANDIDATE_ATTEMPT_STARTED` with the real winning attempt's own
  path/transport kind; `attemptRelayedAttempt`/`armFailoverWatch` record
  the real `RELAY_ACTIVATION_REQUIRED`/`RELAY_ACTIVATION_RESULT`/
  `DATA_PLANE_READINESS_RESULT`/`RELAY_END_TO_END_PROOF_RESULT` events at
  their own real call sites (never fabricated); a `sessionHealth`
  collector (the SAME `StateFlow` the UI already reads) is a generic,
  idempotent BACKSTOP that finishes any session a more specific typed call
  did not already finish - guaranteeing no session is ever left open
  forever, without needing every single failure branch in this large
  class individually instrumented. `InMemoryDiagnosticSessionStore`
  (`DiagnosticSessionStore.MAX_RETAINED_SESSIONS = 8`, oldest-first
  eviction) is the bounded ring buffer - no unlimited logging.
- **Decision-snapshot consistency (task G)**: `connectAuto`'s
  `StartContext` is built from the SAME `CombinedAutoRankingSnapshot`
  (B28's own single-read discipline) that decided the ranked attempts -
  `rawRestrictionClass = restrictionClass()`,
  `stabilizedRestrictionClass = snapshot.restrictionClass`, both read
  once, never independently recomputed after the fact.
  `connectManual`/`connectPrivate` report the SAME raw value for both
  fields, honestly - restriction evidence has no decision-driving effect
  on either path (no relay comparison ever happens there), so there is
  only one real decision to report.
- **Sanitization boundary (task E, `DiagnosticSanitizer.kt`)**: TWO
  independent layers. Structural (primary): the recorder's typed API
  cannot accept a raw string in the first place. Pattern-based (defense in
  depth, applied a SECOND time by `buildSupportBundle` over every event
  tag value before serialization): `DiagnosticSanitizer.isSafeValue`
  rejects UUID-shaped strings, long mixed-case Base64 blobs (AWG/Xray/
  REALITY key shape), `Bearer ...` auth headers, PEM blocks,
  `token=`/`secret=`/`credential=`-shaped key-value pairs, URLs with query
  data, and IPv4/IPv6 addresses - `sanitize()` replaces a rejected value
  with a fixed `"[redacted]"` marker (never a partial/truncated echo,
  which could itself leak a prefix). `sessionId` itself is the one
  deliberate exception (task A's own "opaque diagnostic id", meant to be
  visible/copyable, never a secret). Proven by
  `DiagnosticSanitizerTest`/`SupportBundleTest`'s own required security
  test: sentinel secret strings (a UUID credential, a real-shaped AWG key,
  a bearer token, a PEM block, a URL with a secret query param, an
  endpoint IP) constructed deliberately and proven absent from the
  exported JSON.
- **Bundle/export (task H/I/J, `SupportBundle.kt`)**: `buildSupportBundle`
  is the ONE sanitizer/export boundary function; `SupportBundle.toJson()`
  serializes deterministically (every object's keys in a FIXED explicit
  order, tag maps sorted by key - never relying on `org.json.JSONObject`'s
  own iteration order). `MainViewModel.exportSupportBundleJson()`/
  `recentDiagnosticSessions()`/`clearDiagnosticSessions()`/
  `lastConnectionResultSummary()` are the four new accessors. UI:
  `SettingsScreen`'s new "Diagnostics" section shows only a simple,
  human-readable last-result sentence on the normal screen (task I -
  "the tester must not need technical knowledge") with "Export
  diagnostics"/"Clear diagnostics" one tap away; `AppRoot.kt` wires export
  to a real Android `ACTION_SEND` share-sheet intent carrying the
  sanitized JSON - task J's own "explicit user action... do not silently
  transmit diagnostics to a server" - nothing here is uploaded
  automatically or to any backend; the user's own share-sheet choice
  decides where it goes, exactly like the runbook's own manual-only design
  point.
- **Testability seam**: `MainViewModel`'s existing `nowProvider` (B28) is
  reused for `SupportDiagnosticsRecorder`'s own timestamps where
  applicable - no new wall-clock seam was needed beyond what B28 already
  added.
- **Tests**: `DiagnosticSanitizerTest`, `DiagnosticSessionStoreTest`
  (bounded retention/eviction), `SupportDiagnosticsRecorderTest` (DIRECT/
  CHAIN_DIRECT/CHAIN_CDN success bundles, `RestrictedNetworkNoViableRelay`,
  transport handshake failure, data-plane readiness failure, relay E2E
  proof failure, activation/control-plane failure representation, raw-vs-
  stabilized consistency, last-attempt-wins path/transport recording,
  per-session event bound, abandon-on-supersede, disconnect-before-start
  no-op), `SupportBundleTest` (deterministic serialization, the required
  security test, bounded size), `DiagnosticTypesTest` (closed field-set
  proofs, reflection-checked no-raw-string API surface), and
  `MainViewModelSupportDiagnosticsTest` (a REAL successful manual connect
  produces a real `PROTECTED`/`DIRECT` session end to end; the exported
  bundle never leaks a real gateway config's own host/public
  key/tunnel IP; clear + rebuild-over-empty-store). All new + full
  existing suite green (1148 total tests);
  `compileDebugKotlin`/`assembleDebug` green.
- **Not done this slice**: no field-testing with a real user/support
  workflow (this stays FOUNDATION-only until that happens); no backend
  telemetry/upload endpoint (task's own explicit exclusion - export is
  local share-sheet only); not every single MainViewModel failure branch
  is individually instrumented with a precise typed reason (the generic
  `sessionHealth`-driven backstop covers the remainder, mapped only as far
  as the existing `VpnError` on `DiagnosticsStore` allows); no persistent
  (disk-backed) session store yet - `InMemoryDiagnosticSessionStore` does
  not survive app process death, only app-instance lifetime; this does NOT
  prove Russia hard-whitelist bypass, which remains UNVERIFIED.

## Resilient Activation & Control-Plane Access (B30) - FOUNDATION

**PR #44 review fix (2026-09-03)** - two blockers fixed:

1. **`MainViewModel.activateDevice()`'s real network call now genuinely
   routes through `ActivationResilienceCoordinator`** (it did not before -
   the coordinator previously existed only as tested-but-unused
   foundation code). `activateDevice` builds `origins` via a new
   `controlPlaneOriginsForActivation` constructor seam (defaults to
   `ControlPlaneOriginSetBuilder::forGateway`, the real production
   builder), calls `activationResilienceCoordinator.activate(...)` with
   `hasValidLocalActivation = { false }` (this is an explicit,
   user-triggered action - it must always actually attempt the network,
   never silently skip because some prior local state happens to exist),
   and unwraps the resulting `Outcome` back into the SAME `ProvisioningResult`
   every pre-existing downstream line already branches on
   (`Outcome.Success.result`/`Outcome.Rejected.result`/
   `Outcome.AllOriginsExhausted.lastResult`) - the ~250-line success/
   persistence block (gateway-identity `matchGatewayId` cross-check,
   `gatewayConfigOverride.apply`/`profileStore.write`/
   `clientTunnelIdentityStore.write`, Xray/TLS provisioning chain,
   `reconcileSelectedGatewayIfNeeded`) is untouched, byte-for-byte the same
   code, now fed a `result` that may have come from a later origin instead
   of only ever the first. `retryActivation()` already called
   `activateDevice` verbatim, so Retry automatically reuses the same
   resilient path - no bypass. `Outcome.AllOriginsExhausted` gained a
   `lastResult: ProvisioningResult` field specifically so this unwrapping
   is possible without losing per-status UI fidelity (`ServiceUnavailable`/
   `MalformedResponse`/`NetworkError` still map to their pre-existing
   `ProvisioningUiState.Error` variants when only one real origin exists,
   today's actual production case). Manual `recordActivationStarted`/
   `recordActivationSucceeded`/`recordActivationFailed` calls in
   `activateDevice` were removed (the coordinator now records these
   itself) except one narrow addition: a client-side gateway-identity
   mismatch (a wire-level Success that `matchGatewayId` then rejects) is
   recorded as an additional `TRUST_VALIDATION_REJECTED` failure, since the
   coordinator's own narrow view already recorded `ACTIVATION_SUCCEEDED`
   for the wire response alone.
2. **Trusted-origin audit, performed rather than assumed**: decoded the
   embedded signed bootstrap manifest's canonical bytes directly (see
   `EmbeddedBootstrapManifest.kt`) - each of Germany's and Stockholm's
   `EndpointDescriptor`s carries exactly ONE host across all three
   transport bindings (AWG/51820, a second VPN-transport port/2053,
   TLS/2083 - different PORTS/PROTOCOLS on the SAME IP, not alternate
   hosts, and none of them an HTTP activation-API port anyway). Audited
   `gateway/api/activations.py`: activation state is a durable JSON store
   **local to each gateway's own VPS filesystem** - Germany and Stockholm
   run fully independent `pocvpn-api` processes with independent
   credential-digest-keyed stores; a credential valid on one has no
   meaning to the other (confirmed independently by
   `ProductionGatewayCatalog.matchGatewayId`'s own full-fact,
   never-guessed-at matching). **Conclusion: no genuine second trusted
   control-plane origin exists today, for either gateway** - the two
   production gateways are NOT interchangeable activation backends, and
   there is no alternate edge/host for either one's own control plane in
   any compiled or signed trusted data. Per the review's own accepted
   alternative ("report the architecture blocker instead of fabricating
   failover"), `ControlPlaneOriginSetBuilder.forGateway()` was left
   unchanged (still exactly one real origin per gateway) - inventing a
   second host would violate the "never accept/invent an untrusted origin"
   invariant this same slice exists to enforce. Provisioning a genuine
   second edge (e.g. a load balancer/CDN edge sharing the SAME backend
   store) is real infrastructure work requiring explicit owner approval per
   this repo's own rules, out of scope for a client-only PR.
   `controlPlaneOriginsForActivation` (see point 1) makes the FALLBACK
   MECHANISM itself verifiable today anyway: a new
   `MainViewModelActivationGatewayIdentityTest` integration test injects a
   synthetic two-origin list through this real seam and proves
   `activateDevice()` genuinely retries and persists a later origin's
   success - the mechanism is proven correct through the real production
   code path even though real production data cannot yet exercise it with
   two DIFFERENT physical hosts.
3. **Xray/TLS profile fetch now also genuinely routed through the executor**
   (review's own "verify all profile retrieval endpoints... are actually
   wired through it, not only instrumented"): `XrayProfileProvisioner`/
   `XrayTlsProfileProvisioner` gained additive nullable `gatewayId`/
   `diagnosticsRecorder` params (both null preserves the exact old
   single-call behavior for every pre-B30 test/call site); when
   `gatewayId` is set (now true for all four Factory-constructed
   instances - Germany and Stockholm, REALITY and TLS), `provision()`
   routes its fetch through the new `fetchThroughTrustedOrigins` helper
   (`controlplane/TrustedOriginProfileFetch.kt`) - the SAME
   `TrustedOriginRequestExecutor`/`ControlPlaneOriginSetBuilder`
   activation uses, generalized for any gateway-scoped fetch.
   `IngressProfileProvisioner` (relay/ingress profile fetch) deliberately
   stays diagnostics-instrumented only, NOT routed through this same
   mechanism: an ingress endpoint is `EndpointId`-scoped, not
   `ProductionGatewayId`-scoped (need not be one of the two production
   gateways at all), so forcing it into the gateway-identified origin
   model would misrepresent what is actually trusted for it - its own
   single, already-pinned `ingressBinding.host` is the ONLY origin that
   could ever be correct for that specific ingress.
- **New tests**: `TrustedOriginProfileFetchTest` (executor reuse for
  profile fetch, `classifyXrayProfileResultFailure`/
  `classifyXrayTlsProfileResultFailure` exhaustive mapping),
  `MainViewModelActivationGatewayIdentityTest` additions (primary-fails/
  secondary-succeeds applied+persisted through the REAL activateDevice
  flow; malformed primary response leaves no partial state and the
  secondary's success is what persists; all-origins-exhausted produces
  the required friendly message with no host/exception leakage;
  authorization rejection stops fallback with the secondary never
  attempted), `MainViewModelSupportDiagnosticsTest` addition (activateDevice's
  real diagnostics carry no origin host/IP/URL/credential). All new + full
  existing suite green (1190 total, the same one pre-existing unrelated
  `EffectiveConfigDiffTest` failure); `compileDebugKotlin`/
  `testDebugUnitTest`/`assembleDebug` all re-verified green after these
  fixes.

Architecture goal: activation/profile-retrieval network calls (POST
`/v1/activate`/`/v1/xray-profile`/`/v1/ingress-profile` via
`ProvisioningClient`) become bounded, typed, and origin-list-driven rather
than a single hardcoded call with undifferentiated failure and
default-follow-redirect behavior - without creating a second trust system
alongside B11/B12/B20's signed-manifest/bootstrap/LKG architecture.
**FOUNDATION only** - not yet physically validated on a restrictive
network; does NOT prove Russia hard-whitelist bypass, which remains
UNVERIFIED.

- **Trusted origin model (task 1/2, `controlplane/ControlPlaneOrigin.kt`)**:
  `ControlPlaneOrigin(gatewayId: ProductionGatewayId, host: String)`,
  built ONLY by `ControlPlaneOriginSetBuilder.forGateway(gatewayId)` from
  `ProductionGatewayCatalog` - the same compiled-at-build-time, trusted
  gateway facts every other gateway-identity check in this codebase already
  uses (never a second, independently-maintained origin list; never a
  parameter through which a caller-supplied/arbitrary URL could enter -
  task 2's "never accept arbitrary user-supplied activation URLs" holds
  structurally, not by convention). Today's compiled catalog carries
  exactly one physical origin per gateway (Germany/Stockholm - see that
  catalog's own docs), so this returns a single-element list per gateway;
  the list SHAPE (not a bare host string) is what makes the executor below
  genuinely N-origin-capable the moment ops adds a second trusted origin
  (e.g. a CDN-fronted control-plane edge, mirroring B27's CDN-fronted
  ingress binding) - no call site changes when that happens, only this one
  builder. TLS downgrade/redirect-based origin substitution is structurally
  impossible here: nothing in this file ever performs I/O or inspects a
  response.
- **Generic executor (task 4, `controlplane/TrustedOriginRequestExecutor.kt`)**:
  pure and synchronous - no networking, no coroutines. Tries each origin in
  `origins` (an ordered `List<ControlPlaneOrigin>`) AT MOST ONCE, in order
  (bounded by construction - `origins.size` attempts, never a retry loop,
  never unbounded); the caller supplies `callPerOrigin` (already reduced to
  a typed `OriginCallResult.Success`/`Failure(ControlPlaneFailureReason)`),
  so the bounded/typed-failure/no-infinite-retry discipline is unit-testable
  with fake origins and fake results, never a live HTTPS connection. Stops
  early on `AUTHORIZATION_REJECTED` (default `stopOnReasons`) - a rejected
  credential is evidence about the credential, not about which origin was
  reachable, so it is never retried against a different origin (also
  satisfies task 10's "never forward credentials to another host
  automatically": each origin gets a fresh `callPerOrigin` invocation from
  whatever closure the caller built, no shared connection/header state
  crosses origins). ONE executor, reused by
  `controlplane/ActivationResilienceCoordinator.kt` (activation) and
  `relay/IngressProfileProvisioner.kt` (ingress-profile diagnostics/
  classification) - task 4's own "do not create transport-specific copies
  of control-plane retry logic".
- **Failure taxonomy (task 9, `controlplane/ControlPlaneFailureReason.kt`)**:
  `DNS_RESOLUTION_FAILED`/`CONNECT_TIMEOUT`/`TLS_TRUST_FAILED`/
  `HTTP_UNAVAILABLE`/`AUTHORIZATION_REJECTED`/`MALFORMED_RESPONSE`/
  `TRUST_VALIDATION_REJECTED`/`UNTRUSTED_REDIRECT_REJECTED`/
  `ALL_ORIGINS_EXHAUSTED` - a closed, support-bundle-safe vocabulary,
  distinct from (never replacing) the richer `ProvisioningResult`/
  `IngressProfileResult` types callers still branch on, the same
  "re-label, never replace" discipline B29's `DiagnosticFailureReason`
  mappers already use. `classifyControlPlaneIoException`/
  `classifyNetworkErrorMessage` (`internal`, unit-tested) map a raw
  exception type or `ProvisioningClient`'s own deterministic
  `"${exceptionClass}: ..."` message prefix into this taxonomy - never the
  rest of an exception message, which is never inspected or logged.
- **Redirect lock-down (task 10, `provisioning/ProvisioningClient.kt`)**:
  `executeGeneric` (the ONE shared low-level call every endpoint -
  peers/activate/xray-profile/xray-tls-profile/ingress-profile - already
  goes through) now sets `connection.instanceFollowRedirects = false`
  before connecting. Audit finding: `HttpsURLConnection` follows redirects
  TRANSPARENTLY by default, before any status-code branch in this file ever
  ran - every endpoint here carries a bearer credential, so an auto-followed
  redirect would have silently resent `Authorization` to whatever host a
  response named. A 3xx now surfaces as a real status code, already
  rejected by every `mapResponse` function's own `else -> NetworkError(...)`
  catch-all - never followed, never treated as success. One-line fix,
  applies to all five endpoints at once, zero API changes.
- **Activation resilience (task 3/5/11/12, `controlplane/ActivationResilienceCoordinator.kt`)**:
  wraps the SAME per-gateway `ProvisioningClient.activate(...)` call this
  codebase already has with the executor's bounded/typed discipline.
  `hasValidLocalActivation` (a caller-supplied pure check, task 3) skips the
  network entirely when already valid. Idempotent by construction (task
  11): never generates/rotates identity itself - `publicKey` is always the
  caller's already-get-or-created device key, so a Retry always presents
  the SAME public key + credential, exactly what the server's own
  activation endpoint (idempotent by credential digest -
  `gateway/api/activations.py`) needs to treat a retry as the SAME logical
  activation, never a new device identity. Never applies/persists anything
  itself (task 12 - "no half-written activation credentials"): returns the
  raw `ProvisioningResult.Success` on success, leaving
  `gatewayConfigOverride`/`profileStore`/`clientTunnelIdentityStore` writes
  to the caller, unchanged from `MainViewModel.activateDevice`'s own
  existing "only after full validation, never partial" ordering.
  **PR #44 review fix**: `MainViewModel.activateDevice`'s primary network
  call now genuinely routes through this coordinator (see this section's
  own "PR #44 review fix" note at the top for the full detail) - the
  scope-limited "foundation only, not wired in" state described in the
  original B30 slice no longer holds.
- **First-run failure UX / Retry (task 6/7, `provisioning/ActivationFailureMessage.kt`,
  `MainViewModel.activationFailureMessage`/`retryActivation`)**:
  `activationFailureMessage: StateFlow<String?>` is a pure DERIVED
  projection of the existing `provisioningState` (never a second state
  machine, never mutates it) - `friendlyActivationFailureMessage` collapses
  every failure variant to ONE fixed, non-technical sentence (task 6's own
  required copy for the generic case: "VPN setup could not be completed on
  this network. Try another network or send diagnostics.") - a FIXED string
  literal per branch, never interpolating `ProvisioningUiState.Error`'s own
  raw exception/hostname/malformed-reason text, which is what makes "never
  leaks a raw exception" true by construction. `retryActivation(...)`
  reuses `activateDevice(...)` verbatim - no manual endpoint entry, same
  idempotent identity.
- **Profile-fetch resilience (task 4/5/8, `relay/IngressProfileProvisioner.kt`)**:
  gained an additive nullable `diagnosticsRecorder: SupportDiagnosticsRecorder?`
  (wired from the SAME recorder instance `MainViewModel.Factory.create`
  already builds for B29, via `RelayCompositionFactory.build`'s new
  optional param - never a second, independently-constructed recorder).
  `provision()` now records `PROFILE_FETCH_STARTED`/`_FAILED`/`_SUCCEEDED`,
  classifying every existing outcome branch (Unauthorized/Revoked/Expired/
  DeviceNotBound/ServiceUnavailable/MalformedResponse/NetworkError, plus
  the three pre-existing pinned-fact mismatch checks - ingress id/host+port/
  ingress-kind - now tagged `TRUST_VALIDATION_REJECTED`) through
  `ControlPlaneFailureReason`, never inventing new persistence/network
  behavior. `ensureFreshProfile`'s pre-existing `stillGood` branch (a
  still-valid, unexpired, pinned-fact-matching stored profile, reused with
  ZERO network calls) now also records `OFFLINE_STATE_REUSED` - task 5's
  real, already-existing offline-resilience point, not new logic.
- **Diagnostics integration (task 8, `diagnostics/support/DiagnosticTypes.kt`/
  `SupportDiagnosticsRecorder.kt`/`DiagnosticFailureMapping.kt`)**: ten new
  `DiagnosticEventType` values (`ACTIVATION_STARTED`/`CONTROL_ORIGIN_ATTEMPT`/
  `CONTROL_ORIGIN_FAILED`/`CONTROL_ORIGIN_SUCCEEDED`/`ACTIVATION_SUCCEEDED`/
  `ACTIVATION_FAILED`/`PROFILE_FETCH_STARTED`/`PROFILE_FETCH_FAILED`/
  `PROFILE_FETCH_SUCCEEDED`/`OFFLINE_STATE_REUSED`) and eight new
  `DiagnosticFailureReason` values (the `CONTROL_PLANE_*` finer-grained
  set, mapped 1:1 from `ControlPlaneFailureReason` via
  `mapControlPlaneFailureReasonToFailureReason`). Every new `record*`
  function takes only closed enums/ints - `ProductionGatewayId`, an origin
  ORDINAL INDEX (never the origin's own host), `ControlPlaneFailureReason` -
  continuing B29's structural "zero raw String parameters on any `record*`
  function" invariant (DiagnosticTypesTest's reflection check covers these
  automatically, no exception added). `PROFILE_FETCH_*`/`OFFLINE_STATE_REUSED`
  intentionally carry no gateway/endpoint tag at all - they are shared by
  both `ProductionGatewayId`-scoped (activation-time Xray/TLS) and
  `EndpointId`-scoped (ingress) callers, and no single closed identity model
  fits both without misrepresenting one of them.
- **Tests**: `TrustedOriginRequestExecutorTest` (primary-fails/secondary-
  succeeds, timeout fallthrough, TLS-failure fallthrough, untrusted-redirect
  rejection, bounded attempt count, authorization-rejection stops early,
  per-origin independence, empty-origin-list rejected), `ControlPlaneOriginTest`
  (origins only ever come from `ProductionGatewayCatalog`, never leak a
  different gateway's host, exception/message classification),
  `ActivationResilienceCoordinatorTest` (primary-fails/secondary-succeeds,
  all-origins-exhausted, authorization-rejection is terminal, already-valid
  short-circuits with zero network calls, Retry reuses the same public
  key/credential - never a new logical identity, diagnostics carry typed
  origin-attempt results but no host/IP/URL/credential/UUID),
  `ActivationFailureMessageTest` (every failure variant collapses to the
  required non-technical sentence, `classifyProvisioningResultFailure`'s
  own exhaustive mapping), `IngressProfileProvisionerTest` additions
  (offline reuse records `OFFLINE_STATE_REUSED` with zero network calls, a
  malformed response is never persisted, a pinned-fact mismatch is recorded
  as `CONTROL_PLANE_TRUST_REJECTED` and never persisted, a successful fetch
  carries no host/UUID/token in any diagnostic tag, an expired profile whose
  refresh itself then fails closes rather than silently extending the stale
  profile), and one new `MainViewModelTest` case (an already-activated user,
  `GatewayConfiguration.Configured`, connects successfully while a REAL,
  wired manifest-refresh control-plane call is failing - proving requirement
  5 against genuine failure, not merely an omitted collaborator). All new +
  full existing suite green (1180 total tests, one pre-existing failure
  unrelated to this slice - `EffectiveConfigDiffTest` needs a gitignored,
  developer-local `gateway-dev.properties` this sandbox does not have);
  `compileDebugKotlin`/`assembleDebug` green. No gateway/Python code
  touched this slice (server-side idempotent activation, confirmed via
  `gateway/api/activations.py`'s existing credential-digest locking, was
  sufficient - no server change needed).
- **Not done this slice**: production `ProductionGatewayCatalog`/signed
  manifest data currently carries only one physical origin per gateway
  (audited, see this section's "PR #44 review fix" note - Germany and
  Stockholm are confirmed NOT interchangeable activation backends, and no
  alternate edge/host exists for either one's own control plane), so even
  though `activateDevice` now genuinely routes through
  `ActivationResilienceCoordinator`, real production traffic cannot yet
  exercise cross-HOST fallback - the executor's own N-origin capability is
  proven correct through the real `activateDevice()` code path via an
  injected test seam (`controlPlaneOriginsForActivation`), not live
  redundant infrastructure; provisioning a genuine second edge is real
  infrastructure work requiring explicit owner approval, out of scope
  here. `IngressProfileProvisioner` (relay/ingress profile fetch) is not
  routed through the same gateway-scoped executor (see this section's own
  reasoning for why that would misrepresent its `EndpointId`-scoped
  trust). No live-HTTPS integration test proves the redirect lock-down
  against a real 3xx response (no mock HTTPS server in this test setup -
  covered by code-level review plus a unit-level executor test asserting a
  redirect-classified failure is never treated as success); this does NOT
  prove Russia hard-whitelist bypass, which remains UNVERIFIED.

## Private Gateway Mode (B22) - a third, explicit gateway-selection authority

Architecture principle 9: a user may connect through the managed gateway
network *or* their own compatible VPS running the same pinned AmneziaWG
gateway (`gateway/provision.sh`). `GatewaySelectionMode`
(`AUTO`/`MANUAL_MANAGED`/`PRIVATE`, `vpn/config/GatewaySelectionMode.kt`) is
the one explicit authority `MainViewModel.connect()` dispatches on -
`AUTO`/`MANUAL_MANAGED` call the exact pre-B22 `connectAuto()`/
`connectManual()` functions unchanged; `PRIVATE` is the one new branch
(`connectPrivate()`), AWG-only, single candidate, no `smartConnectDecision`/
`AwgXrayFailoverPolicy` - resolving ONLY from `PrivateGatewayStore`, never
`ProductionGatewayCatalog` or the signed manifest (`PrivateGatewayConfig` has
no conversion function to either type - structurally incapable of entering
them). The legacy `GatewayAutoModeStore` boolean is kept in lockstep both
directions (`selectGatewaySelectionMode`/`setGatewayAutoMode`) so every
pre-B22 caller/test observing that boolean is unaffected; `PRIVATE` can only
ever come from the new store (the boolean has no way to express it).

**Client private key never touches ordinary config (architecture constraint
1)**: `PrivateGatewayConfig` has no private-key field at all - the keypair
lives in a SEPARATE `ClientKeyRepository` instance
(`PrivateGatewayKeyRepositoryFactory`, reusing `AwgClientKeyRepository`/
`FileIdentityStore`/`AndroidKeystoreAesGcmEncryptor` byte-for-byte unchanged,
only the backing file name/AndroidKeyStore alias differ from the
managed-network `ClientKeyRepositoryFactory`) - a genuinely distinct identity
from the managed network's, never the same keypair linking both. Threaded
into the real connect path via one new, additive field on the EXISTING B16
pinning mechanism: `TransportOrchestrator.Resolution.Resolved.privateKeyRepository`
(null for every AUTO/MANUAL_MANAGED resolution) -> `VpnController`'s
`pendingConnectPrivateKeyRepository` (mirrors `pendingConnectConfig`'s own
lifecycle exactly) -> consulted instead of the constructor-owned
`clientKeyRepository` only in `buildTransportConfig`'s `AMNEZIA_WG` branch.
`PrivateGatewayConfig.toGatewayConfigSnapshot()` converges into the SAME
`GatewayConfigSnapshot`/`GatewayConfigSnapshotValidator`/`AwgConfigMapper`/
`AmneziaWgTransport` pipeline every other AWG gateway already uses - no
second execution stack.

Fails closed on anything malformed (`PrivateGatewayConfigValidator`, reusing
the existing `Ipv4Format`/`WgKeyFormat` validators verbatim) - the four AWG
magic-header obfuscation fields are required (a real handshake blocker
against `gateway/provision.sh` if mismatched, per `PocAwgProfile`'s own
documented distinction). `PrivateGatewayDialog` also exposes `AwgProfile`'s
full junk-packet profile (`Jc`/`Jmin`/`Jmax`/`S1`-`S4`) - added after physical
validation against a real Stockholm peer proved matching only the four
headers was NOT sufficient against this exact `gateway/provision.sh` build
(see `docs/ROADMAP.md`'s B22 physical-validation history). These seven remain
optional (blank -> `null`, never a hardcoded/invented value - a different
user's own VPS may need different values or none), validated when present
(non-negative, min/max not inverted) via a dedicated
`INVALID_JUNK_PACKET_PARAMETERS` reason, and persisted by
`FilePrivateGatewayStore` exactly like every other field (a legacy file from
before they existed reads back with them correctly `null`, never invented).
`FilePrivateGatewayStore` re-validates on every read, never trusting a
corrupted/hand-edited file as "configured".

First-slice scope: exactly one private gateway, add/edit/remove UI
(`PrivateGatewayDialog`, a real production dialog reached from
`GatewayPickerDialog`'s new "Private Gateway" row - not debug-only), no
Smart Connect/Auto ranking/`ReachabilityEngine`/`PathScorer` integration, no
Xray/REALITY/TLS/QUIC. **IMPLEMENTED** - physically validated end to end
against a real, independently-provisioned isolated peer on the Stockholm
gateway (real handshake, real bidirectional data plane, distinct exit IP,
DNS/IPv6 invariants held, managed identity/state completely unaffected - see
`docs/ROADMAP.md`'s B22 row for the full evidence).

## Production vs debug boundary

- `XrayDiagnosticsActivity` (and any future manual/debug provisioning helper) lives in
  the `debug` Gradle source set only - must stay absent from the release manifest.
- Normal product UI (picker/LocationCard/Home) shows geography only - no provider/ASN
  names. Provider metadata is diagnostics/debug-only.

## Infrastructure safety

Never allocate/purchase paid cloud resources (including Elastic IPs) or make
destructive production changes without explicit owner approval - this applies to any
change, not just gateway-related ones.

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

---
Last updated: 2026-09-02 (B25 - added the "Relay Readiness / Protected Gating
+ Ingress Provisioning Control Plane" section above: real typed session
identity/Protected gating/end-to-end proof contract on the client, the
path-history ownership fix, a real persisted ingress profile model +
resolver, and a real role-aware `/v1/ingress-profile` control-plane
endpoint + ingress->exit relay identity contract + deployment tooling on
the server. Still FOUNDATION - no real ingress deployed, Russia
hard-whitelist bypass remains UNVERIFIED. See ROADMAP's own B25 row for
the full evidence trail and the exact remaining physical-deployment steps.)

---
Last updated: 2026-09-02 (B26 - added the "First Real DIRECT_IP Ingress
Deployment Readiness" section above: real production composition wiring,
a real EXIT-side end-to-end health endpoint + probe token lifecycle, a
real Android ingress activation client, EXIT relay identity apply/revoke
tooling, ingress deploy/preflight tooling, and a deployment descriptor.
Repository/software side is DEPLOYMENT READY per ROADMAP's own B26 row;
still no real ingress deployed, Russia hard-whitelist bypass remains
UNVERIFIED. PR #40 review fix (same day): closed the two blockers this
section originally left open - activateIngress is now reached through a
real, bounded, product-visible activation prompt (never a UI-less
function or a manual UUID/key paste), and the relay/ingress composition
graph was extracted into RelayCompositionFactory with a real,
Robolectric-backed composition-root test proving production selects the
real implementations. Remaining gap: Frankfurt/Stockholm SSH audit
incomplete (no working credential this session).)

---
Last updated: 2026-09-02 (B27 - added the "CDN_FRONTED Ingress Support"
section above: threaded B23's typed IngressKind through real candidate
construction (AutoGatewaySelector.RelayAttemptCandidate), execution
(RelayedExecutionPlan/RelayActivationRequest), and provisioning
(IngressClientProfile/IngressProfileProvisioner/the /v1/ingress-profile
wire contract) - DIRECT_IP and CDN_FRONTED ingress candidates now coexist
in one ranked relay fabric, and a provisioning response whose ingress_kind
disagrees with the pinned candidate fails closed. No kind-specific
execution/health branch was added anywhere - a CDN-fronted session reaches
RelayProtected through the exact same evidence-driven, end-to-end-proof-
gated path a DIRECT_IP one does. PR #41 review fix (same day): history
IS kind-scoped after all - PathCandidate.Relayed.historyPathId now encodes
ingressKind explicitly (format: ingressId:ingressKind:transport->exitId:
exitTransport), so the same endpoint+transport reclassified between
DIRECT_IP and CDN_FRONTED can never silently reuse the other kind's
success/failure/cooldown evidence - see this file's own "Reachability/
history" bullet above for the exact format and why no migration code was
needed (no pre-B27 relay history exists on any real device). Still
FOUNDATION - no real ingress of either kind is deployed, Russia
hard-whitelist bypass remains UNVERIFIED, and this slice does not claim
CDN whitelist bypass works.)
