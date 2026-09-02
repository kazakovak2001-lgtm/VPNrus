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

**Remaining condition to exercise any of this physically**: a real ingress
host (DIRECT_IP first) running `xray_ingress_config_renderer`'s output,
plus a real per-device activation against that ingress issuing a real Xray
client profile, plus a real `RelayIngressResolver` implementation preparing it
- none of which exist yet (task's own "no new infrastructure without
approval").

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
