# Reachability / Smart Connect pipeline (fixed order, do not reorder or bypass)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

```
NetworkProfiler
  -> RestrictionClassifier
  -> ReachabilityEngine
  -> PathCandidateBuilder / PathScorer   (live-wired for BOTH manual and auto gateway mode - B16)
  -> SmartConnectDecisionEngine           (picks a TRANSPORT, never a gateway)
  -> TransportOrchestrator
```

- `SmartConnectDecisionEngine`/`AwgXrayFailoverPolicy`/`RealityTlsFailoverPolicy`
  operate WITHIN one gateway only (transport choice/intra-gateway failover) -
  unchanged by B16. Manual-gateway chain, each hop one-shot and only for an
  unpinned transport: AWG -> Xray (REALITY or XHTTP), then REALITY -> TLS_TCP
  on the same endpoint; never back to AWG, nothing after TLS_TCP.
- **B16 - automatic multi-GATEWAY selection/failover is real, above that
  boundary**: `AutoGatewaySelector` (`smartconnect/AutoGatewaySelector.kt`)
  promotes the SAME `ReachabilityEngine`/`PathCandidateBuilder`/`PathScorer`
  pipeline (reused verbatim, never a parallel scorer) into a ranked
  `GatewayAttemptCandidate` list. Only engaged when
  `MainViewModel.gatewaySelectionMode` is `AUTO`; the persisted legacy
  `gatewayAutoMode` boolean remains compatibility state. An accepted explicit
  managed selection persists `MANUAL_MANAGED`, turns the compatibility boolean
  off, and applies to the next connection only.
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
