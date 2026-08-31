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
- **B17 - runtime authority for Auto DISCOVERY moved to the signed manifest,
  superseding B16's own shortcut**: `AutoGatewaySelector.buildCandidates`
  now takes `manifestEndpoints: List<EndpointDescriptor>` - the caller
  (`MainViewModel.buildAutoGatewayCandidates`) supplies
  `manifestRepository?.trusted()?.endpoints` (empty when nothing verifies -
  `TrustedManifestState.NoneTrusted` or `manifestRepository` unwired -
  which always yields zero candidates, never a fallback). WHICH endpoints
  even exist as candidates is therefore gated by the trusted manifest, never
  `ProductionGatewayCatalog` enumerated directly. `ProductionGatewayCatalog`
  (via `gatewayFactsFor: (EndpointId) -> ProductionGatewayDescriptor?`) is
  consulted ONLY as a per-endpoint COMPATIBILITY lookup for an endpoint id
  the manifest already named - it supplies the AWG connection facts (server
  public key, gateway tunnel IP, obfuscation profile) needed to dial it,
  which deliberately stay OUT of the public manifest. Local per-device
  provisioning (`provisioned`/`clientTunnelIp`, plus `xrayAvailableFor`/
  `xrayTlsAvailableFor` gating which of the manifest's declared transport
  bindings this device can actually use) still combines with the manifest
  facts exactly as before - a manifest naming an endpoint never implies this
  device is provisioned for it. The embedded bootstrap
  (`EmbeddedBootstrapManifest`) and the production trust root are now the
  SAME real Ed25519 key (see `docs/B12_MANIFEST_KEY_CEREMONY.md`'s
  "Production ceremony (B17)" section for the fingerprint and procedure);
  the bootstrap names BOTH real gateways (frankfurt, stockholm). Live
  `GET /v1/manifest` is deployed and externally verified (byte-identical,
  signature-valid) on BOTH production gateways. **B17 continuation
  (2026-09-01)**: `BuildConfig.MANIFEST_URL` now defaults to the real
  Frankfurt endpoint in both `debug`/`release` builds (`android/app/build.gradle.kts`'s
  `PRODUCTION_MANIFEST_URL`, overridable via a developer's own gitignored
  `gateway-dev.properties`) - the existing `HttpsRemoteManifestFetcher`/
  `ManifestDistributionClient`/`MainViewModel.Factory` wiring is unchanged,
  no second fetch mechanism. Physically verified on a real device: a real
  HTTPS fetch against the live endpoint, correctly Ed25519-verified and
  correctly rejected as "not newer" (bootstrap and the live manifest share
  the same version by ceremony design), both endpoints/6 ranked Auto
  candidates present, a real Auto connect reaching Protected/Germany, and -
  under a reversible, client-side-only airplane-mode fault (no production
  VPS touched) - the same verified embedded bootstrap and full candidate
  list surviving a force-restart, with normal Auto connect resuming once
  network was restored. Signed Offline Bootstrap is now **IMPLEMENTED** -
  see ROADMAP's own row for the one honest caveat (an already-populated LKG
  surviving restart+fetch-failure remains proven only by unit tests, not
  physically exercised, since the live manifest and bootstrap deliberately
  share one version).
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

## Config resolution atomicity

`SelectedProductionGatewaySource.snapshot()` resolves the selected gateway id exactly
once per `GatewayConfigurationRepository.get()` call - a concurrent selection change
mid-resolution can never combine one gateway's host with a different gateway's key/
identity/profile. `GatewayConfigSource.snapshot()` is the one method
`DefaultGatewayConfigurationRepository` actually calls; the six individual getters
exist for direct testability but must not be relied on for atomicity by new callers.

---
Last updated: 2026-09-01 (B17 - Auto gateway/path DISCOVERY runtime authority
moved from `ProductionGatewayCatalog` to the verified `TrustedManifestState`;
the production Ed25519 key ceremony was performed (real keypair, private key
never printed/committed, stored offline outside the repo) and the embedded
bootstrap now names both real gateways under that same production key. Live
`/v1/manifest` is deployed to and verified on both production VPSes, and
`BuildConfig.MANIFEST_URL` now wires the real fetch in both build types -
Signed Offline Bootstrap is now IMPLEMENTED (one honest caveat; see
ROADMAP's own row). Builds on B16's
consolidated review fix - the pinned `GatewayAttemptCandidate.configSnapshot`
is threaded verbatim through `TransportOrchestrator`/`VpnController.connect()`
and actually EXECUTED for the whole attempt, never reconstructed from
`SelectedGatewayStore`/`ClientTunnelIdentityStore`/`ProductionGatewayCatalog`;
the Auto-vs-`AwgXrayFailoverPolicy` relationship is documented accurately; and
same-day B16 physical validation - real Auto failover from Germany to
Stockholm, real data-plane confirmation, restore, normal reconnect confirmed.
If this file's "Current gateway state" table conflicts with `docs/ROADMAP.md`,
ROADMAP wins - update this file to match rather than trusting the stale copy.
