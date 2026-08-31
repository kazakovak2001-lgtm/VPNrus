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
- **B16 - automatic multi-GATEWAY selection/failover is now real, above that
  boundary**: `AutoGatewaySelector` (`smartconnect/AutoGatewaySelector.kt`)
  promotes the SAME `ReachabilityEngine`/`PathCandidateBuilder`/`PathScorer`
  pipeline (reused verbatim, never a parallel scorer) into a ranked
  `GatewayAttemptCandidate` list across every PROVISIONED production gateway.
  `EndpointDescriptor`s for this ranking come from `ProductionGatewayEndpoints`
  (built from `ProductionGatewayCatalog`), deliberately NOT the Signed Offline
  Bootstrap manifest (which still only names "frankfurt" - extending it needs
  the offline key ceremony, out of scope). Only engaged when
  `MainViewModel.gatewayAutoMode` is true (persisted, default `false`/Manual -
  every pre-B16 install/test is unaffected). Manual gateway selection
  (`SelectedGatewayStore`/`selectGateway()`) is byte-for-byte unchanged and
  always wins when active - selecting a gateway manually also turns Auto off.
- **Candidate identity/execution**: `ActiveAttemptGatewaySource` is an
  in-memory, per-attempt override `SelectedProductionGatewaySource`'s
  `selectedGatewayId` supplier consults AHEAD of the persisted
  `SelectedGatewayStore` (whose own `read()` is passed as a LAZY fallback, so
  it is genuinely never invoked while an Auto override is set). MainViewModel
  sets this override to a candidate's `gatewayId` explicitly BEFORE calling
  `controller.connect()` and never changes it until the next attempt/candidate -
  satisfying "never infer gateway identity after the attempt starts, never
  reread SelectedGatewayStore during the attempt." For Manual mode the
  override is never set, so this resolves exactly as before B16.
- **Bounded cross-gateway failover**: on a genuine terminal failure
  (`AutoGatewayFailoverPolicy.isEligibleForNextCandidate` - the same
  enumerated HandshakeTimeout/BackendStartFailure categories
  `AwgXrayFailoverPolicy` already uses for intra-gateway AWG->Xray), the
  SAME `armFailoverWatch` collector advances to the next ranked candidate
  (`AutoGatewaySelector.nextCandidate`), bounded by `MAX_ATTEMPTS=4` and never
  retrying an already-attempted (gateway, transport) pair; exhausting the
  ranked set fails closed (`VpnError.NoCandidateAvailable`). Existing
  intra-gateway AWG->Xray failover (`AwgXrayFailoverPolicy`/
  `maybeFailoverToXray`) is completely unchanged and still applies for Manual
  mode (and within whichever gateway an Auto sequence is currently attempting).

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
by B16). Automatic multi-gateway selection/failover is now **IMPLEMENTED as
pure decision logic** (real candidate construction/ranking/bounded failover,
unit-proven - see AutoGatewaySelectorTest/MainViewModelAutoGatewayTest) but
has **NOT been physically validated on a real device** in this slice - see
ROADMAP's own B16 row for the exact scope of what is/isn't proven.

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
Last updated: 2026-08-31 (after B16 - automatic multi-gateway selection/
failover promoted the existing reachability/PathScorer pipeline into a real
gateway-level decision boundary, pure-logic/unit-verified; NOT yet physically
validated on a real device. See ROADMAP's Gateway Pool / automatic gateway
failover rows).
If this file's "Current gateway state" table conflicts with `docs/ROADMAP.md`,
ROADMAP wins - update this file to match rather than trusting the stale copy.
