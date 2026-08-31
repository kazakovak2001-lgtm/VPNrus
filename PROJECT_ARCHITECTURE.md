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
  -> PathCandidateBuilder / PathScorer   (PathScorer: OBSERVATIONAL ONLY)
  -> SmartConnectDecisionEngine           (picks a TRANSPORT, never a gateway)
  -> TransportOrchestrator
```

- `PathScorer` never drives a live decision unless a ROADMAP slice explicitly promotes it.
- `SmartConnectDecisionEngine`/`AwgXrayFailoverPolicy` operate WITHIN the manually
  selected gateway only. No automatic multi-gateway selection/failover exists.

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
| Self-service control-plane (`/v1/activate`) | deployed, live | code path exists (B14), NOT deployed - fails closed |
| AWG client identity provisioning | real, self-service | no path reaches a live server yet - disabled in picker |
| Public IP addressing | stable | AWS auto-assigned, NOT durable/reserved |

Gateway Pool remains **FOUNDATION**. Automatic multi-gateway failover is **NOT
implemented**.

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
Last updated: 2026-08-31 (after B14 - Stockholm self-service provisioning code path).
If this file's "Current gateway state" table conflicts with `docs/ROADMAP.md`,
ROADMAP wins - update this file to match rather than trusting the stale copy.
