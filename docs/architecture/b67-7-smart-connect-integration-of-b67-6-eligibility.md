# B67.7 - Smart Connect integration of B67.6 eligibility (2026-09-27)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Technical integration only - wires the B67.6 eligible-gateway set into the
EXISTING `AutoGatewaySelector`/`TransportOrchestrator` candidate pipeline.
No new connection pipeline, no new gateway catalog, no ranking logic added
or moved, and no commercial/billing/subscription concept of any kind.

- **Traced the REAL runtime path first, not just this file's own prose.**
  `MainViewModel.connectAuto()` actually builds its candidate list from
  `buildCombinedAutoRankingSnapshot()` (Direct + Relayed combined ranking,
  B24/B32) - **not** the separate `buildAutoGatewayCandidates()`/
  `autoGatewayCandidates()`, which is documented as, and remains, purely
  OBSERVATIONAL (diagnostics/tests only, never itself starting or
  affecting a connect() attempt). Wiring the B67.6 constraint into only
  the observational function would have been dead plumbing with zero
  effect on a real connection - both functions now read trusted-manifest
  endpoints through one new shared private helper,
  `currentEligibilityFilteredManifestEndpoints()`, so the constraint
  applies identically to whichever pipeline is actually driving a
  connection.
- **The filter**: `net.pocvpn.client.activation.EntitlementGatewayEligibility
  .filterEligibleEndpoints(endpoints, eligibleGatewayIds, ...)` - a pure
  function, no I/O, operating on the SAME `EndpointDescriptor` list
  `AutoGatewaySelector.buildCandidates`/`buildCombinedAttempts` already
  consume. `null` constraint -> input unchanged, byte for byte (the
  pre-B67.7 candidate list). A non-null `Set<ProductionGatewayId>` keeps
  only endpoints that map to it via the EXISTING
  `ProductionGatewayCatalog.byEndpointId` (never a second catalog) -
  **an endpoint that maps to NO product gateway at all (an ingress/exit-
  only manifest entry) is left completely untouched.** B67.6 eligibility
  is defined only over gateways; extending it to ingress/relay roles would
  require design decisions no evidence in this repository supports, so the
  relayed/ingress candidate space (`mergedIngressAwareEndpoints`'s
  fallback additions, and any real ingress manifest entry) stays
  structurally outside this constraint's reach.
- **The one new piece of state this slice introduces, audited for
  staleness rather than guessed** (see this milestone's own task
  requirements on manifest freshness): `MainViewModel
  .currentEntitlementEligibleGatewayIds: Set<ProductionGatewayId>?` -
  session-scoped, IN-MEMORY ONLY, never persisted. `null` (no constraint,
  the default) until set; a process restart always restores it to `null`,
  mirroring `ActivationPackageRedeemer`'s own "pending state is never
  persisted, restart requires re-import" discipline exactly - a stale
  restriction can never survive a restart. Manifest trust itself is
  re-read fresh on every candidate build regardless of this field's own
  lifetime (`currentEligibilityFilteredManifestEndpoints` calls
  `manifestRepository.trusted()` directly, never a cached snapshot), so a
  manifest rollback/expiry is reflected immediately and independently -
  the field can only ever narrow WITHIN whatever is currently trusted,
  never override it.
- **Set only on genuine success - a real defect this slice's own audit
  found and fixed before shipping.** The constraint is written ONLY from
  inside `MainViewModel.recordEntitlementEligibilityOnSuccess`, called
  ONLY after `activateDeviceAwaiting` reports a genuinely `SUCCEEDED`
  outcome for an `EntitlementScope.Hinted` redemption - deliberately NOT
  at eligibility-resolution time (`resolveEntitlementGatewayEligibility`
  is a pure query with no side effect). Resolving eligible does not itself
  prove entitlement: a locally-valid envelope can still be rejected
  server-side (revoked/expired/device-limit - the SAME
  `AUTHORIZATION_REJECTED` taxonomy `ActivationResilienceCoordinator`
  already enforces, unchanged). Writing the constraint at resolution time
  would have let a server-REJECTED hinted attempt silently narrow Smart
  Connect away from a gateway this device was already genuinely, 
  separately provisioned for from an earlier real activation - proven as a
  regression by `MainViewModelSmartConnectEligibilityTest`'s own
  "server-rejected (revoked) hinted activation never narrows Smart
  Connect" case before the fix, green after it. An `EntitlementScope
  .Unscoped` redemption (every legacy credential, B67.4's own
  field-enrolled credential) never touches this field at any outcome.
- **Plurality is preserved, never collapsed.** When a hinted, trusted,
  catalog-known resolution names MULTIPLE gateways, `filterEligibleEndpoints`
  keeps every one of them - `AutoGatewaySelector`/`TransportOrchestrator`
  remain the sole ranking/selection/execution authority, completely
  unmodified by this slice; it never ranks, never picks a winner, never
  touches transport selection or profile provisioning (Xray/Xray-TLS/XHTTP/
  Ingress provisioners are all untouched).
- **What did NOT change**: `AutoGatewaySelector.kt`, `TransportOrchestrator`,
  every existing profile provisioner, `ActivationResilienceCoordinator`,
  `activateDevice()`'s own fail-closed gateway-response validation (B13/
  B14), and B67.4's field-enrollment target-gateway selection are all
  byte-for-byte unmodified. No `gatewayId`/host/IP/port/SNI/transport fact
  was added to `ActivationEnvelope`. No second Smart Connect, no second
  gateway catalog, no second profile-provisioning pipeline, no commercial
  entitlement/billing/subscription concept of any kind.
- Tests: `EntitlementGatewayEligibilityTest` (pure `filterEligibleEndpoints`
  cases) and `MainViewModelSmartConnectEligibilityTest` (real end-to-end
  against `autoGatewayCandidates()`/`combinedAutoAttempts()` - the exact
  surfaces `connectAuto()` itself uses) - see ROADMAP's B67.7 row for the
  full list and exact counts.
