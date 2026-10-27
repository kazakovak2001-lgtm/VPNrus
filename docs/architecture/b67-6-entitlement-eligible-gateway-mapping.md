# B67.6 - entitlement -> eligible-gateway mapping (2026-09-27)

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Resolves the one architecture question the B67.6 task left open: how an
`ActivationEnvelope`'s entitlement maps to which gateway(s) a device may
activate against, without turning the envelope into network authority.

- **Entitlement today has no dedicated scope object.** `ActivationEnvelope`
  proves provenance/authorization of a bearer `ActivationCredential` - the
  SAME legacy credential `gateway/api/activations.py` authorizes purely via
  its own store record (see the B67/B63 recovery boundary section above).
  The ONE signed field that can express "this credential's issuer intends
  it for these endpoints" is `bootstrapEndpointHints` - already documented
  since B56-1 as non-authoritative (may only reorder/accelerate use of
  endpoints the client ALREADY trusts, never introduce one) and, until this
  slice, wired to zero runtime consumers.
- **The mapping**: `net.pocvpn.client.activation.EntitlementGatewayEligibility`
  (pure Kotlin, no I/O) takes an `EntitlementScope` - `Unscoped` (no hints:
  every pre-B67.6 envelope, every raw/legacy credential, B67.4's own
  field-enrolled credential) or `Hinted(endpointIds)` (a non-empty signed
  hint list) - and resolves it against the CURRENTLY trusted manifest
  (`EndpointManifestRepository.trusted()`, read fresh on every call, never
  cached) intersected with `ProductionGatewayCatalog.byEndpointId` (the
  existing catalog, reused as the local/product-policy layer: which
  endpoint ids are a real, product-supported gateway in this build at all).
  `Unscoped` is never filtered - it is exactly the pre-B67.6 explicit-
  target behavior. A `Hinted` scope is Eligible only for hints that are
  BOTH trusted AND catalog-known; anything else - no trusted manifest at
  all, hints absent from the trusted manifest, hints trusted but unknown to
  the catalog (e.g. an ingress-only manifest entry) - is `Denied`, fail-
  closed, with a typed reason.
- **Why this preserves the trust model**: the manifest stays the ONLY
  source of "this endpoint's facts are current" (never bypassed,
  `EndpointManifestRepository.offer()`/rollback untouched); the catalog
  stays the ONLY source of "this is a real product gateway" (no second
  catalog); the envelope contributes only an already-signed, already-
  non-authoritative hint list (no schema change, no new gatewayId/host/
  port/SNI field); no new trust root, no new verifier. A hint can only ever
  NARROW what an unscoped flow would already have tried - it can never
  cause an untrusted or unsupported endpoint to be reached.
- **Wiring**: `ActivationPackageRedeemer.activatePending` derives the scope
  from the just-verified envelope's own `bootstrapEndpointHints`
  (`EntitlementScope.fromEnvelopeHints`) and calls a caller-supplied
  `resolveEligibility` BEFORE `activate()` - a `Denied` result clears
  `pending` and returns `ActivationPackageUiState.Rejected(GATEWAY_NOT_ELIGIBLE)`
  without ever reaching the network; `Eligible` passes the resolved gateway
  set into `activate()`. Production: `MainViewModel.importActivationPackage`/
  `retryPendingActivationPackage` supply `resolveEntitlementGatewayEligibility`
  (reads `manifestRepository?.trusted()` fresh) and `chooseEligibleGateway`
  (prefers the caller's own explicit/UI-selected target when it is itself
  eligible, else the first eligible id in signed-hint order - a ranking is
  explicitly NOT attempted here, see below) before calling the SAME
  unmodified `activateDeviceAwaiting()`/`activateDevice()` - B13/B14's
  gateway-response-match fail-closed validation is completely unchanged.
  `ActivationPackageRedeemer` itself stays pure-JVM/dependency-light: it
  only computes `EntitlementScope` from data it already owns and defers the
  manifest/catalog decision to the caller via an injected function,
  keeping its own unit tests free of any manifest/catalog fixture.
- **Deliberately NOT touched**: B67.4's field-enrollment target-gateway
  selection (`MainViewModel.ensureZeroTouchEnrollment`) and the raw-
  credential manual-entry path both produce `EntitlementScope.Unscoped` -
  neither reaches this new gate at all, exactly this slice's own scope
  boundary. This slice only produces the eligible set as a well-typed
  input, never a second Smart Connect or a second gateway-ranking
  authority - see the B67.7 section immediately below for how that set is
  actually consumed.
