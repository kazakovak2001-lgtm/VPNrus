# B67.6 Post-Enrollment Profile Acquisition

<!-- Moved verbatim from docs/ROADMAP.md (2026-10-27): the full table row. -->

## Column 1

B67.6 Post-Enrollment Profile Acquisition

## Column 2

**IMPLEMENTED (entitlement-aware gateway eligibility for the ActivationEnvelope/package path); B67.4's own field-enrollment target-gateway selection and the raw-credential manual-entry path are deliberately untouched**

## Column 3

Resolved the entitlement -> eligible-gateway mapping this slice's audit found unresolved: `ActivationEnvelope.bootstrapEndpointHints` (already-signed, already-documented non-authoritative endpoint hints - see B56-1's own docs, previously inert/zero-consumer) is now the ONE entitlement-scope signal, mapped through `net.pocvpn.client.activation.EntitlementGatewayEligibility` (pure decision logic) - a hint is eligible only if it is BOTH currently trusted (`EndpointManifestRepository.trusted()`, never a cached/rolled-back state) AND a product-supported gateway (`ProductionGatewayCatalog.byEndpointId`, the existing catalog, reused - never a second gateway catalog). An envelope with no hints (`EntitlementScope.Unscoped` - every pre-B67.6 envelope, every raw/legacy credential, B67.4's own field-enrolled credential) is completely unaffected: the caller's own explicit target gateway is used exactly as before. A hinted-but-currently-ineligible envelope (hint absent from the trusted manifest, or trusted but unknown to the catalog, or no manifest trusted at all) fails closed BEFORE any network call - `ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE` - never silently falls back to whatever gateway happens to be UI-selected, which is the exact latent gap this audit found (`MainViewModel.importActivationPackage`'s `targetGatewayId` previously defaulted to `selectedGateway.value` regardless of what the envelope was actually scoped to). `ActivationPackageRedeemer.activatePending` checks eligibility once per activation attempt, still calls the SAME unmodified `activateDevice()`/`ActivationResilienceCoordinator` path (transport-specific profile retrieval - `ProvisioningClient.executeXrayProfile`/`executeXrayTlsProfile`/`executeXrayXhttpProfile`/`executeIngressProfile` - is unchanged, all IMPLEMENTED and live), and still fails closed on a gateway/response mismatch exactly as B13/B14 already required. When a hint resolves to MULTIPLE eligible gateways, this slice deterministically prefers the caller's own explicit target if it is itself eligible, else the first eligible id in signed-hint order - never a ranking; that eligible SET is the exact input B67.7's Smart Connect integration is meant to consume, not attempted here. See `PROJECT_ARCHITECTURE.md`'s B67.6 section for the full mapping/trust-model writeup.
