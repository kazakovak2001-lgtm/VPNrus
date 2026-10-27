# CDN_FRONTED Ingress Support (B27) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

The CDN provider capability profile is a typed, versioned description in the
existing signed `EndpointTransportBinding.metadata` map (`cdnProviderProfile`).
Its codec validates fields and the CDN binding/public-host match; the separate
`CdnClientCapabilityPolicy` then gates `CDN_FRONTED` relay candidates against
local client version, pinned Xray-core version, required client capability
labels, XHTTP mode/method/padding support, TLS version/fingerprint/ALPN support,
request bounds, streaming support, and the declared supported exit id. This is
a fail-closed client/core compatibility gate only: it does not verify
signatures, establish reachability, deploy a provider, or prove the data plane.
No manifest binary-schema change or provider-specific routing branch is
introduced. Credentials remain outside metadata. See
`docs/CDN_PROVIDER_PROFILE.md`.

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
