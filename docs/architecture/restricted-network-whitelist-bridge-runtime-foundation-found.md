# Restricted-Network / Whitelist Bridge Runtime Foundation (B23) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

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
- **B32 - the real production Stockholm-ingress DATA (`ProductionIngressEndpoints`,
  B31) is now genuinely fed into this SAME `connectAuto()`/`buildCombinedAttempts`
  ranking flow, closing the "not yet consumed" gap every note above still
  described.** `MainViewModel.mergedIngressAwareEndpoints` (`internal`, same
  testability pattern as `buildTransportRegistry`) is the ONE seam: it unions
  the trusted manifest's own endpoints with `ProductionIngressEndpoints.all`,
  keyed by endpoint id, and is called exactly once, inside
  `buildCombinedAutoRankingSnapshot` (the function `connectAuto()` itself
  already called pre-B32) - never a second/parallel discovery path.
  Precedence: a manifest-named id always wins over the hardcoded fallback
  sharing that id (the fallback only ever supplements an id the manifest does
  not name yet) - a future signed manifest naming the ingress itself
  supersedes this fallback with zero code change. Filtering by id also makes
  a duplicate endpoint id structurally impossible in the merged list.
  `buildAutoGatewayCandidates` (the Direct-only pipeline `AutoGatewayDiagnostics`
  reads) is deliberately NOT touched - it stays exactly as it was pre-B32.
  **Registry-eligibility fix, required for the merged candidate to ever
  survive `PathScorer.isEligible` at all**: `buildTransportRegistry(endpointId)`
  previously gated XRAY_REALITY/TLS_TCP availability on `isXrayAvailableFor`/
  `isXrayTlsAvailableFor` UNCONDITIONALLY - a per-GATEWAY-endpoint "has this
  device's Direct profile been provisioned" flag that has no real meaning for
  an INGRESS endpoint (no `ProductionGatewayCatalog` entry, hence no Direct
  profile concept at all). Left unfixed, `ProductionIngressEndpoints.STOCKHOLM`
  would have been merged into the endpoint list but PERMANENTLY ineligible
  (`Reason.TRANSPORT_NOT_IMPLEMENTED`) on every real device, since no
  per-device Xray profile is ever registered under the ingress's own distinct
  endpoint id. **Round 2 (PR #53 review) narrowed this**: an earlier version
  gated on "any endpoint id NOT present in `ProductionGatewayCatalog.all`" -
  too broad, since an arbitrary/malformed/unrelated future manifest-named id
  would have spuriously reported dial-capability purely by being unknown.
  Fixed to the narrower, symmetric rule: gated on membership in
  `ProductionIngressEndpoints.all` specifically (the SAME kind of hardcoded,
  code-reviewed catalog check `ProductionGatewayCatalog.all` already is for
  GATEWAY ids) - only a REAL, reviewed ingress id gets the transport
  registered AVAILABLE whenever the transport instance itself is wired
  (`xrayTransport`/`xrayTlsTransport != null`), independent of
  `isXrayAvailableFor`. Any OTHER id (including a hypothetical future
  manifest-named ingress not yet in this catalog) falls through to the
  ORIGINAL `isXrayAvailableFor` gate, which is false for an id this app has
  never heard of - fails closed by construction. This only asserts "this
  device can technically speak the protocol" for a known ingress - it is NOT
  a credential/trust decision and cannot make an unprovisioned relay connect
  on its own. Every GATEWAY endpoint id (Germany's/Stockholm's own) is
  completely unaffected - still gated by `isXrayAvailableFor`/
  `isXrayTlsAvailableFor` exactly as before B32.
  **Production relay-resolver audit (PR #53 review round 2) - corrects an
  earlier, wrong claim in this same note**: production does NOT use
  `NotProvisionedRelayIngressResolver`. `MainViewModel.Factory.create`
  already constructs `IngressProfileStoreFactory.create` ->
  `RelayCompositionFactory.build` -> the REAL `RelayIngressResolverImpl` (plus
  a real `IngressProfileProvisioner`/`HttpRelayEndToEndProbe`) and threads
  them into `MainViewModel`'s constructor - this has been true since B26 (see
  that section above) and is unchanged by B32; `RelayCompositionFactoryTest`
  already proves Factory selects the real types, never the stand-ins.
  `NotProvisionedRelayIngressResolver`/`NotConfiguredRelayEndToEndProbe`
  remain only as class-level constructor DEFAULTS for tests/unwired callers
  (this is what B32's own first test file used, which is what led to the
  earlier wrong claim above). On a real device with no ingress profile
  stored, `RelayIngressResolverImpl.resolve` returns
  `NotProvisioned(PROFILE_NOT_PROVISIONED)` - one of
  `RelayActivationRequest.ACTIVATION_FIXABLE_CATEGORIES` - which
  `attemptRelayedAttempt` (B26) PAUSES the combined sequence for and surfaces
  as a real, UI-observable `relayActivationNeeded` prompt (`AppRoot` reuses
  the existing `ActivationScreen`), never a silent `EXECUTION_NOT_IMPLEMENTED`
  exhaustion. `RelayIngressResolverImplTest` (new, Robolectric) directly
  proves `PROFILE_NOT_PROVISIONED`/`PROFILE_MISMATCH` (including a
  different-binding, different-ingress-kind, and different-endpoint-id
  profile)/`PROFILE_EXPIRED` on the real resolver type; the success/`Resolved`
  branch is not exercised there since it additionally performs a real
  AndroidKeyStore-backed write - a documented, pre-existing incompatibility
  with this project's Robolectric setup (`RelayCompositionFactoryTest`'s own
  docs), not something this task introduces.
  **What did NOT change**: `RelayIngressResolverImpl`/`RelayedExecutionPlan`/
  `attemptRelayedAttempt`/the B26 pause-resume-retry design are untouched - a
  Relayed winner still converges into the exact same real execution boundary
  described in B24/B25/B26 above. On a real device this means: the Stockholm
  CHAIN_DIRECT candidate now genuinely exists, is genuinely ranked, CAN win
  `attemptCombined()`, and reaches the REAL `RelayIngressResolverImpl` - which
  today returns `PROFILE_NOT_PROVISIONED` (no real per-device ingress
  activation has ever been performed against this codebase's production
  ingress), pausing for a real activation prompt rather than exhausting
  silently. A physical device that then completes that activation (real
  `POST /v1/ingress-profile` against the live Stockholm ingress) would
  genuinely reach `RelayIngressResolution.Resolved` - not yet physically
  exercised this task (no phone run performed). Real Russia/restricted-network
  whitelist bypass remains **UNVERIFIED** - this closes the discovery/ranking/
  execution-seam gap only, not the separate "no real ingress activation has
  ever been performed against production" gap B24/
  B25 already named. `sessions=[]` in a support export remains a physical
  retest finding, not something this change altered diagnostics to address.
